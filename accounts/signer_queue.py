"""verify's half of a credential signer that dials out (`SIGNER_QUEUE_KEY`).

Where the app servers come and go, the signer lives on a host of its own and
long-polls this site (signer/poll.py has its half and the wire; the README's
"Poll mode" the deployment). Every app server shares one database, so the
queue is a table in it, `SignerJob`:

1. `ask()` -- an app server that needs the signer writes the request as a
   job, exactly the frame the socket would have carried, and waits for its
   answer in short sleeps, up to `SIGNER_QUEUE_TIMEOUT_SECONDS`.
2. `collect()` -- the signer's `GET /api/v1/signer/jobs/` lands on any app
   server, which claims pending jobs (`claim()`) and hands them over at once,
   or holds the request open, looking again every `JOB_LOOK_SECONDS`, for at
   most `poll.MAX_WAIT_SECONDS`. It answers as soon as it has a job. No
   transaction is held while it waits.
3. `accept()` -- the signer's `POST /api/v1/signer/answers/` stores each
   answer on its job, once, and the waiting app server reads it, deletes the
   job, and returns the answer text: byte for byte what the socket would
   have returned, so `signer_client` reads it the same way.

**Every time is the database's** (`Now()`): a job's creation and expiry, a
claim, an answer, a nonce, the purge. App servers' clocks may disagree; the
database they share has one. Each job handed over says how many seconds it
has left by that clock, and the signer refuses one that runs out before it
reaches it, without acting on it.

**A job is handed out once.** The claim is a conditional write on
`claimed_at IS NULL`, under `SELECT ... FOR UPDATE SKIP LOCKED` where the
database has it (PostgreSQL); on SQLite the same conditional write decides,
so two polls racing each get different jobs. A poll takes at most the jobs
the signer has idle workers for, and about `poll.MAX_CLAIM_BYTES` of them
(one bigger job alone), well under what the signer reads. A signer that dies
holding a job does not get it again: signing twice is worse than not signing.

**Given up, a job says whether anything may have happened.** When the wait
ends with no answer, the job is withdrawn if nobody claimed it -- the same
conditional write, so a claim cannot slip in after -- and that is
`NotCollected`: the signer never saw it, as when a socket refuses to connect.
A job that was claimed is `Lost`: the signer may have signed, so a credential
row stays as `unknown` (`accounts/minting.py`). Either way the job's row is
deleted, and `purge()` takes any a killed process left behind.

**Nobody waits for nothing.** A request is not queued at all when the signer
has not been heard from for `ALIVE_SECONDS` (its newest nonce). And no more
threads of one process wait at once than `SIGNER_QUEUE_MAX_WAITING`: one
more waits a moment for a place (`SLOT_WAIT_SECONDS`, or a tenth of its
timeout if less), then is refused, `Busy`. The answer and the signer's poll
are requests of their own, and on a worker whose every thread waited they
would queue behind the waits until each timed out. **The cap is a backstop,
not the fix:** it counts only the threads waiting here, not one holding the
signer's long poll, so it cannot stand in for the gunicorn pool of its own a
poll-mode site serves /api/v1/signer/ from (signer/deploy/README.md, "Poll
mode"). Its default comes from `GUNICORN_THREADS` (verify/settings.py), which
the site kit's own gunicorn.conf.py reads too.

**Never inside a transaction.** The job is written on this request's own
connection; inside an open transaction the signer could not see it until the
wait was over, and on SQLite the wait would hold the database's one write
lock throughout. `ask()` refuses (`InTransaction`) when any atomic block is
open that is not a test case's own. No caller does it
(`minting.mint_recorded`, `devices.build_bundle_and_chains`, `sync_time`,
`device_log.key_statement`, `acknowledgement`, `revocation_feed`, the
signing pages); a new one must keep it that way.

**One signer.** Each poll names the signer that sent it (`poll.instance_id`),
recorded with its nonce; `pollers()` lists those heard within
`POLLERS_SECONDS`, and Setup warns in red when there is more than one.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError, connection, transaction
from django.db.models import DurationField, ExpressionWrapper, F
from django.db.models.functions import Length, Now
from django.http.request import split_domain_port

from signer import poll

logger = logging.getLogger(__name__)

#: How often an open poll looks for new jobs.
JOB_LOOK_SECONDS = 0.1
#: How often a waiting request looks for its answer: soon, then less often.
ANSWER_LOOK_FIRST = 0.02
ANSWER_LOOK_MAX = 0.1
#: Most jobs one poll may take, and about the most bytes of them: the
#: request texts are ASCII JSON, so a character is a byte.
MAX_JOBS = 50
MAX_CLAIM_BYTES = poll.MAX_CLAIM_BYTES
#: Nonces are kept this long: a request is refused beyond SKEW_SECONDS
#: either way, so a replay can come at most twice that after the first; and
#: long enough to see two signers polling within a few minutes.
NONCE_KEEP_SECONDS = 300
POLLERS_SECONDS = NONCE_KEEP_SECONDS
#: The signer counts as listening while it has been heard from this
#: recently: two of its longest polls and a little more.
ALIVE_SECONDS = 2 * poll.MAX_WAIT_SECONDS + 10
#: Expired jobs and old nonces are deleted at most this often per process.
PURGE_EVERY_SECONDS = 60
#: What a withdrawn job's claim says.
WITHDRAWN = "withdrawn"
#: The longest a request waits for a place among this process's waiting
#: threads before it is refused (`Busy`): briefly, so a burst is smoothed
#: and a worker that is full stays responsive.
SLOT_WAIT_SECONDS = 1.0

#: How both waits pass time: real sleeps on a real clock, which measure only
#: how long this process has waited. A test drives the signer from inside
#: the wait instead, on this thread's own connection.
_pause = time.sleep
_clock = time.monotonic


class QueueError(Exception):
    pass


class NotCollected(QueueError):
    """The signer never took the request: nothing was done."""


class Lost(QueueError):
    """The signer took the request and no answer came: it may have done it."""


class Busy(NotCollected):
    """As many requests of this process wait already as it allows: this one
    was not queued, so nothing was done."""


class InTransaction(NotCollected):
    """Asked inside a transaction the request does not own: not queued."""


class Refused(Exception):
    """A request to the endpoints that is not the signer's."""

    def __init__(self, status, reason):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def enabled() -> bool:
    return bool(settings.SIGNER_QUEUE_KEY)


def key() -> bytes:
    """SIGNER_QUEUE_KEY's 32 bytes. ValueError when it is not one
    (system check accounts.E004 says so at every deploy)."""
    return poll.parse_key(settings.SIGNER_QUEUE_KEY)


def _ago(seconds):
    return Now() - timedelta(seconds=seconds)


# -- the app's side: asking ---------------------------------------------------

def alive() -> bool:
    """Has the signer been heard from within ALIVE_SECONDS, by the
    database's clock?"""
    from accounts.models import SignerNonce

    return SignerNonce.objects.filter(seen_at__gte=_ago(ALIVE_SECONDS)).exists()


def _in_foreign_transaction() -> bool:
    """Is an atomic block open that a test case did not open? Django marks
    its TestCase's own (`_from_testcase`), as it does for durable blocks."""
    if not connection.get_autocommit() and not connection.in_atomic_block:
        return True
    return any(not getattr(block, "_from_testcase", False)
               for block in connection.atomic_blocks)


_waiting = 0
_waiting_lock = threading.Lock()
_slot_free = threading.Condition(_waiting_lock)


class _Slot:
    """One of this process's SIGNER_QUEUE_MAX_WAITING places to wait. When
    all are taken, wait up to `wait` seconds for one, then raise Busy. A
    backstop: it does not count a thread holding the signer's long poll."""

    def __init__(self, wait=0.0):
        self.wait = wait

    def __enter__(self):
        global _waiting
        deadline = time.monotonic() + self.wait
        with _slot_free:
            while _waiting >= max(1, settings.SIGNER_QUEUE_MAX_WAITING):
                left = deadline - time.monotonic()
                if left <= 0:
                    raise Busy("%d requests of this process already wait for "
                               "the signer" % _waiting)
                _slot_free.wait(left)
            _waiting += 1
        return self

    def __exit__(self, *exc):
        global _waiting
        with _slot_free:
            _waiting -= 1
            _slot_free.notify()
        return False


def ask(request_text: str, *, timeout=None) -> str:
    """Queue one request and return the answer text, or raise NotCollected
    (Busy, InTransaction included) or Lost."""
    from accounts.models import SignerJob

    if _in_foreign_transaction():
        logger.error("the signer was asked inside an open transaction; not "
                     "queued (accounts/signer_queue.py)")
        raise InTransaction("asked inside an open transaction")
    sleep, clock = _pause, _clock
    timeout = (settings.SIGNER_QUEUE_TIMEOUT_SECONDS if timeout is None
               else timeout)
    if not alive():
        raise NotCollected("the signer has not polled this site for %d "
                           "seconds" % ALIVE_SECONDS)
    with _Slot(wait=min(SLOT_WAIT_SECONDS, timeout / 10)):
        purge()
        job = SignerJob.objects.create(
            request=request_text, created_at=Now(),
            expires_at=Now() + timedelta(seconds=timeout))
        deadline = clock() + timeout
        look = ANSWER_LOOK_FIRST
        while True:
            answer = _answer(job.pk)
            if answer is not None:
                return answer
            left = deadline - clock()
            if left <= 0:
                break
            sleep(min(look, left))
            look = min(look * 2, ANSWER_LOOK_MAX)
        # Given up. Unclaimed, it is withdrawn in the same conditional write
        # a claim makes, so the signer cannot take it after this.
        withdrawn = SignerJob.objects.filter(
            pk=job.pk, claimed_at__isnull=True).update(
                claimed_at=Now(), claim=WITHDRAWN)
        answer = None if withdrawn else _answer(job.pk)
        SignerJob.objects.filter(pk=job.pk).delete()
    if answer is not None:
        return answer               # it came as the wait ended
    if withdrawn:
        raise NotCollected("the signer did not collect the request within "
                           "%d seconds" % timeout)
    raise Lost("the signer took the request but no answer came within %d "
               "seconds" % timeout)


def _answer(pk):
    """The job's answer, deleting the job, or None while it has none."""
    from accounts.models import SignerJob

    row = (SignerJob.objects.filter(pk=pk, answered_at__isnull=False)
           .values_list("answer", flat=True).first())
    if row is None:
        return None
    SignerJob.objects.filter(pk=pk).delete()
    return row


_purged_at = 0.0
_purge_lock = threading.Lock()


def purge(*, force=False) -> None:
    """Delete jobs past their time and nonces past keeping, by the
    database's clock, at most once a minute per process. Never raises:
    tidying up must not cost a signature."""
    global _purged_at
    from accounts.models import SignerJob, SignerNonce

    with _purge_lock:
        if not force and time.monotonic() - _purged_at < PURGE_EVERY_SECONDS:
            return
        _purged_at = time.monotonic()
    try:
        # A job is read within its timeout; past it, nobody will.
        SignerJob.objects.filter(
            expires_at__lt=_ago(poll.SKEW_SECONDS)).delete()
        SignerNonce.objects.filter(
            seen_at__lt=_ago(NONCE_KEEP_SECONDS)).delete()
    except Exception:
        logger.exception("could not purge the signer queue")


# -- the signer's side: the endpoints -------------------------------------------

def full_path(request) -> str:
    """The path the signer signed: as sent, with its query string."""
    query = request.META.get("QUERY_STRING", "")
    return request.path + ("?" + query if query else "")


def host(request) -> str:
    """This site's host as the request names it, behind ALLOWED_HOSTS
    (`get_host` refuses any other): the HOST in the MAC."""
    return poll.normal_host(split_domain_port(request.get_host())[0])


def authenticate(request, body: bytes, *, signer="") -> str:
    """The request's nonce, once it is known to be the signer's: its MAC,
    for this site's host, its time, and a nonce never seen on any app
    server. `signer`: the instance id the poll named. Raises Refused, with
    nothing more said than the reason."""
    from accounts.models import SignerNonce

    try:
        secret = key()
    except ValueError:
        logger.error("SIGNER_QUEUE_KEY is not 32 bytes; the signer is refused")
        raise Refused(503, "unavailable") from None
    try:
        nonce = poll.check(secret, request.headers.get, request.method,
                           full_path(request), body, host=host(request))
    except poll.AuthError as exc:
        # The clock is worth naming: it is the signer's to fix, and says
        # nothing about the key. Everything else is one answer.
        raise Refused(403, "clock" if exc.reason == "skew"
                      else "unauthenticated") from None
    if not (signer and poll.INSTANCE_PATTERN.fullmatch(signer)):
        signer = ""
    try:
        with transaction.atomic():
            SignerNonce.objects.create(nonce=nonce, seen_at=Now(),
                                       signer=signer)
    except IntegrityError:
        logger.warning("a signer request was replayed (nonce %s...)",
                       nonce[:8])
        raise Refused(403, "replayed") from None
    return nonce


def sign_response(response, request, request_nonce: str):
    """Sign what the site says back, bound to the request it answers."""
    for name, value in poll.sign(key(), poll.RESPONSE, full_path(request),
                                 response.content, host=host(request),
                                 request_nonce=request_nonce).items():
        response[name] = value
    return response


def _within_bytes(rows):
    """The ids of `rows` [(id, size)] in order, up to MAX_CLAIM_BYTES in
    all; the first always, however big, so no job is stuck behind its size."""
    ids, total = [], 0
    for pk, size in rows:
        size = size or 0
        if ids and total + size > MAX_CLAIM_BYTES:
            break
        ids.append(pk)
        total += size
    return ids


def claim(max_jobs: int) -> list:
    """Pending jobs, claimed for this poll: [(id, request text, expires_at,
    seconds left)], oldest first, by the database's clock. Each is claimed
    by one poll only, on any database."""
    from accounts.models import SignerJob

    token = secrets.token_hex(16)
    pending = (SignerJob.objects.filter(claimed_at__isnull=True,
                                        expires_at__gt=Now())
               .order_by("pk").annotate(size=Length("request")))
    if connection.features.has_select_for_update_skip_locked:
        with transaction.atomic():
            ids = _within_bytes(pending.select_for_update(skip_locked=True)
                                .values_list("pk", "size")[:max_jobs])
            if ids:
                SignerJob.objects.filter(pk__in=ids, claimed_at__isnull=True
                                         ).update(claimed_at=Now(), claim=token)
    else:
        # No row locks: the conditional write decides, so a poll racing
        # this one claims none of these, and takes the next ones next time.
        ids = _within_bytes(pending.values_list("pk", "size")[:max_jobs])
        if ids:
            SignerJob.objects.filter(pk__in=ids, claimed_at__isnull=True
                                     ).update(claimed_at=Now(), claim=token)
    left = ExpressionWrapper(F("expires_at") - Now(),
                             output_field=DurationField())
    return [(pk, text, expires_at, max(0.0, remaining.total_seconds()))
            for pk, text, expires_at, remaining in
            SignerJob.objects.filter(claim=token).order_by("pk")
            .annotate(left=left)
            .values_list("pk", "request", "expires_at", "left")]


def collect(max_jobs: int, wait: float) -> list:
    """Claim jobs, or wait for some, at most `wait` seconds; answered as
    soon as there is one."""
    sleep, clock = _pause, _clock
    deadline = clock() + max(0.0, min(float(wait), poll.MAX_WAIT_SECONDS))
    purge()
    while True:
        jobs = claim(max_jobs)
        left = deadline - clock()
        if jobs or left <= 0:
            return jobs
        sleep(min(JOB_LOOK_SECONDS, left))


def accept(answers) -> dict:
    """Store each answer on its job, once: {"accepted": [...], "unknown":
    [...]}. Unknown is a job given up on, or answered already."""
    from accounts.models import SignerJob

    accepted, unknown = [], []
    for job_id, reply in answers:
        stored = SignerJob.objects.filter(
            pk=job_id, claimed_at__isnull=False, answered_at__isnull=True
        ).exclude(claim=WITHDRAWN).update(answer=reply, answered_at=Now())
        (accepted if stored else unknown).append(job_id)
    return {"accepted": accepted, "unknown": unknown}


def pollers() -> list:
    """The signers heard within POLLERS_SECONDS, by their instance ids. More
    than one is two signers answering one site: Setup says so in red."""
    from accounts.models import SignerNonce

    return sorted(set(SignerNonce.objects.filter(
        seen_at__gte=_ago(POLLERS_SECONDS)).exclude(signer="")
        .values_list("signer", flat=True)))
