"""The signer dials out: a long-poll job queue over HTTPS, with an HMAC.

Where verify's app servers come and go -- a group of them replaced at every
release -- the signer cannot sit beside gunicorn on one host and take its
requests over a UNIX socket. In poll mode (`[runtime] transport = "poll"`)
it opens no app socket at all. verify's servers queue each request as a job
in the site's shared database; this process long-polls the site for jobs,
answers each exactly as the app socket would, and posts the answers back:

    GET  /api/v1/signer/jobs/?wait=<s>&max=<n>&signer=<id>  claims pending jobs
    POST /api/v1/signer/answers/                             one answer

Nothing connects to the signer; it only connects out. The admin socket stays:
operators still run `cl03signer` on this host.

**Answered as the app socket answers.** A job is `{"op": ..., "args": ...}`,
the frame verify would have sent on the socket, and goes to
`Dispatcher.handle(request, admin=False)`: the same operations and no
others, the app's role, the same ceilings and ledger. The reply goes back
as the very JSON text the socket would have framed, so verify reads the
same bytes either way. The HMAC stands in for SO_PEERCRED, for the app role
only: no admin operation is reachable through the queue.

**Only what it can answer, and only while it is wanted.** A poll asks for
at most as many jobs as the signer has idle workers, and the site hands
over at most `MAX_WAIT_SECONDS` of waiting and about 2 MiB of jobs at once
(one bigger job alone). Each job says how many seconds it has left, by the
site's database clock; a job that runs out before a worker reaches it is
refused, `expired`, without being acted on -- measured on this host's
monotonic clock from when the poll's answer arrived, so neither clock's
error matters.

**Authentication, both ways.** Every request and every response carries

    X-CL03-Signer-Time    unix seconds, ASCII digits
    X-CL03-Signer-Nonce   random, 16 to 64 of [A-Za-z0-9_-]
    X-CL03-Signer-MAC     64 lowercase hex: HMAC-SHA256, under the shared
                          32-byte key, of

        CL03-signer-poll \\n METHOD \\n HOST \\n PATH \\n TIME \\n NONCE \\n
        hex SHA-256 of the body \\n REQUEST NONCE

where HOST is the site's host name, lowercased, without a port: the host in
the signer's `site_url`, and on the site the request's own host as Django
reads it, behind ALLOWED_HOSTS. Two sites sharing a key cannot replay into
each other. PATH is the request's path with its query string. A request's
METHOD is its own and its REQUEST NONCE empty; a response's METHOD is
`RESPONSE`, its HOST, PATH and REQUEST NONCE those of the request it
answers, so a response cannot be replayed as a request or as the answer to
another one. Either side refuses a time more than `SKEW_SECONDS` away from
its own clock, and anything malformed is a refusal, never an error; the site
also refuses a request nonce it has seen before, remembered in its database
so every app server sees it.

**When the site does not answer**, the signer backs off (a second, doubling
to a minute, with jitter) and alerts once: at once when the site refuses it
or its answer is not signed with the key, at once and in its own words when
something is too large, after `ALERT_AFTER_SECONDS` when the site is only
unreachable; again at most every `REALERT_SECONDS` while it lasts, and once
more when it is back. Answers that do not get through are counted the same
way, and alerted after `ANSWER_ALERT_AFTER` in a row. Not once per attempt.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import http.client
import json
import logging
import random
import re
import secrets
import socket
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

logger = logging.getLogger("cl03-signer")

HEADER_TIME = "X-CL03-Signer-Time"
HEADER_NONCE = "X-CL03-Signer-Nonce"
HEADER_MAC = "X-CL03-Signer-MAC"
#: A response's METHOD in the MAC.
RESPONSE = "RESPONSE"
LABEL = "CL03-signer-poll"
#: Seconds either side's clock may be from the other's.
SKEW_SECONDS = 60
#: The headers' forms, ASCII only: `str.isdigit` takes superscripts, which
#: `int` refuses, and a non-ASCII MAC makes `compare_digest` raise.
TIME_PATTERN = re.compile(r"[0-9]{1,12}", re.ASCII)
NONCE_PATTERN = re.compile(r"[A-Za-z0-9_-]{16,64}", re.ASCII)
MAC_PATTERN = re.compile(r"[0-9a-f]{64}", re.ASCII)
#: A signer's instance id, as it rides in the poll's query.
INSTANCE_PATTERN = re.compile(r"[A-Za-z0-9.-]{1,64}", re.ASCII)

JOBS_PATH = "/api/v1/signer/jobs/"
ANSWERS_PATH = "/api/v1/signer/answers/"
REPORT_PATH = "/api/v1/signer/report/"

#: The longest the site holds a poll open (it caps `wait` at this), and what
#: the signer asks for: under the site's cap, so the site answers first. The
#: site answers at once when it has a job.
MAX_WAIT_SECONDS = 25
WAIT_SECONDS = 20
#: Jobs taken at most per poll, and the threads answering them: a poll asks
#: for no more than are idle.
MAX_JOBS = 10
WORKERS = 4
#: Seconds on top of the wait before a poll is given up as unanswered.
NETWORK_SECONDS = 15
#: Nothing the site says back is bigger than this; the site hands over about
#: `MAX_CLAIM_BYTES` of jobs at once (one bigger job alone).
MAX_BODY = 8 * 1024 * 1024
MAX_CLAIM_BYTES = 2 * 1024 * 1024
#: One answer's request body at most: under Django's own 2.5 MiB
#: (DATA_UPLOAD_MAX_MEMORY_SIZE), which answers anything bigger with a 413.
MAX_ANSWER_BYTES = 2 * 1024 * 1024

BACKOFF_FIRST = 1.0
BACKOFF_MAX = 60.0
ALERT_AFTER_SECONDS = 300
REALERT_SECONDS = 6 * 3600
ANSWER_TRIES = 3
#: Answers lost in a row before it is an alert.
ANSWER_ALERT_AFTER = 3

#: How a poll or an answer failed: refused (the key, the clock, the path),
#: too large, or unreachable (the network, a server error).
REFUSED = "refused"
TOO_LARGE = "too_large"
UNREACHABLE = "unreachable"


# -- the key, the host and the MAC ----------------------------------------------

def parse_key(raw: str) -> bytes:
    """The shared key's 32 bytes, from 64 hex characters or base64 -- the
    same rules as verify's other 32-byte keys. ValueError otherwise."""
    raw = (raw or "").strip()
    if len(raw) == 64:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass
    try:
        key = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        key = b""
    if len(key) != 32:
        raise ValueError("the poll key is 32 bytes, as 64 hex characters or "
                         "base64")
    return key


def read_key(path) -> bytes:
    """The poll key from its systemd credential file."""
    if not path:
        raise FileNotFoundError("no credential directory: the poll key is "
                                "the systemd credential poll-key")
    with open(path, encoding="utf-8") as handle:
        return parse_key(handle.read())


def normal_host(host) -> str:
    """A host name as both ends write it into the MAC: lowercase, no port,
    no brackets around an IPv6 address, no trailing dot."""
    return (host or "").strip().lower().strip("[]").rstrip(".")


def site_host(site_url: str) -> str:
    """The host the signer names in its MACs: its `site_url`'s."""
    return normal_host(urllib.parse.urlsplit(site_url).hostname)


def canonical(method, host, path, timestamp, nonce, body=b"",
              request_nonce="") -> bytes:
    return "\n".join((LABEL, method, normal_host(host), path, str(timestamp),
                      nonce, hashlib.sha256(body or b"").hexdigest(),
                      request_nonce)).encode("utf-8")


def mac(key, method, host, path, timestamp, nonce, body=b"",
        request_nonce="") -> str:
    return hmac.new(key, canonical(method, host, path, timestamp, nonce, body,
                                   request_nonce), hashlib.sha256).hexdigest()


def new_nonce() -> str:
    return secrets.token_hex(16)


def sign(key, method, path, body=b"", *, host, now=None, nonce=None,
         request_nonce="") -> dict:
    """The three headers for a request (or, with `method` RESPONSE and the
    request's nonce, a response) to or from the site at `host`."""
    timestamp = int(time.time() if now is None else now)
    nonce = nonce or new_nonce()
    return {HEADER_TIME: str(timestamp), HEADER_NONCE: nonce,
            HEADER_MAC: mac(key, method, host, path, timestamp, nonce, body,
                            request_nonce)}


class AuthError(Exception):
    """A request or response that does not carry the key's MAC, in time.
    `reason` is one of missing, malformed, skew, mac."""

    def __init__(self, reason, detail=""):
        super().__init__("%s%s" % (reason, ": " + detail if detail else ""))
        self.reason = reason


def check(key, header, method, path, body=b"", *, host, now=None,
          request_nonce="") -> str:
    """The nonce of a message whose headers (`header(name)` -> value or
    None) carry a good MAC, for `host`, from within the skew. Raises
    AuthError, and only AuthError, whatever the headers hold. Whether the
    nonce was seen before is the caller's to know."""
    try:
        stamp = header(HEADER_TIME) or ""
        nonce = header(HEADER_NONCE) or ""
        given = header(HEADER_MAC) or ""
    except Exception:
        raise AuthError("malformed", "the signer's headers cannot be read") \
            from None
    if not stamp or not nonce or not given:
        raise AuthError("missing", "the signer's headers are not there")
    if not (isinstance(stamp, str) and isinstance(nonce, str)
            and isinstance(given, str) and TIME_PATTERN.fullmatch(stamp)
            and NONCE_PATTERN.fullmatch(nonce)
            and MAC_PATTERN.fullmatch(given)):
        raise AuthError("malformed", "the signer's headers are malformed")
    try:
        now = int(time.time() if now is None else now)
        if abs(now - int(stamp)) > SKEW_SECONDS:
            raise AuthError("skew", "the time is %+d seconds from this clock"
                            % (int(stamp) - now))
        expected = mac(key, method, host, path, int(stamp), nonce, body,
                       request_nonce)
        good = hmac.compare_digest(expected, given)
    except AuthError:
        raise
    except (TypeError, ValueError, UnicodeError):
        raise AuthError("malformed", "the signer's headers are malformed") \
            from None
    if not good:
        raise AuthError("mac", "not signed with this key")
    return nonce


def instance_id(store, hostname=None) -> str:
    """This signer's id on the site, stable across restarts: a random part
    kept in its database (`meta`) and the host's name. The site warns when
    two different ids poll it within minutes: two signers answering one
    site would each keep a ledger the other's lacks."""
    value = store.meta("poll_instance")
    if value is None:
        value = secrets.token_hex(6)
        with store as db:
            store.set_meta(db, "poll_instance", value)
    host = re.sub(r"[^A-Za-z0-9.-]", "", hostname or socket.gethostname())
    return ("%s.%s" % (value, host))[:64].rstrip(".-") if host else str(value)


# -- the site, as the signer reaches it ---------------------------------------

class SiteError(Exception):
    """The site did not answer as it should. `kind` is REFUSED (it answered
    and said no, or its answer is not the site's: the key, the clock, the
    path), TOO_LARGE (a body over a limit, either way), or UNREACHABLE (the
    network, a server error: it may pass)."""

    def __init__(self, message, *, kind=UNREACHABLE, status=None):
        super().__init__(message)
        self.kind = kind
        self.status = status

    @property
    def refused(self) -> bool:
        """Waiting does not mend it."""
        return self.kind in (REFUSED, TOO_LARGE)


def _https(method, url, headers, body, timeout):
    """(status, header(name), body) for one request on its own connection.
    https with the system's certificate store, and no redirect followed:
    the MAC names one path."""
    import ssl

    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https":
        conn = http.client.HTTPSConnection(
            parts.hostname, parts.port or 443, timeout=timeout,
            context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(parts.hostname, parts.port or 80,
                                          timeout=timeout)
    target = parts.path + ("?" + parts.query if parts.query else "")
    try:
        conn.request(method, target, body=body or None, headers=headers)
        reply = conn.getresponse()
        data = reply.read(MAX_BODY + 1)
        got = {k.lower(): v for k, v in reply.getheaders()}
        return reply.status, (lambda name: got.get(name.lower())), data
    finally:
        conn.close()


@dataclass
class Job:
    id: int
    request: str
    #: Seconds it had left by the site's clock when the poll was answered.
    expires_in: float
    #: When this host's monotonic clock received it.
    received: float = 0.0


class SiteClient:
    """The two calls the signer makes on the site, signed and checked."""

    def __init__(self, site_url: str, key: bytes, *, send=None, clock=None,
                 monotonic=None, instance=""):
        self.origin = site_url.rstrip("/")
        self.host = site_host(site_url)
        self.key = key
        self.send = send or _https
        self.clock = clock or time.time
        self.monotonic = monotonic or time.monotonic
        self.instance = instance if (instance and INSTANCE_PATTERN.fullmatch(
            instance)) else ""

    def _call(self, method, path, body=b"", *, timeout):
        headers = sign(self.key, method, path, body, host=self.host,
                       now=self.clock())
        if body:
            headers["Content-Type"] = "application/json"
        try:
            status, header, reply = self.send(method, self.origin + path,
                                              headers, body, timeout)
        except (OSError, http.client.HTTPException) as exc:
            # Refused connections, DNS, TLS, timeouts, a dropped reply.
            raise SiteError("%s: %s" % (type(exc).__name__, exc)) from None
        if len(reply) > MAX_BODY:
            raise SiteError("its answer is over %d bytes" % MAX_BODY,
                            kind=TOO_LARGE, status=status)
        if status == 413:
            raise SiteError("HTTP 413: the request is over what the site "
                            "accepts", kind=TOO_LARGE, status=status)
        if status != 200:
            raise SiteError("HTTP %d%s" % (status, _said(reply)),
                            kind=(REFUSED if status in (400, 401, 403, 404,
                                                        405)
                                  else UNREACHABLE), status=status)
        try:
            check(self.key, header, RESPONSE, path, reply, host=self.host,
                  now=self.clock(), request_nonce=headers[HEADER_NONCE])
        except AuthError as exc:
            raise SiteError("its answer is not the site's: %s" % exc,
                            kind=REFUSED, status=status) from None
        try:
            data = json.loads(reply)
        except ValueError:
            raise SiteError("its answer is not JSON", kind=REFUSED,
                            status=status) from None
        if not isinstance(data, dict):
            raise SiteError("its answer is not an object", kind=REFUSED,
                            status=status)
        return data

    def jobs(self, wait=WAIT_SECONDS, max_jobs=MAX_JOBS) -> list:
        """The jobs the site handed this poll, as [Job]."""
        path = "%s?wait=%d&max=%d" % (JOBS_PATH, wait, max_jobs)
        if self.instance:
            path += "&signer=" + self.instance
        data = self._call("GET", path, timeout=wait + NETWORK_SECONDS)
        received = self.monotonic()
        out = []
        for job in data.get("jobs") or []:
            left = job.get("expires_in") if isinstance(job, dict) else None
            if (not isinstance(job, dict) or isinstance(job.get("id"), bool)
                    or not isinstance(job.get("id"), int)
                    or not isinstance(job.get("request"), str)
                    or isinstance(left, bool)
                    or not isinstance(left, (int, float))):
                raise SiteError("a job is malformed", kind=REFUSED)
            out.append(Job(job["id"], job["request"], float(left), received))
        return out

    def answer(self, job_id, reply_text) -> dict:
        """Post one answer. The site keeps one answer per job, and only for
        a job it handed out and has not given up on. One a post, so a
        refusal costs one."""
        body = json.dumps({"answers": [{"id": job_id,
                                        "reply": reply_text}]}).encode()
        if len(body) > MAX_ANSWER_BYTES:
            raise SiteError("the answer is %d bytes, over the %d the site "
                            "accepts" % (len(body), MAX_ANSWER_BYTES),
                            kind=TOO_LARGE)
        return self._call("POST", ANSWERS_PATH, body,
                          timeout=NETWORK_SECONDS * 2)


def _said(reply: bytes) -> str:
    """What the site's error said, short and printable, for the journal and
    an alert: it is the site's word, never trusted further."""
    try:
        said = json.loads(reply).get("error", "")
    except (ValueError, AttributeError):
        return ""
    said = "".join(c for c in str(said) if c.isprintable())[:120]
    return " (%s)" % said if said else ""


# -- the loop -------------------------------------------------------------------

def answer_text(dispatcher, request_text: str) -> str:
    """The reply to one job, as the JSON text the app socket would frame."""
    try:
        request = json.loads(request_text)
    except ValueError:
        request = None
    if not isinstance(request, dict):
        reply = {"ok": False, "reason": "bad_request",
                 "detail": "a job is a JSON object"}
    else:
        reply = dispatcher.handle(request, admin=False, by="app")
    return json.dumps(reply)


def _op_of(request_text) -> str:
    try:
        return str(json.loads(request_text).get("op", ""))[:40]
    except (ValueError, AttributeError):
        return ""


#: What the site is told instead of an answer it would refuse as too large.
#: `unavailable` reads, in verify, as a reply that may have been acted on.
TOO_LARGE_REPLY = {"ok": False, "reason": "unavailable",
                   "detail": "the signer's answer was too large to deliver"}
#: And for a job that ran out before a worker reached it: nothing was done.
EXPIRED_REPLY = {"ok": False, "reason": "expired",
                 "detail": "the request ran out before the signer reached it; "
                           "nothing was done"}


class Poller:
    """Long-poll the site, answer what it hands over, back off and alert
    when it does not answer. `alert(severity, message, fields)` is the
    signer's own channel (in the ledger, then SNS or the journal)."""

    def __init__(self, client, dispatcher, *, alert, stop=None,
                 workers=WORKERS, wait=WAIT_SECONDS, max_jobs=MAX_JOBS,
                 clock=time.monotonic, wall=time.time, sleep=None,
                 jitter=None):
        self.client = client
        self.dispatcher = dispatcher
        self.alert = alert
        self.stop = stop or threading.Event()
        self.wait = min(int(wait), MAX_WAIT_SECONDS)
        self.workers = workers
        self.max_jobs = max_jobs
        self.clock = clock
        self.wall = wall
        self.sleep = sleep or self.stop.wait
        self.jitter = jitter or (lambda: random.uniform(0.5, 1.0))
        self.executor = ThreadPoolExecutor(max_workers=workers,
                                           thread_name_prefix="cl03-poll")
        self._lock = threading.Lock()
        self._idle = threading.Condition(self._lock)
        self.busy = 0
        # The poll itself.
        self.failures = 0
        self.failing_since = None
        self.alerted_at = None
        self.alerted_reason = None
        self.last_ok = None
        self.last_error = ""
        # The answers.
        self.answered = 0
        self.answers_failing = 0
        self.answers_lost = 0
        self.last_answer_error = ""
        self.answer_alerted_at = None
        self.expired = 0
        self.too_large = 0
        self._limited = {}

    # -- what `cl03signer status` shows -------------------------------------

    def state(self) -> dict:
        with self._lock:
            return {"site": self.client.origin,
                    "instance": getattr(self.client, "instance", ""),
                    "last_ok": self.last_ok,
                    "failing_for": (int(self.clock() - self.failing_since)
                                    if self.failing_since is not None else 0),
                    "failures_in_a_row": self.failures,
                    "last_error": self.last_error,
                    "workers": self.workers, "busy": self.busy,
                    "answered": self.answered,
                    "answers_failing_in_a_row": self.answers_failing,
                    "answers_lost": self.answers_lost,
                    "last_answer_error": self.last_answer_error,
                    "expired_unanswered": self.expired,
                    "too_large": self.too_large}

    # -- one poll ---------------------------------------------------------------

    def idle_workers(self) -> int:
        with self._lock:
            return self.workers - self.busy

    def cycle(self) -> float:
        """One poll, for as many jobs as there are idle workers. Returns how
        long to wait before the next."""
        with self._idle:
            if self.busy >= self.workers:
                # Every worker is answering: take nothing more until one is
                # free, so no job waits here while its time runs out.
                self._idle.wait(1.0)
                return 0.0
            free = self.workers - self.busy
        try:
            jobs = self.client.jobs(self.wait, min(free, self.max_jobs))
        except (SiteError, ValueError) as exc:
            return self._failed(exc)
        except Exception as exc:
            # A fault of this code's: say so, and keep polling rather than
            # leave the site with nobody answering.
            logger.exception("polling %s failed", self.client.origin)
            return self._failed(exc)
        self._reached()
        for job in jobs:
            with self._lock:
                self.busy += 1
            try:
                self.executor.submit(self._job, job)
            except Exception:
                self._done()
                raise
        return 0.0

    def _done(self):
        with self._idle:
            self.busy -= 1
            self._idle.notify_all()

    def _job(self, job):
        try:
            self._answer(job)
        finally:
            self._done()

    def _answer(self, job):
        if self.clock() - job.received >= job.expires_in:
            # verify has given up on it, or is about to: acting on it now
            # would sign what nobody will receive. Refused, not done.
            with self._lock:
                self.expired += 1
            logger.warning("job %s ran out before a worker reached it; "
                           "refused without acting", job.id)
            self._deliver(job.id, json.dumps(EXPIRED_REPLY), op="")
            return
        try:
            text = answer_text(self.dispatcher, job.request)
        except Exception:
            # The dispatcher answers every fault itself; this is a fault
            # around it. verify times the job out and reads the reply as lost.
            logger.exception("job %s could not be answered", job.id)
            return
        self._deliver(job.id, text, op=_op_of(job.request))

    def _deliver(self, job_id, text, *, op):
        delay = BACKOFF_FIRST
        error = None
        for attempt in range(ANSWER_TRIES):
            try:
                got = self.client.answer(job_id, text)
            except SiteError as exc:
                error = exc
                if exc.kind == TOO_LARGE:
                    self._too_large(job_id, op, exc)
                    if text != json.dumps(TOO_LARGE_REPLY):
                        # verify still learns the request may have been
                        # done, now rather than at its timeout.
                        text = json.dumps(TOO_LARGE_REPLY)
                        continue
                    break
            except Exception as exc:           # posting again is harmless
                error = exc
            else:
                self._answer_reached()
                if job_id in (got.get("unknown") or []):
                    logger.warning("the site had given up on job %s before "
                                   "its answer came", job_id)
                return
            if attempt + 1 == ANSWER_TRIES or self.stop.is_set():
                break
            self.sleep(delay)
            delay *= 2
        # verify gives up on the job and reads the reply as lost: a
        # credential may exist, so its row stays.
        self._answer_failed(job_id, error)

    def run(self):
        """Poll until stopped; then answer what is in hand, and return."""
        try:
            while not self.stop.is_set():
                delay = self.cycle()
                if delay:
                    self.sleep(delay)
        finally:
            self.executor.shutdown(wait=True)

    # -- alerts, never more than one a reason a while ----------------------------

    def _send(self, severity, message, fields):
        try:
            self.alert(severity, message, fields)
        except Exception:
            logger.exception("the alert could not be sent: %s", message)

    def _limited_send(self, key, severity, message, fields):
        """At most one alert per `key` every REALERT_SECONDS."""
        now = self.clock()
        with self._lock:
            last = self._limited.get(key)
            if last is not None and now - last < REALERT_SECONDS:
                return
            self._limited[key] = now
        self._send(severity, message, fields)

    def _too_large(self, job_id, op, exc):
        with self._lock:
            self.too_large += 1
        logger.error("the answer to job %s (%s) is too large: %s", job_id,
                     op or "?", exc)
        self._limited_send(
            "answer-too-large", "high",
            "an answer to %s (job %s, %s) was too large for the site: %s. "
            "verify reads that request as possibly done; nothing about the "
            "key, the clock or the proxy is wrong"
            % (self.client.origin, job_id, op or "an expired job", exc),
            {"job": job_id, "op": op})

    # -- answers that do not get through ----------------------------------------

    def _answer_reached(self):
        with self._lock:
            self.answered += 1
            alerted = self.answer_alerted_at is not None
            self.answers_failing = 0
            self.answer_alerted_at = None
            self.last_answer_error = ""
        if alerted:
            self._send("medium", "answers reach %s again" % self.client.origin,
                       {})

    def _answer_failed(self, job_id, exc):
        reason = "%s" % (exc or "no answer")
        now = self.clock()
        with self._lock:
            self.answers_failing += 1
            self.answers_lost += 1
            self.last_answer_error = reason
            failing = self.answers_failing
            due = failing >= ANSWER_ALERT_AFTER and (
                self.answer_alerted_at is None
                or now - self.answer_alerted_at >= REALERT_SECONDS)
            if due:
                self.answer_alerted_at = now
        logger.error("the answer to job %s did not reach the site (%d in a "
                     "row): %s", job_id, failing, reason)
        if due:
            self._send("high", "%d answers in a row did not reach %s: %s. "
                       "verify reads each as possibly done, so documents "
                       "print the plain QR and credential rows stay unknown"
                       % (failing, self.client.origin, reason),
                       {"answers_failing": failing})

    # -- reaching the site, and not ---------------------------------------------

    def _reached(self):
        with self._lock:
            was = self.failing_since
            alerted = self.alerted_at is not None
            self.failures = 0
            self.failing_since = None
            self.alerted_at = None
            self.alerted_reason = None
            self.last_error = ""
            self.last_ok = int(self.wall())
        if was is not None and alerted:
            self._send("medium", "the signer reaches %s again, after %d "
                       "minutes" % (self.client.origin,
                                    (self.clock() - was) // 60), {})
        elif was is not None:
            logger.info("the signer reaches %s again", self.client.origin)

    def _failed(self, exc) -> float:
        now = self.clock()
        kind = getattr(exc, "kind", UNREACHABLE)
        refused = kind in (REFUSED, TOO_LARGE)
        reason = str(exc)
        with self._lock:
            self.failures += 1
            if self.failing_since is None:
                self.failing_since = now
            failing_for = now - self.failing_since
            self.last_error = reason
            first = self.alerted_at is None
            due = ((first and (refused or failing_for >= ALERT_AFTER_SECONDS))
                   or (not first and now - self.alerted_at >= REALERT_SECONDS)
                   or (not first and refused and reason != self.alerted_reason))
            if due:
                self.alerted_at = now
                self.alerted_reason = reason
            failures = self.failures
        if failures == 1 or failures % 20 == 0:
            logger.warning("polling %s failed (%d in a row): %s",
                           self.client.origin, failures, reason)
        if due:
            if kind == TOO_LARGE:
                message = ("%s answered the signer's poll with more than it "
                           "may: %s. Nothing is signed for it until that is "
                           "fixed; the key and the clock are not the cause"
                           % (self.client.origin, reason))
            elif refused:
                message = ("%s refuses the signer's poll: %s. Nothing is "
                           "signed for it until that is fixed: the poll key "
                           "(SIGNER_QUEUE_KEY there, the credential poll-key "
                           "here), this host's clock, site_url naming the "
                           "site's own host, or the site's proxy letting "
                           "/api/v1/signer/ through"
                           % (self.client.origin, reason))
            else:
                message = ("the signer has not reached %s for %d minutes: %s. "
                           "Documents print the plain QR and phones cannot "
                           "sync meanwhile" % (self.client.origin,
                                               failing_for // 60, reason))
            self._send("high", message, {"failures": failures})
        return min(BACKOFF_MAX,
                   BACKOFF_FIRST * 2 ** min(failures - 1, 10)) * self.jitter()
