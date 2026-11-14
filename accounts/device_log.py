"""The device activity log: the key a phone seals to, and opening what it sends.

A verifier phone records what it did -- pairing, syncs, unlocks, every document
it read and the verdict -- and seals each record, the moment it is written, to
a public key whose private half is held only here (`ovcrypto/devicelog.py`
says why: a key the phone holds is a key whoever compromises the phone holds).
It uploads the sealed records later, signed by its Secure Enclave key. This
module is the backend's half: it hands out the public key in a statement the
issuer key signs, and opens, checks and stores what comes back.

Four decisions worth keeping.

**The phone trusts nothing new.** The log key reaches it inside a statement
signed by the same issuer key that signs credentials and the revocation feed,
which the phone already pins -- so a server impersonator cannot hand it a key
of its own, and nothing here asks the phone to trust a second anchor.

**One bad record never refuses the batch.** A record that does not open, or
opens to something malformed, is stored as an `unreadable` placeholder under
its sequence number and acknowledged with the rest. A phone whose upload is
refused can never clear its database, so a single corrupt record would
otherwise stop that phone's log reaching anyone, for good.

**The chain is judged over the sealed bytes.** Each record names the SHA-256
of the record before it; that hash is taken over the ciphertext, so the chain
is checkable without believing anything decrypted -- and a placeholder still
has a hash the next record can name. A record that does not extend the newest
one held for that phone is stored with `chain_ok` false: a gap, a rewrite or a
late insertion is a finding for whoever reads the log, not a reason to refuse.

**A sequence number is written once.** The same record again is a duplicate
and changes nothing, which is what makes a retried upload safe. A different
record under a number already held is a conflict: the original stands, the
newcomer is not stored, and it is logged -- the phone that sent it has
rewritten its own history, and keeping the original is what makes that
visible.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import threading
import time
from datetime import datetime, timedelta, timezone as dt_timezone

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from ovcrypto import devicelog, kdf

from accounts import credential_keys
from accounts.devices import MAX_ORGANIZATION_ID
from accounts.models import (DeviceLogEntry, DeviceLogKey, DeviceLogMark,
                            DeviceOrganization)


logger = logging.getLogger(__name__)

#: How long a key statement is good for. The phone fetches a fresh one before
#: this; the window only bounds how long a statement for a key that has since
#: been retired keeps being accepted.
STATEMENT_DAYS = 90

#: One upload. A phone with more queued sends it in more than one; a limit
#: here is what stops one request asking this server to open a million
#: records inside one transaction.
MAX_RECORDS = 1000
#: One sealed record. A real one is a few hundred bytes.
MAX_RECORD_BYTES = 8 * 1024

#: The plaintext's own version. A record of another version is kept as a
#: placeholder rather than guessed at.
PLAINTEXT_VERSION = 1
OUTCOMES = ("success", "failure", "notice")
#: Event names are an open set -- a newer app may record events this
#: deployment has never heard of, and they are kept as they are. Only their
#: SHAPE is checked, so a name is always safe to put in a CSV or a filter.
EVENT_PATTERN = re.compile(r"[a-z_]{1,40}")
PREV_PATTERN = re.compile(r"[0-9a-f]{64}")
MAX_BUILD_CHARS = 40
MAX_DETAIL_KEYS = 32
MAX_DETAIL_KEY_CHARS = 40
MAX_DETAIL_VALUE_CHARS = 200
#: JSON allows any integer; the database and every reader downstream do not.
_INT_RANGE = (-(2 ** 63), 2 ** 63 - 1)

#: The event and outcome a record that could not be read is stored under.
UNREADABLE_EVENT = "unreadable"
UNREADABLE_OUTCOME = "failure"

#: A phone's clock is the phone's to set. A claimed time before this, or more
#: than `CLOCK_SLACK` past this server's, is not a time anything happened:
#: `occurred_at` is left empty and the raw claim kept in `detail`.
EARLIEST_PLAUSIBLE = datetime(2020, 1, 1, tzinfo=dt_timezone.utc)
CLOCK_SLACK = timedelta(days=1)
CLAIMED_AT_KEY = "claimed_at_ms"

#: The sequence column is a signed 64-bit integer; the header allows unsigned.
#: A number past this cannot be stored under, so it is treated as a header
#: that does not parse. No phone counting from 1 will ever reach it.
MAX_STORABLE_SEQ = 2 ** 63 - 1

_EPOCH = datetime(1970, 1, 1, tzinfo=dt_timezone.utc)


#: How far past the newest record held a phone's numbering may move, beside
#: the one jump a phone makes on purpose: a re-key that found no chain head
#: numbers on from its own clock, in milliseconds, so that its log does not
#: restart at 1. A number past both is refused unstored. What this stops is a
#: number no phone could write -- one near 2**63, past which every later
#: record of its own would be a conflict -- not a few numbers ahead, which
#: only the signature on each upload speaks for. The slack is a year, not a
#: day, because the jump uses the phone's clock, which may run ahead.
MAX_SEQ_AHEAD = 100_000
SEQ_CLOCK_SLACK_MS = 366 * 24 * 60 * 60 * 1000


class QuotaExceeded(Exception):
    """This phone has stored `DEVICE_LOG_DAILY_RECORDS` here in the last 24
    hours. Nothing in the upload was stored; the phone keeps it."""


#: device uuid -> when its last refusal was logged: one line a day per phone,
#: not one per upload, so the log is not what a flooding phone fills next.
_quota_logged = {}


class LogUnavailable(Exception):
    """The log keys cannot be opened here. The SERVER's fault, never the
    phone's: an upload that meets this must be refused whole, not stored as
    placeholders -- acknowledging records this deployment could have read
    would have the phone delete them."""


class _Unreadable(Exception):
    """One record that opened to something this format does not allow."""


# ---------------------------------------------------------------------------
# The key
# ---------------------------------------------------------------------------

@transaction.atomic
def current_key() -> DeviceLogKey:
    """The key phones are told to seal to, made on first use.

    Generated and wrapped inside one transaction, so a row never exists
    without its private half. Two first requests racing can each make one.
    Every key still opens what was sealed to it (`private_keys()` returns them
    all), but a signer alerts on every new log key, so the race must settle on
    ONE: the oldest current key wins and any later one is retired at once.
    """
    rows = list(DeviceLogKey.objects.filter(retired_at__isnull=True)
                .order_by("id"))
    if not rows:
        private = devicelog.generate_key()
        DeviceLogKey.objects.create(
            public_key=kdf.public_bytes(private.public_key()),
            # The epoch keys' own wrapper, deliberately -- see DeviceLogKey for
            # why this custody, and not a key file of its own.
            wrapped_private_key=credential_keys._wrapper().wrap(
                kdf.private_bytes(private)))
        rows = list(DeviceLogKey.objects.filter(retired_at__isnull=True)
                    .order_by("id"))
    if len(rows) > 1:
        DeviceLogKey.objects.filter(
            pk__in=[row.pk for row in rows[1:]]).update(
                retired_at=timezone.now())
    return rows[0]


def private_keys() -> dict:
    """{key id: X25519PrivateKey} for EVERY key, retired ones included.

    A phone seals to whichever statement it last fetched, so records sealed
    to a key retired since must still open.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey)

    wrapper = credential_keys._wrapper()
    keys = {}
    for row in DeviceLogKey.objects.all():
        try:
            raw = wrapper.unwrap(bytes(row.wrapped_private_key))
            keys[row.id] = X25519PrivateKey.from_private_bytes(raw)
        except Exception as exc:
            # A changed CREDENTIAL_EPOCH_WRAP_KEY, or a damaged row. Either
            # way, every record sealed to this key would be stored as
            # unreadable and then deleted by the phone -- so stop here.
            raise LogUnavailable(
                "device log key %d cannot be unwrapped" % row.id) from exc
    return keys


#: How long one signed statement is handed out before a fresh one is signed.
#: The endpoint is unauthenticated, so without this every fetch was an issuer
#: signature on demand. A copy a day old still has 89 of its 90 days left, and
#: the phone checks only that its `not_after` has not passed.
STATEMENT_REUSE_SECONDS = 24 * 60 * 60

_statement_lock = threading.Lock()
_statements = {}


def key_statement(now: int = None) -> dict:
    """The current log key, vouched for by the issuer key.

    The signature covers `devicelog.key_statement_bytes` -- a fixed binary
    layout, not this JSON, for the reason the revocation feed gives -- and is
    the same encoding `revocation_feed.build_feed` uses (raw 64-byte r||s,
    low-s), so the phone checks it exactly as it checks the feed, against the
    issuer keys it already pins.

    Memoised per process for `STATEMENT_REUSE_SECONDS`, keyed by the log key
    and the signing key, so a burst of fetches costs one signature. Passing
    `now` asks for a fresh one, as tests do.

    With a signer, the signer signs it and caches it by content itself; this
    process keeps its copy for sixty minutes, and serves it while the signer
    cannot answer as long as it is still good for a day.
    """
    if now is None:
        key = current_key()
        signer = credential_keys.signer_mode()
        memo = ((key.id, bytes(key.public_key), "signer", settings.SIGNER_SOCKET)
                if signer else
                (key.id, bytes(key.public_key),
                 settings.CREDENTIAL_ISSUER_KEY_ID,
                 settings.CREDENTIAL_ISSUER_KEY_PATH))
        reuse = SIGNER_STATEMENT_REUSE_SECONDS if signer else STATEMENT_REUSE_SECONDS
        with _statement_lock:
            held = _statements.get(memo)
            if held is not None and time.time() - held[1] < reuse:
                return dict(held[0])
        try:
            statement = (_signer_statement(key) if signer
                         else _sign_statement(int(time.time()), key))
        except Exception:
            if (held is not None
                    and held[0]["not_after"] - time.time() > 24 * 60 * 60):
                return dict(held[0])
            raise
        with _statement_lock:
            _statements.clear()         # only the current key is ever served
            _statements[memo] = (statement, time.time())
        return dict(statement)
    return _sign_statement(int(now), current_key())


#: With a signer, how long this process keeps the signer's statement. The
#: signer itself re-signs only daily; this only spares it the round trips.
SIGNER_STATEMENT_REUSE_SECONDS = 60 * 60


def _signer_statement(key) -> dict:
    from accounts import signer_client

    return signer_client.statement(log_key_id=key.id,
                                   public_key=bytes(key.public_key))


def _sign_statement(now: int, key) -> dict:
    public = bytes(key.public_key)
    not_after = now + STATEMENT_DAYS * 24 * 60 * 60
    signer = credential_keys.signer()
    signature = signer.sign(devicelog.key_statement_bytes(
        key.id, public, now, not_after, signer.key_id))
    return {
        "format": devicelog.KEY_MAGIC.decode(),
        "version": devicelog.KEY_VERSION,
        "key_id": key.id,
        "public_key": base64.b64encode(public).decode(),
        "issued_at": now,
        "not_after": not_after,
        "sig_key_id": signer.key_id,
        "sig": base64.b64encode(signature).decode(),
    }


def acknowledgement(device, through_seq: int, records: list):
    """This deployment's signed word that it holds `device`'s records up to
    `through_seq` of this upload, or None.

    The phone deletes records only once one of these covers them, signed by a
    key its bundle trusts for statements -- the signer's, or the key file's,
    as for the log key statement. `records` are as uploaded, so it is of
    exactly that upload. None when nothing can sign it just now: the records
    are stored all the same, and the phone keeps its copies and sends them
    again, which arrive as duplicates.
    """
    digest = devicelog.upload_digest(records)
    device_id = device.device_id.bytes
    try:
        if credential_keys.signer_mode():
            from accounts import signer_client

            return signer_client.log_ack(device_id=device_id,
                                         through_seq=through_seq,
                                         digest=digest)
        now = int(time.time())
        signer = credential_keys.signer()
        signature = signer.sign(devicelog.ack_signed_bytes(
            device_id, through_seq, digest, now, signer.key_id))
        return {"format": devicelog.ACK_MAGIC.decode(),
                "version": devicelog.ACK_VERSION, "issued_at": now,
                "sig_key_id": signer.key_id,
                "sig": base64.b64encode(signature).decode()}
    except Exception:
        logger.exception("device %s: the log acknowledgement could not be "
                         "signed; the phone keeps its records", device.device_id)
        return None


# ---------------------------------------------------------------------------
# Opening an upload
# ---------------------------------------------------------------------------

def _is_int(value) -> bool:
    # bool is an int in Python, and `true` is not a sequence number.
    return (type(value) is int
            and _INT_RANGE[0] <= value <= _INT_RANGE[1])


def _detail(value) -> dict:
    if not isinstance(value, dict):
        raise _Unreadable("detail is not an object")
    if len(value) > MAX_DETAIL_KEYS:
        raise _Unreadable("detail has more than %d keys" % MAX_DETAIL_KEYS)
    for key, item in value.items():
        if not key or len(key) > MAX_DETAIL_KEY_CHARS:
            raise _Unreadable("a detail key is empty or over %d characters"
                              % MAX_DETAIL_KEY_CHARS)
        if item is None or isinstance(item, bool) or _is_int(item):
            continue
        if isinstance(item, str) and len(item) <= MAX_DETAIL_VALUE_CHARS:
            continue
        raise _Unreadable("detail %s is not a short string, an integer, "
                          "true, false or null" % key)
    return value


def _parse(plaintext: bytes, seq: int) -> dict:
    """The fields of one opened record, or `_Unreadable` saying why not.

    Unknown top-level keys are ignored, so a newer app can add one without
    every older deployment calling its records unreadable. Everything named
    here is required and typed exactly.
    """
    try:
        data = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        # RecursionError too: the pure-Python decoder recurses once per level
        # of nesting, and one record must never turn into a refused batch.
        raise _Unreadable("not UTF-8 JSON") from None
    if not isinstance(data, dict):
        raise _Unreadable("not a JSON object")
    if not _is_int(data.get("v")) or data["v"] != PLAINTEXT_VERSION:
        raise _Unreadable("unsupported version")
    # The header's number is authenticated too (it is the AEAD's associated
    # data), so a disagreement is a phone that sealed one number and wrote
    # another -- not a record to file under either.
    if not _is_int(data.get("seq")) or data["seq"] != seq:
        raise _Unreadable("seq does not match the header")
    prev = data.get("prev")
    if not isinstance(prev, str) or not PREV_PATTERN.fullmatch(prev):
        raise _Unreadable("prev is not 64 lowercase hex characters")
    if not _is_int(data.get("at")):
        raise _Unreadable("at is not an integer")
    event = data.get("event")
    if not isinstance(event, str) or not EVENT_PATTERN.fullmatch(event):
        raise _Unreadable("event is not 1-40 of a-z and _")
    if data.get("outcome") not in OUTCOMES:
        raise _Unreadable("outcome is not success, failure or notice")
    build = data.get("build")
    if not isinstance(build, str) or len(build) > MAX_BUILD_CHARS:
        raise _Unreadable("build is not text of at most %d characters"
                          % MAX_BUILD_CHARS)
    # The one OPTIONAL field: the organization the phone was working for.
    # Absent and null both mean none -- a phone with no organizations, or one
    # talking to a server that has none, never writes it, and PLAINTEXT_VERSION
    # did not move for it. Present, it is checked as strictly as the rest.
    org = data.get("org")
    if org is not None and not (_is_int(org)
                                and 1 <= org <= MAX_ORGANIZATION_ID):
        raise _Unreadable("org is not an organization id")
    return {"prev": bytes.fromhex(prev), "at": data["at"], "event": event,
            "outcome": data["outcome"], "build": build,
            "detail": dict(_detail(data.get("detail"))), "org": org}


def _attributable(device) -> dict:
    """{organization id: its name now} for every organization this phone has
    EVER been linked to.

    Ever, not currently: a phone queues records offline, so one written
    while it worked for an organization may arrive after the link ended, and
    it is still that organization's record. And only those: a record's `org`
    is the phone's own claim, and the link -- made on the web by somebody who
    could enter the organization -- is what stops a phone filing records
    into the export of an organization it never worked for.
    """
    return dict(DeviceOrganization.objects.filter(device=device)
                .values_list("organization_id", "organization__name"))


def _organization_fields(org_id, attributable) -> dict:
    """The entry's organization columns for a record that claimed `org_id`."""
    if org_id is None:
        return {}
    if org_id not in attributable:
        # Kept, never refused: the claim is the finding.
        return {"claimed_organization_id": org_id}
    return {"claimed_organization_id": org_id, "organization_id": org_id,
            "organization_name": (attributable[org_id] or "")[:255]}


def _claimed_time(at_ms: int, now):
    """The device's claimed time, or None when it is not a plausible one."""
    low = int((EARLIEST_PLAUSIBLE - _EPOCH).total_seconds() * 1000)
    high = int((now + CLOCK_SLACK - _EPOCH).total_seconds() * 1000)
    if not low <= at_ms <= high:
        return None
    return _EPOCH + timedelta(milliseconds=at_ms)


def _snapshot(device) -> dict:
    """Who and what, copied in -- so deleting either does not erase this."""
    owner = device.owner
    return {
        "device": device,
        "device_uuid": device.device_id,
        "device_label": (device.label or "")[:120],
        "owner": owner,
        "owner_name": ((owner.display_name if owner else "") or "")[:255],
        "owner_national_id_number":
            ((owner.national_id_card_number if owner else "") or "")[:16],
    }


@transaction.atomic
def ingest(device, records: list, now=None) -> dict:
    """Open, check and store one upload from `device`. All or nothing.

    The caller has already proved the upload came from this device (the
    Enclave signature over `devicelog.upload_signed_bytes`). What is decided
    here is what each record says and whether the chain holds:

    * a header that does not parse has no number to file it under: counted
      as `unreadable`, not stored;
    * a record that does not open, or opens to something malformed, is
      stored as an `unreadable` placeholder -- never a refusal of the batch;
    * a number already held: the same bytes are a `duplicate`, other bytes a
      `conflict` (the original kept, the newcomer logged and dropped);
    * a number at or below where `purge_device_logs` aged this phone's log
      out (`DeviceLogMark`) is recognised and not stored: its first copy is
      gone, so nothing can tell it sent again from rewritten, and a record
      numbered below one past the retention period is past it too. Counted
      as a `duplicate`, so the phone deletes it, and logged once an upload;
    * otherwise the record is stored, `chain_ok` when it extends the newest
      record held for this phone -- its number one more and its `prev` that
      record's hash, or number 1 naming GENESIS for the very first;
    * a record naming an organization (`org`) is filed under it, with its
      name, when this phone has ever been linked to it; otherwise the claim
      is kept on its own (`claimed_organization_id`) and the record stored
      all the same -- see `_attributable`.

    `through_seq` is the highest header number stored or recognised: everything
    up to it is held here now, one way or another, or aged out, so the phone
    may delete it. The chain is judged from the newest record held or, when
    newer, the mark a purge left.

    Two limits come first. A number further ahead than a phone could have put
    it -- `MAX_SEQ_AHEAD` past the newest held, or past the current time in
    milliseconds a re-key may jump to -- is `refused` and not stored. And a
    phone that has stored `DEVICE_LOG_DAILY_RECORDS` in the last 24 hours gets
    QuotaExceeded; one close to it has the oldest records stored up to the cap
    and the rest `deferred`, which `through_seq` leaves out, so the phone keeps
    them.
    """
    now = now or timezone.now()
    keys = private_keys()
    counts = {"stored": 0, "duplicates": 0, "conflicts": 0,
              "unreadable": 0, "breaks": 0, "refused": 0, "deferred": 0}

    uuid = device.device_id
    newest = (DeviceLogEntry.objects.filter(device_uuid=uuid)
              .order_by("-seq").values_list("seq", "record_hash").first())
    head = (newest[0], bytes(newest[1])) if newest else None
    mark = (DeviceLogMark.objects.filter(device_uuid=uuid)
            .values_list("head_seq", "head_hash").first())
    aged_out = mark[0] if mark else 0
    if mark and (head is None or mark[0] > head[0]):
        head = (mark[0], bytes(mark[1]))
    now_ms = int((now - _EPOCH).total_seconds() * 1000)
    ceiling = max((head[0] if head else 0) + MAX_SEQ_AHEAD,
                  now_ms + SEQ_CLOCK_SLACK_MS)

    numbered = []
    for record in records:
        try:
            seq = devicelog.parse_header(record).seq
        except devicelog.LogError:
            counts["unreadable"] += 1
            continue
        if seq > MAX_STORABLE_SEQ:
            counts["unreadable"] += 1
            continue
        if seq > ceiling:
            counts["refused"] += 1
            continue
        numbered.append((seq, record))
    if counts["refused"]:
        logger.warning("device %s sent %d log record(s) numbered past %d, "
                       "further ahead than a phone numbers; not stored",
                       uuid, counts["refused"], ceiling)
    # Stable, so two records claiming one number keep the order they came in
    # and the second is judged against the first.
    numbered.sort(key=lambda item: item[0])
    if not numbered:
        return dict(through_seq=0, **counts)

    allowed = settings.DEVICE_LOG_DAILY_RECORDS - (
        DeviceLogEntry.objects.filter(
            device_uuid=uuid, received_at__gte=now - timedelta(hours=24))
        .count())
    if allowed <= 0:
        last = _quota_logged.get(uuid)
        if last is None or now - last >= timedelta(hours=24):
            _quota_logged[uuid] = now
            logger.warning("device %s has stored %d activity records in 24 "
                           "hours, the most DEVICE_LOG_DAILY_RECORDS allows; "
                           "its uploads are refused until the count falls",
                           uuid, settings.DEVICE_LOG_DAILY_RECORDS)
        raise QuotaExceeded()
    if len(numbered) > allowed:
        counts["deferred"] = len(numbered) - allowed
        numbered = numbered[:allowed]

    held = dict(DeviceLogEntry.objects
                .filter(device_uuid=uuid, seq__gte=numbered[0][0],
                        seq__lte=numbered[-1][0])
                .values_list("seq", "record_hash"))
    held = {seq: bytes(digest) for seq, digest in held.items()}

    snapshot = _snapshot(device)
    attributable = _attributable(device)
    entries = []
    conflicting = []
    recognised = []
    for seq, record in numbered:
        digest = devicelog.record_hash(record)
        if seq in held:
            if held[seq] == digest:
                counts["duplicates"] += 1
            else:
                # Counted as held, so the acknowledgement covers it and the
                # phone deletes its own copy. Accepted: the first record under
                # a number is the one kept, and a second one signed by this
                # phone's key means that key, or the phone, is no longer to be
                # trusted -- which the warning below says.
                counts["conflicts"] += 1
                conflicting.append(seq)
            continue
        if seq <= aged_out:
            counts["duplicates"] += 1
            recognised.append(seq)
            continue

        try:
            opened = devicelog.open_record(record, keys)
            fields = _parse(opened.plaintext, seq)
        except (devicelog.LogError, _Unreadable) as exc:
            entry = DeviceLogEntry(
                seq=seq, key_id=devicelog.parse_header(record).key_id,
                event=UNREADABLE_EVENT, outcome=UNREADABLE_OUTCOME,
                detail={"reason": str(exc)[:MAX_DETAIL_VALUE_CHARS]},
                occurred_at=None, received_at=now, record_hash=digest,
                chain_ok=False, readable=False, **snapshot)
            counts["unreadable"] += 1
        else:
            if head is None:
                chain_ok = seq == 1 and fields["prev"] == devicelog.GENESIS
            else:
                chain_ok = (seq == head[0] + 1
                            and fields["prev"] == head[1])
            detail = fields["detail"]
            occurred = _claimed_time(fields["at"], now)
            if occurred is None:
                detail[CLAIMED_AT_KEY] = fields["at"]
            entry = DeviceLogEntry(
                seq=seq, key_id=opened.key_id, event=fields["event"],
                outcome=fields["outcome"], detail=detail,
                app_build=fields["build"], occurred_at=occurred,
                received_at=now, record_hash=digest, chain_ok=chain_ok,
                readable=True, **snapshot,
                **_organization_fields(fields["org"], attributable))
            if not chain_ok:
                counts["breaks"] += 1

        entries.append(entry)
        held[seq] = digest
        # The head is always the NEWEST record held. A record filed below it
        # -- a late one filling a gap -- is stored, but the chain is still
        # judged from the top.
        if head is None or seq > head[0]:
            head = (seq, digest)

    DeviceLogEntry.objects.bulk_create(entries)
    counts["stored"] = len(entries)
    if recognised:
        logger.warning("device %s sent %d record(s) numbered at or below %d, "
                       "where its log was aged out (from %d); not stored "
                       "again", uuid, len(recognised), aged_out, recognised[0])
    if counts["conflicts"]:
        # One line per upload, not one per record: a phone made to send a
        # thousand conflicts would otherwise write a thousand lines. Many of
        # them is what a sequence pre-filled by somebody else looks like.
        shown = ", ".join(str(seq) for seq in conflicting[:5])
        more = " and %d more" % (len(conflicting) - 5) if len(conflicting) > 5 else ""
        logger.warning("device %s sent %d record(s) under log numbers already "
                       "held with other contents (sequence %s%s); the first "
                       "ones are kept", uuid, counts["conflicts"], shown, more)
    return dict(through_seq=numbered[-1][0], **counts)
