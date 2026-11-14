"""verify's side of the credential signer.

With `SIGNER_SOCKET` set, no issuer key is in this process. Credentials,
bundles, revocation feeds and log-key statements are asked of the signer over
its app socket, and it signs only what its own policy passes. With
`SIGNER_QUEUE_KEY` set instead, the same requests go through the database as
jobs for a signer that dials out to the site (`accounts.signer_queue`), and
the answer comes back as the very text the socket would have carried: every
caller below reads it the same way. verify can make
things safer from here -- pause, suspend, upload a certificate -- and nothing
more.

Every failure is one of four kinds, so callers can fall back the right way:

* `Paused`     -- the context is paused; the document prints its plain QR.
* `KeyChanged` -- the signer wants another key id; mint again, once.
* `Refused`    -- the policy said no.
* `Unavailable`-- no answer. `reply_lost` says the request may have arrived,
                  so a credential may exist: the row stays, as `unknown`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import socket
import threading
import time

from django.conf import settings
from django.utils import timezone

from ovcrypto import wire

logger = logging.getLogger(__name__)

TIMEOUT_SECONDS = 5
PUBLIC_MAX_AGE = 60
#: Send the revoked set again after this long even when nothing changed here:
#: a signer restored from an older image catches up within minutes, not at
#: the next revocation.
REVOKED_RESEND_SECONDS = 600
#: Sends of the revoked set in one go while the signer says ids still wait:
#: 50,000 new ids at its default of 10,000 a call.
PUT_REVOKED_ROUNDS = 5
LISTED_STATES = ("published", "active", "retired", "legacy")


class SignerError(Exception):
    reply_lost = False

    def __init__(self, reason: str, detail: str = ""):
        super().__init__("%s%s" % (reason, ": " + detail if detail else ""))
        self.reason = reason
        self.detail = detail


class Refused(SignerError):
    pass


class Paused(Refused):
    pass


class KeyChanged(Refused):
    def __init__(self, key_id: int, detail: str = ""):
        super().__init__("key_changed", detail)
        self.key_id = key_id


class Unavailable(SignerError):
    def __init__(self, detail: str = "", *, reply_lost: bool = False):
        super().__init__("unavailable", detail)
        self.reply_lost = reply_lost


# -- transport -------------------------------------------------------------

_transport = None
_lock = threading.Lock()
_public = None
_public_at = 0.0
_sent_generation = None
_sent_at = 0.0


def set_transport(fn):
    """For tests: ``fn(op, **args)`` answers instead of the socket.

    It returns the result, or raises `signer.service.Refused` as the signer
    would. None restores the socket.
    """
    global _transport
    _transport = fn
    reset()


def reset():
    global _public, _public_at, _sent_generation, _sent_at
    with _lock:
        _public, _public_at, _sent_generation, _sent_at = None, 0.0, None, 0.0


def enabled() -> bool:
    """A signer holds the issuer keys: on its socket, or through the queue."""
    return bool(settings.SIGNER_SOCKET or settings.SIGNER_QUEUE_KEY)


def _result(reply):
    """What the signer's reply frame says, as the socket's caller reads it."""
    if not reply.get("ok"):
        from signer.service import Refused as ServiceRefused
        raise ServiceRefused(reply.get("reason", "error"),
                             reply.get("detail", ""),
                             **(reply.get("extra") or {}))
    return reply["result"]


def _socket_call(op, **args):
    from signer.transport import recv_frame, send_frame

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT_SECONDS)
    try:
        try:
            sock.connect(settings.SIGNER_SOCKET)
        except OSError as exc:
            raise Unavailable(str(exc))
        try:
            send_frame(sock, {"op": op, "args": args})
            reply = recv_frame(sock)
        except OSError as exc:
            raise Unavailable(str(exc), reply_lost=True)
    finally:
        sock.close()
    if reply is None:
        raise Unavailable("no reply", reply_lost=True)
    return _result(reply)


def _queue_call(op, **args):
    """The same frame, as a job for a signer that dials out. A job the
    signer never collected is a refused connection (nothing happened); one
    it collected and did not answer is a lost reply (it may have signed)."""
    from django.db import DatabaseError

    from accounts import signer_queue

    try:
        text = signer_queue.ask(json.dumps({"op": op, "args": args}))
    except signer_queue.NotCollected as exc:
        raise Unavailable(str(exc))
    except signer_queue.Lost as exc:
        raise Unavailable(str(exc), reply_lost=True)
    except DatabaseError as exc:
        # The queue itself failed part-way: the job may have been taken.
        raise Unavailable(str(exc), reply_lost=True)
    try:
        reply = json.loads(text)        # what recv_frame would have read
    except ValueError:
        reply = None
    if not isinstance(reply, dict):
        raise Unavailable("the signer's answer is not a reply",
                          reply_lost=True)
    return _result(reply)


def _wire():
    """The socket where one is named; the queue where only its key is."""
    if settings.SIGNER_QUEUE_KEY and not settings.SIGNER_SOCKET:
        return _queue_call
    return _socket_call


def transport() -> str:
    """"queue" for a signer that dials out, "socket" for one on this host."""
    return "queue" if _wire() is _queue_call else "socket"


def call(op, **args):
    from signer.service import Refused as ServiceRefused

    try:
        return (_transport or _wire())(op, **args)
    except ServiceRefused as exc:
        if exc.reason == "paused":
            raise Paused("paused", exc.detail)
        if exc.reason == "key_changed":
            raise KeyChanged(int(exc.extra.get("key_id", 0)), exc.detail)
        if exc.reason == "unavailable":
            raise Unavailable(exc.detail, reply_lost=True)
        raise Refused(exc.reason, exc.detail)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


# -- what the signer holds -------------------------------------------------

def public(force: bool = False) -> dict:
    """The signer's keys and settings, cached for a minute, mirrored here."""
    global _public, _public_at
    with _lock:
        if not force and _public and time.time() - _public_at < PUBLIC_MAX_AGE:
            return _public
    data = call("public")
    with _lock:
        _public, _public_at = data, time.time()
    try:
        refresh_mirror(data)
    except Exception:
        logger.exception("could not refresh the issuer key mirror")
    return data


def signing_key(organization_signing_id=None, *, force=False):
    """(key_id, certified name or None) the signer will use for an org."""
    keys = public(force=force)["keys"]
    org = str(organization_signing_id) if organization_signing_id else None
    if org:
        for k in keys:
            if k["state"] == "active" and k["organization"] == org:
                return k["key_id"], k["certified_name"]
    for k in keys:
        if (k["state"] == "active" and not k["organization"]
                and not k["legacy"]):
            return k["key_id"], None
    raise Refused("no_key", "the signer has no active key")


def refresh_mirror(data: dict):
    """IssuerKey becomes a read-only copy of the signer's registry."""
    from accounts.models import IssuerKey

    now = timezone.now()
    for k in data.get("keys", []):
        window = k.get("window") or [None, None]
        if window[0] is None or window[1] is None:
            continue                      # generated: no window, not listed
        leaf = base64.b64decode(k["leaf"]) if k.get("leaf") else None
        IssuerKey.objects.update_or_create(key_id=k["key_id"], defaults={
            "spki_der": base64.b64decode(k["spki"]),
            "not_before": _dt(window[0]), "not_after": _dt(window[1]),
            "is_active": k["state"] in LISTED_STATES,
            "source": IssuerKey.SOURCE_SIGNER,
            "state": k["state"] + (" (suspended)" if k.get("suspended") else ""),
            "organization_signing_id": k.get("organization") or None,
            "certified_name": k.get("certified_name") or "",
            "certificate_chain": leaf,
            "fingerprint_sha256": hashlib.sha256(leaf).hexdigest() if leaf else "",
            "cert_not_after": (_dt(k["cert_not_after"])
                               if k.get("cert_not_after") else None),
            "synced_at": now,
        })


def _dt(ts: int):
    import datetime
    return datetime.datetime.fromtimestamp(int(ts), datetime.timezone.utc)


# -- signing ----------------------------------------------------------------

class CredentialSigner:
    """What `ovcrypto.issuer.issue` takes as a signer: the signer's key id,
    chosen once per mint, and a sign() that asks the signer."""

    sig_alg = wire.SIG_ECDSA_P256_SHA256

    def __init__(self, key_id: int, *, organization=None, operator="",
                 holder=False, holder_id=""):
        self.key_id = key_id
        self.organization = str(organization) if organization else None
        self.operator = str(operator or "")
        self.holder = bool(holder or holder_id)
        self.holder_id = str(holder_id or "")

    def sign(self, message: bytes) -> bytes:
        result = call("sign_credential", message=_b64(message),
                      organization=self.organization, operator=self.operator,
                      holder=self.holder, holder_id=self.holder_id)
        if int(result["key_id"]) != self.key_id:
            raise Refused("policy", "signed by another key")
        return base64.b64decode(result["sig"])


def ensure_revocations():
    """Send the revoked set when it has changed since this worker last did,
    or when it last did so long ago that the signer may have been restored.

    The generation is read BEFORE the ids. Read after, a revocation committed
    between the two reads would be recorded as sent without being in what was
    sent, and this worker would never send it.
    """
    from accounts import revocation_feed

    global _sent_generation, _sent_at
    generation = revocation_feed.generation()
    with _lock:
        if (generation == _sent_generation
                and time.time() - _sent_at < REVOKED_RESEND_SECONDS):
            return
    ids = [_b64(c) for c in revocation_feed.revoked_ids()]
    # The signer takes a capped number of new ids a call and says how many
    # wait: send again until none do, a few times at most here. Whatever
    # is left goes with this worker's next send, which is not marked done
    # until the signer holds everything.
    for _ in range(PUT_REVOKED_ROUNDS):
        result = call("put_revoked", ids=ids)
        if not result.get("remaining"):
            break
    else:
        logger.warning("the signer still waits for %s revocations; they go "
                       "with the next send", result.get("remaining"))
        return
    with _lock:
        _sent_generation, _sent_at = generation, time.time()


def bundle(*, device_id: bytes, device_key_hash: bytes, epoch_keys: list,
           lease_seconds: int, chains=None) -> dict:
    """`chains`: did the phone asking say it follows issuer certificates? The
    signer's switch gate counts it ready for a certified deployment key
    only if it did. None when verify cannot tell."""
    args = {"device_id": _b64(device_id),
            "device_key_hash": _b64(device_key_hash),
            "epoch_keys": epoch_keys, "lease_seconds": lease_seconds}
    if chains is not None:
        args["chains"] = bool(chains)
    return call("bundle", **args)


def feed() -> dict:
    return call("feed")


def statement(*, log_key_id: int, public_key: bytes) -> dict:
    return call("statement", log_key_id=log_key_id, public_key=_b64(public_key))


def log_ack(*, device_id: bytes, through_seq: int, digest: bytes) -> dict:
    """The signer's acknowledgement of a phone's log upload."""
    return call("log_ack", device_id=_b64(device_id), through_seq=through_seq,
                digest=_b64(digest))


def sync_time(*, device_id: bytes, nonce: bytes) -> dict:
    """The signer's time at a phone's sync, over its nonce."""
    return call("sync_time", device_id=_b64(device_id), nonce=_b64(nonce))


def pause(context: str, reason: str = "") -> dict:
    return call("pause", context=context, reason=reason)


def suspend(key_id: int, operator: str = "") -> dict:
    """Stop a key's credentials at once. `operator` names the site admin who
    asked, for the signer's ledger and alert."""
    args = {"operator": operator} if operator else {}
    result = call("suspend", key_id=key_id, **args)
    public(force=True)
    return result


def install_cert(key_id: int, leaf_der: bytes) -> dict:
    result = call("install_cert", key_id=key_id, leaf=_b64(leaf_der))
    public(force=True)
    return result


def org_generate(signing_id, name: str) -> dict:
    """A key for an organization, certified at once by the Organization CA."""
    result = call("org_generate", organization=str(signing_id), name=name)
    public(force=True)
    return result


def org_keygen(signing_id) -> dict:
    """A key for an organization, and its request for the PKI."""
    result = call("org_keygen", organization=str(signing_id))
    public(force=True)
    return result


def csr(key_id: int) -> str:
    """The PEM request of an organization key waiting for the PKI."""
    return call("csr", key_id=key_id)["csr"]


def discard(key_id: int) -> dict:
    result = call("discard", key_id=key_id)
    public(force=True)
    return result


def org_publish(key_id: int, operator: str) -> dict:
    """Publish an organization's certified key, where the host allows it."""
    result = call("org_publish", key_id=key_id, operator=operator)
    public(force=True)
    return result


def org_activate(key_id: int, operator: str) -> dict:
    """Start an organization's published key signing, where the host allows
    it and once its phones have it."""
    result = call("org_activate", key_id=key_id, operator=operator)
    public(force=True)
    return result


def site_withdraw(key_id: int, operator: str) -> dict:
    """Withdraw a key at once, where the signer's policy sets
    `site_controls_all_keys`; refused otherwise."""
    result = call("site_withdraw", key_id=key_id, operator=operator)
    public(force=True)
    return result


def site_unsuspend(key_id: int, operator: str) -> dict:
    """Lift a key's suspension, where `site_controls_all_keys` is set."""
    result = call("site_unsuspend", key_id=key_id, operator=operator)
    public(force=True)
    return result


def site_resume(context: str, operator: str) -> dict:
    """Lift a pause, where `site_controls_all_keys` is set."""
    return call("site_resume", context=context, operator=operator)


def site_controls_all_keys() -> bool:
    """Does the signer's own policy let any site admin do every key action
    from here? Its word, from `public()`; no signer, or none answering, is
    no. Nothing in verify can make it yes."""
    if not enabled():
        return False
    try:
        return bool(public().get("site_controls_all_keys"))
    except SignerError:
        return False


def status() -> dict:
    return call("status")
