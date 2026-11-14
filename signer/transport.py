"""Two UNIX sockets, and who may say what on each.

* The **app socket** carries verify's requests. Only the gunicorn user
  (`app_user`) may connect, checked with SO_PEERCRED, and only the app
  operations are answered: nothing on it can resume, unsuspend, withdraw, or
  publish or activate a deployment key. It can publish and start an
  organization's key (`SITE_ONLY_OPS`), refused unless the host's policy sets
  `site_publishes_organization_keys`. Where it sets `site_controls_all_keys`,
  the same route also publishes and starts the deployment's keys, and
  withdraws, unsuspends and resumes, under the site admin's name. A poll-mode
  signer has no app socket: it collects verify's requests from the site and
  answers each here, exactly as this socket would, as the app
  (`signer/poll.py`). The HMAC on the poll stands in for SO_PEERCRED.
* The **admin socket** is for `cl03signer`, run by an operator in the
  `cl03-operators` group, by root or by the signer's own user, as the system
  says at each connection. The peer's own user name is what the ledger
  records as `by`, which is what makes "a second, different operator" mean
  something -- procedurally, since root can be anyone.

No TCP port is opened, in either mode. Frames are a 4-byte big-endian length
and JSON; bytes travel as base64.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import socket
import socketserver
import struct
import threading
import time

from .service import Refused

MAX_FRAME = 4 * 1024 * 1024

#: A key id travels as a u32 (credential key_id, trust entries): an admin
#: command naming anything else is refused before it reaches the registry.
#: The highest u32 is no key's: it is the trust entry that binds a bundle's
#: chains (``bundle.CHAINS_DIGEST_ID``).
KEY_ID_MAX = 2 ** 32 - 2

#: Seconds between full tracebacks of internal failures in the journal; the
#: ones in between are a line each, with the count.
LOG_TRACEBACK_EVERY = 60

logger = logging.getLogger("cl03-signer")

APP_OPS = {"sign_credential", "bundle", "put_revoked", "feed", "statement",
           "log_ack", "sync_time", "pause", "suspend", "install_cert",
           "status", "public",
           # organization keys, from verify's pages: made and certified;
           # published and switched in only where the host's policy lets
           # the site (`site_publishes_organization_keys`)
           "org_keygen", "org_generate", "csr", "discard", "org_publish",
           "org_activate",
           # every key, where the host's policy lets the site
           # (`site_controls_all_keys`)
           "site_withdraw", "site_unsuspend", "site_resume"}
#: verify's own route to publish and start an organization's key, under the
#: site admin's name -- and, where `site_controls_all_keys` is set, any key,
#: and to withdraw, unsuspend and resume. Not answered on the admin socket:
#: there one operator publishes or withdraws and a second confirms, and these
#: would let one operator do both alone, under whatever name they typed.
SITE_ONLY_OPS = {"org_publish", "org_activate", "site_withdraw",
                 "site_unsuspend", "site_resume"}
ADMIN_OPS = (APP_OPS - SITE_ONLY_OPS) | {
    "keygen", "publish", "confirm", "withdraw", "activate", "retire",
    "unsuspend", "resume", "legacy_end", "revoked_remove", "ca_keygen",
    "ca_install", "ca_withdraw"}
#: Frequent operations; every other one is a key or admin event, and the
#: ledger is shipped as soon as it is done.
ROUTINE_OPS = {"sign_credential", "bundle", "put_revoked", "feed", "statement",
               "log_ack", "sync_time", "status", "public", "csr"}


def _b(value) -> bytes:
    return base64.b64decode(value) if value else b""


def _key_id(value) -> int:
    """A key id an operator or verify named: a whole number a credential
    could carry, or a bad request."""
    if isinstance(value, bool) or not isinstance(value, int):
        try:
            value = int(str(value), 10)
        except ValueError:
            raise ValueError("a key id is a whole number") from None
    if not 0 < value <= KEY_ID_MAX:
        raise ValueError("a key id is from 1 to %d" % KEY_ID_MAX)
    return value


class Dispatcher:
    """Request dict -> response dict. The same code behind both sockets."""

    def __init__(self, service, after_event=None, clock=time.monotonic,
                 status_extra=None):
        self.svc = service
        self.after_event = after_event or (lambda op: None)
        self.clock = clock
        #: More for `status` to say, as {name: callable}: a poll-mode
        #: signer's link to the site (`poll.Poller.state`).
        self.status_extra = dict(status_extra or {})
        #: Internal failures in a row, per operation, and the last one: what
        #: `status` and the heartbeat say, so a signer refusing something is
        #: not silent. Per operation, so that phones' syncs going through do
        #: not hide credentials failing, and nobody asking for `status`
        #: resets what it is asked to show.
        self.failing_by_op = {}
        self.last_failure = None
        self._logged_at = None
        self._count_lock = threading.Lock()

    @property
    def failing(self) -> int:
        """The longest run of internal failures any operation is in now."""
        return max(self.failing_by_op.values(), default=0)

    def _failed(self, op, exc):
        with self._count_lock:
            self.failing_by_op[op] = self.failing_by_op.get(op, 0) + 1
            failing = self.failing_by_op[op]
            self.last_failure = {"op": op, "error": type(exc).__name__,
                                 "in_a_row": failing}
            now = self.clock()
            full = (self._logged_at is None
                    or now - self._logged_at >= LOG_TRACEBACK_EVERY)
            if full:
                self._logged_at = now
        if full:
            logger.exception("internal failure in %s (%d in a row)", op, failing)
        else:
            logger.error("internal failure in %s: %s (%d in a row)", op,
                         type(exc).__name__, failing)

    def _succeeded(self, op):
        if op in self.failing_by_op:
            with self._count_lock:
                self.failing_by_op.pop(op, None)

    def handle(self, request: dict, *, admin: bool, by: str) -> dict:
        op = request.get("op", "")
        args = request.get("args") or {}
        if op not in (ADMIN_OPS if admin else APP_OPS):
            return {"ok": False, "reason": "forbidden",
                    "detail": "%r is not answered on this socket" % op}
        try:
            result = self._call(op, args, by if admin else "app")
        except Refused as exc:
            return {"ok": False, "reason": exc.reason, "detail": exc.detail,
                    "extra": exc.extra}
        except (KeyError, TypeError, ValueError) as exc:
            return {"ok": False, "reason": "bad_request", "detail": str(exc)}
        except Exception as exc:
            # Whatever it was, its transaction has rolled back (`Store`); the
            # caller hears a refusal, and the socket keeps serving. The
            # journal hears all of it, and the count reaches `status` and the
            # heartbeat.
            self._failed(op, exc)
            return {"ok": False, "reason": "internal",
                    "detail": type(exc).__name__}
        self._succeeded(op)
        if op == "status" and isinstance(result, dict):
            result = dict(result, internal_failures={
                "in_a_row": self.failing, "by_op": dict(self.failing_by_op),
                "last": self.last_failure})
            for name, said in self.status_extra.items():
                result[name] = said()
        if op not in ROUTINE_OPS:
            try:
                self.after_event(op)
            except Exception:
                # The change is committed; its ledger rows ship with the next
                # event or the reconciler, and Setup shows the ledger behind.
                # Answering anyway keeps verify from saying nothing changed.
                logging.getLogger("cl03-signer").exception(
                    "shipping the ledger after %s failed", op)
        return {"ok": True, "result": result}

    def _call(self, op, a, by):
        s = self.svc
        if op == "sign_credential":
            return s.sign_credential(_b(a["message"]),
                                     organization=a.get("organization"),
                                     operator=a.get("operator", ""),
                                     holder=bool(a.get("holder")),
                                     holder_id=str(a.get("holder_id") or ""))
        if op == "bundle":
            chains = a.get("chains")
            if chains is not None and not isinstance(chains, bool):
                raise ValueError("chains is true, false or absent")
            return s.bundle(device_id=_b(a["device_id"]),
                            device_key_hash=_b(a.get("device_key_hash")),
                            epoch_keys=a.get("epoch_keys", []),
                            lease_seconds=int(a["lease_seconds"]),
                            chains=chains)
        if op == "put_revoked":
            return s.put_revoked([_b(c) for c in a.get("ids", [])])
        if op == "feed":
            return s.feed()
        if op == "statement":
            return s.statement(log_key_id=int(a["log_key_id"]),
                               public_key=_b(a["public_key"]))
        if op == "log_ack":
            return s.log_ack(device_id=_b(a["device_id"]),
                             through_seq=int(a["through_seq"]),
                             digest=_b(a["digest"]))
        if op == "sync_time":
            return s.sync_time(device_id=_b(a["device_id"]), nonce=_b(a["nonce"]))
        if op == "pause":
            return s.pause(a["context"], by=by, reason=a.get("reason", ""))
        if op == "suspend":
            # The site admin who asked, from verify's pages; an operator on
            # the host is named by the socket instead.
            return s.suspend(_key_id(a["key_id"]), by=by,
                             operator=(a.get("operator") if by == "app"
                                       else None))
        if op == "install_cert":
            return s.install_cert(_key_id(a["key_id"]), _b(a["leaf"]), by=by)
        if op == "status":
            return s.status()
        if op == "public":
            return s.public()
        if op == "keygen":
            return s.keygen(organization=a.get("organization"), by=by)
        if op == "org_keygen":
            return s.org_keygen(organization=a["organization"], by=by)
        if op == "org_generate":
            return s.org_generate(organization=a["organization"],
                                  name=a["name"], by=by)
        if op == "csr":
            return s.csr(_key_id(a["key_id"]))
        if op == "discard":
            return s.discard(_key_id(a["key_id"]), by=by)
        if op in ("org_publish", "org_activate", "site_withdraw",
                  "site_unsuspend"):
            return getattr(s, op)(_key_id(a["key_id"]),
                                  operator=a.get("operator", ""), by=by)
        if op == "site_resume":
            return s.site_resume(str(a["context"]),
                                 operator=a.get("operator", ""), by=by)
        if op == "ca_keygen":
            return s.ca_keygen(by=by)
        if op == "ca_install":
            ca_id = a.get("ca_id")
            return s.ca_install(None if ca_id is None else int(ca_id),
                                _b(a["cert"]), by=by)
        if op == "ca_withdraw":
            return s.ca_withdraw(_key_id(a["ca_id"]), by=by)
        if op in ("publish", "withdraw", "activate", "retire", "unsuspend",
                  "legacy_end"):
            return getattr(s, op)(_key_id(a["key_id"]), by=by)
        if op == "confirm":
            return s.confirm(int(a["confirmation"]), by=by)
        if op == "resume":
            return s.resume(a["context"], by=by)
        if op == "revoked_remove":
            return s.revoked_remove([_b(c) for c in a["ids"]], by=by)
        raise ValueError("unknown op %r" % op)


# -- framing ---------------------------------------------------------------

def send_frame(sock, obj) -> None:
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_frame(sock):
    head = _recv_exact(sock, 4)
    if head is None:
        return None
    (length,) = struct.unpack(">I", head)
    if length > MAX_FRAME:
        raise ValueError("frame too large")
    body = _recv_exact(sock, length)
    return json.loads(body) if body is not None else None


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


# -- the peer --------------------------------------------------------------

def peer_uid(sock) -> int:
    """The connecting process's uid, from the kernel. Linux only."""
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                            struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", creds)
    return uid


def user_name(uid: int) -> str:
    import pwd
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return "uid%d" % uid


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        uid = peer_uid(self.request)
        if not server.allowed(uid):
            send_frame(self.request, {"ok": False, "reason": "forbidden",
                                      "detail": "uid %d" % uid})
            return
        by = user_name(uid)
        while True:
            try:
                request = recv_frame(self.request)
            except ValueError:
                return
            if request is None:
                return
            send_frame(self.request, server.dispatcher.handle(
                request, admin=server.admin, by=by))


if hasattr(socketserver, "UnixStreamServer"):       # not on Windows

    class SocketServer(socketserver.ThreadingMixIn,
                       socketserver.UnixStreamServer):
        daemon_threads = True

        def __init__(self, path, dispatcher, *, admin: bool, allowed):
            if os.path.exists(path):
                os.unlink(path)
            self.dispatcher = dispatcher
            self.admin = admin
            self.allowed = allowed
            super().__init__(path, _Handler)


def call(path: str, op: str, **args):
    """One request on a socket. Raises Refused with the signer's reason."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(path)
        send_frame(sock, {"op": op, "args": args})
        reply = recv_frame(sock)
    finally:
        sock.close()
    if reply is None:
        raise Refused("unavailable", "no reply")
    if not reply.get("ok"):
        raise Refused(reply.get("reason", "error"), reply.get("detail", ""),
                      **(reply.get("extra") or {}))
    return reply["result"]
