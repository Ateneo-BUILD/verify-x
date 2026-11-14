"""The signer's runtime: who may ask what, shipping, rollback, reconciling."""

import base64
import json
import os
import re
import shutil
import socket
import sqlite3
import threading
import time
import unittest
import uuid

from signer import aws, ledger, loop, reconcile, transport
from signer.store import Store

from .helpers import DAY, SignerTest


class DispatcherTest(SignerTest):

    def setUp(self):
        super().setUp()
        self.events = []
        self.d = transport.Dispatcher(self.svc, after_event=self.events.append)

    def test_the_app_socket_cannot_widen_or_restore_trust(self):
        for op in ("keygen", "publish", "confirm", "activate", "withdraw",
                   "resume", "unsuspend", "retire", "legacy_end",
                   "revoked_remove"):
            reply = self.d.handle({"op": op, "args": {}}, admin=False, by="x")
            self.assertEqual(reply["reason"], "forbidden", op)

    def test_the_app_may_reduce(self):
        reply = self.d.handle({"op": "pause", "args": {"context": "bundle"}},
                              admin=False, by="whoever")
        self.assertTrue(reply["ok"])
        self.assertEqual(self.events, ["pause"])
        row = self.store.one("SELECT * FROM pauses")
        self.assertEqual(row["by"], "app")       # the app cannot claim a name

    def test_the_admin_socket_records_the_operator(self):
        reply = self.d.handle({"op": "keygen", "args": {}}, admin=True,
                              by="alice")
        self.assertTrue(reply["ok"])
        row = self.store.one("SELECT summary FROM ledger WHERE kind = 'key'")
        self.assertEqual(json.loads(row["summary"])["by"], "alice")

    def test_a_refusal_carries_its_reason(self):
        self.ready()
        reply = self.d.handle({"op": "sign_credential", "args": {
            "message": base64.b64encode(b"not a credential").decode()}},
            admin=False, by="x")
        self.assertEqual(reply["reason"], "policy")

    def test_routine_signing_does_not_trigger_shipping(self):
        self.ready()
        self.events.clear()
        message = self.credential(16)
        reply = self.d.handle({"op": "sign_credential", "args": {
            "message": base64.b64encode(message).decode()}},
            admin=False, by="x")
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(self.events, [])

    def test_frames_round_trip(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        transport.send_frame(a, {"op": "status", "args": {"x": [1, 2]}})
        self.assertEqual(transport.recv_frame(b),
                         {"op": "status", "args": {"x": [1, 2]}})


@unittest.skipUnless(hasattr(socket, "AF_UNIX")
                     and hasattr(socket, "SO_PEERCRED"),
                     "SO_PEERCRED is Linux-only")
class UnixSocketTest(SignerTest):

    def test_an_unlisted_uid_is_refused_and_a_listed_one_answered(self):
        import threading

        path = os.path.join(self.dir, "app.sock")
        d = transport.Dispatcher(self.svc)
        server = transport.SocketServer(path, d, admin=False,
                                        allowed=lambda uid: uid == os.getuid())
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        self.assertIn("pauses", transport.call(path, "status"))
        server.allowed = lambda uid: False
        with self.assertRaises(transport.Refused) as err:
            transport.call(path, "status")
        self.assertEqual(err.exception.reason, "forbidden")

    def test_the_admin_socket_names_the_peer_whatever_the_frame_says(self):
        """The two-operator rule rests on this name: it is the connecting
        account's, from SO_PEERCRED, and a frame's own `by` is ignored."""
        import json
        import pwd
        import threading

        path = os.path.join(self.dir, "admin.sock")
        d = transport.Dispatcher(self.svc)
        server = transport.SocketServer(path, d, admin=True,
                                        allowed=lambda uid: uid == os.getuid())
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(path)
            transport.send_frame(conn, {"op": "keygen", "by": "mallory",
                                        "args": {"by": "mallory"}})
            reply = transport.recv_frame(conn)
        self.assertTrue(reply["ok"], reply)
        row = self.store.one("SELECT summary FROM ledger WHERE kind = 'key' "
                             "ORDER BY seq DESC LIMIT 1")
        self.assertEqual(json.loads(row["summary"])["by"],
                         pwd.getpwuid(os.getuid()).pw_name)


class ShipperTest(SignerTest):

    def setUp(self):
        super().setUp()
        self.up = aws.FakeUploader()
        self.ship = aws.Shipper(self.store, self.up, "dev-site", self.clock)

    def test_rows_ship_once(self):
        self.ready()
        n = self.ship.ship()
        self.assertGreater(n, 0)
        self.assertEqual(self.ship.ship(), 0)
        self.svc.keygen(by="alice")
        self.assertEqual(self.ship.ship(), 1)
        self.assertEqual(len(self.up.objects), 2)

    def test_a_restored_older_database_refuses_to_start(self):
        """An old image must not bring back a withdrawn key."""
        self.ready()
        self.ship.ship()
        snapshot = os.path.join(self.dir, "old.db")
        self.store.db.execute("VACUUM INTO ?", (snapshot,))
        self.svc.keygen(by="alice")
        self.ship.ship()
        old = Store(snapshot)
        self.addCleanup(old.db.close)
        with self.assertRaises(aws.Rollback) as err:
            aws.Shipper(old, self.up, "dev-site", self.clock).check_rollback()
        # Said as what it is, a ledger that stops short of the bucket.
        self.assertIn("ends at", str(err.exception))
        self.ship.check_rollback()          # the live one is fine

    def test_a_rewritten_row_is_caught_at_start(self):
        self.ready()
        self.ship.ship()
        self.store.db.execute("UPDATE ledger SET hash = 'x' WHERE seq = "
                              "(SELECT MAX(seq) FROM ledger)")
        with self.assertRaises(aws.Rollback):
            self.ship.check_rollback()

    def test_shipped_rows_verify_as_a_chain(self):
        self.ready()
        self.ship.ship()
        rows = [json.loads(line) for body in self.up.objects.values()
                for line in body.decode().splitlines()]
        self.assertEqual(ledger.verify_chain(rows), len(rows))


class ReconcileTest(SignerTest):

    def setUp(self):
        super().setUp()
        self.key = self.ready()
        self.cid = str(uuid.UUID(bytes=bytes(16)))

    def _signed(self):
        message = self.credential(self.key, credential_id=uuid.UUID(self.cid))
        self.svc.sign_credential(message)

    def _find(self, report):
        return reconcile.findings(self.store, report,
                                  now=self.clock.now(), since=0)

    def test_signed_but_never_recorded(self):
        self._signed()
        self.clock.advance(3600)
        found = self._find({"credentials": [], "scans": []})
        self.assertIn("signed, never recorded", [m for _, m, _ in found])

    def test_a_fresh_signature_has_a_grace_period(self):
        self._signed()
        self.assertEqual(self._find({"credentials": [], "scans": []}), [])

    def test_still_pending_counts_as_never_recorded(self):
        self._signed()
        self.clock.advance(3600)
        found = self._find({"credentials": [{"credential_id": self.cid,
                                             "state": "pending",
                                             "issuer_key_id": self.key}]})
        self.assertIn("signed, never recorded", [m for _, m, _ in found])

    def test_recorded_but_never_signed_here(self):
        found = self._find({"credentials": [{
            "credential_id": str(uuid.uuid4()), "state": "signed",
            "issuer_key_id": self.key}], "scans": []})
        self.assertIn("recorded but never signed here", [m for _, m, _ in found])

    def test_a_genuine_scan_of_an_unsigned_id_is_a_forgery(self):
        found = self._find({"credentials": [], "scans": [{
            "credential_id": str(uuid.uuid4()), "verdict": "valid",
            "issuer_key": self.key}]})
        self.assertEqual(found[0][0], "highest")

    def test_key_1_is_never_checked(self):
        """The PEM era has no ledger rows; nothing about it is an alarm."""
        found = self._find({"credentials": [{
            "credential_id": str(uuid.uuid4()), "state": "signed",
            "issuer_key_id": 1}], "scans": [{
            "credential_id": str(uuid.uuid4()), "verdict": "valid",
            "issuer_key": 1}]})
        self.assertEqual(found, [])



class ShipUnderLockTest(SignerTest):

    def setUp(self):
        super().setUp()
        self.up = aws.FakeUploader()
        self.ship = aws.Shipper(self.store, self.up, "dev-site", self.clock)

    def test_a_ship_never_sees_a_row_that_rolls_back(self):
        self.ready()
        self.ship.ship()
        started, release = threading.Event(), threading.Event()

        def writer():
            try:
                with self.store as db:
                    ledger.append(db, at=self.clock.now(), kind="admin",
                                  context="probe", summary={})
                    started.set()
                    release.wait(5)
                    raise RuntimeError("rolled back")
            except RuntimeError:
                pass

        thread = threading.Thread(target=writer)
        thread.start()
        started.wait(5)
        shipped = []
        shipping = threading.Thread(target=lambda: shipped.append(self.ship.ship()))
        shipping.start()
        shipping.join(0.3)
        release.set()
        thread.join(5)
        shipping.join(5)
        self.assertEqual(shipped, [0])
        uploaded = [json.loads(line) for body in self.up.objects.values()
                    for line in body.decode().splitlines()]
        self.assertNotIn("probe", [row["context"] for row in uploaded])


class DispatcherFailureTest(SignerTest):

    def test_an_unexpected_error_is_a_refusal_and_rolls_back(self):
        self.ready()
        head = ledger.head(self.store)

        def broken(**_kwargs):
            def run(db, now):
                ledger.append(db, at=now, kind="admin", context="half",
                              summary={})
                raise RuntimeError("a bug")
            return self.svc._run(run)

        self.svc.feed = broken
        reply = transport.Dispatcher(self.svc).handle(
            {"op": "feed", "args": {}}, admin=False, by="x")
        self.assertEqual(reply["reason"], "internal")
        self.assertEqual(ledger.head(self.store), head)


class ReconcileRunTest(SignerTest):

    def setUp(self):
        super().setUp()
        self.key = self.ready()

    def test_the_baseline_runs_without_the_report(self):
        for _ in range(20):
            self.clock.advance(61)
            self.sign_ok(self.key)
        sent = []

        def fetch(_since):
            raise RuntimeError("report: HTTP 500")

        found = reconcile.run(self.store, fetch, lambda *a: sent.append(a),
                              now=self.clock.now())
        self.assertIn("signing well above its baseline", [m for _, m, _ in found])
        self.assertEqual(len(sent), len(found))

    def test_a_report_that_stops_coming_is_an_alert(self):
        def parked(_since):
            raise reconcile.Parked()

        for _ in range(reconcile.FAILURES_BEFORE_ALERT - 1):
            found = reconcile.run(self.store, parked, lambda *a: None,
                                  now=self.clock.now())
            self.assertEqual(found, [])
        found = reconcile.run(self.store, parked, lambda *a: None,
                              now=self.clock.now())
        self.assertEqual([s for s, m, _ in found if "unavailable" in m], ["high"])
        reconcile.run(self.store, lambda _since: {"credentials": [], "scans": []},
                      lambda *a: None, now=self.clock.now())
        self.assertEqual(self.store.meta("report_failures"), "0")


class LoopTest(unittest.TestCase):

    def test_a_stop_during_a_ship_ends_with_one_more_ship(self):
        lock = threading.Lock()
        stop, handler = loop.stopper()
        calls = []

        def ship():
            if not lock.acquire(timeout=2):
                raise AssertionError("the stop handler re-entered the ship")
            try:
                calls.append("ship")
                if len(calls) == 1:
                    handler()           # SIGTERM arrives mid-ship
            finally:
                lock.release()

        started = time.monotonic()
        loop.periodic(ship, lambda: None, stop, every=60)
        self.assertEqual(calls, ["ship", "ship"])
        self.assertLess(time.monotonic() - started, 5)


class DeployUnitTest(unittest.TestCase):

    def test_verify_and_operators_can_reach_their_sockets(self):
        path = os.path.join(os.path.dirname(__file__), "..", "deploy",
                            "cl03-signer.service")
        with open(path, encoding="utf-8") as handle:
            mode = re.search(r"^RuntimeDirectoryMode=(\d+)", handle.read(),
                             re.M).group(1)
        self.assertTrue(int(mode, 8) & 0o001)

    def test_the_signer_is_in_the_groups_it_gives_its_sockets(self):
        """chown to a group the process is not in fails, and the signer
        would not start."""
        here = os.path.join(os.path.dirname(__file__), "..", "deploy")
        with open(os.path.join(here, "cl03-signer.service"),
                  encoding="utf-8") as handle:
            groups = re.search(r"^SupplementaryGroups=(.+)$", handle.read(),
                               re.M).group(1).split()
        self.assertEqual(sorted(groups), ["cl03-operators", "cl03-signer-app"])
        with open(os.path.join(here, "install.sh"), encoding="utf-8") as handle:
            script = handle.read()
        self.assertIn("groupadd --system cl03-signer-app", script)
        self.assertIn('usermod -aG cl03-signer-app "$APP_USER"', script)

    def test_the_venv_is_made_with_a_python_that_has_tomllib(self):
        """Amazon Linux 2023's python3 is 3.9: config.load would fail at the
        first start."""
        with open(os.path.join(os.path.dirname(__file__), "..", "deploy",
                               "install.sh"), encoding="utf-8") as handle:
            script = handle.read()
        self.assertIn("sys.exit(sys.version_info < (3, 11))", script)
        self.assertIn('"$PY" -m venv /opt/cl03-signer/venv', script)
        self.assertNotIn("python3 -m venv", script)
