"""The signer's operating safety.

A failed BEGIN or COMMIT leaves the store unlocked and out of any
transaction. Internal failures reach the journal, `status` and the
heartbeat. A start that is refused says so once and stays down, and `check`
tries a start first. Operator membership is read at every connection.
`unsuspend` and every admin key id are checked. The reconciler compares
only what verify's report covers. The units are sandboxed, and install.sh
restarts a running signer.
"""

import base64
import hashlib
import io
import json
import logging
import os
import re
import sqlite3
import threading
import unittest
from types import SimpleNamespace

from signer import aws, reconcile, registry, startup
from signer.service import Refused
from signer.store import Store
from signer.transport import KEY_ID_MAX, Dispatcher, _key_id

from .helpers import DAY, LEGACY_KEY, SITE, T0, SignerTest, spki_of

HERE = os.path.dirname(__file__)
DEPLOY = os.path.join(HERE, "..", "deploy")


def _read(*parts):
    with open(os.path.join(DEPLOY, *parts), encoding="utf-8") as handle:
        return handle.read()


class _FailingCommit:
    """The store's connection, with COMMIT failing as a full disk would."""

    def __init__(self, real):
        self.real = real

    def execute(self, sql, *args):
        if sql == "COMMIT":
            raise sqlite3.OperationalError("disk I/O error")
        return self.real.execute(sql, *args)

    def __getattr__(self, name):
        return getattr(self.real, name)


class StoreLockTest(SignerTest):

    def _lock_is_free(self, store):
        """Can another thread -- another request -- take the lock now? It is
        an RLock, so it is released by the thread that took it."""
        got = []

        def take():
            acquired = store.lock.acquire(timeout=2)
            got.append(acquired)
            if acquired:
                store.lock.release()
        thread = threading.Thread(target=take)
        thread.start()
        thread.join()
        return got == [True]

    def test_a_begin_that_fails_gives_the_lock_back(self):
        store = Store(os.path.join(self.dir, "busy.db"), busy_timeout=0.05)
        self.addCleanup(store.db.close)
        other = sqlite3.connect(os.path.join(self.dir, "busy.db"),
                                isolation_level=None)
        self.addCleanup(other.close)
        other.execute("BEGIN IMMEDIATE")      # another process writing
        with self.assertRaises(sqlite3.OperationalError):
            with store:
                pass
        self.assertTrue(self._lock_is_free(store))
        other.execute("ROLLBACK")
        with store as db:
            db.execute("INSERT INTO meta (name, value) VALUES ('x', '1')")
        self.assertEqual(store.meta("x"), "1")

    def test_a_commit_that_fails_is_rolled_back_and_unlocked(self):
        store = Store(os.path.join(self.dir, "full.db"))
        self.addCleanup(store.db.close)
        real = store.db
        store.db = _FailingCommit(real)
        with self.assertRaises(sqlite3.OperationalError):
            with store as db:
                db.execute("INSERT INTO meta (name, value) VALUES ('y', '1')")
        self.assertFalse(real.in_transaction)
        self.assertTrue(self._lock_is_free(store))
        store.db = real
        self.assertIsNone(store.meta("y"))

    def test_an_error_after_sqlite_ended_the_transaction_is_the_one_raised(self):
        """SQLite can end a transaction itself (a full disk); the ROLLBACK
        that follows then fails, and must not hide what went wrong."""
        store = Store(os.path.join(self.dir, "ended.db"))
        self.addCleanup(store.db.close)
        with self.assertRaises(ZeroDivisionError):
            with store as db:
                db.execute("ROLLBACK")
                1 / 0
        self.assertTrue(self._lock_is_free(store))

    def test_the_wait_is_said_not_assumed(self):
        from signer import store as store_mod
        self.assertEqual(store_mod.BUSY_TIMEOUT, 5.0)


class _Broken:
    """A service whose feed fails and whose status answers."""

    def __init__(self):
        self.fail = True

    def feed(self):
        if self.fail:
            raise sqlite3.OperationalError("database disk image is malformed")
        return {"feed": "ok"}

    def status(self):
        return {"now": 1}

    def public(self):
        """Fails the first time, then answers."""
        if not getattr(self, "public_failed", False):
            self.public_failed = True
            raise sqlite3.OperationalError("database is locked")
        return {"keys": []}


class InternalFailureTest(unittest.TestCase):

    def setUp(self):
        self.now = [1000.0]
        self.svc = _Broken()
        self.dispatcher = Dispatcher(self.svc, clock=lambda: self.now[0])

    def _feed(self):
        return self.dispatcher.handle({"op": "feed"}, admin=False, by="app")

    def test_each_failure_is_in_the_journal_and_counted(self):
        with self.assertLogs("cl03-signer", logging.ERROR) as logs:
            first = self._feed()
            second = self._feed()
        self.assertEqual(first["reason"], "internal")
        self.assertEqual(self.dispatcher.failing, 2)
        self.assertIn("Traceback", logs.output[0])
        self.assertIn("internal failure in feed", logs.output[0])
        self.assertNotIn("Traceback", logs.output[1])
        self.assertIn("2 in a row", logs.output[1])
        self.assertEqual(second["detail"], "OperationalError")

    def test_the_traceback_comes_back_after_a_minute(self):
        with self.assertLogs("cl03-signer", logging.ERROR) as logs:
            self._feed()
            self.now[0] += 61
            self._feed()
        self.assertIn("Traceback", logs.output[1])

    def test_status_says_so_and_asking_does_not_reset_it(self):
        with self.assertLogs("cl03-signer", logging.ERROR):
            self._feed()
            self._feed()
        status = self.dispatcher.handle({"op": "status"}, admin=True, by="alice")
        failures = status["result"]["internal_failures"]
        self.assertEqual(failures["in_a_row"], 2)
        self.assertEqual(failures["by_op"], {"feed": 2})
        self.assertEqual(failures["last"]["op"], "feed")
        self.assertEqual(self.dispatcher.failing, 2)

    def test_other_operations_going_through_do_not_hide_it(self):
        with self.assertLogs("cl03-signer", logging.ERROR):
            self._feed()
        self.dispatcher.handle({"op": "status"}, admin=False, by="app")
        self.assertEqual(self.dispatcher.failing, 1)

    def test_one_operation_recovering_leaves_another_failing(self):
        with self.assertLogs("cl03-signer", logging.ERROR):
            self._feed()
            self.dispatcher.handle({"op": "public"}, admin=False, by="app")
        self.assertTrue(self.dispatcher.handle({"op": "public"}, admin=False,
                                               by="app")["ok"])
        self.assertEqual(self.dispatcher.failing_by_op, {"feed": 1})
        self.assertEqual(self.dispatcher.failing, 1)

    def test_its_own_success_resets_it(self):
        with self.assertLogs("cl03-signer", logging.ERROR):
            self._feed()
        self.svc.fail = False
        self.assertTrue(self._feed()["ok"])
        self.assertEqual(self.dispatcher.failing, 0)

    def test_the_heartbeat_sends_it(self):
        sent = []
        beat = object.__new__(aws.Heartbeat)
        beat.namespace, beat.site = "CL03Signer", "verify"
        beat.cw = SimpleNamespace(put_metric_data=lambda **kw: sent.append(kw))
        beat.beat(0, failing=3)
        metrics = {m["MetricName"]: m["Value"] for m in sent[0]["MetricData"]}
        self.assertEqual(metrics, {"Alive": 1.0, "Paused": 0.0, "Failing": 3.0})
        aws.NoHeartbeat().beat(0, failing=3)


class KeyIdTest(SignerTest):

    def test_unsuspend_refuses_a_key_that_does_not_exist(self):
        before = self.store.one("SELECT COUNT(*) AS n FROM ledger")["n"]
        with self.assertRaises(Refused) as err:
            self.svc.unsuspend(99999, by="alice")
        self.assertEqual(err.exception.reason, "unknown_key")
        self.assertEqual(self.store.one("SELECT COUNT(*) AS n FROM ledger")["n"], before)
        with self.store as db:
            self.assertLess(registry.allocate_key_id(db), 99999)

    def test_no_key_is_given_the_chains_digest_id(self):
        """The last u32 is the trust entry that binds a bundle's
        chains: allocation stops short of it."""
        from ovcrypto import bundle as bundle_mod

        with self.store as db:
            db.execute("INSERT INTO keys (key_id, organization, state, spki, "
                       "window_start, window_end, created_at) VALUES "
                       "(?, NULL, 'generated', ?, NULL, NULL, ?)",
                       (bundle_mod.CHAINS_DIGEST_ID - 2, b"spki", T0))
            self.assertEqual(registry.allocate_key_id(db),
                             bundle_mod.CHAINS_DIGEST_ID - 1)
            db.execute("INSERT INTO keys (key_id, organization, state, spki, "
                       "window_start, window_end, created_at) VALUES "
                       "(?, NULL, 'generated', ?, NULL, NULL, ?)",
                       (bundle_mod.CHAINS_DIGEST_ID - 1, b"spki", T0))
            with self.assertRaises(registry.RegistryError) as err:
                registry.allocate_key_id(db)
        self.assertEqual(err.exception.reason, "key_ids_exhausted")

    def test_a_trust_list_leaves_room_for_the_chains_digest(self):
        """255 entries at most, and the bundle adds one."""
        self.ready()
        listed = len(registry.trust_list(self.store, self.cfg,
                                          self.clock.now())[0])
        with self.store as db:
            for n in range(254 - listed):
                db.execute("INSERT INTO keys (key_id, organization, state, "
                           "spki, window_start, window_end, created_at) VALUES "
                           "(?, NULL, 'published', ?, ?, ?, ?)",
                           (1000 + n, b"spki-%d" % n, T0, T0 + 100 * DAY, T0))
        self.assertEqual(len(registry.trust_list(self.store, self.cfg,
                                                 self.clock.now())[0]), 254)
        with self.store as db:
            db.execute("INSERT INTO keys (key_id, organization, state, spki, "
                       "window_start, window_end, created_at) VALUES "
                       "(9999, NULL, 'published', ?, ?, ?, ?)",
                       (b"one more", T0, T0 + 100 * DAY, T0))
        with self.assertRaises(registry.RegistryError) as err:
            registry.trust_list(self.store, self.cfg, self.clock.now())
        self.assertEqual(err.exception.reason, "trust_list_full")

    def test_no_frame_names_its_own_operator(self):
        """The admin socket's `by` is the peer's account, read by the socket
        layer; a `by` in the frame or its arguments is never the operator,
        or one person could confirm their own change as a second."""
        import json

        d = Dispatcher(self.svc)
        got = d.handle({"op": "keygen", "by": "mallory",
                        "args": {"by": "mallory"}}, admin=True, by="alice")
        self.assertTrue(got["ok"], got)
        row = self.store.one("SELECT summary FROM ledger WHERE kind = 'key' "
                             "ORDER BY seq DESC LIMIT 1")
        self.assertEqual(json.loads(row["summary"])["by"], "alice")
        # The app socket is "app", whatever it says or the socket says: an
        # operation that records who did it, so a wrong name would show.
        got = d.handle({"op": "pause", "by": "alice",
                        "args": {"context": "credential", "by": "alice"}},
                       admin=False, by="alice")
        self.assertTrue(got["ok"], got)
        row = self.store.one("SELECT by FROM pauses WHERE context = 'credential'")
        self.assertEqual(row["by"], "app")

    def test_and_one_that_is_not_suspended(self):
        key_id = self.ready()
        with self.assertRaises(Refused):
            self.svc.unsuspend(key_id, by="alice")
        self.svc.suspend(key_id, by="app")
        self.assertEqual(self.svc.unsuspend(key_id, by="alice"),
                         {"unsuspended": key_id})

    def test_a_key_id_is_a_u32_or_a_bad_request(self):
        dispatcher = Dispatcher(self.svc)
        for value in ("abc", 0, -1, KEY_ID_MAX + 1, 2 ** 40, True, 1.5):
            with self.subTest(value=value):
                got = dispatcher.handle({"op": "unsuspend", "args": {"key_id": value}},
                                        admin=True, by="alice")
                self.assertEqual(got["reason"], "bad_request", got)
        self.assertEqual(_key_id("17"), 17)
        self.assertEqual(_key_id(KEY_ID_MAX), KEY_ID_MAX)
        # The last u32 is the trust entry binding a bundle's chains.
        self.assertEqual(KEY_ID_MAX, 2 ** 32 - 2)
        for value in (0, -1, KEY_ID_MAX + 1, True):
            with self.subTest(direct=value), self.assertRaises(ValueError):
                _key_id(value)


class CheckTest(SignerTest):

    def _policy(self, extra=""):
        keys = os.path.join(self.dir, "keys")
        os.makedirs(keys, exist_ok=True)
        anchor = os.path.join(self.dir, "anchor.der")
        with open(anchor, "wb") as handle:
            handle.write(self.ca_der)
        db = os.path.join(self.dir, "live.db")
        Store(db).db.close()
        path = os.path.join(self.dir, "policy.toml")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                'anchors = ["%s"]\nsite_domain = "%s"\n%s\n[runtime]\n'
                'db = "%s"\nkeys = "%s"\napp_socket = "a.sock"\n'
                'admin_socket = "b.sock"\napp_user = "verify-app"\n'
                'operators_group = "cl03-operators"\nledger_dir = "ledger"\n'
                % (anchor.replace("\\", "/"), SITE, extra,
                   db.replace("\\", "/"), keys.replace("\\", "/")))
        return path, db

    def _hash(self, path):
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()

    def test_a_good_policy_passes_and_nothing_is_written(self):
        path, db = self._policy()
        before = self._hash(db)
        self.assertEqual(startup.check(path), "")
        self.assertEqual(self._hash(db), before)

    def test_it_needs_only_to_read_the_live_database(self):
        """Opened read-only: a database it may not write is no obstacle,
        and SQLite's own housekeeping cannot touch the live one."""
        path, db = self._policy()
        os.chmod(db, 0o444)
        self.addCleanup(os.chmod, db, 0o600)
        self.assertEqual(startup.check(path), "")

    def test_a_typo_is_named(self):
        for extra, words in (('site_publishes_organization_keys = "true"', "unquoted"),
                             ('organization_ca_name = "Old"', "no longer read"),
                             ('site_domain = "not a domain"', "")):
            with self.subTest(extra=extra):
                path, _db = self._policy(extra if not extra.startswith("site_domain")
                                         else "")
                if extra.startswith("site_domain"):
                    with open(path, encoding="utf-8") as handle:
                        text = handle.read().replace(SITE, "not a domain")
                    with open(path, "w", encoding="utf-8") as handle:
                        handle.write(text)
                why = startup.check(path)
                self.assertTrue(why, extra)
                self.assertIn(words, why)

    def test_a_name_it_does_not_read_is_refused(self):
        """A misspelt setting was a default nobody chose, and in a ceiling
        an unlimited window."""
        for extra, words in (
                ("lease_second = 2592000", "policy.toml: lease_second"),
                ('[[ceilings]]\ncontext = "credential"\nprincipal = "operator"\n'
                 "per_minutes = 1", "[[ceilings]]: per_minutes"),
                ('[[legacy]]\nkey_id = 1\nspki = ""\nnot_before = 0\n'
                 "not_after = 1\nnot_afer = 2", "[[legacy]]: not_afer"),
                ('[[held]]\nkey_id = 1\nkey_file = "k.pem"\nspki = ""\n'
                 "not_before = 0\nsigning_until = 1\nsigning_untill = 2",
                 "[[held]]: signing_untill")):
            with self.subTest(extra=extra):
                path, _db = self._policy(extra)
                self.assertIn(words, startup.check(path))
        path, _db = self._policy()
        with open(path, "a", encoding="utf-8") as handle:
            handle.write('report_hots = "verify.example.ph"\n')
        self.assertIn("[runtime]: report_hots", startup.check(path))

    def test_a_ceiling_names_one_the_signer_counts_in_whole_numbers(self):
        from signer import config as cfgmod
        for entry, words in (
                ('context = "credentials"\nprincipal = "operator"\nper_minute = 1',
                 "no ceiling for context"),
                ('context = "credential"\nprincipal = "device"\nper_minute = 1',
                 "no ceiling for context"),
                ('context = "credential"\nprincipal = "operator"\nper_minute = "10"',
                 "per_minute is a whole number"),
                ('context = "credential"\nprincipal = "operator"\nper_day = -1',
                 "per_day is a whole number"),
                ('context = "credential"\nprincipal = "operator"\nper_hour = true',
                 "per_hour is a whole number")):
            with self.subTest(entry=entry):
                path, _db = self._policy("[[ceilings]]\n" + entry)
                self.assertIn(words, startup.check(path))
        path, _db = self._policy('[[ceilings]]\ncontext = "credential"\n'
                                 'principal = "*"\nper_hour = 600')
        self.assertEqual(startup.check(path), "")
        self.assertEqual(cfgmod.load(path).ceiling("credential", "*"),
                         (60, 600, 6000))

    def test_every_name_the_example_shows_is_one_it_reads(self):
        """policy.example.toml, its commented-out examples included, so the
        file install.sh puts in place cannot teach a name that stops the
        signer."""
        import re
        from signer import config as cfgmod
        known = set(cfgmod.TOP_LEVEL) | set(cfgmod.RUNTIME)
        for names in cfgmod._ENTRIES.values():
            known |= set(names)
        example = os.path.join(os.path.dirname(cfgmod.__file__), "deploy",
                               "policy.example.toml")
        with open(example, encoding="utf-8") as handle:
            shown = set(re.findall(r"^#? ?([a-z_]+) = ", handle.read(), re.M))
        self.assertGreater(len(shown), 30)
        self.assertEqual(shown - known, set())

    def test_a_held_key_that_is_not_the_pinned_one_is_named(self):
        other = spki_of(LEGACY_KEY)[:-1] + b"\x00"
        path, _db = self._policy(
            '[[held]]\nkey_id = 1\nkey_file = "key-1.pem"\nspki = "%s"\n'
            'not_before = 1755500000\nsigning_until = 1818572000\n'
            % base64.b64encode(other).decode())
        from cryptography.hazmat.primitives import serialization
        with open(os.path.join(self.dir, "keys", "key-1.pem"), "wb") as handle:
            handle.write(LEGACY_KEY.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        self.assertIn("pinned", startup.check(path))

    def test_a_missing_runtime_setting_is_named(self):
        path, _db = self._policy()
        with open(path, encoding="utf-8") as handle:
            text = handle.read().replace('app_user = "verify-app"\n', "")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        self.assertIn("app_user", startup.check(path))

    def test_a_site_with_aws_needs_its_aws_settings(self):
        path, _db = self._policy()
        with open(path, encoding="utf-8") as handle:
            text = handle.read().replace('ledger_dir = "ledger"\n', "")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        why = startup.check(path)
        self.assertIn("ledger_bucket", why)
        self.assertIn("sns_topic", why)

    def test_a_key_folder_not_made_yet_is_not_a_refusal(self):
        path, _db = self._policy()
        os.rmdir(os.path.join(self.dir, "keys"))
        self.assertEqual(startup.check(path), "")
        self.assertFalse(os.path.exists(os.path.join(self.dir, "keys")))

    def test_it_reads_the_live_database(self):
        """A held key that the live database already has as another key:
        only a check that copied the database can see it."""
        from signer import config as cfgmod
        from signer.keys import FileKeys
        from signer.service import SignerService
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        path, db = self._policy()
        keys = os.path.join(self.dir, "keys")
        with open(os.path.join(keys, "key-1.pem"), "wb") as handle:
            handle.write(LEGACY_KEY.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        live = Store(db)
        self.cfg.legacy = []
        self.cfg.held = [cfgmod.Held(1, "key-1.pem", spki_of(LEGACY_KEY),
                                     1755500000, 1818572000)]
        SignerService(live, FileKeys(keys), self.cfg, clock=self.clock,
                      alerts=lambda *_: None)
        live.db.close()
        other = ec.generate_private_key(ec.SECP256R1())
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        text = text.replace("[runtime]", '[[held]]\nkey_id = 1\nkey_file = "key-1.pem"\n'
                            'spki = "%s"\nnot_before = 1755500000\n'
                            'signing_until = 1818572000\n\n[runtime]'
                            % base64.b64encode(spki_of(other)).decode())
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        self.assertIn("already another key", startup.check(path))

    def test_what_a_start_does_not_take_as_configuration(self):
        """A busy or full disk is retried, not refused for good."""
        self.assertFalse(issubclass(sqlite3.OperationalError, startup.CONFIGURATION_ERRORS))
        self.assertFalse(OSError in startup.CONFIGURATION_ERRORS)
        for kind in (ValueError, KeyError, FileNotFoundError, PermissionError, Refused):
            self.assertTrue(issubclass(kind, startup.CONFIGURATION_ERRORS), kind)

    def test_users_and_groups_are_looked_up(self):
        path, _db = self._policy()

        def nobody(name):
            raise KeyError("getgrnam(): name not found: %r" % name)
        self.assertIn("KeyError", startup.check(path, lookup_group=nobody))


class AlertOnceTest(unittest.TestCase):

    def setUp(self):
        import tempfile
        self.dir = tempfile.mkdtemp()
        self.rt = {"db": os.path.join(self.dir, "signer.db")}
        self.sent = []

    def send(self, severity, message, fields):
        self.sent.append((severity, message))

    def test_a_refusal_is_alerted_once_until_a_start_succeeds(self):
        startup.alert_once(self.rt, "refusing to start: X", self.send)
        startup.alert_once(self.rt, "refusing to start: X", self.send)
        self.assertEqual(self.sent, [("highest", "refusing to start: X")])
        startup.alert_once(self.rt, "refusing to start: Y", self.send)
        self.assertEqual(len(self.sent), 2)
        startup.started(self.rt)
        startup.alert_once(self.rt, "refusing to start: Y", self.send)
        self.assertEqual(len(self.sent), 3)

    def test_an_alert_that_cannot_be_sent_is_tried_again_next_start(self):
        def broken(*_):
            raise RuntimeError("no network")
        import contextlib
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(startup.alert_once(self.rt, "refusing: Z", broken))
        startup.alert_once(self.rt, "refusing: Z", self.send)
        self.assertEqual(self.sent, [("highest", "refusing: Z")])

    def test_a_site_without_sns_alerts_to_the_journal(self):
        made = []

        class Sns:
            def __init__(self, *args):
                made.append(args)
        for name in ("aws-access-key-id", "aws-secret-access-key"):
            with open(os.path.join(self.dir, name), "w") as handle:
                handle.write("x")
        from unittest import mock
        with mock.patch.object(aws, "SnsAlerts", Sns), \
                mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": self.dir}):
            self.assertIsInstance(startup.bare_alerts(
                {"ledger_dir": "/x", "sns_topic": "arn:t", "aws_region": "r"}),
                aws.LogAlerts)
            self.assertIsInstance(startup.bare_alerts({}), aws.LogAlerts)
            self.assertEqual(made, [])
            self.assertIsInstance(startup.bare_alerts(
                {"sns_topic": "arn:t", "aws_region": "r"}), Sns)


class OperatorCheckTest(unittest.TestCase):

    def setUp(self):
        self.groups = {"cl03-operators": SimpleNamespace(gr_gid=900)}
        self.users = {1001: SimpleNamespace(pw_name="alice", pw_gid=1001),
                      1002: SimpleNamespace(pw_name="bob", pw_gid=900)}
        self.member_of = {"alice": [1001, 900], "bob": [900]}
        self.is_operator = startup.operator_check(
            500, "cl03-operators",
            getpwuid=lambda uid: self.users[uid],
            getgrnam=lambda name: self.groups[name],
            getgrouplist=lambda name, gid: self.member_of[name])

    def test_membership_is_read_at_each_connection(self):
        self.assertTrue(self.is_operator(1001))
        self.member_of["alice"] = [1001]          # gpasswd -d alice cl03-operators
        self.assertFalse(self.is_operator(1001))

    def test_a_primary_group_counts_and_root_and_itself_are_operators(self):
        self.assertTrue(self.is_operator(1002))
        self.assertTrue(self.is_operator(0))
        self.assertTrue(self.is_operator(500))

    def test_an_account_that_is_gone_is_nobody(self):
        self.assertFalse(self.is_operator(4242))


class UnitTest(unittest.TestCase):

    def test_the_signer_stays_down_on_purpose_and_retries_the_rest(self):
        unit = _read("cl03-signer.service")
        self.assertRegex(unit, r"(?m)^RestartPreventExitStatus=%d %d$"
                         % (startup.ROLLBACK, startup.CONFIGURATION))
        self.assertRegex(unit, r"(?m)^Restart=on-failure$")
        self.assertNotRegex(unit, r"(?m)^StartLimit")
        self.assertNotRegex(unit, r"(?m)^ExecStartPre=")

    def test_both_units_are_sandboxed(self):
        wanted = ("CapabilityBoundingSet=", "PrivateDevices=yes",
                  "RestrictNamespaces=yes", "RestrictSUIDSGID=yes",
                  "SystemCallArchitectures=native", "UMask=0077",
                  "ProtectProc=invisible", "ProtectClock=yes")
        for name in ("cl03-signer.service", "cl03-signer-reconcile.service"):
            unit = _read(name)
            for line in wanted:
                self.assertRegex(unit, r"(?m)^%s$" % re.escape(line), (name, line))
        reconcile_unit = _read("cl03-signer-reconcile.service")
        for line in ("PrivateTmp=yes", "SystemCallFilter=@system-service",
                     "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6"):
            self.assertIn(line, reconcile_unit)

    def test_install_restarts_a_running_signer(self):
        script = _read("install.sh")
        self.assertIn("if systemctl is-active --quiet cl03-signer; then\n"
                      "    systemctl restart cl03-signer", script)

    def test_main_runs_check_and_refuses_with_the_unit_statuses(self):
        with open(os.path.join(HERE, "..", "__main__.py"), encoding="utf-8") as handle:
            main = handle.read()
        self.assertIn('choices=("serve", "reconcile", "check",\n'
                      '                                            "adopt")', main)
        self.assertIn("startup.CONFIGURATION)", main)
        self.assertIn("startup.ROLLBACK)", main)
        self.assertIn("startup.operator_check(own, rt[\"operators_group\"])", main)
        self.assertNotIn("gr_mem", main)


class ReconcileSpanTest(SignerTest):

    def _signed(self, at, n):
        from signer import ledger
        ids = []
        with self.store as db:
            for _ in range(n):
                cid = os.urandom(8).hex()
                ids.append(cid)
                ledger.append(db, at=at, kind="sign", context="credential",
                              summary={"credential_id": cid, "key_id": 16})
        return ids

    def test_only_what_the_report_covers_is_compared(self):
        now = 2_000_000_000
        old = self._signed(now - 10 * 86400, 3)       # before the report reaches
        new = self._signed(now - 3600, 1)
        report = {"since": now - 8 * 86400,
                  "credentials": [{"credential_id": new[0], "state": "signed",
                                   "issuer_key_id": 16}]}
        found = reconcile.findings(self.store, report, now=now,
                                   since=now - 12 * 86400)
        messages = [(s, m) for s, m, _ in found]
        self.assertNotIn(("high", "signed, never recorded"), messages)
        summary = [f for f in found if f[0] == "medium" and "not compared" in f[1]]
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary[0][2]["credentials"], len(old))

    def test_inside_the_span_a_missing_row_is_still_found(self):
        now = 2_000_000_000
        missing = self._signed(now - 3600, 1)
        found = reconcile.findings(self.store, {"since": now - 86400, "credentials": []},
                                   now=now, since=now - 86400)
        self.assertIn(("high", "signed, never recorded"),
                      [(s, m) for s, m, _ in found])
        self.assertEqual(found[0][2]["credential_id"], missing[0])

    def test_a_report_from_before_it_says_nothing_new(self):
        now = 2_000_000_000
        self._signed(now - 3600, 1)
        found = reconcile.findings(self.store, {"credentials": []}, now=now,
                                   since=now - 86400)
        self.assertEqual([m for _s, m, _f in found], ["signed, never recorded"])
