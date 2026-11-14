"""A rebuilt host carries on from its shipped ledger; the signer warns
before anything runs out; and says which code it runs."""

from __future__ import annotations

import base64
import json
import os
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ovcrypto import pki
from ovcrypto import trust as trust_mod

from signer import adopt, aws, ledger, registry, version, watch
from signer.service import SignerService
from signer.store import Store

from .helpers import DAY, ORG, T0, SignerTest

HERE = os.path.dirname(os.path.abspath(__file__))


class _Shipping(SignerTest):

    def setUp(self):
        super().setUp()
        self.up = aws.FakeUploader()
        self.shipper = aws.Shipper(self.store, self.up, "verify", self.clock)

    def fresh_store(self, name="rebuilt.db"):
        store = Store(os.path.join(self.dir, name))
        self.addCleanup(store.db.close)
        return store

    def history(self):
        """A deployment key, an organization key, a withdrawn key and an
        Organization CA; credentials signed; all of it in the bucket."""
        deployment = self.ready()
        ca_id = self.install_org_ca()
        org_key = self.svc.org_generate(organization=ORG,
                                        name="Alpha Registry",
                                        by="app")["key_id"]
        conf = self.svc.publish(org_key, by="alice")
        self.svc.confirm(conf["confirmation"], by="bob")
        self.svc.activate(org_key, by="alice")
        doomed = self.ready_key(activate=False)
        conf = self.svc.withdraw(doomed, by="alice")
        self.svc.confirm(conf["confirmation"], by="bob")
        self.sign_ok(deployment, issuer_name="Beta Office")
        self.shipper.ship()
        return deployment, ca_id, org_key, doomed


class AdoptTest(_Shipping):

    def test_a_rebuilt_database_has_the_registry_and_the_ledger_back(self):
        deployment, ca_id, org_key, doomed = self.history()
        store = self.fresh_store()
        report = adopt.adopt(store, self.cfg, self.keys, self.up, "verify",
                             now=self.clock.now())
        cols = ("key_id", "organization", "state", "spki", "leaf",
                "certified_name", "certified_by", "leaf_not_before",
                "leaf_not_after", "window_start", "window_end", "ca_id",
                "legacy")
        for kid in (1, deployment, org_key, doomed):
            with self.subTest(key=kid):
                was = registry.get(self.store, kid)
                now = registry.get(store, kid)
                self.assertEqual({c: (bytes(now[c]) if isinstance(now[c], bytes)
                                      else now[c]) for c in cols},
                                 {c: (bytes(was[c]) if isinstance(was[c], bytes)
                                      else was[c]) for c in cols})
        ca = store.one("SELECT * FROM cas WHERE ca_id = ?", (ca_id,))
        self.assertEqual(ca["state"], registry.CERTIFIED)
        self.assertEqual(ca["issued"], 1)
        self.assertEqual(report["key_files"][str(deployment)], "present")
        self.assertEqual(report["not_described"], [])
        # The withdrawn key travels as a tombstone again.
        entries, _ = registry.trust_list(store, self.cfg, self.clock.now())
        stone = [e for e in entries if e.key_id == doomed]
        self.assertTrue(stone and stone[0].is_tombstone)
        self.assertEqual(stone[0].spki, trust_mod.fingerprint(
            bytes(registry.get(self.store, doomed)["spki"])))
        # The chain goes on from the shipped head; nothing is signed twice.
        self.assertEqual(store.one("SELECT COUNT(*) AS n FROM "
                                   "signed_credentials")["n"], 1)
        aws.Shipper(store, self.up, "verify", self.clock).check_rollback()
        rows = store.all("SELECT * FROM ledger ORDER BY seq")
        ledger.verify_chain(rows)
        self.assertEqual(rows[-1]["context"], "adopt")
        # Every shipped row, not just the head: the gate's bundle history
        # and the reconciler read them.
        shipped = self.store.all("SELECT seq, hash FROM ledger ORDER BY seq")
        self.assertEqual([(r["seq"], r["hash"]) for r in rows[:-1]],
                         [(r["seq"], r["hash"]) for r in shipped])

    def test_a_signer_starts_on_it_and_ids_go_on(self):
        deployment, ca_id, org_key, doomed = self.history()
        store = self.fresh_store()
        adopt.adopt(store, self.cfg, self.keys, self.up, "verify",
                    now=self.clock.now())
        svc = SignerService(store, self.keys, self.cfg, clock=self.clock,
                            alerts=lambda *a: None)
        made = svc.keygen(by="alice")
        self.assertGreater(made["key_id"], max(deployment, ca_id, org_key,
                                               doomed))
        svc.put_revoked([])
        svc.bundle(device_id=b"\x01" * 16, device_key_hash=b"h",
                   epoch_keys=[], lease_seconds=30 * DAY, chains=True)

    def test_a_key_file_not_on_the_new_host_is_reported(self):
        deployment, _ca, _org, _doomed = self.history()
        moved = os.path.join(self.dir, "other-keys")
        from signer.keys import FileKeys
        report = adopt.adopt(self.fresh_store(), self.cfg, FileKeys(moved),
                             self.up, "verify", now=self.clock.now())
        self.assertEqual(report["key_files"][str(deployment)], "missing")

    def test_it_refuses_a_database_that_is_not_empty(self):
        self.history()
        with self.assertRaises(adopt.AdoptError) as err:
            adopt.adopt(self.store, self.cfg, self.keys, self.up, "verify",
                        now=self.clock.now())
        self.assertIn("not empty", str(err.exception))

    def test_it_refuses_a_ledger_with_rows_missing_or_changed(self):
        self.history()
        for context in ("credential", "bundle"):
            self.clock.advance(10)
            self.svc.pause(context, by="alice")
            self.shipper.ship()
        keys = sorted(self.up.objects, key=aws._first_seq)
        self.assertEqual(len(keys), 3)
        for lost, words in ((keys[0], "first row"), (keys[1], "are missing")):
            with self.subTest(lost=lost):
                gone = dict(self.up.objects)
                del gone[lost]
                with self.assertRaises(adopt.AdoptError) as err:
                    adopt.shipped_rows(SimpleNamespace(
                        keys=lambda p: sorted(gone, key=aws._first_seq),
                        get=gone.__getitem__), "verify")
                self.assertIn(words, str(err.exception))
        changed = dict(self.up.objects)
        lines = changed[keys[-1]].decode().splitlines()
        row = json.loads(lines[-1])
        row["at"] += 1
        changed[keys[-1]] = ("\n".join(lines[:-1] + [json.dumps(row)])
                             + "\n").encode()
        with self.assertRaises(adopt.AdoptError) as err:
            adopt.shipped_rows(SimpleNamespace(
                keys=lambda p: sorted(changed, key=aws._first_seq),
                get=changed.__getitem__), "verify")
        self.assertIn("broken", str(err.exception))

    def test_nothing_shipped_is_a_new_signer(self):
        with self.assertRaises(adopt.AdoptError) as err:
            adopt.adopt(self.fresh_store(), self.cfg, self.keys, self.up,
                        "verify", now=self.clock.now())
        self.assertIn("new signer", str(err.exception))

    def test_keys_from_before_the_ledger_carried_them_are_recorded(self):
        """A key whose keygen event has no public key: one `record` event at
        the next start, and a rebuild has it."""
        self.ready()
        with self.store as db:
            db.execute("INSERT INTO keys (key_id, organization, state, spki, "
                       "window_start, window_end, created_at, published_at) "
                       "VALUES (40, NULL, 'published', ?, ?, ?, ?, ?)",
                       (b"old-spki", T0, T0 + 100 * DAY, T0, T0))
            db.execute("DELETE FROM meta WHERE name = 'public_halves_recorded'")
        SignerService(self.store, self.keys, self.cfg, clock=self.clock,
                      alerts=lambda *a: None)
        records = [json.loads(r["summary"]) for r in self.store.all(
            "SELECT summary FROM ledger WHERE context = 'record'")]
        self.assertEqual([r["key_id"] for r in records], [40])
        SignerService(self.store, self.keys, self.cfg, clock=self.clock,
                      alerts=lambda *a: None)
        self.assertEqual(self.store.one("SELECT COUNT(*) AS n FROM ledger "
                                        "WHERE context = 'record'")["n"], 1)
        self.shipper.ship()
        store = self.fresh_store()
        adopt.adopt(store, self.cfg, self.keys, self.up, "verify",
                    now=self.clock.now())
        self.assertEqual(bytes(registry.get(store, 40)["spki"]), b"old-spki")

    def test_a_legacy_key_withdrawn_before_the_ledger_said_how_long(self):
        """Its withdraw event has no `not_after` and it has no `record`: the
        tombstone lives as `_do_withdraw` reckons it."""
        item = self.cfg.legacy[0]
        rows = [{"kind": "key", "context": "withdraw", "at": T0,
                 "summary": json.dumps({"key_id": 1, "by": "a+b",
                                        "action": "withdraw"})}]
        keys, _cas, _creds, missing = adopt.replay(rows, self.cfg)
        self.assertEqual(keys[1]["state"], registry.WITHDRAWN)
        self.assertEqual(keys[1]["leaf_not_after"], item.not_after
                         + self.cfg.credential_max_seconds
                         + self.cfg.margin_seconds)
        self.assertEqual(missing, [])

    def test_an_empty_database_is_told_about_adopt(self):
        self.history()
        with self.assertRaises(aws.Rollback) as err:
            aws.Shipper(self.fresh_store(), self.up, "verify",
                        self.clock).check_rollback()
        self.assertIn("python -m signer adopt", str(err.exception))

    def test_the_local_folder_lists_and_reads_its_objects(self):
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder, True)
        local = aws.LocalUploader(folder)
        aws.Shipper(self.store, local, "dev-site", self.clock).ship()
        self.ready()
        aws.Shipper(self.store, local, "dev-site", self.clock).ship()
        names = local.keys("dev-site")
        self.assertEqual(len(names), 2)
        self.assertEqual(adopt.shipped_rows(local, "dev-site")[-1]["seq"],
                         ledger.head(self.store)[0])


class StartOrderTest(SignerTest):
    """serve and the reconcile timer refuse a rollback before seeding writes
    anything, so the database a rebuilt host's refused starts leave stays
    empty for adopt -- with a legacy key to seed, which would write rows."""

    def setUp(self):
        super().setUp()
        # grp, pwd and the Unix socket server are POSIX only; neither path
        # tested here uses them.
        from signer import transport
        with mock.patch.dict(sys.modules, {"grp": SimpleNamespace(),
                                           "pwd": SimpleNamespace()}), \
                mock.patch.object(transport, "SocketServer", object,
                                  create=True):
            sys.modules.pop("signer.__main__", None)
            from signer import __main__ as main
        self.main = main
        self.addCleanup(sys.modules.pop, "signer.__main__", None)
        folder = os.path.join(self.dir, "ledger")
        aws.LocalUploader(folder).put(
            "verify/000000000001-000000000001.jsonl",
            b'{"seq": 1, "hash": "x"}\n', None)
        anchor = os.path.join(self.dir, "anchor.der")
        with open(anchor, "wb") as handle:
            handle.write(self.ca_der)
        self.db = os.path.join(self.dir, "new.db")
        legacy = self.cfg.legacy[0]
        self.path = os.path.join(self.dir, "policy.toml")
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(
                'anchors = ["%s"]\n[[legacy]]\nkey_id = 1\nspki = "%s"\n'
                'not_before = %d\nnot_after = %d\n[runtime]\nsite = "verify"\n'
                'db = "%s"\nkeys = "%s"\napp_socket = "a"\nadmin_socket = "b"\n'
                'app_user = "verify-app"\noperators_group = "cl03-operators"\n'
                'ledger_dir = "%s"\n'
                % (anchor.replace("\\", "/"),
                   base64.b64encode(legacy.spki).decode(), legacy.not_before,
                   legacy.not_after, self.db.replace("\\", "/"),
                   os.path.join(self.dir, "k").replace("\\", "/"),
                   folder.replace("\\", "/")))

    def assert_empty(self):
        store = Store(self.db)
        self.addCleanup(store.db.close)
        for table in ("ledger", "keys", "meta"):
            self.assertEqual(store.one("SELECT COUNT(*) AS n FROM %s"
                                       % table)["n"], 0, table)

    def test_serve_checks_rollback_before_seeding(self):
        with self.assertRaises(aws.Rollback):
            self.main._build(SimpleNamespace(config=self.path),
                             rollback_first=True)
        self.assert_empty()

    def test_so_does_the_reconcile_timer(self):
        """Run within minutes of an install, it seeded the database adopt
        then refused as not empty."""
        with mock.patch("sys.stderr"):
            status = self.main.run_reconcile(SimpleNamespace(config=self.path))
        self.assertEqual(status, self.main.startup.ROLLBACK)
        self.assert_empty()


class WatchTest(SignerTest):

    def setUp(self):
        super().setUp()
        self.sent = []
        self.key = self.ready()
        self.end = registry.get(self.store, self.key)["window_end"]

    def run_watch(self, alerts=None):
        return watch.run(self.store, self.cfg, alerts or (
            lambda s, m, f: self.sent.append((s, m))), now=self.clock.now())

    def at(self, days_before_end):
        self.clock.advance(self.end - days_before_end * DAY - self.clock.now())

    def warnings(self):
        return [(s, m) for s, m in self.sent if m != "daily summary"]

    def test_each_step_before_a_window_ends_is_said_once(self):
        self.run_watch()
        self.assertEqual(self.warnings(), [])
        for days, severity, words in ((119, "medium", "request the next"),
                                      (89, "medium", "install and publish"),
                                      (44, "medium", "switch to its successor"),
                                      (13, "high", "switch to its successor now")):
            with self.subTest(days=days):
                self.sent.clear()
                self.at(days)
                self.run_watch()
                self.run_watch()
                self.assertEqual(len(self.warnings()), 1, self.warnings())
                severity_, message = self.warnings()[0]
                self.assertEqual(severity_, severity)
                self.assertIn("key %d (the deployment's) stops signing its "
                              "documents and every phone's bundles"
                              % self.key, message)
                self.assertIn(words, message)
        self.sent.clear()
        self.at(-1)
        self.run_watch()
        self.assertIn("it has ended", self.warnings()[0][1])

    def test_a_timer_off_for_months_sends_only_the_most_urgent(self):
        self.at(10)
        self.run_watch()
        self.assertEqual(len(self.warnings()), 1)
        self.assertEqual(self.warnings()[0][0], "high")

    def test_a_waiting_successor_is_named(self):
        nxt = self.ready_key(activate=False)
        self.at(40)
        self.run_watch()
        self.assertIn("key %d is published to take over" % nxt,
                      self.warnings()[0][1])

    def test_an_alert_that_could_not_be_sent_is_tried_again(self):
        self.at(40)

        def broken(*_args):
            raise OSError("SNS")

        self.assertEqual(self.run_watch(broken), [])
        self.run_watch()
        self.assertEqual(len(self.warnings()), 1)

    def test_the_organization_ca_and_the_issuing_ca_are_watched(self):
        ca_id = self.install_org_ca()
        ca = self.store.one("SELECT * FROM cas WHERE ca_id = ?", (ca_id,))
        until = registry.issue_until(self.cfg, ca["not_after"])
        self.clock.advance(until - 30 * DAY - self.clock.now())
        self.run_watch()
        self.assertTrue(any("Organization CA %d" % ca_id in m
                            for _s, m in self.warnings()))
        short_key = ec.generate_private_key(ec.SECP256R1())
        short = pki.make_ca(short_key, "Short CA", self.clock.now() - DAY,
                            self.clock.now() + 300 * DAY, serial=7)
        self.cfg.anchors.append(short.public_bytes(serialization.Encoding.DER))
        self.sent.clear()
        self.run_watch()
        self.assertTrue(any(s == "high" and "issuing CA CN=Short CA" in m
                            for s, m in self.warnings()))

    def test_the_daily_summary_carries_the_ledger_head(self):
        self.run_watch()
        self.run_watch()
        summaries = [m for _s, m in self.sent if m == "daily summary"]
        self.assertEqual(len(summaries), 1)
        got = []
        watch.run(self.store, self.cfg, lambda s, m, f: got.append(f),
                  now=self.clock.now() + DAY)
        seq, head = ledger.head(self.store)
        self.assertEqual((got[0]["ledger_seq"], got[0]["ledger_hash"]),
                         (seq, head))
        self.assertEqual(got[0]["signing_keys"]["deployment"]["key_id"],
                         self.key)


class VersionTest(unittest.TestCase):

    def tree(self, files):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        for rel, data in files.items():
            path = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as handle:
                handle.write(data)
        return root

    def test_the_same_code_however_it_was_copied(self):
        # deploy.sh keeps every deploy/ folder off the instance, Python and
        # all, while install.sh copies the signer's.
        a = self.tree({"signer/a.py": b"x = 1\n", "ovcrypto/b.py": b"y\n",
                       "signer/deploy/install.sh": b"#!/bin/sh\n",
                       "signer/deploy/helper.py": b"z = 3\n",
                       "signer/COMMIT": b"$Format:%H$\n"})
        b = self.tree({"signer/a.py": b"x = 1\r\n", "ovcrypto/b.py": b"y\r\n",
                       "signer/__pycache__/a.cpython-313.pyc": b"\0",
                       "signer/COMMIT": b"0" * 40 + b"\n"})
        self.assertEqual(version.digest(a), version.digest(b))
        c = self.tree({"signer/a.py": b"x = 2\n", "ovcrypto/b.py": b"y\n"})
        self.assertNotEqual(version.digest(a), version.digest(c))
        self.assertEqual(version.digest(self.tree({})), "")

    def test_the_commit_is_forty_hex_digits_or_nothing(self):
        good = self.tree({"COMMIT": b"ab" * 20 + b"\n"})
        self.assertEqual(version.commit(good), "ab" * 20)
        for bad in (b"$Format:%H$\n", b"ab" * 19 + b"\n", b"zz" * 20):
            with self.subTest(bad=bad):
                self.assertEqual(version.commit(self.tree({"COMMIT": bad})), "")

    def test_status_says_which_code_it_runs(self):
        root = os.path.dirname(os.path.dirname(HERE))
        self.assertEqual(version.here(), root)
        self.assertEqual(len(version.digest(root)), 64)

    def test_install_and_the_deploy_use_it(self):
        with open(os.path.join(HERE, "..", "deploy", "install.sh"),
                  encoding="utf-8") as handle:
            install = handle.read()
        self.assertIn('STAGE=$(mktemp -d /opt/cl03-signer/.stage.XXXXXX)', install)
        self.assertIn('mv "$STAGE/COMMIT" /opt/cl03-signer/COMMIT', install)
        # The new code's own check of the live policy, before the swap.
        check = install.index("-m signer check --config /etc/cl03-signer/policy.toml")
        self.assertLess(check, install.index('mv "$STAGE/$part" "/opt/cl03-signer/$part"'))
        self.assertIn('git -c safe.directory="$SRC"', install)


class StatusCodeTest(SignerTest):

    def test_status_carries_the_digest_and_commit(self):
        code = self.svc.status()["code"]
        self.assertEqual(code["digest"], version.digest(version.here()))
        self.assertEqual(code["wire"], 1)
