"""A signer holding the raw development key (`[[held]]`), and its ledger in a
folder: a development site while its phones still pin only key 1
(signer/deploy/README.md, "A development site")."""

from __future__ import annotations

import base64
import io
import json
import os
from contextlib import redirect_stderr

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ovcrypto import bundle as bundle_mod
from ovcrypto import chain, keystore, trust

from signer import aws, config as cfgmod, registry
from signer.service import Refused, SignerService
from signer.store import Store

from .helpers import DAY, LEGACY_KEY, ORG, ORG_NAME, SITE, SignerTest, spki_of

DEVICE = bytes(range(16))


def _pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


class HeldKeyTest(SignerTest):

    def setUp(self):
        super().setUp()
        # A database of its own: the helper's signer listed key 1 as legacy.
        self.store = Store(os.path.join(self.dir, "held.db"))
        self.addCleanup(self.store.db.close)
        self.svc = self.holding()
        self.bundle_history()

    def holding(self, *, key=LEGACY_KEY, pin=None, key_id=1, legacy=(),
                not_before=None, signing_until=None, store=None):
        """A signer started with key 1 in its key folder and `[[held]]`."""
        now = self.clock.now()
        path = os.path.join(self.dir, "keys", "key-%d.pem" % key_id)
        if not os.path.exists(path):
            with open(path, "wb") as handle:
                handle.write(_pem(key))
        self.cfg.legacy = list(legacy)
        self.cfg.held = [cfgmod.Held(
            key_id, "key-%d.pem" % key_id,
            pin if pin is not None else spki_of(key),
            now - 200 * DAY if not_before is None else not_before,
            now + 100 * DAY if signing_until is None else signing_until)]
        return SignerService(
            store or self.store, self.keys, self.cfg, clock=self.clock,
            alerts=lambda severity, message, fields: self.alerts.append(
                (severity, message)))

    def signing(self):
        self.svc.activate(1, by="alice")
        self.svc.put_revoked([])

    def bundle(self, chains=True):
        """A sync by the chain-aware app, unless `chains` says otherwise."""
        return self.svc.bundle(device_id=DEVICE, device_key_hash=b"\x11" * 32,
                               epoch_keys=self.epoch_keys(),
                               lease_seconds=30 * DAY, chains=chains)

    def accept(self, got):
        return trust.accept_bundle(
            base64.b64decode(got["bundle"]),
            chain.decode_chains(got["issuer_chains"]),
            anchors=trust.Anchors(raw={1: spki_of(LEGACY_KEY)},
                                  cas=(self.ca_der,)),
            denied=frozenset(), device_id=DEVICE, now=self.clock.now(),
            domain=SITE)

    # -- seeding -----------------------------------------------------------

    def test_it_waits_published_until_an_operator_activates_it(self):
        row = registry.require(self.store, 1)
        self.assertEqual((row["state"], row["legacy"], row["leaf"]),
                         (registry.PUBLISHED, 0, None))
        self.assertIsNone(registry.active_key(self.store, None))
        self.assertIn(("medium", "holding raw key 1, with no certificate"),
                      self.alerts)
        self.signing()
        self.assertEqual(registry.active_key(self.store, None)["key_id"], 1)

    def test_a_restart_keeps_it_and_says_nothing_new(self):
        self.signing()
        before = len(self.alerts)
        self.holding()
        self.assertEqual(registry.require(self.store, 1)["state"],
                         registry.ACTIVE)
        self.assertEqual(len(self.alerts), before)

    def test_a_file_that_is_not_the_pinned_key_stops_the_signer(self):
        other = ec.generate_private_key(ec.SECP256R1())
        os.remove(os.path.join(self.dir, "keys", "key-1.pem"))
        self.store.db.execute("DELETE FROM keys WHERE key_id = 1")
        with self.assertRaises(Refused) as err:
            self.holding(key=other, pin=spki_of(LEGACY_KEY))
        self.assertIn("pinned key", err.exception.detail)

    def test_a_restart_naming_another_key_stops_the_signer(self):
        other = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(Refused) as err:
            self.holding(pin=spki_of(other))
        self.assertIn("already another key", err.exception.detail)

    def test_a_key_other_than_p256_stops_the_signer(self):
        other = ec.generate_private_key(ec.SECP384R1())
        with self.assertRaises(Refused) as err:
            self.holding(key=other, key_id=2)
        self.assertIn("not P-256", err.exception.detail)

    def test_held_and_legacy_at_once_stops_the_signer(self):
        with self.assertRaises(Refused) as err:
            self.holding(legacy=[cfgmod.Legacy(
                1, spki_of(LEGACY_KEY), 0, self.clock.now())])
        self.assertIn("both held and legacy", err.exception.detail)

    def test_a_signer_key_id_is_refused(self):
        with self.assertRaises(Refused) as err:
            self.holding(key_id=registry.FIRST_KEY_ID)
        self.assertIn("below", err.exception.detail)

    def test_an_empty_window_is_refused(self):
        now = self.clock.now()
        with self.assertRaises(Refused) as err:
            self.holding(key_id=3, not_before=now, signing_until=now)
        self.assertIn("window is empty", err.exception.detail)

    def test_it_never_replaces_a_certified_key_that_signs(self):
        self.cfg.held = []
        self.ready_key()                                    # 16, active
        with self.assertRaises(Refused) as err:
            self.holding(key_id=2)
        self.assertIn("certified and signs", err.exception.detail)

    def test_activate_refuses_it_over_a_certified_key(self):
        """Seeded before 16 took over: switching back is refused, since a
        phone holding 16's bundle may refuse key 1's."""
        key_id = self.ready_key()          # 16 takes over from nothing
        self.assertEqual(registry.active_key(self.store, None)["key_id"],
                         key_id)
        with self.assertRaises(Refused) as err:
            self.svc.activate(1, by="alice")
        self.assertIn("does not replace", err.exception.detail)

    # -- signing ----------------------------------------------------------

    def test_key_1_signs_what_the_old_app_checks(self):
        """Bundles, feeds and statements, all under the pinned key 1."""
        self.signing()
        got = self.bundle()
        self.assertEqual(got["key_id"], 1)
        b = bundle_mod.Bundle.unpack(base64.b64decode(got["bundle"]))
        self.assertEqual(b.sig_key_id, 1)
        self.assertTrue(keystore.verify(spki_of(LEGACY_KEY), b.signed_bytes(),
                                        b.sig))
        self.assertEqual(self.svc.feed()["key_id"], 1)
        statement = self.svc.statement(log_key_id=3, public_key=bytes(32))
        self.assertEqual(statement["sig_key_id"], 1)
        self.assertEqual(self.accept(got).signer, 1)

    def test_an_organization_ca_key_rides_in_key_1s_bundle(self):
        self.signing()
        self.install_org_ca()
        key_id = self.svc.org_generate(organization=ORG,
                                       name=ORG_NAME)["key_id"]
        conf = self.svc.publish(key_id, by="alice")
        self.svc.confirm(conf["confirmation"], by="bob")
        self.svc.activate(key_id, by="alice")
        ctx = self.accept(self.bundle())
        self.assertFalse(ctx.chain_signed)
        self.assertEqual(sorted(ctx.entries), [1, key_id])
        self.assertEqual(ctx.entries[key_id].organization, ORG_NAME)
        self.assertEqual(ctx.entries[key_id].ca_name, "verify.example.ph System CA")
        # Its organization signs with it; everyone else with key 1.
        self.assertEqual(self.sign_ok(key_id, issuer_name=ORG_NAME,
                                      organization=ORG)["key_id"], key_id)
        self.assertEqual(self.sign_ok(1, issuer_name="Beta Office")["key_id"],
                         1)

    def test_credentials_stay_inside_its_window(self):
        self.signing()
        self.sign_ok(1, issuer_name="Beta Office")
        self.clock.advance(101 * DAY)
        with self.assertRaises(Refused) as err:
            self.sign_ok(1)
        self.assertEqual(err.exception.reason, "key_out_of_window")

    def test_setup_is_told_it_has_no_certificate(self):
        self.signing()
        listed = {k["key_id"]: k for k in self.svc.public()["keys"]}
        self.assertTrue(listed[1]["raw"])
        self.assertIsNone(listed[1]["leaf"])
        self.assertFalse(listed[1]["legacy"])
        self.ready_key(activate=False)
        listed = {k["key_id"]: k for k in self.svc.public()["keys"]}
        self.assertFalse(listed[16]["raw"])

    def test_a_certified_successor_retires_it_and_its_file(self):
        self.signing()
        self.bundle()
        key_id = self.ready_key(activate=False)
        self.bundle()                      # the phone has seen 16 listed
        self.svc.activate(key_id, by="alice")
        self.assertEqual(registry.require(self.store, 1)["state"],
                         registry.RETIRED)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "keys",
                                                     "key-1.pem")))
        # Still listed, so its credentials verify until they expire.
        self.assertIn(1, sorted(self.accept(self.bundle()).entries))


class HeldPolicyFileTest(SignerTest):

    def test_held_is_read_from_the_policy_file(self):
        spki = spki_of(LEGACY_KEY)
        path = os.path.join(self.dir, "policy.toml")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                '[[held]]\nkey_id = 1\nkey_file = "key-1.pem"\n'
                'spki = "%s"\nnot_before = 1755500000\n'
                'signing_until = 1818572000\n\n[runtime]\nsite = "x"\n'
                % base64.b64encode(spki).decode())
        cfg = cfgmod.load(path)
        self.assertEqual(cfg.held, [cfgmod.Held(1, "key-1.pem", spki,
                                                1755500000, 1818572000)])
        self.assertEqual(cfg.legacy, [])

    def test_no_configured_key_takes_the_chains_digest_id(self):
        """The last u32 is the entry that binds a bundle's chains, never a
        key's."""
        spki = base64.b64encode(spki_of(LEGACY_KEY)).decode()
        path = os.path.join(self.dir, "policy.toml")
        for section, extra in (("held", 'key_file = "k.pem"\nsigning_until = 2\n'),
                               ("legacy", "not_after = 2\n")):
            for key_id in (0, 4294967295, 4294967296):
                with self.subTest(section=section, key_id=key_id):
                    with open(path, "w", encoding="utf-8") as handle:
                        handle.write('[[%s]]\nkey_id = %d\nspki = "%s"\n'
                                     'not_before = 1\n%s' % (section, key_id,
                                                              spki, extra))
                    with self.assertRaises(ValueError):
                        cfgmod.load(path)

    def test_a_lease_shorter_than_an_hour_is_a_configuration_error(self):
        path = os.path.join(self.dir, "policy.toml")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("lease_seconds = 600\n")
        with self.assertRaises(ValueError):
            cfgmod.load(path)


class LocalLedgerTest(SignerTest):

    def setUp(self):
        super().setUp()
        self.folder = os.path.join(self.dir, "ledger")
        self.addCleanup(self._writable)
        self.up = aws.LocalUploader(self.folder)
        self.ship = aws.Shipper(self.store, self.up, "dev-site", self.clock)

    def _writable(self):
        """The objects are read-only, which Windows will not delete."""
        for root, _dirs, files in os.walk(self.folder):
            for name in files:
                os.chmod(os.path.join(root, name), 0o600)

    def test_rows_ship_once_each_to_a_file_of_its_own(self):
        self.ready()
        self.assertGreater(self.ship.ship(), 0)
        self.assertEqual(self.ship.ship(), 0)
        self.svc.keygen(by="alice")
        self.assertEqual(self.ship.ship(), 1)
        self.assertEqual(len(os.listdir(os.path.join(self.folder,
                                                     "dev-site"))), 2)

    def test_a_write_cut_short_leaves_nothing_that_is_read(self):
        from unittest import mock
        with mock.patch.object(aws.os, "fsync",
                               side_effect=RuntimeError("power cut")):
            with self.assertRaises(RuntimeError):
                self.up.put("dev-site/000000000001-000000000009.jsonl",
                            b'{"seq": 1, "hash": "x"}', None)
        self.assertTrue(os.listdir(os.path.join(self.folder, "dev-site")))
        self.assertIsNone(self.up.newest("dev-site"))
        self.ready()
        self.ship.ship()
        self.ship.check_rollback()

    def test_an_unreadable_newest_object_refuses_the_start(self):
        self.up.put("dev-site/000000000001-000000000009.jsonl", b"", None)
        with self.assertRaises(aws.Rollback):
            self.ship.check_rollback()

    def test_an_object_is_never_replaced(self):
        self.up.put("dev-site/000000000001-000000000002.jsonl", b"a", None)
        with self.assertRaises(FileExistsError):
            self.up.put("dev-site/000000000001-000000000002.jsonl", b"b",
                        None)

    def test_the_newest_object_is_the_highest_sequence(self):
        self.up.put("dev-site/000000000001-000000000009.jsonl", b"a", None)
        self.up.put("dev-site/000000000010-000000000012.jsonl", b"b", None)
        self.assertEqual(self.up.newest("dev-site"),
                         ("dev-site/000000000010-000000000012.jsonl", b"b"))
        self.assertIsNone(self.up.newest("elsewhere"))

    def test_a_prefix_cannot_leave_the_folder(self):
        for prefix in ("../x", "a/../../x", "/", ""):
            with self.assertRaises(ValueError):
                self.up.newest(prefix)

    def test_an_older_database_is_still_refused_against_the_folder(self):
        self.ready()
        self.ship.ship()
        snapshot = os.path.join(self.dir, "old.db")
        self.store.db.execute("VACUUM INTO ?", (snapshot,))
        self.svc.keygen(by="alice")
        self.ship.ship()
        from signer.store import Store
        old = Store(snapshot)
        self.addCleanup(old.db.close)
        with self.assertRaises(aws.Rollback):
            aws.Shipper(old, self.up, "dev-site",
                        self.clock).check_rollback()
        self.ship.check_rollback()

    def test_alerts_go_to_the_journal_as_json(self):
        out = io.StringIO()
        with redirect_stderr(out):
            aws.LogAlerts("dev-site")("high", "key 16 withdrawn",
                                        {"key_id": 16})
        line = json.loads(out.getvalue())
        self.assertEqual(line, {"alert": "high", "site": "dev-site",
                                "message": "key 16 withdrawn", "key_id": 16})
