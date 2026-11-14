"""Switching keys without stranding phones."""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from signer import config as cfgmod, registry
from signer.service import Refused, SignerService
from signer.store import Store

from .helpers import DAY, LEGACY_KEY, ORG, SignerTest, spki_of

OLD_PHONE = b"\x0a" * 16
NEW_PHONE = b"\x0b" * 16


class _Switching(SignerTest):

    def sync(self, device=NEW_PHONE, chains=True):
        return self.svc.bundle(device_id=device, device_key_hash=b"h",
                               epoch_keys=[], lease_seconds=30 * DAY,
                               chains=chains)

    def refused(self, reason, fn, *args, **kwargs):
        with self.assertRaises(Refused) as err:
            fn(*args, **kwargs)
        self.assertEqual(err.exception.reason, reason, str(err.exception))
        return err.exception

    def retire_active(self, key_id):
        """retire, and a second operator's confirm."""
        asked = self.svc.retire(key_id, by="alice")
        return self.svc.confirm(asked["confirmation"], by="bob")


class GateNeededTest(_Switching):

    def test_the_deployments_first_key_needs_no_gate(self):
        made = self.ready_key(activate=False)
        gate = registry.activation_gate(self.store, self.cfg,
                                        registry.get(self.store, made),
                                        self.clock.now())
        self.assertFalse(gate["needed"])
        self.svc.activate(made, by="alice")

    def test_with_no_deployment_key_active_nothing_is_waited_for(self):
        """Retired first, nothing can sign a bundle listing the next key, so
        a gate could only lengthen the outage. The wrong order is stopped
        at `retire` instead (RetireTest), and a deliberate one is two
        operators' with the consequence said."""
        old = self.ready()
        self.sync()
        self.retire_active(old)
        nxt = self.ready_key(activate=False)
        gate = registry.activation_gate(self.store, self.cfg,
                                        registry.get(self.store, nxt),
                                        self.clock.now())
        self.assertFalse(gate["needed"])
        self.svc.activate(nxt, by="alice")

    def test_while_one_signs_its_successor_waits(self):
        self.ready()
        self.sync()
        nxt = self.ready_key(activate=False)
        err = self.refused("gate", self.svc.activate, nxt, by="alice")
        self.assertIn("0 of 1 phones", str(err))


class RetireTest(_Switching):

    def test_retiring_an_active_key_needs_a_second_operator(self):
        """Irreversible, so never one operator's alone."""
        key = self.ready()
        asked = self.svc.retire(key, by="alice")
        self.assertIn("confirmation", asked)
        self.assertIn("nothing signs bundles", asked["consequence"])
        self.assertEqual(registry.get(self.store, key)["state"],
                         registry.ACTIVE)
        self.refused("policy", self.svc.confirm, asked["confirmation"],
                     by="alice")
        self.svc.confirm(asked["confirmation"], by="bob")
        row = registry.get(self.store, key)
        self.assertEqual(row["state"], registry.RETIRED)
        self.assertIsNone(row["key_ref"])
        self.assertTrue(any(s == "high" and "retired by alice+bob" in m
                            for s, m in self.alerts))

    def test_it_is_refused_while_a_successor_is_published(self):
        """Activate retires it through the gate; retiring first is
        exactly the order that strands phones."""
        key = self.ready()
        nxt = self.ready_key(activate=False)
        err = self.refused("policy", self.svc.retire, key, by="alice")
        self.assertIn("cl03signer activate %d" % nxt, str(err))
        self.assertEqual(registry.get(self.store, key)["state"],
                         registry.ACTIVE)

    def test_an_unpublished_successor_stops_it_too(self):
        """Retired now, it would be published and started with no gate."""
        key = self.ready()
        made = self.svc.keygen(by="alice")
        err = self.refused("policy", self.svc.retire, key, by="alice")
        self.assertIn("publish key %d, then cl03signer activate %d"
                      % (made["key_id"], made["key_id"]), str(err))

    def test_a_confirm_is_refused_once_a_successor_waits(self):
        key = self.ready()
        asked = self.svc.retire(key, by="alice")
        nxt = self.ready_key(activate=False)
        err = self.refused("policy", self.svc.confirm, asked["confirmation"],
                           by="bob")
        self.assertIn("cl03signer activate %d" % nxt, str(err))
        self.assertEqual(registry.get(self.store, key)["state"],
                         registry.ACTIVE)

    def test_a_published_key_retires_at_once(self):
        self.ready()
        nxt = self.ready_key(activate=False)
        self.assertEqual(self.svc.retire(nxt, by="alice"), {"retired": nxt})
        self.assertEqual(registry.get(self.store, nxt)["state"],
                         registry.RETIRED)

    def test_an_organization_keys_consequence_names_the_deployment_key(self):
        self.ready()
        org_key = self.ready_key(organization=ORG)
        asked = self.svc.retire(org_key, by="alice")
        self.assertIn("signed by the deployment key", asked["consequence"])

    def test_status_shows_the_retire_waiting_with_its_key(self):
        key = self.ready()
        self.svc.retire(key, by="alice")
        pending = self.svc.status()["confirmations"]
        self.assertEqual(pending[0]["action"], "retire")
        self.assertEqual(pending[0]["key"]["key_id"], key)


class UncountedGateTest(_Switching):
    """A signer as new as its database: phones synced through verify's own
    bundles are in no row of its ledger."""

    BUNDLE_HISTORY = False

    def test_no_history_is_unknown_and_only_time_opens_the_gate(self):
        self.ready()
        org_key = self.ready_key(organization=ORG, activate=False)
        gate = registry.activation_gate(
            self.store, self.cfg, registry.get(self.store, org_key),
            self.clock.now())
        self.assertEqual((gate["counted"], gate["of"], gate["open"]),
                         (False, 0, False))
        err = self.refused("gate", self.svc.activate, org_key, by="alice")
        self.assertIn("for under a lease", str(err))
        self.clock.advance(30 * DAY)
        self.svc.activate(org_key, by="alice")

    def test_every_phone_having_it_is_not_enough_before_a_lease(self):
        self.ready()
        self.sync()
        org_key = self.ready_key(organization=ORG, activate=False)
        self.sync()                         # the one phone seen has it
        self.refused("gate", self.svc.activate, org_key, by="alice")

    def test_once_a_lease_of_bundles_is_signed_the_count_is_trusted(self):
        self.ready()
        self.sync()
        self.clock.advance(31 * DAY)
        org_key = self.ready_key(organization=ORG, activate=False)
        self.sync()
        self.svc.activate(org_key, by="alice")


def _write_key_1(directory):
    with open(os.path.join(directory, "key-1.pem"), "wb") as handle:
        handle.write(LEGACY_KEY.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))


class OldAppTest(_Switching):
    """An older app checks bundles, feeds and statements against key 1
    alone. While the signer holds key 1, a certified deployment key taking
    over strands it, whatever that key's bundles list."""

    def setUp(self):
        super().setUp()
        self.store = Store(os.path.join(self.dir, "held.db"))
        self.addCleanup(self.store.db.close)
        _write_key_1(os.path.join(self.dir, "keys"))
        now = self.clock.now()
        self.cfg = cfgmod.Config(
            anchors=self.cfg.anchors, site_domain=self.cfg.site_domain,
            held=[cfgmod.Held(1, "key-1.pem", spki_of(LEGACY_KEY),
                              now - DAY, now + 300 * DAY)])
        self.svc = SignerService(self.store, self.keys, self.cfg,
                                 clock=self.clock, alerts=lambda *a: None)
        self.bundle_history()
        self.svc.activate(1, by="alice")
        self.svc.put_revoked([])

    def test_an_old_app_holds_the_switch_off_key_1_for_good(self):
        self.sync(OLD_PHONE, chains=False)
        nxt = self.ready_key(activate=False)
        self.sync(OLD_PHONE, chains=False)          # lists nxt: not enough
        err = self.refused("gate", self.svc.activate, nxt, by="alice")
        self.assertIn("1 phone that synced within a lease runs an app",
                      str(err))
        self.clock.advance(30 * DAY)
        self.sync(OLD_PHONE, chains=False)
        self.refused("gate", self.svc.activate, nxt, by="alice")
        self.sync(OLD_PHONE, chains=True)            # updated
        self.svc.activate(nxt, by="alice")

    def test_a_phone_that_said_nothing_counts_as_old(self):
        nxt = self.ready_key(activate=False)
        self.sync(chains=None)
        gate = registry.activation_gate(self.store, self.cfg,
                                        registry.get(self.store, nxt),
                                        self.clock.now())
        self.assertEqual(gate["not_capable"], [NEW_PHONE.hex()])

    def test_the_latest_sync_decides(self):
        nxt = self.ready_key(activate=False)
        self.sync(chains=True)
        self.sync(chains=False)
        self.refused("gate", self.svc.activate, nxt, by="alice")

    def test_an_organization_key_does_not_wait_for_the_app(self):
        """The old app trusts every key a key-1 bundle lists."""
        org_key = self.ready_key(organization=ORG, activate=False)
        self.sync(OLD_PHONE, chains=False)
        self.svc.activate(org_key, by="alice")

    def test_status_names_the_phones_it_waits_for(self):
        nxt = self.ready_key(activate=False)
        self.sync(OLD_PHONE, chains=False)
        gate = self.svc.status()["gates"][str(nxt)]
        self.assertEqual(gate["not_capable"], [OLD_PHONE.hex()])
        self.assertEqual(gate["not_capable_count"], 1)
        self.assertFalse(gate["open"])

    def test_the_flag_is_true_false_or_absent_on_the_wire(self):
        from signer.transport import Dispatcher
        reply = Dispatcher(self.svc).handle(
            {"op": "bundle", "args": {"device_id": "AQ==", "device_key_hash":
                                      "AQ==", "lease_seconds": 60,
                                      "chains": "yes"}}, admin=False, by="app")
        self.assertFalse(reply["ok"])


class CertifiedSwitchTest(_Switching):

    def test_once_a_certified_key_signs_the_old_app_holds_nothing_back(self):
        """It is cut off already: holding 16 -> 17 for it would wedge every
        switch after the first."""
        self.ready()
        self.sync(OLD_PHONE, chains=False)
        nxt = self.ready_key(activate=False)
        self.sync(OLD_PHONE, chains=False)
        self.svc.activate(nxt, by="alice")

    def test_a_successor_to_a_key_past_its_window_starts_at_once(self):
        """The old key signs no bundle after its window, so nothing can
        list the successor: the gate would only lengthen the outage."""
        old = self.ready()
        end = registry.get(self.store, old)["window_end"]
        self.clock.advance(end - 10 * DAY - self.clock.now())
        self.sync()
        nxt = self.ready_key(activate=False)       # its own window runs on
        self.refused("gate", self.svc.activate, nxt, by="alice")
        self.clock.advance(10 * DAY + 1)
        self.refused("key_out_of_window", self.sync)
        self.svc.activate(nxt, by="alice")


class WindowEndTest(_Switching):
    """A phone holding a bundle issued after the signer's window closed
    refuses every later one it signs, until its lease runs out."""

    def test_no_bundle_after_the_window_ends(self):
        key = self.ready()
        end = registry.get(self.store, key)["window_end"]
        self.clock.advance(end - self.clock.now())
        self.sync()                    # issued at the end: still followed
        self.clock.advance(1)
        err = self.refused("key_out_of_window", self.sync)
        self.assertIn("window ended", str(err))
        self.refused("key_out_of_window", self.sync)
        self.assertEqual(sum(1 for s, m in self.alerts
                             if "window ended" in m), 1)


class PolicyWindowTest(_Switching):
    """An edit to a held or legacy key's window after the first start
    stops the signer; it is never ignored without a word."""

    def _restart(self, cfg, store=None):
        return SignerService(store or self.store, self.keys, cfg,
                             clock=self.clock, alerts=lambda *a: None)

    def _legacy(self, not_before, not_after):
        return cfgmod.Config(anchors=self.cfg.anchors, site_domain=self.cfg.site_domain,
                             legacy=[cfgmod.Legacy(1, spki_of(LEGACY_KEY),
                                                   not_before, not_after)])

    def test_an_unchanged_policy_starts(self):
        item = self.cfg.legacy[0]
        self._restart(self._legacy(item.not_before, item.not_after))

    def test_a_changed_legacy_window_stops_the_signer(self):
        item = self.cfg.legacy[0]
        for start, end in ((item.not_before, item.not_after + DAY),
                           (item.not_before - DAY, item.not_after),
                           (item.not_before, item.not_after - DAY)):
            with self.subTest(start=start, end=end):
                err = self.refused("config", self._restart,
                                   self._legacy(start, end))
                self.assertIn("never changed from the policy", str(err))

    def test_a_legacy_end_is_not_a_change_of_policy(self):
        item = self.cfg.legacy[0]
        asked = self.svc.legacy_end(1, by="alice")
        self.svc.confirm(asked["confirmation"], by="bob")
        self._restart(self._legacy(item.not_before, item.not_after))

    def test_a_database_from_before_the_rule_is_checked_against_itself(self):
        """No record of the first window: the registry's is the one."""
        item = self.cfg.legacy[0]
        with self.store as db:
            db.execute("DELETE FROM meta WHERE name = 'policy_window:1'")
        self.refused("config", self._restart,
                     self._legacy(item.not_before, item.not_after + DAY))
        with self.store as db:
            db.execute("DELETE FROM meta WHERE name = 'policy_window:1'")
        self._restart(self._legacy(item.not_before, item.not_after))
        self.assertEqual(self.store.meta("policy_window:1"),
                         "%d,%d" % (item.not_before, item.not_after))

    def test_a_changed_held_window_stops_the_signer(self):
        store = Store(os.path.join(self.dir, "held.db"))
        self.addCleanup(store.db.close)
        with open(os.path.join(self.dir, "keys", "key-1.pem"), "wb") as handle:
            handle.write(LEGACY_KEY.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))

        def held(until):
            return cfgmod.Config(anchors=self.cfg.anchors, held=[cfgmod.Held(
                1, "key-1.pem", spki_of(LEGACY_KEY), self.clock.now() - DAY,
                until)])

        until = self.clock.now() + 300 * DAY
        self._restart(held(until), store)
        self._restart(held(until), store)
        err = self.refused("config", self._restart, held(until + DAY), store)
        self.assertIn("retire 1", str(err))

    def test_a_legacy_id_that_is_another_key_stops_the_signer(self):
        """Another key already under id 1 is refused, not silently kept."""
        another = ec.generate_private_key(ec.SECP256R1())
        item = self.cfg.legacy[0]
        self.refused("config", self._restart, cfgmod.Config(
            anchors=self.cfg.anchors, legacy=[cfgmod.Legacy(
                1, spki_of(another), item.not_before, item.not_after)]))
