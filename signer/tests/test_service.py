"""The signer's policy, ceilings, caches and key lifecycle.

Each refusal names what a compromised or careless caller would get from a
signer that allowed it.
"""

import base64
import json
import os
import sys
import threading
import types
import unittest
import uuid
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.asymmetric import ec

from ovcrypto import chain, keystore, pki, trust, wire

from signer import config as cfgmod, ledger, registry
from signer.service import Refused

from .helpers import DAY, ORG, ORG_NAME, T0, SignerTest, spki_of


def _refused(test, reason, fn, *args, **kwargs):
    with test.assertRaises(Refused) as err:
        fn(*args, **kwargs)
    test.assertEqual(err.exception.reason, reason, str(err.exception))
    return err.exception


class CredentialPolicyTest(SignerTest):

    def setUp(self):
        super().setUp()
        self.key = self.ready()

    def test_a_good_credential_is_signed_with_a_verifiable_signature(self):
        message = self.credential(self.key)
        got = self.svc.sign_credential(message)
        spki = registry.get(self.store, self.key)["spki"]
        self.assertTrue(keystore.verify(bytes(spki), message,
                                        base64.b64decode(got["sig"])))

    def test_a_credential_declaring_ed25519_is_not_signed(self):
        """The signer's keys are P-256, and a message saying otherwise would
        be signed as one thing and verified as another (F101's sweep:
        nothing tested this)."""
        message = self.credential(self.key)
        ed25519 = message[:-5] + bytes([wire.SIG_ED25519]) + message[-4:]
        err = _refused(self, "policy", self.svc.sign_credential, ed25519)
        self.assertIn("P-256", str(err))

    def test_the_wrong_key_id_is_answered_with_the_right_one(self):
        err = _refused(self, "key_changed", self.sign_ok, 999)
        self.assertEqual(err.extra["key_id"], self.key)

    def test_issued_at_must_be_now(self):
        _refused(self, "policy", self.sign_ok, self.key,
                 issued_at=T0 - 3600)

    def test_validity_is_capped_at_v(self):
        _refused(self, "policy", self.sign_ok, self.key, valid_days=366)

    def test_a_credential_id_is_signed_once(self):
        cid = uuid.uuid4()
        self.sign_ok(self.key, credential_id=cid)
        _refused(self, "policy", self.sign_ok, self.key, credential_id=cid)

    def test_past_the_window_nothing_is_signed(self):
        """A credential never outlives its key's certificate."""
        self.clock.advance(340 * DAY)
        _refused(self, "key_out_of_window", self.sign_ok, self.key)

    def _window_end(self):
        return registry.get(self.store, self.key)["window_end"]

    def test_inside_the_skew_a_full_term_would_outlive_the_certificate(self):
        """The window allows 300 s of skew; the certificate does not."""
        self.clock.at = self._window_end() + 200
        err = _refused(self, "key_out_of_window", self.sign_ok, self.key)
        self.assertIn("outlives the certificate", str(err))
        # A shorter one issued at the same moment is fine.
        self.sign_ok(self.key, valid_days=300)

    def test_after_the_window_even_a_short_credential_is_refused(self):
        """It would not outlive the certificate, but the key's window is shut."""
        self.clock.at = self._window_end() + DAY
        err = _refused(self, "key_out_of_window", self.sign_ok, self.key,
                       valid_days=1)
        self.assertNotIn("outlives", str(err))

    def test_a_pause_stops_credentials(self):
        self.svc.pause("credential", by="app")
        _refused(self, "paused", self.sign_ok, self.key)

    def test_a_suspended_deployment_key_signs_no_credentials(self):
        self.svc.suspend(self.key, by="app")
        _refused(self, "key_suspended", self.sign_ok, self.key)


class OrganizationKeyTest(SignerTest):
    """One signature proves the organization; its name is only its key's."""

    def setUp(self):
        super().setUp()
        self.deployment = self.ready()
        self.org_key = self.ready_key(organization=ORG)

    def test_an_organization_credential_is_signed_by_its_key(self):
        got = self.sign_ok(self.org_key, organization=ORG, issuer_name=ORG_NAME)
        self.assertEqual(got["key_id"], self.org_key)

    def test_the_organization_key_signs_only_its_certified_name(self):
        _refused(self, "policy", self.sign_ok, self.org_key, organization=ORG,
                 issuer_name="Somebody Else")

    def test_the_deployment_key_cannot_mint_a_certified_name(self):
        """Otherwise the organization's name could be signed uncertified."""
        _refused(self, "policy", self.sign_ok, self.deployment,
                 issuer_name=ORG_NAME)

    def test_an_organization_with_a_key_never_falls_back(self):
        err = _refused(self, "key_changed", self.sign_ok, self.deployment,
                       organization=ORG, issuer_name=ORG_NAME)
        self.assertEqual(err.extra["key_id"], self.org_key)

    def test_suspending_its_key_stops_only_that_organization(self):
        self.svc.suspend(self.org_key, by="app")
        _refused(self, "key_suspended", self.sign_ok, self.org_key,
                 organization=ORG, issuer_name=ORG_NAME)
        self.sign_ok(self.deployment, issuer_name="Another Org")

    def test_an_organization_key_never_signs_a_bundle(self):
        got = self.svc.bundle(device_id=b"\x01" * 16, device_key_hash=b"h",
                              epoch_keys=self.epoch_keys(),
                              lease_seconds=30 * DAY)
        self.assertEqual(got["key_id"], self.deployment)


class CeilingTest(SignerTest):

    def setUp(self):
        super().setUp()
        self.key = self.ready()

    def test_one_operator_over_its_cap_stops_nobody_else(self):
        self.cfg.ceilings[("credential", "operator")] = (2, None, None)
        for _ in range(2):
            self.sign_ok(self.key, operator="op-1")
        _refused(self, "subject_limit", self.sign_ok, self.key, operator="op-1")
        self.sign_ok(self.key, operator="op-2")
        self.assertFalse(self.store.all("SELECT * FROM pauses"))

    def test_the_global_credential_ceiling_pauses_and_stays_paused(self):
        self.cfg.ceilings[("credential", "*")] = (3, None, None)
        for i in range(3):
            self.sign_ok(self.key, operator="op-%d" % i)
        _refused(self, "paused", self.sign_ok, self.key, operator="op-9")
        self.clock.advance(3600)
        _refused(self, "paused", self.sign_ok, self.key, operator="op-9")
        self.assertTrue(any(s == "high" for s, _ in self.alerts))
        self.svc.resume("credential", by="alice")
        self.sign_ok(self.key, operator="op-9")

    def test_a_bundle_breach_never_pauses(self):
        self.cfg.ceilings[("bundle", "*")] = (None, 2, None)
        for i in range(2):
            self.svc.bundle(device_id=bytes([i]) * 16, device_key_hash=b"h",
                            epoch_keys=[], lease_seconds=30 * DAY)
        _refused(self, "over_ceiling", self.svc.bundle, device_id=b"\x09" * 16,
                 device_key_hash=b"h", epoch_keys=[], lease_seconds=30 * DAY)
        self.assertFalse(self.store.all("SELECT * FROM pauses"))
        self.sign_ok(self.key)


class BundleTest(SignerTest):

    def setUp(self):
        super().setUp()
        self.key = self.ready()
        self.device = b"\x42" * 16

    def _accept(self, got, previous=None, denied=()):
        legacy = registry.get(self.store, 1)
        return trust.accept_bundle(
            base64.b64decode(got["bundle"]),
            chain.decode_chains(got["issuer_chains"]),
            anchors=trust.Anchors(raw={1: bytes(legacy["spki"])},
                                  cas=(self.ca_der,)),
            denied=set(denied), device_id=self.device,
            now=self.clock.now(), previous=previous)

    def _bundle(self, lease=30 * DAY):
        return self.svc.bundle(device_id=self.device, device_key_hash=b"hash",
                               epoch_keys=self.epoch_keys(),
                               lease_seconds=lease)

    def test_a_phone_accepts_what_the_signer_builds(self):
        ctx = self._accept(self._bundle())
        self.assertEqual(ctx.signer, self.key)
        self.assertTrue(ctx.chain_signed)
        self.assertEqual(sorted(ctx.entries), [1, self.key])

    def test_the_lease_is_capped(self):
        got = self._bundle(lease=90 * DAY)
        self.assertEqual(got["not_after"] - self.clock.now(), 30 * DAY)

    def test_a_lease_over_on_arrival_is_refused(self):
        """A lease of nothing is over when the phone gets it, and continuity
        does not guard the sync after it."""
        for lease in (-DAY, 0, 60, cfgmod.MIN_LEASE_SECONDS - 1):
            with self.subTest(lease=lease):
                _refused(self, "policy", self._bundle, lease=lease)
        got = self._bundle(lease=cfgmod.MIN_LEASE_SECONDS)
        self.assertEqual(got["not_after"] - self.clock.now(),
                         cfgmod.MIN_LEASE_SECONDS)

    def test_the_bundle_binds_the_chains_beside_it(self):
        """Their digest is inside the signature, so whoever relays them
        cannot drop one organization's key and keep the bundle."""
        from ovcrypto import bundle as bundle_mod

        org = self.ready_key(organization=ORG, activate=False)
        got = self._bundle()
        self.assertIn(str(org), got["issuer_chains"])
        b = bundle_mod.Bundle.unpack(base64.b64decode(got["bundle"]))
        self.assertEqual(b.chains_digest, chain.chains_digest(
            chain.decode_chains(got["issuer_chains"])))
        ctx = self._accept(got)
        self.assertIn(org, ctx.entries)
        self.assertNotIn(bundle_mod.CHAINS_DIGEST_ID, ctx.entries)
        dropped = dict(got["issuer_chains"])
        del dropped[str(org)]
        with self.assertRaises(trust.Refused) as err:
            self._accept(dict(got, issuer_chains=dropped))
        self.assertEqual(err.exception.reason, trust.CHAINS_MISMATCH)
        row = self.store.one("SELECT summary FROM ledger WHERE context = "
                             "'bundle' ORDER BY seq DESC LIMIT 1")
        summary = json.loads(row["summary"])
        self.assertEqual(summary["chains_digest"], b.chains_digest.hex())
        self.assertNotIn(str(bundle_mod.CHAINS_DIGEST_ID), summary["keys"])

    def test_no_bundle_before_the_revoked_set_arrives(self):
        fresh = self.svc
        self.store.db.execute("DELETE FROM meta")
        _refused(self, "no_revocations", fresh.bundle, device_id=self.device,
                 device_key_hash=b"h", epoch_keys=[], lease_seconds=DAY)

    def test_a_revoked_id_is_in_the_bundle_filter(self):
        from ovcrypto import revocation

        cid = uuid.uuid4().bytes
        self.svc.put_revoked([cid])
        raw = base64.b64decode(self._bundle()["bundle"])
        from ovcrypto import bundle as bundle_mod
        f = revocation.CuckooFilter.from_bytes(
            bundle_mod.Bundle.unpack(raw).revocation)
        self.assertIn(cid, f)

    def test_a_withdrawn_key_becomes_a_tombstone_and_its_file_goes(self):
        nxt = self.ready_key(activate=False)
        ref = registry.get(self.store, nxt)["key_ref"]
        conf = self.svc.withdraw(nxt, by="alice")
        self.svc.confirm(conf["confirmation"], by="bob")
        ctx = self._accept(self._bundle())
        self.assertIn(nxt, ctx.tombstones)
        self.assertNotIn(nxt, ctx.entries)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "keys", ref)))

    def test_continuity_lets_a_switch_through_with_a_published_successor(self):
        previous = self._accept(self._bundle())
        nxt = self.ready_key(activate=False)
        between = self._accept(self._bundle(), previous=previous)
        self.clock.advance(31 * DAY)
        self.svc.activate(nxt, by="alice")
        self.clock.advance(-31 * DAY + 2 * DAY)
        ctx = self._accept(self._bundle(), previous=between)
        self.assertEqual(ctx.signer, nxt)


class RevocationAndFeedTest(SignerTest):

    def setUp(self):
        super().setUp()
        self.key = self.ready()

    def _feed_signatures(self):
        return self.store.one("SELECT COUNT(*) AS n FROM ledger WHERE "
                              "kind = 'sign' AND context = 'revocation'")["n"]

    def test_a_thousand_fetches_cost_one_signature(self):
        first = self.svc.feed()
        for _ in range(1000):
            self.assertEqual(self.svc.feed()["sig"], first["sig"])
        self.assertEqual(self._feed_signatures(), 1)

    def test_a_new_revocation_is_signed_after_the_minimum_interval(self):
        self.svc.feed()
        self.svc.put_revoked([uuid.uuid4().bytes])
        self.assertEqual(self._feed_signatures(), 1)    # within a minute
        self.clock.advance(61)
        self.svc.feed()
        self.assertEqual(self._feed_signatures(), 2)

    def test_an_unchanged_set_is_resigned_hourly(self):
        self.svc.feed()
        self.clock.advance(3601)
        self.svc.feed()
        self.assertEqual(self._feed_signatures(), 2)

    def test_a_shrinking_set_alerts_and_is_merged(self):
        """A restored database must not freeze revocation for good."""
        a, b = uuid.uuid4().bytes, uuid.uuid4().bytes
        self.svc.put_revoked([a, b])
        got = self.svc.put_revoked([a])
        self.assertEqual(got["missing"], 1)
        self.assertEqual(got["total"], 2)
        self.assertTrue(any("missing" in m for _, m in self.alerts))

    def test_runaway_growth_is_taken_a_slice_a_call_and_alerted(self):
        """The lowest ids are taken, the rest wait for the next call, and a
        high alert says so."""
        self.cfg.revocation_growth_per_call = 5
        ids = sorted(uuid.uuid4().bytes for _ in range(12))
        got = self.svc.put_revoked(ids)
        self.assertEqual((got["added"], got["remaining"]), (5, 7))
        held = [r["credential_id"] for r in self.store.all(
            "SELECT credential_id FROM revoked ORDER BY credential_id")]
        self.assertEqual(held, ids[:5])
        self.assertIn(("high", "verify sent more new revocations than the "
                       "signer takes in one call (5); the rest come with the "
                       "next calls"), self.alerts)
        got = self.svc.put_revoked(ids)
        self.assertEqual((got["added"], got["remaining"]), (5, 2))
        got = self.svc.put_revoked(ids)
        self.assertEqual((got["added"], got["remaining"], got["total"]),
                         (2, 0, 12))
        # Once an hour, not once a call.
        self.assertEqual(sum(1 for a in self.alerts
                             if "in one call" in a[1]), 1)

    def test_nothing_is_built_from_part_of_the_set(self):
        """A bundle or feed from part of it would have phones forget ids
        they hold, after a rebuild."""
        self.cfg.revocation_growth_per_call = 5
        ids = [uuid.uuid4().bytes for _ in range(8)]
        self.svc.put_revoked(ids)

        def bundle():
            return self.svc.bundle(device_id=b"\x01" * 16, device_key_hash=b"h",
                                   epoch_keys=[], lease_seconds=30 * DAY,
                                   chains=True)

        _refused(self, "revocations_incomplete", bundle)
        _refused(self, "revocations_incomplete", self.svc.feed)
        self.svc.put_revoked(ids)
        bundle()
        self.svc.feed()

    def test_a_days_growth_is_alerted(self):
        self.cfg.revocation_alert_per_day = 3
        self.svc.put_revoked([uuid.uuid4().bytes for _ in range(3)])
        self.assertFalse([a for a in self.alerts if "in a day" in a[1]])
        self.svc.put_revoked([uuid.uuid4().bytes for _ in range(4)])
        self.assertIn(("high", "over 3 revocations added in a day"),
                      self.alerts)
        self.svc.put_revoked([uuid.uuid4().bytes for _ in range(2)])
        self.assertEqual(sum(1 for a in self.alerts if "in a day" in a[1]), 1)

    def test_two_operators_remove_a_planted_revocation(self):
        planted = uuid.uuid4().bytes
        self.svc.put_revoked([planted])
        conf = self.svc.revoked_remove([planted], by="alice")
        self.svc.confirm(conf["confirmation"], by="bob")
        self.assertIsNone(self.store.one(
            "SELECT 1 FROM revoked WHERE credential_id = ?", (planted,)))


class StatementTest(SignerTest):

    def setUp(self):
        super().setUp()
        self.key = self.ready()

    def test_a_thousand_fetches_cost_one_signature(self):
        pub = os.urandom(32)
        first = self.svc.statement(log_key_id=1, public_key=pub)
        for _ in range(1000):
            self.svc.statement(log_key_id=1, public_key=pub)
        n = self.store.one("SELECT COUNT(*) AS n FROM ledger WHERE "
                           "kind = 'sign' AND context = 'log-key'")["n"]
        self.assertEqual(n, 1)
        leaf_end = registry.get(self.store, self.key)["leaf_not_after"]
        self.assertLessEqual(first["not_after"],
                             leaf_end - self.cfg.margin_seconds)

    def test_a_new_log_key_alerts(self):
        self.svc.statement(log_key_id=1, public_key=os.urandom(32))
        self.assertTrue(any("new log key" in m for _, m in self.alerts))


class LogAckTest(SignerTest):
    """verify's acknowledgement of a phone's log upload: signed by the
    statement key, a ledger row each, under a ceiling per phone."""

    def setUp(self):
        super().setUp()
        self.key = self.ready()
        self.device = uuid.uuid4().bytes
        self.digest = os.urandom(32)

    def test_an_acknowledgement_is_signed_over_exactly_its_upload(self):
        from ovcrypto import devicelog

        got = self.svc.log_ack(device_id=self.device, through_seq=512,
                               digest=self.digest)
        self.assertEqual((got["format"], got["version"], got["sig_key_id"]),
                         ("CL03LA", 1, self.key))
        signed = devicelog.ack_signed_bytes(self.device, 512, self.digest,
                                            got["issued_at"], self.key)
        spki = registry.get(self.store, self.key)["spki"]
        self.assertTrue(keystore.verify(bytes(spki), signed,
                                        base64.b64decode(got["sig"])))
        n = self.store.one("SELECT COUNT(*) AS n FROM ledger WHERE "
                           "kind = 'sign' AND context = 'log-ack'")["n"]
        self.assertEqual(n, 1)

    def test_malformed_requests_are_refused(self):
        _refused(self, "policy", self.svc.log_ack, device_id=bytes(15),
                 through_seq=1, digest=self.digest)
        _refused(self, "policy", self.svc.log_ack, device_id=self.device,
                 through_seq=1, digest=bytes(31))
        _refused(self, "policy", self.svc.log_ack, device_id=self.device,
                 through_seq=-1, digest=self.digest)
        _refused(self, "policy", self.svc.log_ack, device_id=self.device,
                 through_seq=True, digest=self.digest)

    def test_one_phone_cannot_use_the_fleets_budget(self):
        limit = self.cfg.ceiling(cfgmod.LOG_ACK, "device")[1]
        for seq in range(limit):
            self.svc.log_ack(device_id=self.device, through_seq=seq + 1,
                             digest=self.digest)
        _refused(self, "subject_limit", self.svc.log_ack, device_id=self.device,
                 through_seq=limit + 1, digest=self.digest)
        # Another phone is not held up by it.
        self.svc.log_ack(device_id=uuid.uuid4().bytes, through_seq=1,
                         digest=self.digest)

    def test_it_is_answered_on_verifys_socket(self):
        from signer import transport

        self.assertIn("log_ack", transport.APP_OPS)
        self.assertIn("log_ack", transport.ROUTINE_OPS)


class SyncTimeTest(SignerTest):
    """verify's time at a phone's sync, over the phone's own nonce: signed by
    the statement key, a ledger row each, under a ceiling per phone."""

    def setUp(self):
        super().setUp()
        self.key = self.ready()
        self.device = uuid.uuid4().bytes
        self.nonce = os.urandom(16)

    def test_the_time_is_signed_over_the_phones_nonce(self):
        from ovcrypto import devicelog

        got = self.svc.sync_time(device_id=self.device, nonce=self.nonce)
        self.assertEqual((got["format"], got["version"], got["sig_key_id"]),
                         ("CL03ST", 1, self.key))
        signed = devicelog.time_signed_bytes(self.device, self.nonce,
                                             got["issued_at"], self.key)
        spki = registry.get(self.store, self.key)["spki"]
        self.assertTrue(keystore.verify(bytes(spki), signed,
                                        base64.b64decode(got["sig"])))
        n = self.store.one("SELECT COUNT(*) AS n FROM ledger WHERE "
                           "kind = 'sign' AND context = 'sync-time'")["n"]
        self.assertEqual(n, 1)

    def test_malformed_requests_are_refused(self):
        _refused(self, "policy", self.svc.sync_time, device_id=bytes(15),
                 nonce=self.nonce)
        _refused(self, "policy", self.svc.sync_time, device_id=self.device,
                 nonce=bytes(15))
        _refused(self, "policy", self.svc.sync_time, device_id=self.device,
                 nonce=bytes(32))

    def test_one_phone_cannot_use_the_fleets_budget(self):
        limit = self.cfg.ceiling(cfgmod.SYNC_TIME, "device")[1]
        for _ in range(limit):
            self.svc.sync_time(device_id=self.device, nonce=self.nonce)
        _refused(self, "subject_limit", self.svc.sync_time,
                 device_id=self.device, nonce=self.nonce)
        self.svc.sync_time(device_id=uuid.uuid4().bytes, nonce=self.nonce)

    def test_it_is_answered_on_verifys_socket(self):
        from signer import transport

        self.assertIn("sync_time", transport.APP_OPS)
        self.assertIn("sync_time", transport.ROUTINE_OPS)


class LifecycleTest(SignerTest):

    def test_key_ids_start_at_16_and_are_never_reused(self):
        first = self.svc.keygen(by="alice")["key_id"]
        self.assertEqual(first, 16)
        self.store.db.execute("DELETE FROM keys WHERE key_id = 16")
        self.assertEqual(self.svc.keygen(by="alice")["key_id"], 17)

    def test_publishing_needs_a_second_operator(self):
        made = self.svc.keygen(by="alice")
        self.svc.install_cert(made["key_id"],
                              self.certify(made["key_id"], made["csr"]),
                              by="alice")
        conf = self.svc.publish(made["key_id"], by="alice")
        _refused(self, "policy", self.svc.confirm, conf["confirmation"],
                 by="alice")
        self.clock.advance(25 * 3600)
        _refused(self, "policy", self.svc.confirm, conf["confirmation"],
                 by="bob")

    def _sync(self, device, chains=True):
        self.svc.bundle(device_id=device, device_key_hash=b"h", epoch_keys=[],
                        lease_seconds=30 * DAY, chains=chains)

    def test_the_gate_waits_for_every_recent_device(self):
        """Switching early would leave a phone refusing the new signer."""
        self.ready()
        self._sync(b"\x01" * 16)
        nxt = self.ready_key(activate=False)
        _refused(self, "gate", self.svc.activate, nxt, by="alice")
        self.clock.advance(60)
        self._sync(b"\x01" * 16)          # now holds a bundle listing nxt
        self.svc.activate(nxt, by="alice")

    def test_the_gate_opens_after_a_lease_whoever_has_synced(self):
        self.ready()
        self._sync(b"\x01" * 16)
        nxt = self.ready_key(activate=False)
        self.clock.advance(30 * DAY)
        self.svc.activate(nxt, by="alice")

    def test_a_switch_retires_and_destroys_the_previous_key(self):
        old = self.ready()
        ref = registry.get(self.store, old)["key_ref"]
        nxt = self.ready_key(activate=False)
        self.clock.advance(30 * DAY)
        self.svc.activate(nxt, by="alice")
        row = registry.get(self.store, old)
        self.assertEqual(row["state"], registry.RETIRED)
        self.assertLessEqual(row["window_end"], self.clock.now())
        self.assertFalse(os.path.exists(os.path.join(self.dir, "keys", ref)))

    def test_install_refuses_a_certificate_from_another_ca(self):
        other_key = ec.generate_private_key(ec.SECP256R1())
        from ovcrypto import pki
        other = pki.make_ca(other_key, "Other CA", T0 - DAY, T0 + 3650 * DAY,
                            serial=9)
        made = self.svc.keygen(by="alice")
        cert = self.certify(made["key_id"], made["csr"], ca_key=other_key,
                            ca=other)
        err = _refused(self, "certificate", self.svc.install_cert,
                       made["key_id"], cert)
        self.assertIn("unknown_ca", str(err))

    def test_install_refuses_another_keys_certificate(self):
        a = self.svc.keygen(by="alice")
        b = self.svc.keygen(by="alice")
        _refused(self, "certificate", self.svc.install_cert, a["key_id"],
                 self.certify(b["key_id"], b["csr"]))

    def test_install_refuses_a_short_certificate(self):
        made = self.svc.keygen(by="alice")
        _refused(self, "certificate", self.svc.install_cert, made["key_id"],
                 self.certify(made["key_id"], made["csr"], days=400))

    def test_the_deployment_key_needs_the_infrastructure_eku(self):
        """A credential-only certificate cannot make a key that signs bundles."""
        made = self.svc.keygen(by="alice")
        err = _refused(self, "certificate", self.svc.install_cert,
                       made["key_id"], self.certify(made["key_id"], made["csr"],
                                                    organization=ORG))
        self.assertIn("infrastructure", str(err))

    def test_an_organization_key_needs_an_organization_certificate(self):
        made = self.svc.keygen(organization=ORG, by="alice")
        _refused(self, "certificate", self.svc.install_cert, made["key_id"],
                 self.certify(made["key_id"], made["csr"]))
        other_org = str(uuid.uuid4())
        _refused(self, "certificate", self.svc.install_cert, made["key_id"],
                 self.certify(made["key_id"], made["csr"],
                              organization=other_org))


class LedgerTest(SignerTest):

    def test_the_chain_holds_and_a_changed_row_is_found(self):
        key = self.ready()
        self.sign_ok(key)
        rows = ledger.rows_since(self.store, 0)
        self.assertGreater(ledger.verify_chain(rows), 5)
        self.store.db.execute("UPDATE ledger SET summary = '{}' WHERE seq = 3")
        with self.assertRaises(ValueError):
            ledger.verify_chain(ledger.rows_since(self.store, 0))

    def test_every_signature_is_in_the_ledger(self):
        key = self.ready()
        message = self.credential(key)
        self.svc.sign_credential(message)
        row = self.store.one("SELECT * FROM ledger WHERE context = 'credential'")
        import hashlib
        self.assertEqual(row["digest"], hashlib.sha256(message).hexdigest())



class AlertDeliveryTest(SignerTest):
    """An alert leaves only after its transaction commits and the lock frees."""

    def _other_thread_can_lock(self):
        got = []

        def probe():
            ok = self.store.lock.acquire(timeout=0.5)
            if ok:
                self.store.lock.release()
            got.append(ok)

        thread = threading.Thread(target=probe)
        thread.start()
        thread.join()
        return got[0]

    def test_alerts_are_sent_after_commit_outside_the_lock(self):
        seen = []
        self.svc._alert_hook = lambda severity, message, fields: seen.append(
            (self.store.db.in_transaction, self._other_thread_can_lock()))
        self.ready()
        self.svc.pause("credential", by="app")
        self.assertTrue(seen)
        self.assertEqual(set(seen), {(False, True)})

    def test_a_device_over_its_cap_is_heard_of_once_a_window(self):
        self.ready()
        self.cfg.ceilings[("bundle", "device")] = (None, 1, None)
        args = dict(device_id=b"\x01" * 16, device_key_hash=b"h",
                    epoch_keys=[], lease_seconds=30 * DAY)
        self.svc.bundle(**args)

        def alerts():
            return (len([m for _, m in self.alerts if "over its bundle" in m]),
                    self.store.one("SELECT COUNT(*) AS n FROM ledger WHERE "
                                   "kind = 'alert' AND summary LIKE "
                                   "'%over its bundle%'")["n"])

        for _ in range(5):
            _refused(self, "subject_limit", self.svc.bundle, **args)
        self.assertEqual(alerts(), (1, 1))
        self.clock.advance(3601)
        self.svc.bundle(**args)
        _refused(self, "subject_limit", self.svc.bundle, **args)
        self.assertEqual(alerts(), (2, 2))


class SnsTimeoutTest(unittest.TestCase):

    def test_an_alert_gets_seconds_and_one_try(self):
        from signer import aws

        captured = {}

        class Config:
            def __init__(self, **kwargs):
                captured.update(kwargs)

        boto3 = types.SimpleNamespace(
            client=lambda *a, **k: captured.setdefault("client", k))
        botocore = types.ModuleType("botocore")
        botocore_config = types.ModuleType("botocore.config")
        botocore_config.Config = Config
        botocore.config = botocore_config
        with mock.patch.dict(sys.modules, {"boto3": boto3, "botocore": botocore,
                                           "botocore.config": botocore_config}):
            aws.SnsAlerts("arn:aws:sns:x:1:t", "ap-southeast-1", "verify")
        self.assertIn("config", captured["client"])
        self.assertLessEqual(captured["connect_timeout"], 5)
        self.assertLessEqual(captured["read_timeout"], 10)
        self.assertEqual(captured["retries"]["max_attempts"], 1)


class LogKeyBindingTest(SignerTest):

    def setUp(self):
        super().setUp()
        self.ready()

    def test_a_log_key_id_is_32_bits(self):
        head = ledger.head(self.store)
        _refused(self, "policy", self.svc.statement, log_key_id=2 ** 40,
                 public_key=b"\x01" * 32)
        self.assertEqual(ledger.head(self.store), head)

    def test_one_id_names_one_public_key_for_good(self):
        self.svc.statement(log_key_id=3, public_key=b"\x01" * 32)
        _refused(self, "policy", self.svc.statement, log_key_id=3,
                 public_key=b"\x02" * 32)
        self.assertIn("high", [s for s, m in self.alerts
                               if "another public key" in m])
        self.svc.statement(log_key_id=4, public_key=b"\x02" * 32)
        self.svc.statement(log_key_id=3, public_key=b"\x01" * 32)


class CertificateBindingTest(SignerTest):

    def test_a_deployment_key_needs_both_ekus(self):
        made = self.svc.keygen(by="alice")
        csr = x509.load_pem_x509_csr(made["csr"].encode())
        leaf = pki.leaf_builder(
            self.ca_key, self.ca, csr.public_key(), T0 - 60, T0 + 730 * DAY,
            serial=x509.random_serial_number(), common_name="infrastructure",
            ekus=(chain.INFRASTRUCTURE_EKU,))
        err = _refused(self, "certificate", self.svc.install_cert,
                       made["key_id"], leaf.public_bytes(
                           serialization.Encoding.DER))
        self.assertIn("credential EKU", str(err))

    def test_a_publish_is_for_the_certificate_it_was_asked_for(self):
        made = self.svc.keygen(by="alice")
        key_id = made["key_id"]
        self.svc.install_cert(key_id, self.certify(key_id, made["csr"]),
                              by="alice")
        conf = self.svc.publish(key_id, by="alice")
        # Another certificate for the same key cannot be slipped in while the
        # second operator is being asked...
        _refused(self, "policy", self.svc.install_cert, key_id,
                 self.certify(key_id, made["csr"]))
        # ...and one changed underneath is not what they confirm.
        with self.store as db:
            db.execute("UPDATE keys SET leaf = ? WHERE key_id = ?",
                       (self.certify(key_id, made["csr"]), key_id))
        _refused(self, "policy", self.svc.confirm, conf["confirmation"],
                 by="bob")
        self.assertEqual(registry.get(self.store, key_id)["state"],
                         registry.CERTIFIED)


class HolderCeilingTest(SignerTest):

    def setUp(self):
        super().setUp()
        self.key = self.ready()

    def test_one_holder_cannot_spend_every_holders_budget(self):
        self.cfg.ceilings[("credential", "holder_id")] = (2, None, None)
        for _ in range(2):
            self.sign_ok(self.key, holder=True, holder_id="h1")
        _refused(self, "subject_limit", self.sign_ok, self.key, holder=True,
                 holder_id="h1")
        self.sign_ok(self.key, holder=True, holder_id="h2")

    def test_no_principal_reaches_a_global_cap_alone(self):
        """A quarter at most: four at their caps, or a compromised app."""
        for (context, kind), limits in cfgmod.DEFAULT_CEILINGS.items():
            if kind == "*":
                continue
            for mine, total in zip(limits, cfgmod.DEFAULT_CEILINGS[(context, "*")]):
                if mine is not None and total is not None:
                    self.assertLessEqual(4 * mine, total, (context, kind))

    def test_thirty_phones_at_their_cap_leave_the_fleet_room(self):
        per_device = cfgmod.DEFAULT_CEILINGS[("bundle", "device")]
        total = cfgmod.DEFAULT_CEILINGS[("bundle", "*")]
        for mine, all_ in zip(per_device, total):
            if mine is not None:
                self.assertLess(30 * mine, all_ / 2)
