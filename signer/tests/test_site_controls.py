"""Every key from verify's pages, where the host's policy says so.

`site_controls_all_keys` is meant for a site whose app servers are replaced
at every release: one site admin publishes and starts the deployment's keys
as well as organizations', unsuspends a key, resumes a paused context and
withdraws any key, with no operator on the host. Off by default, and then
nothing here is reachable. Each test says what the switch would give away if
it leaked.
"""

import json
import os

from signer import adopt, aws, config as cfgmod, registry
from signer.transport import Dispatcher

from .helpers import ORG, ORG_NAME, SignerTest
from .test_org_ca import _Base, _refused

SAM = "Sam Admin (user 7)"


class _Controls(_Base):

    def ledger(self, kind, context):
        return [json.loads(r["summary"]) for r in self.store.all(
            "SELECT summary FROM ledger WHERE kind = ? AND context = ? "
            "ORDER BY seq", (kind, context))]

    def certified_deployment_key(self):
        """A deployment key made and certified on the host, not published."""
        made = self.svc.keygen(by="alice")
        self.svc.install_cert(made["key_id"],
                              self.certify(made["key_id"], made["csr"]),
                              by="alice")
        return made["key_id"]

    def high(self):
        return [m for severity, m in self.alerts if severity == "high"]


class OffByDefaultTest(_Controls):
    """The rule stands unless root on the host changes it."""

    def test_the_policy_says_no_unless_set(self):
        self.assertFalse(cfgmod.Config().site_controls_all_keys)
        self.assertIs(self.svc.public()["site_controls_all_keys"], False)

    def test_nothing_is_withdrawn_unsuspended_or_resumed_from_the_site(self):
        """Else one admin session could stop every phone's sync."""
        self.svc.suspend(self.deployment)
        self.svc.pause("credential", reason="test")
        for fn, arg in ((self.svc.site_withdraw, self.deployment),
                        (self.svc.site_unsuspend, self.deployment),
                        (self.svc.site_resume, "credential")):
            with self.subTest(fn=fn.__name__):
                err = _refused(self, "policy", fn, arg, operator=SAM)
                self.assertIn("signer host", err.detail)
        row = registry.get(self.store, self.deployment)
        self.assertEqual(row["state"], registry.ACTIVE)
        self.assertIsNotNone(row["suspended_at"])
        self.assertTrue(self.store.all("SELECT 1 FROM pauses"))

    def test_publishing_organization_keys_alone_is_not_enough(self):
        """The narrower switch publishes organization keys, nothing more."""
        self.cfg.site_publishes_organization_keys = True
        self.svc.suspend(self.deployment)
        _refused(self, "policy", self.svc.site_withdraw, self.deployment,
                 operator=SAM)
        _refused(self, "policy", self.svc.site_unsuspend, self.deployment,
                 operator=SAM)
        key_id = self.certified_deployment_key()
        err = _refused(self, "policy", self.svc.org_publish, key_id,
                       operator=SAM)
        self.assertIn("deployment", err.detail)


class SiteControlsTest(_Controls):

    def setUp(self):
        super().setUp()
        self.cfg.site_controls_all_keys = True

    # -- publish and start -------------------------------------------------

    def test_a_deployment_key_is_published_and_started_from_the_site(self):
        key_id = self.certified_deployment_key()
        self.alerts.clear()
        self.assertEqual(self.svc.org_publish(key_id, operator=SAM),
                         {"published": key_id})
        ctx, _ = self.accept()
        self.assertIn(key_id, ctx.entries)
        # It waits for the phones, as `cl03signer activate` does.
        self.svc.bundle(device_id=self.device, device_key_hash=b"h",
                        epoch_keys=[], lease_seconds=30 * 86400)
        self.assertEqual(self.svc.org_activate(key_id, operator=SAM),
                         {"active": key_id})
        self.assertEqual(registry.get(self.store, self.deployment)["state"],
                         registry.RETIRED)
        for context in ("publish", "activate"):
            with self.subTest(context=context):
                event = self.ledger("key", context)[-1]
                self.assertEqual((event["key_id"], event["by"],
                                  event["operator"]), (key_id, "app", SAM))
        self.assertEqual(len(self.high()), 2, self.alerts)
        self.assertTrue(all(SAM in m and "deployment key" in m
                            for m in self.high()), self.alerts)

    def test_the_switch_gate_still_holds_a_deployment_key(self):
        """It is a safety rule, not a second person: phones without the key
        would refuse every bundle it signs."""
        self.svc.bundle(device_id=self.device, device_key_hash=b"h",
                        epoch_keys=[], lease_seconds=30 * 86400)
        key_id = self.certified_deployment_key()
        self.svc.org_publish(key_id, operator=SAM)
        _refused(self, "gate", self.svc.org_activate, key_id, operator=SAM)

    def test_an_organization_key_needs_no_other_switch(self):
        self.install_org_ca()
        key_id = self.svc.org_generate(organization=ORG,
                                       name=ORG_NAME)["key_id"]
        self.assertFalse(self.cfg.site_publishes_organization_keys)
        self.svc.org_publish(key_id, operator=SAM)
        self.assertEqual(registry.get(self.store, key_id)["state"],
                         registry.PUBLISHED)

    def test_a_legacy_key_stays_the_policys(self):
        """Key 1's window comes from policy.toml, changed by two operators."""
        for fn in (self.svc.org_publish, self.svc.org_activate,
                   self.svc.site_withdraw, self.svc.site_unsuspend):
            with self.subTest(fn=fn.__name__):
                _refused(self, "unknown_key", fn, 1, operator=SAM)

    # -- withdraw ----------------------------------------------------------

    def test_the_deployment_key_is_withdrawn_at_once_and_syncs_stop(self):
        """What the switch costs: one admin stops every phone's sync."""
        self.alerts.clear()
        self.assertEqual(self.svc.site_withdraw(self.deployment, operator=SAM),
                         {"withdrawn": self.deployment})
        row = registry.get(self.store, self.deployment)
        self.assertEqual(row["state"], registry.WITHDRAWN)
        self.assertIsNone(row["key_ref"])
        _refused(self, "no_key", self.svc.bundle, device_id=self.device,
                 device_key_hash=b"h", epoch_keys=[],
                 lease_seconds=30 * 86400)
        event = self.ledger("key", "withdraw")[-1]
        self.assertEqual((event["key_id"], event["by"], event["operator"]),
                         (self.deployment, "app", SAM))
        self.assertTrue(event["tombstone"])
        [message] = self.high()
        self.assertIn(SAM, message)
        self.assertIn("every phone's sync", message)

    def test_an_organization_key_is_withdrawn_and_travels_as_a_tombstone(self):
        self.install_org_ca()
        key_id = self.svc.org_generate(organization=ORG,
                                       name=ORG_NAME)["key_id"]
        self.svc.org_publish(key_id, operator=SAM)
        self.svc.site_withdraw(key_id, operator=SAM)
        entries, _ = registry.trust_list(self.store, self.cfg,
                                         self.clock.now())
        stone = [e for e in entries if e.key_id == key_id]
        self.assertTrue(stone and stone[0].is_tombstone)
        self.assertNotIn("every phone's sync", self.high()[-1])

    def test_a_key_never_published_is_discarded_not_withdrawn(self):
        key_id = self.certified_deployment_key()
        err = _refused(self, "policy", self.svc.site_withdraw, key_id,
                       operator=SAM)
        self.assertIn("discard", err.detail)
        self.svc.site_withdraw(self.deployment, operator=SAM)
        _refused(self, "policy", self.svc.site_withdraw, self.deployment,
                 operator=SAM)

    def test_a_rebuilt_host_brings_the_withdrawal_back(self):
        """The ledger row is the host's own shape, so `adopt` reads it."""
        uploader = aws.FakeUploader()
        shipper = aws.Shipper(self.store, uploader, "verify", self.clock)
        self.svc.site_withdraw(self.deployment, operator=SAM)
        shipper.ship()
        from signer.store import Store
        store = Store(os.path.join(self.dir, "rebuilt.db"))
        self.addCleanup(store.db.close)
        adopt.adopt(store, self.cfg, self.keys, uploader, "verify",
                    now=self.clock.now())
        self.assertEqual(registry.get(store, self.deployment)["state"],
                         registry.WITHDRAWN)

    # -- unsuspend and resume ----------------------------------------------

    def test_a_suspended_key_is_resumed_from_the_site(self):
        self.svc.suspend(self.deployment)
        _refused(self, "key_suspended", self.sign_ok, self.deployment)
        self.alerts.clear()
        self.assertEqual(self.svc.site_unsuspend(self.deployment, operator=SAM),
                         {"unsuspended": self.deployment})
        self.sign_ok(self.deployment)
        self.assertEqual(self.ledger("key", "unsuspend")[-1]["operator"], SAM)
        self.assertTrue(any(SAM in m for m in self.high()), self.alerts)
        _refused(self, "policy", self.svc.site_unsuspend, self.deployment,
                 operator=SAM)

    def test_a_pause_is_lifted_from_the_site(self):
        """The global ceiling's pause too, which otherwise waits for an
        operator on the host."""
        self.svc.pause("credential", reason="Setup")
        _refused(self, "paused", self.sign_ok, self.deployment)
        self.alerts.clear()
        self.assertEqual(self.svc.site_resume("credential", operator=SAM),
                         {"resumed": "credential"})
        self.sign_ok(self.deployment)
        resumed = self.ledger("admin", "resume")[-1]
        self.assertEqual((resumed["context"], resumed["operator"]),
                         ("credential", SAM))
        self.assertTrue(any(SAM in m for m in self.high()), self.alerts)
        _refused(self, "policy", self.svc.site_resume, "credential",
                 operator=SAM)
        _refused(self, "policy", self.svc.site_resume, "everything",
                 operator=SAM)

    # -- who asked, and on which socket --------------------------------------

    def test_the_admin_who_asked_is_named(self):
        self.svc.suspend(self.deployment)
        for operator in ("", "   ", "Sam\nAdmin", "Sam ", None,
                         "S" * 201):
            with self.subTest(operator=str(operator)[:8]):
                _refused(self, "policy", self.svc.site_unsuspend,
                         self.deployment, operator=operator)
                _refused(self, "policy", self.svc.site_withdraw,
                         self.deployment, operator=operator)
        self.assertEqual(registry.get(self.store, self.deployment)["state"],
                         registry.ACTIVE)

    def test_the_app_socket_answers_and_the_admin_socket_does_not(self):
        """On the host one operator would withdraw alone, under any name."""
        dispatcher = Dispatcher(self.svc)
        self.svc.suspend(self.deployment)
        for op, args in (("site_unsuspend", {"key_id": self.deployment}),
                         ("site_resume", {"context": "credential"}),
                         ("site_withdraw", {"key_id": self.deployment})):
            with self.subTest(op=op):
                reply = dispatcher.handle(
                    {"op": op, "args": dict(args, operator=SAM)}, admin=True,
                    by="mallory")
                self.assertEqual(reply["reason"], "forbidden")
        self.assertEqual(dispatcher.handle(
            {"op": "site_unsuspend",
             "args": {"key_id": self.deployment, "operator": SAM}},
            admin=False, by="app"),
            {"ok": True, "result": {"unsuspended": self.deployment}})
        self.svc.pause("credential")
        self.assertEqual(dispatcher.handle(
            {"op": "site_resume",
             "args": {"context": "credential", "operator": SAM}},
            admin=False, by="app"),
            {"ok": True, "result": {"resumed": "credential"}})
        self.assertEqual(dispatcher.handle(
            {"op": "site_withdraw",
             "args": {"key_id": self.deployment, "operator": SAM}},
            admin=False, by="app"),
            {"ok": True, "result": {"withdrawn": self.deployment}})

    def test_public_tells_the_site(self):
        self.assertIs(self.svc.public()["site_controls_all_keys"], True)


class SiteControlsPolicyFileTest(SignerTest):

    def _load(self, text):
        path = os.path.join(self.dir, "policy.toml")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text + '\n[runtime]\nsite = "x"\n')
        return cfgmod.load(path)

    def test_read_from_the_policy_file_and_off_without_it(self):
        self.assertFalse(self._load("").site_controls_all_keys)
        self.assertTrue(self._load("site_controls_all_keys = true")
                        .site_controls_all_keys)
        self.assertFalse(self._load("site_controls_all_keys = false")
                         .site_controls_all_keys)

    def test_a_quoted_value_is_refused_not_read_as_yes(self):
        for text in ('site_controls_all_keys = "false"',
                     "site_controls_all_keys = 1"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    self._load(text)


class HeldKeyControlsTest(SignerTest):
    """A `[[held]]` key is the policy's, as a legacy key is: the switch does
    not reach it."""

    def setUp(self):
        super().setUp()
        from signer.service import SignerService
        from signer.store import Store

        from .helpers import DAY, LEGACY_KEY, spki_of
        from .test_held import _pem

        self.store = Store(os.path.join(self.dir, "held.db"))
        self.addCleanup(self.store.db.close)
        with open(os.path.join(self.dir, "keys", "key-1.pem"), "wb") as handle:
            handle.write(_pem(LEGACY_KEY))
        now = self.clock.now()
        self.cfg.legacy = []
        self.cfg.held = [cfgmod.Held(1, "key-1.pem", spki_of(LEGACY_KEY),
                                     now - 200 * DAY, now + 100 * DAY)]
        self.cfg.site_controls_all_keys = True
        self.svc = SignerService(self.store, self.keys, self.cfg,
                                 clock=self.clock, alerts=lambda *a: None)

    def test_nothing_the_switch_allows_moves_it(self):
        _refused(self, "policy", self.svc.org_activate, 1, operator=SAM)
        self.svc.activate(1, by="alice")
        self.svc.suspend(1)
        for fn in (self.svc.site_unsuspend, self.svc.site_withdraw):
            with self.subTest(fn=fn.__name__):
                err = _refused(self, "policy", fn, 1, operator=SAM)
                self.assertIn("held", err.detail)
        row = registry.get(self.store, 1)
        self.assertEqual(row["state"], registry.ACTIVE)
        self.assertIsNotNone(row["suspended_at"])


class SuspendAttributionTest(_Controls):
    """A suspension from verify's pages names the admin, as the other site
    operations do; on the host the socket names the operator."""

    def test_the_site_admin_is_named_in_the_ledger_and_the_alert(self):
        self.alerts.clear()
        Dispatcher(self.svc).handle(
            {"op": "suspend", "args": {"key_id": self.deployment,
                                       "operator": SAM}},
            admin=False, by="app")
        event = self.ledger("key", "suspend")[-1]
        self.assertEqual((event["by"], event["operator"]), ("app", SAM))
        self.assertTrue(any(SAM in m for _, m in self.alerts), self.alerts)

    def test_a_name_that_cannot_be_recorded_does_not_stop_the_suspension(self):
        self.svc.suspend(self.deployment, operator="Sam\nkey 99 withdrawn")
        self.assertIsNotNone(
            registry.get(self.store, self.deployment)["suspended_at"])
        self.assertNotIn("\n", self.ledger("key", "suspend")[-1]["operator"])

    def test_on_the_admin_socket_the_operator_is_the_sockets(self):
        Dispatcher(self.svc).handle(
            {"op": "suspend", "args": {"key_id": self.deployment,
                                       "operator": "somebody else"}},
            admin=True, by="alice")
        event = self.ledger("key", "suspend")[-1]
        self.assertEqual(event["by"], "alice")
        self.assertNotIn("operator", event)
