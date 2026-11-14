"""An organization's key published and started from verify's pages.

Only where the host's policy sets `site_publishes_organization_keys`: one site
admin then does what two operators do on the host, for an organization's key
and nothing else (signer/deploy/README.md, "Publishing from the site"). Each
test names what a compromised app, or a careless admin, would get from a
signer that allowed more.
"""

import json
import os
import uuid

from signer import config as cfgmod, registry
from signer.transport import Dispatcher

from .helpers import DAY, ORG, ORG_NAME, SignerTest
from .test_org_ca import _Base, _refused

SAM = "Sam Admin (user 7)"


class SitePublishTest(_Base):

    def setUp(self):
        super().setUp()
        self.install_org_ca()
        self.cfg.site_publishes_organization_keys = True

    def generate(self, organization=ORG, name=ORG_NAME):
        return self.svc.org_generate(organization=organization,
                                     name=name)["key_id"]

    def sync(self, device=None):
        self.svc.bundle(device_id=device or self.device, device_key_hash=b"h",
                        epoch_keys=[], lease_seconds=30 * DAY)

    def ledger(self, context):
        return [json.loads(r["summary"]) for r in self.store.all(
            "SELECT summary FROM ledger WHERE kind = 'key' AND context = ? "
            "ORDER BY seq", (context,))]

    def test_off_unless_the_host_turns_it_on(self):
        """Else every deployment's site admins could put a name on phones."""
        self.cfg.site_publishes_organization_keys = False
        key_id = self.generate()
        err = _refused(self, "policy", self.svc.org_publish, key_id,
                       operator=SAM)
        self.assertIn("signer host", err.detail)
        self.assertEqual(registry.get(self.store, key_id)["state"],
                         registry.CERTIFIED)
        self.publish(key_id, activate=False)     # the host's way still works
        _refused(self, "policy", self.svc.org_activate, key_id, operator=SAM)

    def test_one_admin_publishes_and_phones_get_it_at_their_next_sync(self):
        key_id = self.generate()
        self.assertEqual(self.svc.org_publish(key_id, operator=SAM),
                         {"published": key_id})
        ctx, _ = self.accept()
        self.assertEqual(ctx.entries[key_id].organization, ORG_NAME)

    def test_nothing_signs_with_it_until_it_is_started(self):
        key_id = self.generate()
        self.svc.org_publish(key_id, operator=SAM)
        self.assertEqual(self.sign_ok(self.deployment, organization=ORG,
                                      issuer_name=ORG_NAME)["key_id"],
                         self.deployment)
        self.assertEqual(self.svc.org_activate(key_id, operator=SAM),
                         {"active": key_id})
        self.assertEqual(self.sign_ok(key_id, organization=ORG,
                                      issuer_name=ORG_NAME)["key_id"], key_id)

    def test_the_ledger_and_a_high_alert_name_the_admin_and_the_name(self):
        """The name on every phone changed: who did it must be on record."""
        key_id = self.generate()
        self.alerts.clear()
        self.svc.org_publish(key_id, operator=SAM)
        self.svc.org_activate(key_id, operator=SAM)
        for context in ("publish", "activate"):
            with self.subTest(context=context):
                event = self.ledger(context)[-1]
                self.assertEqual((event["key_id"], event["by"],
                                  event["operator"]), (key_id, "app", SAM))
        self.assertEqual(self.ledger("publish")[-1]["name"], ORG_NAME)
        high = [m for severity, m in self.alerts if severity == "high"]
        self.assertEqual(len(high), 2, self.alerts)
        self.assertTrue(all(SAM in m and ORG_NAME in m for m in high), high)

    def test_the_admin_who_asked_is_named(self):
        key_id = self.generate()
        for operator in ("", "   ", "Sam\nAdmin", None):
            with self.subTest(operator=operator):
                _refused(self, "policy", self.svc.org_publish, key_id,
                         operator=operator)
        self.assertEqual(registry.get(self.store, key_id)["state"],
                         registry.CERTIFIED)

    def test_the_deployment_keys_stay_on_the_host(self):
        """Its key signs bundles and feeds: the whole phone, not one name."""
        made = self.svc.keygen(by="alice")
        self.svc.install_cert(made["key_id"],
                              self.certify(made["key_id"], made["csr"]),
                              by="alice")
        for fn in (self.svc.org_publish, self.svc.org_activate):
            with self.subTest(fn=fn.__name__):
                _refused(self, "policy", fn, made["key_id"], operator=SAM)
        _refused(self, "unknown_key", self.svc.org_publish, 1, operator=SAM)
        _refused(self, "unknown_key", self.svc.org_publish, 999, operator=SAM)

    def test_only_a_certified_key_is_published_and_a_published_one_started(self):
        waiting = self.svc.org_keygen(organization=ORG)["key_id"]
        _refused(self, "policy", self.svc.org_publish, waiting, operator=SAM)
        self.svc.discard(waiting)
        key_id = self.generate()
        _refused(self, "policy", self.svc.org_activate, key_id, operator=SAM)
        self.svc.org_publish(key_id, operator=SAM)
        _refused(self, "policy", self.svc.org_publish, key_id, operator=SAM)

    def test_a_suspended_key_is_not_started(self):
        key_id = self.generate()
        self.svc.org_publish(key_id, operator=SAM)
        self.svc.suspend(key_id)
        _refused(self, "policy", self.svc.org_activate, key_id, operator=SAM)

    def test_a_first_key_waits_for_the_phones_that_synced(self):
        """Its organization's documents were the deployment key's before it;
        a phone without the new key would refuse them."""
        self.sync()
        key_id = self.generate()
        self.svc.org_publish(key_id, operator=SAM)
        _refused(self, "gate", self.svc.org_activate, key_id, operator=SAM)
        # The host's own activate keeps the same rule.
        _refused(self, "gate", self.svc.activate, key_id, by="alice")
        self.clock.advance(60)
        self.sync()
        self.svc.org_activate(key_id, operator=SAM)

    def test_the_gate_opens_after_a_lease_whoever_has_synced(self):
        self.sync()
        key_id = self.generate()
        self.svc.org_publish(key_id, operator=SAM)
        self.clock.advance(30 * DAY)
        self.svc.org_activate(key_id, operator=SAM)

    def test_starting_the_next_key_retires_the_one_before(self):
        first = self.generate()
        self.svc.org_publish(first, operator=SAM)
        self.svc.org_activate(first, operator=SAM)
        ref = registry.get(self.store, first)["key_ref"]
        nxt = self.generate()
        self.svc.org_publish(nxt, operator=SAM)
        self.svc.org_activate(nxt, operator=SAM)
        row = registry.get(self.store, first)
        self.assertEqual(row["state"], registry.RETIRED)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "keys", ref)))

    def test_one_organizations_admin_action_leaves_the_others_alone(self):
        other = str(uuid.uuid4())
        mine = self.generate()
        theirs = self.generate(organization=other, name="Beta Office")
        self.svc.org_publish(mine, operator=SAM)
        self.svc.org_activate(mine, operator=SAM)
        self.assertEqual(registry.get(self.store, theirs)["state"],
                         registry.CERTIFIED)

    def test_withdrawing_stays_on_the_host(self):
        key_id = self.generate()
        self.svc.org_publish(key_id, operator=SAM)
        got = Dispatcher(self.svc).handle(
            {"op": "withdraw", "args": {"key_id": key_id}}, admin=False,
            by="app")
        self.assertEqual(got["reason"], "forbidden")

    def test_the_app_socket_answers_and_names_the_operator(self):
        key_id = self.generate()
        d = Dispatcher(self.svc)
        got = d.handle({"op": "org_publish",
                        "args": {"key_id": key_id, "operator": SAM}},
                       admin=False, by="app")
        self.assertEqual(got, {"ok": True, "result": {"published": key_id}})
        self.assertEqual(self.ledger("publish")[-1]["operator"], SAM)
        got = d.handle({"op": "org_activate", "args": {"key_id": key_id}},
                       admin=False, by="app")
        self.assertEqual(got["reason"], "policy")
        got = d.handle({"op": "org_activate",
                        "args": {"key_id": key_id, "operator": SAM}},
                       admin=False, by="app")
        self.assertEqual(got, {"ok": True, "result": {"active": key_id}})

    def test_public_tells_the_site_whether_it_may(self):
        self.assertIs(self.svc.public()["site_publishes_organization_keys"],
                      True)
        self.cfg.site_publishes_organization_keys = False
        self.assertIs(self.svc.public()["site_publishes_organization_keys"],
                      False)


class SitePublishPolicyFileTest(SignerTest):

    def _load(self, text):
        path = os.path.join(self.dir, "policy.toml")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text + '\n[runtime]\nsite = "x"\n')
        return cfgmod.load(path)

    def test_read_from_the_policy_file_and_off_without_it(self):
        self.assertFalse(self._load("").site_publishes_organization_keys)
        self.assertTrue(self._load("site_publishes_organization_keys = true")
                        .site_publishes_organization_keys)
        self.assertFalse(self._load("site_publishes_organization_keys = false")
                         .site_publishes_organization_keys)

    def test_a_quoted_value_is_refused_not_read_as_yes(self):
        for text in ('site_publishes_organization_keys = "false"',
                     "site_publishes_organization_keys = 0"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    self._load(text)


class SitePublishEdgeCasesTest(_Base):

    def setUp(self):
        super().setUp()
        self.install_org_ca()
        self.cfg.site_publishes_organization_keys = True

    def generate(self, organization=ORG, name=ORG_NAME):
        return self.svc.org_generate(organization=organization,
                                     name=name)["key_id"]

    def test_a_key_its_ca_certified_for_another_site_is_neither_published_nor_started(self):
        """The site moved to another domain after the key was certified:
        phones paired with it would drop the key, so its documents would
        fail everywhere."""
        key_id = self.generate()
        self.cfg.site_domain = "elsewhere.example.ph"
        err = _refused(self, "organization_ca", self.svc.org_publish, key_id,
                       operator=SAM)
        self.assertIn("not for elsewhere.example.ph", err.detail)
        conf = self.svc.publish(key_id, by="alice")      # the host's way too
        _refused(self, "organization_ca", self.svc.confirm,
                 conf["confirmation"], by="bob")
        self.assertEqual(registry.get(self.store, key_id)["state"],
                         registry.CERTIFIED)
        # Published while it still matched, started after the move.
        self.cfg.site_domain = "verify.example.ph"
        self.svc.org_publish(key_id, operator=SAM)
        self.cfg.site_domain = "elsewhere.example.ph"
        _refused(self, "organization_ca", self.svc.org_activate, key_id,
                 operator=SAM)
        _refused(self, "organization_ca", self.svc.activate, key_id, by="alice")
        self.assertEqual(registry.get(self.store, key_id)["state"],
                         registry.PUBLISHED)

    def test_the_admin_socket_does_not_answer_the_sites_publish(self):
        """There one operator would publish and start alone, under any name."""
        key_id = self.generate()
        reply = Dispatcher(self.svc).handle(
            {"op": "org_publish", "args": {"key_id": key_id,
                                           "operator": SAM}},
            admin=True, by="mallory")
        self.assertEqual(reply["reason"], "forbidden")
        reply = Dispatcher(self.svc).handle(
            {"op": "org_activate", "args": {"key_id": key_id,
                                            "operator": SAM}},
            admin=True, by="mallory")
        self.assertEqual(reply["reason"], "forbidden")
        self.assertEqual(registry.get(self.store, key_id)["state"],
                         registry.CERTIFIED)

    def test_a_ledger_that_cannot_ship_does_not_lose_the_answer(self):
        key_id = self.generate()

        def ship(_op):
            raise OSError(30, "Read-only file system")

        with self.assertLogs("cl03-signer", "ERROR"):
            reply = Dispatcher(self.svc, after_event=ship).handle(
                {"op": "org_publish", "args": {"key_id": key_id,
                                               "operator": SAM}},
                admin=False, by="app")
        self.assertEqual(reply, {"ok": True, "result": {"published": key_id}})
        self.assertEqual(registry.get(self.store, key_id)["state"],
                         registry.PUBLISHED)

    def test_names_that_break_lines_are_refused(self):
        key_id = self.generate()
        for operator in ("Sam\u2028key 99 withdrawn by alice+bob",
                         "Sam\u2029", "S" * 201):
            with self.subTest(operator=operator[:12]):
                _refused(self, "policy", self.svc.org_publish, key_id,
                         operator=operator)
        _refused(self, "policy", self.svc.org_generate,
                 organization=str(uuid.uuid4()), name="Beta\u2028Office")
        self.svc.org_publish(key_id, operator="S" * 200)
