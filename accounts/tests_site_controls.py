"""Every key action from the site's pages, where the signer's policy says so.

With `site_controls_all_keys = true` in the signer's policy, an option for a
site whose app servers are replaced at every release, any site admin -- a
designated one included -- publishes and starts the deployment's keys as
well as organizations', unsuspends, resumes and withdraws, alone. Off, which
is the default, none of it is offered, and nothing is sent. Against the real
signer in process; the switch is the signer's own word.
"""

import json
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.test import TestCase

from ovcrypto import pki

from accounts import admin_roles, signer_client
from accounts import tests_signing_pages as pages
from accounts.models import User
from accounts.tests_signer_client import DAY

SAMPLE_CARD = "3916098324035936"      # the invented sample identity's PCN


class _Controls(pages._OrganizationPages):

    def setUp(self):
        super().setUp()
        # The invented sample identity, designated a site admin by a
        # superuser: an eVerify sign-in with no Django login.
        self.designated = User.objects.create(
            national_id_card_number=SAMPLE_CARD,
            digital_national_id="CWD0842", given_name="JUAN MIGUEL",
            middle_name="SANTOS", last_name="DELA CRUZ")
        admin_roles.designate(self.designated, "site_admin", self.site_admin,
                              "test")

    def switch(self, on):
        self.svc.cfg.site_controls_all_keys = on
        signer_client.reset()

    def post(self, url, user=None, **data):
        self._sign_in(user or self.designated, self.org)
        return self.client.post(url, dict({"next": "setup"}, **data))

    def key_url(self, key_id, step):
        return "/app/setup/signing/keys/%d/%s/" % (key_id, step)

    def certified_deployment_key(self):
        made = self.svc.keygen(by="alice")
        csr = x509.load_pem_x509_csr(made["csr"].encode())
        cert = pki.sign_csr(csr, self.ca_key, self.ca, pki.DEPLOYMENT,
                            self.clock.now() - 60, self.clock.now() + 730 * DAY,
                            serial=x509.random_serial_number())
        self.svc.install_cert(made["key_id"], cert.public_bytes(
            serialization.Encoding.DER), by="alice")
        signer_client.reset()
        return made["key_id"]

    def setup_page(self, user=None):
        self._sign_in(user or self.designated, self.org)
        return self.client.get("/app/setup/").content.decode()

    def ledger(self, kind, context):
        return [json.loads(r["summary"]) for r in self.svc.store.all(
            "SELECT summary FROM ledger WHERE kind = ? AND context = ? "
            "ORDER BY seq", (kind, context))]


class SwitchOffTest(_Controls):
    """The default: none of it is offered, and nothing is sent."""

    def test_the_rule_on_the_person(self):
        self.assertFalse(self.designated.may_switch_signing_keys(False))
        self.assertTrue(self.designated.may_switch_signing_keys(True))
        self.assertTrue(self.site_admin.may_switch_signing_keys(False))
        self.assertFalse(self.org_admin.may_switch_signing_keys(True))
        everyone = User.objects.create(national_id_card_number="1234123412341234")
        admin_roles.designate(everyone, "all_org_admin", self.site_admin, "test")
        self.assertFalse(everyone.may_switch_signing_keys(True))

    def test_nothing_is_withdrawn_unsuspended_or_resumed_from_the_site(self):
        self.svc.suspend(self.deployment)
        self.svc.pause("credential", by="test")
        signer_client.reset()
        # Whatever the signer would do with them, they never reach it: the
        # spy sees every call the app makes.
        with mock.patch.object(signer_client, "call",
                               wraps=signer_client.call) as sent:
            for user in (self.designated, self.site_admin):
                with self.subTest(user=user.pk):
                    self.post(self.key_url(self.deployment, "withdraw"), user)
                    self.post(self.key_url(self.deployment, "unsuspend"), user)
                    self.post("/app/setup/signing/resume/", user,
                              context="credential")
        ops = [c.args[0] for c in sent.call_args_list]
        self.assertTrue(ops, "the spy saw nothing at all")
        self.assertEqual(set(ops), {"public"})
        key = self._keys()[self.deployment]
        self.assertEqual((key["state"], key["suspended"]), ("active", True))
        self.assertEqual([p["context"] for p in self.svc.status()["pauses"]],
                         ["credential"])
        self.assertEqual(self.ledger("key", "withdraw"), [])
        self.assertIn("done on the signer host here", self.setup_page())

    def test_setup_names_the_host_commands_and_offers_no_buttons(self):
        self.svc.suspend(self.deployment)
        self.svc.pause("credential", by="test")
        key_id = self.certified_deployment_key()
        page = self.setup_page()
        self.assertIn("cl03signer unsuspend %d" % self.deployment, page)
        self.assertIn("cl03signer resume credential", page)
        self.assertIn("cl03signer publish %d" % key_id, page)
        for offered in ("/signing/keys/%d/withdraw/" % self.deployment,
                        "/signing/keys/%d/unsuspend/" % self.deployment,
                        "/app/setup/signing/resume/",
                        "Resume credential signing</button>",
                        "Publish key %d</button>" % key_id):
            self.assertNotIn(offered, page)

    def test_a_designated_admin_publishes_nothing(self):
        key_id = self.certified_deployment_key()
        with mock.patch.object(signer_client, "call",
                               wraps=signer_client.call) as sent:
            self.post(self.key_url(key_id, "publish"))
            self.post(self.key_url(key_id, "activate"))
        self.assertNotIn("org_publish", [c.args[0] for c in sent.call_args_list])
        self.assertNotIn("org_activate",
                         [c.args[0] for c in sent.call_args_list])
        self.assertEqual(self._keys()[key_id]["state"], "certified")

    def test_a_suspension_names_the_admin_who_asked(self):
        """Any site admin may suspend, switch or no switch; the signer's
        ledger names who, as it does for the site's other key actions."""
        self.post(self.key_url(self.deployment, "suspend"))
        event = self.ledger("key", "suspend")[-1]
        self.assertEqual((event["by"], event["operator"]),
                         ("app", "%s (user %d)" % (self.designated.display_name,
                                                   self.designated.pk)))
        self.assertTrue(self._keys()[self.deployment]["suspended"])


class SwitchOnTest(_Controls):

    def setUp(self):
        super().setUp()
        self.switch(True)

    def test_a_designated_admin_publishes_and_starts_the_deployment_key(self):
        key_id = self.certified_deployment_key()
        page = self.setup_page()
        self.assertIn("Publish key %d</button>" % key_id, page)
        self.assertNotIn("cl03signer publish %d" % key_id, page)
        self.post(self.key_url(key_id, "publish"))
        self.assertEqual(self._keys()[key_id]["state"], "published")
        page = self.setup_page()
        self.assertIn("Start signing with key %d</button>" % key_id, page)
        self.post(self.key_url(key_id, "activate"))
        keys = self._keys()
        self.assertEqual((keys[key_id]["state"], keys[self.deployment]["state"]),
                         ("active", "retired"))
        self.assertIn("now signs bundles, feeds and statements",
                      self.setup_page())
        operator = "%s (user %d)" % (self.designated.display_name,
                                     self.designated.pk)
        self.assertEqual([e["operator"] for e in self.ledger("key", "publish")
                          if e["key_id"] == key_id], [operator])

    def test_a_designated_admin_publishes_and_starts_an_organizations_key(self):
        self._install_org_ca()
        self._generate()
        key_id = next(k["key_id"] for k in self._keys().values()
                      if k["organization"] == str(self.org.signing_id))
        self._sign_in(self.designated, self.org)
        page = self.client.get(self.site_page).content.decode()
        self.assertIn("Publish key %d</button>" % key_id, page)
        self.assertNotIn("takes a Django superuser", page)
        self.post(self.key_url(key_id, "publish"), next="org:%d" % self.org.id)
        self.post(self.key_url(key_id, "activate"), next="org:%d" % self.org.id)
        self.assertEqual(self._keys()[key_id]["state"], "active")

    def test_a_suspended_key_is_resumed_on_setup(self):
        self.svc.suspend(self.deployment)
        signer_client.reset()
        page = self.setup_page()
        self.assertIn("/signing/keys/%d/unsuspend/" % self.deployment, page)
        self.assertNotIn("cl03signer unsuspend", page)
        self.post(self.key_url(self.deployment, "unsuspend"))
        self.assertFalse(self._keys()[self.deployment]["suspended"])
        self.assertIn("is resumed and signs again", self.setup_page())

    def test_credential_signing_is_resumed_on_setup(self):
        self.svc.pause("credential", by="test")
        signer_client.reset()
        page = self.setup_page()
        self.assertIn("Resume credential signing</button>", page)
        self.assertNotIn("cl03signer resume credential", page)
        self.post("/app/setup/signing/resume/", context="credential")
        self.assertEqual(self.svc.status()["pauses"], [])
        resumed = self.ledger("admin", "resume")[-1]
        self.assertEqual(resumed["operator"], "%s (user %d)" % (
            self.designated.display_name, self.designated.pk))
        self.post("/app/setup/signing/resume/", context="everything")
        self.assertIn("no such kind of signing", self.setup_page())

    def test_the_deployment_key_is_withdrawn_and_every_sync_stops(self):
        """What the switch costs, said before and after."""
        page = self.setup_page()
        self.assertIn("/signing/keys/%d/withdraw/" % self.deployment, page)
        self.assertIn("every phone's sync is refused meanwhile", page)
        self.post(self.key_url(self.deployment, "withdraw"))
        self.assertEqual(self._keys()[self.deployment]["state"], "withdrawn")
        self.assertIn("Nothing signs bundles, feeds or statements",
                      self.setup_page())
        event = self.ledger("key", "withdraw")[-1]
        self.assertEqual((event["key_id"], event["by"]),
                         (self.deployment, "app"))

    def test_an_organization_admin_can_do_none_of_it(self):
        self.svc.suspend(self.deployment)
        signer_client.reset()
        for step in ("withdraw", "unsuspend"):
            response = self.post(self.key_url(self.deployment, step),
                                 self.org_admin)
            self.assertRedirects(response, "/app/",
                                 fetch_redirect_response=False)
        key = self._keys()[self.deployment]
        self.assertEqual((key["state"], key["suspended"]), ("active", True))

    def test_each_post_needs_its_csrf_token(self):
        self.svc.suspend(self.deployment)
        self.svc.pause("credential", by="test")
        self.client = self.client_class(enforce_csrf_checks=True)
        for url in (self.key_url(self.deployment, "withdraw"),
                    self.key_url(self.deployment, "unsuspend"),
                    "/app/setup/signing/resume/"):
            with self.subTest(url=url):
                self.assertEqual(self.post(url, context="credential")
                                 .status_code, 403)
        key = self._keys()[self.deployment]
        self.assertEqual((key["state"], key["suspended"]), ("active", True))


class HeldKeyRowTest(TestCase):
    """A held key (`[[held]]`, the development key 1) is the policy's: with
    the switch on, its row offers nothing the switch allows."""

    def test_no_button_for_a_held_key(self):
        from accounts import signing_status
        for state, suspended in (("published", False), ("active", True)):
            with self.subTest(state=state):
                row = signing_status._row(
                    {"key_id": 1, "state": state, "suspended": suspended,
                     "raw": True, "legacy": False, "organization": None,
                     "window": [0, 2 ** 31]},
                    orgs={}, gates={}, credential_days=365, now=1,
                    site_controls=True)
                self.assertFalse(row["can_withdraw"] or row["can_unsuspend"]
                                 or row["can_activate"] or row["can_publish"])
                if suspended:
                    self.assertEqual(row["host_command"], "cl03signer unsuspend 1")
