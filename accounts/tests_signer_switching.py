"""Switching, rebuilding and warning, from this side. The signer's half is
signer/tests/test_switching.py and signer/tests/test_rebuild.py.
"""

import base64
import json
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.template.loader import render_to_string
from django.test import TestCase, override_settings
from django.urls import reverse

from accounts import (admin_roles, credential_keys, devices, signer_client,
                      signing_status)
from accounts.models import IssuerKey, Organization, User
from accounts.tests import make_org
from accounts.tests_signer_client import DAY, SignerBundleTest, _SignerTest
from accounts.tests_web_security import sign_in
from ovcrypto import pki

WRAP = "ab" * 32


def _certified(test, made, profile, **names):
    """The PKI's certificate for a key the signer made: install, publish
    (two operators)."""
    csr = x509.load_pem_x509_csr(made["csr"].encode())
    cert = pki.sign_csr(csr, test.ca_key, test.ca, profile,
                        test.clock.now() - 60, test.clock.now() + 730 * DAY,
                        serial=x509.random_serial_number(), **names)
    test.svc.install_cert(made["key_id"], cert.public_bytes(
        serialization.Encoding.DER), by="alice")
    conf = test.svc.publish(made["key_id"], by="alice")
    test.svc.confirm(conf["confirmation"], by="bob")
    signer_client.reset()
    return made["key_id"]


def _last_bundle_row(svc):
    return json.loads(svc.store.one(
        "SELECT summary FROM ledger WHERE kind = 'sign' AND "
        "context = 'bundle' ORDER BY seq DESC LIMIT 1")["summary"])


class ChainFlagTest(SignerBundleTest):
    """The phone's word, in this request, reaches the signer."""

    def _sync(self, capabilities):
        nonce = json.loads(self.client.post(
            "/api/v1/device/challenge/").content)["challenge"]
        der = self.device_key.sign(base64.b64decode(nonce),
                                   ec.ECDSA(hashes.SHA256()))
        body = {"device_id": str(self.device.device_id), "challenge": nonce,
                "signature": base64.b64encode(der).decode()}
        if capabilities is not None:
            body["capabilities"] = capabilities
        reply = self.client.post("/api/v1/device/keys/", data=json.dumps(body),
                                 content_type="application/json")
        self.assertEqual(reply.status_code, 200, reply.content)

    def test_a_chain_aware_phone_is_recorded_as_one(self):
        self._sync(["issuer-chain"])
        self.assertIs(_last_bundle_row(self.svc)["chains"], True)

    def test_an_old_app_is_recorded_as_not(self):
        self._sync(None)
        self.assertIs(_last_bundle_row(self.svc)["chains"], False)
        self._sync(["something-else"])
        self.assertIs(_last_bundle_row(self.svc)["chains"], False)

    def test_a_bundle_built_without_a_request_says_nothing(self):
        devices.build_bundle_and_chains(self.device)
        self.assertIsNone(_last_bundle_row(self.svc)["chains"])


class RevokedSetTest(_SignerTest):
    """The signer takes a capped number of new ids a call."""

    def setUp(self):
        super().setUp()
        self.calls = []
        real = signer_client._transport

        def counting(op, **args):
            if op == "put_revoked":
                self.calls.append(len(args["ids"]))
            return real(op, **args)

        signer_client.set_transport(counting)
        signer_client.reset()

    def _revoke(self, n):
        from accounts import revocation_feed
        with patch.object(revocation_feed, "revoked_ids",
                          return_value=[bytes([i % 256, i // 256]) * 8
                                        for i in range(n)]), \
                patch.object(revocation_feed, "generation", return_value=n):
            signer_client.ensure_revocations()

    def test_it_is_sent_until_the_signer_holds_all_of_it(self):
        self.svc.cfg.revocation_growth_per_call = 4
        self._revoke(10)
        self.assertEqual(self.calls, [10, 10, 10])
        self.assertEqual(self.svc.store.one(
            "SELECT COUNT(*) AS n FROM revoked")["n"], 10)

    def test_what_is_left_after_a_few_rounds_goes_next_time(self):
        self.svc.cfg.revocation_growth_per_call = 1
        with self.assertLogs("accounts.signer_client", "WARNING"):
            self._revoke(signer_client.PUT_REVOKED_ROUNDS + 2)
        self.assertEqual(len(self.calls), signer_client.PUT_REVOKED_ROUNDS)
        self._revoke(signer_client.PUT_REVOKED_ROUNDS + 2)   # not marked sent
        self.assertEqual(len(self.calls), signer_client.PUT_REVOKED_ROUNDS + 2)


class GateWordsTest(TestCase):
    """The gate's sentence, on Setup ("switch") and the Site page
    ("start"): the signer's own answer in words."""

    def _say(self, **gate):
        base = {"have": 0, "of": 0, "open": False, "counted": True,
                "not_capable": 0, "phones": [], "opens_at": None}
        base.update(gate)
        return " ".join(render_to_string("includes/signing_gate.html",
                                         {"gate": base, "verb": "switch"})
                        .split())

    def test_each_case(self):
        self.assertIn("2 phones that synced within a lease run an app that "
                      "cannot follow this key: Field 1, Field 2. Update them, "
                      "or unpair them and wait out their last lease.",
                      self._say(not_capable=2, phones=["Field 1", "Field 2"]))
        self.assertIn("The signer has signed bundles for under a lease, so it "
                      "cannot yet tell which phones have this key.",
                      self._say(counted=False))
        self.assertIn("No phone has synced within a lease, so it may switch now.",
                      self._say(open=True))
        self.assertIn("All 3 phones that synced within a lease have it",
                      self._say(open=True, have=3, of=3))
        self.assertIn("It was published a lease ago, so it may switch now.",
                      self._say(open=True, counted=False))
        self.assertIn("1 of 3 phones that synced within a lease have it.",
                      self._say(have=1, of=3))


class SetupGateTest(_SignerTest):

    def setUp(self):
        super().setUp()
        self.site = User.objects.create(national_id_card_number="9999000011112222")
        admin_roles.designate(self.site, "site_admin", None, "test")
        sign_in(self.client, self.site, self.org)

    def test_setup_names_the_phone_with_the_old_app(self):
        """The signer's hex ids, as the phones' names. (Which phones hold the
        gate is the signer's to say: signer/tests/test_switching.py.)"""
        from accounts.models import Device
        phone = Device.objects.create(owner=self.site, label="Counter 3",
                                      public_key_der=b"\x01" * 91)
        _certified(self, self.svc.keygen(by="alice"), pki.DEPLOYMENT)
        real = self.svc.status

        def status():
            got = real()
            for gate in got["gates"].values():
                gate.update(needed=True, open=False, not_capable_count=1,
                            not_capable=[phone.device_id.hex])
            return got

        with patch.object(self.svc, "status", side_effect=status):
            page = " ".join(self.client.get(reverse("setup")).content.decode()
                            .split())
        self.assertIn("1 phone that synced within a lease runs an app that "
                      "cannot follow this key: Counter 3.", page)


class CodeTest(TestCase):
    """A deploy of verify never updates the signer."""

    def setUp(self):
        self.org = make_org("Alpha")
        self.site = User.objects.create(national_id_card_number="9999000011112222")
        admin_roles.designate(self.site, "site_admin", None, "test")
        sign_in(self.client, self.site, self.org)

    def _overview(self, code):
        public = {"keys": [], "organization_cas": []}
        status = {"now": 1, "code": code}
        with patch.object(signing_status.signer_client, "public",
                          return_value=public), \
                patch.object(signing_status.signer_client, "status",
                             return_value=status):
            return (signing_status.overview(),
                    self.client.get(reverse("setup")).content.decode())

    @override_settings(SIGNER_SOCKET="/run/cl03-signer/app.sock",
                       CREDENTIAL_EPOCH_WRAP_KEY=WRAP)
    def test_other_code_is_said_in_red(self):
        overview, page = self._overview({"digest": "f" * 64,
                                         "commit": "ab" * 20, "wire": 1})
        self.assertTrue(overview["code"]["differs"])
        self.assertIn("The signer runs other code than this site", page)
        self.assertIn("commit <code>%s</code>" % ("ab" * 6), page)

    @override_settings(SIGNER_SOCKET="/run/cl03-signer/app.sock",
                       CREDENTIAL_EPOCH_WRAP_KEY=WRAP)
    def test_the_same_code_says_nothing(self):
        from django.conf import settings

        from signer import version
        same = version.cached_digest(str(settings.BASE_DIR))
        overview, page = self._overview({"digest": same, "commit": "",
                                         "wire": 1})
        self.assertFalse(overview["code"]["differs"])
        self.assertNotIn("runs other code", page)

    @override_settings(SIGNER_SOCKET="/run/cl03-signer/app.sock",
                       CREDENTIAL_EPOCH_WRAP_KEY=WRAP)
    def test_a_signer_from_before_says_nothing(self):
        overview, page = self._overview(None)
        self.assertFalse(overview["code"]["known"])
        self.assertNotIn("runs other code", page)


class DeleteOrganizationTest(_SignerTest):
    """An organization with a key phones list is not deleted: the key would
    sign for nobody and keep its name from the deployment key."""

    def setUp(self):
        super().setUp()
        self.site = User.objects.create(national_id_card_number="9999000011112222")
        admin_roles.designate(self.site, "site_admin", None, "test")
        self.other = Organization.objects.create(name="Beta Office")
        sign_in(self.client, self.site, self.org)

    def _delete(self, org):
        return self.client.post(reverse("site_delete_org", args=[org.id]))

    def _org_key(self, publish):
        made = self.svc.keygen(organization=str(self.other.signing_id),
                               by="alice")
        if publish:
            return _certified(self, made, pki.ORGANIZATION,
                              organization="Beta Office",
                              organization_id=str(self.other.signing_id))
        signer_client.reset()
        return made["key_id"]

    def test_a_published_key_stops_the_delete_and_names_the_command(self):
        key_id = self._org_key(publish=True)
        reply = self._delete(self.other)
        self.assertEqual(reply.status_code, 400)
        self.assertIn("cl03signer retire %d" % key_id, reply.json()["message"])
        self.assertTrue(Organization.objects.filter(pk=self.other.pk).exists())

    def test_an_unpublished_key_goes_with_it(self):
        key_id = self._org_key(publish=False)
        reply = self._delete(self.other)
        self.assertEqual(reply.status_code, 200, reply.content)
        self.assertIn("unpublished signing key %d was discarded" % key_id,
                      reply.json()["message"])
        self.assertEqual(self.svc.store.one(
            "SELECT state FROM keys WHERE key_id = ?", (key_id,))["state"],
            "discarded")
        self.assertFalse(Organization.objects.filter(pk=self.other.pk).exists())

    def test_a_signer_that_does_not_answer_deletes_nothing(self):
        down = signer_client.Unavailable("no socket")
        with patch.object(signer_client, "public", side_effect=down):
            reply = self._delete(self.other)
        self.assertEqual(reply.status_code, 400)
        self.assertIn("did not answer", reply.json()["message"])
        self.assertTrue(Organization.objects.filter(pk=self.other.pk).exists())

    def test_django_admin_cannot_delete_one(self):
        """It would skip both refusals."""
        from django.contrib import admin as django_admin
        from accounts.admin import OrganizationAdmin
        model_admin = OrganizationAdmin(Organization, django_admin.site)
        # Django offers its bulk delete only with this permission too.
        self.assertFalse(model_admin.has_delete_permission(None, self.other))

    def test_setup_offers_the_command_for_a_key_left_behind(self):
        key_id = self._org_key(publish=True)
        Organization.objects.filter(pk=self.other.pk).delete()
        row = next(r for r in signing_status.overview()["rows"]
                   if r["key_id"] == key_id)
        self.assertEqual(row["host_command"], "cl03signer retire %d" % key_id)
        self.assertEqual(row["note"],
                         "Its organization is no longer on this site.")


@override_settings(SIGNER_SOCKET="", CREDENTIAL_ISSUER_KEY_PATH="/k.pem",
                   CREDENTIAL_ISSUER_KEY_ID=1, CREDENTIAL_EPOCH_WRAP_KEY=WRAP,
                   CREDENTIAL_FILE_MODE_AFTER_SIGNER="")
class FileModeAfterSignerTest(TestCase):
    """Back on the key file after a signer, verify would sign under key 1
    while listing keys it has no private half of."""

    def _mirrored(self):
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        IssuerKey.objects.create(key_id=16, spki_der=b"k", not_before=now,
                                 not_after=now, is_active=True,
                                 source=IssuerKey.SOURCE_SIGNER)

    def test_a_key_file_alone_is_as_before(self):
        self.assertTrue(credential_keys.configured())
        self.assertEqual(credential_keys.missing(), [])

    def test_after_a_signer_it_needs_the_operators_word(self):
        self._mirrored()
        self.assertFalse(credential_keys.configured())
        self.assertEqual(credential_keys.missing(),
                         ["CREDENTIAL_FILE_MODE_AFTER_SIGNER"])

    @override_settings(CREDENTIAL_FILE_MODE_AFTER_SIGNER="1")
    def test_naming_the_files_key_lets_it_sign(self):
        self._mirrored()
        self.assertTrue(credential_keys.configured())

    @override_settings(CREDENTIAL_FILE_MODE_AFTER_SIGNER="16")
    def test_naming_another_key_does_not(self):
        self._mirrored()
        self.assertFalse(credential_keys.configured())

    @override_settings(SIGNER_SOCKET="/run/cl03-signer/app.sock")
    def test_the_signer_itself_is_untouched(self):
        self._mirrored()
        self.assertTrue(credential_keys.configured())
