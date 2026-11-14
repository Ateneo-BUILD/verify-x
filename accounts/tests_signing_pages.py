"""Setup's Credential signing card and the organization pages' signing section.

Against the real signer in process (`tests_signer_client._SignerTest`): what
the pages show is what its registry says, and the three things verify may do
-- pause, suspend, upload a certificate -- reach it and come back as one
plain sentence. Nothing else changes a key from here.
"""

import json

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings

from ovcrypto import pki

from accounts import signer_client
from django.contrib.auth import get_user_model

from accounts.models import Membership, Organization, User, bridge_card
from accounts.tests_signer_client import DAY, SITE, _SignerTest
from signer.service import Refused as ServiceRefused
from verify.views.helpers import ORG_SESSION_KEY

SESSION_KEY = "verify_user_id"


class _Pages:

    def _people(self, org):
        # A Django superuser's own row: publishing and starting a key take
        # one, so a designated site admin would not do here.
        self.django_root = get_user_model().objects.create_superuser(
            "sam", "sam@example.org", "pw")
        self.site_admin = User.objects.create(
            national_id_card_number=bridge_card(self.django_root.pk), given_name="Sam",
            is_site_admin=True)
        self.org_admin = User.objects.create(
            national_id_card_number="1111222233334444", given_name="Ola")
        Membership.objects.create(user=self.org_admin, organization=org,
                                  role=Membership.ROLE_ADMIN)

    def _sign_in(self, user, org):
        if user.is_bridge_row:
            # A bridge row's session lives only with its Django login.
            self.client.force_login(self.django_root)
        session = self.client.session
        session[SESSION_KEY] = user.id
        session[ORG_SESSION_KEY] = org.id
        session.save()


@override_settings(SIGNER_SOCKET="", CREDENTIAL_ISSUER_KEY_PATH="/keys/issuer.pem",
                   CREDENTIAL_ISSUER_KEY_ID=1)
class SigningCardWithoutASignerTest(_Pages, TestCase):

    def setUp(self):
        self.org = Organization.objects.create(name="Alpha Registry")
        self._people(self.org)

    def test_a_site_admin_is_told_the_key_file_signs(self):
        self._sign_in(self.site_admin, self.org)
        page = self.client.get("/app/setup/").content.decode()
        self.assertIn("Credential signing", page)
        self.assertIn("Signing with the key file on this server (key 1).", page)
        self.assertNotIn("Pause credential signing", page)

    def test_an_organization_admin_sees_no_signing_card(self):
        self._sign_in(self.org_admin, self.org)
        self.assertNotContains(self.client.get("/app/setup/"), "Credential signing")
        self.assertNotContains(self.client.get("/app/admin/"), "Credential signing")

    def test_the_actions_need_a_signer_and_a_site_admin(self):
        self._sign_in(self.org_admin, self.org)
        response = self.client.post("/app/setup/signing/pause/")
        self.assertRedirects(response, "/app/", fetch_redirect_response=False)


class SignerSetupTest(_Pages, _SignerTest):
    """With a signer: the card, the organization section, and the actions."""

    def setUp(self):
        super().setUp()
        self._people(self.org)

    def _org_key(self, org):
        """A key the signer generated for `org`: (key id, keygen's answer)."""
        made = self.svc.keygen(organization=str(org.signing_id), by="alice")
        signer_client.reset()
        return made["key_id"], made

    def _cert(self, made, org):
        """The PKI's certificate for that key, naming `org`."""
        csr = x509.load_pem_x509_csr(made["csr"].encode())
        return pki.sign_csr(csr, self.ca_key, self.ca, pki.ORGANIZATION,
                            self.clock.now() - 60, self.clock.now() + 730 * DAY,
                            serial=x509.random_serial_number(),
                            organization=org.name,
                            organization_id=str(org.signing_id))

    def _activate(self, key_id, cert):
        """Everything the signer host does after the upload."""
        self.svc.install_cert(key_id, cert.public_bytes(serialization.Encoding.DER),
                              by="alice")
        conf = self.svc.publish(key_id, by="alice")
        self.svc.confirm(conf["confirmation"], by="bob")
        self.svc.activate(key_id, by="alice")
        signer_client.reset()

    def _setup_page(self):
        self._sign_in(self.site_admin, self.org)
        return self.client.get("/app/setup/").content.decode()

    def test_the_card_lists_what_the_signer_holds(self):
        self._org_key(self.org)
        page = self._setup_page()
        self.assertIn("Credential signing", page)
        self.assertIn("Running", page)
        self.assertIn("This deployment", page)
        self.assertIn("organizations without a key", page)
        self.assertIn("Needs certificate", page)
        # The organization key's upload is on its own page.
        self.assertIn("/app/site/organizations/%d/#signing" % self.org.id, page)
        self.assertIn("Pause credential signing", page)

    def test_an_operator_never_sees_it(self):
        self._sign_in(self.org_admin, self.org)
        self.assertNotContains(self.client.get("/app/setup/"), "Credential signing")

    def test_pausing_reaches_the_signer_and_says_how_to_resume(self):
        self._sign_in(self.site_admin, self.org)
        response = self.client.post("/app/setup/signing/pause/", {"next": "setup"})
        self.assertRedirects(response, "/app/setup/", fetch_redirect_response=False)
        self.assertEqual([p["context"] for p in self.svc.status()["pauses"]],
                         ["credential"])
        page = self.client.get("/app/setup/").content.decode()
        self.assertIn("Credential signing is paused.", page)
        self.assertIn("cl03signer resume credential", page)
        # The notice is said once.
        self.assertEqual(
            self.client.get("/app/setup/").content.decode().count(
                "until someone on the signer host runs"), 0)

    def test_an_organization_admin_cannot_pause_or_suspend(self):
        self._sign_in(self.org_admin, self.org)
        self.client.post("/app/setup/signing/pause/")
        self.client.post("/app/setup/signing/keys/%d/suspend/" % self.deployment)
        self.assertEqual(self.svc.status()["pauses"], [])
        key = {k["key_id"]: k for k in self.svc.public()["keys"]}[self.deployment]
        self.assertFalse(key["suspended"])

    def test_the_actions_are_post_only(self):
        self._sign_in(self.site_admin, self.org)
        self.assertEqual(self.client.get("/app/setup/signing/pause/").status_code, 405)
        self.assertEqual(self.client.get(
            "/app/setup/signing/keys/%d/suspend/" % self.deployment).status_code, 405)

    def test_suspending_a_key_reaches_the_signer(self):
        self._sign_in(self.site_admin, self.org)
        self.client.post("/app/setup/signing/keys/%d/suspend/" % self.deployment,
                         {"next": "setup"})
        key = {k["key_id"]: k for k in self.svc.public()["keys"]}[self.deployment]
        self.assertTrue(key["suspended"])
        page = self.client.get("/app/setup/").content.decode()
        self.assertIn("Suspended", page)
        self.assertIn("cl03signer unsuspend %d" % self.deployment, page)

    def test_a_published_key_shows_how_far_the_switch_is(self):
        made = self.svc.keygen(by="alice")
        csr = x509.load_pem_x509_csr(made["csr"].encode())
        cert = pki.sign_csr(csr, self.ca_key, self.ca, pki.DEPLOYMENT,
                            self.clock.now() - 60, self.clock.now() + 730 * DAY,
                            serial=x509.random_serial_number())
        self.svc.install_cert(made["key_id"], cert.public_bytes(
            serialization.Encoding.DER), by="alice")
        conf = self.svc.publish(made["key_id"], by="alice")
        self.svc.confirm(conf["confirmation"], by="bob")
        signer_client.reset()
        page = self._setup_page()
        self.assertIn("Published", page)
        self.assertIn("next key", page)
        self.assertIn("No phone has synced within a lease, so it may switch now.", page)
        self.assertIn("cl03signer activate %d" % made["key_id"], page)

    def test_an_organization_certificate_uploads_from_its_page(self):
        key_id, made = self._org_key(self.org)
        cert = self._cert(made, self.org)
        self._sign_in(self.site_admin, self.org)
        page = self.client.get("/app/site/organizations/%d/" % self.org.id)
        self.assertContains(page, str(self.org.signing_id))
        self.assertContains(page, "Upload certificate")

        upload = SimpleUploadedFile("leaf.pem", cert.public_bytes(
            serialization.Encoding.PEM))
        response = self.client.post(
            "/app/setup/signing/keys/%d/certificate/" % key_id,
            {"certificate": upload, "next": "org:%d" % self.org.id})
        self.assertRedirects(response, "/app/site/organizations/%d/" % self.org.id,
                             fetch_redirect_response=False)
        key = {k["key_id"]: k for k in self.svc.public()["keys"]}[key_id]
        self.assertEqual(key["state"], "certified")
        page = self.client.get("/app/site/organizations/%d/" % self.org.id)
        self.assertContains(page, "Key %d is certified" % key_id)
        self.assertContains(page, "cl03signer publish %d" % key_id)

    def test_another_organizations_certificate_is_refused_in_a_sentence(self):
        other = Organization.objects.create(name="Beta Office")
        key_id, made = self._org_key(self.org)
        # This key's own public half, certified as the other organization.
        wrong = self._cert(made, other)
        self._sign_in(self.site_admin, self.org)
        upload = SimpleUploadedFile("leaf.der", wrong.public_bytes(
            serialization.Encoding.DER))
        self.client.post("/app/setup/signing/keys/%d/certificate/" % key_id,
                         {"certificate": upload, "next": "org:%d" % self.org.id})
        page = self.client.get("/app/site/organizations/%d/" % self.org.id)
        self.assertContains(page, "The signer refused this certificate")
        self.assertContains(page, "another organization")
        self.assertEqual({k["key_id"]: k for k in self.svc.public()["keys"]}
                         [key_id]["state"], "generated")

    def test_a_file_that_is_not_one_certificate_is_turned_away_here(self):
        key_id, _ = self._org_key(self.org)
        self._sign_in(self.site_admin, self.org)
        upload = SimpleUploadedFile("notes.txt", b"not a certificate")
        self.client.post("/app/setup/signing/keys/%d/certificate/" % key_id,
                         {"certificate": upload, "next": "setup"})
        self.assertIn("Choose one certificate file", self.client.get(
            "/app/setup/").content.decode())

    def test_a_file_holding_a_chain_is_turned_away_here(self):
        """Only the key's own certificate: a chain is not what was asked for."""
        key_id, made = self._org_key(self.org)
        leaf = self._cert(made, self.org).public_bytes(serialization.Encoding.PEM)
        ca = self.ca.public_bytes(serialization.Encoding.PEM)
        self._sign_in(self.site_admin, self.org)
        self.client.post("/app/setup/signing/keys/%d/certificate/" % key_id,
                         {"certificate": SimpleUploadedFile("chain.pem", leaf + ca),
                          "next": "setup"})
        self.assertIn("Choose one certificate file", self.client.get(
            "/app/setup/").content.decode())
        self.assertEqual({k["key_id"]: k for k in self.svc.public()["keys"]}
                         [key_id]["state"], "generated")

    def test_the_organization_admin_reads_the_status_without_an_upload(self):
        key_id, made = self._org_key(self.org)
        self._activate(key_id, self._cert(made, self.org))
        self._sign_in(self.org_admin, self.org)
        page = self.client.get("/app/admin/").content.decode()
        self.assertIn("Credential signing", page)
        self.assertIn("Certified as", page)
        self.assertIn("certified by Test Issuing CA", page)
        self.assertNotIn('name="certificate"', page)

    def test_a_renamed_organization_is_told_its_certificate_keeps_the_old_name(self):
        key_id, made = self._org_key(self.org)
        self._activate(key_id, self._cert(made, self.org))
        Organization.objects.filter(pk=self.org.pk).update(name="Alpha City Registry")
        self._sign_in(self.site_admin, self.org)
        page = self.client.get("/app/site/organizations/%d/" % self.org.id)
        self.assertContains(page, "new documents keep that name")

    def test_a_signer_that_does_not_answer_is_said_plainly(self):
        def down(op, **args):
            raise ServiceRefused("unavailable", "connection refused")

        signer_client.set_transport(down)
        signer_client.reset()
        page = self._setup_page()
        self.assertIn("The signer did not answer", page)
        self.assertNotIn("Pause credential signing", page)


class _OrganizationPages(_Pages, _SignerTest):
    """An organization's Site page against the signer in process."""

    def setUp(self):
        super().setUp()
        self._people(self.org)
        self.site_page = "/app/site/organizations/%d/" % self.org.id

    def _install_org_ca(self, days=5 * 365):
        made = self.svc.ca_keygen(by="alice")
        csr = x509.load_pem_x509_csr(made["csr"].encode())
        cert = pki.sign_csr(
            csr, self.ca_key, self.ca, pki.ORGANIZATION_CA,
            self.clock.now() - 60, self.clock.now() + days * DAY,
            serial=x509.random_serial_number(), domain=SITE)
        self.svc.ca_install(made["ca_id"],
                            cert.public_bytes(serialization.Encoding.DER),
                            by="alice")
        signer_client.reset()
        return made["ca_id"]

    def _page(self, user=None):
        self._sign_in(user or self.site_admin, self.org)
        return self.client.get(self.site_page).content.decode()

    def _setup_page(self):
        self._sign_in(self.site_admin, self.org)
        return self.client.get("/app/setup/").content.decode()

    def _keys(self):
        return {k["key_id"]: k for k in self.svc.public()["keys"]}

    def _generate(self, name=None):
        self._sign_in(self.site_admin, self.org)
        return self.client.post(
            "/app/setup/signing/organizations/%d/generate/" % self.org.id,
            {"name": self.org.name if name is None else name})


class OrganizationCertificatePagesTest(_OrganizationPages):
    """An organization's next certificate from its Site page: generated at
    once by the Organization CA, or requested from the PKI."""

    def test_without_an_organization_ca_generate_is_greyed_and_says_why(self):
        page = self._page()
        self.assertIn("Generate certificate", page)
        self.assertRegex(page, r"<button type=\"submit\" disabled>Generate certificate")
        self.assertIn("This site has no Organization CA", page)
        self.assertIn("Request from the PKI", page)
        self.assertIn("cl03signer ca keygen", self._setup_page())

    def test_a_ca_past_its_last_issuing_day_greys_generate_and_says_why(self):
        # 500 days leave 15 days in which a certificate still gets 90 days
        # of signing (500 - 365 - 30 - 90).
        self._install_org_ca(days=500)
        self.assertIn("Certified at once by verify.example.ph System CA", self._page())
        self.clock.advance(20 * DAY)
        signer_client.reset()
        page = self._page()
        self.assertRegex(page, r"<button type=\"submit\" disabled>Generate certificate")
        self.assertIn("ends too soon to leave 90 days of signing", page)

    @override_settings(DEVICE_PAIRING_BASE_URL="https://%s" % SITE)
    def test_setup_names_the_site_the_ca_is_for(self):
        self._install_org_ca()
        page = self._setup_page()
        self.assertIn("%s System CA <span class=\"sg-pill sg-active\">Certified"
                      % SITE, page)
        self.assertIn("for phones paired with %s." % SITE, page)
        self.assertNotIn("pairing QR sends phones to", page)

    def test_setup_warns_when_the_pairing_qr_names_another_host(self):
        """The test client is "testserver": phones paired through this page
        would refuse what the System CA certifies."""
        self._install_org_ca()
        page = self._setup_page()
        self.assertIn("This site's pairing QR sends phones to testserver, but "
                      "the signer\n        is set up for %s." % SITE, page)

    def test_a_ca_for_another_site_greys_generate_and_says_why(self):
        self._install_org_ca()
        self.svc.cfg.site_domain = "elsewhere.example.ph"
        signer_client.reset()
        page = self._page()
        self.assertRegex(page, r"<button type=\"submit\" disabled>Generate certificate")
        self.assertIn("%s is not for elsewhere.example.ph, the site phones "
                      "pair with" % "%s System CA" % SITE, page)
        setup = self._setup_page()
        self.assertIn("Not for this site", setup)
        self.assertIn("Start a System CA for elsewhere.example.ph", setup)

    def test_the_page_shows_the_name_and_id_before_anything_is_made(self):
        self._install_org_ca()
        page = self._page()
        self.assertIn("Names <b>Alpha Registry</b>", page)
        self.assertIn(str(self.org.signing_id), page)
        self.assertIn("Certified at once by verify.example.ph System CA", page)

    def test_generate_certifies_at_once_and_names_the_publish_command(self):
        ca_id = self._install_org_ca()
        response = self._generate()
        self.assertRedirects(response, self.site_page,
                             fetch_redirect_response=False)
        key = next(k for k in self._keys().values()
                   if k["organization"] == str(self.org.signing_id))
        self.assertEqual((key["state"], key["ca_id"], key["certified_name"]),
                         ("certified", ca_id, "Alpha Registry"))
        page = self._page()
        self.assertIn("Key %d is certified by verify.example.ph System CA as "
                      "“Alpha Registry”" % key["key_id"], page)
        self.assertIn("cl03signer publish %d" % key["key_id"], page)
        self.assertIn("Discard key %d" % key["key_id"], page)
        self.assertNotIn("Generate certificate", page)
        # It already has its certificate: nothing to upload, here or on Setup.
        self.assertNotIn('name="certificate"', page)
        self.assertNotIn("/signing/keys/%d/certificate/" % key["key_id"],
                         self._setup_page())

    def test_a_rename_between_page_and_click_is_not_certified(self):
        self._install_org_ca()
        self._generate(name="Alpha Registry (old)")
        self.assertFalse([k for k in self._keys().values()
                          if k["organization"] == str(self.org.signing_id)])
        self.assertIn("name changed after this page was shown", self._page())

    def test_request_download_and_upload_from_the_pki(self):
        self._sign_in(self.site_admin, self.org)
        self.client.post("/app/setup/signing/organizations/%d/request/"
                         % self.org.id)
        key_id = next(k["key_id"] for k in self._keys().values()
                      if k["organization"] == str(self.org.signing_id))
        page = self._page()
        self.assertIn("Key %d, waiting for the PKI" % key_id, page)
        self.assertIn("Download request (.csr)", page)

        got = self.client.get("/app/setup/signing/keys/%d/request.csr" % key_id)
        self.assertEqual(got["Content-Type"], "application/pkcs10")
        self.assertIn('filename="key-%d.csr"' % key_id,
                      got["Content-Disposition"])
        csr = x509.load_pem_x509_csr(got.content)
        cert = pki.sign_csr(csr, self.ca_key, self.ca, pki.ORGANIZATION,
                            self.clock.now() - 60, self.clock.now() + 730 * DAY,
                            serial=x509.random_serial_number(),
                            organization=self.org.name,
                            organization_id=str(self.org.signing_id))
        self.client.post(
            "/app/setup/signing/keys/%d/certificate/" % key_id,
            {"certificate": SimpleUploadedFile("leaf.pem", cert.public_bytes(
                serialization.Encoding.PEM)), "next": "org:%d" % self.org.id})
        key = self._keys()[key_id]
        self.assertEqual((key["state"], key["ca_id"], key["certified_by"]),
                         ("certified", None, "Test Issuing CA"))

    def test_discard_frees_the_organization_for_a_new_start(self):
        self._install_org_ca()
        self._generate()
        key_id = next(k["key_id"] for k in self._keys().values()
                      if k["organization"] == str(self.org.signing_id))
        response = self.client.post(
            "/app/setup/signing/keys/%d/discard/" % key_id,
            {"next": "org:%d" % self.org.id})
        self.assertRedirects(response, self.site_page,
                             fetch_redirect_response=False)
        self.assertNotIn(key_id, self._keys())
        page = self._page()
        self.assertIn("Key %d is discarded" % key_id, page)
        self.assertIn("Generate certificate", page)

    def test_a_second_key_is_refused_in_a_sentence(self):
        self._install_org_ca()
        self._generate()
        self._generate()
        self.assertIn("a key already waits for this organization", self._page())

    def test_an_organization_admin_can_do_none_of_it(self):
        self._install_org_ca()
        self._sign_in(self.org_admin, self.org)
        for url in ("/app/setup/signing/organizations/%d/generate/" % self.org.id,
                    "/app/setup/signing/organizations/%d/request/" % self.org.id):
            response = self.client.post(url, {"name": self.org.name})
            self.assertRedirects(response, "/app/", fetch_redirect_response=False)
        self.assertFalse([k for k in self._keys().values()
                          if k["organization"] == str(self.org.signing_id)])
        made = self.svc.org_keygen(organization=str(self.org.signing_id))
        self._sign_in(self.org_admin, self.org)
        for response in (
                self.client.get("/app/setup/signing/keys/%d/request.csr"
                                % made["key_id"]),
                self.client.post("/app/setup/signing/keys/%d/discard/"
                                 % made["key_id"])):
            self.assertRedirects(response, "/app/", fetch_redirect_response=False)
        self.assertIn(made["key_id"], self._keys())

    def test_the_actions_that_change_keys_are_post_only(self):
        self._sign_in(self.site_admin, self.org)
        for url in ("/app/setup/signing/organizations/%d/generate/" % self.org.id,
                    "/app/setup/signing/organizations/%d/request/" % self.org.id,
                    "/app/setup/signing/keys/5/discard/"):
            self.assertEqual(self.client.get(url).status_code, 405, url)

    def test_setup_shows_the_ca_and_who_certified_each_key(self):
        ca_id = self._install_org_ca()
        self._generate()
        page = self._setup_page()
        self.assertIn("verify.example.ph System CA", page)
        self.assertIn("1 certificate issued", page)
        self.assertIn("cl03signer ca withdraw %d" % ca_id, page)
        self.assertIn('title="verify.example.ph System CA">Organization CA', page)
        self.assertIn('title="Test Issuing CA">PKI', page)

    def test_the_organization_admin_reads_who_certified_it(self):
        self._install_org_ca()
        made = self.svc.org_generate(organization=str(self.org.signing_id),
                                     name=self.org.name)
        conf = self.svc.publish(made["key_id"], by="alice")
        self.svc.confirm(conf["confirmation"], by="bob")
        self.svc.activate(made["key_id"], by="alice")
        signer_client.reset()
        self._sign_in(self.org_admin, self.org)
        page = self.client.get("/app/admin/").content.decode()
        self.assertIn("certified by verify.example.ph System CA", page)
        self.assertNotIn("Generate certificate", page)


class SitePublishPagesTest(_OrganizationPages):
    """Where the signer's policy lets the site publish organization keys: the
    Site page publishes the key, then starts it signing once its phones have
    it."""

    def setUp(self):
        super().setUp()
        self._install_org_ca()
        self.svc.cfg.site_publishes_organization_keys = True
        signer_client.reset()

    def _key_id(self):
        return next(k["key_id"] for k in self._keys().values()
                    if k["organization"] == str(self.org.signing_id))

    def _post(self, key_id, step, user=None):
        self._sign_in(user or self.site_admin, self.org)
        return self.client.post("/app/setup/signing/keys/%d/%s/" % (key_id, step),
                                {"next": "org:%d" % self.org.id})

    def _sync(self, device=b"\x07" * 16):
        self.svc.put_revoked([])
        self.svc.bundle(device_id=device, device_key_hash=b"h", epoch_keys=[],
                        lease_seconds=30 * DAY)
        signer_client.reset()

    def test_a_designated_site_admin_is_told_and_not_offered_the_buttons(self):
        """Publishing or starting a key takes a superuser's own login; a site
        admin a superuser designated sees why instead of a button."""
        from accounts import admin_roles
        designated = User.objects.create(national_id_card_number="9999888877776666",
                                         given_name="Dee")
        admin_roles.designate(designated, "site_admin", self.site_admin, "test")
        self._generate()
        key_id = self._key_id()
        page = self._page(designated)
        self.assertNotIn("Publish key %d</button>" % key_id, page)
        self.assertIn("Publishing key %d takes a Django superuser's own login" % key_id, page)
        self.assertIn("Publish key %d</button>" % key_id, self._page())

    def test_generate_then_publish_then_start_all_on_the_site_page(self):
        self._generate()
        key_id = self._key_id()
        page = self._page()
        self.assertIn("Publish it on this page when you are ready.", page)
        self.assertIn("Publish key %d</button>" % key_id, page)
        self.assertNotIn("cl03signer publish", page)

        response = self._post(key_id, "publish")
        self.assertRedirects(response, self.site_page,
                             fetch_redirect_response=False)
        self.assertEqual(self._keys()[key_id]["state"], "published")
        page = self._page()
        self.assertIn("Key %d is published." % key_id, page)
        self.assertIn("No phone has synced within a lease, so it may start now.",
                      page)
        self.assertIn('<button type="submit">Start signing with key %d</button>'
                      % key_id, page)
        self.assertNotIn("cl03signer activate", page)
        self.assertNotIn("Discard key", page)

        self._post(key_id, "activate")
        self.assertEqual(self._keys()[key_id]["state"], "active")
        page = self._page()
        self.assertIn("Key %d now signs this organization&#x27;s new documents"
                      % key_id, page)
        self.assertIn("<dt>Certified as</dt><dd>Alpha Registry</dd>", page)

    def test_start_is_greyed_until_the_phones_that_synced_have_it(self):
        self._sync()
        self._generate()
        key_id = self._key_id()
        self._post(key_id, "publish")
        page = self._page()
        self.assertIn("0 of 1 phones that synced within a lease have it", page)
        self.assertIn('<button type="submit" disabled>Start signing with key %d'
                      % key_id, page)
        # A post anyway is the signer's to refuse, in a sentence.
        self._post(key_id, "activate")
        self.assertEqual(self._keys()[key_id]["state"], "published")
        self.assertIn("do not have this key yet", self._page())
        self.clock.advance(60)
        self._sync()
        self.assertIn("All 1 phone that synced within a lease has it",
                      self._page())
        self._post(key_id, "activate")
        self.assertEqual(self._keys()[key_id]["state"], "active")

    def test_the_signer_is_told_which_admin_asked(self):
        self._generate()
        key_id = self._key_id()
        self._post(key_id, "publish")
        events = [json.loads(r["summary"]) for r in self.svc.store.all(
            "SELECT summary FROM ledger WHERE kind = 'key' AND "
            "context = 'publish'")]
        self.assertEqual(events[-1]["operator"],
                         "Sam (user %d)" % self.site_admin.pk)

    def test_setup_sends_the_admin_to_the_site_page(self):
        self._generate()
        key_id = self._key_id()
        page = self._setup_page()
        self.assertIn("Publish it from its organization&#x27;s Site page.", page)
        self.assertNotIn("cl03signer publish %d" % key_id, page)

    def test_the_deployment_key_still_names_the_host(self):
        made = self.svc.keygen(by="alice")
        self.svc.install_cert(made["key_id"], self._deployment_cert(made),
                              by="alice")
        signer_client.reset()
        self.assertIn("cl03signer publish %d" % made["key_id"], self._setup_page())
        self._post(made["key_id"], "publish")
        self.assertEqual(self._keys()[made["key_id"]]["state"], "certified")

    def _deployment_cert(self, made):
        csr = x509.load_pem_x509_csr(made["csr"].encode())
        return pki.sign_csr(csr, self.ca_key, self.ca, pki.DEPLOYMENT,
                            self.clock.now() - 60, self.clock.now() + 730 * DAY,
                            serial=x509.random_serial_number()).public_bytes(
            serialization.Encoding.DER)

    def test_without_the_policy_the_page_names_the_host_commands(self):
        self.svc.cfg.site_publishes_organization_keys = False
        signer_client.reset()
        self._generate()
        key_id = self._key_id()
        page = self._page()
        self.assertIn("cl03signer publish %d" % key_id, page)
        self.assertNotIn("Publish key %d</button>" % key_id, page)
        self._post(key_id, "publish")
        self.assertEqual(self._keys()[key_id]["state"], "certified")
        self.assertIn("published on the signer host here", self._page())

    def test_an_organization_admin_can_do_none_of_it(self):
        self._generate()
        key_id = self._key_id()
        response = self._post(key_id, "publish", user=self.org_admin)
        self.assertRedirects(response, "/app/", fetch_redirect_response=False)
        self.assertEqual(self._keys()[key_id]["state"], "certified")
        self._post(key_id, "publish")
        response = self._post(key_id, "activate", user=self.org_admin)
        self.assertRedirects(response, "/app/", fetch_redirect_response=False)
        self.assertEqual(self._keys()[key_id]["state"], "published")
        self._sign_in(self.org_admin, self.org)
        self.assertNotIn("Start signing", self.client.get("/app/admin/")
                         .content.decode())

    def test_publish_and_start_are_post_only(self):
        self._sign_in(self.site_admin, self.org)
        for step in ("publish", "activate"):
            self.assertEqual(self.client.get(
                "/app/setup/signing/keys/5/%s/" % step).status_code, 405, step)


class HeldKeySetupTest(_Pages, _SignerTest):
    """A signer that holds the development key 1 (`[[held]]`): the card says
    what the key is, and never shows a certificate it lacks."""

    def setUp(self):
        import os

        from cryptography.hazmat.primitives.asymmetric import ec

        from signer import config as cfgmod
        from signer.keys import FileKeys
        from signer.service import SignerService
        from signer.store import Store
        from signer.transport import Dispatcher

        super().setUp()
        self._people(self.org)
        key = ec.generate_private_key(ec.SECP256R1())
        keys = FileKeys(os.path.join(self.dir, "held"))
        with open(os.path.join(self.dir, "held", "key-1.pem"), "wb") as handle:
            handle.write(key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        store = Store(os.path.join(self.dir, "held.db"))
        self.addCleanup(store.db.close)
        now = self.clock.now()
        self.svc = SignerService(store, keys, cfgmod.Config(
            anchors=[self.ca_der], site_domain=SITE, held=[cfgmod.Held(
                1, "key-1.pem", key.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo),
                now - 30 * DAY, now + 300 * DAY)]), clock=self.clock)
        self.svc.activate(1, by="alice")
        dispatcher = Dispatcher(self.svc)

        def transport(op, **args):
            reply = dispatcher.handle({"op": op, "args": args}, admin=False,
                                      by="app")
            if not reply["ok"]:
                raise ServiceRefused(reply["reason"], reply.get("detail", ""),
                                     **(reply.get("extra") or {}))
            return reply["result"]

        signer_client.set_transport(transport)
        signer_client.reset()

    def test_the_card_names_the_development_key_and_no_certificate(self):
        self._sign_in(self.site_admin, self.org)
        page = self.client.get("/app/setup/").content.decode()
        row = page[page.index('<td class="kid">1</td>'):]
        row = row[:row.index("</tr>")]
        self.assertIn("This deployment", row)
        self.assertIn("development key, held by the signer", row)
        self.assertIn("organizations without a key", row)
        self.assertIn("not certified", row)
        self.assertIn("no certificate", row)
        # The signer's own bookkeeping date is not a certificate's end.
        import datetime
        made_up = datetime.datetime.fromtimestamp(
            signer_client.public()["keys"][0]["cert_not_after"],
            datetime.timezone.utc)
        self.assertNotIn("%d %s" % (made_up.day, made_up.strftime("%b %Y")),
                         row)


class SigningPagesEdgeCasesTest(_OrganizationPages):

    def setUp(self):
        super().setUp()
        self._install_org_ca()
        self.svc.cfg.site_publishes_organization_keys = True
        signer_client.reset()

    def _key_id(self):
        return next(k["key_id"] for k in self._keys().values()
                    if k["organization"] == str(self.org.signing_id))

    def test_a_key_its_ca_certified_for_another_site_offers_no_publish(self):
        self._generate()
        key_id = self._key_id()
        self.svc.cfg.site_domain = "elsewhere.example.ph"
        signer_client.reset()
        page = self._page()
        self.assertNotIn("Publish key %d</button>" % key_id, page)
        self.assertIn("Certified by a CA that is not for this site, so phones "
                      "paired with it drop this key. Discard it and generate a "
                      "new one.", page)
        self.assertIn("Discard key %d" % key_id, page)

    def test_a_lost_reply_does_not_say_nothing_changed(self):
        from verify.views.signing import _explain
        text = _explain(signer_client.Unavailable("reset", reply_lost=True))
        self.assertIn("may have done it", text)
        self.assertNotIn("nothing changed", text)
