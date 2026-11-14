"""One certified name, one organization.

Phones render a key certified under a name as "Issued by <name>, certified by
<site> System CA", with nothing to tell two organizations under one name
apart. So the signer refuses to certify, install or publish a key whose name
another organization's live key holds -- compared after NFKC and case
folding -- and alerts when it does.
"""

import uuid

from signer import registry

from .helpers import ORG, ORG_NAME
from .test_org_ca import _Base, _refused

OTHER = str(uuid.uuid4())


class NameUniquenessTest(_Base):

    def setUp(self):
        super().setUp()
        self.install_org_ca()

    def test_another_organization_cannot_take_a_waiting_keys_name(self):
        self.svc.org_generate(organization=ORG, name=ORG_NAME)
        for name in (ORG_NAME, ORG_NAME.upper(), ORG_NAME.lower(),
                     "Ａlpha Registry"):        # fullwidth A
            with self.subTest(name=name):
                err = _refused(self, "policy", self.svc.org_generate,
                               organization=OTHER, name=name)
                self.assertIn("phones could not tell them apart", str(err))

    def test_nor_a_signing_keys(self):
        key_id = self.svc.org_generate(organization=ORG, name=ORG_NAME)["key_id"]
        self.publish(key_id)
        _refused(self, "policy", self.svc.org_generate, organization=OTHER,
                 name=ORG_NAME)

    def test_the_refusal_is_alerted_with_both_organizations(self):
        self.svc.org_generate(organization=ORG, name=ORG_NAME)
        self.alerts.clear()
        _refused(self, "policy", self.svc.org_generate, organization=OTHER,
                 name=ORG_NAME)
        self.assertEqual([s for s, _ in self.alerts], ["high"])
        message = self.alerts[0][1]
        self.assertIn(OTHER, message)
        self.assertIn(ORG, message)
        self.assertEqual(self.store.one(
            "SELECT COUNT(*) AS n FROM keys WHERE organization = ?",
            (OTHER,))["n"], 0)

    def test_an_organization_keeps_its_own_name_across_keys(self):
        key_id = self.svc.org_generate(organization=ORG, name=ORG_NAME)["key_id"]
        self.publish(key_id)
        self.svc.org_generate(organization=ORG, name=ORG_NAME)

    def test_a_name_given_up_is_free_again(self):
        key_id = self.svc.org_generate(organization=ORG, name=ORG_NAME)["key_id"]
        self.svc.discard(key_id)
        self.svc.org_generate(organization=OTHER, name=ORG_NAME)

    def test_a_different_name_is_fine(self):
        self.svc.org_generate(organization=ORG, name=ORG_NAME)
        self.svc.org_generate(organization=OTHER, name="Beta Office")

    def test_a_certificate_from_the_pki_is_held_to_it_too(self):
        """install_cert: the PKI certified another organization id under a
        name that is already taken."""
        self.svc.org_generate(organization=ORG, name=ORG_NAME)
        made = self.svc.org_keygen(organization=OTHER)
        leaf = self.certify(made["key_id"], made["csr"], organization=OTHER)
        _refused(self, "policy", self.svc.install_cert, made["key_id"], leaf)
        self.assertEqual(registry.get(self.store, made["key_id"])["state"],
                         registry.GENERATED)

    def _clash_made_before_the_rule(self):
        """Two organizations' keys under one name, as a signer before this
        rule could have left them."""
        first = self.svc.org_generate(organization=ORG, name=ORG_NAME)["key_id"]
        second = self.svc.org_generate(organization=OTHER,
                                       name="Beta Office")["key_id"]
        with self.store as db:
            db.execute("UPDATE keys SET certified_name = ? WHERE key_id = ?",
                       (ORG_NAME, second))
        return first, second

    def test_operators_see_a_clash_before_they_publish(self):
        first, second = self._clash_made_before_the_rule()
        waiting = {k["key_id"]: k for k in self.svc.status()["waiting"]}
        self.assertEqual(waiting[second]["same_name_as"], first)
        self.assertEqual(waiting[first]["same_name_as"], second)
        conf = self.svc.publish(second, by="alice")
        self.assertEqual(conf["key"]["same_name_as"], first)

    def test_and_the_site_cannot_publish_it(self):
        self.cfg.site_publishes_organization_keys = True
        _first, second = self._clash_made_before_the_rule()
        _refused(self, "policy", self.svc.org_publish, second, operator="sam")
        self.assertEqual(registry.get(self.store, second)["state"],
                         registry.CERTIFIED)

    def test_a_key_with_no_clash_says_so(self):
        key_id = self.svc.org_generate(organization=ORG, name=ORG_NAME)["key_id"]
        waiting = {k["key_id"]: k for k in self.svc.status()["waiting"]}
        self.assertIsNone(waiting[key_id]["same_name_as"])


class LookAlikeNameTest(_Base):

    def setUp(self):
        super().setUp()
        self.install_org_ca()
        self.svc.org_generate(organization=ORG, name=ORG_NAME)

    def test_spacing_and_punctuation_do_not_make_a_new_name(self):
        for name in ("Alpha  Registry", "Alpha Registry.", "Alpha-Registry",
                     "ALPHA REGISTRY!"):
            with self.subTest(name=name):
                _refused(self, "policy", self.svc.org_generate,
                         organization=OTHER, name=name)

    def test_a_name_mixing_look_alike_scripts_is_refused_outright(self):
        for name in ("\u0410lpha Registry",      # Cyrillic A
                     "\u0391lpha Registry",      # Greek Alpha
                     "Beta \u0421linic"):         # Cyrillic Es, no clash at all
            with self.subTest(name=name):
                _refused(self, "policy", self.svc.org_generate,
                         organization=str(uuid.uuid4()), name=name)

    def test_one_script_is_fine_whichever(self):
        self.svc.org_generate(organization=str(uuid.uuid4()),
                              name="\u0410\u043b\u044c\u0444\u0430")   # Cyrillic only
        self.svc.org_generate(organization=str(uuid.uuid4()),
                              name="Nuestra Se\u00f1ora")


class InstalledCertificateNameTest(_Base):
    """A certificate from the PKI is held to org_generate's rules on its
    name."""

    def setUp(self):
        super().setUp()
        self.install_org_ca()

    def _install(self, name):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from ovcrypto import pki
        from .helpers import DAY
        made = self.svc.org_keygen(organization=OTHER)
        csr = x509.load_pem_x509_csr(made["csr"].encode())
        cert = pki.sign_csr(csr, self.ca_key, self.ca, pki.ORGANIZATION,
                            self.clock.now() - 60, self.clock.now() + 730 * DAY,
                            serial=x509.random_serial_number(),
                            organization=name, organization_id=OTHER)
        return made["key_id"], cert.public_bytes(serialization.Encoding.DER)

    def test_a_padded_or_broken_name_is_refused(self):
        for name in ("Beta Office ", " Beta Office", "Beta\u200b Office",
                     "Beta\tOffice", "\u0412eta Office"):
            with self.subTest(name=name):
                key_id, leaf = self._install(name)
                _refused(self, "certificate", self.svc.install_cert, key_id, leaf)
                self.svc.discard(key_id)

    def test_a_clean_one_installs(self):
        key_id, leaf = self._install("Beta Office")
        self.svc.install_cert(key_id, leaf)


class DeploymentKeyIssuerTest(_Base):
    """The deployment key refuses a certified name in any spelling: a case or
    fullwidth variant reads the same on a phone."""

    def setUp(self):
        super().setUp()
        self.install_org_ca()
        key_id = self.svc.org_generate(organization=ORG, name=ORG_NAME)["key_id"]
        self.publish(key_id)

    def test_every_spelling_of_a_certified_name_is_refused(self):
        for issuer in (ORG_NAME, ORG_NAME.lower(), ORG_NAME.upper(),
                       "\uff21lpha Registry", "Alpha  Registry."):
            with self.subTest(issuer=issuer):
                _refused(self, "policy", self.sign_ok, self.deployment,
                         issuer_name=issuer)

    def test_another_name_is_signed(self):
        self.sign_ok(self.deployment, issuer_name="Another Org")

    def test_public_shows_a_clash_too(self):
        other = self.svc.org_generate(organization=OTHER, name="Beta Office")["key_id"]
        with self.store as db:
            db.execute("UPDATE keys SET certified_name = ? WHERE key_id = ?",
                       (ORG_NAME, other))
        keys = {k["key_id"]: k for k in self.svc.public()["keys"]}
        self.assertEqual(keys[other]["same_name_as"],
                         next(k for k, v in keys.items()
                              if v["organization"] == ORG and v["state"] == "active"))
        self.assertIsNone(keys[self.deployment]["same_name_as"])
