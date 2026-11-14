"""Organization keys made from verify's pages, and the Organization CA.

A site admin may have the signer make an organization's key and certify it at
once with the Organization CA, or hand back its request for the PKI. Each
test names what a compromised app, or a careless admin, would get from a
signer that allowed it.
"""

import base64
import contextlib
import io
import json
import os
import ssl
import unittest
import uuid
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ovcrypto import chain, pki, trust

from signer import config as cfgmod, registry, sitecheck
from signer.service import Refused
from signer.transport import Dispatcher

from .helpers import DAY, ORG, ORG_NAME, SITE, SignerTest


def _refused(test, reason, fn, *args, **kwargs):
    with test.assertRaises(Refused) as err:
        fn(*args, **kwargs)
    test.assertEqual(err.exception.reason, reason, str(err.exception))
    return err.exception


class _Base(SignerTest):

    def setUp(self):
        super().setUp()
        self.deployment = self.ready()
        self.device = b"\x42" * 16

    def accept(self, previous=None, denied_keys=frozenset(), domain=SITE):
        """What a phone paired with ``domain`` makes of the bundle the signer
        builds now."""
        got = self.svc.bundle(device_id=self.device, device_key_hash=b"h",
                              epoch_keys=self.epoch_keys(),
                              lease_seconds=30 * DAY)
        legacy = registry.get(self.store, 1)
        return trust.accept_bundle(
            base64.b64decode(got["bundle"]),
            chain.decode_chains(got["issuer_chains"]),
            anchors=trust.Anchors(raw={1: bytes(legacy["spki"])},
                                  cas=(self.ca_der,)),
            denied=set(), device_id=self.device, now=self.clock.now(),
            previous=previous, denied_keys=denied_keys, domain=domain), got

    def publish(self, key_id, activate=True):
        conf = self.svc.publish(key_id, by="alice")
        self.svc.confirm(conf["confirmation"], by="bob")
        if activate:
            self.svc.activate(key_id, by="alice")

    def key_file(self, key_id):
        return os.path.join(self.dir, "keys", "key-%d.pem" % key_id)


class GenerateTest(_Base):

    def setUp(self):
        super().setUp()
        self.ca_id = self.install_org_ca()

    def test_one_click_certifies_but_publishes_nothing(self):
        got = self.svc.org_generate(organization=ORG, name=ORG_NAME)
        self.assertEqual(got["state"], registry.CERTIFIED)
        self.assertEqual(got["certified_by"], "verify.example.ph System CA")
        ctx, _ = self.accept()
        self.assertNotIn(got["key_id"], ctx.entries)

    def test_once_two_operators_publish_it_phones_trust_it_by_name(self):
        key_id = self.svc.org_generate(organization=ORG,
                                       name=ORG_NAME)["key_id"]
        self.publish(key_id)
        ctx, raw = self.accept()
        entry = ctx.entries[key_id]
        self.assertEqual(entry.organization, ORG_NAME)
        self.assertEqual(entry.ca_name, "verify.example.ph System CA")
        self.assertEqual(len(raw["issuer_chains"][str(key_id)]), 2)
        self.assertEqual(ctx.credential_trust_list(self.clock.now())
                         .certified[key_id], ORG_NAME)
        signed = self.sign_ok(key_id, organization=ORG, issuer_name=ORG_NAME)
        self.assertEqual(signed["key_id"], key_id)

    def test_the_certificate_names_this_organization_and_nothing_more(self):
        key_id = self.svc.org_generate(organization=ORG,
                                       name=ORG_NAME)["key_id"]
        row = registry.get(self.store, key_id)
        ca = self.store.one("SELECT cert FROM cas WHERE ca_id = ?",
                            (self.ca_id,))
        got = chain.validate(bytes(row["leaf"]), [self.ca_der],
                             self.clock.now(), [bytes(ca["cert"])], SITE)
        self.assertEqual(got.classes, {chain.CREDENTIAL})
        self.assertEqual((got.organization, got.organization_id),
                         (ORG_NAME, ORG))
        self.assertEqual(row["window_end"],
                         registry.signing_until(self.cfg, got.not_after))
        self.assertEqual(self.store.one("SELECT issued FROM cas WHERE ca_id = ?",
                                        (self.ca_id,))["issued"], 1)

    def test_every_certificate_it_issues_is_alerted_on(self):
        self.alerts.clear()
        self.svc.org_generate(organization=ORG, name=ORG_NAME)
        self.assertTrue(any("certified key" in m and ORG_NAME in m
                            for _, m in self.alerts), self.alerts)

    def test_one_key_waits_per_organization(self):
        """Else a looping page, or a compromised app, fills the key folder."""
        self.svc.org_generate(organization=ORG, name=ORG_NAME)
        _refused(self, "policy", self.svc.org_generate, organization=ORG,
                 name=ORG_NAME)
        _refused(self, "policy", self.svc.org_keygen, organization=ORG)
        other = str(uuid.uuid4())
        self.svc.org_generate(organization=other, name="Beta Office")

    def test_a_published_key_still_waits_until_it_signs(self):
        key_id = self.svc.org_generate(organization=ORG,
                                       name=ORG_NAME)["key_id"]
        self.publish(key_id, activate=False)
        _refused(self, "policy", self.svc.org_generate, organization=ORG,
                 name=ORG_NAME)
        self.svc.activate(key_id, by="alice")
        self.svc.org_keygen(organization=ORG)

    def test_the_app_may_make_only_so_many_keys_a_day(self):
        self.cfg.app_keys_per_day = 3
        # Three names: one name is one organization's.
        for n in range(3):
            self.svc.org_generate(organization=str(uuid.uuid4()), name="X%d" % n)
        self.alerts.clear()
        _refused(self, "ceiling", self.svc.org_generate,
                 organization=str(uuid.uuid4()), name="X3")
        _refused(self, "ceiling", self.svc.org_keygen,
                 organization=str(uuid.uuid4()))
        self.assertEqual([s for s, _ in self.alerts], ["high"])
        self.clock.advance(DAY + 1)
        self.svc.org_keygen(organization=str(uuid.uuid4()))

    def test_a_name_must_be_one_a_credential_can_carry(self):
        for name in ("", " Padded", "Padded ", "Tab\tName", "x" * 97,
                     "Line\nbreak", "Zero​width"):
            with self.subTest(name=name):
                _refused(self, "policy", self.svc.org_generate,
                         organization=ORG, name=name)
        self.svc.org_generate(organization=ORG, name="Ñuestra Señora, Inc.")

    def test_an_organization_is_named_by_its_signing_id(self):
        with self.assertRaises(ValueError):
            self.svc.org_generate(organization="not-a-uuid", name=ORG_NAME)

    def test_the_leaf_never_outlives_the_ca(self):
        # A successor CA that ends in 600 days: the leaf ends with it.
        self.install_org_ca(days=600)
        key_id = self.svc.org_generate(organization=ORG,
                                       name=ORG_NAME)["key_id"]
        row = registry.get(self.store, key_id)
        ca = self.store.one("SELECT not_after FROM cas WHERE state = ?",
                            (registry.CERTIFIED,))
        self.assertEqual(row["leaf_not_after"], ca["not_after"])
        leaf = x509.load_der_x509_certificate(bytes(row["leaf"]))
        self.assertLessEqual(int(leaf.not_valid_after_utc.timestamp()),
                             ca["not_after"])

    def test_a_ca_too_close_to_its_end_stops_generating(self):
        self.clock.advance(5 * 365 * DAY - 400 * DAY)
        err = _refused(self, "organization_ca", self.svc.org_generate,
                       organization=ORG, name=ORG_NAME)
        # Said before any key is made, and naming the CA's end, not the
        # leaf setting.
        self.assertIn("ends too soon", err.detail)
        # The PKI path still works.
        self.svc.org_keygen(organization=ORG)

    def test_a_short_leaf_setting_is_refused_and_leaves_no_key(self):
        """A leaf under V + M + 90 days would sign for less than install_cert
        allows, or not at all (its window would end before it starts)."""
        self.cfg.organization_leaf_days = 300
        err = _refused(self, "organization_ca", self.svc.org_generate,
                       organization=ORG, name=ORG_NAME)
        self.assertIn("organization_leaf_days", err.detail)
        self.assertIsNone(registry.waiting_key(self.store, ORG))
        self.assertEqual(sorted(os.listdir(os.path.join(self.dir, "keys"))),
                         ["key-%d.pem" % k for k in
                          sorted([self.deployment, self.ca_id])])

    def test_operators_see_the_name_before_they_publish(self):
        key_id = self.svc.org_generate(organization=ORG,
                                       name=ORG_NAME)["key_id"]
        waiting = {k["key_id"]: k for k in self.svc.status()["waiting"]}
        self.assertEqual((waiting[key_id]["certified_name"],
                          waiting[key_id]["organization"],
                          waiting[key_id]["certified_by"]),
                         (ORG_NAME, ORG, "verify.example.ph System CA"))
        asked = self.svc.publish(key_id, by="alice")
        self.assertEqual(asked["key"]["certified_name"], ORG_NAME)
        pending = self.svc.status()["confirmations"]
        self.assertEqual([(p["confirmation"], p["key"]["certified_name"])
                          for p in pending],
                         [(asked["confirmation"], ORG_NAME)])

    def test_without_an_organization_ca_nothing_is_generated(self):
        conf = self.svc.ca_withdraw(self.ca_id, by="alice")
        self.svc.confirm(conf["confirmation"], by="bob")
        _refused(self, "no_organization_ca", self.svc.org_generate,
                 organization=ORG, name=ORG_NAME)

    def test_a_failure_after_the_key_is_made_leaves_no_key_behind(self):
        from unittest import mock
        with mock.patch.object(chain, "validate",
                               side_effect=chain.ChainError("eku")):
            _refused(self, "organization_ca", self.svc.org_generate,
                     organization=ORG, name=ORG_NAME)
        self.assertEqual(os.listdir(os.path.join(self.dir, "keys")),
                         ["key-%d.pem" % k for k in
                          sorted([self.deployment, self.ca_id])])
        self.assertIsNone(registry.waiting_key(self.store, ORG))


class PkiRequestTest(_Base):

    def test_a_request_for_the_pki_then_its_certificate(self):
        made = self.svc.org_keygen(organization=ORG)
        again = self.svc.csr(made["key_id"])
        self.assertEqual(x509.load_pem_x509_csr(again["csr"].encode())
                         .public_key().public_bytes(
                             serialization.Encoding.DER,
                             serialization.PublicFormat.SubjectPublicKeyInfo),
                         bytes(registry.get(self.store, made["key_id"])["spki"]))
        leaf = self.certify(made["key_id"], made["csr"], organization=ORG)
        self.svc.install_cert(made["key_id"], leaf)
        row = registry.get(self.store, made["key_id"])
        self.assertEqual(row["certified_by"], "Test Issuing CA")
        self.assertIsNone(row["ca_id"])
        _refused(self, "policy", self.svc.csr, made["key_id"])

    def test_only_an_organization_key_hands_out_a_request(self):
        made = self.svc.keygen(by="alice")
        _refused(self, "policy", self.svc.csr, made["key_id"])


class DiscardTest(_Base):

    def setUp(self):
        super().setUp()
        self.install_org_ca()

    def test_discard_destroys_the_key_and_frees_the_organization(self):
        key_id = self.svc.org_generate(organization=ORG,
                                       name=ORG_NAME)["key_id"]
        self.assertTrue(os.path.exists(self.key_file(key_id)))
        self.svc.discard(key_id)
        self.assertFalse(os.path.exists(self.key_file(key_id)))
        self.assertNotIn(key_id, [k["key_id"] for k in self.svc.public()["keys"]])
        nxt = self.svc.org_generate(organization=ORG, name=ORG_NAME)["key_id"]
        self.assertGreater(nxt, key_id)

    def test_a_published_key_is_withdrawn_not_discarded(self):
        """Phones already list it; only a tombstone takes it back."""
        key_id = self.svc.org_generate(organization=ORG,
                                       name=ORG_NAME)["key_id"]
        self.publish(key_id, activate=False)
        _refused(self, "policy", self.svc.discard, key_id)

    def test_not_while_a_publish_waits_for_its_second_operator(self):
        key_id = self.svc.org_generate(organization=ORG,
                                       name=ORG_NAME)["key_id"]
        self.svc.publish(key_id, by="alice")
        _refused(self, "policy", self.svc.discard, key_id)

    def test_the_app_cannot_discard_the_deployments_next_key(self):
        made = self.svc.keygen(by="alice")
        _refused(self, "policy", self.svc.discard, made["key_id"])
        self.svc.discard(made["key_id"], by="alice")


class OrganizationCATest(_Base):

    def test_the_app_socket_cannot_touch_the_ca_or_publish(self):
        d = Dispatcher(self.svc)
        for op in ("ca_keygen", "ca_install", "ca_withdraw", "publish",
                   "confirm", "keygen", "activate", "withdraw"):
            with self.subTest(op=op):
                got = d.handle({"op": op, "args": {}}, admin=False, by="app")
                self.assertEqual(got["reason"], "forbidden")
        for op in ("org_keygen", "org_generate", "csr", "discard"):
            got = d.handle({"op": op, "args": {}}, admin=False, by="app")
            self.assertNotEqual(got.get("reason"), "forbidden", op)

    def test_ids_come_from_the_key_sequence(self):
        ca_id = self.install_org_ca()
        self.assertGreater(ca_id, self.deployment)
        key_id = self.svc.org_generate(organization=ORG,
                                       name=ORG_NAME)["key_id"]
        self.assertEqual(key_id, ca_id + 1)

    def test_a_ca_request_that_cannot_be_made_leaves_no_key_behind(self):
        """The key file must not outlive the refusal, or the next keygen
        reuses its id and finds the file there."""
        with mock.patch.object(self.keys, "csr",
                               side_effect=ValueError("no request")):
            _refused(self, "config", self.svc.ca_keygen, by="alice")
        self.svc.ca_keygen(by="alice")
        self.svc.org_keygen(organization=ORG)

    def test_a_domain_no_ca_can_be_named_after_makes_no_key(self):
        """A CN holds 64 characters, so the domain holds 54."""
        before = sorted(os.listdir(os.path.join(self.dir, "keys")))
        for domain in ("x" * 52 + ".ph", ""):
            with self.subTest(domain=domain):
                self.cfg.site_domain = domain
                _refused(self, "config", self.svc.ca_keygen, by="alice")
        self.assertEqual(sorted(os.listdir(os.path.join(self.dir, "keys"))),
                         before)

    def test_install_refuses_a_ca_phones_cannot_name(self):
        from cryptography.x509.oid import NameOID
        made = self.svc.ca_keygen(by="alice")
        cert = self.org_ca_cert(made["csr"], subject=x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Nameless CA Inc")]))
        err = _refused(self, "certificate", self.svc.ca_install, made["ca_id"],
                       cert, by="alice")
        self.assertEqual(err.detail, "intermediate_name")

    def test_one_ca_waits_for_its_certificate_at_a_time(self):
        self.svc.ca_keygen(by="alice")
        _refused(self, "policy", self.svc.ca_keygen, by="alice")

    def test_install_refuses_what_a_phone_would_refuse(self):
        made = self.svc.ca_keygen(by="alice")
        for reason, knobs in (
                ("intermediate_path_length", {"path_length": 1}),
                ("intermediate_eku", {"ekus": (chain.INFRASTRUCTURE_EKU,
                                               chain.CREDENTIAL_EKU)}),
                ("intermediate_not_a_ca", {"key_cert_sign": False})):
            with self.subTest(reason=reason):
                err = _refused(self, "certificate", self.svc.ca_install,
                               made["ca_id"], self.org_ca_cert(made["csr"],
                                                               **knobs),
                               by="alice")
                self.assertEqual(err.detail, reason)

    def test_install_refuses_a_ca_under_a_ca_without_room(self):
        strict_key = ec.generate_private_key(ec.SECP256R1())
        strict = pki.make_ca(strict_key, "Strict CA", self.clock.now() - DAY,
                             self.clock.now() + 3650 * DAY, serial=9)
        self.cfg.anchors = [strict.public_bytes(serialization.Encoding.DER)]
        made = self.svc.ca_keygen(by="alice")
        csr = x509.load_pem_x509_csr(made["csr"].encode())
        cert = pki.issue_organization_ca(strict_key, strict, csr.public_key(),
                                         self.clock.now() - 60,
                                         self.clock.now() + 1000 * DAY,
                                         serial=10, domain=SITE)
        err = _refused(self, "certificate", self.svc.ca_install, made["ca_id"],
                       cert.public_bytes(serialization.Encoding.DER),
                       by="alice")
        self.assertEqual(err.detail, "ca_path_length")

    def test_install_refuses_another_cas_certificate(self):
        made = self.svc.ca_keygen(by="alice")
        other = self.svc  # a request from a different key
        stray_key = ec.generate_private_key(ec.SECP256R1())
        cert = pki.issue_organization_ca(self.ca_key, self.ca,
                                         stray_key.public_key(),
                                         self.clock.now() - 60,
                                         self.clock.now() + 1000 * DAY,
                                         serial=11, domain=SITE)
        err = _refused(self, "certificate", other.ca_install, made["ca_id"],
                       cert.public_bytes(serialization.Encoding.DER),
                       by="alice")
        self.assertIn("not this CA", err.detail)

    def test_install_refuses_a_ca_too_short_to_issue(self):
        made = self.svc.ca_keygen(by="alice")
        _refused(self, "certificate", self.svc.ca_install, made["ca_id"],
                 self.org_ca_cert(made["csr"], days=400), by="alice")

    def test_a_successor_retires_the_old_ca_and_its_keys_keep_their_chains(self):
        old = self.install_org_ca()
        first = self.svc.org_generate(organization=ORG,
                                      name=ORG_NAME)["key_id"]
        self.publish(first)
        new = self.install_org_ca()
        self.assertFalse(os.path.exists(self.key_file(old)))
        ctx, got = self.accept()
        self.assertEqual(ctx.entries[first].ca_name, "verify.example.ph System CA")
        self.assertEqual(registry.get(self.store, first)["ca_id"], old)
        old_cert = bytes(self.store.one("SELECT cert FROM cas WHERE ca_id = ?",
                                        (old,))["cert"])
        self.assertEqual(base64.b64decode(got["issuer_chains"][str(first)][1]),
                         old_cert)
        other = str(uuid.uuid4())
        second = self.svc.org_generate(organization=other, name="Beta")
        self.assertEqual(second["certified_by"], "verify.example.ph System CA")
        self.assertEqual(registry.get(self.store, second["key_id"])["ca_id"], new)

    def test_withdrawing_the_ca_takes_everything_it_certified(self):
        ca_id = self.install_org_ca()
        key_id = self.svc.org_generate(organization=ORG,
                                       name=ORG_NAME)["key_id"]
        self.publish(key_id)
        before, _ = self.accept()
        self.assertIn(key_id, before.entries)

        conf = self.svc.ca_withdraw(ca_id, by="alice")
        _refused(self, "policy", self.svc.confirm, conf["confirmation"],
                 by="alice")
        self.svc.confirm(conf["confirmation"], by="bob")

        self.assertFalse(os.path.exists(self.key_file(ca_id)))
        self.assertEqual(registry.get(self.store, key_id)["state"],
                         registry.WITHDRAWN)
        after, _ = self.accept(previous=before)
        self.assertNotIn(key_id, after.entries)
        self.assertEqual({ca_id, key_id} & after.tombstones, {ca_id, key_id})
        ca_spki = self.store.one("SELECT spki FROM cas WHERE ca_id = ?",
                                 (ca_id,))["spki"]
        self.assertIn(trust.fingerprint(bytes(ca_spki)), after.withdrawn_keys)
        # Its organization's documents fall back to the deployment key.
        self.assertIsNone(registry.active_key(self.store, ORG))
        self.assertTrue(any("Organization CA %d withdrawn" % ca_id in m
                            for _, m in self.alerts))

    def test_a_phone_refuses_a_key_from_a_withdrawn_ca_under_any_id(self):
        """Whoever kept the CA's key can mint keys we never knew of: the
        CA's fingerprint on the phone's deny-list stops all of them."""
        ca_id = self.install_org_ca()
        key_id = self.svc.org_generate(organization=ORG,
                                       name=ORG_NAME)["key_id"]
        self.publish(key_id)
        ca_spki = bytes(self.store.one("SELECT spki FROM cas WHERE ca_id = ?",
                                       (ca_id,))["spki"])
        ctx, _ = self.accept(denied_keys={trust.fingerprint(ca_spki)})
        self.assertNotIn(key_id, ctx.entries)
        self.assertIn((key_id, trust.ENTRY_DENIED), ctx.dropped)

    def test_the_setup_page_learns_the_ca_from_public(self):
        ca_id = self.install_org_ca()
        cas = self.svc.public()["organization_cas"]
        self.assertEqual([(c["ca_id"], c["state"], c["name"]) for c in cas],
                         [(ca_id, "certified", "verify.example.ph System CA")])
        self.assertLess(cas[0]["issue_until"], cas[0]["not_after"])

    def test_the_cli_speaks_the_ca_commands(self):
        from signer import cli
        calls = []

        def fake_call(sock, op, **args):
            calls.append((op, args))
            if op == "public":
                return {"site_domain": SITE}
            return {"csr": "REQ"} if op == "ca_keygen" else {}

        from unittest import mock
        pem = os.path.join(self.dir, "ca.pem")
        made = self.svc.ca_keygen(by="alice")
        with open(pem, "wb") as fh:
            fh.write(x509.load_der_x509_certificate(
                self.org_ca_cert(made["csr"])).public_bytes(
                    serialization.Encoding.PEM))
        seen = {"issuer": "Test Web CA", "not_after": "Mar 26 2027",
                "domain": SITE}
        with mock.patch.object(cli, "call", fake_call), \
                mock.patch.object(sitecheck, "check", return_value=seen), \
                contextlib.redirect_stderr(io.StringIO()), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            cli.main(["ca", "keygen"])
            cli.main(["ca", "install", pem])
            cli.main(["ca", "withdraw", "31"])
            cli.main(["discard", "22"])
        self.assertTrue(out.getvalue().startswith("REQ"))
        self.assertEqual([op for op, _ in calls],
                         ["public", "ca_keygen", "ca_install", "ca_withdraw",
                          "discard"])
        self.assertIsNone(calls[2][1]["ca_id"])
        self.assertEqual(calls[3][1], {"ca_id": 31})


class SystemCADomainTest(_Base):
    """The Organization CA is this site's System CA: named after the domain
    phones pair with, listing it, and trusted by a phone only for that
    site."""

    def ledger(self, context):
        return [json.loads(r["summary"]) for r in self.store.all(
            "SELECT summary FROM ledger WHERE kind = 'key' AND context = ? "
            "ORDER BY seq", (context,))]

    def test_its_request_is_named_after_the_site_and_asks_for_it(self):
        made = self.svc.ca_keygen(by="alice")
        csr = x509.load_pem_x509_csr(made["csr"].encode())
        self.assertEqual(csr.subject.rfc4514_string(),
                         "CN=verify.example.ph System CA")
        self.assertEqual(pki.request_domains(csr), [SITE])
        self.assertEqual(made["domain"], SITE)
        self.assertEqual(self.ledger("ca-keygen")[-1]["domain"], SITE)

    def test_the_pki_it_asks_signs_it_for_this_site_only(self):
        made = self.svc.ca_keygen(by="alice")
        csr = x509.load_pem_x509_csr(made["csr"].encode())
        with self.assertRaisesRegex(ValueError, "the request is for"):
            pki.sign_csr(csr, self.ca_key, self.ca, pki.ORGANIZATION_CA,
                         self.clock.now(), self.clock.now() + 900 * DAY,
                         serial=7, domain="elsewhere.example.ph")
        cert = pki.sign_csr(csr, self.ca_key, self.ca, pki.ORGANIZATION_CA,
                            self.clock.now() - 60,
                            self.clock.now() + 5 * 365 * DAY, serial=8,
                            domain=SITE)
        got = self.svc.ca_install(made["ca_id"], cert.public_bytes(
            serialization.Encoding.DER), by="alice")
        self.assertEqual(got["name"], "verify.example.ph System CA")
        self.assertEqual(self.ledger("ca-install")[-1]["domain"], SITE)

    def test_install_refuses_a_ca_for_another_site_or_none(self):
        made = self.svc.ca_keygen(by="alice")
        for names, shown in ((("elsewhere.example.ph",), "elsewhere.example.ph"),
                             ((), "no domain"),
                             (("*.example.ph",), "no domain"),
                             (("verify.example.ph.",), "verify.example.ph.")):
            with self.subTest(names=names):
                err = _refused(self, "certificate", self.svc.ca_install,
                               made["ca_id"],
                               self.org_ca_cert(made["csr"], dns_names=names),
                               by="alice")
                self.assertIn("is for %s, not %s" % (shown, SITE), str(err))
        self.assertIsNone(registry.current_ca(self.store))
        self.svc.ca_install(made["ca_id"], self.org_ca_cert(made["csr"]),
                            by="alice")
        self.assertIsNotNone(registry.current_ca(self.store))

    def test_install_refuses_a_ca_named_otherwise(self):
        made = self.svc.ca_keygen(by="alice")
        err = _refused(self, "certificate", self.svc.ca_install, made["ca_id"],
                       self.org_ca_cert(made["csr"],
                                        common_name="Some Organization CA"),
                       by="alice")
        self.assertIn("named 'Some Organization CA'", str(err))

    def test_without_a_site_domain_nothing_is_made_installed_or_issued(self):
        made = self.svc.ca_keygen(by="alice")
        cert = self.org_ca_cert(made["csr"])
        self.svc.ca_install(made["ca_id"], cert, by="alice")
        self.cfg.site_domain = ""
        _refused(self, "config", self.svc.ca_keygen, by="alice")
        _refused(self, "config", self.svc.ca_install, None, cert, by="alice")
        err = _refused(self, "organization_ca", self.svc.org_generate,
                       organization=ORG, name=ORG_NAME)
        self.assertIn("site_domain is not set", str(err))

    def test_a_site_moved_to_another_domain_stops_issuing_and_keeps_no_key(self):
        self.install_org_ca()
        keys_before = sorted(os.listdir(os.path.join(self.dir, "keys")))
        self.cfg.site_domain = "elsewhere.example.ph"
        err = _refused(self, "organization_ca", self.svc.org_generate,
                       organization=ORG, name=ORG_NAME)
        self.assertIn("not for elsewhere.example.ph", str(err))
        self.assertEqual(sorted(os.listdir(os.path.join(self.dir, "keys"))),
                         keys_before)
        self.cfg.site_domain = SITE
        self.svc.org_generate(organization=ORG, name=ORG_NAME)

    def test_a_phone_paired_with_another_site_drops_its_keys(self):
        self.install_org_ca()
        key_id = self.svc.org_generate(organization=ORG,
                                       name=ORG_NAME)["key_id"]
        self.publish(key_id)
        ctx, _ = self.accept()
        self.assertEqual(ctx.entries[key_id].ca_name,
                         "verify.example.ph System CA")
        for domain in ("elsewhere.example.ph", None):
            with self.subTest(domain=domain):
                ctx, _ = self.accept(domain=domain)
                self.assertNotIn(key_id, ctx.entries)
                self.assertIn((key_id, trust.ENTRY_WRONG_DOMAIN), ctx.dropped)
                # The deployment key, from the PKI itself, still counts.
                self.assertIn(self.deployment, ctx.entries)

    def test_public_says_which_site_and_what_the_ca_lists(self):
        ca_id = self.install_org_ca()
        public = self.svc.public()
        self.assertEqual(public["site_domain"], SITE)
        self.assertEqual([(c["ca_id"], c["domains"])
                          for c in public["organization_cas"]],
                         [(ca_id, [SITE])])
        waiting = self.svc.ca_keygen(by="alice")["ca_id"]
        self.assertEqual({c["ca_id"]: c["domains"]
                          for c in self.svc.public()["organization_cas"]},
                         {ca_id: [SITE], waiting: []})

    def test_the_cli_checks_the_site_before_it_makes_a_ca(self):
        from signer import cli
        calls = []

        def fake_call(sock, op, **args):
            calls.append(op)
            return {"site_domain": SITE} if op == "public" else {"csr": "REQ"}

        failed = sitecheck.SiteCheckFailed("https://%s/ did not answer" % SITE)
        with mock.patch.object(cli, "call", fake_call), \
                mock.patch.object(sitecheck, "check",
                                  side_effect=failed) as check, \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["ca", "keygen"]), 1)
        check.assert_called_once_with(SITE)
        self.assertEqual(calls, ["public"])
        self.assertIn("did not answer", err.getvalue())


class SiteCheckTest(unittest.TestCase):
    """What `cl03signer ca keygen` and the test PKI see of the site."""

    class _TLS:
        def __init__(self, cert=None, error=None):
            self.cert, self.error = cert, error

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def getpeercert(self):
            return self.cert

    class _Context:
        def __init__(self, tls):
            self.tls, self.hostnames = tls, []

        def wrap_socket(self, sock, server_hostname):
            self.hostnames.append(server_hostname)
            if self.tls.error:
                raise self.tls.error
            return self.tls

    def _connect(self, address, timeout):
        self.addresses.append(address)
        return contextlib.nullcontext()

    def setUp(self):
        self.addresses = []

    def test_a_valid_certificate_for_the_domain_passes(self):
        ctx = self._Context(self._TLS(cert={
            "issuer": ((("countryName", "US"),), (("organizationName", "Amazon"),),
                       (("commonName", "Amazon RSA 2048 M01"),)),
            "notAfter": "Mar 26 23:59:59 2027 GMT"}))
        got = sitecheck.check(SITE, context=ctx, connect=self._connect)
        self.assertEqual(self.addresses, [(SITE, 443)])
        self.assertEqual(ctx.hostnames, [SITE])
        self.assertEqual(got["issuer"], "Amazon RSA 2048 M01")
        self.assertIn("valid until Mar 26 23:59:59 2027 GMT",
                      sitecheck.describe(got))

    def test_a_certificate_for_another_name_fails(self):
        error = ssl.SSLCertVerificationError("hostname mismatch")
        error.verify_message = "Hostname mismatch"
        ctx = self._Context(self._TLS(error=error))
        with self.assertRaisesRegex(sitecheck.SiteCheckFailed,
                                    "no certificate valid for"):
            sitecheck.check(SITE, context=ctx, connect=self._connect)

    def test_a_site_that_does_not_answer_fails(self):
        def refuse(address, timeout):
            raise ConnectionRefusedError("refused")
        with self.assertRaisesRegex(sitecheck.SiteCheckFailed, "did not answer"):
            sitecheck.check(SITE, connect=refuse)

    def test_without_a_context_it_uses_the_systems_checks(self):
        """The system's roots and its host-name check, as iOS checks a site."""
        ctx = self._Context(self._TLS(cert={"issuer": (), "notAfter": ""}))
        with mock.patch.object(sitecheck.ssl, "create_default_context",
                               return_value=ctx) as made:
            sitecheck.check(SITE, connect=self._connect)
        made.assert_called_once_with()
        real = ssl.create_default_context()
        self.assertTrue(real.check_hostname)
        self.assertEqual(real.verify_mode, ssl.CERT_REQUIRED)


class SiteDomainPolicyFileTest(SignerTest):

    def _load(self, text):
        path = os.path.join(self.dir, "policy.toml")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text + '\n[runtime]\nsite = "x"\n')
        return cfgmod.load(path)

    def test_read_from_the_policy_file(self):
        self.assertEqual(self._load("").site_domain, "")
        self.assertEqual(self._load('site_domain = "dev.verify.example.ph"')
                         .site_domain, "dev.verify.example.ph")

    def test_a_domain_no_ca_can_be_for_is_refused_at_start(self):
        for text in ('site_domain = "Verify.Example.PH"',
                     'site_domain = "https://verify.example.ph"',
                     'site_domain = "verify.example.ph."',
                     'site_domain = "10.0.0.9"',
                     "site_domain = 5"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    self._load(text)

    def test_the_old_name_setting_is_refused_not_ignored(self):
        with self.assertRaisesRegex(ValueError, "site_domain"):
            self._load('organization_ca_name = "Test Organization CA"')
