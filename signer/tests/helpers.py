"""A signer on a temporary folder, a test CA, and a clock tests can move."""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import tempfile
import unittest
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ovcrypto import issuer, pki, wire

from signer import config as cfgmod
from signer.clock import FixedClock
from signer.keys import FileKeys
from signer.service import SignerService
from signer.store import Store

DAY = 86400
T0 = 1_800_000_000
ORG = "3f1d2c4b-5a69-4e8f-9a0b-1c2d3e4f5a6b"
ORG_NAME = "Alpha Registry"
#: The site the tests' phones pair with, which the System CA is for.
SITE = "verify.example.ph"
LEGACY_KEY = ec.derive_private_key(
    int.from_bytes(hashlib.sha256(b"signer-test-legacy").digest(), "big"),
    ec.SECP256R1())


def spki_of(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)


class SignerTest(unittest.TestCase):
    """A fresh signer per test, with alerts captured."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.clock = FixedClock(T0)
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        # Path length 1: room for the Organization CA below it.
        self.ca = pki.make_ca(self.ca_key, "Test Issuing CA", T0 - 365 * DAY,
                              T0 + 3650 * DAY, serial=2, path_length=1)
        self.ca_der = self.ca.public_bytes(serialization.Encoding.DER)
        self.cfg = cfgmod.Config(anchors=[self.ca_der], site_domain=SITE,
                                 legacy=[cfgmod.Legacy(
                                     1, spki_of(LEGACY_KEY), T0 - 200 * DAY,
                                     T0 + 100 * DAY)])
        self.alerts = []
        self.store = Store(os.path.join(self.dir, "signer.db"))
        self.addCleanup(self.store.db.close)
        self.keys = FileKeys(os.path.join(self.dir, "keys"))
        self.svc = SignerService(
            self.store, self.keys, self.cfg, clock=self.clock,
            alerts=lambda severity, message, fields: self.alerts.append(
                (severity, message)))
        if self.BUNDLE_HISTORY:
            self.bundle_history()

    #: A signer that has signed bundles for over a lease, as one in service
    #: has: its switch gate trusts its own count. False for a signer as new
    #: as its database.
    BUNDLE_HISTORY = True

    def bundle_history(self, at=None):
        """One bundle row a lease and a day ago, for a phone long gone."""
        from signer import ledger
        with self.store as db:
            ledger.append(db, at=at or self.clock.now() - 31 * DAY,
                          kind="sign", context="bundle", summary={
                              "device": "00" * 16, "keys": "||",
                              "key_id": 0, "chains": True})

    # -- keys ------------------------------------------------------------

    def certify(self, key_id, csr_pem, *, organization=None, days=730,
                ca_key=None, ca=None):
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        profile = pki.ORGANIZATION if organization else pki.DEPLOYMENT
        cert = pki.sign_csr(csr, ca_key or self.ca_key, ca or self.ca, profile,
                            self.clock.now() - 60,
                            self.clock.now() + days * DAY,
                            serial=x509.random_serial_number(),
                            organization=ORG_NAME if organization else None,
                            organization_id=organization)
        return cert.public_bytes(serialization.Encoding.DER)

    def ready_key(self, organization=None, *, activate=True):
        """keygen, certify, install, publish (two operators), activate."""
        made = self.svc.keygen(organization=organization, by="alice")
        key_id = made["key_id"]
        self.svc.install_cert(key_id, self.certify(key_id, made["csr"],
                                                   organization=organization),
                              by="alice")
        conf = self.svc.publish(key_id, by="alice")
        self.svc.confirm(conf["confirmation"], by="bob")
        if activate:
            self.svc.activate(key_id, by="alice")
        return key_id

    def org_ca_cert(self, csr_pem, *, days=5 * 365, **knobs):
        """The PKI's certificate for an Organization CA request; knobs make
        the wrong ones (``pki.intermediate_builder``)."""
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        cert = pki.intermediate_builder(
            self.ca_key, self.ca, csr.public_key(), self.clock.now() - 60,
            self.clock.now() + days * DAY, serial=x509.random_serial_number(),
            common_name=knobs.pop("common_name", pki.system_ca_name(SITE)),
            dns_names=knobs.pop("dns_names", (SITE,)), **knobs)
        return cert.public_bytes(serialization.Encoding.DER)

    def install_org_ca(self, **knobs):
        """ca keygen, then the PKI's certificate installed. Its id."""
        made = self.svc.ca_keygen(by="alice")
        self.svc.ca_install(made["ca_id"], self.org_ca_cert(made["csr"],
                                                            **knobs),
                            by="alice")
        return made["ca_id"]

    def ready(self):
        """A deployment key that signs, and the revoked set received."""
        key_id = self.ready_key()
        self.svc.put_revoked([])
        return key_id

    # -- credentials -----------------------------------------------------

    def credential(self, key_id, *, issuer_name="Alpha Registry",
                   issued_at=None, valid_days=365, operator="OPERATOR",
                   credential_id=None):
        """The exact bytes issuer.issue would ask a signer to sign."""
        issued_at = self.clock.now() if issued_at is None else issued_at
        public = {
            wire.T_CREDENTIAL_ID: (credential_id or uuid.uuid4()).bytes,
            wire.T_ISSUED_AT: wire.u32(issued_at),
            wire.T_EXPIRES_AT: wire.u32(issued_at + valid_days * DAY),
            wire.T_DOC_NUMBER: b"DOC-1",
        }
        if issuer_name:
            public[wire.T_ISSUER_ID] = issuer_name.encode()
        if operator:
            public[wire.T_OPERATOR] = operator.encode()
        captured = {}

        class Capture:
            pass

        cap = Capture()
        cap.key_id = key_id
        cap.sig_alg = wire.SIG_ECDSA_P256_SHA256
        cap.sign = lambda message: captured.setdefault("m", message) and bytes(64)
        tier = X25519PrivateKey.generate()
        issuer.issue(public, {}, epoch_keys=issuer.EpochPublicKeys(
            42, tier.public_key(), None), signer=cap)
        return captured["m"]

    def sign_ok(self, key_id, **kwargs):
        sign_kwargs = {k: kwargs.pop(k) for k in ("organization", "operator",
                                                  "holder_id",
                                                  "holder") if k in kwargs}
        return self.svc.sign_credential(self.credential(key_id, **kwargs),
                                        **sign_kwargs)

    def epoch_keys(self):
        return [{"epoch": 42, "tier": 0, "not_before": self.clock.now(),
                 "not_after": self.clock.now() + 120 * DAY,
                 "wrapped": base64.b64encode(os.urandom(113)).decode()}]
