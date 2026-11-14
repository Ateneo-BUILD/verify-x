"""Private keys. Stage 1 keeps them as files only `cl03-signer` can read.

A key file is P-256, PKCS#8, mode 0600, in the key directory -- outside the
application tree, never in verify's database or `.env`, which are copied
into backups. A retired key's file is overwritten and removed: once it no
longer signs, it should no longer exist. Hardware tokens (stage 2) replace
this class, not the policy.

Signatures are raw 64-byte r||s with low-s, as every phone requires.
"""

from __future__ import annotations

import os
import stat

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ovcrypto import keystore, pki


class FileKeys:
    def __init__(self, directory: str):
        self.directory = directory
        os.makedirs(directory, exist_ok=True)

    def _path(self, key_ref: str) -> str:
        if "/" in key_ref or "\\" in key_ref or key_ref.startswith("."):
            raise ValueError("bad key reference")
        return os.path.join(self.directory, key_ref)

    def _load(self, key_ref: str):
        with open(self._path(key_ref), "rb") as handle:
            return serialization.load_pem_private_key(handle.read(), None)

    def generate(self, key_id: int):
        """A new key. Returns (key_ref, spki_der)."""
        key = ec.generate_private_key(ec.SECP256R1())
        key_ref = "key-%d.pem" % key_id
        path = self._path(key_ref)
        if os.path.exists(path):
            raise ValueError("a key file for id %d already exists" % key_id)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                     stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "wb") as handle:
            handle.write(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
        return key_ref, self.spki(key_ref)

    def spki(self, key_ref: str) -> bytes:
        return self._load(key_ref).public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)

    def csr(self, key_ref: str, common_name: str, dns_names=()) -> bytes:
        """A certificate request for the key, PEM. The PKI sets the subject;
        ``dns_names`` are the domains asked for, which the PKI checks against
        what it was told (an Organization CA's site)."""
        builder = (x509.CertificateSigningRequestBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(
                       NameOID.COMMON_NAME, common_name)])))
        if dns_names:
            builder = builder.add_extension(x509.SubjectAlternativeName(
                [x509.DNSName(name) for name in dns_names]), critical=False)
        req = builder.sign(self._load(key_ref), hashes.SHA256())
        return req.public_bytes(serialization.Encoding.PEM)

    def certify(self, ca_ref: str, ca_cert_der: bytes, spki_der: bytes, *,
                not_before: int, not_after: int, organization: str,
                organization_id: str) -> bytes:
        """An organization leaf for ``spki_der``, signed by the Organization
        CA whose key is ``ca_ref``: the profile the PKI issues
        (``ovcrypto.pki.issue_leaf``). DER."""
        leaf = pki.issue_leaf(
            self._load(ca_ref), x509.load_der_x509_certificate(ca_cert_der),
            serialization.load_der_public_key(spki_der), pki.ORGANIZATION,
            not_before, not_after, serial=x509.random_serial_number(),
            organization=organization, organization_id=organization_id)
        return leaf.public_bytes(serialization.Encoding.DER)

    def sign(self, key_ref: str, message: bytes) -> bytes:
        der = self._load(key_ref).sign(message, ec.ECDSA(hashes.SHA256()))
        return keystore.der_to_raw_p256(der)

    def destroy(self, key_ref: str):
        path = self._path(key_ref)
        if not os.path.exists(path):
            return
        size = os.path.getsize(path)
        with open(path, "r+b") as handle:
            handle.write(os.urandom(size))
            handle.flush()
            os.fsync(handle.fileno())
        os.remove(path)
