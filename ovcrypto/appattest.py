"""Apple App Attest: the attestation a phone sends when it pairs, and the
assertion it sends with each sync.

Attestation proves *what* is calling -- this app, unmodified, on real Apple
hardware -- and the pairing ticket proves *who* authorised it. Neither stands
in for the other. Without a check here the ticket alone would authorise
binding a key that may live in software.

The steps are Apple's, from "Validating Apps That Connect to Your Server":

attestation, a single time, at pairing --
  1. a CBOR map with ``fmt`` "apple-appattest", ``attStmt.x5c`` [credential
     certificate, intermediate] and ``authData``;
  2. the chain from the credential certificate through the intermediate to
     Apple's App Attestation Root CA, each valid now;
  3. the credential certificate's nonce extension equal to
     SHA-256(authData || SHA-256(client data)), the client data being
     ``attest_client_data``: the single challenge the server issued for this
     pairing, and the device key being paired, so the attestation vouches for
     that key and no other;
  4. the key id equal to SHA-256 of the attested public key's point;
  5. authData naming this app (rpIdHash = SHA-256 of "<TeamID>.<BundleID>"),
     counter 0, the AAGUID of the environment the build was signed for, and a
     credential id equal to the key id.

assertion, on each sync --
  1. a CBOR map with ``signature`` and ``authenticatorData``;
  2. the signature, ECDSA over SHA-256, by the key attested at pairing, valid
     for SHA-256(authenticatorData || SHA-256(client data));
  3. rpIdHash naming this app;
  4. a counter greater than the last one seen, or the assertion was replayed
     or the key cloned.

The attested key is a key of its own, held by the App Attest service. It is
NOT the Secure Enclave key the phone signs challenges with, and an assertion is
checked against the key stored at pairing, never against that one.

Written in this repository and copied verbatim into verify, like the rest of
ovcrypto. It needs nothing beyond ``cryptography``: the CBOR it reads is the
small, definite-length subset these two objects use, and anything else is
refused.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class AttestationError(ValueError):
    """Not accepted. The message says which step, for the server's log."""


#: Apple App Attestation Root CA, as served at
#: https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
#: (P-384, valid from March 2020 to March 2045). Pinned here, with its
#: fingerprint checked when it is loaded, rather than read from a file a
#: deployment could replace.
APPLE_ROOT_PEM = b"""-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----
"""
APPLE_ROOT_SHA256 = (
    "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932")

#: The extension carrying the nonce in the credential certificate.
NONCE_OID = "1.2.840.113635.100.8.2"
#: Its value, exactly: SEQUENCE { [1] { OCTET STRING (32) } }.
_NONCE_PREFIX = bytes.fromhex("3024a1220420")

#: authData's AAGUID for each environment a build can be signed for.
AAGUIDS = {
    "production": b"appattest" + bytes(7),
    "development": b"appattestdevelop",
}

#: What a phone attests at pairing goes behind a context of its own and names
#: the Secure Enclave key it is pairing. An attestation of the bare challenge
#: proves only that a genuine app attested something this server issued: a
#: relay between a real phone and the server could post it beside a key of
#: its own, kept in software, and be recorded as attested. A phone that
#: attests this way says "attest-device-key" when it pairs.
ATTEST_CONTEXT = b"OfflineVerifier/v1/attest\x00"

#: Generous caps for what is decoded: an attestation is a few kilobytes.
MAX_OBJECT_BYTES = 32 * 1024
_MAX_DEPTH = 4


def attest_client_data(challenge: bytes, device_public_key: bytes) -> bytes:
    """The client data a phone attests at pairing: the context, the challenge
    the server issued, and SHA-256 of the device public key exactly as the
    phone sent it (base64-decoded)."""
    return ATTEST_CONTEXT + challenge + hashlib.sha256(device_public_key).digest()


def apple_root() -> x509.Certificate:
    """The pinned root, refused if it is not the certificate fingerprinted
    above."""
    root = x509.load_pem_x509_certificate(APPLE_ROOT_PEM)
    der = root.public_bytes(serialization.Encoding.DER)
    if hashlib.sha256(der).hexdigest() != APPLE_ROOT_SHA256:
        raise AttestationError("the pinned Apple root is not the one expected")
    return root


# -- CBOR, the subset used ----------------------------------------------------

def cbor_loads(data: bytes):
    """Decode one CBOR item: unsigned and negative integers, byte and text
    strings, arrays and maps, definite lengths only, all of `data` used.
    Anything else -- tags, floats, simple values, indefinite lengths,
    trailing bytes -- is refused."""
    if len(data) > MAX_OBJECT_BYTES:
        raise AttestationError("the object is over %d bytes" % MAX_OBJECT_BYTES)
    value, end = _item(data, 0, 0)
    if end != len(data):
        raise AttestationError("trailing bytes after the CBOR item")
    return value


def _length(data: bytes, pos: int, info: int):
    if info < 24:
        return info, pos
    width = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
    if width is None or pos + width > len(data):
        raise AttestationError("unsupported or truncated CBOR length")
    return int.from_bytes(data[pos:pos + width], "big"), pos + width


def _item(data: bytes, pos: int, depth: int):
    if depth > _MAX_DEPTH:
        raise AttestationError("CBOR nested too deeply")
    if pos >= len(data):
        raise AttestationError("truncated CBOR")
    major, info = data[pos] >> 5, data[pos] & 0x1F
    length, pos = _length(data, pos + 1, info)
    if major == 0:
        return length, pos
    if major == 1:
        return -1 - length, pos
    if major in (2, 3):
        if pos + length > len(data):
            raise AttestationError("truncated CBOR string")
        raw = data[pos:pos + length]
        if major == 2:
            return bytes(raw), pos + length
        try:
            return raw.decode("utf-8"), pos + length
        except UnicodeDecodeError:
            raise AttestationError("CBOR text is not UTF-8") from None
    if major == 4:
        if length > len(data):
            raise AttestationError("CBOR array longer than its input")
        items = []
        for _ in range(length):
            value, pos = _item(data, pos, depth + 1)
            items.append(value)
        return items, pos
    if major == 5:
        if length > len(data):
            raise AttestationError("CBOR map longer than its input")
        out = {}
        for _ in range(length):
            key, pos = _item(data, pos, depth + 1)
            if not isinstance(key, (str, int)) or key in out:
                raise AttestationError("a CBOR map key is not unique text")
            out[key], pos = _item(data, pos, depth + 1)
        return out, pos
    raise AttestationError("unsupported CBOR type %d" % major)


# -- the two checks -----------------------------------------------------------

@dataclass(frozen=True)
class Attested:
    """What an accepted attestation establishes."""
    public_key_der: bytes   # the App Attest key, SubjectPublicKeyInfo
    environment: str


#: What `cryptography` raises reading a certificate it parsed but cannot use:
#: an algorithm it does not know, an extension it cannot decode. Each is a
#: refusal here, never a server error.
_UNREADABLE = (UnsupportedAlgorithm, ValueError, TypeError)


def _verify_signed_by(child: x509.Certificate, parent: x509.Certificate):
    try:
        key = parent.public_key()
        algorithm = child.signature_hash_algorithm
    except _UNREADABLE:
        raise AttestationError("a certificate in the chain uses an algorithm "
                               "this does not read") from None
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise AttestationError("an issuer key in the chain is not EC")
    try:
        key.verify(child.signature, child.tbs_certificate_bytes,
                   ec.ECDSA(algorithm))
    except (InvalidSignature, *_UNREADABLE):
        raise AttestationError("the certificate chain does not verify") from None


def _point(key) -> bytes:
    return key.public_bytes(serialization.Encoding.X962,
                            serialization.PublicFormat.UncompressedPoint)


def verify_attestation(attestation: bytes, *, key_id: bytes, client_data: bytes,
                       app_id: str, environment: str,
                       root: x509.Certificate = None,
                       now: datetime = None) -> Attested:
    """Check a fresh attestation object, or raise AttestationError.

    `key_id` is the raw 32 bytes (the app sends it base64), `client_data`
    `attest_client_data` of the challenge the server issued for this pairing
    and the device key being paired, `app_id` "<TeamID>.<BundleID>",
    `environment` "production" or "development". `root` and `now` are for
    tests; the root is Apple's otherwise.
    """
    if environment not in AAGUIDS:
        raise AttestationError("unknown App Attest environment %r" % environment)
    if not app_id:
        raise AttestationError("no app id is configured for App Attest")
    if len(key_id) != 32:
        raise AttestationError("a key id is 32 bytes")
    obj = cbor_loads(attestation)
    if not isinstance(obj, dict) or obj.get("fmt") != "apple-appattest":
        raise AttestationError("not an apple-appattest object")
    statement = obj.get("attStmt")
    auth_data = obj.get("authData")
    chain = statement.get("x5c") if isinstance(statement, dict) else None
    if (not isinstance(auth_data, bytes) or not isinstance(chain, list)
            or len(chain) < 2 or not all(isinstance(c, bytes) for c in chain)):
        raise AttestationError("missing authData or certificates")
    try:
        credential = x509.load_der_x509_certificate(chain[0])
        intermediate = x509.load_der_x509_certificate(chain[1])
    except ValueError:
        raise AttestationError("a certificate does not parse") from None

    # 2. The chain, each valid now.
    root = root or apple_root()
    _verify_signed_by(credential, intermediate)
    _verify_signed_by(intermediate, root)
    now = now or datetime.now(timezone.utc)
    for cert in (credential, intermediate):
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            raise AttestationError("a certificate in the chain is not valid now")

    # 3. The nonce binds this attestation to the server's single challenge,
    # and to the device key being paired.
    nonce = hashlib.sha256(auth_data + hashlib.sha256(client_data).digest()).digest()
    try:
        ext = credential.extensions.get_extension_for_oid(
            x509.ObjectIdentifier(NONCE_OID))
        value = ext.value.value
    except x509.ExtensionNotFound:
        raise AttestationError("the credential certificate has no nonce") from None
    except (*_UNREADABLE, AttributeError):
        raise AttestationError("the credential certificate's extensions do "
                               "not read") from None
    if value != _NONCE_PREFIX + nonce:
        raise AttestationError("the nonce does not match the challenge and key")

    # 4. The key id names the attested key.
    try:
        public = credential.public_key()
    except _UNREADABLE:
        raise AttestationError("the attested key is not P-256") from None
    if (not isinstance(public, ec.EllipticCurvePublicKey)
            or not isinstance(public.curve, ec.SECP256R1)):
        raise AttestationError("the attested key is not P-256")
    if hashlib.sha256(_point(public)).digest() != key_id:
        raise AttestationError("the key id is not the attested key's")

    # 5. authData: this app, a fresh key, this environment, this key id.
    if len(auth_data) < 55:
        raise AttestationError("authData is too short")
    if auth_data[:32] != hashlib.sha256(app_id.encode()).digest():
        raise AttestationError("the attestation is for another app id")
    if struct.unpack(">I", auth_data[33:37])[0] != 0:
        raise AttestationError("a fresh attestation has counter 0")
    if auth_data[37:53] != AAGUIDS[environment]:
        raise AttestationError("the attestation is for another environment "
                               "than %s" % environment)
    length = struct.unpack(">H", auth_data[53:55])[0]
    if auth_data[55:55 + length] != key_id:
        raise AttestationError("the credential id is not the key id")

    return Attested(
        public_key_der=public.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo),
        environment=environment)


def verify_assertion(assertion: bytes, *, client_data: bytes,
                     public_key_der: bytes, app_id: str,
                     previous_counter: int) -> int:
    """Check an assertion by the key attested at pairing; return its counter,
    which must be greater than `previous_counter`. Raises AttestationError."""
    obj = cbor_loads(assertion)
    signature = obj.get("signature") if isinstance(obj, dict) else None
    auth_data = obj.get("authenticatorData") if isinstance(obj, dict) else None
    if not isinstance(signature, bytes) or not isinstance(auth_data, bytes):
        raise AttestationError("missing signature or authenticatorData")
    if len(auth_data) < 37:
        raise AttestationError("authenticatorData is too short")
    if auth_data[:32] != hashlib.sha256(app_id.encode()).digest():
        raise AttestationError("the assertion is for another app id")
    try:
        key = serialization.load_der_public_key(public_key_der)
    except _UNREADABLE:
        raise AttestationError("the stored attested key does not parse") from None
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise AttestationError("the stored attested key is not EC")
    nonce = hashlib.sha256(auth_data + hashlib.sha256(client_data).digest()).digest()
    try:
        key.verify(signature, nonce, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError):
        raise AttestationError("the assertion signature does not verify") from None
    counter = struct.unpack(">I", auth_data[33:37])[0]
    if counter <= previous_counter:
        raise AttestationError("the counter did not advance (%d after %d)"
                               % (counter, previous_counter))
    return counter
