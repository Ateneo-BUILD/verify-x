"""Credential issuance: claims -> sign -> two-tier encrypt -> QR string.

Only the backend runs this. The printing system POSTs claims and receives a
finished QR string, so it holds no signing key at all -- compromising the print
shop yields no forgery capability, and the backend gets a complete issuance
audit log for free.

Ordering matters and is not arbitrary: each section is compressed *before* it is
signed, so the signature covers the exact bytes that appear on the wire. The
``flags`` byte -- which records both compression decisions and whether a
restricted section exists -- is therefore fully determined before signing, and
is itself covered by the signature.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)

from . import base45, kdf, wire

ZERO_HASH = b"\x00" * wire.HASH_LEN


class IssueError(RuntimeError):
    pass


@dataclass
class EpochPublicKeys:
    """The two audience public keys for one epoch."""
    epoch: int
    public_tier: X25519PublicKey
    restricted_tier: X25519PublicKey = None


def issue(public_claims: dict, restricted_claims: dict, *,
          epoch_keys: EpochPublicKeys, signer, eph_priv=None) -> bytes:
    """Build a complete encrypted payload. Returns raw bytes.

    ``eph_priv`` is injectable purely so test vectors can be deterministic;
    production always lets it default to a fresh key.
    """
    for tag in public_claims:
        if tag == 0:
            raise IssueError("claim 0x00 is no claim: the public tier is "
                             "0x01-0x3F")
        if tag >= 0x40:
            raise IssueError(
                "claim 0x%02x is a restricted-tier tag but was passed as public; "
                "it would be readable by every device" % tag)
    for tag in restricted_claims or {}:
        if tag < 0x40:
            raise IssueError("claim 0x%02x is a public-tier tag" % tag)

    pub_claims, pub_deflated = wire.maybe_deflate(wire.encode_claims(public_claims))

    has_restricted = bool(restricted_claims)
    if has_restricted:
        if epoch_keys.restricted_tier is None:
            raise IssueError("restricted claims given but no restricted-tier key")
        res_plain, res_deflated = wire.maybe_deflate(
            wire.encode_claims(restricted_claims))
        res_hash = hashlib.sha256(res_plain).digest()
    else:
        res_plain, res_deflated, res_hash = b"", False, ZERO_HASH

    flags = 0
    if pub_deflated:
        flags |= wire.FLAG_PUBLIC_DEFLATED
    if has_restricted:
        flags |= wire.FLAG_RESTRICTED_PRESENT
    if res_deflated:
        flags |= wire.FLAG_RESTRICTED_DEFLATED

    # The algorithm comes from the signer rather than a constant: with the key
    # on a PKCS#11 token rather than a cloud KMS, Ed25519 is available wherever
    # the token supports CKM_EDDSA.
    sig_alg = getattr(signer, "sig_alg", wire.SIG_ECDSA_P256_SHA256)
    if sig_alg not in (wire.SIG_ECDSA_P256_SHA256, wire.SIG_ED25519):
        raise IssueError("unsupported signature algorithm %d" % sig_alg)

    sig = signer.sign(wire.signed_bytes(
        wire.VERSION, wire.SUITE_X25519_AESGCM, flags, epoch_keys.epoch,
        pub_claims, res_hash, sig_alg, signer.key_id))
    if len(sig) != wire.SIG_LEN:
        raise IssueError("signature must be %d bytes, got %d"
                         % (wire.SIG_LEN, len(sig)))

    section = wire.PublicSection(
        claims=pub_claims, res_hash=res_hash,
        sig_alg=sig_alg, key_id=signer.key_id, sig=sig)

    if eph_priv is None:
        eph_priv = X25519PrivateKey.generate()
    header = wire.Header(wire.VERSION, wire.SUITE_X25519_AESGCM, flags,
                         epoch_keys.epoch, kdf.public_bytes(eph_priv.public_key()))
    header_bytes = header.pack()

    key, nonce = kdf.sender_derive(eph_priv, epoch_keys.public_tier,
                                   header_bytes, kdf.TIER_PUBLIC)
    sealed = AESGCM(key).encrypt(nonce, section.pack(),
                                 header_bytes + wire.AAD_PUBLIC)
    payload = wire.Payload(header, sealed[:-wire.TAG_LEN], sealed[-wire.TAG_LEN:])

    if has_restricted:
        key, nonce = kdf.sender_derive(eph_priv, epoch_keys.restricted_tier,
                                       header_bytes, kdf.TIER_RESTRICTED)
        sealed = AESGCM(key).encrypt(nonce, res_plain,
                                     header_bytes + wire.AAD_RESTRICTED)
        payload.restricted_ct = sealed[:-wire.TAG_LEN]
        payload.restricted_tag = sealed[-wire.TAG_LEN:]

    return payload.pack()


#: What a reader trims from either end of a scanned string.
QR_WHITESPACE = " \t\n\r\x0b\x0c"


def to_qr_string(payload: bytes) -> str:
    return wire.QR_PREFIX + base45.encode(payload)


def from_qr_string(text: str) -> bytes:
    """The payload after the first ``CL03:``, as the app reads it.

    verify prints its stamps as ``<transaction UUID>:CL03:<base45>``, the UUID
    in the clear ahead of the credential, so the marker is not always first.
    The first one is the right one: a UUID cannot contain the marker, and
    Base45's alphabet can spell it, so a body may hold ``CL03:`` by chance.
    """
    # ASCII whitespace only, as the app trims: str.strip() would also take
    # control characters the app keeps, and read what it refuses.
    text = text.strip(QR_WHITESPACE)
    at = text.find(wire.QR_PREFIX)
    if at < 0:
        raise wire.WireError("not a CL03 QR string")
    return base45.decode(text[at + len(wire.QR_PREFIX):])
