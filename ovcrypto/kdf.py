"""Key schedule shared by the issuer and the verifier.

One ephemeral X25519 key pair serves both tiers: the ephemeral public key is
32 bytes and would otherwise have to be repeated, so a second tier costs only
its 16-byte GCM tag. Each tier runs its own ECDH against its own static key,
producing independent secrets.

Two details follow HPKE practice rather than textbook ECIES:

* the recipient's static public key is mixed into the HKDF salt, so a shared
  secret cannot be reinterpreted against a different recipient;
* the GCM nonce is *derived* rather than transmitted, saving 12 wire bytes.
  That is safe only because every message carries a fresh ephemeral key, which
  makes each (key, nonce) pair unique.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

TIER_PUBLIC = 0
TIER_RESTRICTED = 1

_TIER_LABEL = {TIER_PUBLIC: b"public", TIER_RESTRICTED: b"restricted"}

KEY_LEN = 32
NONCE_LEN = 12


def public_bytes(key: X25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw,
                            serialization.PublicFormat.Raw)


def private_bytes(key: X25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.Raw,
                             serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length,
                salt=salt, info=info).derive(ikm)


def derive(shared_secret: bytes, header: bytes, static_pub: bytes,
           tier: int) -> tuple[bytes, bytes]:
    """Return ``(key, nonce)`` for one tier."""
    label = _TIER_LABEL[tier]
    salt = header + static_pub
    # "CL03" in these two labels is a constant of the key schedule, not the
    # QR marker: changing either label would leave every credential already
    # issued unopenable.
    key = _hkdf(shared_secret, salt, b"CL03 key " + label, KEY_LEN)
    nonce = _hkdf(shared_secret, salt, b"CL03 nonce " + label, NONCE_LEN)
    return key, nonce


def sender_derive(eph_priv: X25519PrivateKey, static_pub: X25519PublicKey,
                  header: bytes, tier: int) -> tuple[bytes, bytes]:
    return derive(eph_priv.exchange(static_pub), header,
                  public_bytes(static_pub), tier)


def recipient_derive(static_priv: X25519PrivateKey, eph_pub_raw: bytes,
                     header: bytes, tier: int) -> tuple[bytes, bytes]:
    eph_pub = X25519PublicKey.from_public_bytes(eph_pub_raw)
    return derive(static_priv.exchange(eph_pub), header,
                  public_bytes(static_priv.public_key()), tier)
