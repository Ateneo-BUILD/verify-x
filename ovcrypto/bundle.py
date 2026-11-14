"""Signed key bundle: what the backend hands a device on every sync.

Carries, for one device: the wrapped epoch private keys it is entitled to, the
issuer trust list, the revocation filter, and the device lease window.

Two design points worth stating plainly.

**Binary, not JSON.** The bundle is signed, and the device must reproduce the
signed bytes exactly. Canonical JSON across Python and Swift is a well-known
source of silent mismatches (key order, integer vs float, unicode escaping), so
the bundle is a binary format and JSON appears only as a transport envelope
around a base64 blob.

**notBefore/notAfter are inside the signature.** That is what makes them
authoritative on a device whose clock the attacker controls: winding the phone's
clock back does not alter the lease the backend granted, and the device compares
against a monotonic high-water mark rather than trusting the wall clock alone.

Epoch private keys are wrapped with Apple's ECIES to the device's Secure Enclave
P-256 public key, so they are decryptable only by that Enclave, only under the
biometric gate set at enrolment.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import keystore

MAGIC = b"CL03KB"
VERSION = 1
SIG_CONTEXT = b"OfflineVerifier/v1/bundle\x00"

TIER_PUBLIC = 0
TIER_RESTRICTED = 1

#: The longest lease a phone accepts. Compiled into the app as well: a bundle
#: whose lease the phone had no upper bound for could be made to outlast every
#: later, legitimate one.
MAX_LEASE_SECONDS = 31 * 86400


class BundleError(ValueError):
    pass


# --------------------------------------------------------------------------
# Apple ECIES -- eciesEncryptionCofactorVariableIVX963SHA256AESGCM
#
# This is the exact format `SecKeyCreateDecryptedData` expects for a Secure
# Enclave P-256 key, and the reason the device never sees an epoch key in the
# clear outside the Enclave's decryption call.
#
#   output = ephemeralPublicKey (65 B, X9.62 uncompressed) || ciphertext || tag
#   X9.63-KDF(SHA-256) over the ECDH secret, sharedInfo = ephemeral public key,
#   producing 32 bytes: AES-128 key (16) || IV (16). AES-128-GCM, no AAD.
# --------------------------------------------------------------------------

def x963_kdf(shared_secret: bytes, shared_info: bytes, length: int) -> bytes:
    out = b""
    counter = 1
    while len(out) < length:
        out += hashlib.sha256(
            shared_secret + struct.pack(">I", counter) + shared_info).digest()
        counter += 1
    return out[:length]


def apple_ecies_encrypt(recipient_pub: ec.EllipticCurvePublicKey,
                        plaintext: bytes, eph_priv=None) -> bytes:
    if eph_priv is None:
        eph_priv = ec.generate_private_key(ec.SECP256R1())
    eph_pub_bytes = eph_priv.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint)
    shared = eph_priv.exchange(ec.ECDH(), recipient_pub)
    derived = x963_kdf(shared, eph_pub_bytes, 32)
    return eph_pub_bytes + AESGCM(derived[:16]).encrypt(
        derived[16:], plaintext, None)


def apple_ecies_decrypt(recipient_priv: ec.EllipticCurvePrivateKey,
                        blob: bytes) -> bytes:
    """Software mirror of the Enclave's decrypt, for tests only.

    On device this is `SecKeyCreateDecryptedData`; the private key is inside the
    Secure Enclave and this code path does not exist.
    """
    if len(blob) < 65 + 16:
        raise BundleError("ECIES blob too short")
    eph_pub_bytes, rest = blob[:65], blob[65:]
    eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), eph_pub_bytes)
    shared = recipient_priv.exchange(ec.ECDH(), eph_pub)
    derived = x963_kdf(shared, eph_pub_bytes, 32)
    return AESGCM(derived[:16]).decrypt(derived[16:], rest, None)


# --------------------------------------------------------------------------
# Bundle structure
# --------------------------------------------------------------------------

@dataclass
class WrappedEpochKey:
    epoch: int
    tier: int
    not_before: int
    not_after: int
    wrapped: bytes  # X25519 private key, Apple-ECIES to the device SE key


#: A tombstone's fingerprint: SHA-256 of the withdrawn key's DER SPKI.
TOMBSTONE_FINGERPRINT_LEN = 32

#: The trust entry that binds the certificates sent beside a bundle: in place
#: of a key, ``chain.chains_digest`` of the ``issuer_chains`` the signer
#: returned with it, so whoever relays them cannot drop one organization's key
#: and keep the bundle. Never a key's id. Its window opens, so a phone that
#: predates it parses a key it cannot load and trusts nothing new: a
#: tombstone's shape would have gone into those phones' deny-lists for good,
#: one fingerprint per sync.
CHAINS_DIGEST_ID = 0xFFFFFFFF
CHAINS_DIGEST_LEN = 32


@dataclass
class TrustEntry:
    key_id: int
    not_before: int
    not_after: int
    spki: bytes  # DER SubjectPublicKeyInfo, P-256; a tombstone: see below

    @property
    def is_chains_digest(self) -> bool:
        """The entry that binds the chains, not a key (CHAINS_DIGEST_ID)."""
        return self.key_id == CHAINS_DIGEST_ID

    @property
    def is_tombstone(self) -> bool:
        """A withdrawn key, named so phones can refuse it everywhere.

        A window that never opens, and in place of a key either nothing (the
        id alone) or the SHA-256 of the withdrawn key's SPKI, 32 bytes. The
        fingerprint is what matters: a certificate does not say which key id
        it belongs to, so whoever holds a withdrawn key could offer it again
        under a new id. A phone that predates tombstones parses either as a
        key it cannot load, so it trusts nothing new.
        """
        return (not self.is_chains_digest
                and self.not_before >= self.not_after
                and len(self.spki) in (0, TOMBSTONE_FINGERPRINT_LEN))


def chains_entry(digest: bytes) -> TrustEntry:
    """The entry binding a bundle's chains, as the signer lists it."""
    if len(digest) != CHAINS_DIGEST_LEN:
        raise BundleError("a chains digest is %d bytes" % CHAINS_DIGEST_LEN)
    return TrustEntry(CHAINS_DIGEST_ID, 0, 1, digest)


@dataclass
class Bundle:
    device_id: bytes
    issued_at: int
    not_before: int
    not_after: int          # end of the device lease
    epoch_keys: list = field(default_factory=list)
    trust: list = field(default_factory=list)
    revocation: bytes = b""
    sig_key_id: int = 0
    sig: bytes = b""

    @property
    def chains_digest(self):
        """The digest of the chains this bundle binds, or None if it binds
        none (a bundle made before bundles bound their chains, or one made
        without a signer)."""
        for t in self.trust:
            if t.is_chains_digest:
                return t.spki
        return None

    # -- serialisation -------------------------------------------------

    def _body(self) -> bytes:
        if len(self.device_id) > 255:
            raise BundleError("device id too long")
        if len(self.epoch_keys) > 255 or len(self.trust) > 255:
            raise BundleError("too many entries")
        out = bytearray(MAGIC)
        out += bytes([VERSION, 0])
        out += struct.pack(">III", self.issued_at, self.not_before, self.not_after)
        out.append(len(self.device_id))
        out += self.device_id

        out.append(len(self.epoch_keys))
        for k in self.epoch_keys:
            out += struct.pack(">IBII", k.epoch, k.tier, k.not_before, k.not_after)
            out += struct.pack(">H", len(k.wrapped)) + k.wrapped

        out.append(len(self.trust))
        for t in self.trust:
            out += struct.pack(">III", t.key_id, t.not_before, t.not_after)
            out += struct.pack(">H", len(t.spki)) + t.spki

        out += struct.pack(">I", len(self.revocation)) + self.revocation
        out += struct.pack(">I", self.sig_key_id)
        return bytes(out)

    def signed_bytes(self) -> bytes:
        return SIG_CONTEXT + self._body()

    def pack(self) -> bytes:
        if len(self.sig) != 64:
            raise BundleError("bundle is not signed")
        return self._body() + self.sig

    def check_entries(self) -> None:
        """What every bundle must satisfy, signed or parsed.

        A repeated key id would let one trust list name two keys for one id,
        and the app would fail on it at scan time. An entry with no key must
        be a tombstone, and a tombstone must carry no key.
        """
        seen = set()
        for t in self.trust:
            if t.key_id in seen:
                raise BundleError("key id %d listed twice" % t.key_id)
            seen.add(t.key_id)
            if t.is_chains_digest:
                if (len(t.spki) != CHAINS_DIGEST_LEN
                        or t.not_before >= t.not_after):
                    raise BundleError("the chains digest entry is malformed")
                continue
            if not t.spki and not t.is_tombstone:
                raise BundleError("key %d has no key and is not a tombstone"
                                  % t.key_id)
            if (t.spki and t.not_before >= t.not_after
                    and not t.is_tombstone):
                raise BundleError("key %d has an empty window" % t.key_id)

    def check(self) -> None:
        """Everything `check_entries` does, plus the lease's bounds.

        A lease that ends when it starts, or before, is over on arrival, and
        continuity does not guard the sync after it.
        """
        self.check_entries()
        if self.not_after - self.issued_at > MAX_LEASE_SECONDS:
            raise BundleError("lease of %d s is longer than %d s"
                              % (self.not_after - self.issued_at,
                                 MAX_LEASE_SECONDS))
        if self.not_after <= self.issued_at:
            raise BundleError("the lease ends when it starts")

    def sign(self, signer) -> "Bundle":
        self.check()
        self.sig_key_id = signer.key_id
        self.sig = signer.sign(self.signed_bytes())
        return self

    def verify(self, trust_list) -> bool:
        spki = trust_list.get(self.sig_key_id)
        if spki is None:
            return False
        return keystore.verify(spki, self.signed_bytes(), self.sig)

    @classmethod
    def unpack(cls, data: bytes) -> "Bundle":
        if len(data) < 22 or data[:len(MAGIC)] != MAGIC:
            raise BundleError("not a key bundle")
        if data[6] != VERSION:
            raise BundleError("unsupported bundle version %d" % data[6])
        # The signature is checked over bytes rebuilt from these fields, which
        # write this byte as 0; one sent as anything else would verify here
        # and not on a phone, which checks the bytes it got. Refused, so both
        # sides judge the same bytes.
        if data[7] != 0:
            raise BundleError("reserved byte is %d, not 0" % data[7])
        i = 8
        issued_at, not_before, not_after = struct.unpack_from(">III", data, i)
        i += 12

        def take(n, what):
            nonlocal i
            if i + n > len(data):
                raise BundleError("truncated bundle: %s" % what)
            chunk = data[i:i + n]
            i += n
            return chunk

        device_id = take(take(1, "device id length")[0], "device id")

        epoch_keys = []
        for _ in range(take(1, "epoch count")[0]):
            epoch, tier, nb, na = struct.unpack(">IBII", take(13, "epoch key"))
            length = struct.unpack(">H", take(2, "wrapped length"))[0]
            epoch_keys.append(
                WrappedEpochKey(epoch, tier, nb, na, take(length, "wrapped key")))

        trust = []
        for _ in range(take(1, "trust count")[0]):
            key_id, nb, na = struct.unpack(">III", take(12, "trust entry"))
            length = struct.unpack(">H", take(2, "spki length"))[0]
            trust.append(TrustEntry(key_id, nb, na, take(length, "spki")))

        rev_len = struct.unpack(">I", take(4, "revocation length"))[0]
        revocation = take(rev_len, "revocation filter")
        sig_key_id = struct.unpack(">I", take(4, "sig key id"))[0]
        sig = take(64, "signature")
        if i != len(data):
            raise BundleError("%d trailing bytes after bundle" % (len(data) - i))

        parsed = cls(device_id, issued_at, not_before, not_after,
                     epoch_keys, trust, revocation, sig_key_id, sig)
        # Structure only. Whether the lease is acceptable is the trust rule's
        # call (ovcrypto/trust.py), made against the phone's own clock.
        parsed.check_entries()
        return parsed
