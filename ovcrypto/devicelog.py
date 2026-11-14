"""The device activity log: records a phone can write and cannot read back.

A verifier phone records what it did -- pairing, syncs, unlocks, every document
it read and the verdict -- and later uploads the lot to the backend that paired
it. The log has to hold up on a phone that is jailbroken or otherwise
compromised, and the design follows from one rule: **a key the phone holds is
a key whoever compromises the phone holds.** So the phone holds no key that
opens the log at all.

Each record is sealed, the moment it is written, to a public key whose private
half never leaves the backend: one ephemeral X25519 key per record, ECDH
against the log key, HKDF-SHA256, AES-256-GCM. It is the credential's own
construction (`kdf.py`), with its own labels. The phone keeps only ciphertext
and the log key's *public* half. Root on the phone reads ciphertext; the
records written before the compromise stay closed.

What sealing does not do is stop a compromised phone writing false records, or
deleting unsent ones. Two things bound that:

* every record carries its sequence number and the SHA-256 of the record
  before it, inside the sealed part, so a record removed from the middle or a
  history rewritten after an upload shows on the backend as a break in the
  chain;
* the upload is signed by the device's Secure Enclave key over the server's
  challenge and a digest of exactly the records sent (`upload_signed_bytes`).

The log key reaches the phone in a statement signed by the issuer key
(`key_statement_bytes`), which the phone already pins, so a server impersonator
cannot hand it a key of its own.

Record layout (all integers big-endian)::

    "CL03LG"          6   magic
    0x01              1   version
    key_id            4   which log key it is sealed to
    seq               8   this device's record number, from 1
    ephemeral        32   X25519 public key, fresh per record
    ciphertext + tag  n+16

The first 19 bytes are the header. The header and the ephemeral key are the
AEAD's associated data, so neither can be changed without the record failing
to open. The plaintext is UTF-8 JSON.

The sealing side is in the iPhone app (`LogSeal.swift`); `seal` here exists for
tests and for vectors.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import kdf

MAGIC = b"CL03LG"
VERSION = 1
HEADER_LEN = 6 + 1 + 4 + 8
EPH_LEN = 32
TAG_LEN = 16
MIN_RECORD_LEN = HEADER_LEN + EPH_LEN + TAG_LEN

#: The `prev` of a device's first record: no record came before it.
GENESIS = bytes(32)

#: What the issuer key signs when it vouches for a log key. Domain-separated
#: from credentials ("OfflineVerifier/v1/sig"), bundles (".../bundle") and the
#: revocation feed (".../revocation"), so no one of them verifies as another.
KEY_CONTEXT = b"OfflineVerifier/v1/log-key\x00"
KEY_MAGIC = b"CL03LK"
KEY_VERSION = 1

#: What the device's Enclave key signs for an upload. Separate from the bare
#: challenge `/keys/` signs, so an upload signature can never be replayed as a
#: key request, or the other way round.
UPLOAD_CONTEXT = b"OfflineVerifier/v1/log-upload\x00"

#: What the device's Enclave key signs at `/keys/`: the challenge behind a
#: context of its own, so a server that handed out "challenges" could not get
#: it to sign any other message. A phone says it signs this way with the
#: capability "keys-context"; one that does not signs the bare challenge.
KEYS_CONTEXT = b"OfflineVerifier/v1/keys\x00"

#: What a server signs, with a key the phone's bundle trusts for statements,
#: to say it holds a phone's log records. The phone deletes records only
#: once this covers them, so whoever merely answers for the site's host
#: cannot make it delete evidence it never received.
ACK_CONTEXT = b"OfflineVerifier/v1/log-ack\x00"
ACK_MAGIC = b"CL03LA"
ACK_VERSION = 1

#: What a server signs, with the same key, to tell a phone its time at one
#: sync: over a nonce the phone made for that sync, so the answer cannot have
#: been kept from an earlier one. It is the only time a phone brings its
#: clock's high-water mark back to; a bundle's own `issued_at` is no proof of
#: when it was received, since a phone's holder who intercepts their own TLS
#: could hold one back and serve it later. Not over the server's challenge,
#: which that holder could replay to the phone along with the answer they kept
#: for it.
TIME_CONTEXT = b"OfflineVerifier/v1/sync-time\x00"
TIME_MAGIC = b"CL03ST"
TIME_VERSION = 1
TIME_NONCE_BYTES = 16

_KEY_INFO = b"CL03LG key"
_NONCE_INFO = b"CL03LG nonce"


class LogError(ValueError):
    pass


@dataclass(frozen=True)
class Header:
    key_id: int
    seq: int


@dataclass(frozen=True)
class Opened:
    key_id: int
    seq: int
    plaintext: bytes


def header_bytes(key_id: int, seq: int) -> bytes:
    if not 0 <= key_id <= 0xFFFFFFFF:
        raise LogError("key id out of range")
    if not 1 <= seq <= 0xFFFFFFFFFFFFFFFF:
        raise LogError("sequence number out of range")
    return MAGIC + bytes([VERSION]) + struct.pack(">IQ", key_id, seq)


def parse_header(record: bytes) -> Header:
    """Read the clear part. Says nothing about whether the record opens."""
    if len(record) < MIN_RECORD_LEN:
        raise LogError("record too short")
    if record[:len(MAGIC)] != MAGIC:
        raise LogError("not a log record")
    if record[6] != VERSION:
        raise LogError("unsupported log record version %d" % record[6])
    key_id, seq = struct.unpack(">IQ", record[7:HEADER_LEN])
    if seq == 0:
        raise LogError("sequence number 0")
    return Header(key_id, seq)


def _derive(shared: bytes, header: bytes, eph_pub: bytes,
            static_pub: bytes) -> tuple[bytes, bytes]:
    # As kdf.derive: the recipient's static key in the salt, the nonce derived
    # rather than sent. Safe for the same reason -- a fresh ephemeral key per
    # record makes every (key, nonce) pair unique.
    salt = header + eph_pub + static_pub
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
               info=_KEY_INFO).derive(shared)
    nonce = HKDF(algorithm=hashes.SHA256(), length=12, salt=salt,
                 info=_NONCE_INFO).derive(shared)
    return key, nonce


def seal(plaintext: bytes, *, key_id: int, seq: int,
         recipient: X25519PublicKey,
         ephemeral: X25519PrivateKey | None = None) -> bytes:
    """Seal one record to the log key. The phone's job; here for tests."""
    eph = ephemeral or X25519PrivateKey.generate()
    eph_pub = kdf.public_bytes(eph.public_key())
    header = header_bytes(key_id, seq)
    key, nonce = _derive(eph.exchange(recipient), header, eph_pub,
                         kdf.public_bytes(recipient))
    return header + eph_pub + AESGCM(key).encrypt(nonce, plaintext,
                                                  header + eph_pub)


def open_record(record: bytes, keys: dict[int, X25519PrivateKey]) -> Opened:
    """Open a record with whichever log key its header names.

    Raises `LogError` for an unknown key or a record that does not open; the
    two are not told apart beyond the message, since either way nothing in it
    can be believed.
    """
    head = parse_header(record)
    private = keys.get(head.key_id)
    if private is None:
        raise LogError("sealed to unknown log key %d" % head.key_id)
    header = record[:HEADER_LEN]
    eph_pub = record[HEADER_LEN:HEADER_LEN + EPH_LEN]
    body = record[HEADER_LEN + EPH_LEN:]
    try:
        shared = private.exchange(X25519PublicKey.from_public_bytes(eph_pub))
        key, nonce = _derive(shared, header, eph_pub,
                             kdf.public_bytes(private.public_key()))
        plaintext = AESGCM(key).decrypt(nonce, body, header + eph_pub)
    except Exception as exc:  # InvalidTag, a low-order point, ...
        raise LogError("record does not open") from exc
    return Opened(head.key_id, head.seq, plaintext)


def record_hash(record: bytes) -> bytes:
    """What the next record names as its `prev`: SHA-256 of the sealed bytes.

    Over the sealed record rather than the plaintext, so the backend can check
    the chain without trusting anything it decrypted.
    """
    return hashlib.sha256(record).digest()


def key_statement_bytes(log_key_id: int, public_key: bytes, issued_at: int,
                        not_after: int, sig_key_id: int) -> bytes:
    """What the issuer key signs to vouch for a log key. Fixed layout."""
    if len(public_key) != 32:
        raise LogError("a log key is 32 bytes")
    return (KEY_CONTEXT + KEY_MAGIC + bytes([KEY_VERSION])
            + struct.pack(">I", log_key_id) + public_key
            + struct.pack(">III", issued_at, not_after, sig_key_id))


def upload_digest(records: list[bytes]) -> bytes:
    """SHA-256 over the records as sent, each length-prefixed."""
    h = hashlib.sha256()
    for record in records:
        h.update(struct.pack(">I", len(record)))
        h.update(record)
    return h.digest()


def upload_signed_bytes(challenge: bytes, records: list[bytes]) -> bytes:
    """What the device signs for an upload: context, challenge, digest."""
    return UPLOAD_CONTEXT + challenge + upload_digest(records)


def keys_signed_bytes(challenge: bytes) -> bytes:
    """What the device signs at `/keys/`, when it says "keys-context"."""
    return KEYS_CONTEXT + challenge


def ack_signed_bytes(device_id: bytes, through_seq: int, digest: bytes,
                     issued_at: int, sig_key_id: int) -> bytes:
    """What the server signs to acknowledge an upload. Fixed layout.

    `digest` is `upload_digest` of the records as the phone sent them, so the
    acknowledgement is of exactly that upload; `through_seq` is the number up
    to which the server holds them.
    """
    if len(device_id) != 16:
        raise LogError("a device id is 16 bytes")
    if len(digest) != 32:
        raise LogError("an upload digest is 32 bytes")
    if not 0 <= through_seq < 2 ** 63:
        raise LogError("through_seq is out of range")
    return (ACK_CONTEXT + ACK_MAGIC + bytes([ACK_VERSION]) + device_id
            + struct.pack(">Q", through_seq) + digest
            + struct.pack(">II", issued_at, sig_key_id))


def time_signed_bytes(device_id: bytes, nonce: bytes, issued_at: int,
                      sig_key_id: int) -> bytes:
    """What the server signs to tell a phone its time at a sync. Fixed
    layout: context, magic, version, the device id, the phone's nonce for
    this sync, issued_at, sig_key_id."""
    if len(device_id) != 16:
        raise LogError("a device id is 16 bytes")
    if len(nonce) != TIME_NONCE_BYTES:
        raise LogError("a sync nonce is %d bytes" % TIME_NONCE_BYTES)
    if not 0 <= issued_at <= 0xFFFFFFFF or not 0 <= sig_key_id <= 0xFFFFFFFF:
        raise LogError("issued_at or sig_key_id is out of range")
    return (TIME_CONTEXT + TIME_MAGIC + bytes([TIME_VERSION]) + device_id
            + nonce + struct.pack(">II", issued_at, sig_key_id))


def generate_key() -> X25519PrivateKey:
    return X25519PrivateKey.generate()
