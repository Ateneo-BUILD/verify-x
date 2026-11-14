"""CL03 wire format v1 -- pure codec, no cryptography.

This module is the normative definition of the byte layout. ``vectors.json`` is
generated from it and consumed by the Swift tests, so the two implementations
cannot silently drift.

    header (43 B, also the AEAD associated data):
      "CL03" 4 | ver 1 | suite 1 | flags 1 | epoch 4 | ephPub 32

    body:
      pubLen 2 | pubCT pubLen | pubTag 16          AES-256-GCM under K_pub
      resLen 2 | resCT resLen | resTag 16          present iff flags bit1

    public section plaintext:
      claimsLen 2 | claims N | resHash 32 | sigAlg 1 | keyId 4 | sig 64
    restricted section plaintext:
      claims N        (length implied by the ciphertext length)

``resHash`` is what lets one signature serve both tiers: the signature covers a
hash of the restricted section rather than its contents, so a public-tier device
that cannot decrypt that section still verifies the whole credential.
"""

from __future__ import annotations

import datetime as _dt
import struct
import zlib
from dataclasses import dataclass

MAGIC = b"CL03"
VERSION = 1

# suite 0x01: X25519 / HKDF-SHA256 / AES-256-GCM
SUITE_X25519_AESGCM = 0x01

# sigAlg. Both are implemented and both are 64 bytes on the wire. P-256 is the
# default only because PKCS#11 EdDSA support varies by token and firmware, while
# every token does P-256; pick Ed25519 when the token supports CKM_EDDSA.
SIG_ECDSA_P256_SHA256 = 0x01
SIG_ED25519 = 0x02

FLAG_PUBLIC_DEFLATED = 0x01
FLAG_RESTRICTED_PRESENT = 0x02
FLAG_RESTRICTED_DEFLATED = 0x04
#: Bits 3-7 are reserved and must be zero. A parser that let them through
#: would read one credential under two flags bytes.
FLAGS_KNOWN = FLAG_PUBLIC_DEFLATED | FLAG_RESTRICTED_PRESENT | FLAG_RESTRICTED_DEFLATED

HEADER_LEN = 43
EPH_PUB_LEN = 32
TAG_LEN = 16
SIG_LEN = 64
HASH_LEN = 32

SIG_CONTEXT = b"OfflineVerifier/v1/sig\x00"
#: The marker: CL03, the name of this QR code and its validation. The
#: only one an issuer writes or a reader accepts.
QR_PREFIX = "CL03:"
#: Reserved, and read or written by nothing: the designators this format
#: carried before CL03, kept as the alternate code if one is ever
#: needed. Using them is a code change, not a setting.
LEGACY_MAGIC = b"OV"
LEGACY_QR_PREFIX = "OV1:"

# Domain separation between the two AEAD invocations under one ephemeral key.
AAD_PUBLIC = b"\x00"
AAD_RESTRICTED = b"\x01"

_EPOCH_DAY = _dt.date(1970, 1, 1)


class WireError(ValueError):
    """Malformed payload. Always fail closed on this."""


# --------------------------------------------------------------------------
# Claim tags. 0x01-0x3F public tier, 0x40-0x7F restricted tier.
# --------------------------------------------------------------------------

T_CREDENTIAL_ID = 0x01    # 16 B UUID
T_DOC_TYPE = 0x02         # uint8
T_DOC_NUMBER = 0x03       # utf-8
T_DOCUMENT_HASH = 0x04    # 32 B SHA-256 of the document contents
T_ISSUER_ID = 0x05        # utf-8
T_ISSUED_AT = 0x06        # uint32 unix seconds
T_EXPIRES_AT = 0x07       # uint32 unix seconds
T_ISSUER_LOCATION = 0x08  # utf-8
# The human-readable label for what this credential attests. Text, carried
# verbatim, because it is the issuer's word and not something a verifier can
# derive: `doc_type` is an opaque uint8 with no registry behind it, and a phone
# that turned one into a name was guessing. A per-organization category that
# changes without anybody telling a phone can only travel as text.
T_TRANSACTION_TYPE = 0x09  # utf-8
# Who performed it, in full. A staff name, not an identifier: it is already
# printed on the document, so a phone showing what the paper shows discloses
# nothing new. Public tier for the same reason -- withholding it from a device
# that can read the page in its hand would be theatre.
T_OPERATOR = 0x0A          # utf-8
# Attachments every device with the epoch key may read: an attachment list
# (ovcrypto.attachments). Content of any media type, inline or split
# across part symbols beside the credential.
T_PUBLIC_ATTACHMENTS = 0x0B

T_SURNAME = 0x40
T_GIVEN_NAMES = 0x41
T_MIDDLE_NAME = 0x42
T_SUFFIX = 0x43
T_DATE_OF_BIRTH = 0x44    # int32 days since 1970-01-01 (signed: pre-1970 valid)
T_SEX = 0x45              # ISO 5218: 0 unknown, 1 male, 2 female, 9 n/a
T_PCN = 0x46              # 8 B packed BCD of the 16-digit card number
T_DIGITAL_ID = 0x47       # utf-8, e.g. CWD0842
T_PORTRAIT_HASH = 0x48    # 32 B SHA-256 of the printed portrait
T_PLACE_OF_BIRTH = 0x49   # utf-8
# Every field the issuing organization chose to DISPLAY, as ordered
# (label, value) pairs -- see encode_fields.
#
# A list rather than a tag per field, because the labels are editable per
# organization and the set is not fixed: no registry of tags can cover
# "whatever this deployment decided to print". The order is the document's, so
# a verifier can render the same rows in the same sequence as the paper.
T_FIELDS = 0x4A
# Attachments only an entitled device reads: the same list as
# T_PUBLIC_ATTACHMENTS, in the restricted section. No id in both.
T_ATTACHMENTS = 0x4B

TAG_NAMES = {
    T_CREDENTIAL_ID: "credential_id", T_DOC_TYPE: "doc_type",
    T_DOC_NUMBER: "doc_number", T_DOCUMENT_HASH: "document_hash",
    T_ISSUER_ID: "issuer_id", T_ISSUED_AT: "issued_at",
    T_EXPIRES_AT: "expires_at", T_ISSUER_LOCATION: "issuer_location",
    T_TRANSACTION_TYPE: "transaction_type",
    T_SURNAME: "surname", T_GIVEN_NAMES: "given_names",
    T_MIDDLE_NAME: "middle_name", T_SUFFIX: "suffix",
    T_DATE_OF_BIRTH: "date_of_birth", T_SEX: "sex", T_PCN: "pcn",
    T_DIGITAL_ID: "digital_id", T_PORTRAIT_HASH: "portrait_hash",
    T_PLACE_OF_BIRTH: "place_of_birth", T_FIELDS: "fields",
    T_OPERATOR: "operator",
    T_PUBLIC_ATTACHMENTS: "public_attachments", T_ATTACHMENTS: "attachments",
}

PUBLIC_TAGS = frozenset(t for t in TAG_NAMES if t < 0x40)
RESTRICTED_TAGS = frozenset(t for t in TAG_NAMES if t >= 0x40)

TAG_EXTENDED_LENGTH = 0xFF  # value length follows as 2 BE bytes


# --------------------------------------------------------------------------
# TLV claims
# --------------------------------------------------------------------------

def encode_fields(pairs):
    """(label, value) pairs -> bytes, for T_FIELDS.

        repeat:  u8 labelLen | label utf-8 | u16 valueLen | value utf-8

    u16 on the value because an address runs past 255 bytes; u8 on the label
    because a column heading that long is a bug, not a label. Order is
    preserved exactly -- it is the document's order, and the point is that a
    phone can show the same rows in the same sequence as the paper.

    No deduplication and no sorting. Two rows may legitimately share a label,
    and re-ordering would make the credential disagree with the page it was
    printed beside.
    """
    out = bytearray()
    for label, value in pairs:
        lb = str(label).encode("utf-8")
        vb = str(value).encode("utf-8")
        if len(lb) > 0xFF:
            raise WireError("field label too long: %d bytes" % len(lb))
        if len(vb) > 0xFFFF:
            raise WireError("field value too long: %d bytes" % len(vb))
        out.append(len(lb))
        out += lb
        out += struct.pack(">H", len(vb))
        out += vb
    return bytes(out)


def decode_fields(data):
    """Inverse of encode_fields. Fails closed on anything ragged."""
    out = []
    i, n = 0, len(data)
    while i < n:
        if i + 1 > n - 1 and i + 1 != n:
            raise WireError("truncated field label length")
        label_len = data[i]
        i += 1
        if i + label_len + 2 > n:
            raise WireError("truncated field label")
        label = data[i:i + label_len].decode("utf-8", "replace")
        i += label_len
        (value_len,) = struct.unpack(">H", data[i:i + 2])
        i += 2
        if i + value_len > n:
            raise WireError("truncated field value")
        out.append((label, data[i:i + value_len].decode("utf-8", "replace")))
        i += value_len
    return out


def encode_claims(claims):
    """Serialise claims in ascending tag order.

    Deterministic ordering matters: the signature is computed over these exact
    bytes, so a verifier must be able to reproduce them.
    """
    out = bytearray()
    for tag in sorted(claims):
        if not 0 <= tag <= 0xFE:
            raise WireError("claim tag out of range: %d" % tag)
        value = claims[tag]
        if len(value) > 0xFFFF:
            raise WireError("claim 0x%02x too long: %d" % (tag, len(value)))
        if len(value) < 0xFF:
            out.append(tag)
            out.append(len(value))
        else:
            out.append(TAG_EXTENDED_LENGTH)
            out.append(tag)
            out += struct.pack(">H", len(value))
        out += value
    return bytes(out)


def decode_claims(data):
    """Inverse of encode_claims, and only of it.

    One claim set has one encoding: tags in ascending order, the extended
    form only for a value of 255 bytes or more, and never 0xFF as a tag.
    Anything else is refused, so two byte strings never read as one set of
    claims.
    """
    out = {}
    i, n = 0, len(data)
    previous = -1
    while i < n:
        tag = data[i]
        i += 1
        if tag == TAG_EXTENDED_LENGTH:
            if i + 3 > n:
                raise WireError("truncated extended claim header")
            tag = data[i]
            length = struct.unpack_from(">H", data, i + 1)[0]
            i += 3
            if tag == TAG_EXTENDED_LENGTH:
                raise WireError("claim tag 0xff is reserved")
            if length < 0xFF:
                raise WireError("claim 0x%02x uses the extended form for %d bytes"
                                % (tag, length))
        else:
            if i >= n:
                raise WireError("truncated claim header")
            length = data[i]
            i += 1
            if length == 0xFF:
                raise WireError("claim 0x%02x uses the short form for 255 bytes"
                                % tag)
        if i + length > n:
            raise WireError("truncated claim 0x%02x" % tag)
        if tag in out:
            raise WireError("duplicate claim tag 0x%02x" % tag)
        if tag < previous:
            raise WireError("claim 0x%02x out of order" % tag)
        previous = tag
        out[tag] = data[i:i + length]
        i += length
    return out


# ---- typed accessors -----------------------------------------------------

def u32(value):
    return struct.pack(">I", value)


def read_u32(value):
    if len(value) != 4:
        raise WireError("expected 4-byte integer")
    return struct.unpack(">I", value)[0]


def date_to_days(d):
    return struct.pack(">i", (d - _EPOCH_DAY).days)


def days_to_date(value):
    if len(value) != 4:
        raise WireError("expected 4-byte date")
    try:
        return _EPOCH_DAY + _dt.timedelta(days=struct.unpack(">i", value)[0])
    except OverflowError:
        # Past year 9999, which datetime cannot hold.
        raise WireError("date out of range") from None


def pack_pcn(pcn):
    """16-digit card number -> 8 bytes of packed BCD."""
    digits = "".join(ch for ch in pcn if ch.isdigit())
    if len(digits) != 16:
        raise WireError("PCN must be 16 digits, got %d" % len(digits))
    return bytes(int(digits[i:i + 2], 16) for i in range(0, 16, 2))


def unpack_pcn(value):
    if len(value) != 8:
        raise WireError("expected 8-byte PCN")
    return "".join("%02x" % b for b in value)


# --------------------------------------------------------------------------
# Compression -- applied per section, kept only when it actually helps.
# Much of this payload is hashes and UUIDs, which expand under deflate.
# --------------------------------------------------------------------------

def maybe_deflate(data):
    # raw deflate (wbits=-15): no zlib header, no adler32 -- saves 6 bytes
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    packed = c.compress(data) + c.flush()
    return (packed, True) if len(packed) < len(data) else (data, False)


#: The most a compressed section may inflate to. A zip-bomb guard: 65,535
#: compressed bytes could otherwise become tens of megabytes.
MAX_INFLATED = 1 << 20


def inflate(data):
    """Raw DEFLATE, one complete stream and nothing after it, inflating to
    between 1 byte and MAX_INFLATED.

    Over the cap is an error, not a cut: a silent cut at a claim boundary
    would read as a smaller claim set that still verifies. Nothing, or a
    stream cut short, is an error too, as the app reads it: the issuer
    never compresses a section that compression does not shorten, so
    neither comes from it.
    """
    d = zlib.decompressobj(-15)
    try:
        out = d.decompress(data, MAX_INFLATED + 1)
    except zlib.error as exc:
        raise WireError("inflate failed: %s" % exc) from None
    if len(out) > MAX_INFLATED:
        raise WireError("section inflates past %d bytes" % MAX_INFLATED)
    if not d.eof:
        raise WireError("inflate failed: the stream is cut short")
    if d.unused_data:
        raise WireError("inflate failed: %d bytes after the stream"
                        % len(d.unused_data))
    if not out:
        raise WireError("inflate failed: the section inflates to nothing")
    return out


# --------------------------------------------------------------------------
# Header
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Header:
    version: int
    suite: int
    flags: int
    epoch: int
    eph_pub: bytes

    def pack(self):
        if len(self.eph_pub) != EPH_PUB_LEN:
            raise WireError("ephemeral public key must be 32 bytes")
        return (MAGIC + bytes([self.version, self.suite, self.flags])
                + struct.pack(">I", self.epoch) + self.eph_pub)

    @property
    def has_restricted(self):
        return bool(self.flags & FLAG_RESTRICTED_PRESENT)

    @classmethod
    def unpack(cls, data):
        if len(data) < HEADER_LEN:
            raise WireError("payload shorter than header")
        if data[:len(MAGIC)] != MAGIC:
            raise WireError("bad magic -- not a CL03 payload")
        version, suite, flags = data[4], data[5], data[6]
        if version != VERSION:
            raise WireError("unsupported version %d" % version)
        if suite != SUITE_X25519_AESGCM:
            raise WireError("unsupported suite %d" % suite)
        if flags & ~FLAGS_KNOWN:
            raise WireError("reserved flag bits set: 0x%02x" % flags)
        if flags & FLAG_RESTRICTED_DEFLATED and not flags & FLAG_RESTRICTED_PRESENT:
            raise WireError("a restricted section compressed but not present")
        epoch = struct.unpack_from(">I", data, 7)[0]
        return cls(version, suite, flags, epoch, data[11:HEADER_LEN])


# --------------------------------------------------------------------------
# Signed bytes
#
# Covers epoch, suite and flags -- so a credential cannot be relabelled into
# another key window -- but deliberately NOT ephPub, which keeps signing
# separable from encryption so an offline printer HSM could sign without
# encrypting. ephPub is still integrity-protected as AEAD associated data.
# --------------------------------------------------------------------------

def signed_bytes(version, suite, flags, epoch, claims, res_hash, sig_alg, key_id):
    if len(res_hash) != HASH_LEN:
        raise WireError("restricted-section hash must be 32 bytes")
    return (SIG_CONTEXT + bytes([version, suite, flags])
            + struct.pack(">I", epoch) + struct.pack(">H", len(claims))
            + claims + res_hash + bytes([sig_alg]) + struct.pack(">I", key_id))


# --------------------------------------------------------------------------
# Section framing
# --------------------------------------------------------------------------

@dataclass
class PublicSection:
    """Plaintext of the public section."""
    claims: bytes
    res_hash: bytes
    sig_alg: int
    key_id: int
    sig: bytes

    def pack(self):
        if len(self.res_hash) != HASH_LEN:
            raise WireError("restricted-section hash must be 32 bytes")
        if len(self.sig) != SIG_LEN:
            raise WireError("signature must be 64 bytes")
        return (struct.pack(">H", len(self.claims)) + self.claims
                + self.res_hash + bytes([self.sig_alg])
                + struct.pack(">I", self.key_id) + self.sig)

    @classmethod
    def unpack(cls, data):
        if len(data) < 2 + HASH_LEN + 1 + 4 + SIG_LEN:
            raise WireError("public section too short")
        claims_len = struct.unpack_from(">H", data, 0)[0]
        if 2 + claims_len + HASH_LEN + 1 + 4 + SIG_LEN != len(data):
            raise WireError("public section length mismatch")
        i = 2 + claims_len
        return cls(
            claims=data[2:i],
            res_hash=data[i:i + HASH_LEN],
            sig_alg=data[i + HASH_LEN],
            key_id=struct.unpack_from(">I", data, i + HASH_LEN + 1)[0],
            sig=data[i + HASH_LEN + 5:],
        )


@dataclass
class Payload:
    """A parsed but still-encrypted payload."""
    header: Header
    public_ct: bytes
    public_tag: bytes
    restricted_ct: bytes = None
    restricted_tag: bytes = None

    def pack(self):
        out = bytearray(self.header.pack())
        out += struct.pack(">H", len(self.public_ct)) + self.public_ct + self.public_tag
        if self.header.has_restricted:
            if self.restricted_ct is None or self.restricted_tag is None:
                raise WireError("restricted flag set but section missing")
            out += struct.pack(">H", len(self.restricted_ct))
            out += self.restricted_ct + self.restricted_tag
        return bytes(out)

    @classmethod
    def unpack(cls, data):
        header = Header.unpack(data)
        i = HEADER_LEN
        if i + 2 > len(data):
            raise WireError("truncated public section length")
        pub_len = struct.unpack_from(">H", data, i)[0]
        i += 2
        if i + pub_len + TAG_LEN > len(data):
            raise WireError("truncated public section")
        pub_ct = data[i:i + pub_len]
        pub_tag = data[i + pub_len:i + pub_len + TAG_LEN]
        i += pub_len + TAG_LEN

        res_ct = res_tag = None
        if header.has_restricted:
            if i + 2 > len(data):
                raise WireError("truncated restricted section length")
            res_len = struct.unpack_from(">H", data, i)[0]
            i += 2
            if i + res_len + TAG_LEN > len(data):
                raise WireError("truncated restricted section")
            res_ct = data[i:i + res_len]
            res_tag = data[i + res_len:i + res_len + TAG_LEN]
            i += res_len + TAG_LEN
        if i != len(data):
            raise WireError("%d trailing bytes after payload" % (len(data) - i))
        return cls(header, pub_ct, pub_tag, res_ct, res_tag)
