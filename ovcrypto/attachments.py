"""Attachments: content of any media type, signed with a credential.

An attachment is described by an entry in a claim -- ``public_attachments``
(0x0B) or ``attachments`` (0x4B) -- and travels either inline, inside that
entry, or sealed and split across part symbols printed beside the credential:

    CL03P1:<base45 of: credential_id 16 | id 1 | index 1 | count 1 | chunk>

The entry carries the content key and a SHA-256 of the sealed bytes, so the
credential's signature covers every part, and a part is ciphertext to anyone
who cannot read the list that describes it. The digest, not the GCM tag, is
what binds: every reader of the list holds the key.

Issuing: ``prepare`` turns attachments into the two claim values and the part
symbols. Reading: ``Collector`` takes a verified credential's entries and the
part symbols in any order, and says what became of each attachment.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import base45, qrsize, wire

CARRIAGE_INLINE = 0x01
CARRIAGE_PARTS = 0x02

ENCODING_NONE = 0x00
ENCODING_DEFLATE = 0x01

#: The part symbol's marker. Starts the string, as the portrait's does.
PART_PREFIX = "CL03P1:"
#: credential_id 16 | id 1 | index 1 | count 1
PART_HEADER_LEN = 19

KEY_LEN = 32
#: Fixed: each key seals one content only.
NONCE = bytes(12)
AAD_CONTEXT = b"CL03AT"

MAX_ID = 255
MAX_PARTS = 255
MAX_MEDIA_TYPE = 127
MAX_INLINE = 0xFFFF
#: The most split content may be, inflated: the cap on any section.
MAX_SIZE = wire.MAX_INFLATED

#: What every part symbol is printed at unless the issuer says otherwise.
DEFAULT_PART_STAMP_MM = 40.0

_TOKEN = r"[a-z0-9][a-z0-9!#$&^_.+-]*"
_MEDIA_TYPE = re.compile(r"\A%s/%s\Z" % (_TOKEN, _TOKEN))

# Results, per attachment.
OPENED = "opened"
INCOMPLETE = "incomplete"
CONTRADICTED = "contradicted"
MALFORMED = "malformed"


class AttachmentError(wire.WireError):
    """An attachment list, a part symbol or a sealed content that breaks the
    format. In a list, it makes the credential malformed."""


class PrepareError(ValueError):
    """What an issuer asked for cannot be carried."""


# --------------------------------------------------------------------------
# The list
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Entry:
    """One entry of an attachment list, as signed."""
    id: int
    carriage: int
    media_type: str
    label: str
    #: Inline: the content. Parts: None.
    content: bytes = None
    #: Parts only, below.
    encoding: int = ENCODING_NONE
    size: int = 0
    count: int = 0
    digest: bytes = None
    key: bytes = None

    @property
    def inline(self) -> bool:
        return self.carriage == CARRIAGE_INLINE

    def pack(self) -> bytes:
        check_media_type(self.media_type)
        if not 1 <= self.id <= MAX_ID:
            raise AttachmentError("attachment id %d out of range" % self.id)
        mt = self.media_type.encode("ascii")
        label = self.label.encode("utf-8")
        if len(label) > 0xFF:
            raise AttachmentError("attachment label too long: %d bytes" % len(label))
        out = bytearray([self.id, self.carriage, len(mt)]) + mt
        out += bytes([len(label)]) + label
        if self.carriage == CARRIAGE_INLINE:
            if not 1 <= len(self.content) <= MAX_INLINE:
                raise AttachmentError("inline content of %d bytes" % len(self.content))
            out += struct.pack(">H", len(self.content)) + self.content
        elif self.carriage == CARRIAGE_PARTS:
            if self.encoding not in (ENCODING_NONE, ENCODING_DEFLATE):
                raise AttachmentError("unknown encoding %d" % self.encoding)
            if not 1 <= self.size <= MAX_SIZE:
                raise AttachmentError("size %d out of range" % self.size)
            if not 1 <= self.count <= MAX_PARTS:
                raise AttachmentError("count %d out of range" % self.count)
            if len(self.digest) != wire.HASH_LEN or len(self.key) != KEY_LEN:
                raise AttachmentError("digest and key are 32 bytes each")
            out += bytes([self.encoding]) + struct.pack(">I", self.size)
            out += bytes([self.count]) + self.digest + self.key
        else:
            raise AttachmentError("unknown carriage %d" % self.carriage)
        return bytes(out)


def check_media_type(media_type: str) -> None:
    if (not isinstance(media_type, str)
            or not 1 <= len(media_type) <= MAX_MEDIA_TYPE
            or not _MEDIA_TYPE.match(media_type)):
        raise AttachmentError("media type %r is not type/subtype" % (media_type,))


def encode_list(entries) -> bytes:
    """Entries -> a claim value. Ids must already be ascending."""
    entries = list(entries)
    if not entries:
        raise AttachmentError("an attachment list has at least one entry")
    ids = [e.id for e in entries]
    if ids != sorted(set(ids)):
        raise AttachmentError("attachment ids must be strictly ascending")
    return b"".join(e.pack() for e in entries)


def decode_list(data: bytes) -> list:
    """A claim value -> entries. The inverse of ``encode_list``, and only of
    it: anything else is an AttachmentError."""
    data = bytes(data)
    entries = []
    i, n = 0, len(data)
    previous = 0

    def take(count, what):
        nonlocal i
        if i + count > n:
            raise AttachmentError("truncated attachment %s" % what)
        chunk = data[i:i + count]
        i += count
        return chunk

    if n == 0:
        raise AttachmentError("an attachment list has at least one entry")
    while i < n:
        ident, carriage, type_len = take(3, "entry header")
        if ident == 0 or ident <= previous:
            raise AttachmentError("attachment id %d out of order" % ident)
        previous = ident
        if not 1 <= type_len <= MAX_MEDIA_TYPE:
            raise AttachmentError("media type length %d" % type_len)
        raw_type = take(type_len, "media type")
        try:
            media_type = raw_type.decode("ascii")
        except UnicodeDecodeError:
            raise AttachmentError("media type is not ASCII") from None
        check_media_type(media_type)
        (label_len,) = take(1, "label length")
        try:
            label = take(label_len, "label").decode("utf-8")
        except UnicodeDecodeError:
            raise AttachmentError("label is not UTF-8") from None
        if carriage == CARRIAGE_INLINE:
            (size,) = struct.unpack(">H", take(2, "size"))
            if size == 0:
                raise AttachmentError("inline content is empty")
            entries.append(Entry(ident, carriage, media_type, label,
                                 content=take(size, "content")))
        elif carriage == CARRIAGE_PARTS:
            encoding = take(1, "encoding")[0]
            if encoding not in (ENCODING_NONE, ENCODING_DEFLATE):
                raise AttachmentError("unknown encoding %d" % encoding)
            (size,) = struct.unpack(">I", take(4, "size"))
            if not 1 <= size <= MAX_SIZE:
                raise AttachmentError("size %d out of range" % size)
            count = take(1, "count")[0]
            if count == 0:
                raise AttachmentError("count is zero")
            digest = take(wire.HASH_LEN, "digest")
            key = take(KEY_LEN, "key")
            entries.append(Entry(ident, carriage, media_type, label,
                                 encoding=encoding, size=size, count=count,
                                 digest=digest, key=key))
        else:
            raise AttachmentError("unknown carriage %d" % carriage)
    return entries


def entries_of(public_claims: dict, restricted_claims: dict = None) -> list:
    """Every entry this reader can see, public list first. Raises
    AttachmentError for a malformed list, including an id in both."""
    entries = []
    if wire.T_PUBLIC_ATTACHMENTS in public_claims:
        entries += decode_list(public_claims[wire.T_PUBLIC_ATTACHMENTS])
    if restricted_claims and wire.T_ATTACHMENTS in restricted_claims:
        restricted = decode_list(restricted_claims[wire.T_ATTACHMENTS])
        shared = {e.id for e in entries} & {e.id for e in restricted}
        if shared:
            raise AttachmentError("attachment id %d is in both lists" % min(shared))
        entries += restricted
    return entries


# --------------------------------------------------------------------------
# Sealing
# --------------------------------------------------------------------------

def aad(credential_id: bytes, ident: int) -> bytes:
    if len(credential_id) != 16:
        raise AttachmentError("credential id must be 16 bytes")
    return AAD_CONTEXT + credential_id + bytes([ident])


def seal(content: bytes, *, credential_id: bytes, ident: int, key: bytes):
    """-> (encoding, sealed). Compressed only when that shortens it."""
    if len(key) != KEY_LEN:
        raise AttachmentError("key must be 32 bytes")
    packed, deflated = wire.maybe_deflate(content)
    sealed = AESGCM(key).encrypt(NONCE, packed, aad(credential_id, ident))
    return (ENCODING_DEFLATE if deflated else ENCODING_NONE), sealed


def unseal(entry: Entry, sealed: bytes, *, credential_id: bytes) -> bytes:
    """Sealed bytes whose digest already matched -> the content.

    Raises AttachmentError: after a matching digest, any failure here is the
    issuer's."""
    try:
        plain = AESGCM(entry.key).decrypt(NONCE, sealed, aad(credential_id, entry.id))
    except InvalidTag:
        raise AttachmentError("attachment %d does not open" % entry.id) from None
    content = wire.inflate(plain) if entry.encoding == ENCODING_DEFLATE else plain
    if len(content) != entry.size:
        raise AttachmentError("attachment %d is %d bytes, not %d"
                              % (entry.id, len(content), entry.size))
    return content


# --------------------------------------------------------------------------
# Part symbols
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Part:
    credential_id: bytes
    id: int
    index: int
    count: int
    chunk: bytes

    def to_qr_string(self) -> str:
        if not (1 <= self.id <= MAX_ID and 1 <= self.count <= MAX_PARTS
                and 1 <= self.index <= self.count and self.chunk
                and len(self.credential_id) == 16):
            raise AttachmentError("part %r out of range" % ((self.id, self.index,
                                                             self.count),))
        return PART_PREFIX + base45.encode(
            self.credential_id + bytes([self.id, self.index, self.count]) + self.chunk)


def looks_like_part(text: str) -> bool:
    return text.strip(_QR_WHITESPACE).startswith(PART_PREFIX)


#: What a reader trims from either end.
_QR_WHITESPACE = " \t\n\r\x0b\x0c"


def parse_part(text: str) -> Part:
    """A scanned part symbol -> Part. Raises AttachmentError."""
    trimmed = text.strip(_QR_WHITESPACE)
    if not trimmed.startswith(PART_PREFIX):
        raise AttachmentError("not a part symbol")
    try:
        raw = base45.decode(trimmed[len(PART_PREFIX):])
    except ValueError:
        raise AttachmentError("part symbol is not Base45") from None
    if len(raw) < PART_HEADER_LEN + 1:
        raise AttachmentError("part symbol too short")
    ident, index, count = raw[16], raw[17], raw[18]
    if ident == 0 or count == 0 or not 1 <= index <= count:
        raise AttachmentError("part %d of %d for attachment %d" % (index, count, ident))
    return Part(raw[:16], ident, index, count, raw[PART_HEADER_LEN:])


def base45_len(n: int) -> int:
    return 3 * (n // 2) + 2 * (n % 2)


def chunk_capacity(max_chars: int) -> int:
    """The most chunk bytes a part symbol of ``max_chars`` characters holds."""
    budget = max_chars - len(PART_PREFIX)
    n = (budget // 3) * 2 + (1 if budget % 3 == 2 else 0)
    return n - PART_HEADER_LEN


def part_capacity(stamp_mm: float = DEFAULT_PART_STAMP_MM, ec_level: str = "Q") -> int:
    """Characters a part symbol may have and still print at 0.4 mm a module
    on a ``stamp_mm`` square: the capacity of the largest version that fits."""
    best = 0
    for version, capacity in enumerate(qrsize.CAPACITY_ALNUM[ec_level], start=1):
        if qrsize.module_mm(version, stamp_mm) >= qrsize.MIN_MODULE_MM:
            best = capacity
    if chunk_capacity(best) < 1:
        raise PrepareError("a %.1f mm stamp holds no part symbol" % stamp_mm)
    return best


def split(sealed: bytes, *, credential_id: bytes, ident: int,
          max_chars: int) -> list:
    """Sealed bytes -> part symbols, cut evenly, each within ``max_chars``."""
    per = chunk_capacity(max_chars)
    if per < 1:
        raise PrepareError("%d characters hold no chunk" % max_chars)
    count = -(-len(sealed) // per)
    if count > MAX_PARTS:
        raise PrepareError("attachment %d needs %d part symbols; at most %d"
                           % (ident, count, MAX_PARTS))
    size = -(-len(sealed) // count)
    chunks = [sealed[i:i + size] for i in range(0, len(sealed), size)]
    return [Part(credential_id, ident, i, len(chunks), chunk).to_qr_string()
            for i, chunk in enumerate(chunks, start=1)]


# --------------------------------------------------------------------------
# Issuing
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Attachment:
    """What an issuer asks to attach."""
    label: str
    media_type: str
    content: bytes
    #: In the restricted list, readable only where personal data is.
    restricted: bool = False
    #: In the credential itself rather than in part symbols.
    inline: bool = False
    #: Assigned in order when None.
    id: int = None


@dataclass
class Prepared:
    #: The claim values, or None for an empty list.
    public_value: bytes = None
    restricted_value: bytes = None
    #: Part symbols by attachment id, in index order.
    parts: dict = field(default_factory=dict)

    @property
    def part_count(self) -> int:
        """Part symbols to print, over every attachment."""
        return sum(len(parts) for parts in self.parts.values())

    def claims(self, public_claims: dict, restricted_claims: dict):
        """The claim dicts with the lists added: (public, restricted)."""
        public = dict(public_claims)
        restricted = dict(restricted_claims or {})
        if self.public_value is not None:
            public[wire.T_PUBLIC_ATTACHMENTS] = self.public_value
        if self.restricted_value is not None:
            restricted[wire.T_ATTACHMENTS] = self.restricted_value
        return public, restricted


def part_budget(max_qr_codes, *, portrait: bool):
    """How many part symbols a document may print under a cap on its QR codes:
    the credential is one code, its portrait another. None for no cap. A cap
    that leaves no room for the credential and its portrait is refused,
    since such a document could not be issued at all."""
    if max_qr_codes is None:
        return None
    budget = int(max_qr_codes) - 1 - (1 if portrait else 0)
    if budget < 0:
        raise PrepareError("a cap of %d QR codes leaves no room for the credential%s"
                           % (max_qr_codes, " and its portrait" if portrait else ""))
    return budget


def prepare(attachments, *, credential_id: bytes, max_part_chars: int = None,
            max_part_symbols: int = None, key_source=os.urandom) -> Prepared:
    """Attachments -> the two lists and the part symbols.

    ``max_part_symbols`` caps the part symbols over every attachment
    (``part_budget``): what needs more is refused, never cut short, because a
    phone cannot tell a cap from a code that was not printed. Inline
    attachments print nothing and are not counted.

    ``key_source(32)`` draws each content key; injectable for vectors only.
    """
    attachments = list(attachments)
    if max_part_chars is None:
        max_part_chars = part_capacity()
    next_id, used = 1, set()
    for a in attachments:
        if a.id is not None:
            used.add(a.id)
    prepared = Prepared()
    lists = {False: [], True: []}
    for a in attachments:
        ident = a.id
        if ident is None:
            while next_id in used:
                next_id += 1
            ident = next_id
            used.add(ident)
        elif not 1 <= ident <= MAX_ID:
            raise PrepareError("attachment id %d out of range" % ident)
        if ident > MAX_ID:
            raise PrepareError("more than %d attachments" % MAX_ID)
        check_media_type(a.media_type)
        content = bytes(a.content)
        if not content:
            raise PrepareError("attachment %d is empty" % ident)
        if a.media_type.startswith("text/") or a.media_type == "application/json":
            try:
                content.decode("utf-8")
            except UnicodeDecodeError:
                raise PrepareError("attachment %d is text but not UTF-8" % ident) from None
        if a.inline:
            entry = Entry(ident, CARRIAGE_INLINE, a.media_type, a.label, content=content)
        else:
            if len(content) > MAX_SIZE:
                raise PrepareError("attachment %d is past %d bytes" % (ident, MAX_SIZE))
            key = key_source(KEY_LEN)
            encoding, sealed = seal(content, credential_id=credential_id,
                                    ident=ident, key=key)
            parts = split(sealed, credential_id=credential_id, ident=ident,
                          max_chars=max_part_chars)
            entry = Entry(ident, CARRIAGE_PARTS, a.media_type, a.label,
                          encoding=encoding, size=len(content), count=len(parts),
                          digest=hashlib.sha256(sealed).digest(), key=key)
            prepared.parts[ident] = parts
        lists[a.restricted].append(entry)
    if max_part_symbols is not None and prepared.part_count > max_part_symbols:
        raise PrepareError(
            "the attachments need %d part symbols; this issuer prints at most %d. "
            "Carry them inline, or attach less" % (prepared.part_count, max_part_symbols))
    for restricted, entries in lists.items():
        if entries:
            value = encode_list(sorted(entries, key=lambda e: e.id))
            if len(value) > 0xFFFF:
                raise PrepareError("the %s attachment list is %d bytes"
                                   % ("restricted" if restricted else "public", len(value)))
            if restricted:
                prepared.restricted_value = value
            else:
                prepared.public_value = value
    return prepared


# --------------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------------

@dataclass
class Outcome:
    """What became of one attachment."""
    entry: Entry
    status: str
    content: bytes = None
    held: int = 0
    detail: str = ""


class Collector:
    """A verified credential's attachments, and the parts scanned for them.

    Built from a ``verifier.Result`` that is VALID. ``take`` routes one part
    symbol and returns why it was or was not used.
    """

    # What ``take`` says about a part.
    TAKEN = "taken"
    ALREADY_HELD = "already_held"
    ANOTHER_DOCUMENT = "another_document"
    NOT_FOR_THIS_DEVICE = "not_for_this_device"
    UNREADABLE = "unreadable"
    NOT_SPLIT = "not_split"

    def __init__(self, credential_id: bytes, entries):
        self.credential_id = credential_id
        self.entries = {e.id: e for e in entries}
        self._held = {e.id: {} for e in entries if not e.inline}
        self._done = {}
        for e in entries:
            if e.inline:
                self._done[e.id] = Outcome(e, OPENED, content=e.content)

    @classmethod
    def for_result(cls, result) -> "Collector":
        from .verifier import Verdict  # the reader's own module; no cycle at import
        if result.verdict is not Verdict.VALID:
            return cls(result.public_claims.get(wire.T_CREDENTIAL_ID, bytes(16)), [])
        return cls(result.public_claims[wire.T_CREDENTIAL_ID], result.attachments)

    def take(self, text: str) -> str:
        try:
            part = parse_part(text)
        except AttachmentError:
            return self.UNREADABLE
        if part.credential_id != self.credential_id:
            return self.ANOTHER_DOCUMENT
        entry = self.entries.get(part.id)
        if entry is None:
            return self.NOT_FOR_THIS_DEVICE
        if entry.inline:
            return self.NOT_SPLIT
        if part.count != entry.count:
            return self.UNREADABLE
        outcome = self._done.get(entry.id)
        if outcome is not None and outcome.status in (OPENED, MALFORMED):
            return self.ALREADY_HELD
        held = self._held[entry.id]
        if part.index in held:
            return self.ALREADY_HELD
        held[part.index] = part.chunk
        self._done.pop(entry.id, None)
        if len(held) == entry.count:
            self._finish(entry)
        return self.TAKEN

    def _finish(self, entry: Entry) -> None:
        held = self._held[entry.id]
        sealed = b"".join(held[i] for i in range(1, entry.count + 1))
        if hashlib.sha256(sealed).digest() != entry.digest:
            # Dropped, so the parts can be scanned again.
            self._held[entry.id] = {}
            self._done[entry.id] = Outcome(
                entry, CONTRADICTED,
                detail="the parts are not the ones the credential was signed with")
            return
        try:
            content = unseal(entry, sealed, credential_id=self.credential_id)
        except wire.WireError as exc:
            self._done[entry.id] = Outcome(entry, MALFORMED, detail=str(exc))
            return
        self._done[entry.id] = Outcome(entry, OPENED, content=content)

    def outcomes(self) -> list:
        """Every attachment, in id order."""
        out = []
        for ident in sorted(self.entries):
            done = self._done.get(ident)
            if done is not None:
                out.append(done)
            else:
                out.append(Outcome(self.entries[ident], INCOMPLETE,
                                   held=len(self._held[ident])))
        return out

    def outcome(self, ident: int) -> Outcome:
        return next(o for o in self.outcomes() if o.entry.id == ident)
