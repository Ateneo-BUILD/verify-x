"""Cuckoo filter of revoked credential IDs, shipped inside each key bundle.

An offline device cannot call OCSP or fetch a CRL, so revocation has to travel
with the keys. A probabilistic filter makes that cheap: 100k revocations is
about 256 KB, which is nothing to sync, versus 1.6 MB for the raw UUID list.

**A filter hit is advisory, never a rejection.** False positives are inherent to
the construction, so a hit means "confirm online before accepting" and nothing
stronger. False *negatives* are impossible, which is the direction that matters
-- a revoked credential is never silently accepted as clean, it is only
possibly-flagged late, bounded by the epoch length.

16-bit fingerprints with 4-slot buckets give a measured false-positive rate near
0.01% (2*b/2^f). 8-bit fingerprints would halve the size but push the rate to
~3%, which at field volumes means a spurious "check online" every thirty-odd
scans -- not dangerous, but corrosive to trust in the prompt.

Size runs 2.1-4.2 bytes per entry. The XOR alt-index trick requires a
power-of-two bucket count, so capacity rounds up to the next power of two and
the realised load factor lands anywhere in 0.47-0.94. Measured: 20k revocations
occupy 64 KB (3.3 B/entry, load 0.61); 100k occupy 256 KB. Budget for the
worst case, not the average.

The layout is byte-exact and mirrored by ``RevocationFilter.swift``.
"""

from __future__ import annotations

import hashlib
import random
import struct

MAGIC = b"CL03RF"
VERSION = 1
SLOTS_PER_BUCKET = 4
MAX_KICKS = 500
HEADER_LEN = 14
#: The largest log2 bucket count a filter may claim: 2**24 buckets is a 128 MiB
#: filter, far past anything a bundle carries. Checked before the shift, and
#: the smallest is 1 (two buckets, what `CuckooFilter` itself requires), so
#: Swift's fixed-width arithmetic and Python's unbounded ints refuse the same
#: bytes.
MAX_LOG2_BUCKETS = 24

_FP_SALT = b"cl03-cuckoo-fp\x00"
_IDX_SALT = b"cl03-cuckoo-idx\x00"
_ALT_SALT = b"cl03-cuckoo-alt\x00"


class FilterFull(RuntimeError):
    """Insertion failed after MAX_KICKS evictions. Rebuild with more buckets."""


def _fingerprint(item: bytes) -> int:
    fp = int.from_bytes(hashlib.sha256(_FP_SALT + item).digest()[:2], "big")
    return fp or 1  # 0 marks an empty slot


def _index(item: bytes, num_buckets: int) -> int:
    return int.from_bytes(
        hashlib.sha256(_IDX_SALT + item).digest()[:4], "big") % num_buckets


def _alt_index(index: int, fp: int, num_buckets: int) -> int:
    # num_buckets is a power of two, so the modulo is a mask and the XOR is an
    # involution -- alt(alt(i)) == i, which is what makes lookup work from
    # either bucket.
    shift = int.from_bytes(
        hashlib.sha256(_ALT_SALT + struct.pack(">H", fp)).digest()[:4], "big")
    return (index ^ shift) % num_buckets


class CuckooFilter:
    def __init__(self, num_buckets: int, seed: int = 0):
        if num_buckets & (num_buckets - 1) or num_buckets < 2:
            raise ValueError("num_buckets must be a power of two >= 2")
        self.num_buckets = num_buckets
        self.buckets = [[0] * SLOTS_PER_BUCKET for _ in range(num_buckets)]
        self.count = 0
        self._rng = random.Random(seed)

    @classmethod
    def for_capacity(cls, capacity: int, load_factor: float = 0.94,
                     seed: int = 0) -> "CuckooFilter":
        needed = max(2, int(capacity / load_factor / SLOTS_PER_BUCKET) + 1)
        num_buckets = 1 << max(1, (needed - 1).bit_length())
        return cls(num_buckets, seed)

    # -- changing it ------------------------------------------------------

    def add(self, item: bytes) -> None:
        fp = _fingerprint(item)
        i1 = _index(item, self.num_buckets)
        i2 = _alt_index(i1, fp, self.num_buckets)
        for i in (i1, i2):
            if self._insert_into(i, fp):
                return
        i = self._rng.choice((i1, i2))
        for _ in range(MAX_KICKS):
            slot = self._rng.randrange(SLOTS_PER_BUCKET)
            fp, self.buckets[i][slot] = self.buckets[i][slot], fp
            i = _alt_index(i, fp, self.num_buckets)
            if self._insert_into(i, fp):
                return
        raise FilterFull("filter is full; rebuild with a larger capacity")

    def _insert_into(self, index: int, fp: int) -> bool:
        bucket = self.buckets[index]
        for slot in range(SLOTS_PER_BUCKET):
            if bucket[slot] == 0:
                bucket[slot] = fp
                self.count += 1
                return True
        return False

    def remove(self, item: bytes) -> bool:
        fp = _fingerprint(item)
        i1 = _index(item, self.num_buckets)
        for i in (i1, _alt_index(i1, fp, self.num_buckets)):
            bucket = self.buckets[i]
            for slot in range(SLOTS_PER_BUCKET):
                if bucket[slot] == fp:
                    bucket[slot] = 0
                    self.count -= 1
                    return True
        return False

    # -- query ------------------------------------------------------------

    def __contains__(self, item: bytes) -> bool:
        fp = _fingerprint(item)
        i1 = _index(item, self.num_buckets)
        if fp in self.buckets[i1]:
            return True
        return fp in self.buckets[_alt_index(i1, fp, self.num_buckets)]

    def __len__(self) -> int:
        return self.count

    # -- serialisation ----------------------------------------------------

    def to_bytes(self) -> bytes:
        out = bytearray(MAGIC)
        out.append(VERSION)
        out.append(self.num_buckets.bit_length() - 1)  # log2
        out += struct.pack(">H", 0)  # reserved
        out += struct.pack(">I", self.count)
        for bucket in self.buckets:
            for fp in bucket:
                out += struct.pack(">H", fp)
        return bytes(out)

    @classmethod
    def from_bytes(cls, data: bytes) -> "CuckooFilter":
        if len(data) < HEADER_LEN or data[:len(MAGIC)] != MAGIC:
            raise ValueError("not a revocation filter")
        if data[6] != VERSION:
            raise ValueError("unsupported filter version %d" % data[6])
        if not 1 <= data[7] <= MAX_LOG2_BUCKETS:
            raise ValueError("filter size out of range: log2 buckets %d"
                             % data[7])
        num_buckets = 1 << data[7]
        count = struct.unpack_from(">I", data, 10)[0]
        expected = HEADER_LEN + num_buckets * SLOTS_PER_BUCKET * 2
        if len(data) != expected:
            raise ValueError("filter length mismatch: %d != %d"
                             % (len(data), expected))
        f = cls(num_buckets)
        offset = HEADER_LEN
        for b in range(num_buckets):
            for slot in range(SLOTS_PER_BUCKET):
                f.buckets[b][slot] = struct.unpack_from(">H", data, offset)[0]
                offset += 2
        f.count = count
        return f


def build(credential_ids, seed: int = 0) -> CuckooFilter:
    """Build a filter over an iterable of 16-byte credential IDs.

    Deterministic: the same set gives the same bytes whatever order it came in,
    which is what lets a signer cache a feed by its content.

    It cannot be made to fail. An id the filter already matches is skipped,
    since lookups for it succeed either way, so repeated fingerprints cannot
    pile up in one bucket pair; and a filter that still fills is rebuilt with
    twice the buckets. Without both, nine crafted ids sharing a fingerprint
    and a bucket would make every later feed and bundle unbuildable.
    """
    ids = sorted(set(credential_ids))
    capacity = max(len(ids), 1)
    while True:
        f = CuckooFilter.for_capacity(capacity, seed=seed)
        try:
            for cid in ids:
                if cid not in f:
                    f.add(cid)
            return f
        except FilterFull:
            capacity *= 2
