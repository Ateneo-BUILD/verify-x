"""The revocation feed: a signed cuckoo filter a device fetches beside its
bundle.

The reference for its signed bytes and for the rules a client applies
(`verify_feed`): verify's signer and its key-file path build feeds with
`feed_signed_bytes`, and `Crypto/RevocationFeed.swift` must reach the same
answer, with the same reason, on every feed in `vectors/vectors.json`.

    "OfflineVerifier/v1/revocation" 0x00 | "CL03RL" | version 1
    | issued_at 4 | not_after 4 | key_id 4 | filterLen 4 | filter (CL03RF)

The filter is the same CL03RF a bundle carries.
"""

from __future__ import annotations

import base64
import binascii
import struct

from . import keystore, revocation

FEED_CONTEXT = b"OfflineVerifier/v1/revocation\x00"
FEED_MAGIC = b"CL03RL"
FEED_VERSION = 1

# Refusals, the same strings the app's RevocationFeed gives.
MALFORMED = "malformed"
UNSUPPORTED_VERSION = "unsupported_version"
UNKNOWN_KEY = "unknown_key"
BAD_SIGNATURE = "bad_signature"
STALE = "stale"

_U32 = 2 ** 32


class FeedRefused(Exception):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__("%s%s" % (reason, ": " + detail if detail else ""))
        self.reason = reason


def feed_signed_bytes(issued_at: int, not_after: int, key_id: int,
                      filter_blob: bytes) -> bytes:
    """What a feed's signature covers. Fixed layout, big-endian, no JSON."""
    return (FEED_CONTEXT + FEED_MAGIC + bytes([FEED_VERSION])
            + struct.pack(">IIII", issued_at, not_after, key_id,
                          len(filter_blob))
            + filter_blob)


def _u32(feed: dict, name: str) -> int:
    value = feed.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < _U32:
        raise FeedRefused(MALFORMED, "missing a timestamp or key id")
    return value


def _b64(feed: dict, name: str) -> bytes:
    value = feed.get(name)
    if not isinstance(value, str):
        raise FeedRefused(MALFORMED, name)
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise FeedRefused(MALFORMED, name) from None


def verify_feed(feed: dict, *, keys: dict, now: int) -> revocation.CuckooFilter:
    """The filter a feed carries, or ``FeedRefused``.

    ``keys`` maps a key id to the DER SPKI of a key the device trusts for
    feeds: those its bundle lists with the infrastructure EKU
    (``TrustContext.listed_signer``), or a pinned raw key before it holds a
    judged bundle. The rules, in order: the envelope's form, its version, a
    known key, the signature over `feed_signed_bytes`, ``now`` no later than
    ``not_after`` (what bounds replay), and a filter that parses -- one
    that does not is never "nothing revoked".
    """
    if not isinstance(feed, dict) or feed.get("format") != "CL03RL":
        raise FeedRefused(MALFORMED, "not an CL03RL feed")
    version = feed.get("version")
    # An integer: a phone refuses 1.0, so this does too.
    if (isinstance(version, bool) or not isinstance(version, int)
            or version != FEED_VERSION):
        raise FeedRefused(UNSUPPORTED_VERSION, repr(version))
    issued_at = _u32(feed, "issued_at")
    not_after = _u32(feed, "not_after")
    key_id = _u32(feed, "key_id")
    blob = _b64(feed, "filter")
    sig = _b64(feed, "sig")
    spki = keys.get(key_id)
    if spki is None:
        raise FeedRefused(UNKNOWN_KEY, "key %d" % key_id)
    if not keystore.verify(spki, feed_signed_bytes(issued_at, not_after,
                                                   key_id, blob), sig):
        raise FeedRefused(BAD_SIGNATURE)
    if now > not_after:
        raise FeedRefused(STALE, "expired at %d" % not_after)
    try:
        return revocation.CuckooFilter.from_bytes(blob)
    except ValueError as exc:
        raise FeedRefused(MALFORMED, "CL03RF payload: %s" % exc) from None


def keys_for(context) -> dict:
    """The feed keys an accepted bundle's context trusts: its listed entries
    with the infrastructure EKU (a raw key counts)."""
    from . import chain
    return {e.key_id: e.spki for e in context.entries.values()
            if chain.INFRASTRUCTURE in e.classes}
