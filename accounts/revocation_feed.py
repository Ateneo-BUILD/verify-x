"""The signed revocation feed a configured device fetches from this system.

verify is the authoritative record of every credential it has minted, so it is
also the authoritative answer to "has this one been withdrawn". A device is
given this endpoint's URL when it is configured, and polls it; nothing here
knows or needs to know which devices exist.

Three decisions worth keeping.

**It is signed, and that is not optional.** The filter itself is not secret --
it is a list of opaque 16-bit fingerprints -- so serving it publicly costs
nothing. But an UNSIGNED revocation list is strippable: anyone between the
device and this server could replace it with an empty one and turn every
revoked credential back into a valid one. It is signed with the same issuer
key that signs credentials, so a device needs no new trust material: it
already carries that public key, or it could not verify a credential either.

**It carries its own expiry.** A signature alone does not stop yesterday's
feed being replayed to hide today's revocation, so `not_after` is inside the
signed bytes and a device must refuse a feed past it. That bounds how long a
suppressed revocation can be hidden to the freshness window rather than
forever.

**The signature covers a fixed binary layout, not the JSON.** JSON is the
transport envelope around base64; reproducing canonical JSON byte for byte
across Python and Swift is a well-known source of silent mismatches, so the
layout is what is signed, as it is for the key bundle.

**Every worker sees a revocation at its next request.** Each gunicorn process
keeps its own copy of the feed, keyed by the revocation *generation*, a
one-row counter every revocation bumps (`RevocationState`). Reading it is one
indexed row, so an unauthenticated poll never scans the revoked set, yet a
revocation made in one worker is not served stale by the others for the rest
of the rebuild interval.
"""

from __future__ import annotations

import base64
import struct
import threading
import time

from django.conf import settings
from django.db import transaction
from django.db.models import F

from ovcrypto import feed, revocation

from accounts import credential_keys
from accounts.models import IssuedCredential, RevocationState, RevokedCredentialId


#: Domain separation. A revocation feed must never verify as a credential or
#: as a key bundle, and vice versa; the sibling project uses
#: "OfflineVerifier/v1/sig" and ".../bundle" for exactly this reason. The
#: layout is ovcrypto's reference (`ovcrypto.feed`).
SIG_CONTEXT = feed.FEED_CONTEXT

MAGIC = feed.FEED_MAGIC
VERSION = feed.FEED_VERSION

_lock = threading.Lock()
_cached = None
_cached_at = 0.0
_cached_key = None


def generation() -> int:
    """How many times the revoked set has changed. One row, by primary key."""
    value = (RevocationState.objects.filter(pk=1)
             .values_list("generation", flat=True).first())
    return value or 0


def bump():
    """Record that the revoked set changed. Call inside the change's transaction."""
    if not RevocationState.objects.filter(pk=1).update(
            generation=F("generation") + 1):
        RevocationState.objects.get_or_create(pk=1, defaults={"generation": 1})


#: What the signature covers. Fixed layout, big-endian, no JSON.
signed_bytes = feed.feed_signed_bytes


def revoked_ids() -> list:
    """Every revoked credential id, as 16-byte values, sorted and unique.

    Issued credentials that were revoked, and ids revoked without ever having
    been issued here -- forgeries made with a trusted key.
    """
    issued = (IssuedCredential.objects.filter(revoked_at__isnull=False)
              .values_list("credential_id", flat=True).iterator())
    forged = (RevokedCredentialId.objects
              .values_list("credential_id", flat=True).iterator())
    return sorted({item.bytes for item in issued} | {item.bytes for item in forged})


def build_filter() -> bytes:
    """A cuckoo filter over every revoked credential id.

    The same CL03RF format devices already understand -- it is what rides in
    their key bundle -- so a device needs no second parser. The same set gives
    the same bytes, whatever order the database returns it in.
    """
    return revocation.build(revoked_ids()).to_bytes()


def build_feed(now: int = None) -> dict:
    """The signed envelope, as the endpoint returns it."""
    now = int(now if now is not None else time.time())
    not_after = now + settings.CREDENTIAL_REVOCATION_TTL_SECONDS
    blob = build_filter()
    signer = credential_keys.signer()
    signature = signer.sign(
        signed_bytes(now, not_after, signer.key_id, blob))
    return {
        "format": MAGIC.decode(),
        "version": VERSION,
        "issued_at": now,
        "not_after": not_after,
        "key_id": signer.key_id,
        "filter": base64.b64encode(blob).decode(),
        "sig": base64.b64encode(signature).decode(),
    }


def current_feed(force: bool = False) -> dict:
    """Cached per process by (generation, key). Rebuilding scans the set.

    A new revocation changes the generation, so it is served at the next
    request in every worker. Otherwise the copy is kept for the rebuild
    interval: staleness is harmless in the direction that matters, and what
    the interval must stay well under is the freshness window, or a device
    would reject what it is served.
    """
    global _cached, _cached_at, _cached_key

    if credential_keys.signer_mode():
        key = (generation(), "signer", settings.SIGNER_SOCKET)
    else:
        key = (generation(), settings.CREDENTIAL_ISSUER_KEY_ID,
               settings.CREDENTIAL_ISSUER_KEY_PATH)
    with _lock:
        interval = settings.CREDENTIAL_REVOCATION_REBUILD_SECONDS
        if (not force and _cached and _cached_key == key
                and (time.time() - _cached_at) < interval):
            return _cached
        try:
            feed = (_signer_feed() if credential_keys.signer_mode()
                    else build_feed())
        except Exception:
            # A copy with an hour left is still a feed phones accept; serving
            # it beats a 503 while the signer is restarting.
            if _cached and _cached["not_after"] - time.time() > HELD_MIN_SECONDS:
                return _cached
            raise
        _cached, _cached_at, _cached_key = feed, time.time(), key
        return _cached


#: How long a held feed must still be good for to be served when it cannot be
#: rebuilt.
HELD_MIN_SECONDS = 3600


def _signer_feed() -> dict:
    """The signer's feed: it builds the filter from the set sent here first."""
    from accounts import signer_client

    signer_client.ensure_revocations()
    return signer_client.feed()


def invalidate():
    """Drop this process's copy, so its next poll rebuilds the feed."""
    global _cached_at
    with _lock:
        _cached_at = 0.0


def revoke(credential, *, actor=None, reason=""):
    """Withdraw one credential. Idempotent; the first revocation stands."""
    from django.utils import timezone

    if credential.revoked_at is None:
        with transaction.atomic():
            credential.revoked_at = timezone.now()
            credential.revoked_by = actor
            credential.revoked_reason = (reason or "")[:200]
            credential.save(update_fields=["revoked_at", "revoked_by",
                                           "revoked_reason"])
            bump()
        invalidate()
    return credential


def add_forged(credential_ids, *, actor=None, reason="") -> int:
    """Revoke ids that were never issued here. Returns how many were new.

    For a forgery made with a trusted key: phones must flag it although no
    `IssuedCredential` row exists. Only ever adds.
    """
    added = 0
    with transaction.atomic():
        for cid in credential_ids:
            _, created = RevokedCredentialId.objects.get_or_create(
                credential_id=cid,
                defaults={"reason": (reason or "")[:200], "added_by": actor})
            added += int(created)
        if added:
            bump()
    if added:
        invalidate()
    return added
