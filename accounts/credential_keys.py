"""The keys a credential is signed and encrypted with, and when they roll.

Two different kinds of key, with opposite custody, which is the whole reason
OfflineVerifier splits them and why this module keeps them apart:

* the ISSUER key signs. Its private half never leaves this deployment, and a
  phone holds only the public half -- so draining a phone yields no forgery
  capability. Held as a PEM outside the application directory.
* the EPOCH keys encrypt. Their private halves must reach every phone, so
  they cannot be secret from the fleet; what protects them here is wrapping
  at rest. They roll on a fixed schedule, and a credential is bound to the
  epoch it was minted in.

Both are shared with the sibling OfflineVerifier deployment rather than chosen
here -- see the note in settings.py for what breaks otherwise.
"""

from __future__ import annotations

import base64
import functools
import logging
from datetime import datetime, timedelta, timezone as dt_timezone

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from ovcrypto import issuer as issuer_mod
from ovcrypto import keystore

from accounts.credentials import CredentialError, PemSigningBackend
from accounts.models import CredentialEpochKey, IssuedCredential, SiteSettings

logger = logging.getLogger(__name__)


TIER_PUBLIC = CredentialEpochKey.Tier.PUBLIC
TIER_RESTRICTED = CredentialEpochKey.Tier.RESTRICTED


# ---------------------------------------------------------------------------
# The epoch schedule
# ---------------------------------------------------------------------------

def epoch_at(when: int) -> int:
    """Which epoch a unix timestamp falls in."""
    return max(0, (when - settings.CREDENTIAL_GENESIS)
               // settings.CREDENTIAL_EPOCH_SECONDS)


def epoch_start(epoch: int) -> int:
    return settings.CREDENTIAL_GENESIS + epoch * settings.CREDENTIAL_EPOCH_SECONDS


def epoch_end(epoch: int) -> int:
    return epoch_start(epoch + 1)


def readable_until(epoch: int) -> int:
    """The earliest phones stop carrying this epoch's key.

    An epoch key outlives its ISSUING window by the overlap, because devices
    must still be able to open what was minted under it. A credential valid for
    longer than that moves the row's `not_after` on (`keep_readable_until`).
    Past `not_after` a phone reports `device_stale` -- which is a statement
    about the device, and must never be shown as the document being expired or
    invalid.
    """
    return (epoch_end(epoch)
            + settings.CREDENTIAL_OVERLAP_EPOCHS
            * settings.CREDENTIAL_EPOCH_SECONDS)


def current_epoch(when=None) -> int:
    return epoch_at(int((when or timezone.now()).timestamp()))


# ---------------------------------------------------------------------------
# Key material
# ---------------------------------------------------------------------------

@functools.lru_cache(maxsize=1)
def _wrapper():
    raw = settings.CREDENTIAL_EPOCH_WRAP_KEY
    if not raw:
        raise CredentialError(
            "CREDENTIAL_EPOCH_WRAP_KEY is not set. Without it stored epoch "
            "keys cannot be unwrapped, and generating a new one would orphan "
            "every epoch key already stored.")
    return keystore.FileKeyWrapper(parse_wrap_key(raw))


def parse_wrap_key(raw: str) -> bytes:
    """A wrap key's 32 bytes, from 64 hex characters or base64.

    Hex or base64. OfflineVerifier also accepts raw bytes, because it reads
    a file; this is an environment variable, and arbitrary key bytes do not
    survive being text. Accepting both encodings means one value can be
    pasted into either deployment without checking which it wanted.
    `manage.py rewrap_keys` reads a new key by the same rules.
    """
    raw = raw.strip()
    key = None
    if len(raw) == 64:
        try:
            key = bytes.fromhex(raw)
        except ValueError:
            key = None
    if key is None:
        try:
            decoded = base64.b64decode(raw, validate=True)
            key = decoded if len(decoded) == 32 else None
        except Exception:
            key = None
    if key is None:
        raise CredentialError(
            "CREDENTIAL_EPOCH_WRAP_KEY must be 32 bytes, as 64 hex "
            "characters or base64.")
    return key


def reset_caches():
    """For tests, which override settings between cases."""
    _wrapper.cache_clear()
    signer.cache_clear()
    _readable.clear()


@functools.lru_cache(maxsize=1)
def signer() -> PemSigningBackend:
    """The issuer key. Cached: it is a file read, on the document path."""
    return PemSigningBackend.from_path(settings.CREDENTIAL_ISSUER_KEY_PATH,
                                       settings.CREDENTIAL_ISSUER_KEY_ID)


@transaction.atomic
def epoch_key_row(epoch: int, tier: int, *, accept_loss=False) -> CredentialEpochKey:
    """Fetch or create the stored key pair for one (epoch, tier).

    get_or_create under a transaction rather than check-then-create: two
    verifications crossing an epoch boundary at the same moment would
    otherwise both generate a key pair, and one of them would win -- leaving
    credentials encrypted to a public key no phone will ever be given.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    row = CredentialEpochKey.objects.filter(epoch=epoch, tier=tier).first()
    if row is not None:
        return row

    # A credential minted under this epoch means its keys existed here, and
    # are gone: deleted, or a database put back that never had them. New
    # ones under the same number would fork the epoch -- documents made with
    # the old keys unreadable on every phone that syncs, silently. Refused
    # instead, until the keys are put back, or the operator accepts their
    # loss (manage.py remake_epoch_keys).
    if not accept_loss and IssuedCredential.objects.filter(epoch=epoch).exists():
        logger.error("Keys for epoch %d are missing although credentials were "
                     "minted under it: not making new ones. Put the epoch's "
                     "keys back from a backup (manage.py replace_database)",
                     epoch)
        raise CredentialError(
            "The keys for epoch %d are missing from this database, although "
            "documents were made with them. Making new ones would leave those "
            "documents unreadable, so none are made until the old ones are "
            "put back." % epoch)
    late = int(timezone.now().timestamp()) - epoch_start(epoch)
    if late > LATE_EPOCH_SECONDS and CredentialEpochKey.objects.filter(
            epoch__lt=epoch).exists():
        # Normal on a site nobody used for a while. After a restore it is
        # the only trace: the copy put back may have predated keys that
        # documents were made with. A site's very first keys are late by
        # this measure too, and say nothing about a restore.
        logger.warning("Making keys for epoch %d, %d days after it began. If "
                       "this database was restored from a copy older than "
                       "that, documents made with the keys it had no longer "
                       "open (docs/deploy-aws.md, \"Restoring the database\")",
                       epoch, late // 86400)

    private = X25519PrivateKey.generate()
    raw_private = private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption())
    raw_public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    row, _ = CredentialEpochKey.objects.get_or_create(
        epoch=epoch, tier=tier,
        defaults={
            "public_key": raw_public,
            "wrapped_private_key": _wrapper().wrap(raw_private),
            "not_before": _as_datetime(epoch_start(epoch)),
            "not_after": _as_datetime(readable_until(epoch)),
        })
    return row


def _as_datetime(unix_seconds: int):
    return datetime.fromtimestamp(unix_seconds, dt_timezone.utc)


def issuing_keys(when=None) -> issuer_mod.EpochPublicKeys:
    """The public keys a credential minted now is encrypted to.

    Only the PUBLIC halves are needed to mint. The private halves exist here
    because the fleet has to be given them, not because issuing needs them.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    epoch = current_epoch(when)
    rows = {tier: epoch_key_row(epoch, tier)
            for tier in (TIER_PUBLIC, TIER_RESTRICTED)}
    # Encrypting to a key whose private half this site cannot open would
    # make documents no phone will ever be given the key to: a database
    # brought from elsewhere, under another wrap key.
    for row in rows.values():
        if not readable(row):
            raise CredentialError(
                "The keys for epoch %d cannot be opened with this site's "
                "CREDENTIAL_EPOCH_WRAP_KEY." % epoch)
    return issuer_mod.EpochPublicKeys(
        epoch,
        X25519PublicKey.from_public_bytes(bytes(rows[TIER_PUBLIC].public_key)),
        X25519PublicKey.from_public_bytes(
            bytes(rows[TIER_RESTRICTED].public_key)))


def private_key(row: CredentialEpochKey) -> bytes:
    """The raw X25519 private key for an epoch, for handing to the fleet."""
    return _wrapper().unwrap(bytes(row.wrapped_private_key))


#: A new epoch's keys are made by the first mint or sync in it. Later than
#: this after it began is logged (`epoch_key_row`).
LATE_EPOCH_SECONDS = 7 * 24 * 60 * 60

#: (row id, digest of both halves) -> whether the private half opens and
#: belongs to the public half. Rows are never edited, so an answer holds for
#: the life of the process -- unless a changed database or wrap key changed
#: the bytes, which changes the digest.
_readable = {}


def unwraps_to(public_key: bytes, wrapped: bytes, wrapper=None) -> bool:
    """Whether `wrapped` opens under the wrap key and is the private half of
    `public_key`. Also what `accounts/database_swap.py` checks a database
    brought from elsewhere with."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    try:
        raw = (wrapper or _wrapper()).unwrap(bytes(wrapped))
        derived = X25519PrivateKey.from_private_bytes(raw).public_key()
    except Exception:
        return False
    return derived.public_bytes(serialization.Encoding.Raw,
                                serialization.PublicFormat.Raw) == bytes(public_key)


def readable(row: CredentialEpochKey) -> bool:
    import hashlib

    digest = hashlib.sha256(bytes(row.public_key)
                            + bytes(row.wrapped_private_key)).digest()
    key = (row.pk, digest)
    if key not in _readable:
        _readable[key] = unwraps_to(row.public_key, row.wrapped_private_key)
    return _readable[key]


def unreadable_epoch_keys(now=None) -> list:
    """["epoch 16 public", ...]: the keys phones are still given that this
    site cannot open. Setup says so in red; the device sync answers 503
    rather than failing inside. [] without a wrap key, which `missing()`
    reports instead."""
    if not settings.CREDENTIAL_EPOCH_WRAP_KEY:
        return []
    try:
        _wrapper()
    except CredentialError:
        return []
    from django.db.models import Q

    now = now or timezone.now()
    # The current epoch's whatever its row says: every mint and sync opens it.
    rows = CredentialEpochKey.objects.filter(
        Q(not_after__gte=now) | Q(epoch=current_epoch(now))).order_by("epoch", "tier")
    return ["epoch %d %s" % (row.epoch, row.get_tier_display().lower())
            for row in rows if not readable(row)]


def lost_epoch_keys(now=None) -> list:
    """["epoch 16 public", ...]: the current epoch's keys missing although
    documents were made with them. `epoch_key_row` will not make new ones,
    so nothing is minted or synced until they are put back (a backup, through
    manage.py replace_database) or their loss is accepted (manage.py
    remake_epoch_keys). Setup says so in red."""
    epoch = current_epoch(now)
    have = set(CredentialEpochKey.objects.filter(epoch=epoch)
               .values_list("tier", flat=True))
    missing = [tier for tier in (TIER_PUBLIC, TIER_RESTRICTED) if tier not in have]
    if not missing or not IssuedCredential.objects.filter(epoch=epoch).exists():
        return []
    return ["epoch %d %s" % (epoch, CredentialEpochKey.Tier(tier).label.lower())
            for tier in missing]


def signer_mode() -> bool:
    """True when a credential signer holds the issuer keys: on its app
    socket (`SIGNER_SOCKET`), or dialling out to this site for its jobs
    (`SIGNER_QUEUE_KEY`, `accounts.signer_queue`)."""
    return bool(settings.SIGNER_SOCKET or settings.SIGNER_QUEUE_KEY)


def missing() -> list:
    """The settings minting still needs when an issuer key IS named -- a
    signer or a key file -- and something else is not set; [] otherwise.

    The case it exists for: a site brought up to a signer with an `.env`
    from before the CREDENTIAL_* settings. `configured()` is false and every
    document prints the plain QR, and without this nothing would say why:
    Setup would show the signer Running. Also the statement a key file
    needs after a signer (`left_signer_unconfirmed`)."""
    if not (settings.CREDENTIAL_ISSUER_KEY_PATH or signer_mode()):
        return []
    absent = [name for name in ("CREDENTIAL_EPOCH_WRAP_KEY",)
              if not getattr(settings, name, "")]
    if left_signer_unconfirmed():
        absent.append("CREDENTIAL_FILE_MODE_AFTER_SIGNER")
    return absent


def left_signer_unconfirmed() -> bool:
    """A key file named, no signer, and keys the signer listed still mirrored
    here: verify would sign with the file under CREDENTIAL_ISSUER_KEY_ID
    while its bundles list keys it holds no private half of and leave out
    every withdrawn key's tombstone. Safe only while that key is the one the
    signer signed with (such as a key 1 the signer held), so it takes
    the operator saying so: CREDENTIAL_FILE_MODE_AFTER_SIGNER set to
    that id (signer/deploy/README.md, "Leaving signer mode"). One indexed
    query, in file mode only."""
    if signer_mode() or not settings.CREDENTIAL_ISSUER_KEY_PATH:
        return False
    if str(settings.CREDENTIAL_FILE_MODE_AFTER_SIGNER) == str(
            settings.CREDENTIAL_ISSUER_KEY_ID):
        return False
    from accounts.models import IssuerKey
    return IssuerKey.objects.filter(source=IssuerKey.SOURCE_SIGNER,
                                    is_active=True).exists()


_warned_missing = False


def warn_if_half_configured():
    """Log, once per process, that an issuer key is named but minting is off
    for want of `missing()`. Called where a document gives up its credential."""
    global _warned_missing
    absent = missing()
    if absent and not _warned_missing:
        _warned_missing = True
        logger.error("An issuer key is configured but %s is not set: every "
                     "document prints the plain QR until it is",
                     ", ".join(absent))


def configured() -> bool:
    """Enough to mint. Checked before a document tries and fails.

    Local on purpose: it never asks the signer, because it guards the
    unauthenticated feed and log-key endpoints and log uploads too, and a
    signer that is down must not turn those into 503s before the held copies
    can be served.
    """
    return bool((settings.CREDENTIAL_ISSUER_KEY_PATH or signer_mode())
                and settings.CREDENTIAL_EPOCH_WRAP_KEY
                and not left_signer_unconfirmed())


def validity_ceiling_days() -> int:
    """The longest a credential may be valid here: this site's limit and, with a
    signer, the signer's, which refuses anything longer."""
    ceiling = settings.CREDENTIAL_MAX_VALIDITY_DAYS
    if signer_mode():
        from accounts import signer_client

        try:
            ceiling = min(ceiling,
                          int(signer_client.public().get("credential_max_days", ceiling)))
        except Exception:
            # A signer that does not answer cannot sign either, and minting
            # says so itself. Setup still has to draw its form.
            logger.warning("could not read the signer's credential_max_days",
                           exc_info=True)
    return ceiling


def validity_days() -> int:
    """How long a credential minted now is valid: the site's choice, held inside
    the ceiling. A value stored before a ceiling came down must not turn every
    document into one the signer refuses."""
    return max(1, min(SiteSettings.load().credential_validity_days,
                      validity_ceiling_days()))


def validity_window(issued_at=None):
    """(issued_at, expires_at) for a credential minted now."""
    issued = issued_at or timezone.now()
    return issued, issued + timedelta(days=validity_days())


def keep_readable_until(epoch: int, expires_at) -> None:
    """Keep this epoch's keys on phones until `expires_at`, if that is later.

    A phone that syncs can read a card for as long as the card is valid. So a
    credential outliving the overlap carries its epoch's keys along with it, and
    only that epoch's: at a validity inside the overlap this changes nothing,
    and phones hold exactly what they held. A long validity is the site's
    choice, and what it costs is every phone holding more keys for longer, so a
    phone that is lost or revoked can open more old cards.

    Both tiers, as a filter so a row that is already later is left alone: this
    only ever moves a date on, and a sync reads `not_after` and nothing else.
    """
    CredentialEpochKey.objects.filter(
        epoch=epoch, not_after__lt=expires_at).update(not_after=expires_at)
