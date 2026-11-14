"""Holders: somebody who verified THEMSELVES in idmanager, registering here.

Everything else in this app is an operator verifying somebody at a counter.
This is the other direction: a person runs eVerify and liveness on their own
phone, in idmanager, and comes here to register that phone and be issued a
credential for themselves. Three parties, and each does one thing:

* **idmanager vouches.** It signs a short-lived assertion -- "this person
  passed eVerify and liveness at this moment" -- with a P-256 key whose public
  half is pinned in `HOLDER_ASSERTION_KEYS`. That pin is the whole trust
  decision, and with it empty the endpoint does not exist.
* **The phone's Secure Enclave binds.** The assertion names the SHA-256 of
  the phone's Enclave public key (`cnf.spki_s256`), and the phone separately
  proves it holds the private half by signing one of our challenges. So an
  assertion lifted off one handset registers nothing on another, and nobody
  can register a key they cannot use.
* **This app issues**, exactly as for any other verification: the same
  `ovcrypto` mint, the same issuer key, an `IssuedCredential` row, the same
  revocation feed. idmanager never holds a signing key of the fleet's.

**What a holder is NOT is the load-bearing part.** The login path here was
built on "verify must not auto-provision" -- an unknown ID never reaches
eVerify, and SSO never creates an account. Registering holders does not undo
that, because a holder is not an operator:

| | |
|---|---|
| cannot sign in | `User.is_holder_only` is skipped by `_find_user()` and `registered_operator()` until an organization makes them a member |
| public tier only | the field default for `device_restricted_tier` is ON (for operators), so a holder row is created with it OFF -- and every phone registered here is capped by `Device.public_tier_only` regardless, because the restricted tier is other people's details |
| belongs to no organization | the `Transaction` has no organization, so no tenant's log, export or statistics ever lists a stranger who registered themselves |

A public-tier key opens what a credential's QR already shows a plain camera:
the transaction UUID sits in the clear in front of `CL03:`, and
`/api/validate/` answers for it without a sign-in -- with the outcome only,
never the name or ID numbers. So the worst a stolen
idmanager key buys is a phone that can confirm documents are genuine -- and
credentials naming a self-verification, which say so on their face.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import re
import time
import uuid
from datetime import datetime, timedelta, timezone as dt_timezone
from types import SimpleNamespace

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from accounts import (credential_keys, credentials, everify_fields, minting,
                      user_records)
from accounts.models import (Device, HolderAssertion, IssuedCredential,
                             Transaction, User)


logger = logging.getLogger(__name__)


class HolderError(Exception):
    """Refused. The message is shown to the caller, so keep it plain."""


#: One refusal for every way an assertion can be unacceptable -- forged,
#: expired, replayed, for another audience, bound to another key, describing
#: a check that is too old. Telling them apart tells somebody probing the
#: endpoint which of their attempts came closest. The specific reason is
#: logged, without the person's details, for whoever runs this deployment.
REFUSED = "That registration is not valid."

#: The JOSE header this endpoint accepts, and nothing else. `typ` is domain
#: separation: an idmanager key that also signed some other kind of token
#: could not have one of those replayed here as a registration.
ALG = "ES256"
TYP = "idmanager-holder+jwt"

#: Honest clock drift between idmanager's host and this one.
SKEW_SECONDS = 60

#: An assertion is a few hundred bytes. Anything near this is not one, and
#: decoding megabytes to find that out is work an unauthenticated caller
#: should not be able to ask for.
MAX_ASSERTION_CHARS = 16 * 1024

#: idmanager attests a biometric-backed check and nothing weaker. An
#: assertion that does not say both were done is refused, so a future
#: idmanager path that skipped liveness could not quietly reach this one.
REQUIRED_AMR = frozenset({"everify", "liveness"})

#: What a holder's credential carries, in the document's order (the order
#: `everify_fields` defines). Deliberately short: a holder credential is shown
#: to strangers, so it carries enough to compare against the person and the
#: card -- not their address, marital status or blood type. idmanager sends
#: only these, and anything else in an assertion is ignored rather than
#: minted.
CREDENTIAL_FIELDS = ("first_name", "middle_name", "last_name", "reference",
                     "code", "gender", "birth_date")

#: What the credential and the transaction call this kind of verification.
TRANSACTION_TYPE = "Self-verification"

#: A portrait is tens of kilobytes from eVerify. The cap is generous and
#: exists only so a hostile body cannot make the renderer chew on megabytes.
MAX_FACE_BYTES = 512 * 1024

#: What a holder phone's Enclave key signs at each holder endpoint once it
#: says "holder-context": that endpoint's context, then the decoded challenge
#: (carried here from `/keys/`). Signed bare, a challenge is also what
#: `/keys/` takes from a phone that does not say "keys-context", and what the
#: other holder endpoint takes, so one bare signature that reached the wrong
#: host could be spent at any of them; behind its context it is good at one
#: endpoint only. What a device key signs for this site is the bare challenge
#: (older apps), `devicelog.KEYS_CONTEXT` or `devicelog.UPLOAD_CONTEXT` + its
#: bytes, or one of these two + the challenge. Each context ends in NUL, so
#: none is a prefix of another.
REGISTER_CONTEXT = b"OfflineVerifier/v1/holder-register\x00"
PASSES_CONTEXT = b"OfflineVerifier/v1/holder-passes\x00"

#: The answer to a bare signature while `HOLDER_REQUIRE_CONTEXT` is on.
TOO_OLD = "This app is too old for this site. Update it, then try again."


def says_context(data):
    """Whether a holder request says it signs behind its endpoint's context.
    Capabilities that are not a list say nothing, as at `/keys/`."""
    capabilities = data.get("capabilities")
    return isinstance(capabilities, list) and "holder-context" in capabilities


_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")
_KID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def pinned_keys() -> dict:
    """`kid -> P-256 public key` from HOLDER_ASSERTION_KEYS.

    An entry that does not parse is dropped with a warning rather than
    failing the whole list: one bad paste during a rotation must not take the
    working key down with it. Nothing that is not a P-256 key is accepted --
    ES256 is the only algorithm, so a key of any other type could only ever
    be the shape of an algorithm-confusion attempt.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    keys = {}
    for entry in (settings.HOLDER_ASSERTION_KEYS or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        kid, _, der_b64 = entry.partition(":")
        kid = kid.strip()
        try:
            if not _KID.match(kid):
                raise ValueError("bad key id")
            key = serialization.load_der_public_key(
                base64.b64decode(der_b64.strip(), validate=True))
            if not (isinstance(key, ec.EllipticCurvePublicKey)
                    and key.curve.name == "secp256r1"):
                raise ValueError("not a P-256 key")
        except Exception as exc:
            logger.warning("HOLDER_ASSERTION_KEYS: ignoring entry %r: %s",
                           kid[:64], exc)
            continue
        keys[kid] = key
    return keys


def enabled() -> bool:
    """Both halves of the trust decision are present."""
    return bool(settings.HOLDER_ASSERTION_ISSUER and pinned_keys())


# ---------------------------------------------------------------------------
# The assertion
# ---------------------------------------------------------------------------

def spki_thumbprint(public_key_der: bytes) -> str:
    """base64url(SHA-256(DER SPKI)), unpadded -- what `cnf.spki_s256` holds."""
    digest = hashlib.sha256(bytes(public_key_der)).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _b64url(part: str) -> bytes:
    # urlsafe_b64decode quietly skips characters outside its alphabet, so the
    # alphabet is checked first: a token that is not exactly base64url is not
    # one this endpoint signed off on.
    if not _B64URL.match(part):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _refuse(reason: str):
    logger.info("holder assertion refused: %s", reason)
    return HolderError(REFUSED)


def _int_claim(payload, name):
    value = payload.get(name)
    # bool is an int in Python; `"exp": true` must not read as 1970 + 1s.
    if isinstance(value, bool) or not isinstance(value, int):
        raise _refuse("%s is not an integer" % name)
    return value


def _text(value, limit):
    if not isinstance(value, str):
        return ""
    return value.strip()[:limit]


def verify_assertion(token, *, audience: str, device_public_key: bytes,
                     now: int = None) -> dict:
    """Check an idmanager assertion and return what it vouches for.

    Raises HolderError(REFUSED) for every failure. Does NOT spend the
    assertion -- `register()` does, inside the transaction that acts on it,
    so a registration that fails afterwards has not burned the person's
    check for nothing.

    `audience` is this deployment's own address as the phone reaches it
    (`devices.base_url()`), so an assertion idmanager minted for another
    verify deployment is refused here.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from ovcrypto import keystore

    if not enabled():
        raise _refuse("holder registration is not configured")
    if not isinstance(token, str) or not token or len(token) > MAX_ASSERTION_CHARS:
        raise _refuse("no assertion, or one of an implausible size")
    parts = token.split(".")
    if len(parts) != 3:
        raise _refuse("not a compact JWS")
    header_b64, payload_b64, sig_b64 = parts

    try:
        header = json.loads(_b64url(header_b64))
        signature = _b64url(sig_b64)
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise _refuse("header or signature does not decode") from None
    if not isinstance(header, dict):
        raise _refuse("header is not an object")
    if header.get("alg") != ALG or header.get("typ") != TYP:
        raise _refuse("wrong alg or typ")
    kid = header.get("kid")
    key = pinned_keys().get(kid) if isinstance(kid, str) else None
    if key is None:
        raise _refuse("unknown key id")

    # JWS ES256 is the raw 64-byte r||s, not DER. Low-s is NOT enforced:
    # ordinary JWS signers do not normalise, and nothing here is keyed on the
    # signature -- `jti` is what makes an assertion single-use.
    if len(signature) != 64:
        raise _refuse("signature is not 64 bytes")
    try:
        key.verify(keystore.raw_to_der_p256(signature),
                   ("%s.%s" % (header_b64, payload_b64)).encode("ascii"),
                   ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        raise _refuse("signature does not verify") from None

    # Only now is anything inside trusted enough to read.
    try:
        payload = json.loads(_b64url(payload_b64))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise _refuse("payload does not decode") from None
    if not isinstance(payload, dict):
        raise _refuse("payload is not an object")

    if payload.get("iss") != settings.HOLDER_ASSERTION_ISSUER:
        raise _refuse("wrong issuer")
    if payload.get("aud") != audience:
        raise _refuse("minted for another audience")

    now = int(now if now is not None else timezone.now().timestamp())
    iat = _int_claim(payload, "iat")
    exp = _int_claim(payload, "exp")
    verified_at = _int_claim(payload, "verified_at")
    if exp <= now:
        raise _refuse("expired")
    if iat > now + SKEW_SECONDS:
        raise _refuse("issued in the future")
    if not 0 < exp - iat <= settings.HOLDER_ASSERTION_MAX_LIFETIME_SECONDS:
        raise _refuse("claims an implausible lifetime")
    if verified_at > now + SKEW_SECONDS:
        raise _refuse("check dated in the future")
    if now - verified_at > settings.HOLDER_VERIFICATION_MAX_AGE_SECONDS:
        raise _refuse("the check it describes is too old")

    amr = payload.get("amr")
    if not isinstance(amr, list) or not REQUIRED_AMR <= set(
            item for item in amr if isinstance(item, str)):
        raise _refuse("does not attest eVerify and liveness")

    jti, subject = payload.get("jti"), payload.get("sub")
    if not isinstance(jti, str) or not 0 < len(jti) <= 64:
        raise _refuse("no usable jti")
    if not isinstance(subject, str) or not 0 < len(subject) <= 255:
        raise _refuse("no usable subject")

    cnf = payload.get("cnf")
    bound = cnf.get("spki_s256") if isinstance(cnf, dict) else None
    if not isinstance(bound, str) or not hmac.compare_digest(
            bound, spki_thumbprint(device_public_key)):
        raise _refuse("bound to a different device key")

    person = payload.get("person")
    if not isinstance(person, dict):
        raise _refuse("names nobody")
    pcn = _text(person.get("reference"), 32).replace("-", "").replace(" ", "")
    if not (len(pcn) == 16 and pcn.isdigit()):
        raise _refuse("no usable card number")
    cleaned = {field: _text(person.get(field), credentials.MAX_TEXT)
               for field in CREDENTIAL_FIELDS}
    cleaned["reference"] = pcn
    cleaned["code"] = cleaned["code"].upper()
    if not (cleaned["first_name"] and cleaned["last_name"]):
        raise _refuse("names nobody")

    face_sha256 = payload.get("face_sha256")
    if face_sha256 is not None and not (
            isinstance(face_sha256, str) and _HEX64.match(face_sha256)):
        raise _refuse("face_sha256 is not a SHA-256")

    return {
        "jti": jti,
        "sub": subject,
        "kid": kid,
        "iss": payload["iss"],
        "verified_at": datetime.fromtimestamp(verified_at, dt_timezone.utc),
        "expires_at": datetime.fromtimestamp(exp, dt_timezone.utc),
        "person": cleaned,
        "face_sha256": face_sha256,
    }


def face_matches(claims: dict, face: bytes) -> bool:
    """Is this the portrait idmanager vouched for?

    The face travels beside the assertion rather than inside it -- tens of
    kilobytes have no business in a token -- so the assertion carries its
    hash and an unhashed face is simply not used. A face nobody signed for
    must never reach a credential, where `portrait_hash` would bind it.
    """
    expected = claims.get("face_sha256")
    if not expected or not face or len(face) > MAX_FACE_BYTES:
        return False
    return hmac.compare_digest(hashlib.sha256(face).hexdigest(), expected)


# ---------------------------------------------------------------------------
# Registering
# ---------------------------------------------------------------------------

@transaction.atomic
def register(claims: dict, device_public_key: bytes, *, label: str = ""):
    """`(user, device, created)` for an accepted assertion. Spends it.

    The person is found by card number -- the same key every other path
    here resolves people by. A row this app has never seen becomes a HOLDER;
    an existing row is used as it is.

    An operator's row is never rewritten from here. It is an organization's
    record of its own member, and idmanager's word is enough to register a
    phone, not to edit what an organization keeps. A holder's own row, which
    nobody else maintains, is kept in step with the check just made.

    The `HolderAssertion` row is written last and its `jti` is unique, so two
    phones racing one assertion cannot both come away registered: the loser's
    whole transaction rolls back on the index. The caller turns that
    IntegrityError into the same refusal as any other.
    """
    if HolderAssertion.objects.filter(jti=claims["jti"]).exists():
        raise _refuse("replayed")

    person = claims["person"]
    names = {
        "given_name": person["first_name"][:255],
        "middle_name": person["middle_name"][:150],
        "last_name": person["last_name"][:150],
    }
    user = User.objects.filter(
        national_id_card_number=person["reference"]).first()
    if user is None:
        user = User.objects.create(
            national_id_card_number=person["reference"],
            digital_national_id=person["code"][:20],
            registered_via=User.REGISTERED_VIA_IDMANAGER,
            # The field default is ON, for operators. A holder is a member of
            # the public, and the restricted tier is everybody else's details.
            device_restricted_tier=False,
            **names)
    elif user.is_holder_only:
        changed = [field for field, value in names.items()
                   if value and getattr(user, field) != value]
        for field in changed:
            setattr(user, field, names[field])
        if person["code"] and user.digital_national_id != person["code"][:20]:
            user.digital_national_id = person["code"][:20]
            changed.append("digital_national_id")
        if changed:
            user.save(update_fields=changed)

    device = Device.objects.filter(public_key_der=device_public_key).first()
    if device is not None:
        # The same phone coming back to be re-verified: no second row. Any
        # other owner, or a revoked phone, is refused -- reviving a revoked
        # device on idmanager's word would be an un-revoke by another name.
        if device.owner_id != user.pk or not device.is_active:
            # The same refusal as any other: which of the two it was is the
            # log's to say, not an answer to whoever asked.
            logger.info("holder registration refused: the key belongs to "
                        "device %s, %s", device.device_id,
                        "another owner's" if device.owner_id != user.pk
                        else "revoked")
            raise HolderError(REFUSED)
        created = False
    else:
        device = Device.objects.create(
            # Nobody on this side typed a name, so the phone's own label is
            # the only one there is.
            label=(label or "").strip()[:120] or "Phone registered from idmanager",
            public_key_der=device_public_key,
            owner=user,
            public_tier_only=True,
            lease_expires_at=timezone.now() + timedelta(
                seconds=settings.DEVICE_LEASE_SECONDS))
        created = True

    HolderAssertion.objects.create(
        jti=claims["jti"], issuer=claims["iss"], key_id=claims["kid"],
        subject=claims["sub"], user=user, device=device,
        verified_at=claims["verified_at"], expires_at=claims["expires_at"])
    return user, device, created


# ---------------------------------------------------------------------------
# The holder's credential
# ---------------------------------------------------------------------------

def credential_rows(person: dict):
    """The rows a holder credential carries, shaped like the operator path's.

    Same `field`/`key`/`value` rows `_prepare_data_for_frontend` builds, with
    the built-in labels and the birth date in the document's MM/DD/YYYY, so a
    verifier renders a holder's credential exactly as it renders anybody's.
    """
    rows = []
    for field in CREDENTIAL_FIELDS:
        value = person.get(field) or ""
        if not value:
            continue
        if field == "birth_date":
            try:
                value = datetime.strptime(value, "%Y-%m-%d").strftime("%m/%d/%Y")
            except ValueError:
                pass
        rows.append({"field": field,
                     "key": everify_fields.DEFAULT_NAMES.get(field) or field,
                     "value": value})
    return rows


def mint_for_holder(claims: dict, *, face: bytes = None):
    """Log the self-verification and mint its credential, or None.

    NEVER raises, the rule `_mint_credential()` follows: a phone registered
    without a credential is a smaller failure than a registration lost to an
    unreadable key file, and the phone can come back for one.

    The `Transaction` is what makes the UUID at the front of the QR resolve
    at `/api/validate/`, as every document's does. It has no organization and
    no operator -- the truth about a self-verification -- and its type and
    location say where it came from.
    """
    if not credential_keys.configured():
        credential_keys.warn_if_half_configured()
        return None
    person = claims["person"]
    issuer_name = settings.HOLDER_CREDENTIAL_ISSUER_NAME
    try:
        rows = credential_rows(person)
        columns = {column: (person.get(field) or "")
                   for field, column in everify_fields.TRANSACTION_COLUMNS.items()}
        txn = Transaction.objects.create(
            organization=None,
            operator=None,
            operator_location=issuer_name[:255],
            authentication_result="success",
            transaction_type=TRANSACTION_TYPE,
            logged_fields={row["field"]: row["value"] for row in rows},
            # idmanager's signed assertion is this path's upstream answer,
            # so the person it names is a verified one -- and their own
            # self-verification belongs in their User Records.
            subject_key=user_records.subject_key(person.get("reference"),
                                                 person.get("code")),
            **columns)

        issued, expires = credential_keys.validity_window(
            txn.verification_timestamp)
        portrait = None
        if face:
            data_uri = "data:image/jpeg;base64," + base64.b64encode(face).decode()
            portrait, _px = credentials.render_portrait_fitted(data_uri)
        # Recorded before it is signed, as every credential is: one that
        # exists in the world and not in IssuedCredential cannot be revoked.
        minted = minting.mint_recorded(
            rows,
            transaction=txn,
            organization=None,
            claims_organization=SimpleNamespace(name=issuer_name),
            holder=True,
            # Pseudonymous and stable, so one person has a ceiling of their
            # own beside every holder's: the subject key is already an HMAC.
            holder_id=(txn.subject_key or "")[:16],
            location_code="",
            issued_at=issued,
            expires_at=expires,
            transaction_type=TRANSACTION_TYPE,
            portrait=portrait)
    except Exception:
        logger.exception("holder credential minting failed")
        return None

    result = {
        "qr": minted["qr"],
        "credential_id": str(minted["credential_id"]),
        "transaction_id": str(txn.transaction_id),
        "issuer": issuer_name,
        "transaction_type": TRANSACTION_TYPE,
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
    }
    if portrait:
        result["portrait_qr"] = credentials.portrait_qr(
            portrait, credential_id=minted["credential_id"])
    return result


# ---------------------------------------------------------------------------
# The holder's own symbols, coming back for Apple Wallet
# ---------------------------------------------------------------------------

#: One refusal for every way a symbol a phone sends back can be unacceptable --
#: forged, tampered, expired, revoked, somebody else's, a face that is not the
#: one the credential binds. Same reasoning as REFUSED: which of those it was
#: is logged, not told.
NOT_YOURS = "That credential is not one this deployment issued to you."

#: A credential is about 1.4 KB at its largest and a portrait symbol about
#: the same. Anything near this is neither.
MAX_SYMBOL_CHARS = 8 * 1024


def _not_yours(reason: str):
    logger.info("holder symbol refused: %s", reason)
    return HolderError(NOT_YOURS)


def is_holder_device(device) -> bool:
    """A phone registered on idmanager's word -- the only kind that is a
    holder's, and so the only kind a holder's passes go to."""
    return device.holder_assertions.exists()


def open_own(qr: str):
    """One of this deployment's credentials, opened with its OWN keys; or None.

    This server minted with every epoch's keys and still holds them, so it
    opens both tiers -- which is what lets it check a portrait's hash, a
    thing the holder's own public-tier phone cannot do. The trust list is the
    one phones are given, active issuer keys only, each with its window and,
    for an organization key, the organization its certificate names, and none
    whose certificate has ended: so nothing opens here that a verifier phone
    would refuse.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey)
    from ovcrypto import issuer as issuer_mod, verifier, wire

    from accounts.models import CredentialEpochKey, IssuerKey

    parts = credentials.split_stamp(qr) if isinstance(qr, str) else None
    if parts is None or len(qr) > MAX_SYMBOL_CHARS:
        return None
    body = parts[1] + parts[2]
    try:
        epoch = wire.Payload.unpack(issuer_mod.from_qr_string(body)).header.epoch
    except (wire.WireError, ValueError):
        return None
    rows = {row.tier: row
            for row in CredentialEpochKey.objects.filter(epoch=epoch)}
    if not {credential_keys.TIER_PUBLIC, credential_keys.TIER_RESTRICTED} <= set(rows):
        return None
    if not all(credential_keys.readable(row) for row in rows.values()):
        # The site's fault, not the holder's.
        from accounts.devices import KEYS_UNAVAILABLE, KeysUnavailable
        logger.error("epoch %d's keys cannot be opened with "
                     "CREDENTIAL_EPOCH_WRAP_KEY: no wallet pass", epoch)
        raise KeysUnavailable(KEYS_UNAVAILABLE)
    private = lambda tier: X25519PrivateKey.from_private_bytes(
        credential_keys.private_key(rows[tier]))
    keys = {epoch: verifier.EpochPrivateKeys(
        epoch, private(credential_keys.TIER_PUBLIC),
        private(credential_keys.TIER_RESTRICTED))}
    now = int(time.time())
    trust = verifier.TrustList({}, {}, {})
    for key in IssuerKey.objects.filter(is_active=True):
        if key.cert_not_after is not None and now > key.cert_not_after.timestamp():
            continue
        trust.keys[key.key_id] = bytes(key.spki_der)
        trust.windows[key.key_id] = (int(key.not_before.timestamp()),
                                     int(key.not_after.timestamp()))
        if key.organization_signing_id and key.certified_name:
            trust.certified[key.key_id] = key.certified_name
    try:
        result = verifier.verify(body, epoch_keys=keys, trust_list=trust,
                                 now=now)
    except (wire.WireError, ValueError):
        return None
    return result if result.ok else None


def own_symbols(device, credential_text, portrait_text=None):
    """`(issued, face_webp)` for symbols this phone's holder was issued.

    Raises HolderError(NOT_YOURS) for anything else. A pass is signed with
    this deployment's Pass Type certificate and sits in a wallet
    indefinitely, so what goes on one is decided here, not by the request:

    * the credential must open with this deployment's own keys, unexpired --
      so it is genuine and intact, byte for byte;
    * it must be on record and unrevoked, and its transaction a
      self-verification of THIS phone's holder -- matched on card number,
      the key `register()` found the holder by;
    * the UUID in front, which is outside the signature, must be the
      credential's own;
    * a portrait must be the very face the credential's restricted section
      hashes, which is what earns it a place on the pass as the holder's
      photo.

    What the pass then SAYS comes from the stored transaction
    (`handoff.holder_card()`); the phone supplies only the two symbols, and
    only after they have been proved to be these.
    """
    from ovcrypto import wire

    opened = open_own(credential_text)
    if opened is None:
        raise _not_yours("the credential did not open with this deployment's keys")
    try:
        credential_id = uuid.UUID(bytes=bytes(
            opened.public_claims.get(wire.T_CREDENTIAL_ID) or b""))
    except ValueError:
        raise _not_yours("the credential carries no usable id") from None

    issued = (IssuedCredential.objects.select_related("transaction")
              .filter(credential_id=credential_id).first())
    txn = issued.transaction if issued is not None else None
    if issued is None or issued.revoked_at is not None or txn is None:
        raise _not_yours("not on record, revoked, or its transaction is gone")
    owner_card = (device.owner.national_id_card_number or "") if device.owner_id else ""
    if (txn.organization_id is not None
            or txn.transaction_type != TRANSACTION_TYPE
            or not owner_card
            or txn.national_id_card_number != owner_card):
        raise _not_yours("not a self-verification of this phone's holder")
    parts = credentials.split_stamp(credential_text)
    front = (parts[0] if parts else credential_text).strip()
    if front.upper() != str(issued.document_uuid).upper():
        raise _not_yours("the UUID in front is not the credential's own")

    face = None
    if portrait_text:
        face = _bound_face(opened, credential_id, portrait_text)
    return issued, face


def _bound_face(opened, credential_id, text):
    """The image inside a portrait symbol, if it is the face `opened` binds."""
    from ovcrypto import base45, wire

    if not isinstance(text, str) or len(text) > MAX_SYMBOL_CHARS:
        raise _not_yours("the portrait symbol is not usable")
    parts = text.strip().split(":", 2)
    if len(parts) != 3 or parts[0] not in credentials.PORTRAIT_MAGICS:
        raise _not_yours("not a portrait symbol")
    try:
        claimed = uuid.UUID(parts[1])
        image = base45.decode(parts[2])
    except ValueError:
        raise _not_yours("the portrait symbol does not decode") from None
    expected = (opened.restricted_claims or {}).get(wire.T_PORTRAIT_HASH)
    if (claimed != credential_id or not expected
            or not hmac.compare_digest(hashlib.sha256(image).digest(),
                                       bytes(expected))):
        raise _not_yours("the portrait is not the face this credential binds")
    return image
