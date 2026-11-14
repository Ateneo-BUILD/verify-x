"""Handing a management operation to a phone, and giving it the keys.

The shape here is the sibling OfflineVerifier project's, and it is worth
stating why rather than copying it on faith:

**The QR carries a connection, not the operation's data.** What a phone cannot
guess is exactly three things -- which server to talk to, which operation an
authenticated human just authorised, and a one-time code proving they did.
That fits in around 130 characters, a symbol anyone can scan across a desk. A
key bundle does not: a four-epoch one is 1,899 characters and a 157-module
symbol, and it stops fitting in a QR at all once a few hundred credentials
have been revoked. So the QR connects, and everything after it is HTTPS. That
is why there is one QR shape for pairing, re-keying and syncing rather than a
bespoke payload per operation: none of them put their data in the symbol.

**Nothing carries a bearer token.** A ticket authorises exactly the one
operation it names, once. Afterwards a device proves itself by signing a
server-issued single-use challenge with a key that never leaves its Secure
Enclave, so there is no credential to steal from a phone and replay from
somewhere else.

**The tier is read from the owner, every time.** A device never states its own
access, and the answer is not cached on its row -- see `Device.restricted_tier`
and the note on `User.device_restricted_tier`.

**Organizations are a context, not an access level.** A phone is linked to the
organizations it works for (`DeviceOrganization`), and is told them at every
sync so the app can ask which one the operator is working for. It still reads
every organization's credentials -- nothing about a bundle depends on a link.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone as dt_timezone

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from ovcrypto import appattest
from ovcrypto import bundle as bundle_mod
from ovcrypto import devicelog

from accounts import credential_keys
from accounts.credentials import CredentialError
from accounts.models import (CredentialEpochKey, Device, DeviceChallenge,
                             DeviceOrganization, DeviceTicket, IssuerKey,
                             Membership, organizations_open_to)

logger = logging.getLogger(__name__)


class PairingError(Exception):
    """Refused. The message is shown to the caller, so keep it plain."""


#: Unknown, revoked and unparseable alike -- the caller learns nothing about
#: which, exactly as with a refused ticket. The app shows it as it stands, so
#: it says what to do: a phone whose row went with a restored database, or
#: was revoked, comes back only by resetting and pairing again.
UNKNOWN_DEVICE = ("This phone is not registered with this site. To use it "
                  "here again, reset its keys in the app's Settings, then pair "
                  "it with a new code from the site.")


class UnknownDevice(PairingError):
    """No live device row for the id given: answered 403."""

    def __init__(self):
        super().__init__(UNKNOWN_DEVICE)


class KeysUnavailable(Exception):
    """This site cannot open the document keys a phone would be given: the
    server's fault, answered 503, never a 500 after the phone's challenge
    was spent. The message is shown to the phone."""


#: Bumped only on a breaking change to the QR payload. The app should refuse a
#: version it does not know rather than guess at unfamiliar fields. 2 added
#: `op`, which the app must read: a phone that ignored it would treat a sync
#: ticket as an invitation to enrol.
PAYLOAD_VERSION = 2

#: One refusal for every way a ticket can fail to be usable -- expired, spent,
#: never existed, wrong purpose, pointing at a device that has gone. Telling
#: them apart tells somebody feeding in guesses which ones were real.
TICKET_REFUSED = "That code is not valid."

#: These resolve on the machine serving the page and nowhere else. A QR built
#: from one sends the phone to itself, which surfaces as an enrolment that
#: times out with no clue why -- so it is reported rather than shipped.
UNREACHABLE_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "[::1]"}


def _load_p256(public_key_der: bytes):
    """A P-256 public key from DER SubjectPublicKeyInfo, or None.

    None rather than an exception: every caller here is answering "is this
    usable", and a device sending nonsense is an ordinary refusal rather than
    a server error.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    try:
        key = serialization.load_der_public_key(bytes(public_key_der))
    except Exception:
        return None
    if not isinstance(key, ec.EllipticCurvePublicKey):
        return None
    if key.curve.name != "secp256r1":
        return None
    return key


# ---------------------------------------------------------------------------
# The connection QR
# ---------------------------------------------------------------------------

def as_https(url: str) -> str:
    """The same address over https.

    Not a preference: the app connects over https and refuses every other
    scheme, so a cleartext QR is not a worse QR, it is one no phone can use.
    Upgrading beats copying whatever scheme this page happened to be served
    over -- right wherever TLS exists, and no more wrong where it does not.

    Host and port are left alone. A proxy terminating TLS on a non-default
    port is a real deployment, and inventing 443 would break it;
    `DEVICE_PAIRING_BASE_URL` states an address that differs by more.
    """
    if "://" not in url:
        return "https://" + url
    scheme, rest = url.split("://", 1)
    return "https://" + rest if scheme.lower() != "https" else url


def _raw_base_url(request) -> str:
    configured = (settings.DEVICE_PAIRING_BASE_URL or "").strip().rstrip("/")
    return configured or request.build_absolute_uri("/").rstrip("/")


def base_url(request) -> str:
    """Where the QR tells the phone to connect. Always https -- see `as_https`."""
    return as_https(_raw_base_url(request))


def was_upgraded(request) -> bool:
    """True when the address had to be rewritten to https to be usable.

    Reported rather than swallowed. Reaching this page over http behind the load balancer
    means nginx is overwriting `X-Forwarded-Proto` with `$scheme`, and that same
    fault leaves `request.is_secure()` false for everything else -- secure
    cookies, HSTS, every absolute URL Django builds. Fixing the QR must not
    quietly hide the cause.
    """
    raw = _raw_base_url(request)
    return raw != as_https(raw)


def is_reachable(url: str) -> bool:
    """False when the phone provably cannot resolve this address."""
    host = url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    return host.lower() not in UNREACHABLE_HOSTS


def phone_will_load(url: str) -> bool:
    """False when the app refuses this address outright.

    The app connects over https and nothing else: `BackendSettings.normalise`
    rejects any other scheme, and the build carries no ATS exception, so iOS
    refuses cleartext too. A `http://` QR therefore fails *inside* the phone
    before a packet is sent, which looks like a broken app rather than a
    misaddressed code.

    This deployment already has a certificate -- the load balancer terminates TLS and
    `SECURE_PROXY_SSL_HEADER` is set -- so an http address here means the page
    was opened over http, and the QR faithfully copied the scheme it was served
    over. Opening the site at its https address is the whole fix; setting
    `DEVICE_PAIRING_BASE_URL` pins it regardless.

    Kept exactly as strict as the client. A server-side rule more permissive
    than the app would approve an address no phone can use, which is worse than
    having no check.
    """
    return url.split("://", 1)[0].lower() == "https" if "://" in url else False


def service_descriptor(url: str) -> dict:
    """Where the phone should talk, resolved rather than guessed.

    Built with `reverse()` so it cannot drift from `urls.py`, and handed over
    at connect time so a path can move without re-flashing a fleet -- which is
    the whole point of the phone asking instead of hard-coding.

    Nothing here is a secret. It is the same for every operator on the
    deployment, and it is useless without a ticket and, after that, a key.
    """
    from django.urls import reverse

    return {name: url + reverse(route) for name, route in (
        ("connect", "device_connect"),
        ("enrol", "device_enrol"),
        ("challenge", "device_challenge"),
        ("keys", "device_keys"),
        ("revocations", "revocation_feed"),
        ("log-key", "device_log_key"),
        ("logs", "device_logs"),
    )}


def ticket_payload(ticket: DeviceTicket, *, url: str) -> str:
    """The exact string encoded into the QR.

    Compact keys and no whitespace: every byte pushes the symbol toward a
    denser version, and a denser symbol is harder to scan across a desk.

    Note what is NOT here: no endpoint list, no key, no bundle, nothing about
    the operation beyond its name. The phone gets all of that by connecting.
    """
    data = {"v": PAYLOAD_VERSION, "url": url, "code": ticket.code,
            "op": ticket.purpose}
    if ticket.device is not None:
        # Which phone this concerns, in the spelling the API uses. It is also
        # returned by /connect/, so this is a convenience rather than the
        # source of truth -- a phone that trusted it would be trusting a
        # printed string. Base64 is twelve characters shorter than the
        # hyphenated form, which the symbol notices and the reader does not.
        data["dev"] = device_id_wire(ticket.device)
    owner = ticket.user
    if owner is not None:
        # Shown by the app before it acts, so somebody holding two phones can
        # see which account they are about to join. Display only -- the server
        # never reads it back and nothing depends on it.
        data["for"] = owner.public_name[:60]
    return json.dumps(data, separators=(",", ":"))


@transaction.atomic
def mint_ticket(user, purpose: str = DeviceTicket.PURPOSE_ENROL, *,
                device: Device = None, label: str = "",
                organization_ids=()) -> DeviceTicket:
    """Authorise one operation, for this person, for a short while.

    The device is checked against the person here rather than trusted from
    the form: this is the one place a ticket is created, so it is the one
    place that has to hold.

    `organization_ids` is what a new phone starts out working for, and is
    kept only on an ENROL ticket and only where this person may enter the
    organization -- for the same reason as the device check: an id on a form
    is a request, not a fact. Device-scoped tickets carry none; a phone that
    exists has its links changed on the Devices page.
    """
    if purpose not in dict(DeviceTicket.PURPOSES):
        raise PairingError("Unknown operation.")
    if purpose in DeviceTicket.DEVICE_SCOPED:
        if device is None:
            raise PairingError("That operation needs a device.")
        if device.owner_id != user.id:
            raise PairingError("That device belongs to somebody else.")
        if not device.is_active:
            raise PairingError("That device has been revoked.")
    else:
        device = None
    ticket = DeviceTicket.objects.create(
        code=DeviceTicket.new_code(),
        purpose=purpose,
        label=(label or "").strip()[:120],
        user=user,
        device=device,
        expires_at=timezone.now() + timedelta(
            seconds=settings.DEVICE_PAIRING_TTL_SECONDS))
    wanted = _ids(organization_ids)
    if purpose == DeviceTicket.PURPOSE_ENROL and wanted:
        ticket.organizations.set(
            organizations_open_to(user).filter(pk__in=wanted))
    return ticket


def _live_tickets():
    return DeviceTicket.objects.filter(used_at__isnull=True,
                                       expires_at__gt=timezone.now())


def resolve_ticket(code_str: str, *, purpose: str = None) -> DeviceTicket:
    """Look a scanned code up. Does NOT spend it.

    Reading a ticket performs nothing, so the operation endpoint is where it
    is spent -- that keeps "a ticket authorises one operation, once" true even
    though the phone asks about it first.
    """
    code_str = (code_str or "").strip().upper()
    if not code_str:
        raise PairingError(TICKET_REFUSED)
    ticket = (_live_tickets().filter(code=code_str)
              .select_related("user", "device").first())
    if ticket is None:
        raise PairingError(TICKET_REFUSED)
    if purpose is not None and ticket.purpose != purpose:
        # A live sync ticket must not enrol a phone. Checking the purpose is
        # what makes the ticket authorise ONE operation rather than merely
        # prove that somebody signed in recently.
        raise PairingError(TICKET_REFUSED)
    if ticket.purpose in DeviceTicket.DEVICE_SCOPED and (
            ticket.device is None or not ticket.device.is_active):
        raise PairingError(TICKET_REFUSED)
    return ticket


@transaction.atomic
def spend_ticket(ticket: DeviceTicket, *, device: Device = None) -> DeviceTicket:
    """Mark a ticket used, once, losing a race rather than winning it twice.

    select_for_update and a re-check of `used_at`, so two phones racing the
    same code cannot both come away having done the operation.
    """
    spent = (DeviceTicket.objects.select_for_update()
             .filter(pk=ticket.pk, used_at__isnull=True,
                     expires_at__gt=timezone.now()).first())
    if spent is None:
        raise PairingError(TICKET_REFUSED)
    spent.used_at = timezone.now()
    fields = ["used_at"]
    if device is not None:
        spent.device = device
        fields.append("device")
    spent.save(update_fields=fields)
    return spent


# ---------------------------------------------------------------------------
# Enrolment
# ---------------------------------------------------------------------------

#: Plenty for an attestation object (a few kilobytes) in base64.
MAX_ATTESTATION_CHARS = 64 * 1024


def check_attestation(attestation, attest_key_id, challenge, *,
                      public_key_der: bytes, capabilities=None):
    """App Attest at pairing: (status, attested key DER or None, detail for the
    log and the device).

    The checks are `ovcrypto.appattest`'s, against Apple's root. `challenge` is
    the one the phone attested with, which must be one this site issued and
    nobody has used: it is spent here. The attestation must also name the
    device key being paired, `public_key_der` (`appattest.attest_client_data`),
    which a phone says with "attest-device-key". One of the bare challenge,
    from an older app, proves only that a genuine app attested something this
    site issued: a relay between a real phone and this site could post it
    beside a key of its own, kept in software. It is not counted -- "absent",
    as though none were sent. Never raises -- whether a status other than
    "attested" refuses the pairing is `DEVICE_REQUIRE_APP_ATTEST`'s to say, in
    `enrol`.
    """
    if not attestation:
        return "absent", None, "the phone sent no attestation"
    if not isinstance(capabilities, list) or "attest-device-key" not in capabilities:
        return ("absent", None, "an older app: its attestation does not name "
                "its device key, so it is not counted")
    if not settings.DEVICE_APP_ATTEST_APP_ID:
        return "unconfigured", None, "DEVICE_APP_ATTEST_APP_ID is not set"
    if (not isinstance(attestation, str) or not isinstance(attest_key_id, str)
            or len(attestation) > MAX_ATTESTATION_CHARS):
        return "failed", None, "the attestation is not a base64 string"
    try:
        raw = base64.b64decode(attestation, validate=True)
        key_id = base64.b64decode(attest_key_id, validate=True)
        nonce = base64.b64decode(challenge or "", validate=True)
    except (binascii.Error, ValueError, TypeError):
        return "failed", None, "the attestation is not base64"
    try:
        consume_challenge(challenge)
    except PairingError:
        return "failed", None, "its challenge is not one this site issued and nobody used"
    try:
        attested = appattest.verify_attestation(
            raw, key_id=key_id,
            client_data=appattest.attest_client_data(nonce, public_key_der),
            app_id=settings.DEVICE_APP_ATTEST_APP_ID,
            environment=settings.DEVICE_APP_ATTEST_ENVIRONMENT)
    except appattest.AttestationError as exc:
        return "failed", None, str(exc)[:200]
    return "attested", attested.public_key_der, ""


def check_assertion(device: Device, assertion, challenge: bytes) -> bool:
    """App Attest at each sync: whether the sync may go on.

    The assertion is checked against the key attested at pairing, its counter
    must advance, and the result is recorded on the device. With
    `DEVICE_REQUIRE_APP_ATTEST` off nothing is refused; on, a device with no
    attested key -- paired before the check, or never attested -- and any
    assertion that fails are refused. A failure stays on the device until it
    pairs again, one being what a cloned app looks like, and with the check
    required every sync after it is refused too. A counter that does not
    advance is not a failure: it refuses its own request and nothing else.

    Holder phones are the exception to "no attested key": idmanager's app,
    registered by `holders.register` on idmanager's signed word, never
    attests, and is public-tier only (`public_tier_only`, which nothing else
    sets). Requiring App Attest refuses the verifier app's pairings that do
    not attest, idmanager's verifier mode among them, not those phones.
    """
    required = settings.DEVICE_REQUIRE_APP_ATTEST
    if not device.attest_public_key_der:
        return not required or device.public_tier_only
    if required and device.attest_status == "failed":
        logger.warning("device %s: App Attest failed before (%s); refused until "
                       "it pairs again", device.device_id, device.attest_detail)
        return False
    now = timezone.now()
    try:
        if not isinstance(assertion, str) or not assertion:
            raise appattest.AttestationError("the phone sent no assertion")
        if len(assertion) > MAX_ATTESTATION_CHARS:
            raise appattest.AttestationError("the assertion is too large")
        try:
            raw = base64.b64decode(assertion, validate=True)
        except (binascii.Error, ValueError):
            raise appattest.AttestationError("the assertion is not base64") from None
        counter = appattest.verify_assertion(
            raw, client_data=challenge,
            public_key_der=bytes(device.attest_public_key_der),
            app_id=settings.DEVICE_APP_ATTEST_APP_ID,
            # Compared below, in the database, in one statement.
            previous_counter=-1)
    except appattest.AttestationError as exc:
        return _assertion_failed(device, "assertion: %s" % exc, now, required)
    # It must advance past the counter stored, and is stored only if it does,
    # in one statement: two syncs in flight could otherwise both pass a check
    # against the counter read before either wrote, and leave the lower one
    # stored. One that does not advance refuses this request only, and is
    # recorded nowhere: its challenge was this site's, single-use and signed
    # by the phone's Enclave key, so it is the phone's own sync, overtaken by
    # another -- never a replay, and no reason to lock the phone out until it
    # pairs again.
    if not Device.objects.filter(pk=device.pk, attest_counter__lt=counter).update(
            attest_counter=counter, attest_checked_at=now):
        logger.warning("device %s: App Attest counter %d did not advance past "
                       "the one stored; this sync is %s", device.device_id,
                       counter, "refused" if required else "let through")
        return not required
    return True


def _assertion_failed(device: Device, detail: str, now, required: bool) -> bool:
    detail = detail[:200]
    Device.objects.filter(pk=device.pk).update(
        attest_status="failed", attest_detail=detail, attest_checked_at=now)
    logger.warning("device %s: App Attest %s", device.device_id, detail)
    return not required


def sync_time(device: Device, nonce: bytes):
    """This deployment's signed time at a sync, over the nonce the phone made
    for it, or None.

    The only time a phone brings its clock's high-water mark back to, so it is
    over the phone's own nonce: a bundle can be held back from one sync and
    served at another, and so can this site's challenge. Signed by the key
    that signs statements, as the log acknowledgement is -- the signer's
    `sync_time`, or the key file's. None when nothing can sign it just now;
    the phone then leaves its mark where it is.
    """
    device_id = device.device_id.bytes
    try:
        if credential_keys.signer_mode():
            from accounts import signer_client

            return signer_client.sync_time(device_id=device_id, nonce=nonce)
        now = int(time.time())
        signer = credential_keys.signer()
        signature = signer.sign(devicelog.time_signed_bytes(
            device_id, nonce, now, signer.key_id))
        return {"format": devicelog.TIME_MAGIC.decode(),
                "version": devicelog.TIME_VERSION, "issued_at": now,
                "sig_key_id": signer.key_id,
                "sig": base64.b64encode(signature).decode()}
    except Exception:
        logger.exception("device %s: the sync time could not be signed; the "
                         "phone keeps its clock's mark", device.device_id)
        return None


@transaction.atomic
def enrol(code_str: str, public_key_der: bytes, *, label: str = "",
          attestation=None, attest_key_id: str = "",
          challenge: str = "", capabilities=None) -> Device:
    """Bind one Secure Enclave key, using one ticket.

    Serves both `enrol` -- a phone joining an account -- and `rekey`, a phone
    that already has a row here presenting a NEW Enclave key. They share every
    check because they are the same act: the ticket says which, and the ticket
    is the only thing that does.
    """
    if not public_key_der:
        raise PairingError("A device public key is required.")

    ticket = resolve_ticket(code_str)
    if ticket.purpose not in (DeviceTicket.PURPOSE_ENROL,
                              DeviceTicket.PURPOSE_REKEY):
        raise PairingError(TICKET_REFUSED)

    status, attested_key, detail = check_attestation(
        attestation, attest_key_id, challenge, public_key_der=public_key_der,
        capabilities=capabilities)
    # Kept as sent when it is text; anything else is stored blank.
    stored_key_id = attest_key_id[:200] if isinstance(attest_key_id, str) else ""
    if settings.DEVICE_REQUIRE_APP_ATTEST and status != "attested":
        logger.warning("pairing refused: App Attest %s: %s", status, detail)
        raise PairingError("Device attestation was not accepted.")
    attest_fields = dict(attest_public_key_der=attested_key,
                         attest_status=status, attest_detail=detail,
                         attest_checked_at=timezone.now(), attest_counter=0)

    if _load_p256(public_key_der) is None:
        raise PairingError("That device public key is not usable.")

    clash = Device.objects.filter(public_key_der=public_key_der)
    if ticket.purpose == DeviceTicket.PURPOSE_REKEY:
        clash = clash.exclude(pk=ticket.device.pk)
    if clash.exists():
        raise PairingError("That device is already paired.")

    if ticket.purpose == DeviceTicket.PURPOSE_REKEY:
        device = ticket.device
        device.public_key_der = public_key_der
        device.attest_key_id = stored_key_id
        # A new key and a new attestation: what was recorded for the old one
        # does not carry over, a failure included.
        for name, value in attest_fields.items():
            setattr(device, name, value)
        # The name is deliberately NOT touched. The row already carries what
        # its owner calls it -- typed when the phone was paired, or changed on
        # the Devices page since -- and a re-key is a handset replacing a key
        # it lost, not a handset renaming itself. Letting the phone's own
        # label win here would quietly undo a rename every time somebody
        # restored their phone, which is the failure this whole ordering
        # exists to stop.
        #
        # Everything it held was wrapped to the key it has just replaced, so
        # it holds nothing readable now. Say so -- "Keys stale" until it syncs
        # is the truth, and a lease left running would claim otherwise.
        device.last_sync_at = None
        device.lease_expires_at = timezone.now()
        device.save(update_fields=["public_key_der", "attest_key_id",
                                   "last_sync_at", "lease_expires_at",
                                   *attest_fields])
    else:
        # The name typed on the web comes FIRST, and that order is the whole
        # point: it is what an operator decided to call this handset, and it
        # is what the Devices list is read by. The phone's own label is a
        # fallback for a pairing where nobody typed anything, and "Verifier
        # device" is the fallback for that. The other way round, the
        # name would be discarded the moment the handset sent one, and
        # "Name this phone" would name nothing.
        device = Device.objects.create(
            label=(ticket.label or label or "Verifier device")[:120],
            public_key_der=public_key_der,
            owner=ticket.user,
            attest_key_id=stored_key_id,
            **attest_fields,
            lease_expires_at=timezone.now() + timedelta(
                seconds=settings.DEVICE_LEASE_SECONDS))
        # What the pairing form ticked, less anything the owner can no longer
        # enter -- a membership can end between showing the QR and the scan.
        # A re-key is the same phone, so it keeps the links it has.
        DeviceOrganization.objects.bulk_create([
            DeviceOrganization(device=device, organization=org,
                               linked_by=ticket.user)
            for org in ticket_organizations(ticket)])

    spend_ticket(ticket, device=device)
    return device


# ---------------------------------------------------------------------------
# Proving possession
# ---------------------------------------------------------------------------

def issue_challenge() -> DeviceChallenge:
    """A nonce for anyone who asks. Alone it grants nothing.

    Base64 of 24 random bytes, because that is what the verifier app already
    receives from the sibling deployment and signs: it decodes the challenge
    and signs the BYTES. Hex would have meant the one client had to know which
    server it was talking to in order to know what to sign.
    """
    prune_challenges()
    return DeviceChallenge.objects.create(
        nonce=base64.b64encode(secrets.token_bytes(24)).decode())


def prune_challenges():
    DeviceChallenge.objects.filter(
        created_at__lt=timezone.now() - timedelta(
            seconds=settings.DEVICE_CHALLENGE_TTL_SECONDS * 4)).delete()


@transaction.atomic
def consume_challenge(nonce: str) -> DeviceChallenge:
    """Spend a nonce, once. Replay is the attack this exists to stop."""
    row = (DeviceChallenge.objects
           .select_for_update()
           .filter(nonce=(nonce or "").strip(), used_at__isnull=True,
                   created_at__gte=timezone.now() - timedelta(
                       seconds=settings.DEVICE_CHALLENGE_TTL_SECONDS))
           .first())
    if row is None:
        raise PairingError("That challenge is not valid.")
    row.used_at = timezone.now()
    row.save(update_fields=["used_at"])
    return row


def device_id_wire(device: Device) -> str:
    """How a device id goes over the API: base64 of the sixteen raw bytes.

    Not the hyphenated string. A key bundle carries the id as raw bytes, so
    the app already holds it that way; handing it a second spelling on the way
    in would make it convert twice for no reason.
    """
    return base64.b64encode(device.device_id.bytes).decode()


def parse_device_id(value):
    """A device id out of untrusted text, or None.

    Accepts both spellings of the one identifier: the hyphenated form the web
    pages post, and base64 of the sixteen bytes the API speaks. That is not
    two dialects -- each caller only ever emits one, and a UUID is a UUID
    however it is written.

    Filtering a UUID column by something that is not a UUID raises
    ValidationError rather than matching nothing, so without this a typo at an
    unauthenticated endpoint is a 500 instead of a refusal. None means the
    same thing as "no such device", which is the honest answer to both.
    """
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return uuid.UUID(text)
    except (AttributeError, TypeError, ValueError):
        pass
    try:
        raw = base64.b64decode(text, validate=True)
    except Exception:
        return None
    return uuid.UUID(bytes=raw) if len(raw) == 16 else None


def device_for(device_id: str) -> Device:
    parsed = parse_device_id(device_id)
    device = None
    if parsed is not None:
        device = Device.objects.filter(device_id=parsed,
                                       revoked_at__isnull=True).first()
    if device is None:
        raise UnknownDevice()
    return device


def signature_ok(device: Device, message: bytes, signature_der: bytes) -> bool:
    """Did this device sign these bytes with the key it enrolled?

    Naming another device's id gains nothing: it only changes which public key
    the signature is checked against, and the caller cannot satisfy one it
    does not hold the private half of.

    **DER, not the 64-byte form `ovcrypto` uses.** That is what a Secure
    Enclave key produces -- `SecKeyCreateSignature` with
    `.ecdsaSignatureMessageX962SHA256` -- and what the sibling deployment's
    device API already accepts, so a phone needs no second dialect. Mirrors
    `keys/api.py::_verify_device_signature` there deliberately: two
    implementations of one check should not differ.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    key = _load_p256(bytes(device.public_key_der))
    if key is None:
        return False
    try:
        key.verify(signature_der, message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


# ---------------------------------------------------------------------------
# The key bundle
# ---------------------------------------------------------------------------

def epochs_for(device: Device):
    """Which epoch keys this device should hold.

    Every epoch still readable -- current plus the overlap -- so a document
    minted under an older one still opens. Restricted-tier rows only when the
    OWNER is entitled: a public-tier device is never sent the key, so it
    cannot read personal data at all. The separation is cryptographic, not a
    setting in the app.
    """
    # Make sure the CURRENT epoch exists before reading. Epoch rows are
    # created on demand, so without this a deployment that paired a phone
    # before it verified anybody would hand over a bundle with no epoch keys
    # at all: a device that can decrypt nothing, reporting device_stale on
    # every document it is shown.
    credential_keys.issuing_keys()

    rows = CredentialEpochKey.objects.filter(
        not_after__gte=timezone.now()).order_by("epoch", "tier")
    if not device.restricted_tier:
        rows = rows.filter(tier=credential_keys.TIER_PUBLIC)
    return list(rows)


def trust_entries():
    """The issuer keys a device should accept credentials from."""
    return [
        bundle_mod.TrustEntry(key.key_id, int(key.not_before.timestamp()),
                              int(key.not_after.timestamp()),
                              bytes(key.spki_der))
        for key in IssuerKey.objects.filter(is_active=True)
    ]


def build_bundle(device: Device) -> bytes:
    """Everything the phone needs, signed, in one binary blob.

    Binary rather than JSON specifically because it is signed: reproducing
    canonical JSON byte for byte across Python and Swift is a well-known
    source of silent mismatches. The format is `ovcrypto.bundle`, which the
    verifier app already parses.
    """
    return build_bundle_and_chains(device)[0]


def build_bundle_and_chains(device: Device, chain_capable=None):
    """(bundle bytes, issuer_chains envelope or None).

    With a signer, verify sends only what belongs to the device -- its id, a
    hash of its enrolled key, its wrapped epoch keys and the lease asked for --
    and the signer adds the times, the trust list, the revocation filter and
    the signature. The chains of the certified keys it lists travel beside it.
    `chain_capable` is whether the phone said, in this request, that it follows
    issuer certificates: the signer's switch gate counts on it.
    """
    from accounts import revocation_feed, signer_client

    if not credential_keys.configured():
        raise PairingError("Key issuance is not configured on this deployment.")

    if credential_keys.signer_mode():
        wrapped = _wrapped_epoch_keys(device)
        try:
            # Every revocation reaches the signer before any bundle, so the
            # filter a phone carries is never older than the feed.
            signer_client.ensure_revocations()
            got = signer_client.bundle(
                device_id=device.device_id.bytes,
                device_key_hash=hashlib.sha256(
                    bytes(device.public_key_der)).digest(),
                epoch_keys=[{"epoch": k.epoch, "tier": k.tier,
                             "not_before": k.not_before,
                             "not_after": k.not_after,
                             "wrapped": base64.b64encode(k.wrapped).decode()}
                            for k in wrapped],
                lease_seconds=settings.DEVICE_LEASE_SECONDS,
                chains=chain_capable)
        except signer_client.SignerError as exc:
            raise PairingError("Keys could not be issued right now (%s). "
                               "Try again shortly." % exc.reason)
        Device.objects.filter(pk=device.pk).update(
            last_sync_at=timezone.now(),
            lease_expires_at=datetime.fromtimestamp(got["not_after"],
                                                    dt_timezone.utc))
        return base64.b64decode(got["bundle"]), got["issuer_chains"]

    trust = trust_entries()
    if not trust:
        # A bundle with no trust list is a phone that rejects every credential
        # as forged. Refuse rather than hand one over.
        raise PairingError(
            "No issuer key is registered, so a device would trust nothing. "
            "Run manage.py load_credential_keys.")

    wrapped = _wrapped_epoch_keys(device)

    now = int(timezone.now().timestamp())
    lease = now + settings.DEVICE_LEASE_SECONDS
    try:
        blob = bundle_mod.Bundle(
            device_id=device.device_id.bytes,
            issued_at=now, not_before=now, not_after=lease,
            epoch_keys=wrapped, trust=trust,
            revocation=revocation_feed.build_filter(),
        ).sign(credential_keys.signer()).pack()
    except bundle_mod.BundleError as exc:
        # This site's settings, not the phone (accounts.E001, E002): a 503
        # after its challenge was spent, never a 500.
        logger.error("no bundle for device %s: %s", device.pk, exc)
        raise KeysUnavailable(BUNDLE_SETTINGS_WRONG) from None

    Device.objects.filter(pk=device.pk).update(
        last_sync_at=timezone.now(),
        lease_expires_at=datetime.fromtimestamp(lease, dt_timezone.utc))
    return blob, None


def _wrapped_epoch_keys(device: Device) -> list:
    """The epoch keys this device may hold, wrapped to its Enclave key.

    KeysUnavailable when this site cannot open one: a database brought from
    elsewhere under another CREDENTIAL_EPOCH_WRAP_KEY, or the current epoch's
    keys missing (`credential_keys.epoch_key_row`)."""
    public_key = _load_p256(bytes(device.public_key_der))
    if public_key is None:
        raise PairingError("This device's stored public key is not usable.")
    try:
        rows = epochs_for(device)
    except CredentialError as exc:
        logger.error("no bundle for device %s: %s", device.pk, exc)
        raise KeysUnavailable(KEYS_UNAVAILABLE) from exc
    wrapped = []
    for row in rows:
        if not credential_keys.readable(row):
            logger.error("no bundle for device %s: epoch %d %s cannot be "
                         "opened with CREDENTIAL_EPOCH_WRAP_KEY", device.pk,
                         row.epoch, row.get_tier_display().lower())
            raise KeysUnavailable(KEYS_UNAVAILABLE)
        wrapped.append(bundle_mod.WrappedEpochKey(
            row.epoch, row.tier,
            int(row.not_before.timestamp()), int(row.not_after.timestamp()),
            bundle_mod.apple_ecies_encrypt(
                public_key, credential_keys.private_key(row))))
    return wrapped


BUNDLE_SETTINGS_WRONG = ("This site's settings stop it issuing keys, so nothing "
                         "was issued. Its administrator can see why with "
                         "manage.py check. Try again later.")
KEYS_UNAVAILABLE = ("This site cannot open its own document keys, so nothing "
                    "was issued. Its administrator can see why on the Setup "
                    "page. Try again later.")


def rename(device: Device, name: str) -> Device:
    """Call a phone something else. The name is the owner's to choose.

    Presentation only -- nothing depends on it, nothing signs it, and no
    credential carries it. That is why this needs no ticket and no signature:
    it changes what a list on the web says, and reaches the handset only as
    the `label` echoed back by `/connect/`.

    **Blank keeps what is stored**, the same rule the masked fields on Setup
    and Organization follow. A row whose name is empty would print as a blank
    cell above its device id, which reads as a broken record rather than as
    an unnamed one -- and `enrol()` goes out of its way to guarantee every
    device has a name, so this must not be the one path that takes it away.
    """
    name = (name or "").strip()[:120]
    if name and name != device.label:
        device.label = name
        device.save(update_fields=["label"])
    return device


def revoke(device: Device, *, actor=None, reason=""):
    """Withdraw a device. It stops syncing; what it already holds expires."""
    if device.revoked_at is None:
        device.revoked_at = timezone.now()
        device.revoked_by = actor
        device.revoked_reason = (reason or "")[:200]
        device.save(update_fields=["revoked_at", "revoked_by",
                                   "revoked_reason"])
    return device


# ---------------------------------------------------------------------------
# Organizations: which ones a phone works for
# ---------------------------------------------------------------------------
# A link says which organizations the app offers in its chooser, and so which
# one each log record names. It grants nothing: a phone reads every
# organization's credentials whatever it is linked to.

#: Organization ids as they travel: positive, and inside a signed 32-bit
#: integer, which is what the log plaintext's `org` is bounded by too. A
#: bigger number names no row and would overflow a query parameter first.
MAX_ORGANIZATION_ID = 2 ** 31 - 1

#: The largest logo a phone is sent, decoded. The list rides every sync and
#: the app keeps it in the Keychain, while the web takes logos four times
#: this size -- so a large one is left out rather than shrunk here, and the
#: app draws the initials mark instead, as for an organization with none.
MAX_DEVICE_LOGO_BYTES = 64 * 1024


def _ids(values) -> set:
    """Organization ids out of a form. Junk is dropped, not an error: every
    caller filters what is left by what the person may enter anyway."""
    ids = set()
    for value in values or ():
        try:
            number = int(str(value).strip())
        except (TypeError, ValueError):
            continue
        if 0 < number <= MAX_ORGANIZATION_ID:
            ids.add(number)
    return ids


def linked_organizations(device):
    """The organizations this phone is CURRENTLY linked to that its owner may
    enter NOW, by name.

    Both halves, every time. A link outlives the membership behind it -- it
    is not deleted when somebody leaves an organization, or when an
    organization is disabled -- so the rule is applied on the way out rather
    than by tidying rows: the link simply stops being sent, and comes back
    if the membership does.
    """
    return organizations_open_to(device.owner).filter(
        pk__in=DeviceOrganization.objects.filter(
            device=device, unlinked_at__isnull=True).values("organization_id"))


def _device_logo(org) -> str:
    """The logo as a phone is sent it: the stored data URI, or "" when there
    is none, it is not one, or it decodes to more than
    MAX_DEVICE_LOGO_BYTES."""
    data = org.logo_data or ""
    head, separator, payload = data.partition(";base64,")
    if not separator or not head.startswith("data:image/"):
        return ""
    try:
        raw = base64.b64decode(payload, validate=True)
    except ValueError:
        return ""
    return data if 0 < len(raw) <= MAX_DEVICE_LOGO_BYTES else ""


def organizations_for(device: Device) -> list:
    """What `/keys/` tells a phone it works for, ordered by name.

    Each is drawn by the app as this site draws it -- name, subtitle, the
    logo or else the initials on the mark colour -- plus the owner's role
    there. A site admin may enter an organization without being a member
    of it, and is its admin in every sense this site recognises, so a site
    admin with no membership is "admin".
    """
    owner = device.owner
    roles = dict(Membership.objects.filter(user=owner).values_list(
        "organization_id", "role"))
    return [{
        "id": org.id,
        "name": org.name,
        "subtitle": org.subtitle or "",
        "role": roles.get(org.id, Membership.ROLE_ADMIN),
        "initials": org.initials,
        "mark_color": org.mark_color,
        "logo": _device_logo(org),
    } for org in linked_organizations(device)]


def ticket_organizations(ticket: DeviceTicket) -> list:
    """The organizations an enrol ticket would link its phone to NOW: the
    ones it names that its owner may still enter, by name."""
    return list(organizations_open_to(ticket.user).filter(
        pk__in=ticket.organizations.values("pk")))


def connect_organizations(ticket: DeviceTicket) -> list:
    """`organizations` for `/connect/`: id and name only, by name.

    A pairing has no phone yet, so it answers with what the ticket will link
    -- which is what lets the app's confirmation sheet say "Works for"
    before anything is done. A sync or re-key concerns a phone that exists,
    and answers with what that phone is told at `/keys/`.
    """
    if ticket.purpose == DeviceTicket.PURPOSE_ENROL:
        organizations = ticket_organizations(ticket)
    elif ticket.device is not None:
        organizations = linked_organizations(ticket.device)
    else:
        organizations = []
    return [{"id": org.id, "name": org.name} for org in organizations]


@transaction.atomic
def set_organizations(device: Device, organization_ids, *, actor) -> Device:
    """Make a phone work for exactly the ticked organizations -- of the ones
    its owner may enter.

    Applied as a difference, and only inside that set. A link to an
    organization the owner can no longer enter is not on the form, so it is
    neither ended nor renewed here; it is simply not sent while it stays
    out of reach. An id outside the set is not linked, whatever the form
    said: the form is a request, and the rule is `organizations_open_to`.

    Ending a link stamps it rather than deleting it, because a record the
    phone wrote while it worked for that organization may not have arrived
    yet -- see `DeviceOrganization`.

    The owner is checked again here, as `mint_ticket` checks it: the page
    already looks the phone up on the signed-in person's own devices, and
    this is the one place a link is made.
    """
    if device.owner_id != actor.id:
        raise PairingError("That device belongs to somebody else.")
    if not device.is_active:
        raise PairingError("That device has been revoked.")

    reachable = set(organizations_open_to(device.owner)
                    .values_list("pk", flat=True))
    wanted = _ids(organization_ids) & reachable
    current = dict(DeviceOrganization.objects.select_for_update()
                   .filter(device=device, unlinked_at__isnull=True)
                   .values_list("organization_id", "pk"))

    ending = [pk for org_id, pk in current.items()
              if org_id in reachable and org_id not in wanted]
    if ending:
        DeviceOrganization.objects.filter(pk__in=ending).update(
            unlinked_at=timezone.now(), unlinked_by=actor)
    # A second submit of the same boxes racing this one would hit the
    # one-current-link constraint; the link it wanted is there either way,
    # so a conflict is skipped rather than turned into a 500.
    DeviceOrganization.objects.bulk_create([
        DeviceOrganization(device=device, organization_id=org_id,
                           linked_by=actor)
        for org_id in sorted(wanted - set(current))], ignore_conflicts=True)
    return device
