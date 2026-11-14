"""The machine endpoints a verifier phone uses.

Signature-authenticated and `csrf_exempt`, deliberately: CSRF protects a
browser session against a page on another origin, and none of these callers is
a browser or holds a session. The control here is that a device proves itself
by signing a server-issued single-use challenge with a key that never left its
Secure Enclave.

    POST /api/v1/device/connect/    a scanned ticket           -> what and where
    POST /api/v1/device/enrol/      a ticket + a public key    -> device id
    POST /api/v1/device/challenge/  nothing                    -> a challenge
    POST /api/v1/device/keys/       a signature over one       -> the key bundle
    GET  /api/v1/device/log-key/    nothing                    -> the log key,
                                                                  issuer-signed
    POST /api/v1/device/logs/       sealed records + a         -> what was kept
                                    signature over them

**The field names and encodings are the sibling deployment's, not ours.**
`enrolment_code`, `device_public_key`, `challenge` as base64 of raw bytes, a
device id as base64 of sixteen bytes, a DER signature over the decoded
challenge. None of that is what these endpoints would have chosen on their
own; all of it is what the verifier app already speaks. A second dialect
would have bought nothing and cost every client a branch.

**`/connect/` is where a QR stops.** The symbol carries a server address, an
operation and a one-time code; the phone brings them here and is told which
endpoints to use and which device the operation concerns. Everything the
operation actually needs -- keys, trust lists, revocations -- travels over
HTTPS afterwards, because none of it fits in a symbol anyone can scan.

`/connect/` deliberately performs nothing and spends nothing: it is a read,
and what it returns is the same for every operator on the deployment. The
ticket is spent by the endpoint that does the work, which is what keeps "a
ticket authorises one operation, once" true.

`/challenge/` is unauthenticated because a nonce alone grants nothing: it is
worth something only to somebody who can sign it, and that needs a private
key this server has never held. Naming another device's id at `/keys/` gains
nothing either -- it only changes which public key the signature is checked
against.
"""

import base64
import json
import logging

from django.conf import settings
from django.core.exceptions import RequestDataTooBig
from django.db import IntegrityError
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from ovcrypto import devicelog

from accounts import credential_keys, device_log, throttle
from accounts import devices as device_service
from accounts.devices import KeysUnavailable, PairingError, UnknownDevice
from accounts.models import Device, DeviceTicket


logger = logging.getLogger(__name__)

#: A Secure Enclave P-256 SPKI is ~91 bytes and a signature 64. Anything
#: remotely near this is not one, and decoding megabytes to find that out is
#: work an unauthenticated caller should not be able to ask for.
MAX_FIELD_BYTES = 8 * 1024


def _body(request):
    try:
        data = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _b64(value, field):
    if not value:
        raise PairingError("%s is required." % field)
    if not isinstance(value, str) or len(value) > MAX_FIELD_BYTES:
        raise PairingError("%s is not usable." % field)
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        raise PairingError("%s is not valid base64." % field) from None


def _time_nonce(value):
    """The phone's own nonce for the signed time at this sync, or None from
    an older phone, which sends none."""
    if value is None:
        return None
    raw = _b64(value, "time_nonce")
    if len(raw) != devicelog.TIME_NONCE_BYTES:
        raise PairingError("time_nonce is not usable.")
    return raw


def _fail(message, status=400):
    return JsonResponse({"ok": False, "error": message}, status=status)


def _refuse_signature(device, endpoint):
    """403 with the unknown-device text, for a signature that did not verify.

    One text whether or not the id names a live device: a caller holding an
    old QR or an export could otherwise ask whether a phone had been revoked
    yet. It is also what to do either way -- a phone whose key this site does
    not hold comes back by resetting and pairing again, including a phone
    left with an older Enclave key. The server's log keeps which it was."""
    logger.info("device %s: %s signature did not verify", device.device_id,
                endpoint)
    return _fail(device_service.UNKNOWN_DEVICE, status=403)


def _ok(**payload):
    return JsonResponse(dict(ok=True, **payload))


@csrf_exempt
@require_POST
def device_connect(request):
    """Turn a scanned ticket into an operation and a set of endpoints.

    This is the whole reason a management QR is small: it names the operation
    and proves a human authorised it, and the phone comes here for everything
    else. Nothing is performed and the ticket is not spent -- the endpoint
    that does the work spends it.
    """
    data = _body(request)
    if data is None:
        return _fail("Malformed request body.")
    try:
        ticket = device_service.resolve_ticket(data.get("code", ""))
    except PairingError as exc:
        return _fail(str(exc))

    url = device_service.base_url(request)
    owner = ticket.user
    payload = {
        "v": device_service.PAYLOAD_VERSION,
        "purpose": ticket.purpose,
        "api_base": url,
        "endpoints": device_service.service_descriptor(url),
        "expires_at": ticket.expires_at.isoformat(),
        # Display only, exactly as in the QR: the phone shows whose account
        # it is about to act on.
        "for": owner.public_name[:60],
        # What the OWNER is entitled to, read live -- so a phone shows the
        # truth before it syncs rather than after. It is not a grant: a
        # public-tier owner is simply never sent the restricted epoch key.
        "restricted_tier": bool(owner.device_restricted_tier),
        # Which organizations the phone will work for (a pairing) or works
        # for (a sync or re-key), id and name -- for the confirmation sheet's
        # "Works for". Always present from this server: a server that sends
        # no key at all has no organizations, and the app behaves as it does
        # without them.
        "organizations": device_service.connect_organizations(ticket),
    }
    if ticket.device is not None:
        payload["device_id"] = device_service.device_id_wire(ticket.device)
        payload["label"] = ticket.device.label
    return _ok(**payload)


@csrf_exempt
@require_POST
def device_enrol(request):
    """Bind a Secure Enclave key to an account, using one ticket.

    Serves both a new phone (`enrol`) and one presenting a replacement key
    (`rekey`). Which of the two is settled by the ticket and by nothing the
    caller sends.
    """
    data = _body(request)
    if data is None:
        return _fail("Malformed request body.")
    try:
        device = device_service.enrol(
            data.get("enrolment_code", ""),
            _b64(data.get("device_public_key"), "device_public_key"),
            label=data.get("label", ""),
            attestation=data.get("attestation"),
            attest_key_id=data.get("attest_key_id", ""),
            challenge=data.get("challenge", ""),
            capabilities=data.get("capabilities"))
    except PairingError as exc:
        return _fail(str(exc))
    logger.info("device %s enrolled for user %s", device.device_id,
                device.owner_id)
    # restricted_tier is read from the OWNER, live. Returned here so the app
    # can say what this phone will be able to read before its first sync.
    return _ok(device_id=device_service.device_id_wire(device),
               label=device.label,
               restricted_tier=device.restricted_tier)


@csrf_exempt
@require_POST
def device_challenge(request):
    """A single-use challenge. Grants nothing on its own.

    Each one is a row, so they are limited per address, generously: an
    organization's phones may share one address."""
    refused = throttle.refuse_cross_site(request)
    if refused is not None:
        return refused
    if not throttle.allow(request, "device-challenge"):
        response = _fail("Too many requests from this network. Try again in a "
                         "few minutes.", status=429)
        response["Retry-After"] = "60"
        return response
    challenge = device_service.issue_challenge()
    return _ok(challenge=challenge.nonce)


@csrf_exempt
@require_POST
def device_keys(request):
    """The key bundle, for a device that can prove it is itself.

    A `code` may accompany the signature, and is how a sync a human asked for
    on the web is closed out: the ticket is spent so the QR cannot be scanned
    again, and the console can stop saying one is outstanding. It is NOT what
    authorises the sync -- the signature is, and a device syncing on its own
    schedule sends no code at all. So a stolen sync ticket buys nothing: it
    still takes the Enclave key to use it.
    """
    data = _body(request)
    if data is None:
        return _fail("Malformed request body.")
    try:
        # The challenge travels as the base64 string it was issued as, and
        # that string is what identifies it here. The SIGNATURE is over the
        # decoded bytes -- which is what a Secure Enclave key signs, and
        # what the sibling deployment already asks for.
        challenge = data.get("challenge", "")
        signed = _b64(challenge, "challenge") if challenge else b""
        signature = _b64(data.get("signature"), "signature")
        # The phone's own nonce, for the signed time below.
        time_nonce = _time_nonce(data.get("time_nonce"))
        # A phone that says "keys-context" signs the challenge behind a
        # context of its own; an older one signs it bare, until
        # DEVICE_REQUIRE_KEYS_CONTEXT says no phone does. Settled from the
        # request alone, before the device is looked up: after it, "too old"
        # would tell a live id from an unknown one.
        capabilities = data.get("capabilities")
        capabilities = capabilities if isinstance(capabilities, list) else []
        keys_context = "keys-context" in capabilities
        if not keys_context and settings.DEVICE_REQUIRE_KEYS_CONTEXT:
            return _fail("This app is too old for this site. Update it, then "
                         "sync again.", status=403)
        # Spend the nonce BEFORE checking the signature, so a wrong signature
        # costs the attempt too. Otherwise one captured nonce could fund a
        # grind at signatures for as long as it lives. And before the device
        # is looked up: everything the caller sent is judged first, so a live
        # id and an unknown one get the same answer to the same malformed
        # request.
        device_service.consume_challenge(challenge)
        device = device_service.device_for(data.get("device_id", ""))
        message = devicelog.keys_signed_bytes(signed) if keys_context else signed
        if not device_service.signature_ok(device, message, signature):
            return _refuse_signature(device, "keys")
        # App Attest, checked and recorded; refused only when required.
        if not device_service.check_assertion(device, data.get("assertion"),
                                              signed):
            return _fail("Device attestation was not accepted.", status=403)
        ticket = None
        if data.get("code"):
            # Only once the signature has verified: checked before it,
            # "That code is not valid." would tell a live id from an unknown
            # one, and say whether a code was that phone's open sync.
            ticket = device_service.resolve_ticket(
                data["code"], purpose=DeviceTicket.PURPOSE_SYNC)
            if ticket.device_id != device.pk:
                # A sync ticket names one phone. Honouring it for another
                # would let one device close out another's outstanding
                # request, which is the console lying about what happened.
                return _fail(device_service.TICKET_REFUSED)
        # A phone that understands issuer certificates says so, in each
        # request; the signer's switch gate counts on it.
        chain_capable = "issuer-chain" in capabilities
        blob, chains = device_service.build_bundle_and_chains(
            device, chain_capable=chain_capable)
        if ticket is not None:
            # After the bundle, not before: a ticket spent on a sync that then
            # failed would leave the operator with a QR that no longer works
            # and a phone that still has old keys.
            device_service.spend_ticket(ticket)
        if chain_capable:
            Device.objects.filter(pk=device.pk).update(
                issuer_chain_capable_at=timezone.now())
    except PairingError as exc:
        return _fail(str(exc), status=403 if isinstance(exc, UnknownDevice)
                     else 400)
    except KeysUnavailable as exc:
        # The server's fault: 503, which the phone retries with a new
        # challenge, never a 500.
        return _fail(str(exc), status=503)
    # Beside the bundle, not inside it: which organizations a phone works for
    # is a context it offers the operator, not anything a signature has to
    # protect -- it changes no key the phone holds and no verdict it reaches.
    # Read live at every sync, so a link ended on the web, or a membership
    # removed, leaves the phone's chooser at its next one.
    extra = {}
    if chains is not None:
        # Outside the signature, and passed on exactly as the signer returned
        # them: a certificate only ever raises trust in its key, and the
        # phone checks it against the CA it pins. The bundle carries their
        # digest, so a phone refuses it whole if one is dropped or changed
        # here.
        extra["issuer_chains"] = chains
    if time_nonce is not None:
        # Beside the bundle too: the server's time over this sync's nonce, the
        # one time a phone brings its clock's mark back to.
        signed_time = device_service.sync_time(device, time_nonce)
        if signed_time is not None:
            extra["time"] = signed_time
    return _ok(bundle=base64.b64encode(blob).decode(),
               device_id=device_service.device_id_wire(device),
               organizations=device_service.organizations_for(device), **extra)


# ---------------------------------------------------------------------------
# The device activity log
# ---------------------------------------------------------------------------

#: Short, like the revocation feed's: the statement is good for
#: `device_log.STATEMENT_DAYS`, and the only thing a cache delays is a phone
#: hearing that its key was retired.
LOG_KEY_MAX_AGE_SECONDS = 300


@require_GET
def device_log_key(request):
    """The public key a phone seals its activity log to, issuer-signed.

    Unauthenticated, like the revocation feed and for the same reason: it is
    a PUBLIC key, and what matters is that it cannot be substituted, which is
    the signature's job. The phone checks `sig` against the issuer keys it
    already pins, over `devicelog.key_statement_bytes`, before sealing a
    single record to it -- so a server impersonator cannot hand it a key
    whose private half it holds.

    503 while credential keys are unconfigured: with no issuer key nothing
    can be signed, and with no wrapping key the private half could not be
    stored. An unsigned key would be worse than none.
    """
    if not credential_keys.configured():
        return _fail("Device logs are not configured on this deployment.",
                     status=503)
    try:
        statement = device_log.key_statement()
    except Exception:
        logger.exception("device log key statement could not be built")
        return _fail("Device log key unavailable.", status=503)
    response = _ok(**statement)
    response["Cache-Control"] = "public, max-age=%d" % LOG_KEY_MAX_AGE_SECONDS
    return response


def _records(value):
    """The sealed records, decoded, or PairingError naming the limit broken.

    Capped before anything is decoded, for the reason MAX_FIELD_BYTES is: an
    unauthenticated caller does not get to make this server decode megabytes
    to find out they are not records.
    """
    limit = device_log.MAX_RECORDS
    size = device_log.MAX_RECORD_BYTES
    if not isinstance(value, list) or not value:
        raise PairingError(
            "records must be a list of 1 to %d sealed records." % limit)
    if len(value) > limit:
        raise PairingError(
            "records holds at most %d sealed records; send the rest in "
            "another upload." % limit)
    decoded = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            raise PairingError("records[%d] is not a base64 string." % index)
        if len(item) > (size + 2) // 3 * 4:
            raise PairingError("records[%d] is over the %d-byte limit for "
                               "one record." % (index, size))
        try:
            raw = base64.b64decode(item, validate=True)
        except Exception:
            raise PairingError(
                "records[%d] is not valid base64." % index) from None
        if len(raw) > size:
            raise PairingError("records[%d] is over the %d-byte limit for "
                               "one record." % (index, size))
        decoded.append(raw)
    return decoded


@csrf_exempt
@require_POST
def device_logs(request):
    """A phone's sealed activity records: open them, store them, say how far.

        POST {device_id, challenge, signature, records: [base64, ...]}
          -> {ok, through_seq, stored, duplicates, conflicts, unreadable,
              breaks}

    **The signature is NOT over the bare challenge.** Everywhere else in this
    dialect a device signs the decoded challenge, because that is all the
    request carries. Here it would bind nothing: anybody on the path could
    keep a valid signature and swap the records under it. So the Enclave key
    signs `devicelog.upload_signed_bytes` -- a context string, the decoded
    challenge, and a digest of exactly the records sent, in order. The
    context also means an upload signature can never be replayed at `/keys/`
    as a key request, nor a `/keys/` signature here.

    The rest is `/keys/`'s: one challenge, spent BEFORE the signature is
    checked, so a wrong signature costs the attempt too; an unknown, revoked
    or unparseable device gets one refusal.

    **Nothing in the batch is refused for one bad record** -- see
    `device_log.ingest`. Every number up to `through_seq` is held here now,
    and the phone may delete it.

    503, with nothing stored, in two cases that are the server's fault:
    credential keys unconfigured, answered before the challenge is spent;
    and log keys that will not unwrap, which is only found once the
    signature has been checked -- so that challenge IS spent, and the phone
    asks for another. Acknowledging records this deployment ought to have
    read would have the phone delete them.
    """
    if not credential_keys.configured():
        return _fail("Device logs are not configured on this deployment.",
                     status=503)
    try:
        data = _body(request)
    except RequestDataTooBig:
        # Django's own cap on a request body (DATA_UPLOAD_MAX_MEMORY_SIZE,
        # 2.5 MB by default) is below MAX_RECORDS full-size records. Answered
        # in the dialect, so the phone can send fewer at once rather than
        # meet an HTML error page.
        return _fail("The upload is larger than this server accepts in one "
                     "request; send fewer records at once.", status=413)
    if data is None:
        return _fail("Malformed request body.")
    try:
        challenge = data.get("challenge", "")
        signed = _b64(challenge, "challenge")
        signature = _b64(data.get("signature"), "signature")
        records = _records(data.get("records"))
        # Spent BEFORE the signature is checked, as `/keys/` does, and before
        # the device is looked up, so an id never changes the answer.
        device_service.consume_challenge(challenge)
        device = device_service.device_for(data.get("device_id", ""))
    except PairingError as exc:
        return _fail(str(exc), status=403 if isinstance(exc, UnknownDevice)
                     else 400)
    if not device_service.signature_ok(
            device, devicelog.upload_signed_bytes(signed, records),
            signature):
        return _refuse_signature(device, "logs")
    try:
        result = device_log.ingest(device, records)
    except device_log.QuotaExceeded:
        # The phone keeps every record and sends again later.
        response = _fail("This phone has sent as many activity records today "
                         "as this server keeps in a day; nothing more was "
                         "stored. Send again tomorrow.", status=429)
        response["Retry-After"] = "3600"
        return response
    except device_log.LogUnavailable:
        logger.exception("device log upload from %s could not be opened",
                         device.device_id)
        return _fail("Device logs cannot be opened on this deployment just "
                     "now; nothing was stored. Send again later.", status=503)
    except IntegrityError:
        # Two uploads of the same records crossing: the other one stored
        # them. Nothing here was kept, and the next attempt will find them
        # as duplicates.
        return _fail("Another upload from this device was being stored; "
                     "send again.", status=409)
    logger.info("device %s sent %d log record(s): %s", device.device_id,
                len(records), result)
    if result["through_seq"]:
        # Signed: only this lets the phone delete what it sent. None when
        # nothing can sign just now; the phone then keeps its copies.
        ack = device_log.acknowledgement(device, result["through_seq"], records)
        if ack is not None:
            result["ack"] = ack
    response = _ok(**result)
    response["Cache-Control"] = "no-store"
    return response
