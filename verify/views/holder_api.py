"""The two endpoints only a holder's phone uses.

    POST /api/v1/holder/register/   an idmanager assertion + an Enclave key
                                    + a signed challenge  -> device + credential
    POST /api/v1/holder/passes/     its two symbols + a signed challenge
                                    -> the card as an Apple Wallet pass

Everything after it is the verifier phone's ordinary API, unchanged:
`/api/v1/device/challenge/` and `/api/v1/device/keys/` for the key bundle,
`/api/v1/revocations/` for the feed. A holder's phone is a device like any
other, capped at the public tier -- see accounts/holders.py for why each part
is the shape it is.

`csrf_exempt` for the reason device_api.py gives: the caller is not a browser
and holds no session. The controls are the assertion, which only idmanager
can sign, and the challenge signature, which only the phone's Enclave can
produce.

**404 while unconfigured**, not a polite refusal. With no pinned idmanager
key the feature does not exist on this deployment, and an endpoint that said
"not enabled" would still be telling anybody asking that it could be.
"""

import base64
import json
import logging

from django.conf import settings
from django.db import IntegrityError
from django.http import JsonResponse
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from accounts import devices as device_service
from accounts import holders, wallet_pass
from accounts.devices import KeysUnavailable, PairingError, UnknownDevice
from accounts.models import Transaction

#: A holder phone the site has no live registration for: unknown, revoked or
#: never registered, alike.
HOLDER_UNKNOWN = ("This phone is not registered with this site. Register it "
                  "again from the app.")

from . import handoff


logger = logging.getLogger(__name__)

#: An Enclave SPKI is ~91 bytes and a DER signature ~72. The cap is the device
#: API's: nothing near it is one, and an unauthenticated caller does not get
#: to make this server decode megabytes to find that out.
MAX_FIELD_BYTES = 8 * 1024


def _fail(message, status=400):
    return JsonResponse({"ok": False, "error": message}, status=status)


def _b64(value, field, limit=MAX_FIELD_BYTES):
    if not value:
        raise PairingError("%s is required." % field)
    if not isinstance(value, str) or len(value) > limit * 4 // 3 + 4:
        raise PairingError("%s is not usable." % field)
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        raise PairingError("%s is not valid base64." % field) from None


@csrf_exempt
@require_POST
def holder_register(request):
    """Register a self-verified person's phone, and mint their credential.

    The order is the point:

    1. the challenge is spent BEFORE anything is checked, so a failed attempt
       still costs it -- the rule `/keys/` follows;
    2. the phone proves it holds the Enclave key it is registering;
    3. the assertion is checked, including that it names THAT key;
    4. the person and phone are recorded and the assertion spent, atomically;
    5. only then is a credential minted -- and a failure there leaves the
       phone registered, able to come back with a fresh check for one.
    """
    if not holders.enabled():
        return _fail("Not found.", status=404)

    try:
        data = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        data = None
    if not isinstance(data, dict):
        return _fail("Malformed request body.")

    try:
        public_key = _b64(data.get("device_public_key"), "device_public_key")
        challenge = data.get("challenge", "")
        signed = _b64(challenge, "challenge")
        signature = _b64(data.get("signature"), "signature")
        face = None
        if data.get("face"):
            face = _b64(data["face"], "face", limit=holders.MAX_FACE_BYTES)
    except PairingError as exc:
        return _fail(str(exc))

    if device_service._load_p256(public_key) is None:
        return _fail("That device public key is not usable.")
    # Behind this endpoint's context when the phone says so, bare until
    # HOLDER_REQUIRE_CONTEXT says no phone signs that way (`holders.
    # REGISTER_CONTEXT`). Decided from the request alone, as `/keys/` does.
    contexted = holders.says_context(data)
    if not contexted and settings.HOLDER_REQUIRE_CONTEXT:
        return _fail(holders.TOO_OLD, status=403)

    try:
        device_service.consume_challenge(challenge)
    except PairingError as exc:
        return _fail(str(exc))
    message = holders.REGISTER_CONTEXT + signed if contexted else signed
    if not _key_signed(public_key, message, signature):
        return _fail("Signature did not verify.", status=403)

    url = device_service.base_url(request)
    try:
        claims = holders.verify_assertion(
            data.get("assertion"), audience=url, device_public_key=public_key)
        user, device, created = holders.register(
            claims, public_key, label=str(data.get("label") or ""))
    except holders.HolderError as exc:
        return _fail(str(exc), status=403)
    except IntegrityError:
        # Lost a race on the assertion's jti: somebody else spent it first.
        return _fail(holders.REFUSED, status=403)

    if face is not None and not holders.face_matches(claims, face):
        # Not a refusal -- the registration is good. A face nobody vouched
        # for simply does not ride along into a credential.
        logger.info("holder face did not match its assertion; minting without")
        face = None
    credential = holders.mint_for_holder(claims, face=face)
    if credential is not None:
        txn = Transaction.objects.filter(
            transaction_id=credential["transaction_id"]).first()
        if txn is not None:
            # What the phone prints beside the two symbols when it draws the
            # card -- composed here, from the record, as the document's is.
            credential["card"] = handoff.holder_card(txn)

    logger.info("holder device %s %s for user %s", device.device_id,
                "registered" if created else "re-verified", user.pk)
    return JsonResponse({
        "ok": True,
        "v": 1,
        "created": created,
        "device_id": device_service.device_id_wire(device),
        "label": device.label,
        # Always false for a phone registered here, and returned so the app
        # can say so rather than discover it at its first sync.
        "restricted_tier": device.restricted_tier,
        "api_base": url,
        "endpoints": device_service.service_descriptor(url),
        "for": user.display_name[:60],
        "credential": credential,
        # Where this phone can collect its card as an Apple Wallet pass, or
        # null on a deployment with no Pass Type certificate -- so the app
        # draws no button rather than one that fails when pressed.
        "wallet_passes": (url + reverse("holder_passes")
                          if wallet_pass.configured() else None),
    })


@csrf_exempt
@require_POST
def holder_passes(request):
    """A holder's card as ONE Apple Wallet pass: the credential, their photo.

        POST {device_id, challenge, signature, credential, portrait_qr?}
          -> {"ok": true, "passes": [{"kind": "credential", "pkpass"}]}

    The same pass the card page gives -- see `wallet_pass.card_pass()` for
    what a photo on a pass costs and why it is tolerable. The phone sends both symbols back because
    they cannot be re-made -- every mint draws a fresh ephemeral key -- and
    this deployment deliberately keeps no copy (`IssuedCredential` stores no
    claim values). So they are PROVED instead (`holders.own_symbols()`):
    genuine, intact, unrevoked, this holder's, and a face the credential
    binds. Everything else the passes say comes from the stored transaction.

    The authorisation is `/keys/`'s: a fresh challenge, spent before
    anything is checked, signed by the Enclave key of a phone registered on
    idmanager's word. A list of passes inside JSON rather than a bare
    `.pkpass`, so the shape outlives which passes there are -- the phone
    adds whatever it is given as one Wallet sheet.

    404 while holders or Wallet passes are unconfigured, for the reason
    `holder_register` gives.
    """
    if not holders.enabled() or not wallet_pass.configured():
        return _fail("Not found.", status=404)

    try:
        data = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        data = None
    if not isinstance(data, dict):
        return _fail("Malformed request body.")

    try:
        challenge = data.get("challenge", "")
        signed = _b64(challenge, "challenge")
        signature = _b64(data.get("signature"), "signature")
        # Behind this endpoint's context, or bare until HOLDER_REQUIRE_CONTEXT
        # (`holders.PASSES_CONTEXT`): decided before the device is looked up,
        # so "too old" says nothing about an id.
        contexted = holders.says_context(data)
        if not contexted and settings.HOLDER_REQUIRE_CONTEXT:
            return _fail(holders.TOO_OLD, status=403)
        # Spent BEFORE the signature is checked, as `/keys/` does, so a wrong
        # signature costs the attempt too -- and before the device is looked
        # up, so an id never changes the answer.
        device_service.consume_challenge(challenge)
        device = device_service.device_for(data.get("device_id", ""))
    except UnknownDevice:
        # Not the verifier app's words: a holder phone registers through its
        # own app, never with a code from the site.
        return _fail(HOLDER_UNKNOWN, status=403)
    except PairingError as exc:
        return _fail(str(exc), status=400)
    message = holders.PASSES_CONTEXT + signed if contexted else signed
    if not device_service.signature_ok(device, message, signature):
        # The same answer as an unknown device; the log says which.
        logger.info("holder device %s: signature did not verify",
                    device.device_id)
        return _fail(HOLDER_UNKNOWN, status=403)
    if not holders.is_holder_device(device):
        # A verifier phone an operator paired holds nobody's card.
        return _fail(holders.NOT_YOURS, status=403)

    try:
        issued, face = holders.own_symbols(
            device, data.get("credential"), data.get("portrait_qr") or None)
    except holders.HolderError as exc:
        return _fail(str(exc), status=403)
    except KeysUnavailable as exc:
        return _fail(str(exc), status=503)

    # `face` is set only when `own_symbols()` proved it is the face the
    # credential binds; it becomes the pass's photo.
    blob = wallet_pass.for_holder(
        handoff.holder_card(issued.transaction),
        message=data["credential"].strip(), face=face,
        expires_at=issued.expires_at.isoformat())
    if blob is None:
        return _fail("The pass could not be built.", status=503)

    logger.info("holder device %s collected its wallet pass%s",
                device.device_id, "" if face is not None else " (no photo)")
    response = JsonResponse({"ok": True, "v": 1, "passes": [
        {"kind": "credential", "pkpass": base64.b64encode(blob).decode()}]})
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    return response


def _key_signed(public_key_der, message, signature_der):
    """Did the key being registered sign this message?

    `devices.signature_ok()` asks the same of a key already on record; this
    asks it of the one arriving, so both take a DER signature over the
    message -- the decoded challenge, behind `holders.REGISTER_CONTEXT` when
    the phone says so -- which is what `SecKeyCreateSignature` produces.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    key = device_service._load_p256(public_key_der)
    if key is None:
        return False
    try:
        key.verify(signature_der, message, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True
