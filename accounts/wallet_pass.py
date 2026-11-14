"""The Apple Wallet pass for a verification: ONE pass, the credential in its
barcode and the holder's photo as its picture.

It is the same pass however it reaches the holder -- from the card page after
a counter verification (`from_handoff()`), or from idmanager after a
self-verification (`for_holder()`) -- because both are `card_pass()`. Which
words are on it differs only where the verification itself did.

A `.pkpass` is a zip of `pass.json`, its images, a `manifest.json` of SHA-1
digests, and a detached PKCS#7 signature over that manifest made with an
Apple **Pass Type ID** certificate. Nothing here is Apple-specific magic --
it is that zip, built in that order.

**Read `verify/views/handoff.py` before wiring this to the web.** The card
hand-off is the only endpoint in this app that serves an identity without a
session, and a pass is the same identity in a more durable container: the
token's five minutes protect the *fetch*, and a pass, once added, sits in the
holder's wallet indefinitely. Build one only from a hand-off's **stored**
payload, which is already demo-masked and already narrowed to the
organization's displayed fields. Never from anything a request carried.

**The barcode is a string, and iOS draws it.** `pass.json` gives you the
format, the message and its encoding -- there is no error-correction setting,
so the density trade this app makes everywhere else (level Q, sized against a
0.4 mm module floor) is not available here. iOS picks. Two consequences:

* the message is **uppercased**, because the alphanumeric charset has no
  lowercase and a lowercase UUID would drop the whole symbol into byte mode,
  costing about 45%% of the capacity -- the same rule `drawQR()` follows in
  `document.html`, for the same reason;
* whether a ~963-character credential is legible from a wallet is a
  **measurement on a handset**, not something to settle here. 113 modules
  needs 45.2 mm to clear this project's floor, and an iPhone 15 is 65.1 mm
  across 393 points. It is marginal. `barcode_report()` prints the
  numbers.

Signing needs three files, and none of them belongs in the repository or in
`db.sqlite3` -- `deploy.sh` rsyncs with `--delete` and the database rides the
off-site database backups. Keep them outside the application directory, mode 0600,
paths in settings, exactly as `CREDENTIAL_ISSUER_KEY_PATH` already is.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from django.conf import settings

logger = logging.getLogger(__name__)

#: The QR alphanumeric charset. A message outside it falls back to byte mode.
ALNUM = set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:")

#: What a symbol of N modules must measure to clear the module floor this
#: project enforces everywhere else. Kept here so the report cannot drift.
MIN_MODULE_MM = 0.4

#: iPhone 15: 65.1 mm of screen across 393 points.
MM_PER_POINT = 65.1 / 393.0


def modules_for(message):
    """QR module count for the message AS IT WILL SHIP, or None.

    The uppercased form, because that is what `build_pass_json()` puts in the
    barcode. `ovcrypto.qrsize` holds an alphanumeric table only, which is the
    right one here and the wrong one for anything outside that charset -- so
    a message still not alphanumeric after uppercasing gets no answer rather
    than a wrong one.
    """
    from ovcrypto import qrsize

    shipped = message.upper()
    if not all(c in ALNUM for c in shipped):
        return None
    try:
        return qrsize.modules(qrsize.version_for(len(shipped), "Q"))
    except qrsize.TooLarge:
        return None


def barcode_report(message):
    """What this message costs on a phone screen. Numbers, not opinions."""
    shipped = message.upper()
    modules = modules_for(message)
    if modules is None:
        if not all(c in ALNUM for c in shipped):
            return ("%d chars: not alphanumeric even uppercased, so iOS draws "
                    "it in byte mode at about 45%% less capacity" % len(shipped))
        return "%d chars: past QR capacity at level Q" % len(shipped)
    mm = modules * MIN_MODULE_MM
    return ("%d chars, alphanumeric -> %d modules; needs %.1f mm to clear the "
            "%.1f mm floor -- %.0f pt of an iPhone 15's 393 pt screen"
            % (len(shipped), modules, mm, MIN_MODULE_MM, mm / MM_PER_POINT))


def build_pass_json(*, pass_type_id, team_id, serial, organization_name,
                    description, barcode_message, holder, card_number,
                    digital_id, transaction_type, location, verified_at,
                    alt_text=None, expiration_date=None):
    """The `pass.json` for one verification.

    A `generic` pass: the holder is the primary field, the two ID numbers are
    secondary, and the transaction's own facts are auxiliary -- the same
    split the printed card makes, so the two objects read alike.

    `expiration_date` (ISO 8601) is the credential's own expiry, so Wallet
    marks the pass expired when the credential is.

    No header. A generic pass with a square barcode shows at most four
    secondary and auxiliary fields combined (Apple's limit), and these four
    fill it; the header once named which of two passes this was, and there
    is one.
    """
    fields = lambda *rows: [
        {"key": key, "label": label, "value": value}
        for key, label, value in rows if value
    ]
    pass_json = {
        "formatVersion": 1,
        "passTypeIdentifier": pass_type_id,
        "teamIdentifier": team_id,
        # The transaction id, so a pass is one verification and re-adding it
        # replaces rather than duplicates.
        "serialNumber": str(serial),
        "organizationName": organization_name,
        "description": description,
        "backgroundColor": "rgb(255, 255, 255)",
        "foregroundColor": "rgb(20, 32, 44)",
        "labelColor": "rgb(0, 82, 155)",
        "generic": {
            "primaryFields": fields(("holder", "Verified", holder)),
            "secondaryFields": fields(
                ("card", "National ID card number", card_number),
                ("digital", "Digital National ID", digital_id)),
            "auxiliaryFields": fields(
                ("type", "Transaction", transaction_type),
                ("location", "Location", location)),
            "backFields": fields(
                ("when", "Verified at", verified_at),
                ("txn", "Transaction", str(serial))),
        },
        "barcodes": [{
            "format": "PKBarcodeFormatQR",
            # UPPERCASE: see the module docstring. iOS chooses the encoding
            # mode from the content, and lowercase costs about 45% capacity.
            "message": barcode_message.upper(),
            "messageEncoding": "iso-8859-1",
            "altText": alt_text or "",
        }],
    }
    if expiration_date:
        pass_json["expirationDate"] = expiration_date
    return pass_json


def _manifest(files):
    return {name: hashlib.sha1(blob).hexdigest() for name, blob in files.items()}


def sign_manifest(manifest_bytes, *, certificate_pem, private_key_pem,
                  wwdr_pem, password=None):
    """The detached PKCS#7 signature Apple checks, in DER.

    `add_certificate(wwdr)` is not decoration: the pass carries the chain up
    to Apple's intermediate, and a pass signed without it is refused on the
    device with no useful message.

    **`Binary` is not optional either, and it is the subtler of the two.**
    Without it `cryptography` applies S/MIME text canonicalisation and signs
    the manifest with its newlines rewritten to CRLF -- so the digest covers
    bytes that are not the bytes in the zip. Caught here by verifying the
    signature back with OpenSSL, which said `digest failure`; on a handset it
    is a pass that will not add, and iOS does not say why.
    """
    certificate = x509.load_pem_x509_certificate(certificate_pem)
    wwdr = x509.load_pem_x509_certificate(wwdr_pem)
    key = serialization.load_pem_private_key(private_key_pem, password=password)
    return (pkcs7.PKCS7SignatureBuilder()
            .set_data(manifest_bytes)
            .add_signer(certificate, key, hashes.SHA256())
            .add_certificate(wwdr)
            .sign(serialization.Encoding.DER,
                  [pkcs7.PKCS7Options.DetachedSignature,
                   pkcs7.PKCS7Options.Binary]))


def build(pass_json, images, *, certificate_pem, private_key_pem, wwdr_pem,
          password=None):
    """The finished `.pkpass` bytes.

    `images` maps a pass file name to its bytes; `icon.png` is REQUIRED --
    a pass without one is rejected on the device rather than shown badly.
    """
    if "icon.png" not in images:
        raise ValueError("a pass without icon.png is rejected by iOS")

    files = {"pass.json": json.dumps(pass_json, indent=2).encode("utf-8")}
    files.update(images)

    manifest = json.dumps(_manifest(files), indent=2).encode("utf-8")
    files["manifest.json"] = manifest
    files["signature"] = sign_manifest(
        manifest, certificate_pem=certificate_pem,
        private_key_pem=private_key_pem, wwdr_pem=wwdr_pem, password=password)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, blob in files.items():
            zf.writestr(name, blob)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# The hand-off, as a pass
# ---------------------------------------------------------------------------

#: A pass with no icon is rejected on the device rather than shown badly.
ICON_SIZES = ((29, "icon.png"), (58, "icon@2x.png"), (87, "icon@3x.png"))

#: #00529B, the application's own primary, in the BGRA cv2 wants.
MARK_BGR = (155, 82, 0)


def _paths():
    return {
        "pass_type": getattr(settings, "WALLET_PASS_TYPE_ID", ""),
        "team": getattr(settings, "WALLET_TEAM_ID", ""),
        "cert": getattr(settings, "WALLET_CERT_PATH", ""),
        "key": getattr(settings, "WALLET_KEY_PATH", ""),
        "wwdr": getattr(settings, "WALLET_WWDR_PATH", ""),
    }


def configured():
    """Whether this deployment can sign a pass at all.

    All five settings, and the three files actually readable. Asked by the
    card page BEFORE it draws the button, so an unconfigured deployment shows
    no button rather than one that fails when pressed.
    """
    values = _paths()
    if not all(values.values()):
        return False
    return all(os.path.isfile(os.path.expanduser(values[name]))
               for name in ("cert", "key", "wwdr"))


def _mark(size):
    """A plain square mark, for the icon slots."""
    import cv2
    import numpy as np

    img = np.zeros((size, size, 3), dtype=np.uint8)
    img[:, :] = MARK_BGR
    ok, buf = cv2.imencode(".png", img)
    return buf.tobytes() if ok else b""


# ---------------------------------------------------------------------------
# The card page's pass
# ---------------------------------------------------------------------------

#: What the card page serves.
PASS_CONTENT_TYPE = "application/vnd.apple.pkpass"


def _symbol_image(text):
    """The image bytes inside a portrait symbol -- `CL03F1:` or `CL03F2:` --
    or None. Never raises: a symbol that will not read costs the photo."""
    try:
        from accounts import credentials
        from ovcrypto import base45

        magic, _id, body = str(text or "").strip().split(":", 2)
        if magic not in credentials.PORTRAIT_MAGICS or not body:
            return None
        return base45.decode(body)
    except Exception:
        return None


def from_handoff(payload):
    """The hand-off as Wallet takes it -- `(bytes, content type, file name)`
    -- or None.

    **The holder's pass, exactly** (`card_pass()`): the credential in its
    one barcode and the face as its picture: the pass idmanager gives.

    **The photo is the portrait SYMBOL's image, never the card's `face`.**
    Those bytes are exactly what the credential's `portrait_hash` covers,
    minted in the same request as the credential and stored with it, so the
    picture is the face this deployment bound to this document -- already
    cropped, and already resampled away when the operator was presenting.
    The `face` field is the same picture wrapped for a browser; taking the
    symbol's bytes means there is only one thing it could be.

    **Everything on it comes from the STORED payload.** That payload was
    composed where there was a session -- already narrowed to the
    organization's displayed fields, already demo-masked. Recomposing any of
    it here would be a second opinion about what this verification was, and
    the browser asking for the pass is the one being masked.

    **Never raises**, the rule `_mint_credential()` and `open_handoff()`
    follow, and it degrades in one direction only: no credential, no pass;
    no portrait symbol, or one that will not decode, and the pass goes
    without its photo.
    """
    try:
        payload = payload or {}
        if not payload.get("qr"):
            # No credential, no pass. The card IS the offline half; without
            # it there is nothing here a wallet could check.
            return None
        blob = card_pass(payload, message=payload["qr"],
                         face=_symbol_image(payload.get("portrait_qr")),
                         expires_at=payload.get("expires_at") or "")
    except Exception:
        logger.exception("could not build a wallet pass")
        return None
    if blob is None:
        return None
    return blob, PASS_CONTENT_TYPE, "Verification Card.pkpass"


# ---------------------------------------------------------------------------
# The pass: the credential, and the holder's photo
# ---------------------------------------------------------------------------

#: Wallet shows a generic pass's thumbnail at up to 90 x 90 pt.
PHOTO_PT = 90


def _png_photo(image, longest):
    """PNG bytes for a portrait symbol's image, `longest` px on its long
    side, or None. **Never raises**: a face that will not decode costs the
    pass its photo and nothing else.

    Aspect kept, never cropped or squashed -- the portrait is already cropped
    to the head. Read by `credentials.decode_portrait()`, the one decoder for
    both forms a portrait symbol carries: the WebP of `CL03F1:`, and the
    compact AVIF of `CL03F2:`, which is not a file anything can open until the
    container is rebuilt around it -- so handing it to Pillow as it stands
    would cost every AVIF holder their photo, silently.
    """
    try:
        import cv2

        from accounts import credentials

        gray = credentials.decode_portrait(bytes(image))
        if gray is None:
            return None
        img = cv2.cvtColor(gray, cv2.COLOR_GRAY2BGR)
        height, width = img.shape[:2]
        scale = longest / max(height, width)
        img = cv2.resize(img, (max(1, round(width * scale)),
                               max(1, round(height * scale))),
                         interpolation=(cv2.INTER_AREA if scale < 1
                                        else cv2.INTER_CUBIC))
        ok, buf = cv2.imencode(".png", img)
        return buf.tobytes() if ok else None
    except Exception:
        logger.warning("holder pass: the face could not be transcoded",
                       exc_info=True)
        return None


def card_pass(card, *, message, face=None, expires_at=""):
    """ONE pass -- the credential and the holder's photo -- or None.

    The credential is the pass's one barcode and the face its thumbnail, at
    1x, 2x and 3x. A pass shows exactly one barcode, and one barcode cannot
    carry both symbols (measured when the pass was built), so the face
    rides as a picture.

    **What that costs, plainly:** no camera checks a photo on a pass, and
    anyone with an Apple developer account can sign one. So the photo is
    only ever a face this deployment bound to the credential by
    `portrait_hash` -- `from_handoff()` takes the stored portrait symbol's
    bytes, `holders.own_symbols()` proves the holder's before
    `for_holder()` -- and the hash-checked portrait symbol stays on the card
    image, on the printed document and in idmanager, where the verifier app
    checks it.

    `card` carries the words -- `payload_from_rows()`'s keys -- and
    `message` the credential, both chosen by the caller; nothing else
    reaches the pass. The serial is the transaction id, so re-adding a pass
    updates it rather than duplicating it; `expires_at` is the credential's
    expiry. **Never raises**: a face that will not decode costs the photo,
    and anything else costs the pass.
    """
    try:
        if not configured() or not message:
            return None
        transaction_id = card.get("transaction_id") or ""
        if not transaction_id:
            return None
        values = _paths()
        read = lambda name: open(os.path.expanduser(values[name]), "rb").read()

        pass_json = build_pass_json(
            pass_type_id=values["pass_type"],
            team_id=values["team"],
            serial=transaction_id,
            organization_name=card.get("organization") or "",
            description="National ID verification",
            barcode_message=message,
            holder=card.get("holder") or "",
            card_number=card.get("card_number") or "",
            digital_id=card.get("digital_id") or "",
            transaction_type=card.get("transaction_type") or "",
            location=card.get("location") or "",
            verified_at=card.get("verified_at") or "",
            alt_text=transaction_id,
            expiration_date=expires_at or None)

        images = {name: _mark(size) for size, name in ICON_SIZES}
        if face:
            for scale, name in ((1, "thumbnail.png"), (2, "thumbnail@2x.png"),
                                (3, "thumbnail@3x.png")):
                photo = _png_photo(face, PHOTO_PT * scale)
                if photo:
                    images[name] = photo

        return build(pass_json, images,
                     certificate_pem=read("cert"),
                     private_key_pem=read("key"),
                     wwdr_pem=read("wwdr"))
    except Exception:
        logger.exception("could not build a wallet pass")
        return None


def for_holder(card, *, message, face=None, expires_at=""):
    """A holder's card -- `card_pass()`, with the face `holders.own_symbols()`
    proved and the card `handoff.holder_card()` composed from the stored
    transaction. The same pass the card page gives."""
    return card_pass(card, message=message, face=face, expires_at=expires_at)
