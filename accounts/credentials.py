"""Mint the offline-verifiable credential that rides in the document QR.

The wire format, the crypto and the sizing all come from `ovcrypto/`, which is
a VERBATIM copy of the module of the same name in the sibling OfflineVerifier
project. Keep it verbatim. `vectors/vectors.json` came with it and is what
proves the copy has not drifted -- a credential this app mints has to open on
a phone running that project's Swift verifier, and the two implementations
agree only for as long as both pass the same vectors.

Nothing here edits the vendored copy. Where this app needs to behave
differently -- notably the signing key, which OfflineVerifier refuses to hold
in-process -- it adds its own class beside it rather than patching theirs.

What goes in the credential:

* the PUBLIC tier carries provenance -- which organization, which location,
  when, and the transaction UUID as `doc_number`, so an offline read names
  the same record the online QR resolves to.
* the RESTRICTED tier carries the person, and carries exactly the fields the
  organization SHOWS on its document. The QR is handed to the holder on that
  document; it says what the page says, and nothing the organization has
  chosen not to show.
"""

from __future__ import annotations

import hashlib
import logging
import os
import uuid

from ovcrypto import attachments as attachments_mod
from ovcrypto import base45, issuer as issuer_mod
from ovcrypto import keystore, qrsize, wire

from accounts import everify_fields


logger = logging.getLogger(__name__)


class CredentialError(Exception):
    """Minting failed. The document still prints -- see mint_for_transaction()."""


#: Claim values are capped, as in OfflineVerifier's own issuer. A QR that does
#: not fit is not a smaller problem than a missing field.
MAX_TEXT = 96

#: How wide the stamp has to be printed. The payload decides the QR version;
#: below 0.4 mm per module a laser print photographed under field lighting
#: stops scanning, so this is a physical minimum, not a preference.
#:
#: QR version 26 carrying the whole default display set -- every field, with
#: the longest values eVerify returns -- needs 48.4 mm. The stamp prints 48.8.
#:
#: The spare 0.4 mm is not decoration. A stamp sized to exactly the measured
#: minimum lands on the wrong side of the floor in binary floating point --
#: 46.8 / 117 modules is 0.39999999999999997 -- and reports itself unscannable.
#: Size the stamp to clear the floor, never to meet it.
#:
#: The capacity table is `qrsize.CAPACITY_ALNUM["Q"]`, checked against a
#: standards encoder. A table that is too generous sizes every stamp for
#: fewer modules than the symbol actually has -- which is to say, below the
#: floor, on paper, silently.
#:
#: Size it against the longest values eVerify returns: the two address
#: fields, which are displayed by default. A fixture that stops at "Place of
#: Birth" never reaches them, and sizing off a convenient sample passes its
#: own test and fails in the field.
#:
#: The face is NOT in here. It does not fit at any quality worth printing and
#: rides its own symbol; see PORTRAIT_STAMP_MM below.
#:
#: `test_it_fits_the_stamp_the_document_prints` mints the full set with long
#: real values and fails if it stops fitting, which is the only thing keeping
#: this honest.
STAMP_MM = 48.8

#: ---------------------------------------------------------------------------
#: The printed card: how big one canvas pixel is on paper
#: ---------------------------------------------------------------------------
#:
#: The document prints the SAME card the holder saves to their phone --
#: `static/cardcanvas.js` draws both -- turned ninety degrees above the cut
#: line. So the printed size is not a layout decision made in CSS; it is this
#: one number, and everything about the card follows from it.
#:
#: 1080 x 2700 canvas pixels at 0.063 mm each is 68.04 x 170.10 mm, which
#: fits the 190 mm sheet on its side, and a QR module of 8 canvas pixels lands
#: at 0.504 mm -- comfortably over the 0.4 mm floor, and LARGER than the
#: 0.432 mm the old CSS card managed at 48.8 mm across 113 modules.
#:
#: Chosen from three stops that all fit and all decode (0.054 / 0.063 /
#: 0.068). 0.063 is the first whose ID numbers print at 5.4 pt, matching the
#: smallest type the card printed before it; 0.054 saves 10 mm of sheet and
#: sets them at 4.6. If a test print says the captions are too small, 0.068 is
#: one number away and still fits.
#:
#: `test_the_printed_card_clears_the_module_floor` is what stops anybody
#: shrinking this without noticing the symbols went under the floor.
CARD_PRINT_MM_PER_PX = 0.063

#: The canvas `cardcanvas.js` draws, and the module it draws a symbol at.
#: Mirrored here rather than parsed out of the JavaScript, and pinned to it by
#: `test_the_card_geometry_matches_the_renderer`: two numbers that must agree
#: are better asserted than inferred.
CARD_CANVAS_W_PX = 1080
CARD_CANVAS_H_PX = 2700
CARD_MODULE_PX = 8

#: What comes out of the printer. The long side lies ACROSS the sheet.
CARD_PRINT_W_MM = round(CARD_CANVAS_W_PX * CARD_PRINT_MM_PER_PX, 2)
CARD_PRINT_H_MM = round(CARD_CANVAS_H_PX * CARD_PRINT_MM_PER_PX, 2)

#: The floor this must clear, never meet -- the same rule STAMP_MM follows.
CARD_PRINT_MODULE_MM = CARD_MODULE_PX * CARD_PRINT_MM_PER_PX

#: The typed person tags 0x40-0x49 are no longer emitted. They duplicated the
#: ordered T_FIELDS list, and two of them -- ISO 5218 sex and days-since-epoch
#: birth date -- were exactly the codes a reader cannot expand. `wire.py` still
#: defines them, so credentials that carry them decode unchanged.

#: What this app issues. One code, registered with the verifier fleet; it is
#: not verify's per-organization transaction type, which is a business
#: category and changes without anybody telling a phone.
DOC_TYPE_VERIFICATION = 2


# ---------------------------------------------------------------------------
# The signing key
# ---------------------------------------------------------------------------

class PemSigningBackend:
    """An issuer key read from a PEM file on private storage.

    OfflineVerifier's `keystore.LocalSigningBackend` refuses to run under
    `OV_ENV=production` -- deliberately, because a private key the web process
    can read is one an application-level compromise walks away with. This app
    has chosen to hold a PEM anyway, so it says so in its own class instead of
    editing that guard out of a vendored file, where the next re-sync would
    silently restore it.

    What is actually done about the risk:

    * the file lives OUTSIDE the application directory, so `deploy.sh`'s
      `rsync --delete` cannot touch it and a redeploy cannot replace it;
    * it is not in the database, so it does not ride the off-site database backups
      that `db.sqlite3` does;
    * `from_path` refuses a file another account can open: a group or
      other bit, or on Windows an access list naming anyone but this
      account, SYSTEM and Administrators;
    * rotation is by issuing a new key id and dating the old one out, never by
      overwriting the file under a running process.
    """

    def __init__(self, private_key, key_id: int):
        self.private_key = private_key
        self.key_id = key_id
        self.sig_alg = keystore.SIG_ECDSA_P256_SHA256

    @classmethod
    def from_path(cls, path: str, key_id: int) -> "PemSigningBackend":
        from cryptography.hazmat.primitives import serialization

        if not path:
            raise CredentialError("No issuer key path configured.")
        if not os.path.exists(path):
            raise CredentialError("Issuer key not found at %s." % path)
        try:
            keystore._require_private_mode(path)
        except keystore.SigningError as exc:
            raise CredentialError(str(exc)) from None
        with open(path, "rb") as handle:
            key = serialization.load_pem_private_key(handle.read(),
                                                     password=None)
        return cls(key, key_id)

    def sign(self, message: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

        return keystore.der_to_raw_p256(
            self.private_key.sign(message, ECDSA(hashes.SHA256())))

    def public_key_der(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self.private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)


# ---------------------------------------------------------------------------
# Claims
# ---------------------------------------------------------------------------

def _text(value):
    value = ("" if value is None else str(value)).strip()
    return value[:MAX_TEXT]


def build_claims(rows, *, organization, location_code, document_uuid,
                 document_hash, issued_at, expires_at, field_rows=None,
                 transaction_type="", operator_name="", location_name="",
                 portrait=None, credential_id=None, issuer_name=None):
    """(public, restricted) TLV claim dicts for one verification.

    `rows` are the carried verification rows -- each with `field` (eVerify's
    key) and `value`. `field_rows` is the organization's field configuration;
    a field reaches the credential only where that organization SHOWS it, so
    the QR carries exactly what the page carries -- less the computed fields,
    which `mint()` leaves out before they get here.

    **Names, not codes.** `issuer_id` and `issuer_location` carry the full
    names, not the short codes `Organization.issuer_code` and `Location.code`,
    although the names are long and a signed credential outlives a rename:
    a person reading a verified document on a phone needs to see "Philippine
    Statistics Authority", not "PSA", and a code the reader cannot expand is
    worth nothing to them. The rename risk is real and accepted -- the
    credential records what the organization was called when it was issued,
    which is arguably the more truthful answer.

    **The person's details travel as an ordered list, not as typed tags.**
    `T_FIELDS` carries (label, value) in document order, so the phone renders
    the same rows in the same sequence as the paper. The typed tags 0x40-0x49
    are no longer emitted: they duplicated the list, and two of them --
    ISO 5218 sex and days-since-epoch birth date -- are precisely the codes
    this is meant to stop carrying. They remain defined so credentials that
    carry them still decode.

    `credential_id` is chosen by the caller when it must be recorded before
    the signature is asked for (`accounts/minting.py`); `issuer_name`
    replaces the organization's name with the one its signing certificate
    certifies, which is the only name an organization key may sign.
    """
    shown = None
    if field_rows is not None:
        shown = {row["key"] for row in everify_fields.document_rows(field_rows)}

    public = {
        wire.T_CREDENTIAL_ID: (credential_id or uuid.uuid4()).bytes,
        wire.T_DOC_TYPE: bytes([DOC_TYPE_VERIFICATION]),
        wire.T_DOC_NUMBER: str(document_uuid).encode("utf-8"),
        wire.T_DOCUMENT_HASH: document_hash,
        # The transaction's own moment. The document prints it, the phone
        # shows it, and it is the same instant the credential was minted.
        wire.T_ISSUED_AT: wire.u32(int(issued_at.timestamp())),
        wire.T_EXPIRES_AT: wire.u32(int(expires_at.timestamp())),
    }

    issuer = _text(issuer_name if issuer_name is not None
                   else (getattr(organization, "name", "") or ""))
    if issuer:
        public[wire.T_ISSUER_ID] = issuer.encode("utf-8")
    # The location's name, falling back to its code only when there is no
    # name to give -- a code beats an empty row, but only just.
    where = _text(location_name) or _text(location_code)
    if where:
        public[wire.T_ISSUER_LOCATION] = where.encode("utf-8")
    kind = _text(transaction_type)
    if kind:
        public[wire.T_TRANSACTION_TYPE] = kind.encode("utf-8")
    who = _text(operator_name)
    if who:
        public[wire.T_OPERATOR] = who.encode("utf-8")

    restricted = {}

    # Every displayed field, in the document's order, label and value as the
    # page shows them. The face is excluded: it does not fit in this symbol
    # and rides its own -- bound to this credential by the hash below.
    pairs = []
    for row in rows:
        field = everify_fields.field_of(row)
        if not field or field in everify_fields.NOT_LOGGABLE:
            continue
        if shown is not None and field not in shown:
            continue
        value = _text(row.get("value"))
        if not value:
            continue
        label = _text(row.get("key")) or field
        pairs.append((label, value))
    if pairs:
        restricted[wire.T_FIELDS] = wire.encode_fields(pairs)

    # Ties the portrait symbol to this credential. Without it the two QRs are
    # independent, and a document could be presented with somebody else's
    # face beside it -- both scanning perfectly.
    if portrait:
        restricted[wire.T_PORTRAIT_HASH] = hashlib.sha256(portrait).digest()

    return public, restricted


def document_digest(rows):
    """SHA-256 over what the document says, for T_DOCUMENT_HASH.

    Field and value, in the order they are carried, so the hash changes if any
    printed value changes or if two of them are swapped. It deliberately does
    NOT cover the labels: renaming a field on the document is a presentation
    decision and must not invalidate a credential already in someone's hand.
    """
    digest = hashlib.sha256()
    for row in rows:
        digest.update(everify_fields.field_of(row).encode("utf-8"))
        digest.update(b"\x00")
        digest.update(str(row.get("value", "")).encode("utf-8"))
        digest.update(b"\x00")
    return digest.digest()


# ---------------------------------------------------------------------------
# Minting
# ---------------------------------------------------------------------------

def compose(document_uuid, qr_string):
    """`UUID:CL03:<base45>` -- one QR, the UUID readable in the clear.

    A QR carries one string, and the credential is ciphertext, so there is no
    way for a plain reader to see inside it. Putting the UUID in front is what
    keeps the online path working from any camera: the text it shows begins
    with the transaction id. The verifier app splits on the `CL03:` marker
    (`split_stamp`).

    Uppercase because the whole string must stay inside the QR ALPHANUMERIC
    charset, which has no lowercase -- byte mode would cost ~45% of the
    capacity budget and push the stamp past 45 mm.
    """
    return "%s:%s" % (str(document_uuid).upper(), qr_string)


def split_stamp(text):
    """`(front, marker, base45)` of a stamp, split at its first `CL03:` when
    a `:` precedes it, or None when there is none.

    The first one, as the app reads it: Base45 can spell the marker, so a
    body may hold `:CL03:` by chance; the front is a UUID, which cannot.
    """
    at = text.find(":" + wire.QR_PREFIX)
    if at < 0:
        return None
    return text[:at], wire.QR_PREFIX, text[at + 1 + len(wire.QR_PREFIX):]


def mint(rows, *, organization, location_code, document_uuid, epoch_keys,
         signer, issued_at, expires_at, field_rows=None, transaction_type="",
         operator_name="", location_name="", portrait=None,
         credential_id=None, issuer_name=None, attachments=None):
    """Sign, encrypt and render one credential. Returns a dict.

    `attachments` are `ovcrypto.attachments.Attachment`s, each in the tier
    its caller chose. What does not ride inline is split across part symbols,
    returned as `attachment_parts` for the page to print -- within
    CREDENTIAL_MAX_QR_CODES, the credential and its portrait counted.

    `portrait` is the rendered portrait image, when the document carries one.
    Only its hash goes in here -- the image itself does not fit and rides its
    own symbol, which `mint_portrait` builds.

    The computed fields are the one thing the page prints and the credential
    does not carry, in the field list or the document hash: an age is true
    for a year, a credential is shown for longer, and the date of birth it
    came from is carried already.
    """
    rows = [row for row in rows
            if everify_fields.field_of(row) not in everify_fields.COMPUTED]
    public, restricted = build_claims(
        rows, organization=organization, location_code=location_code,
        document_uuid=document_uuid, document_hash=document_digest(rows),
        issued_at=issued_at, expires_at=expires_at, field_rows=field_rows,
        transaction_type=transaction_type, operator_name=operator_name,
        location_name=location_name, portrait=portrait,
        credential_id=credential_id, issuer_name=issuer_name)

    prepared = prepare_attachments(attachments, public[wire.T_CREDENTIAL_ID],
                                   portrait=portrait is not None)
    if prepared is not None:
        public, restricted = prepared.claims(public, restricted)

    raw = issuer_mod.issue(public, restricted, epoch_keys=epoch_keys,
                           signer=signer)
    composed = compose(document_uuid, issuer_mod.to_qr_string(raw))
    plan = qrsize.plan(len(composed), STAMP_MM, "Q")
    return {
        "qr": composed,
        "credential_id": uuid.UUID(bytes=public[wire.T_CREDENTIAL_ID]),
        "epoch": epoch_keys.epoch,
        "payload_bytes": len(raw),
        "chars": len(composed),
        "qr_version": plan["version"],
        "min_stamp_mm": round(plan["min_stamp_mm"], 1),
        "fits_at_stamp": plan["scannable"],
        # By attachment id, in index order; empty when nothing is split.
        "attachment_parts": prepared.parts if prepared is not None else {},
    }


def max_qr_codes():
    """CREDENTIAL_MAX_QR_CODES, or None for no cap."""
    from django.conf import settings

    return getattr(settings, "CREDENTIAL_MAX_QR_CODES", 2) or None


def prepare_attachments(attachments, credential_id, *, portrait):
    """`attachments.Prepared` for `mint`, or None with nothing attached.

    The cap is checked either way: it counts the credential and its portrait
    too, and a document past it is refused rather than printed short.
    Raises CredentialError, before anything is signed.
    """
    try:
        budget = attachments_mod.part_budget(max_qr_codes(), portrait=portrait)
        if not attachments:
            return None
        return attachments_mod.prepare(attachments, credential_id=credential_id,
                                       max_part_symbols=budget)
    except (attachments_mod.PrepareError, attachments_mod.AttachmentError) as exc:
        raise CredentialError("attachments: %s" % exc) from None


# ---------------------------------------------------------------------------
# The portrait symbol
# ---------------------------------------------------------------------------
#
# The face does not fit in the credential. Measured, at 200x200 grayscale:
# JPEG at any quality above 20 exceeds the QR ceiling outright, and quality 10
# -- a smudge -- would fill a 60 mm symbol on its own, leaving no room for the
# claims. So the portrait rides its own symbol beside the credential -- the
# same size as it, which costs the face detail rather than the page room; see
# PORTRAIT_PX.
#
# WebP rather than JPEG, and the difference is not marginal: at quality 50 it
# is 1,390 bytes where JPEG is 2,667 and does not fit at all. iOS has decoded
# WebP natively since 14, so this costs the reader nothing.
#
# The two symbols are bound by T_PORTRAIT_HASH inside the credential's
# restricted section. Without that they are independent, and a document could
# be presented with somebody else's face beside it -- both scanning perfectly.

PORTRAIT_MAGIC = "CL03F1"

#: The same symbol carrying AVIF in place of WebP -- see `portrait_avif` for
#: what follows the credential id, and PORTRAIT_FORMAT for when it is used.
PORTRAIT_MAGIC_AVIF = "CL03F2"

#: Every marker a portrait symbol may start with, for anything that reads one.
PORTRAIT_MAGICS = (PORTRAIT_MAGIC, PORTRAIT_MAGIC_AVIF)

#: The encoders the portrait may be drawn with. WebP is what every verifier
#: app in the field reads; AVIF is the same face about 0.05 sharper at the
#: same bytes, and reads only on an app that knows `CL03F2:`.
PORTRAIT_FORMATS = ("webp", "avif")


def portrait_format():
    """Which encoder the deployment draws the portrait with: PORTRAIT_FORMAT,
    or WebP for anything that is not a known name."""
    from django.conf import settings

    chosen = str(getattr(settings, "PORTRAIT_FORMAT", "webp")).strip().lower()
    return chosen if chosen in PORTRAIT_FORMATS else "webp"


#: The face is cropped to the HEAD before it is resized: a square
#: PORTRAIT_HEAD_SCALE face-widths on a side around the largest face found,
#: lifted by PORTRAIT_HEAD_LIFT of a face-width so the hairline is in.
#:
#: **Measured, and the gain depends entirely on the framing.** On the sample
#: photograph -- an ID shot with shoulders, the face 43% of the width -- the
#: crop is worth 0.04-0.05 of face SSIM at every budget. On real eVerify
#: portraits it is worth about 0.017: those are 127 x 170 and already framed
#: on the face (66% of the width), so the crop trims the top and bottom and
#: little else. It is never worse, because a face that already fills the
#: picture leaves a crop nearly the size of the picture.
#:
#: 1.5 rather than tighter because the chin is the line that matters: the
#: detector's box ends at about the chin, and 1.5 leaves 0.19 of a face-height
#: below it on a real capture. 1.3 scored higher on that one face and leaves
#: under a tenth -- close to the "squaring it off cuts the chin" failure.
PORTRAIT_HEAD_SCALE = 1.5
PORTRAIT_HEAD_LIFT = 0.06

#: A face narrower than this share of the picture's shorter side is not the
#: subject of an ID portrait -- a badge, a poster, a pattern -- and is not
#: cropped to.
PORTRAIT_FACE_MIN_SHARE = 0.25

_face_detector_cache = []


def _face_detector():
    """OpenCV's frontal-face cascade, which ships inside the cv2 wheel, or
    None when it cannot be loaded -- and then nothing is cropped."""
    if not _face_detector_cache:
        detector = None
        try:
            import cv2

            loaded = cv2.CascadeClassifier(os.path.join(
                cv2.data.haarcascades, "haarcascade_frontalface_default.xml"))
            detector = None if loaded.empty() else loaded
        except Exception as exc:
            logger.warning("face detector unavailable: %s", exc)
        _face_detector_cache.append(detector)
    return _face_detector_cache[0]


def face_box(image):
    """`(x, y, width, height)` of the largest face in `image`, in its own
    pixels, or None. Never raises."""
    try:
        import cv2

        detector = _face_detector()
        if detector is None:
            return None
        height, width = image.shape[:2]
        gray = (cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
                if image.ndim == 3 else image)
        # Detection does not need the full picture, and a 1,254 px upload
        # costs ten times what 480 does.
        scale = min(1.0, 480.0 / max(height, width))
        if scale < 1.0:
            gray = cv2.resize(gray, (max(1, round(width * scale)),
                                     max(1, round(height * scale))),
                              interpolation=cv2.INTER_AREA)
        least = max(24, int(min(gray.shape[:2]) * PORTRAIT_FACE_MIN_SHARE))
        found = detector.detectMultiScale(gray, scaleFactor=1.1,
                                          minNeighbors=5,
                                          minSize=(least, least))
        if len(found) == 0:
            return None
        return tuple(float(v) / scale
                     for v in max(found, key=lambda f: f[2] * f[3]))
    except Exception as exc:
        logger.warning("face detection failed: %s", exc)
        return None


def portrait_frame(image):
    """`(x, y, width, height)` of the part of `image` the portrait keeps.

    The head box around the largest face, clamped inside the picture -- or
    the whole picture when there is no face to find, which is exactly what
    every portrait was before the crop. Never raises.
    """
    height, width = image.shape[:2]
    whole = (0, 0, width, height)
    try:
        face = face_box(image)
        if face is None:
            return whole
        fx, fy, fw, fh = face
        side = int(round(min(PORTRAIT_HEAD_SCALE * fw, width, height)))
        cx = fx + fw / 2
        cy = fy + fh / 2 - PORTRAIT_HEAD_LIFT * fw
        x = int(round(min(max(cx - side / 2, 0), width - side)))
        y = int(round(min(max(cy - side / 2, 0), height - side)))
        return (x, y, side, side)
    except Exception as exc:
        logger.warning("face detection failed: %s", exc)
        return whole


#: The resolution the face is rendered at before it is encoded.
#:
#: 160, not the 200 this started at, and the number follows the stamp. At the
#: credential's own 48.8 mm the image budget is 701 bytes where a 68 mm symbol
#: held 1,426, and at half the budget 200 x 200 stops winning: the encoder is
#: driven down to quality 2-15, where its own artefacts cost more than the
#: extra pixels buy.
#:
#: Measured on five real captures, SSIM against the upstream image at its
#: own resolution. The curve is FLAT from 128 to 208 -- 0.821 to
#: 0.835, which is noise on five faces -- and falls away properly below 120.
#: So this is not a peak that was found; it is the middle of a plateau, picked
#: because at 160 the encoder lands at quality 10-31 rather than in the
#: single digits.
#:
#: The decisive figure was never the SSIM. At 200 px the quality ladder ran
#: out before anything fitted for TWO of the five faces, and a face that does
#: not fit is no portrait symbol at all.
PORTRAIT_PX = 160

#: Demo Mode: the square grid the face is resampled down to before being
#: enlarged again. Small enough that no facial structure remains -- structure
#: is exactly what identifies a face, and what the 200 x 200 render exists to
#: preserve the rest of the time.
PORTRAIT_REDACT_PX = 10

#: How wide the portrait symbol has to be printed, same 0.4 mm floor as the
#: credential -- and now the same size, so the card carries a matched pair
#: rather than a large symbol and a small one.
#:
#: TIED to STAMP_MM rather than repeating the number, because the whole point
#: is that they cannot drift apart: raise the credential's stamp and the
#: portrait's budget follows it up, without a second edit that somebody has
#: to remember.
#:
#: It was 68 mm first, and the reason was sound -- an image is simply more
#: bytes than a page of text, and no encoding cleverness closes that gap. What
#: closes it is PAYING: the budget falls from 1,426 bytes to 701, and mean
#: SSIM on real faces from 0.888 to 0.832, which is about what a 112 x 112
#: render looked like at the old size. That is the trade, and it is a
#: presentation decision rather than a technical one. Widen this back if the
#: face on the paper turns out not to be good enough to compare against the
#: person holding it -- the ladder below simply spends the extra bytes.
PORTRAIT_STAMP_MM = STAMP_MM

#: The qualities a WebP portrait may be drawn at; the best one that fits
#: `PORTRAIT_STAMP_MM` wins. Quality is what gives way, never the 0.4 mm floor
#: -- a sharper face on a symbol that will not scan is worth nothing. At 160 px
#: inside the 48.8 mm stamp, real faces land between quality 10 and 31.
#:
#: Every step, not every fifth. The coarse ladder had a floor at 5 and could
#: reach it without ever fitting, which is how a working encoder returns no
#: portrait; covering every step removes the floor rather than lowering it.
#:
#: Covered, not walked: `_fit_webp()` searches it. Walking it from the top
#: costs about 95 encodes at 1.44 ms each before the sample photograph fits
#: -- 200 of the 227 ms that logging a verification would cost.
PORTRAIT_QUALITY_LADDER = tuple(range(95, 0, -1))

#: How far above the bisection's answer `_fit_webp()` looks before trusting it.
#: WebP's size does not always grow with quality, so a bisection that assumes
#: it does can stop a step or two below the best quality that fits. AVIF's
#: needed no such look (see `_fit_avif`); WebP's does, and this is how far.
PORTRAIT_WEBP_PROBE = 4

#: And when the quality ladder runs out with nothing that fits, the
#: RESOLUTION gives way -- 8 px at a time, aspect fit preserved, down to a
#: face that is still a face.
#:
#: The alternative would be no portrait symbol at all. That is right for a
#: document (it is still valid without one) and wrong for a picture somebody
#: chose to put on it, and the two cases are not distinguishable here -- so
#: the render is asked to fit the symbol rather than to report that it
#: could not.
#:
#: **Largest that fits, not best quality that fits**, and that is measured
#: rather than assumed. On the cel art `static/sample-face.png` held when this
#: was measured -- whose hard outlines cost 908 bytes against a 701-byte budget
#: at quality 1, so nothing at 160 px fits at all -- every rung that fits,
#: scored against the source:
#:
#:     | px  | quality | bytes | SSIM   |
#:     | 136 |       1 |   698 | 0.7774 |
#:     | 128 |       2 |   674 | 0.7711 |
#:     | 112 |       5 |   680 | 0.7612 |
#:     |  96 |      10 |   678 | 0.7550 |
#:     |  80 |      23 |   700 | 0.7473 |
#:
#: It falls away monotonically, so the first rung that fits is also the best
#: one, and no quality floor is needed to pick between them. Note this does
#: NOT contradict PORTRAIT_PX above: that compared two resolutions where both
#: fitted, and here the larger one does not fit at any quality at all.
#:
#: 80 px is the floor, and below it there is no face left to compare against
#: the person holding the page. An image that cannot fit even there gets no
#: symbol at all.
PORTRAIT_PX_FLOOR = 80
PORTRAIT_PX_STEP = 8


def portrait_px_ladder(px=PORTRAIT_PX):
    """The resolutions to try, largest first."""
    if px <= PORTRAIT_PX_FLOOR:
        return (px,)
    return tuple(range(px, PORTRAIT_PX_FLOOR - 1, -PORTRAIT_PX_STEP))


def render_portrait_fitted(data_uri, *, px=PORTRAIT_PX, redact=False):
    """The face, fitted to the symbol: quality first, then resolution.

    Returns `(bytes, px)` -- the rendered image and the resolution it took to
    make it fit -- or `(None, None)` when even the floor is too large.

    This is what the minting path uses, and `render_portrait()` below is the
    single-resolution primitive it is built from. They are kept apart on
    purpose: a caller asking "what does 200 px cost this face" wants an
    answer about 200 px, not a symbol produced at some other resolution --
    that is `debug_sizes --px`, and it is how the shipped resolution was
    chosen in the first place.
    """
    for step in portrait_px_ladder(px):
        blob = render_portrait(data_uri, px=step, redact=redact)
        if blob is not None:
            return blob, step
    return None, None


def render_portrait(data_uri, *, px=PORTRAIT_PX, redact=False, fmt=None):
    """A data URI from eVerify -> grayscale image bytes for the portrait
    symbol, or None: WebP, or the compact AVIF of `portrait_avif` when `fmt`
    (default: `portrait_format()`) asks for it and the encoder is here.

    **Grayscale, and measured rather than assumed.** Against five real faces
    at a fixed byte budget, SSIM to the original ran 0.966 at 200x200 gray,
    0.958 at 200x200 colour, 0.942 at 128x128 and 0.898 at 100x100. Colour
    costs 16-17% of the budget, which buys less than the luminance detail it
    displaces. Note the comparison scores luminance only, so it cannot credit
    what colour does add (skin tone, hair); the case for grayscale is that
    facial STRUCTURE is what identifies a face, and structure is exactly what
    those bytes buy.

    **"Resolution beats quality" was true at the old budget and is not a
    law.** It held monotonically while the symbol was 68 mm wide; at the
    48.8 mm stamp, where the budget is half, the curve is flat from 128 to
    208 px and 200 does WORSE than 160 -- see PORTRAIT_PX. Re-measure it
    against the budget rather than carrying the conclusion across.

    **cv2 for everything but the AVIF encoder.** Pillow is declared for AVIF
    alone -- the opencv wheels carry no AVIF encoder -- and an AVIF that
    cannot be made falls back to WebP rather than to no face. A library this
    relies on must be declared: one that is merely installed where the tests
    run would return None on every deployment.

    **Cropped to the head, then aspect fit** -- see PORTRAIT_HEAD_SCALE. The
    upstream portrait is already framed on the face (the crop gains little
    there), and the head box's margin under the chin is what keeps squaring
    it off from cutting somebody's chin off; a picture with no face found is
    not cropped at all.

    `redact` is Demo Mode. The document blurs the face in CSS so a real ID
    can be shown to an audience; without this the symbol beside it still
    carried the face in full, and anyone in the room could scan it. What is
    done here is NOT a blur: a blur is a filter, and filters can be partly
    undone. The image is resampled down to a handful of pixels and back up,
    which throws the information away rather than hiding it, and happens to
    look like the blur on the page.

    Never raises. A document that cannot carry a portrait symbol is still a
    valid document -- exactly as `_mint_credential` treats the credential.

    ONE resolution, the one it was asked for: returning None here means "this
    face does not fit the symbol at `px`", which is the question
    `debug_sizes --px` asks and the question PORTRAIT_PX was chosen by.
    `render_portrait_fitted()` is what the minting path calls, and it walks
    the resolution down until something fits.
    """
    if not data_uri:
        return None
    try:
        import base64 as _b64

        import cv2
        import numpy as np

        head, _, body = str(data_uri).partition(",")
        raw = _b64.b64decode(body if body else head)
        image = cv2.imdecode(np.frombuffer(raw, np.uint8), cv2.IMREAD_COLOR)
        if image is None:
            return None

        x, y, width, height = portrait_frame(image)
        image = image[y:y + height, x:x + width]
        scale = min(px / width, px / height)
        image = cv2.resize(
            image, (max(1, int(round(width * scale))),
                    max(1, int(round(height * scale)))),
            interpolation=cv2.INTER_AREA)
        image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

        if redact:
            # Down to PORTRAIT_REDACT_PX on the long side and back up. INTER_AREA
            # on the way down averages whole blocks away; INTER_CUBIC on the way
            # back up smooths what is left into something that reads as a face
            # having been there, and nothing more.
            small = cv2.resize(image, (PORTRAIT_REDACT_PX, PORTRAIT_REDACT_PX),
                               interpolation=cv2.INTER_AREA)
            image = cv2.resize(small, (image.shape[1], image.shape[0]),
                               interpolation=cv2.INTER_CUBIC)

        if (fmt or portrait_format()) == "avif":
            try:
                return _fit_avif(image)
            except _NoAvif as exc:
                logger.warning("AVIF portrait unavailable, drawing WebP: %s",
                               exc)

        return _fit_webp(image)
    except Exception as exc:
        # A warning, not an exception trace: a portrait that will not decode
        # is an ordinary bad input, and the document is still valid without
        # one. A stack trace per malformed face would drown the log.
        logger.warning("portrait rendering failed: %s", exc)
        return None


def _fit_webp(gray):
    """The WebP at the highest quality on PORTRAIT_QUALITY_LADDER whose symbol
    scans at PORTRAIT_STAMP_MM, or None when none does at this resolution --
    the resolution ladder's cue.

    Searched, not walked. A bisection over the ladder finds the boundary in
    about seven encodes, then the qualities up to PORTRAIT_WEBP_PROBE above it
    are tried as well, and any that fits moves the answer and the window up
    with it. The look upward is what makes the answer the walk's answer: WebP's
    size is not monotone in quality, so a bisection alone can settle a step or
    two low. It also starts from the bottom when the bisection found nothing,
    so None still means no quality fits, not that the search skipped one.
    """
    import cv2

    blobs = {}

    def encoded(quality):
        if quality not in blobs:
            ok, buffer = cv2.imencode(
                ".webp", gray, [int(cv2.IMWRITE_WEBP_QUALITY), int(quality)])
            blobs[quality] = bytes(buffer) if ok else None
        return blobs[quality]

    def fits(quality):
        blob = encoded(quality)
        return blob is not None and portrait_fits(blob)

    bottom, top = min(PORTRAIT_QUALITY_LADDER), max(PORTRAIT_QUALITY_LADDER)
    best, low, high = None, bottom, top
    while low <= high:
        quality = (low + high) // 2
        if fits(quality):
            best, low = quality, quality + 1
        else:
            high = quality - 1

    floor = best if best is not None else bottom - 1
    quality, limit = floor + 1, min(top, floor + PORTRAIT_WEBP_PROBE)
    while quality <= limit:
        if fits(quality):
            best, limit = quality, min(top, quality + PORTRAIT_WEBP_PROBE)
        quality += 1
    return blobs[best] if best is not None else None


class _NoAvif(Exception):
    """AVIF was asked for and cannot be made here; WebP is drawn instead."""


def _fit_avif(gray):
    """The highest AVIF quality whose symbol scans at PORTRAIT_STAMP_MM, or
    None when not even quality 0 fits at this resolution -- which is the
    resolution ladder's cue, exactly as for WebP. Raises `_NoAvif` when the
    encoder is missing or misbehaves.

    Searched, not walked: an encode is ~13 ms where WebP's is under one.
    Bisection alone, and that is measured: across 44 faces and resolutions
    it found exactly the quality an exhaustive walk did every time, where
    WebP needed a look a few steps up.
    """
    from accounts import portrait_avif

    if not portrait_avif.available():
        raise _NoAvif("Pillow has no AVIF support")
    try:
        best, low, high = None, 0, 100
        while low <= high:
            quality = (low + high) // 2
            blob = portrait_avif.encode(gray, quality)
            if portrait_fits(blob):
                best, low = blob, quality + 1
            else:
                high = quality - 1
        if best is None:
            return None
        # The face goes out in OUR container, not the encoder's: prove that
        # container decodes, here, before a phone is asked to.
        back = portrait_avif.decode(best)
        if back.shape[:2] != gray.shape[:2]:
            raise ValueError("decoded %r, encoded %r" % (back.shape, gray.shape))
        return best
    except Exception as exc:
        raise _NoAvif(str(exc)) from None


def is_avif_portrait(blob):
    """True for the compact AVIF of `portrait_avif`, False for WebP.

    Told apart by what the compact form must have: no WebP `RIFF` signature,
    and the AV1 configuration's marker byte (0x81) after the two dimensions.
    Anything else is treated as WebP, which is what every portrait was."""
    head = bytes(blob[:5])
    return len(head) == 5 and head[:4] != b"RIFF" and head[4] == 0x81


def portrait_data_uri(blob):
    """The portrait as an image a browser can draw -- the card's face.

    WebP as it is; AVIF wrapped in the container, since the symbol's compact
    form is not a file anything but this app's readers can open."""
    import base64 as _b64

    if is_avif_portrait(blob):
        from accounts import portrait_avif

        return ("data:image/avif;base64,"
                + _b64.b64encode(portrait_avif.expand(blob)).decode())
    return "data:image/webp;base64," + _b64.b64encode(blob).decode()


def decode_portrait(blob):
    """Portrait bytes in either form -> a 2-D uint8 array, or None."""
    try:
        if is_avif_portrait(blob):
            from accounts import portrait_avif

            return portrait_avif.decode(blob)
        import cv2
        import numpy as np

        return cv2.imdecode(np.frombuffer(blob, np.uint8),
                            cv2.IMREAD_GRAYSCALE)
    except Exception as exc:
        logger.warning("portrait does not decode: %s", exc)
        return None


def portrait_qr(blob, *, credential_id):
    """The exact string encoded into the portrait symbol.

    `CL03F1:<credential uuid>:<base45 WebP>`, or `CL03F2:` with the compact
    AVIF -- the marker says which, so a reader never has to sniff.

    The credential id is in the clear so a phone that scans this one first can
    say which document it belongs to instead of failing silently. It proves
    nothing by itself -- the binding that matters is the hash inside the
    credential's restricted section, which only an entitled device can read.
    """
    magic = PORTRAIT_MAGIC_AVIF if is_avif_portrait(blob) else PORTRAIT_MAGIC
    return "%s:%s:%s" % (magic, str(credential_id).upper(),
                         base45.encode(blob))


def portrait_fits(blob, *, credential_id=uuid.UUID(int=0)):
    """Would this image scan at PORTRAIT_STAMP_MM?

    False, never an exception, for an image past QR capacity entirely. The
    quality ladder asks this about its largest rung first, so a raising
    version aborted the whole render and returned no portrait at all -- which
    is how a working encoder produced nothing.
    """
    try:
        plan = qrsize.plan(len(portrait_qr(blob, credential_id=credential_id)),
                           PORTRAIT_STAMP_MM, "Q")
    except qrsize.TooLarge:
        return False
    return plan["scannable"]
