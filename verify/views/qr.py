"""National ID QR code decoding. Not a login."""

import base64
import json
import logging
import re
from datetime import datetime, timezone as dt_timezone, timedelta

import cv2
import numpy as np

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from accounts import throttle

from .helpers import _get_session_user

logger = logging.getLogger(__name__)


NATIONAL_ID_FIELD_MAP = {
    "n_l": "last_name",
    "n_f": "first_name",
    "n_m": "middle_name",
    "n_s": "suffix",
    "s": "sex",
    "bd": "date_of_birth",
    "pob": "place_of_birth",
    "bt": "blood_type",
    "ms": "marital_status",
    "id": "id_number",
    "pcn": "pcn",
    "iss": "issuer",
    "v": "version",
}

# The PhilID card -- the plastic card -- carries its large QR on the back as
# PSA's JSON with the person nested under `subject`, in PSA's own key names:
#
#   {"DateIssued": ..., "Issuer": "PSA", "subject": {"Suffix", "lName",
#    "fName", "mName", "sex", "BF", "DOB", "POB", "PCN"}, "alg": "EDDSA",
#    "signature": ...}
#
# None of those keys is in NATIONAL_ID_FIELD_MAP, which is the Digital
# National ID's back, so the card needs a map of its own.
# `BF` (best-captured fingers) is left out: nothing here uses it.
PHILID_SUBJECT_FIELD_MAP = {
    "lName": "last_name",
    "fName": "first_name",
    "mName": "middle_name",
    "Suffix": "suffix",
    "sex": "sex",
    "DOB": "date_of_birth",
    "POB": "place_of_birth",
    "PCN": "pcn",
}


def _decode_qr_from_bytes(image_bytes):
    """Decode QR code from image bytes using multiple OpenCV strategies."""
    arr = np.frombuffer(image_bytes, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        return None

    detector = cv2.QRCodeDetector()

    # 1. Aruco-based detector (most robust, handles low-quality images)
    try:
        aruco = cv2.QRCodeDetectorAruco()
        ok, decoded, _, _ = aruco.detectAndDecodeMulti(img)
        if ok and decoded and decoded[0]:
            return decoded[0]
    except Exception:
        pass

    # 2. Standard detector on original
    data, _, _ = detector.detectAndDecode(img)
    if data:
        return data

    # 3. Upscale small images (< 300px) for better detection
    h, w = img.shape[:2]
    if max(h, w) < 300:
        scale = 400 / max(h, w)
        upscaled = cv2.resize(img, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
        try:
            ok, decoded, _, _ = aruco.detectAndDecodeMulti(upscaled)
            if ok and decoded and decoded[0]:
                return decoded[0]
        except Exception:
            pass
        data, _, _ = detector.detectAndDecode(upscaled)
        if data:
            return data

    # 4. Grayscale + Otsu threshold
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    data, _, _ = detector.detectAndDecode(otsu)
    if data:
        return data

    # 5. Sharpen + upscale + Otsu (for blurry/compressed images)
    upg = cv2.resize(gray, (400, 400), interpolation=cv2.INTER_CUBIC)
    kernel = np.array([[-1, -1, -1], [-1, 9, -1], [-1, -1, -1]])
    sharpened = cv2.filter2D(upg, -1, kernel)
    _, sharp_bin = cv2.threshold(sharpened, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    data, _, _ = detector.detectAndDecode(sharp_bin)
    if data:
        return data

    # 6. Adaptive threshold
    adaptive = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 51, 11
    )
    data, _, _ = detector.detectAndDecode(adaptive)
    return data if data else None


def _parse_national_id_payload(raw_json_str):
    """Parse National ID QR JSON payload into a dict of readable fields."""
    payload = json.loads(raw_json_str)
    if not isinstance(payload, dict):
        raise ValueError("QR payload is not a JSON object.")

    subject = payload.get("subject")
    if isinstance(subject, dict):
        return _parse_philid_card(payload, subject)

    result = {}
    for json_key, attr_name in NATIONAL_ID_FIELD_MAP.items():
        value = payload.get(json_key)
        if value is not None:
            result[attr_name] = str(value)

    # Parse issued-at timestamp
    iat = payload.get("iat")
    if iat is not None:
        try:
            gmt8 = dt_timezone(timedelta(hours=8))
            dt = datetime.fromtimestamp(int(iat), tz=gmt8)
            result["issued_at"] = dt.strftime("%m/%d/%Y %I:%M %p")
        except (ValueError, OSError):
            result["issued_at"] = str(iat)

    # Extract photo as data URI
    photo_b64 = payload.get("p")
    if photo_b64:
        try:
            base64.b64decode(photo_b64)
            result["photo_data_uri"] = f"data:image/webp;base64,{photo_b64}"
        except Exception:
            pass

    return result


def _parse_philid_card(payload, subject):
    """The PhilID card's QR, into the same readable fields.

    The signature is not checked, as the Digital National ID's is not: these
    fields only fill the ID box, and the identity still comes back from
    eVerify. The PCN is printed with dashes; it is returned bare, as
    `_extract_plain_id` returns one.
    """
    result = {}
    for json_key, attr_name in PHILID_SUBJECT_FIELD_MAP.items():
        value = subject.get(json_key)
        if value is not None:
            result[attr_name] = str(value)
    if "pcn" in result:
        result["pcn"] = re.sub(r'[-\s]', '', result["pcn"])

    issuer = payload.get("Issuer")
    if issuer is not None:
        result["issuer"] = str(issuer)
    # A date as printed ("12 February 1990"), with no time to format.
    issued = payload.get("DateIssued")
    if issued is not None:
        result["issued_at"] = str(issued)
    return result


def _extract_plain_id(raw):
    """Try to extract a plain National ID from a raw QR string (not JSON).
    Returns dict with id_number or pcn if matched, else None."""
    s = raw.strip()
    stripped = re.sub(r'[-\s]', '', s)
    if re.match(r'^\d{16}$', stripped):
        return {"pcn": stripped}
    if re.match(r'^[A-Za-z]{3}\d{3,4}$', s):
        return {"id_number": s.upper()}
    if re.match(r'^[A-Za-z0-9]+$', stripped) and len(stripped) > 0:
        return {"id_number": stripped.upper()}
    return None


@csrf_exempt
@require_http_methods(["POST"])
def decode_national_id_qr(request):
    """Decode a National ID QR code image and return extracted fields."""
    # Six OpenCV passes over up to 10 MB, open to the login page: limited
    # per address when signed out. Another site's page cannot spend that
    # limit from somebody's browser.
    refused = throttle.refuse_cross_site(request)
    if refused is not None:
        return refused
    if _get_session_user(request) is None and not throttle.allow(request, "decode-qr"):
        return throttle.refused_json()
    try:
        uploaded = request.FILES.get("qr_image")
        if not uploaded:
            return JsonResponse({"message": "No image uploaded."}, status=400)

        content_type = getattr(uploaded, 'content_type', '')
        if content_type and not content_type.startswith('image/'):
            return JsonResponse({"message": "File must be an image."}, status=400)

        if uploaded.size > 10 * 1024 * 1024:
            return JsonResponse({"message": "Image too large (max 10MB)."}, status=400)

        image_bytes = uploaded.read()
        raw = _decode_qr_from_bytes(image_bytes)
        if not raw:
            return JsonResponse({"message": "No QR code detected in the image."}, status=422)

        plain = _extract_plain_id(raw)
        if plain:
            return JsonResponse({"status": "ok", "data": plain})

        data = _parse_national_id_payload(raw)
        return JsonResponse({"status": "ok", "data": data})

    except json.JSONDecodeError:
        return JsonResponse({"message": "QR code does not contain valid National ID data."}, status=422)
    except ValueError as e:
        return JsonResponse({"message": str(e)}, status=422)
    except Exception:
        # The detail goes to the log, not to whoever posted the image: this
        # endpoint needs no session, and an exception's text describes the
        # server, not the picture.
        logger.exception("QR decode failed")
        return JsonResponse({"message": "Could not process that image."}, status=500)


# No QR login (`POST /qr-login/`): a login from `id_number` / `pcn` in the
# request body, with no eVerify exchange and no liveness check, would let
# anyone who knew a National ID card number POST it and be logged in as its
# owner.
#
# This decoder is deliberately NOT an authentication path. It returns decoded
# fields to the client, which feeds them into the eVerify + liveness flow at
# `POST /everify/`; that is the only route that may start a session, because it
# is the only one where the identity comes back from the upstream rather than
# from the caller. Do not reintroduce a login endpoint here.
