"""The dev-only store of whole eVerify responses, and the sizing report over it.

Every measurement of what fits on a printed document -- the QR stamp size,
the portrait's resolution and quality, the density tiers -- needs real data.
`static/mock-face.png` is a cartoon smiley that compresses nothing like
skin, so measuring on it gives wrong answers.

So on a development instance the app keeps what the upstream actually
returned: every key of the response, and the face fetched from it.

**This table holds complete identity records of real people, faces included.**
It exists for measuring on a development instance; it must never come into
existence anywhere else, and it is meant to be emptied as soon as a study is
finished -- `manage.py debug_cleanup`, or the button on `/debug-cleanup/`.

The same switch also decides whether the upstream call trace comes back to
the page that asked -- see `UpstreamTrace`. One flag, because both answer the
same question: is this deployment a workbench?

TWO opt-ins, exactly as the self-verifying mock has, and for the same reason
`_mock_login_allowed()` gives: gating on DEBUG alone would make one stray
DJANGO_DEBUG=1 start recording every verified person's identity and face into
a database that rides the off-site database backups -- with no loud symptom at all.
The health check would still return 200 and every page would look normal.

**A third control exists and it can only say no.**
`SiteSettings.debug_capture_enabled` is a switch on the Setup page, read by
`capture_enabled()` BEHIND `debug_allowed()` and never instead of it. It
pauses a store the environment has already allowed and cannot open one it has
not -- a switch that could turn capture on would be a way to start recording
complete identity records from a web form, on the strength of one admin
session, on a deployment whose environment says it must not have them. It
defaults ON, so an instance whose environment opens the gate keeps capturing
until somebody pauses it.

**Failures are kept too, and for a different reason than the successes.** A
success is data to size the printed document against. A failure is the
evidence of an upstream that stopped answering, kept while it is fresh: which
401 eVerify sent is otherwise hard to work out after the event. A failure row
carries no identity: eVerify's error bodies are {error, error_description,
message}, and nothing from the caller's own request is written -- not even
the National ID that was typed, which is where an identity would come from.
"""

from __future__ import annotations

import logging

from django.conf import settings

logger = logging.getLogger(__name__)

#: What the report calls a capture with no face.
NO_PORTRAIT = "no portrait"


def debug_allowed():
    """Is this an instance somebody is debugging?

    ONE switch, and it governs both affordances here: keeping eVerify
    responses, and showing the upstream call trace to the page that asked.
    They are the same decision -- "this deployment is a workbench" -- and two
    flags would only make it possible to set half of it.

    False on anything without BOTH opt-ins, which is every production
    deployment twice over. The env var is named EVERIFY_DEBUG_CAPTURE,
    which is narrower than what it now means; renaming it would silently
    switch the store off wherever it is set.

    The second opt-in is DEBUG, or VERIFY_WORKBENCH naming one of this site's
    own hosts: a development instance can keep its store without Django's
    debug pages and insecure cookies. Still two deliberate settings, never
    one.
    """
    if not getattr(settings, "EVERIFY_DEBUG_CAPTURE", False):
        return False
    if settings.DEBUG:
        return True
    bench = getattr(settings, "VERIFY_WORKBENCH", "")
    return bool(bench) and bench in [h.lower() for h in settings.ALLOWED_HOSTS
                                     if h != "*"]


class UpstreamTrace:
    """What the app asked eVerify, and what came back, step by step.

    The reason this exists: a 401 from the query endpoint can reach the
    login page as "Server returned 401" a full step after the camera closed,
    where it reads as a liveness failure although liveness had already
    succeeded and handed back a session id. Without the trace, telling the
    two apart takes the server's journal and probes against the upstream.

    None of the steps carry a credential. The token is counted, never
    quoted; the client id is not here at all (the server log has it if it is
    ever needed); a response body is recorded only for a call that FAILED,
    and truncated. eVerify's error bodies are {error, message,
    error_description} and carry no identity.
    """

    #: Enough of a failing body to read the upstream's own words.
    MAX_BODY = 400

    def __init__(self):
        self.steps = []

    def note(self, step, *, detail="", url="", method="", status=None,
             ms=None, body=""):
        entry = {"step": step}
        if detail:
            entry["detail"] = detail
        if url:
            entry["url"] = url
        if method:
            entry["method"] = method
        if status is not None:
            entry["status"] = status
        if ms is not None:
            entry["ms"] = int(ms)
        # Only a failure's body, and only as much of it as says what went
        # wrong. A 200's body is the person.
        if body and (status is None or not 200 <= int(status) < 300):
            text = str(body)
            entry["body"] = (text[:self.MAX_BODY] + "\u2026"
                             if len(text) > self.MAX_BODY else text)
        self.steps.append(entry)
        return entry

    def as_list(self):
        return list(self.steps)


def attach_trace(payload, trace):
    """Put the trace in the response -- only where debugging is allowed.

    A production operator must not be shown eVerify's URLs and raw error
    bodies in a modal, and the same gate that decides whether this instance
    keeps responses decides this. `payload` is returned either way, so the
    call site reads the same on both.
    """
    if trace is not None and debug_allowed():
        payload["trace"] = trace.as_list()
    return payload


def capture_enabled():
    """May the store take a row right now?

    The gate FIRST, then the switch. Read in that order and only in that
    order: `debug_allowed()` decides whether a store may exist on this
    deployment at all, and the switch decides whether one that may exist is
    currently taking rows. Reading the switch alone would make a row in the
    settings table a third opt-in nobody audited.

    On by default. `SiteSettings.load()` does not write on a read path, so an
    instance that was capturing before the column existed goes on capturing
    after it -- a new column must not quietly stop a study.
    """
    if not debug_allowed():
        return False
    from accounts.models import SiteSettings

    return bool(SiteSettings.load().debug_capture_enabled)


def capture(raw, prepared, *, purpose, organization=None,
            outcome=None, detail="", status_code=200):
    """Record one eVerify response. Returns the row, or None.

    `raw` is the response's own `data` object, before the field whitelist
    narrows it -- the whole point is to see keys the app does not currently
    carry. `prepared` is what `_prepare_data_for_frontend()` made of it, which
    is where the face has already been fetched into a data URI; taking it from
    there rather than re-fetching means the store costs no extra request and
    holds the same bytes the document did.

    `outcome` says whether the lookup identified anybody. A 200 that named
    nobody, and a `verified: false`, are FAILURES that happen to carry data --
    filing either as a success would make the two counts on the page a lie.
    The second keeps its payload, because the upstream did name somebody.

    **Never raises.** A verification is not worth losing to a debug facility,
    which is the same rule `_mint_credential()` follows.
    """
    if not capture_enabled():
        return None
    try:
        from accounts.models import DebugCapture

        payload = {k: v for k, v in dict(raw or {}).items() if k != "face_url"}
        photo = ""
        for row in prepared or []:
            if row.get("field") == "face_url" and row.get("value"):
                photo = row["value"]
                break
        return DebugCapture.objects.create(
            purpose=purpose, payload=payload, photo_data=photo,
            organization=organization,
            outcome=outcome or DebugCapture.OUTCOME_SUCCESS,
            detail=detail or "", status_code=status_code)
    except Exception as exc:
        logger.warning("debug capture failed: %s", exc)
        return None


#: How much of an upstream error body a failure row keeps. Enough to read the
#: message and the error code, not so much that a store of failures becomes a
#: store of something else.
MAX_FAILURE_BODY = 2000


def capture_failure(*, purpose, organization=None, detail="",
                    status_code=None, trace=None, body=None):
    """Record a lookup that produced no identity. Returns the row, or None.

    An upstream refusal with its status and body, a 401 at `/auth`, a run of
    attempts that never got an answer, a 200 carrying no `data` object. The
    row says which in `detail`, and carries what the upstream said plus the
    trace of the call in `payload`.

    **Nothing from the caller's own request is written here** -- not the
    National ID that was typed, not the liveness session id. That is what
    makes a failure row not an identity record, and it is why the failure half
    of the store is kept by `--photos-only` and is the half that is safe to
    leave lying about. Do not add the request to it.

    The trace is already forbidden a token or a client id -- see
    `UpstreamTrace.note()`, which is the one place that rule lives.

    **Never raises**, and the caller is told exactly what it would have been
    told without a store: a debug facility is never worth a verification, or a
    sensible error message.
    """
    if not capture_enabled():
        return None
    try:
        from accounts.models import DebugCapture

        payload = {}
        if body:
            payload["response"] = str(body)[:MAX_FAILURE_BODY]
        if trace is not None:
            payload["trace"] = trace.as_list()
        return DebugCapture.objects.create(
            purpose=purpose, payload=payload, photo_data="",
            organization=organization,
            outcome=DebugCapture.OUTCOME_FAILURE,
            detail=(detail or "")[:200], status_code=status_code)
    except Exception as exc:
        logger.warning("debug failure capture failed: %s", exc)
        return None


def store_summary():
    """The counts both pages show, plus the state of the switch.

    One function, because the Setup section and `/debug-cleanup/` show the
    same four numbers and two implementations of "how many are there" is how
    two pages come to disagree about one table.
    """
    from accounts.models import DebugCapture

    rows = DebugCapture.objects.all()
    return {
        "total": rows.count(),
        "successes": rows.filter(
            outcome=DebugCapture.OUTCOME_SUCCESS).count(),
        "failures": rows.filter(
            outcome=DebugCapture.OUTCOME_FAILURE).count(),
        "with_photos": rows.exclude(photo_data="").count(),
        "capture_enabled": capture_enabled(),
    }


def purge_one(pk):
    """Delete one capture. Returns how many rows went, which is 0 or 1.

    The row-level counterpart of `purge()`, and it exists because the store is
    a scratch pad: a study usually wants a handful of the captures it has and
    not the rest, and the alternative to dropping one is dropping all of them
    and running the lookups again.

    `pk` is whatever the POST carried, so it is **parsed before it is
    queried** -- filtering an integer column by junk raises rather than
    matching nothing, which is how `POST /api/v1/device/keys/` came to answer
    a malformed id with a 500. Junk and "no such row" get the same answer,
    which is 0.
    """
    from accounts.models import DebugCapture

    try:
        pk = int(str(pk).strip())
    except (TypeError, ValueError):
        return 0
    return DebugCapture.objects.filter(pk=pk).delete()[0]


def purge(*, photos_only=False):
    """Empty the store. Returns how many rows were affected."""
    from accounts.models import DebugCapture

    rows = DebugCapture.objects.all()
    if photos_only:
        rows = rows.exclude(photo_data="")
        count = rows.count()
        rows.update(photo_data="")
        return count
    count = rows.count()
    rows.delete()
    return count


# ---------------------------------------------------------------------------
# The report: what the captured data does to the two symbols on the card.
# ---------------------------------------------------------------------------

def _ssim(a, b):
    """Gaussian-window SSIM, the standard 11x11 / sigma 1.5 formulation.

    Written out rather than imported: scikit-image is not a declared
    dependency, and code that leans on a library merely installed where the
    tests run returns None on every deployment that lacks it.
    """
    import cv2
    import numpy as np

    a = a.astype(np.float64)
    b = b.astype(np.float64)
    c1, c2 = (0.01 * 255) ** 2, (0.03 * 255) ** 2
    k, s = (11, 11), 1.5
    mu_a, mu_b = cv2.GaussianBlur(a, k, s), cv2.GaussianBlur(b, k, s)
    mu_a2, mu_b2, mu_ab = mu_a * mu_a, mu_b * mu_b, mu_a * mu_b
    va = cv2.GaussianBlur(a * a, k, s) - mu_a2
    vb = cv2.GaussianBlur(b * b, k, s) - mu_b2
    vab = cv2.GaussianBlur(a * b, k, s) - mu_ab
    return float(np.mean(((2 * mu_ab + c1) * (2 * vab + c2))
                         / ((mu_a2 + mu_b2 + c1) * (va + vb + c2))))


def measure_portrait(photo_data, *, px=None, stamp_mm=None, redact=False):
    """What one captured face costs, and what remains of it.

    Returns a dict, or None when there is no usable image. `px` and `stamp_mm`
    default to what the app ships, so calling this with neither answers "is
    what we deploy still right for this face"; passing them answers "what
    would a different choice have done".

    That difference decides which renderer is used, and it matters: with no
    `px` this reports what the DOCUMENT would carry, so it walks the
    resolution ladder exactly as minting does and `px` comes back as the rung
    that fitted. With an explicit `px` it reports that resolution or nothing,
    because rows that quietly answer about some other resolution cannot
    choose one.
    """
    import base64

    import cv2
    import numpy as np

    from accounts import credentials
    from ovcrypto import qrsize

    if not photo_data:
        return None
    asked = px
    px = px or credentials.PORTRAIT_PX
    stamp_mm = stamp_mm or credentials.PORTRAIT_STAMP_MM

    if asked:
        blob = credentials.render_portrait(photo_data, px=px, redact=redact)
    else:
        blob, fitted = credentials.render_portrait_fitted(photo_data,
                                                          redact=redact)
        px = fitted or px
    out = {"px": px, "stamp_mm": stamp_mm, "bytes": None, "version": None,
           "module_mm": None, "scannable": False, "ssim": None}
    if blob is None:
        return out

    import uuid as _uuid
    text = credentials.portrait_qr(blob, credential_id=_uuid.uuid4())
    try:
        plan = qrsize.plan(len(text), stamp_mm, "Q")
    except qrsize.TooLarge:
        out["bytes"] = len(blob)
        return out
    out.update(bytes=len(blob), version=plan["version"],
               module_mm=plan["module_mm"], scannable=plan["scannable"])

    try:
        _, _, body = str(photo_data).partition(",")
        raw = base64.b64decode(body or photo_data)
        original = cv2.imdecode(np.frombuffer(raw, np.uint8),
                                cv2.IMREAD_GRAYSCALE)
        back = credentials.decode_portrait(blob)
        if original is not None:
            # Against the part of the picture the portrait KEEPS: the head
            # crop means the symbol no longer carries the whole upload, and
            # stretching it back over the whole frame would score the crop
            # rather than the encoding.
            x, y, width, height = credentials.portrait_frame(original)
            original = original[y:y + height, x:x + width]
        if original is not None and back is not None:
            back = cv2.resize(back, (original.shape[1], original.shape[0]),
                              interpolation=cv2.INTER_CUBIC)
            out["ssim"] = _ssim(original, back)
    except Exception as exc:  # a face that will not decode is not a crash
        logger.warning("ssim failed: %s", exc)
    return out


def measure_credential(payload, *, organization=None, portrait=None):
    """How large the credential symbol has to be for these demographics.

    The values are what decide it -- an address is the longest thing eVerify
    returns, and a name at exactly a version's capacity tips the symbol into
    the next version. Reported in characters and in the millimetres
    the 0.4 mm module floor then demands, which is the number that either fits
    the card or does not.

    Minted for real rather than estimated: the claims are signed and then
    encrypted, so the length is not something to reason about from the values.
    `portrait` is passed through because its hash rides in the restricted
    tier, and a sizing that left it out would be measuring a document nobody
    prints.

    Returns None when the deployment cannot mint, because guessing would be
    worse than saying so.
    """
    import datetime

    from accounts import credential_keys, credentials, everify_fields
    from ovcrypto import qrsize

    if not credential_keys.configured():
        return None

    rows = everify_fields.rows_for(organization)
    values = []
    for row in everify_fields.processed_rows(rows):
        key = row["key"]
        if key == "face_url" or (payload or {}).get(key) in (None, ""):
            continue
        values.append({"field": key, "key": everify_fields.label_for(row),
                       "value": payload[key], "show": row["display"]})
    if not values:
        return None

    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        minted = credentials.mint(
            values,
            organization=organization or _StubOrg(),
            location_code="Q1",
            document_uuid="00000000-0000-0000-0000-000000000000",
            epoch_keys=credential_keys.issuing_keys(),
            # A throwaway key, never the issuer's. A signature is 64 bytes
            # whoever makes it, so the size is the same; and these are real,
            # valid-looking credentials, up to 200 a page, that nobody records
            # -- with the real key they would be forgeries in all but name,
            # and a signer would count them against its ceilings.
            signer=_throwaway_signer(),
            issued_at=now,
            expires_at=now + datetime.timedelta(days=365),
            field_rows=rows,
            transaction_type="Release of Certificate of Live Birth",
            location_name="Main Office",
            operator_name="OPERATOR NAME",
            portrait=portrait)
    except Exception as exc:
        logger.info("credential sizing skipped: %s", exc)
        return None

    text = minted["qr"]
    try:
        plan = qrsize.plan(len(text), credentials.STAMP_MM, "Q")
    except qrsize.TooLarge:
        return {"fields": len(values), "chars": len(text), "version": None,
                "min_stamp_mm": None, "scannable": False}
    return {"fields": len(values), "chars": len(text),
            "version": plan["version"], "min_stamp_mm": plan["min_stamp_mm"],
            "scannable": plan["scannable"]}


class _StubOrg:
    """Enough of an Organization for `mint()` when the capture has none."""
    name = "Organization"
    issuer_code = "ORG"


def _throwaway_signer():
    """A fresh P-256 key nobody trusts, under key id 0, for measuring only."""
    from cryptography.hazmat.primitives.asymmetric import ec

    from accounts.credentials import PemSigningBackend

    return PemSigningBackend(ec.generate_private_key(ec.SECP256R1()), key_id=0)
