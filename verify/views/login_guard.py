"""Who gets to reach eVerify at sign-in, and what happens to everyone else.

**Nothing in this module creates a session, and nothing in it may.** It is a
one-way filter: it can stop an identifier from reaching eVerify, and that is
all it can do. The identity a session is granted for still comes only from
what the upstream returned;
this module sits in front of that rule rather than replacing it.

Without it, `POST /everify/` would call eVerify for any well-formed National
ID anybody typed on the login page. A caller who is not
a registered operator cannot be signed in whatever the upstream says
(`_login_user_from_everify()` gives up when `_find_user()` misses), so those
calls could only ever fail -- but each one still spent a liveness session and
a query against the site's eVerify client. That is a quota-burn vector open
to anyone who can reach the login page, and it is the reason the organization
is never resolved from the typed National ID.

So: an identifier that names no row in Users never reaches the eVerify
IDENTITY QUERY. It is answered instead by a delay drawn to match what a real
lookup costs, and the same 404 in the same words, so the two cannot be told
apart by a stopwatch or by reading the reply.

**The liveness check itself is the real one, on both paths.** Not an
imitation of it -- the genuine eVerify SDK, in the genuine iframe, against
the site's own public key. A hand-built copy of the liveness screen, made
from the upstream's own source, would still not be identical: spacing,
buttons and camera handling would differ, and each of those differences would
tell the operator whether the ID they typed was registered. A hand-copy
cannot win that race -- their UI is a third party's build that changes
without notice, so the copy is wrong the moment it is made and drifts further
afterwards.

Running the real check removes the question. There is nothing left to match,
because it IS the thing being matched: same iframe, same spacing, same
buttons, same camera handling, same network requests. The client makes no
decision at all -- there is no branch in login.html and no endpoint that
tells it which check to run, deliberately, because either would be the oracle
in another form. Whether the ID is registered is decided on the server,
afterwards, and never travels back except as a refusal identical to a genuine
eVerify miss.

**What this costs.** A refused attempt still creates a liveness session on
the upstream, so this no longer protects the liveness quota -- only the
identity query, which is the billable lookup. That is the deliberate trade:
an enumeration oracle is worse than the sessions an enumerator would spend.
The sessions are protected by a limit per address instead
(`accounts/throttle.py`): it applies to registered and unregistered alike, so
unlike a different-looking check it tells an attacker nothing.

**Where the face comes from.** The liveness iframe posts
`{photo, session_id, photo_url}` up to the parent when it completes, so the
real check already hands back the capture; nothing here opens a camera. The
page forwards it on EVERY attempt, and it is stored only for a refused one --
a client that sent it selectively would be the oracle again.
"""

import base64
import logging
import random
import re
import time

from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from accounts import throttle
from accounts.models import LoginAttempt, User

from .helpers import BRIDGE_PREFIX


logger = logging.getLogger(__name__)

#: How long a refusal takes to answer, in seconds. A real signed-out lookup is
#: three upstream calls (auth, then query, plus the face fetch) and measures
#: 2-5 s, which is also what login.html tells the operator to expect. The real
#: path logs its own elapsed time at INFO under "signed-out lookup took", so
#: this range can be re-tuned from production logs rather than guessed at.
REFUSAL_DELAY_SECONDS = (2.0, 5.0)

#: A captured face as the liveness iframe hands it over. Generous enough for
#: a full-resolution selfie frame, small enough that the column cannot serve
#: to park something large in the database.
MAX_PHOTO_BYTES = 600 * 1024

#: What a face capture may be. SVG is absent deliberately -- it can carry
#: script, and it is not something a camera produces.
_PHOTO_TYPES = (
    ("image/jpeg", (b"\xff\xd8\xff",)),
    ("image/png", (b"\x89PNG\r\n\x1a\n",)),
    ("image/webp", (b"RIFF",)),
)

#: The iframe may hand over a complete data: URI or bare base64, so both are
#: accepted -- but the media type is settled by SNIFFING the decoded bytes,
#: never by what the caller declared. A lie in the prefix therefore cannot
#: matter: it is not read.
_DATA_URI = re.compile(r"^data:image/[a-z+]+;base64,(.*)$", re.S)
_BASE64 = re.compile(r"^[A-Za-z0-9+/=\s]+$")

_jitter = random.SystemRandom()


def normalise_identifier(value):
    """A typed National ID in the one spelling everything else stores.

    The login form accepts `1234-5678-9012-3456` and `abc1234`; Users holds
    `1234567890123456` and `ABC1234`. Comparing without this step refuses
    genuine operators for punctuation.
    """
    return (value or "").strip().replace("-", "").replace(" ", "").upper()


def identifier_kind(value):
    """Which of the two National ID numbers this looks like."""
    compact = normalise_identifier(value)
    if compact.isdigit() and len(compact) == 16:
        return LoginAttempt.KIND_CARD
    if re.match(r"^[A-Z]{3}\d{3,4}$", compact):
        return LoginAttempt.KIND_DIGITAL
    return LoginAttempt.KIND_OTHER


def registered_operator(value):
    """The User a typed sign-in identifier names, or None.

    Deliberately as wide as `_find_user()`, which is what actually resolves
    the identity once the upstream has answered: either column, either
    spelling. A narrower check here is not a hardening, it is a lockout --
    an operator whose row carries only a card number, who signs in with the
    digital ID printed on the same card, must not be refused before eVerify
    has had the chance to map one to the other.

    That case is still reachable, and it is the one risk this gate carries:
    a member added by card number alone, who has never signed in (so nothing
    has backfilled their digital ID yet), and who types the digital ID. They
    are refused, and the refusal is recorded on LoginAttempt with the ID they
    used, which is what an admin needs to fix it -- add that digital ID to
    the member and the next attempt goes through.
    """
    compact = normalise_identifier(value)
    if not compact:
        return None
    # national_id_card_number is unique; digital_national_id is not, and
    # defaults to "" -- which is why the empty case bails out above. The
    # Django-admin bridge's rows are skipped, as `_find_user()` skips them.
    operators = User.objects.exclude(national_id_card_number__startswith=BRIDGE_PREFIX)
    user = (operators.filter(national_id_card_number__iexact=compact).first()
            or operators.filter(digital_national_id__iexact=compact).first())
    # A holder registered from idmanager is not an operator, and is refused
    # here before eVerify is spent on them -- the same rule `_find_user()`
    # applies after, kept as wide as it.
    if user is not None and user.is_holder_only:
        return None
    return user


def clean_photo(photo):
    """A storable `data:image/...;base64,...` face capture, or "".

    Takes what the liveness iframe posts to the parent, which is either a
    complete data: URI or bare base64. Never raises and never returns
    anything it has not checked: it arrives in an unauthenticated request
    body, so the type is settled by sniffing the decoded bytes and the
    declared one is not read at all. Anything that is not a JPEG, PNG or
    WebP -- an SVG, a text file, a blob -- becomes "".
    """
    if not photo or not isinstance(photo, str):
        return ""
    photo = photo.strip()
    if len(photo) > MAX_PHOTO_BYTES * 2:  # base64 is ~4/3, plus slack
        return ""
    match = _DATA_URI.match(photo)
    payload = match.group(1).strip() if match else photo
    if not payload or not _BASE64.match(payload):
        return ""
    try:
        raw = base64.b64decode(payload, validate=False)
    except Exception:
        return ""
    if not raw or len(raw) > MAX_PHOTO_BYTES:
        return ""
    for media_type, magics in _PHOTO_TYPES:
        if any(raw.startswith(magic) for magic in magics):
            return (f"data:{media_type};base64,"
                    f"{base64.b64encode(raw).decode('ascii')}")
    return ""


#: Refused attempts from one address in an hour after which no more faces
#: are kept from it. The row is still written; the photo is what makes a
#: flood of refusals expensive to store.
PHOTOS_PER_ADDRESS_PER_HOUR = 5


def _client_ip(request):
    """The address the nearest trusted proxy saw, never the left-most
    X-Forwarded-For entry, which the client writes. None when it is not
    an address."""
    address = throttle.client_address(request)
    return None if address == "unknown" else address


def _photo_allowed(ip_address):
    if ip_address is None:
        return True
    since = timezone.now() - timedelta(hours=1)
    return LoginAttempt.objects.filter(
        ip_address=ip_address, created_at__gte=since,
    ).exclude(photo_data="").count() < PHOTOS_PER_ADDRESS_PER_HOUR


def record_refused_attempt(request, value, photo_data_uri=""):
    """Log a sign-in attempt that never reached eVerify, face included.

    Best-effort: a login page that fails because this write failed is a
    worse outcome than a missing row, so every error here is swallowed and
    logged. Mirrors `_log_failure_transaction()`.
    """
    try:
        ip_address = _client_ip(request)
        attempt = LoginAttempt.objects.create(
            submitted_id=normalise_identifier(value)[:32],
            id_kind=identifier_kind(value),
            photo_data=(clean_photo(photo_data_uri)
                        if _photo_allowed(ip_address) else ""),
            ip_address=ip_address,
            user_agent=(request.META.get("HTTP_USER_AGENT") or "")[:255],
        )
        # The row, not the number: the log is kept apart from the database,
        # for months, and read by whoever reads logs. The ID number someone
        # typed stays in the row, with the face.
        logger.warning(
            "Login refused before eVerify: attempt=%s kind=%s photo=%s ip=%s",
            attempt.pk, attempt.id_kind,
            "yes" if attempt.photo_data else "no", attempt.ip_address)
        return attempt
    except Exception as exc:  # pragma: no cover - audit must not break login
        logger.error(f"Failed to record refused login attempt: {exc}")
        return None


def sleep_to_match(started_at):
    """Hold the response until it has taken as long as a real lookup would.

    Anchored to when the request started, not simply added on top: the work
    a refusal does do (validating and storing the capture) is not free, and
    sleeping a flat interval after it would leave that difference readable in
    the total. Drawn fresh from a system-random source each
    time, so the value cannot be predicted and averaged away either.

    A range of (0, 0) disables it, which is what the test suite uses.
    """
    low, high = getattr(settings, "EVERIFY_DECOY_DELAY_SECONDS",
                        REFUSAL_DELAY_SECONDS)
    if high <= 0:
        return 0.0
    target = _jitter.uniform(low, high)
    remaining = target - (time.monotonic() - started_at)
    if remaining > 0:
        time.sleep(remaining)
    return target
