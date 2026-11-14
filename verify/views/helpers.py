"""Session, authentication, organization context, and admin helpers."""

import logging
import random
import re

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import redirect
from django.utils import timezone

from accounts import everify_fields
from accounts.models import BRIDGE_PREFIX as _BRIDGE_PREFIX
from accounts.models import CARD_NUMBER as _CARD_NUMBER
from accounts.models import DIGITAL_ID as _DIGITAL_ID
from accounts.models import (Location, Membership, Organization, User,
                             UserSettings, bridge_card, bridge_roles,
                             organizations_open_to)
from verify.sessions import clear_expired, mark_signed_in

logger = logging.getLogger(__name__)

#: The organization the current session is acting for.
ORG_SESSION_KEY = "verify_org_id"

#: How the card number of a Django-admin bridge row starts (accounts.models).
BRIDGE_PREFIX = _BRIDGE_PREFIX

#: The two ID shapes (accounts.models).
CARD_NUMBER = _CARD_NUMBER
DIGITAL_ID = _DIGITAL_ID

#: Remembers the last organization/location on THIS DEVICE, so a returning
#: operator finds the chooser pre-filled. It is a convenience only: the
#: chooser is still shown and still has to be confirmed, and nothing is
#: granted from the cookie -- _available_organizations() is what decides
#: which organizations the signed-in user may actually enter.
CONTEXT_COOKIE = "verify_last_context"
CONTEXT_COOKIE_AGE = 60 * 60 * 24 * 180  # 180 days


def _get_session_user(request):
    """Return the logged-in User or None (flushes invalid sessions).
    Also supports Django admin users -- if a Django staff/superuser is logged
    in, find or create its bridge row, whose roles follow the Django account
    on every request: a superuser is a site admin, staff that is not a
    superuser an admin of every organization (bridge_roles)."""
    # Check verify session first
    user_id = request.session.get("verify_user_id")
    if user_id:
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            request.session.flush()
            return None
        # A bridge row's session lives exactly as long as the Django login
        # that opened it: deactivating the account, taking its staff status,
        # changing its password (which ends the Django session) or logging it
        # out ends this one at the next request.
        if user.national_id_card_number.startswith(BRIDGE_PREFIX):
            if not _bridge_login_holds(request, user):
                logger.info("Ended a Django-admin bridge session for user %s: "
                            "its Django login is gone or no longer staff", user.pk)
                request.session.flush()
                return None
            # Made or unmade a superuser since the last request: the row's
            # roles follow, before anything below reads them.
            _sync_bridge_roles(user, request.user)
        return user

    # Check Django admin login
    django_user = getattr(request, 'user', None)
    if django_user and django_user.is_authenticated and (django_user.is_staff or django_user.is_superuser):
        # The bridge's own row is found by the card number only the bridge
        # writes -- ADMIN plus the Django id -- and never by digital ID. The
        # digital ID is a column organization admins type, so looking the
        # username up there would let one plant the row a staff account is
        # bound to and promoted to site admin. Every
        # typed card number is sixteen digits, so nobody else can write this
        # one. The username is still written below, as a label only.
        #
        # ADMIN plus eleven digits is sixteen characters, the column's
        # max_length. Twelve digits made seventeen, which SQLite stores
        # silently and PostgreSQL refuses, so the first superuser to open
        # /app/ on PostgreSQL got a server error. 0042 shortened the rows
        # already written.
        card = bridge_card(django_user.id)
        verify_user = User.objects.filter(national_id_card_number=card).first()
        if not verify_user:
            site, every_org = bridge_roles(django_user)
            verify_user = User.objects.create(
                national_id_card_number=card,
                digital_national_id=django_user.username,
                given_name=django_user.first_name or django_user.username,
                last_name=django_user.last_name or "",
                is_site_admin=site,
                is_all_org_admin=every_org,
                # Its phones read the public tier until a site administrator
                # grants more, and that grant is then recorded.
                device_restricted_tier=False,
            )
        else:
            _sync_bridge_roles(verify_user, django_user)
        request.session["verify_user_id"] = verify_user.id
        request.session[SIGN_IN_KEY] = "django"
        return verify_user

    return None


def _bridge_login_holds(request, row):
    """The Django login behind a bridge row's session is still there, still
    active and still staff, and is the account this row belongs to."""
    django_user = getattr(request, "user", None)
    return bool(django_user is not None and django_user.is_authenticated
                and django_user.is_active
                and (django_user.is_staff or django_user.is_superuser)
                and row.national_id_card_number == bridge_card(django_user.id))


def _sync_bridge_roles(row, django_user):
    """Set a bridge row's site-admin and every-organization flags from its
    Django account (bridge_roles), writing only when they changed."""
    site, every_org = bridge_roles(django_user)
    if (row.is_site_admin, row.is_all_org_admin) == (site, every_org):
        return
    logger.warning("Django-admin bridge row %s: site admin %s -> %s, admin of "
                   "every organization %s -> %s (django user %s)", row.pk,
                   row.is_site_admin, site, row.is_all_org_admin, every_org,
                   django_user.pk)
    row.is_site_admin, row.is_all_org_admin = site, every_org
    row.save(update_fields=["is_site_admin", "is_all_org_admin"])


def _require_login(request):
    """Return (user, redirect_response). One of them is always None."""
    user = _get_session_user(request)
    if user is None:
        return None, redirect("home")
    return user, None


# ---------------------------------------------------------------------------
# Organization context
# ---------------------------------------------------------------------------
# Every organization-scoped read and write goes through these. The rule they
# enforce is one sentence: a request may only touch an organization the
# signed-in user can enter, and "can enter" means a membership -- or the
# site-admin or every-organization flag (User.reaches_every_organization),
# which is deliberately a superset.


def _available_organizations(user):
    """Active organizations this user may act for, in menu order.

    Site admins and admins of every organization may enter every active
    organization; that is a decision, and it is why the Transaction stamps
    acting_as_site_admin and acting_as_all_org_admin exist (_log_context).

    The rule itself is `accounts.models.organizations_open_to`, because a
    phone is told which organizations it works for by the same rule, from
    code that must not import views.
    """
    return organizations_open_to(user)


def _membership(user, org):
    """The user's membership in org, or None (site admins often have none)."""
    if user is None or org is None:
        return None
    return Membership.objects.filter(user=user, organization=org).first()


def _may_enter(user, org):
    if user is None or org is None or not org.is_active:
        return False
    return bool(user.reaches_every_organization or _membership(user, org))


def _is_org_admin(user, org):
    """Admin *of this organization*. Site admins and admins of every
    organization qualify everywhere."""
    if user is None or org is None:
        return False
    if user.reaches_every_organization:
        return True
    membership = _membership(user, org)
    return bool(membership and membership.is_admin)


def _current_organization(request, user=None):
    """The organization this session is acting for, or None.

    Re-checked on every request rather than trusted from the session: a
    membership can be revoked or an organization disabled while somebody is
    signed in, and that must end their access to it immediately.
    """
    org_id = request.session.get(ORG_SESSION_KEY)
    if not org_id:
        return None
    user = user or _get_session_user(request)
    org = Organization.objects.filter(pk=org_id).first()
    if org is None or not _may_enter(user, org):
        request.session.pop(ORG_SESSION_KEY, None)
        request.session.pop("operator_location", None)
        return None
    return org


def _auto_context(request, user):
    """Set the context without asking when there is only one possible answer.

    Returns the organization if it could be resolved, else None. This is what
    makes the chooser invisible to a single-organization, single-location
    operator -- the common case, and the one that must not get slower.
    """
    orgs = list(_available_organizations(user)[:2])
    if len(orgs) != 1:
        return None
    org = orgs[0]
    locations = list(org.locations.filter(is_active=True)[:2])
    if len(locations) > 1:
        return None
    request.session[ORG_SESSION_KEY] = org.id
    request.session["operator_location"] = str(locations[0].id) if locations else ""
    return org


def _require_context(request):
    """Return (user, organization, redirect_response); one of the last two is None.

    Views that act on behalf of an organization use this instead of
    _require_login: it guarantees `organization` is one the user may enter.
    """
    user = _get_session_user(request)
    if user is None:
        return None, None, redirect("home")
    org = _current_organization(request, user)
    if org is None:
        org = _auto_context(request, user)
    if org is None:
        return user, None, redirect("choose")
    return user, org, None


def _org_admin_required(request):
    """(user, organization, error_response) for organization-scoped JSON APIs."""
    user = _get_session_user(request)
    if user is None:
        return None, None, JsonResponse({"message": "Unauthorized."}, status=403)
    org = _current_organization(request, user)
    if org is None or not _is_org_admin(user, org):
        return None, None, JsonResponse({"message": "Unauthorized."}, status=403)
    return user, org, None


def _site_admin_required(request):
    """(user, error_response) for site-wide JSON APIs."""
    user = _get_session_user(request)
    if user is None or not user.is_site_admin:
        return None, JsonResponse({"message": "Unauthorized."}, status=403)
    return user, None


def _location_name(org, raw):
    """Display name for a stored operator_location value.

    The session holds a Location id; fall back to the raw string so rows
    written before locations were rows still render.
    """
    if not raw:
        return ""
    try:
        return Location.objects.get(id=int(raw), organization=org).name
    except (TypeError, ValueError, Location.DoesNotExist):
        return str(raw)


def _log_context(request, user, org):
    """(organization, stamp) for a Transaction: stamp is its
    acting_as_site_admin and acting_as_all_org_admin, True for the role that
    let a non-member in."""
    stamp = {"acting_as_site_admin": False, "acting_as_all_org_admin": False}
    if org is None:
        return None, stamp
    if user and user.reaches_every_organization and not _membership(user, org):
        stamp["acting_as_site_admin"] = bool(user.is_site_admin)
        stamp["acting_as_all_org_admin"] = not user.is_site_admin
    return org, stamp


def _remember_context(response, org_id, location_id):
    """Pre-fill the chooser next time on this device. Grants nothing."""
    response.set_cookie(
        CONTEXT_COOKIE, f"{org_id}:{location_id or ''}",
        max_age=CONTEXT_COOKIE_AGE, samesite="Lax",
        secure=not settings.DEBUG, httponly=True)
    return response


def _remembered_context(request):
    """(org_id, location_id) from the device cookie, as ints or None."""
    raw = request.COOKIES.get(CONTEXT_COOKIE, "")
    org_id, _, location_id = raw.partition(":")
    def as_int(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    return as_int(org_id), as_int(location_id)


def _find_user(digital_id=None, pcn=None):
    """Find existing user by national_id_card_number (primary) or digital_id. Returns User or None.

    Callers must pass identifiers that came back from the upstream eVerify
    response, never values taken from the request body — this function only
    resolves an identifier to a row, it does not establish that the caller owns
    it. Every empty/degenerate identifier must resolve to None: an identifier
    that matches "any user" is an authentication bypass.

    A HOLDER -- somebody who registered their own phone from idmanager -- is
    not an operator and resolves to None here, exactly as if no row existed,
    until an organization makes them a member. Every sign-in path comes
    through this function, so this is the one place that keeps "verify must
    not auto-provision" true now that idmanager can create rows. See
    accounts/holders.py.
    """
    user = _lookup_user(digital_id, pcn)
    if user is not None and user.is_holder_only:
        return None
    return user


def _lookup_user(digital_id=None, pcn=None):
    """`_find_user()` without the holder rule. Never call this to sign in.

    The card number decides first. The digital ID is a fallback for when the
    upstream returned no card number, or a row that holds none -- not for a
    row whose card number is a DIFFERENT one. Whoever can write a digital ID
    onto somebody's row would otherwise decide who else signs in as them.
    The cost: a person whose card was replaced is refused until an admin
    puts the new number on their row in Django admin; the warning below
    names the row.
    """
    # The Django-admin bridge's rows (_get_session_user) are reached by a
    # Django login and nothing else. Their digital ID holds the staff
    # username, so without this an upstream answer naming that username and
    # no card would sign in as a site admin.
    operators = User.objects.exclude(national_id_card_number__startswith=BRIDGE_PREFIX)
    clean_pcn = ""
    if pcn:
        # A value like "-" or "   " strips to "", which would otherwise query
        # for national_id_card_number="" and match a row with an unset ID.
        clean_pcn = pcn.replace("-", "").replace(" ", "").strip()
        if clean_pcn:
            try:
                return operators.get(national_id_card_number=clean_pcn)
            except (User.DoesNotExist, User.MultipleObjectsReturned):
                pass
    if digital_id and digital_id.strip():
        try:
            # digital_national_id is non-unique and defaults to "", so an empty
            # lookup here would match an arbitrary user. Guarded above.
            user = operators.filter(digital_national_id__iexact=digital_id.strip()).first()
        except Exception:
            return None
        if (user is not None and clean_pcn and user.national_id_card_number
                and user.national_id_card_number != clean_pcn):
            logger.warning(
                "Sign-in refused: digital ID matches user %s, whose card ends %s, "
                "but the upstream returned a card ending %s",
                user.pk, user.national_id_card_number[-4:], clean_pcn[-4:])
            return None
        return user
    return None


#: How this session signed in: "everify", "sso" or "django" (the bridge),
#: so a session's actions can be told apart by path.
SIGN_IN_KEY = "verify_sign_in"


def _login_session(request, user, via="everify", **detail):
    """Stamp last_login and store user in session.

    `via` and any `detail` (the SSO provider's subject id) are kept on the
    session and logged, so a session's actions can be traced to the path
    that opened it."""
    user.last_login = timezone.now()
    user.save(update_fields=["last_login"])
    request.session.cycle_key()  # Prevent session fixation
    mark_signed_in(request.session)
    request.session["verify_user_id"] = user.id
    request.session[SIGN_IN_KEY] = via
    for name, value in detail.items():
        request.session[f"{SIGN_IN_KEY}_{name}"] = str(value)[:255]
    logger.info("Signed in user %s via %s%s", user.pk, via,
                "".join(f" {name}={value}" for name, value in sorted(detail.items())))
    # Sessions abandoned mid-verification still hold that person's rows and
    # face; this is where they go, as hand-offs go on every open.
    clear_expired()


# ---------------------------------------------------------------------------
# Demo mode
# ---------------------------------------------------------------------------
# These name eVerify's OWN keys, not the labels on the document. The labels
# are editable per organization now, so keying the mask on them would mean
# renaming "Middle Name" quietly stopped it being redacted -- a leak with no
# symptom, found by an audience.

DEMO_MASK_CHAR = "\u2022"  # bullet

#: Every field is masked outright unless it is named below. Lists naming
#: what to mask would let a field a site admin switches on -- Full Name,
#: which undoes the given and middle names' masking, e-mail, mobile number,
#: the address parts -- reach the page, the credential and the card in the
#: clear.

#: Shown in the clear: the page's decision, not the mask's.
DEMO_CLEAR = ("last_name",)

#: Not text. The portrait is blurred in CSS, and the credential's is
#: resampled where it is minted.
DEMO_NOT_TEXT = ("face_url",)

#: Shown as far as their first word; every later word is masked.
DEMO_FIRST_WORD_ONLY = ("first_name", "full_name", "full_address",
                        "present_full_address")

#: Masked except for the last character, enough to tell two IDs apart on
#: screen without showing either.
DEMO_LAST_TWO = ("reference", "code")
DEMO_TAIL_KEPT = 1

# Everything else is masked outright: the middle name, the birth date, the
# age with it (it narrows the birth date to a year), the sex, and whatever
# a site admin switches on next.


#: Bullet runs are jittered by this much either side of the real word length,
#: so the redaction does not give the length of what it hides.
DEMO_LENGTH_JITTER = 3


def _mask_word(word):
    """Replace a word with a run of bullets of deliberately wrong length."""
    jitter = random.randint(-DEMO_LENGTH_JITTER, DEMO_LENGTH_JITTER)
    return DEMO_MASK_CHAR * max(1, len(word) + jitter)


def _demo_mask(text, keep_first_word):
    words = str(text).split()
    if not words:
        return text
    if keep_first_word:
        return " ".join([words[0]] + [_mask_word(w) for w in words[1:]])
    return " ".join(_mask_word(w) for w in words)


def _demo_mask_tail(text, keep=DEMO_TAIL_KEPT):
    """Redact all but the last `keep` characters, as one jittered run.

    Separators go with the redacted part, so "1111-2222-3333-4444" does not
    leak its grouping. A value no longer than `keep` is masked outright
    rather than shown whole.
    """
    value = str(text).strip()
    if len(value) <= keep:
        return _mask_word(value)
    return _mask_word(value[:-keep]) + value[-keep:]


def _demo_mask_url(text):
    """A URL with its scheme kept and everything after it redacted.

    The scheme is a URL's equivalent of a name's first word: enough to show
    that a value is set, and roughly what kind, without giving away the host
    it points at.
    """
    value = str(text).strip()
    if not value:
        return text
    for scheme in ("https://", "http://"):
        if value.lower().startswith(scheme):
            return scheme + _mask_word(value[len(scheme):])
    return _mask_word(value)


# The same three conventions, named for use outside the verification result:
# the administration pages put real operators' names, National IDs and
# credentials on screen, and an operator presenting to an audience has to be
# able to open those pages without showing them.


def mask_name(text):
    """A person's name, as far as its first word. Matches "Given Name" on the
    Verify page, so one convention covers both."""
    return _demo_mask(text, keep_first_word=True)


def mask_identifier(text):
    """A National ID or a client ID, down to its last character -- enough to
    tell two apart on screen without showing either."""
    return _demo_mask_tail(text)


def mask_url(text):
    return _demo_mask_url(text)


def demo_mode_for(user):
    """Is this operator presenting to an audience right now?

    filter().first(), never get_or_create(): this is read while rendering
    every signed-in page, and creating a row there would be a write on a read
    path -- the same rule the fingerprint reader and SiteSettings.load() obey.
    """
    if user is None:
        return False
    row = (UserSettings.objects.filter(user=user)
           .only("demo_mode").first())
    return bool(row and row.demo_mode)


def is_demo_masked(value):
    """Did this value come back off a screen that was masking it?

    The safety catch for every form that Demo Mode redacts. A masked field
    posted back must never be SAVED -- that would write bullets over a real
    URL or client ID and break sign-in for everybody. The mask character
    cannot occur in a legitimate URL, identifier or name, so its presence is
    an unambiguous "this is not a real value, keep what is stored".
    """
    return DEMO_MASK_CHAR in str(value or "")


def apply_demo_mask(data):
    """Return a masked copy of the verification rows for demo mode.

    Only the rows rendered on the page are masked. The caller keeps the
    unmasked list for the transaction log, so a demo verification is still
    recorded truthfully. The face photo is not touched here -- it is blurred
    in CSS, because masking a base64 image server-side would mean adding an
    imaging library to the production requirements.

    Default-deny: a field in none of the lists above is masked outright, so
    a field switched on later cannot reach an audience by being new.
    """
    masked = []
    for item in data:
        field, value = everify_fields.field_of(item), item.get("value")
        if field in DEMO_NOT_TEXT or field in DEMO_CLEAR:
            pass
        elif value is not None and str(value).strip():
            if field in DEMO_FIRST_WORD_ONLY:
                value = _demo_mask(value, keep_first_word=True)
            elif field in DEMO_LAST_TWO:
                value = _demo_mask_tail(value)
            else:
                value = _demo_mask(value, keep_first_word=False)
        row = dict(item)
        row["value"] = value
        masked.append(row)
    return masked
