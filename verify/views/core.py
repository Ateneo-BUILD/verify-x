"""Core page views and admin CRUD operations."""

import csv
import logging
import re
from datetime import datetime, timezone as dt_timezone, timedelta
from io import StringIO

from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods

from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from urllib.parse import urlparse

from django.conf import settings

from django.utils import timezone
from django.utils.html import format_html

from accounts import credential_keys, credentials, debug_store
from accounts import devices as device_service
from accounts import (everify_address, everify_fields, restricted_tier,
                      sso_issuer)
from accounts import revocation_feed as revocation_feed_module
from accounts import signing_status, user_records, verified_answer
from verify import csv_cells
from accounts.holders import TRANSACTION_TYPE as SELF_VERIFICATION
from accounts.models import (DebugCapture, DeviceTicket,
                             FingerprintSettings, SiteSettings,
                             Transaction, UserSettings, organizations_open_to)
from .helpers import (_get_session_user, _require_login, _require_context,
                      _current_organization, _is_org_admin, _location_name,
                      _may_enter,
                      apply_demo_mask, demo_mode_for, is_demo_masked,
                      mask_name)
from .everify import _mock_login_allowed
from . import handoff, signing


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Page Views
# ---------------------------------------------------------------------------

def home(request):
    if request.session.get("verify_user_id"):
        return redirect("app")
    # Drives whether login.html loads the liveness SDK. Must track the same
    # switch the server uses to accept mock logins, or DJANGO_DEBUG=1 alone
    # would skip liveness in the browser while the server still demanded a real
    # session id from the upstream.
    site = SiteSettings.load()
    # Both conditions, so a half-configured provider never replaces the
    # working login page with one that cannot sign anybody in.
    if site.sso_login_active:
        return render(request, "login_sso.html", _sso_page_context(site))
    return render(request, "login.html", {"debug": _mock_login_allowed()})


def _sso_page_context(site, error=""):
    """Context for login_sso.html. The issuer host is shown to the operator
    so it is obvious which service the sign-in is handed to."""
    host = urlparse(site.sso_issuer).netloc or site.sso_issuer
    return {"sso_issuer_host": host, "error": error}


def app(request):
    user, org, redir = _require_context(request)
    if redir:
        return redir
    # The Verify page is the next person: whoever was verified last is no
    # longer on file, for the document, the log or User Records.
    verified_answer.forget(request.session)
    user_settings, _ = UserSettings.objects.get_or_create(user=user)
    # The reader belongs to the desk, so it is looked up for THIS
    # organization. filter().first(), not get_or_create(): most operators
    # have no reader, and creating an empty row on every page view would be
    # a write on a read path.
    fingerprint = FingerprintSettings.objects.filter(
        user=user, organization=org).first()
    return render(request, "app.html", {
        "user": user,
        "operator_location": request.session.get("operator_location", ""),
        "settings": user_settings,
        "fingerprint": fingerprint,
        # An organization with no client of its own cannot verify. Say so on
        # the page rather than letting the operator reach the failure with a
        # citizen in front of them.
        "everify_ready": org.everify_configured,
    })


def setup(request):
    user, redir = _require_login(request)
    if redir:
        return redir

    settings_obj, _ = UserSettings.objects.get_or_create(user=user)
    site = SiteSettings.load()
    # Fingerprint settings belong to (operator, organization). A site admin
    # with no organization selected has no reader to configure, and the
    # section says so rather than saving into nowhere.
    org = _current_organization(request, user)
    fingerprint = None
    if org is not None:
        fingerprint = (FingerprintSettings.objects
                       .filter(user=user, organization=org).first()
                       or FingerprintSettings(user=user, organization=org))
    message = ""
    error = ""

    if request.method == "POST":
        # Demo Mode redacts these on screen. A redacted value posted back must
        # never be stored -- it would replace a working reader endpoint, or a
        # client ID that signs everybody in, with a row of bullets. The
        # template also marks the fields readonly, but this is the guard
        # that actually holds: it holds against a hand-made POST and a
        # template edit.
        endpoint = (request.POST.get("fingerprint_auth_endpoint") or "").strip()
        serial = (request.POST.get("serial_number") or "").strip()
        if fingerprint is not None:
            if is_demo_masked(endpoint):
                endpoint = fingerprint.auth_endpoint
            if is_demo_masked(serial):
                serial = fingerprint.serial_number
        # An unchecked checkbox is absent from the POST, so absence is "off".
        demo_mode = bool(request.POST.get("demo_mode"))

        if len(serial) > 20:
            error = "Serial number must be 20 characters or fewer."
        elif endpoint:
            try:
                URLValidator(schemes=["http", "https"])(endpoint)
            except ValidationError:
                error = "Fingerprint Auth WebAPI Endpoint must be a valid URL."

        # Site administration is site-admin only. A non-site-admin POST never
        # reaches these fields, so an organization admin cannot change the
        # site's login method or read back its credentials by posting the
        # form themselves.
        if user.is_site_admin and not error:
            error = _save_site_settings(request, site)

        if not error:
            settings_obj.demo_mode = demo_mode
            settings_obj.save()
            if org is not None:
                fingerprint, _ = FingerprintSettings.objects.get_or_create(
                    user=user, organization=org)
                fingerprint.auth_endpoint = endpoint
                fingerprint.serial_number = serial
                fingerprint.save()
            message = "Setup saved."

    context = {
        "user": user,
        "settings": settings_obj,
        "fingerprint": fingerprint,
        "site": site,
        "login_modes": SiteSettings.LOGIN_MODES,
        "sso_allowed_issuers": sso_issuer.allowed_issuers(),
        "message": message,
        "error": error,
        # Whether this deployment may keep eVerify responses at all. It is
        # the environment gate, not the switch: the section appears only
        # where a store can exist, and production is neither.
        "debug_store_open": debug_store.debug_allowed(),
    }
    # The store's own section, and only where there is a store and somebody
    # entitled to look at real faces. Two checks, exactly as `/debug-cleanup/`
    # makes them, and neither replaces the other.
    if context["debug_store_open"] and user.is_site_admin:
        context.update(debug_store.store_summary())
        context["captures"] = list(DebugCapture.objects.all()[:25])
    # Credential signing, site admins only: what the signer holds, and the
    # three reversible things this page may do about it.
    if user.is_site_admin:
        context["credential_validity_ceiling"] = credential_keys.validity_ceiling_days()
        context["signing"] = signing_status.overview()
        context["signing_notice"] = signing.take_notice(request)
        # Where this page's pairing QR sends phones: the host their System
        # CA must name.
        context["pairing_host"] = (urlparse(device_service.base_url(request))
                                   .hostname or "")
        # Everybody whose phones read holders' details, from every
        # organization's documents.
        context["restricted_people"] = list(restricted_tier.holders())
    return render(request, "setup.html", context)


def _save_site_settings(request, site):
    """Apply the site-admin-only fields. Returns an error string, or ""."""
    login_mode = (request.POST.get("login_mode") or "").strip()
    if login_mode not in dict(SiteSettings.LOGIN_MODES):
        return "Unrecognised login method."

    # Absent means a post from before the field existed, and leaves it alone.
    old_validity = site.credential_validity_days
    if "credential_validity_days" in request.POST:
        ceiling = credential_keys.validity_ceiling_days()
        raw_validity = (request.POST.get("credential_validity_days") or "").strip()
        days = int(raw_validity) if raw_validity.isascii() and raw_validity.isdigit() else 0
        if not 1 <= days <= ceiling:
            return ("Credential validity must be a whole number of days from 1 to "
                    "%d." % ceiling)
        site.credential_validity_days = days

    def kept(field, stored):
        """The submitted value, or the stored one if it came back redacted.

        Demo Mode masks these fields on screen; saving the form while it is on
        must leave them exactly as they were rather than writing bullets into
        the credentials the whole site signs in against.
        """
        value = (request.POST.get(field) or "").strip()
        return stored if is_demo_masked(value) else value

    # Whatever answers here decides who signs in, so it is held to the same
    # rule as an organization's address: https only. See accounts/everify_address.py.
    old_everify_base = site.everify_base_url
    everify_base = kept("everify_base_url", site.everify_base_url)
    if everify_base != site.everify_base_url:
        everify_base, base_error = everify_address.clean(everify_base)
        if base_error:
            return base_error

    # The issuer decides who signs in when SSO is selected, so it must be one
    # the server lists (accounts/sso_issuer.py). One stored before that rule
    # is kept, not re-judged, so other edits still save; it simply does not
    # count as SSO configured.
    old_issuer = site.sso_issuer
    issuer = kept("sso_issuer", site.sso_issuer)
    if issuer.rstrip("/") != (site.sso_issuer or "").rstrip("/"):
        issuer, issuer_error = sso_issuer.clean(issuer)
        if issuer_error:
            return issuer_error
    else:
        issuer = site.sso_issuer

    client_id = kept("sso_client_id", site.sso_client_id)
    # The secret is write-only: the form never renders it back, so a blank
    # field means "leave it alone", not "clear it". Clearing is explicit.
    secret = (request.POST.get("sso_client_secret") or "").strip()
    if request.POST.get("sso_clear_secret"):
        site.sso_client_secret = ""
    elif secret:
        site.sso_client_secret = secret

    # The eVerify client that signs operators IN. Not the one verifications
    # run against -- that is per organization. Same write-only rule as above.
    site.everify_base_url = everify_base
    site.everify_client_id = kept("everify_client_id", site.everify_client_id)
    for field, clear_key in (("everify_client_secret", "everify_clear_secret"),
                             ("everify_public_api_key", "everify_clear_public_key")):
        if request.POST.get(clear_key):
            setattr(site, field, "")
        else:
            value = (request.POST.get(field) or "").strip()
            if value:
                setattr(site, field, value)

    site.login_mode = login_mode
    site.sso_issuer = issuer
    site.sso_client_id = client_id

    if login_mode == SiteSettings.LOGIN_SSO and site.sso_issuer_refused:
        return ("The SSO issuer is not one this server allows, so single "
                "sign-on cannot be selected. Its operator lists the issuers "
                "it may use in SSO_ALLOWED_ISSUERS.")
    if login_mode == SiteSettings.LOGIN_SSO and not site.sso_configured:
        return ("Single sign-on needs an issuer, a client ID and a client secret "
                "before it can be selected as the login method.")

    site.save()
    actor = request.session.get("verify_user_id")
    everify_address.log_change(actor, "site sign-in", old_everify_base, everify_base)
    sso_issuer.log_change(actor, old_issuer, issuer)
    if site.credential_validity_days != old_validity:
        logger.warning("user %s changed credential validity from %d to %d days",
                       actor, old_validity, site.credential_validity_days)
    return ""


def validate(request):
    user, org, redir = _require_context(request)
    if redir:
        return redir
    return render(request, "validate.html", {"user": user})


def transaction_payload(txn):
    """What `/api/validate/` says about one transaction.

    Split out of the view so the ONE thing that can also need it -- the
    development sample validation page -- builds its rows through exactly this
    code, from an unsaved `Transaction` it never writes. A second formatter
    would drift: the dashes in the card number and the +08 timestamp are
    presentation decisions, and a sample that renders them differently is a
    sample of a page that does not exist.
    """
    gmt8 = dt_timezone(timedelta(hours=8))
    operator_name = ""
    if txn.operator_id or getattr(txn, "operator", None):
        operator = txn.operator
        operator_name = f"{operator.given_name} {operator.last_name}".strip()

    card = txn.national_id_card_number
    if card and len(card) == 16 and card.isdigit():
        card = f"{card[0:4]}-{card[4:8]}-{card[8:12]}-{card[12:16]}"

    ts = ""
    if txn.verification_timestamp:
        ts = txn.verification_timestamp.astimezone(gmt8).strftime(
            "%m/%d/%Y %I:%M %p")

    return {
        "organization": txn.organization.name if txn.organization else "",
        "operator_name": operator_name,
        "operator_location": txn.operator_location,
        "given_name": txn.given_name,
        "middle_name": txn.middle_name,
        "last_name": txn.last_name,
        "national_id_card_number": card,
        "digital_national_id_number": txn.digital_national_id_number,
        "verification_timestamp": ts,
        "transaction_type": txn.transaction_type,
        "authentication_result": txn.authentication_result,
    }


#: What `/api/validate/` tells a caller who may not see whom the record
#: names: that it exists, what it was and how it came out. The name, the ID
#: numbers, the operator and the location go only to a signed-in operator
#: who may enter the record's organization (_may_see_identity). The UUID
#: sits in the clear on every credential's public tier, so without this,
#: anybody shown a phone screen or a printout -- or another organization's
#: operator, or a phone that may only read the public tier -- could look
#: the holder up.
PUBLIC_VALIDATE_KEYS = ("organization", "verification_timestamp",
                        "transaction_type", "authentication_result")


def _may_see_identity(user, txn):
    """The tenant boundary every other page keeps: a member of the record's
    organization, or a site admin or admin of every organization. A record
    with no organization (a holder's self-verification) names its holder to
    those two roles only."""
    if user is None:
        return False
    if user.reaches_every_organization:
        return True
    return txn.organization is not None and _may_enter(user, txn.organization)


@never_cache
def validate_transaction_api(request, transaction_uuid):
    """Look up a transaction by UUID and return its details.

    Deliberately still reachable without a session: this is what the QR code
    on a printed verification document resolves to, and the point of that QR
    is that a third party can check the document is genuine. To anybody
    who may not see whom it names it says only that (PUBLIC_VALIDATE_KEYS,
    with identity_withheld); an operator of the record's organization -- the
    Validate page -- gets every field. Never cached: the answer depends on
    who asks.

    **It answers for stored transactions and nothing else.** The development
    sample page fills the Validate view in the browser instead of teaching
    this endpoint to vouch for a record that was never logged -- an endpoint
    whose whole job is "this really happened" must not have a mode where it
    says so about something that did not.
    """
    try:
        txn = Transaction.objects.select_related("organization").get(
            transaction_id=transaction_uuid)
        payload = transaction_payload(txn)
        if not _may_see_identity(_get_session_user(request), txn):
            payload = {key: payload[key] for key in PUBLIC_VALIDATE_KEYS}
            payload["identity_withheld"] = True
        return JsonResponse({"status": "found", "transaction": payload})
    except Transaction.DoesNotExist:
        return JsonResponse({"status": "not_found"})
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)


def document(request):
    user, org, redir = _require_context(request)
    if redir:
        return redir
    # eVerify's answer, as /everify/ kept it for THIS organization -- never
    # rows the browser sent (accounts/verified_answer.py).
    data = verified_answer.rows(request.session, org)
    if not data:
        return redirect("app")
    # A session opened before the field configuration shipped holds rows with
    # no key and no "show"; that operator is mid-verification while the deploy
    # lands, and their document still has to render.
    data = everify_fields.normalise_rows(data)

    operator_location = request.session.get("operator_location", "")

    # Demo mode masks only what is rendered. The log reads the kept answer,
    # not this page, so it records the real verification whatever is shown.
    # filter().first(), not get_or_create(): this is a GET, and creating a
    # settings row here would be a write on a read path.
    user_settings = UserSettings.objects.filter(user=user).first()
    demo_mode = bool(user_settings and user_settings.demo_mode)
    display_data = apply_demo_mask(data) if demo_mode else data

    shown = [row for row in display_data if row.get("show", True)]

    # The certificate states the holder once, at the top -- portrait, name and
    # both ID numbers -- so those rows must not also appear in the list below
    # it. Selected by eVerify's OWN key through the same helper the phone card
    # uses, so the paper and the card cannot come to name different people;
    # what is PRINTED is still the organization's editable label.
    holder = handoff.holder_from_rows(shown)
    face_value = ""
    holder_age = ""
    for row in shown:
        field = everify_fields.field_of(row)
        if field == handoff.FACE_FIELD:
            face_value = row.get("value") or ""
        elif field == "age":
            holder_age = row.get("value") or ""
    lifted = set(handoff.HOLDER_FIELDS) | {handoff.FACE_FIELD}
    doc_rows = [
        row for row in shown if everify_fields.field_of(row) not in lifted
    ]

    return render(request, "document.html", {
        "user": user,
        # Only the fields the organization shows. Nothing else of the answer
        # reaches the page: the log takes it from the session.
        "data": shown,
        # What the certificate block prints, and the rows left over for the
        # list under it. An organization that displays none of the holder
        # fields simply gets no certificate block -- the template asks.
        "holder_name": holder["name"],
        # After the name on this page only. Not through holder_from_rows():
        # the phone card reads that too, and the card carries no age.
        "holder_age": holder_age,
        "holder_numbers": holder["numbers"],
        "face_value": face_value,
        "doc_rows": doc_rows,
        "demo_mode": demo_mode,
        "operator_location_name": _location_name(org, operator_location),
        # The cut-out card is the holder's phone card, printed on its side,
        # and its size on paper is ONE number rather than a figure typed into
        # CSS: 0.063 mm per canvas pixel puts a QR module at 0.504 mm against
        # the 0.4 mm floor. Everything the template needs to place it comes
        # from the module that decides it, so the two cannot drift.
        #
        # Nothing here sizes a symbol: the renderer draws both at 8 canvas
        # pixels a module, and the scale above is what turns that into
        # millimetres.
        "card_print_w_mm": credentials.CARD_PRINT_W_MM,
        "card_print_h_mm": credentials.CARD_PRINT_H_MM,
        "card_canvas_w_px": credentials.CARD_CANVAS_W_PX,
        "card_canvas_h_px": credentials.CARD_CANVAS_H_PX,
    })


@require_http_methods(["GET"])
def user_records_api(request):
    """User Records: the verified person's earlier transactions, as JSON.

    Whose records is never a parameter. The person is the one eVerify
    verified in THIS session, for THIS organization
    (accounts/verified_answer.py), so the only way to see somebody's history
    here is to verify them here. `?current=` names the
    transaction the page has just logged, so the list can mark it; it selects
    nothing.

    Searching and paging are the page's: it is sent the newest
    `user_records.MAX_RECORDS` and told when there were more.

    Each record says whether it `counts_as_repeat` -- logged here, inside
    this organization's window, with the alert on -- and `repeat_alert` is
    the window (`{"days": n}`, 0 for any time) or None when the alert is off.
    Matching the TYPE is the page's, because it follows the picker.
    """
    user = _get_session_user(request)
    org = _current_organization(request, user) if user else None
    if user is None or org is None:
        return JsonResponse({"message": "Unauthorized."}, status=403)
    if not org.check_user_records:
        return JsonResponse(
            {"message": "User Records is off for this organization."},
            status=403)

    key = verified_answer.subject(request.session, org)
    txns, truncated = user_records.records_for(key)
    if key:
        # Who read whose history, here and when.
        user_records.record_read(user, org, key, len(txns))
    current = request.GET.get("current", "")
    demo_mode = demo_mode_for(user)
    on, since = user_records.repeat_window(org)
    records = [_user_record(txn, current, demo_mode,
                            user_records.counts_as_repeat(txn, org, on, since,
                                                          current),
                            viewer=org)
               for txn in txns]
    response = JsonResponse({
        "status": "ok",
        # False when this session verified nobody eVerify could key -- the
        # page says so rather than claiming the person has no history.
        "available": bool(key),
        "records": records,
        "organizations": len({r["organization"] for r in records}),
        "truncated": truncated,
        "limit": user_records.MAX_RECORDS,
        "repeat_alert": ({"days": org.repeat_alert_days or 0} if on
                         else None),
    })
    # Another organization's operators and dates. Not for a shared cache.
    response["Cache-Control"] = "no-store"
    return response


def _user_record(txn, current, demo_mode, counts_as_repeat=False, viewer=None):
    """One row of User Records, already decided: the page draws, never chooses.

    `counts_as_repeat` is `user_records.counts_as_repeat()`'s answer; the page
    adds only whether the type matches the one being logged.

    Another organization's row names its type only when that organization
    shares it (`user_records.type_shown`); `viewer` is the organization
    reading.

    A self-verification has no organization and no operator -- the truth
    about it -- so it is named by its issuer, which is where it came from.
    A row whose organization was deleted since keeps its place in the
    person's history but has no name left to show.
    """
    org = txn.organization
    if org is not None:
        organization = org.name
    elif txn.operator_id is None and txn.transaction_type == SELF_VERIFICATION:
        organization = txn.operator_location or SELF_VERIFICATION
    else:
        organization = "Deleted organization"

    operator = ""
    if txn.operator is not None:
        # One string, then masked: mask_name keeps the first word, so
        # masking the halves separately would redact nothing.
        operator = txn.operator.full_name
        if demo_mode:
            operator = mask_name(operator)
        if operator and txn.acting_as_site_admin:
            # So no organization's history shows an operator it never
            # assigned without saying who they were.
            operator += " (site admin)"
        elif operator and txn.acting_as_all_org_admin:
            operator += " (admin of every organization)"

    return {
        "when": handoff.verified_at_text(txn.verification_timestamp),
        "organization": organization,
        "transaction_type": (txn.transaction_type or "—"
                             if user_records.type_shown(txn, viewer)
                             else user_records.TYPE_NOT_SHARED),
        "operator": operator or "—",
        "current": bool(current) and str(txn.transaction_id) == current,
        "counts_as_repeat": bool(counts_as_repeat),
    }


@require_http_methods(["GET", "POST"])
def logout(request):
    """Sign out: a POST with the CSRF token, from the pages' own buttons.

    A GET -- a bookmark, a link typed by hand -- asks first and signs nobody
    out by itself, so another page cannot end somebody's session with an
    image tag."""
    if request.method == "POST":
        request.session.flush()
        return redirect("home")
    if _get_session_user(request) is None:
        return redirect("home")
    return render(request, "sign_out.html")


def get_lookup_data(request):
    """Active locations and transaction types for the CURRENT organization.

    Signed-in only, and scoped: these lists belong to organizations, so
    there is no correct answer to give a caller with no context.
    """
    user, org, redir = _require_context(request)
    if redir:
        return JsonResponse({"locations": [], "transaction_types": []}, status=403)
    return JsonResponse({
        "locations": list(org.locations.filter(is_active=True).values("id", "name")),
        "transaction_types": list(
            org.transaction_types.filter(is_active=True).values("id", "name")),
    })


# ---------------------------------------------------------------------------
# Admin: statistics and export, scoped to the current organization
# ---------------------------------------------------------------------------

def _admin_scope(request):
    """(transactions, organization, error_response) this admin may report on."""
    user = _get_session_user(request)
    org = _current_organization(request, user) if user else None
    if not user or org is None or not _is_org_admin(user, org):
        return None, None, JsonResponse({"error": "Unauthorized"}, status=403)
    return Transaction.objects.filter(organization=org), org, None


def _date_filtered(txns, request, field="verification_timestamp"):
    """Apply the ?start / ?end range. Dates are GMT+8 and inclusive.

    `field` is the timestamp the range is applied to -- the transaction's by
    default; the device log export passes an annotation of its own.
    """
    gmt8 = dt_timezone(timedelta(hours=8))
    start_date = request.GET.get("start", "")
    end_date = request.GET.get("end", "")
    if start_date:
        try:
            start_dt = datetime.strptime(start_date, "%Y-%m-%d").replace(
                hour=0, minute=0, second=0, tzinfo=gmt8)
            txns = txns.filter(**{field + "__gte": start_dt})
        except ValueError:
            pass
    if end_date:
        try:
            end_dt = datetime.strptime(end_date, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59, microsecond=999999, tzinfo=gmt8)
            txns = txns.filter(**{field + "__lte": end_dt})
        except ValueError:
            pass
    return txns


def admin_stats(request):
    """Filtered statistics for the current organization, as JSON."""
    txns, org, err = _admin_scope(request)
    if err:
        return err
    txns = _date_filtered(txns, request)
    return JsonResponse({
        "total_users": org.memberships.count(),
        "total_verifications": txns.count(),
        "successful_verifications": txns.filter(authentication_result="success").count(),
        "failed_verifications": txns.filter(authentication_result="failure").count(),
    })


def _csv_heading(label):
    """A column heading from a display name: GIVEN_NAME, PLACE_OF_BIRTH."""
    return re.sub(r"[^A-Za-z0-9]+", "_", label).strip("_").upper() or "FIELD"


def _logged_value(txn, field):
    """One field off a transaction row.

    logged_fields is the record of what the organization chose to keep. Rows
    written before it existed have none, so fall back to the named column --
    which is also why turning a field off does not blank the history.
    """
    stored = txn.logged_fields or {}
    if field in stored:
        return stored[field]
    column = everify_fields.TRANSACTION_COLUMNS.get(field)
    return getattr(txn, column, "") if column else ""


def _acting_as(txn):
    """The ACTING_AS_SITE_ADMIN cell: "Yes" for a site admin, as it has always
    been, and its own word for an admin of every organization, so a
    spreadsheet filtering on "Yes" still finds exactly the site admins."""
    if txn.acting_as_site_admin:
        return "Yes"
    if txn.acting_as_all_org_admin:
        return "Admin of every organization"
    return ""


def admin_export_transactions(request):
    """Export this organization's transaction log as CSV.

    The person-columns, their order and their headings are the organization's
    own configuration; the transaction's own facts -- who ran it, where, when,
    and whether it succeeded -- are fixed, because they are what makes the row
    a log entry rather than a record about somebody.

    Deliberately NOT masked in Demo Mode: an export is a data operation, not
    something on a projector.

    Every cell goes through `csv_cells.cell`. The names and IDs in a failure
    row are what somebody typed, and the rest came from an upstream: none of
    it may become a formula in the administrator's spreadsheet.
    """
    txns, org, err = _admin_scope(request)
    if err:
        return redirect("app")
    txns = _date_filtered(txns, request).order_by("verification_timestamp")

    columns = everify_fields.log_rows(everify_fields.rows_for(org))

    gmt8 = dt_timezone(timedelta(hours=8))
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ["TRANSACTION_ID", "ORGANIZATION", "OPERATOR_NATIONAL_ID_NUMBER",
         "OPERATOR_LOCATION", "ACTING_AS_SITE_ADMIN"]
        + [_csv_heading(everify_fields.label_for(row)) for row in columns]
        + ["VERIFICATION_TIMESTAMP", "AUTHENTICATION_RESULT",
           "TRANSACTION_TYPE"])

    for txn in txns:
        ts = txn.verification_timestamp
        if ts:
            ts = ts.astimezone(gmt8).strftime("%m/%d/%Y %I:%M %p")
        writer.writerow([csv_cells.cell(value) for value in (
            [str(txn.transaction_id), org.name, txn.operator_national_id_number,
             txn.operator_location, _acting_as(txn)]
            + [_logged_value(txn, row["key"]) for row in columns]
            + [ts or "", txn.authentication_result, txn.transaction_type])])

    response = HttpResponse(output.getvalue(), content_type="text/csv")
    slug = re.sub(r"[^A-Za-z0-9]+", "-", org.name).strip("-").lower() or "organization"
    # The dates go into a response header, so only a real date does.
    start_date = csv_cells.date_label(request.GET.get("start"))
    end_date = csv_cells.date_label(request.GET.get("end"))
    response["Content-Disposition"] = (
        f'attachment; filename="transactions_{slug}_{start_date}_{end_date}.csv"')
    return response


# ---------------------------------------------------------------------------
# The revocation feed a configured device polls
# ---------------------------------------------------------------------------

@require_http_methods(["GET"])
def revocation_feed(request):
    """Every credential this system has withdrawn, signed.

    Deliberately UNAUTHENTICATED. This app has no device registry -- devices
    enrol with the verifier fleet, not here -- and the filter is a list of
    opaque 16-bit fingerprints, so there is nothing in it to protect. What
    matters is that it cannot be forged or stripped, and that is the
    signature's job, not an API key's: a caller who could not authenticate
    would simply be served nothing, which is exactly the outcome an attacker
    wants.

    A device is given this URL when it is configured, and checks the signature
    against the issuer public key it already carries -- the same one it needs
    to verify a credential at all, so nothing new is trusted.
    """
    if not credential_keys.configured():
        # No issuer key means nothing here can be signed, and an unsigned
        # feed is worse than no feed: it is strippable.
        return JsonResponse(
            {"error": "Revocation is not configured on this deployment."},
            status=503)
    try:
        feed = revocation_feed_module.current_feed()
    except Exception:
        logger.exception("revocation feed could not be built")
        return JsonResponse({"error": "Revocation feed unavailable."},
                            status=503)
    response = JsonResponse(feed)
    # Cacheable, but never past the point a device would reject it anyway.
    response["Cache-Control"] = "public, max-age=%d" % min(
        settings.CREDENTIAL_REVOCATION_REBUILD_SECONDS,
        settings.CREDENTIAL_REVOCATION_TTL_SECONDS)
    return response


# ---------------------------------------------------------------------------
# Devices: the phones a signed-in operator has paired
# ---------------------------------------------------------------------------
# Every management operation is handed to a phone the same way: a ticket is
# minted by a POST and its QR shown by the GET that follows, with the id held
# in the SESSION in between rather than in the URL -- so a live code never
# lands in browser history, a log line, or a Referer header sent to whatever
# the page links to.

PAIRING_SESSION_KEY = "pending_pairing_code"

#: What the panel says, per operation. Kept here rather than branched in the
#: template: three near-identical blocks of markup is how one of them quietly
#: stops matching the others.
#: `format_html` throughout, not %: the phone's name is typed by whoever
#: paired it, and it is being interpolated into markup.
TICKET_COPY = {
    "enrol": {
        "heading": "Pair a phone",
        #: Used instead when a name was typed, so the panel confirms what this
        #: handset is about to be called. Only `enrol` has two: for the other
        #: operations the phone already exists and always has a name.
        "heading_named": "Pair {}",
        "lead": "Open the Verify app on the phone, tap <b>Scan</b>, and point "
                "it at this. The phone gets the server address and the code "
                "together &mdash; nothing needs typing.",
    },
    "sync": {
        "heading": "Refresh the keys on {}",
        "lead": "Scan this with <b>{}</b>. It connects to this server and "
                "pulls a fresh set of keys, a trust list and the revocation "
                "filter &mdash; none of which would fit in a QR.",
    },
    "rekey": {
        "heading": "Replace the key on {}",
        "lead": "Scan this with <b>{}</b> after reinstalling or restoring it. "
                "The phone generates a new key in its Secure Enclave and "
                "rebinds to this record, keeping its history.",
    },
}


def _pending_ticket(request, user):
    """The QR to show on this render, if one was just minted for this person.

    Popped, not read: a ticket is single-use, and leaving it in the session
    would redisplay a spent one on the next refresh as though it were good.
    """
    ticket_id = request.session.pop(PAIRING_SESSION_KEY, None)
    if not ticket_id:
        return None
    ticket = DeviceTicket.objects.filter(
        pk=ticket_id, user=user, used_at__isnull=True,
        expires_at__gt=timezone.now()).select_related("device").first()
    if ticket is None:
        return None
    url = device_service.base_url(request)
    copy = TICKET_COPY.get(ticket.purpose, TICKET_COPY["enrol"])
    # Which phone this code is for: an operation on one that exists says what
    # it is called, and a pairing says what it is about to be called. The
    # second half is the one that was missing -- the name was typed, stored on
    # the ticket and then never shown, so nothing confirmed it had taken.
    name = ticket.device.label if ticket.device else ticket.label
    heading = (name and copy.get("heading_named")) or copy["heading"]
    # No payload means no symbol: the template has nothing to draw. Decided
    # here rather than in the markup so it holds for every caller -- a guard in
    # a template is one forgotten `{% if %}` away from shipping the thing it
    # was meant to prevent. A QR the app refuses is worse than none: scanning
    # is the step people trust, and one that silently does nothing sends
    # somebody looking at the handset, the camera and the network before they
    # look at the address.
    will_load = device_service.phone_will_load(url)
    return {
        "code": ticket,
        "url": url,
        "heading": format_html(heading, name),
        "lead": format_html(copy["lead"], name),
        "payload": device_service.ticket_payload(ticket, url=url)
                   if will_load else "",
        "reachable": device_service.is_reachable(url),
        "will_load": will_load,
        "scheme_upgraded": device_service.was_upgraded(request),
        # What the boxes ticked will link, confirmed where the QR is -- the
        # same reason the heading names the phone. Only a pairing links
        # anything; a sync or re-key leaves the phone's links as they are.
        "organizations": (device_service.ticket_organizations(ticket)
                          if ticket.purpose == DeviceTicket.PURPOSE_ENROL
                          else []),
    }


def _pairing_preselect(request, user, organizations):
    """Which organizations the pairing form starts ticked.

    The one this session is working in, when there is one: somebody pairing
    a phone from inside an organization is almost always pairing it for that
    organization. Otherwise the only one, when there is exactly one -- the
    same "only one possible answer" rule `_auto_context` follows. Otherwise
    none, rather than all: ticking every organization a site admin may enter
    would put a chooser of the whole deployment on a phone nobody asked for.
    """
    current = _current_organization(request, user)
    if current is not None and current in organizations:
        return {current.id}
    if len(organizations) == 1:
        return {organizations[0].id}
    return set()


def devices(request):
    """The phones this person has paired, and a way to pair another."""
    user, redir = _require_login(request)
    if redir:
        return redir

    # The organizations this person may enter: what each phone's "Works for"
    # boxes offer, and the pairing form's. Never more -- see
    # `device_service.set_organizations`, which applies the same rule again.
    organizations = list(organizations_open_to(user))
    phones = list(user.devices.order_by("revoked_at", "-enrolled_at"))
    for phone in phones:
        # What the phone is told at its next sync, which is the honest thing
        # to show: a link to an organization this person can no longer
        # enter is kept, but not sent, so it is not listed either.
        phone.works_for = (list(device_service.linked_organizations(
            phone)) if phone.is_active else [])
        phone.works_for_ids = {org.id for org in phone.works_for}

    return render(request, "devices.html", {
        "user": user,
        "active_nav": "devices",
        "devices": phones,
        "organizations": organizations,
        "pairing_organizations": _pairing_preselect(request, user,
                                                    organizations),
        "pairing": _pending_ticket(request, user),
        # Shown, never set here. A page where somebody grants their own phone
        # access to personal data would not be a control -- see the note on
        # User.device_restricted_tier.
        "restricted_tier": user.device_restricted_tier,
        "pairing_ttl_minutes": settings.DEVICE_PAIRING_TTL_SECONDS // 60,
        "lease_days": settings.DEVICE_LEASE_SECONDS // 86400,
    })


@require_http_methods(["POST"])
def devices_ticket(request):
    """Authorise one management operation, and show its QR.

    Pairing, re-keying and syncing take the same route because they are the
    same act on the web side: an authenticated person says what should happen
    to which phone, and the QR is only how that reaches the handset.

    The device is looked up on THIS person's devices, so a device id belonging
    to somebody else does not resolve -- the same shape as the organization
    rule, one level down. `mint_ticket` checks ownership again, because it is
    the one place a ticket is created.
    """
    user, redir = _require_login(request)
    if redir:
        return redir

    device = None
    device_id = device_service.parse_device_id(request.POST.get("device_id"))
    if device_id is not None:
        device = user.devices.filter(device_id=device_id).first()
    try:
        # The boxes are on the pairing form only; mint_ticket keeps them for
        # an enrol ticket and only where this person may enter.
        ticket = device_service.mint_ticket(
            user, request.POST.get("purpose", DeviceTicket.PURPOSE_ENROL),
            device=device, label=request.POST.get("label", ""),
            organization_ids=request.POST.getlist("organizations"))
    except device_service.PairingError:
        # Nothing to show, and nothing to explain: every way to get here is a
        # hand-made POST, since the page only offers operations that apply.
        return redirect("devices")
    request.session[PAIRING_SESSION_KEY] = ticket.pk
    return redirect("devices")


@require_http_methods(["POST"])
def devices_rename(request):
    """Change what one of this person's own phones is listed as.

    The device is looked up on THIS person's devices, so an id belonging to
    somebody else does not resolve -- the same shape as every other operation
    on this page, and the reason a rename needs no separate ownership check
    of its own.

    Nothing about the handset changes: a name is presentation, it signs
    nothing and no credential carries it. So unlike sync and re-key this does
    not mint a ticket -- there is nothing here for a phone to scan.
    """
    user, redir = _require_login(request)
    if redir:
        return redir
    device_id = device_service.parse_device_id(request.POST.get("device_id"))
    device = (user.devices.filter(device_id=device_id).first()
              if device_id is not None else None)
    if device is not None:
        device_service.rename(device, request.POST.get("label", ""))
    return redirect("devices")


@require_http_methods(["POST"])
def devices_organizations(request):
    """Change which organizations one of this person's own phones works for.

    The ticked boxes are the whole answer, applied as a difference by
    `device_service.set_organizations`: a box newly ticked links, one newly
    cleared ends its link -- stamped, never deleted, because the phone may
    still be holding records it wrote for that organization. A box for an
    organization this person may not enter cannot be posted into a link.

    Like rename, no ticket and nothing to scan: the phone hears at its next
    sync, which is the soonest it could act on it anyway. The device is
    looked up on THIS person's active devices, so an id belonging to
    somebody else, or a revoked phone, resolves to nothing.
    """
    user, redir = _require_login(request)
    if redir:
        return redir
    device_id = device_service.parse_device_id(request.POST.get("device_id"))
    device = (user.devices.filter(device_id=device_id,
                                  revoked_at__isnull=True).first()
              if device_id is not None else None)
    if device is not None:
        try:
            device_service.set_organizations(
                device, request.POST.getlist("organizations"), actor=user)
        except device_service.PairingError:
            # Only a hand-made POST gets here; the page offers this form on
            # the person's own active phones and nowhere else.
            pass
    return redirect("devices")


@require_http_methods(["POST"])
def devices_revoke(request):
    """Withdraw one of this person's own devices."""
    user, redir = _require_login(request)
    if redir:
        return redir
    device_id = device_service.parse_device_id(request.POST.get("device_id"))
    device = (user.devices.filter(device_id=device_id).first()
              if device_id is not None else None)
    if device is not None:
        device_service.revoke(device, actor=user,
                              reason="Revoked by the owner")
    return redirect("devices")
