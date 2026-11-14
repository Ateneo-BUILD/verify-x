"""Organization context, organization administration, and site administration.

Three audiences, three gates, kept apart on purpose:

  * every signed-in operator  -> choose()
  * admins of one organization -> organization_admin() and its JSON endpoints,
    gated by _org_admin_required(), which resolves the organization from the
    SESSION and never from the request body
  * site admins                -> site_*(), gated by _site_admin_required()

The organization an admin acts on is deliberately not a parameter on the
organization-scoped endpoints. If it were, an admin of one organization could
edit another by changing an id in the request -- the exact shape of bug the
sign-in identity rules exist to prevent, one level up.
"""

import base64
import binascii
import csv
import json
import logging
import re
from datetime import datetime, timedelta, timezone as dt_timezone
from io import StringIO

from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.db.models import Count, Max
from django.db.models.functions import Coalesce
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from accounts import (everify_address, everify_fields, org_names,
                      restricted_tier, signing_status, user_records,
                      verified_answer)
from accounts.models import (DeviceLogEntry, IssuedCredential, Location,
                             Membership, next_issuer_code,
                             next_location_code, Organization,
                             OrganizationFieldSetting, Transaction,
                             TransactionType, User)
from verify import csv_cells

from . import signing
from .core import _admin_scope, _date_filtered
from .helpers import (CARD_NUMBER, DIGITAL_ID, ORG_SESSION_KEY,
                      _available_organizations,
                      _is_org_admin, _membership, _org_admin_required,
                      _remember_context, _remembered_context,
                      _require_context, _require_login, _site_admin_required,
                      is_demo_masked)

logger = logging.getLogger(__name__)

#: What every JSON view answers for a body its pages never send.
INVALID_JSON = {"message": "Invalid JSON."}


def _json_object(request):
    """The JSON object posted, or None: not JSON, or not an object. A view
    answers 400 for that, never a 500."""
    try:
        data = json.loads(request.body)
    except ValueError:  # JSONDecodeError, and UnicodeDecodeError
        return None
    return data if isinstance(data, dict) else None


#: Why the last admin of an organization stays one.
LAST_ADMIN_MESSAGE = (
    "This is the organization's only admin. Make somebody else an admin "
    "first, so the organization is not left with nobody to manage it.")


def _lock_admins(organization_id):
    """Lock the organization's admin memberships for this transaction, so the
    last-admin check and the change it allows are one step: two admins
    removing each other at once cannot both pass. On SQLite the second
    writer is refused by the database's own lock instead."""
    list(Membership.objects.select_for_update().filter(
        organization_id=organization_id, role=Membership.ROLE_ADMIN))


def _last_admin(membership):
    """Is `membership` its organization's only admin? Removing or demoting it
    would leave the organization manageable by site admins alone."""
    return (membership.role == Membership.ROLE_ADMIN
            and not Membership.objects.filter(
                organization_id=membership.organization_id,
                role=Membership.ROLE_ADMIN).exclude(pk=membership.pk).exists())


# ---------------------------------------------------------------------------
# Logos
# ---------------------------------------------------------------------------
# Stored as a data URI on the row rather than as an uploaded file: deploy.sh
# rsyncs the app to instances with no shared media volume, so a file would
# exist on whichever instance received the upload and 404 on the others.

MAX_LOGO_BYTES = 256 * 1024

#: SVG is deliberately absent. It is a document format that can carry script,
#: and this value is echoed into pages and into the printed document.
_LOGO_TYPES = {
    "image/png": (b"\x89PNG\r\n\x1a\n",),
    "image/jpeg": (b"\xff\xd8\xff",),
    "image/gif": (b"GIF87a", b"GIF89a"),
    "image/webp": (b"RIFF",),
}

_DATA_URI = re.compile(r"^data:(image/[a-z+]+);base64,(.+)$", re.I | re.S)


def _clean_logo(raw):
    """Return (data_uri, error). An empty value clears the logo.

    The declared media type is checked against the actual magic bytes, so a
    file cannot claim to be a PNG and be something else.
    """
    raw = (raw or "").strip()
    if not raw:
        return "", ""
    match = _DATA_URI.match(raw)
    if not match:
        return "", "Logo must be a PNG, JPEG, GIF or WebP image."
    media_type = match.group(1).lower()
    if media_type not in _LOGO_TYPES:
        return "", "Logo must be a PNG, JPEG, GIF or WebP image."
    try:
        blob = base64.b64decode(match.group(2), validate=True)
    except (binascii.Error, ValueError):
        return "", "The logo image could not be read. Try uploading it again."
    if not blob:
        return "", "The logo image is empty."
    if len(blob) > MAX_LOGO_BYTES:
        return "", f"Logo must be {MAX_LOGO_BYTES // 1024} KB or smaller."
    if not any(blob.startswith(sig) for sig in _LOGO_TYPES[media_type]):
        return "", "That file is not a valid image."
    return f"data:{media_type};base64,{base64.b64encode(blob).decode('ascii')}", ""


_HEX_COLOR = re.compile(r"^#[0-9a-f]{6}$", re.I)


def _clean_color(raw, fallback="#00386a"):
    raw = (raw or "").strip()
    return raw if _HEX_COLOR.match(raw) else fallback


# ---------------------------------------------------------------------------
# Choosing the working context
# ---------------------------------------------------------------------------

def choose(request):
    """Pick the organization, and the location within it, for this session.

    Shown only when the answer is not already determined: _require_context()
    resolves a single-organization, single-location operator automatically and
    never sends them here.
    """
    user, redir = _require_login(request)
    if redir:
        return redir

    orgs = list(_available_organizations(user))
    if not orgs:
        return render(request, "choose.html", {"user": user, "organizations": []})

    if request.method == "POST":
        return _apply_choice(request, user, orgs)

    remembered_org, remembered_location = _remembered_context(request)
    selected = next((o for o in orgs if o.id == remembered_org), orgs[0])
    return render(request, "choose.html", _choice_context(
        user, orgs, selected, remembered_location))


def _choice_context(user, orgs, selected, selected_location=None, error=""):
    """Every organization the user may enter, each with its own locations.

    All the location lists are rendered, not fetched: switching organization
    on this page must not need a round trip, and there is no endpoint that
    could safely answer "the locations of an organization I have not chosen"
    anyway.
    """
    rows = []
    for org in orgs:
        locations = list(org.locations.filter(is_active=True))
        chosen = selected_location if org.id == selected.id else None
        if chosen not in {loc.id for loc in locations}:
            chosen = locations[0].id if locations else None
        rows.append({
            "org": org,
            "role": ("Admin" if _is_org_admin(user, org) else "Operator"),
            "is_admin": _is_org_admin(user, org),
            # A site admin with no membership here is a guest, and the page
            # says so: their transactions are stamped acting_as_site_admin.
            "guest": _membership(user, org) is None,
            "locations": locations,
            "location_count": len(locations),
            "type_count": org.transaction_types.filter(is_active=True).count(),
            "selected_location": chosen,
            "selected": org.id == selected.id,
        })
    return {
        "user": user,
        "organizations": rows,
        "selected": selected,
        "error": error,
    }


def _apply_choice(request, user, orgs):
    """Validate the submitted pair and start acting for it."""
    try:
        org_id = int(request.POST.get("organization") or 0)
    except ValueError:
        org_id = 0
    org = next((o for o in orgs if o.id == org_id), None)
    if org is None:
        # Not "invalid id": an organization the user cannot enter must look
        # exactly like one that does not exist.
        return render(request, "choose.html", _choice_context(
            user, orgs, orgs[0], None,
            "Select an organization you belong to."))

    locations = list(org.locations.filter(is_active=True))
    location_id = None
    if locations:
        try:
            location_id = int(request.POST.get("location") or 0)
        except ValueError:
            location_id = 0
        if location_id not in {loc.id for loc in locations}:
            return render(request, "choose.html", _choice_context(
                user, orgs, org, None,
                "Select the location you are working at."))

    request.session[ORG_SESSION_KEY] = org.id
    request.session["operator_location"] = str(location_id) if location_id else ""
    return _remember_context(redirect("app"), org.id, location_id)


@require_http_methods(["GET", "POST"])
def switch(request):
    """Drop the current context and ask again.

    A POST with the CSRF token, from the context strip's Change button: it
    forgets the verified answer, and a GET from another site must not. A
    GET only opens the chooser, which leaves the current organization in
    place until another is chosen."""
    user, redir = _require_login(request)
    if redir:
        return redir
    if request.method != "POST":
        return redirect("choose")
    request.session.pop(ORG_SESSION_KEY, None)
    request.session.pop("operator_location", None)
    # What the last organization was answered is not the next one's.
    verified_answer.forget(request.session)
    return redirect("choose")


# ---------------------------------------------------------------------------
# Organization administration (admins of the current organization)
# ---------------------------------------------------------------------------

def organization_admin(request):
    """The organization's own settings, people and lists."""
    user, org, redir = _require_context(request)
    if redir:
        return redir
    if not _is_org_admin(user, org):
        return redirect("app")

    txns = Transaction.objects.filter(organization=org)
    return render(request, "app_admin.html", {
        "user": user,
        "memberships": Membership.objects.filter(organization=org)
                                 .select_related("user"),
        "locations": org.locations.all(),
        "transaction_types": org.transaction_types.all(),
        "total_users": Membership.objects.filter(organization=org).count(),
        "total_verifications": txns.count(),
        "successful_verifications": txns.filter(authentication_result="success").count(),
        "failed_verifications": txns.filter(authentication_result="failure").count(),
        "max_repeat_alert_days": user_records.MAX_REPEAT_ALERT_DAYS,
        "org_signing": signing_status.for_organization(org),
        "name_locked": org_names.locked_for(org, user.is_site_admin),
    })


@require_http_methods(["POST"])
def org_save_profile(request):
    """Name, subtitle, mark colour and logo for the current organization."""
    user, org, err = _org_admin_required(request)
    if err:
        return err
    data = _json_object(request)
    if data is None:
        return JsonResponse(INVALID_JSON, status=400)

    name = (data.get("name") or "").strip()
    if not name:
        return JsonResponse({"message": "Organization name is required."}, status=400)
    name_problem = org_names.problem(name, org)
    if name_problem:
        return JsonResponse({"message": name_problem}, status=400)
    # The name is what this organization's documents say issued them: once it
    # has verified anybody, a site admin's to change.
    if name != org.name and org_names.locked_for(org, user.is_site_admin):
        return JsonResponse({"message": org_names.LOCKED_MESSAGE}, status=403)

    logo = org.logo_data
    if "logo_data" in data:
        logo, error = _clean_logo(data.get("logo_data"))
        if error:
            return JsonResponse({"message": error}, status=400)

    org_names.log_rename(user, org, org.name, name)
    org.name = name
    org.subtitle = (data.get("subtitle") or "").strip()[:255]
    org.mark_color = _clean_color(data.get("mark_color"), org.mark_color)
    org.logo_data = logo
    org.save()
    return JsonResponse({"status": "ok", "message": "Organization profile saved.",
                         "initials": org.initials})


@require_http_methods(["POST"])
def org_save_everify(request):
    """The credentials this organization's verifications run against.

    The secret and the public API key are write-only, like the SSO secret in
    Setup: blank means "keep what is stored", and clearing is explicit.

    The ADDRESS is not saved here, by anybody. Whatever answers there decides
    who a verified person is, so it is a site administrator's decision, made
    on the Site page -- see accounts/everify_address.py. An organization
    admin who could set it could point it at a server of their own and have
    this site sign credentials for people who do not exist. The page shows
    the address read-only; a request that tries to change it anyway is
    refused rather than half-applied.
    """
    user, org, err = _org_admin_required(request)
    if err:
        return err
    data = _json_object(request)
    if data is None:
        return JsonResponse(INVALID_JSON, status=400)

    # Demo Mode redacts the address on the page, so a masked value posted back
    # is "unchanged" too. See is_demo_masked().
    if "everify_base_url" in data:
        posted = str(data.get("everify_base_url") or "").strip()
        if not is_demo_masked(posted) and posted != org.everify_base_url:
            return JsonResponse(
                {"message": "The eVerify base URL is set by a site administrator, "
                            "on the Site page."},
                status=403)

    # Demo Mode redacts the client ID as well. A redacted value posted back
    # keeps what is stored: saving while presenting must not replace the
    # client this organization's verifications bill to with a row of bullets.
    client_id = str(data.get("everify_client_id") or "").strip()[:255]
    if is_demo_masked(client_id):
        client_id = org.everify_client_id

    org.everify_client_id = client_id

    for field, clear_key in (("everify_client_secret", "clear_secret"),
                             ("everify_public_api_key", "clear_public_key")):
        if data.get(clear_key):
            setattr(org, field, "")
        else:
            value = str(data.get(field) or "").strip()
            if value:
                setattr(org, field, value)
    org.save()
    return JsonResponse({
        "status": "ok",
        "message": "eVerify credentials saved.",
        "configured": org.everify_configured,
        "has_secret": bool(org.everify_client_secret),
        "has_public_key": bool(org.everify_public_api_key),
    })


@require_http_methods(["POST"])
def org_save_verification(request):
    """How verification behaves here: User Records and its repeat alert.

    The repeat alert is the organization's own admins' to set: it reads only
    this organization's rows. User Records itself is a SITE ADMIN's
    switch, because it opens every organization's
    rows to this one's operators: an organization admin may send the value
    stored, and nothing else. Whether this organization's records appear in
    other organizations' lists is not decided here -- they do, less the
    types it keeps to itself.

    `repeat_alert` and `repeat_alert_days` may be left out, which keeps what
    is stored: a page loaded before they existed still saves the switch.
    Everything sent is checked before anything is written, so a refusal takes
    the whole save with it.
    """
    user, org, err = _org_admin_required(request)
    if err:
        return err
    data = _json_object(request)
    if data is None:
        return JsonResponse(INVALID_JSON, status=400)

    # A bool and nothing else. "false" is a truthy string, and a switch that
    # turned itself on when somebody turned it off would be worse than none.
    value = data.get("check_user_records")
    if not isinstance(value, bool):
        return JsonResponse(
            {"message": "check_user_records must be true or false."},
            status=400)
    if value != org.check_user_records and not user.is_site_admin:
        return JsonResponse(
            {"message": "Only a site administrator turns User Records on or off."},
            status=403)
    fields = {"check_user_records": value}

    if "repeat_alert" in data:
        if not isinstance(data["repeat_alert"], bool):
            return JsonResponse(
                {"message": "repeat_alert must be true or false."},
                status=400)
        fields["repeat_alert"] = data["repeat_alert"]

    if "repeat_alert_days" in data:
        days = data["repeat_alert_days"]
        # bool is an int in Python, and True would quietly mean one day.
        if (isinstance(days, bool) or not isinstance(days, int)
                or not 0 <= days <= user_records.MAX_REPEAT_ALERT_DAYS):
            return JsonResponse(
                {"message": "The repeat alert window must be a whole number "
                            "of days from 0 to %d."
                            % user_records.MAX_REPEAT_ALERT_DAYS},
                status=400)
        fields["repeat_alert_days"] = days

    for name, field_value in fields.items():
        setattr(org, name, field_value)
    org.save(update_fields=list(fields) + ["updated_at"])
    return JsonResponse({
        "status": "ok",
        "message": "Verification settings saved.",
        "check_user_records": org.check_user_records,
        "repeat_alert": org.repeat_alert,
        "repeat_alert_days": org.repeat_alert_days,
    })


#: The two ID shapes, shared with the failure log (helpers.py).
_CARD_NUMBER = CARD_NUMBER
_DIGITAL_ID = DIGITAL_ID


def _clean_member_ids(data):
    """(card_number, digital_id, error) from an add-member request.

    These rows are made from what an admin types, before the person has ever
    signed in, and their values are then shown on other admins' pages. So
    they are held to the shapes sign-in itself reads -- a 16-digit card
    number, a digital ID of letters and digits -- rather than stored as
    typed.
    """
    card = re.sub(r"[-\s]", "", str(data.get("national_id_card_number") or ""))
    digital = str(data.get("digital_national_id") or "").strip().upper()
    if not card:
        return "", "", "National ID Card Number is required."
    if not _CARD_NUMBER.fullmatch(card):
        return "", "", "National ID Card Number must be 16 digits."
    if digital and not _DIGITAL_ID.fullmatch(digital):
        return "", "", "Digital National ID must be letters and digits only."
    return card, digital, ""


def _may_take_digital_id(target, org):
    """May an admin of `org` attach a digital ID to this existing row?

    Sign-in falls back to the digital ID when eVerify's card number matches
    no row, so whoever attaches one decides who else can sign in as that row.
    An organization admin may do it only to a row that is theirs alone:
    never signed in, not a site admin, not a holder, and a member of no other
    organization. Otherwise an admin could attach an accomplice's digital ID
    to a site admin's row and have the accomplice sign in as them -- and a
    site admin sets the eVerify address. Everybody else's digital ID is
    recorded at their
    own first sign-in, from eVerify's answer.
    """
    return (not target.digital_national_id
            and target.last_login is None
            and not target.reaches_every_organization
            and not target.registered_via
            and not target.memberships.exclude(organization=org).exists())


@require_http_methods(["POST"])
def org_add_member(request):
    """Grant somebody access to the CURRENT organization.

    Membership, not account creation in the security sense: a person who has
    never signed in has no session either way. What this decides is which
    organizations an already-verified identity may act for.
    """
    user, org, err = _org_admin_required(request)
    if err:
        return err
    data = _json_object(request)
    if data is None:
        return JsonResponse(INVALID_JSON, status=400)
    try:
        card_number, digital_id, id_error = _clean_member_ids(data)
        if id_error:
            return JsonResponse({"message": id_error}, status=400)
        role = data.get("role")
        if role not in (Membership.ROLE_OPERATOR, Membership.ROLE_ADMIN):
            role = Membership.ROLE_OPERATOR

        target = User.objects.filter(national_id_card_number=card_number).first()
        attached = False
        new_person = target is None
        if new_person:
            # Phones confirm documents only until a site administrator says
            # otherwise: the restricted tier opens every organization's
            # documents, not this one's.
            target = User.objects.create(national_id_card_number=card_number,
                                         digital_national_id=digital_id,
                                         device_restricted_tier=False)
            logger.warning(
                "Organization admin user %s added new user %s to organization "
                "%s; their phones confirm documents only until a site "
                "administrator grants the restricted tier",
                user.pk, target.pk, org.pk)
        elif digital_id and _may_take_digital_id(target, org):
            target.digital_national_id = digital_id
            target.save(update_fields=["digital_national_id"])
            attached = True

        membership, created = Membership.objects.get_or_create(
            organization=org, user=target, defaults={"role": role})
        if not created:
            if attached:
                # The page's own advice for a "card number only" member: post
                # them again with the digital ID.
                return JsonResponse({"status": "ok",
                                     "message": f"Digital National ID {digital_id} added."})
            return JsonResponse(
                {"message": "That person is already in this organization."}, status=400)
        if new_person:
            return JsonResponse({"status": "ok", "message": (
                f"{card_number} added. Their phones confirm documents only "
                "until a site administrator lets them read holders' details.")})
        return JsonResponse({"status": "ok", "message": f"{card_number} added."})
    except Exception as exc:
        return JsonResponse({"message": f"Error: {exc}"}, status=500)


@require_http_methods(["POST"])
def org_update_member_role(request):
    user, org, err = _org_admin_required(request)
    if err:
        return err
    data = _json_object(request)
    if data is None:
        return JsonResponse(INVALID_JSON, status=400)
    try:
        role = data.get("role")
        if role not in (Membership.ROLE_OPERATOR, Membership.ROLE_ADMIN):
            return JsonResponse({"message": "Invalid role."}, status=400)
        membership = Membership.objects.filter(
            organization=org, user_id=data.get("user_id")).first()
        if membership is None:
            return JsonResponse({"message": "Not a member of this organization."},
                                status=404)
        if membership.user_id == user.id:
            return JsonResponse({"message": "Cannot change your own role."}, status=400)
        with transaction.atomic():
            _lock_admins(org.pk)
            membership.refresh_from_db()
            if role != Membership.ROLE_ADMIN and _last_admin(membership):
                return JsonResponse({"message": LAST_ADMIN_MESSAGE}, status=400)
            membership.role = role
            membership.save(update_fields=["role"])
        return JsonResponse({"status": "ok", "message": f"Role updated to {role}."})
    except Exception as exc:
        return JsonResponse({"message": f"Error: {exc}"}, status=500)


@require_http_methods(["POST"])
def org_remove_member(request):
    """Remove somebody from this organization. The account itself is untouched
    -- they may still be an operator elsewhere."""
    user, org, err = _org_admin_required(request)
    if err:
        return err
    data = _json_object(request)
    if data is None:
        return JsonResponse(INVALID_JSON, status=400)
    try:
        membership = Membership.objects.filter(
            organization=org, user_id=data.get("user_id")).first()
        if membership is None:
            return JsonResponse({"message": "Not a member of this organization."},
                                status=404)
        if membership.user_id == user.id:
            return JsonResponse({"message": "Cannot remove yourself."}, status=400)
        with transaction.atomic():
            _lock_admins(org.pk)
            membership.refresh_from_db()
            if _last_admin(membership):
                return JsonResponse({"message": LAST_ADMIN_MESSAGE}, status=400)
            membership.delete()
        return JsonResponse({"status": "ok", "message": "Removed from this organization."})
    except Exception as exc:
        return JsonResponse({"message": f"Error: {exc}"}, status=500)


def _org_list_crud(model, label, on_create=None):
    """add/update/remove views for a name-only list owned by an organization.

    Every query is filtered by the session's organization, so an id belonging
    to another organization simply is not found.

    `on_create(org, name) -> dict` supplies extra fields at creation. Only
    Location uses it, for the short code its offline credential is named by;
    passing a callable rather than testing the model keeps this helper
    genuinely shared instead of quietly being about one caller.
    """

    @require_http_methods(["POST"])
    def add_view(request):
        user, org, err = _org_admin_required(request)
        if err:
            return err
        data = _json_object(request)
        if data is None:
            return JsonResponse(INVALID_JSON, status=400)
        try:
            name = (data.get("name") or "").strip()
            if not name:
                return JsonResponse({"message": "Name is required."}, status=400)
            if model.objects.filter(organization=org, name__iexact=name).exists():
                return JsonResponse({"message": f"{label} '{name}' already exists."},
                                    status=400)
            extra = on_create(org, name) if on_create else {}
            obj = model.objects.create(organization=org, name=name, **extra)
            return JsonResponse({"status": "ok", "id": obj.id,
                                 "code": getattr(obj, "code", ""),
                                 "message": f"{label} '{name}' added."})
        except Exception as exc:
            return JsonResponse({"message": f"Error: {exc}"}, status=500)

    @require_http_methods(["POST"])
    def update_view(request):
        user, org, err = _org_admin_required(request)
        if err:
            return err
        data = _json_object(request)
        if data is None:
            return JsonResponse(INVALID_JSON, status=400)
        try:
            obj = model.objects.filter(organization=org, id=data.get("id")).first()
            if obj is None:
                return JsonResponse({"message": f"{label} not found."}, status=404)
            if "name" in data:
                name = (data.get("name") or "").strip()
                if not name:
                    return JsonResponse({"message": "Name is required."}, status=400)
                clash = model.objects.filter(organization=org, name__iexact=name)
                if clash.exclude(pk=obj.pk).exists():
                    return JsonResponse({"message": f"{label} '{name}' already exists."},
                                        status=400)
                obj.name = name
            if "code" in data and hasattr(obj, "code"):
                # Uppercase A-Z0-9 only and six at most: this rides a QR
                # payload already at the limit of what a printed stamp can
                # carry, and a code that is not unique within its organization
                # would name two desks the same in a signed credential.
                code = (data.get("code") or "").strip().upper()
                if code:
                    if not re.fullmatch(r"[A-Z0-9]{1,6}", code):
                        return JsonResponse(
                            {"message": "Code must be 1 to 6 characters, "
                                        "letters A-Z and digits only."},
                            status=400)
                    clash = model.objects.filter(organization=org, code=code)
                    if clash.exclude(pk=obj.pk).exists():
                        return JsonResponse(
                            {"message": f"Code '{code}' is already used by "
                                        f"another location."}, status=400)
                obj.code = code
            if "is_active" in data:
                obj.is_active = bool(data.get("is_active"))
            if "shared_in_user_records" in data and hasattr(obj, "shared_in_user_records"):
                # A bool and nothing else: "false" is a truthy string.
                shared = data.get("shared_in_user_records")
                if not isinstance(shared, bool):
                    return JsonResponse(
                        {"message": "shared_in_user_records must be true or false."},
                        status=400)
                obj.shared_in_user_records = shared
            obj.save()
            return JsonResponse({"status": "ok", "message": f"{label} updated."})
        except Exception as exc:
            return JsonResponse({"message": f"Error: {exc}"}, status=500)

    @require_http_methods(["POST"])
    def remove_view(request):
        user, org, err = _org_admin_required(request)
        if err:
            return err
        data = _json_object(request)
        if data is None:
            return JsonResponse(INVALID_JSON, status=400)
        try:
            obj_id = data.get("id")
            if not obj_id:
                return JsonResponse({"message": "ID is required."}, status=400)
            model.objects.filter(organization=org, id=obj_id).delete()
            return JsonResponse({"status": "ok", "message": f"{label} removed."})
        except Exception as exc:
            return JsonResponse({"message": f"Error: {exc}"}, status=500)

    return add_view, update_view, remove_view


org_add_location, org_update_location, org_remove_location = _org_list_crud(
    Location, "Location",
    on_create=lambda org, name: {"code": next_location_code(org, name)})
org_add_transaction_type, org_update_transaction_type, org_remove_transaction_type = \
    _org_list_crud(TransactionType, "Transaction type")


# ---------------------------------------------------------------------------
# Site administration
# ---------------------------------------------------------------------------

def site_admin(request):
    """Every organization on the site, and the button that opens the form for
    another. The button leads to a form; it does not create anything."""
    user, redir = _require_login(request)
    if redir:
        return redir
    if not user.is_site_admin:
        return redirect("app")

    orgs = Organization.objects.all()
    rows = []
    for org in orgs:
        # An organization with history cannot be deleted -- see
        # site_delete_organization() -- so the row offers the reason rather
        # than a button that can only be refused.
        transactions, credentials, log_entries = _history(org)
        rows.append({
            "org": org,
            "people": org.memberships.count(),
            "locations": org.locations.count(),
            "types": org.transaction_types.count(),
            "transactions": transactions,
            "credentials": credentials,
            "log_entries": log_entries,
            "deletable": not (transactions or credentials or log_entries),
        })
    return render(request, "site_admin.html", {
        "user": user,
        "rows": rows,
        "total_organizations": len(rows),
        "active_organizations": sum(1 for r in rows if r["org"].is_active),
        "total_people": User.objects.count(),
        "total_verifications": Transaction.objects.count(),
        "device_log": DeviceLogEntry.objects.aggregate(
            entries=Count("id"), phones=Count("device_uuid", distinct=True),
            last_received=Max("received_at")),
    })


# ---------------------------------------------------------------------------
# The device activity log: the whole site's, and one organization's
# ---------------------------------------------------------------------------

DEVICE_LOG_COLUMNS = [
    "DEVICE_ID", "DEVICE_LABEL", "OWNER", "OWNER_NATIONAL_ID_NUMBER",
    "OWNER_ORGANIZATIONS", "ORGANIZATION", "SEQUENCE", "OCCURRED_AT",
    "RECEIVED_AT", "EVENT", "OUTCOME", "DETAIL", "APP_BUILD", "CHAIN",
    "READABLE",
]

#: An organization's own export: the site's columns less the owner's
#: memberships. Those are the person's, as they are now, across every
#: organization -- one tenant has no business reading which others a person
#: also works for, and ORGANIZATION already says the one that matters here.
ORGANIZATION_DEVICE_LOG_COLUMNS = [
    column for column in DEVICE_LOG_COLUMNS
    if column != "OWNER_ORGANIZATIONS"]

#: A phone's detail values and build string are the phone's to write, and the
#: threat the log exists for is a compromised phone -- so a cell it wrote is
#: not allowed to become a formula on the machine of whoever exports it.
#: The rule is shared with the transactions export: verify/csv_cells.py.
_csv_text = csv_cells.cell
_date_label = csv_cells.date_label


def _detail_text(detail):
    """`key=value; key=value`, sorted by key. Strings as they are; numbers,
    booleans and null in their JSON spelling, so `true` and "true" differ."""
    parts = []
    for key in sorted(detail or {}):
        value = detail[key]
        parts.append("%s=%s" % (key, value if isinstance(value, str)
                                else json.dumps(value)))
    return "; ".join(parts)


def _gmt8(when):
    if not when:
        return ""
    return when.astimezone(dt_timezone(timedelta(hours=8))).strftime(
        "%m/%d/%Y %I:%M %p")


def _organization_cell(entry):
    """Which organization the record was filed under, as the export says it.

    The name it had when the record arrived -- kept even if the organization
    has since been renamed or deleted. A record that named an organization
    this phone was never linked to says so, with the id it claimed: that is
    a finding about the phone, not a blank to be read as "none".
    """
    if entry.organization_name:
        return entry.organization_name
    if entry.claimed_organization_id is not None:
        return "#%d (not linked)" % entry.claimed_organization_id
    return ""


def _device_log_csv(request, entries, columns, filename):
    """The device-log CSV over `entries`, in `columns` -- one writer for both
    exports, so the organization's cannot drift from the site's.

    The range is on the DEVICE's claimed time, because that is when a thing
    happened; a record whose claim was implausible has none, and falls back
    to when it arrived here. Both times are columns, and a gap between them
    is something to read, not something to hide.
    """
    entries = entries.annotate(happened=Coalesce("occurred_at", "received_at"))
    entries = _date_filtered(entries, request, field="happened").order_by(
        "device_uuid", "seq")

    organizations = {}
    if "OWNER_ORGANIZATIONS" in columns:
        owner_ids = set(entries.exclude(owner__isnull=True)
                        .values_list("owner_id", flat=True))
        for owner_id, name in (Membership.objects
                               .filter(user_id__in=owner_ids)
                               .order_by("organization__name")
                               .values_list("user_id", "organization__name")):
            organizations.setdefault(owner_id, []).append(name)

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(columns)
    for entry in entries.iterator():
        cells = {
            "DEVICE_ID": str(entry.device_uuid),
            "DEVICE_LABEL": _csv_text(entry.device_label),
            "OWNER": _csv_text(entry.owner_name),
            "OWNER_NATIONAL_ID_NUMBER": entry.owner_national_id_number,
            "OWNER_ORGANIZATIONS": _csv_text(
                "; ".join(organizations.get(entry.owner_id, []))),
            "ORGANIZATION": _csv_text(_organization_cell(entry)),
            "SEQUENCE": entry.seq,
            "OCCURRED_AT": _gmt8(entry.occurred_at),
            "RECEIVED_AT": _gmt8(entry.received_at),
            "EVENT": entry.event,
            "OUTCOME": entry.outcome,
            "DETAIL": _csv_text(_detail_text(entry.detail)),
            "APP_BUILD": _csv_text(entry.app_build),
            "CHAIN": "ok" if entry.chain_ok else "break",
            "READABLE": "yes" if entry.readable else "no",
        }
        writer.writerow([cells[column] for column in columns])

    response = HttpResponse(output.getvalue(), content_type="text/csv")
    response["Content-Disposition"] = (
        'attachment; filename="%s_%s_%s.csv"'
        % (filename, _date_label(request.GET.get("start")),
           _date_label(request.GET.get("end"))))
    return response


def site_export_device_logs(request):
    """Every phone's activity log, as CSV. A site admin's, and nobody else's.

    **The whole log is site-level, never an organization's.** A device
    belongs to a PERSON, and a person may be a member of several
    organizations; handing one organization everything a phone did would
    show one tenant what that phone did while working for another. So this
    sits beside the site admin page, behind `is_site_admin`, and
    OWNER_ORGANIZATIONS is a column -- the person's memberships as they are
    now -- rather than a filter. ORGANIZATION is the one the RECORD was
    filed under; `admin_export_device_logs` is an organization's view of
    exactly those.

    Not masked in Demo Mode, like every export: a CSV is a data operation,
    not something on a projector.
    """
    user, redir = _require_login(request)
    if redir:
        return redir
    if not user.is_site_admin:
        return redirect("app")
    return _device_log_csv(request, DeviceLogEntry.objects.all(),
                           DEVICE_LOG_COLUMNS, "device_logs")


def admin_export_device_logs(request):
    """What this organization's phones recorded while working for it, as CSV.

    **Filed, not inferred.** Only records the phone itself said it wrote for
    this organization, and that were attributed to it at upload because the
    phone was linked to it (`device_log.ingest`). Not every record of every
    phone a member owns: a person may work for several organizations, and
    what their phone did for another is that one's. A record claiming an
    organization the phone was never linked to is filed under none, so no
    phone can write itself into an organization's export.

    The admins of the organization in context -- site admins in context
    included -- through the gate the Transactions export uses, so the
    organization comes from the session and never from the request. Same
    range as the site export; no OWNER_ORGANIZATIONS, which would tell this
    tenant where else a person works.
    """
    _, org, err = _admin_scope(request)
    if err:
        return redirect("app")
    slug = (re.sub(r"[^A-Za-z0-9]+", "-", org.name).strip("-").lower()
            or "organization")
    return _device_log_csv(
        request, DeviceLogEntry.objects.filter(organization=org),
        ORGANIZATION_DEVICE_LOG_COLUMNS, "device_logs_%s" % slug)


def site_new_organization(request):
    """The form for an organization that does not exist yet.

    **Nothing is written before this form is submitted.** The button on the
    list page is a LINK, not a create, so an admin who wants to see the form
    first, or who mistypes, leaves no row behind -- a row with no eVerify
    client, which every later screen would have to describe, and which only
    the delete below could be rid of.

    It renders site_organization.html and saves through the same
    _save_organization(), deliberately: a create form of its own would be a
    second home for the name and issuer-code rules, and two of those drift.
    The sections that need a saved row -- the people list, the eVerify field
    list -- are simply not drawn until there is one.
    """
    user, redir = _require_login(request)
    if redir:
        return redir
    if not user.is_site_admin:
        return redirect("app")

    org = Organization()
    error = ""
    if request.method == "POST":
        _, error = _save_organization(request, org)
        if not error:
            return redirect("site_organization", org_id=org.pk)
        # A refused create must not also cost the typing. Editing a saved
        # organization redisplays the STORED row, which is right there and
        # wrong here -- there is no row -- so the unsaved one is filled from
        # what was posted and the form comes back as it was left. The secrets
        # are deliberately not among these: they are write-only and are never
        # rendered back into a page.
        org.name = (request.POST.get("name") or "").strip()
        org.issuer_code = (request.POST.get("issuer_code") or "").strip().upper()
        org.everify_base_url = (request.POST.get("everify_base_url") or "").strip()
        _apply_organization_form(org, request.POST)

    return render(request, "site_organization.html", {
        "user": user,
        "org": org,
        "is_new": True,
        # Everything below needs a row to hang off. Empty rather than absent,
        # so the template asks the same questions of both pages.
        "fields": [],
        "credential_sources": [],
        "memberships": [],
        "location_count": 0,
        "type_count": 0,
        "transaction_count": 0,
        "roles": Membership.ROLE_CHOICES,
        "message": "",
        "error": error,
    })


def site_organization(request, org_id):
    """One organization, as the site admin sees it.

    Deliberately does NOT repeat the locations and transaction-type editors:
    those belong to the organization's own admins, and two screens that can
    disagree about the same list is a bug waiting to happen.
    """
    user, redir = _require_login(request)
    if redir:
        return redir
    if not user.is_site_admin:
        return redirect("app")
    org = Organization.objects.filter(pk=org_id).first()
    if org is None:
        return redirect("site_admin")

    message = error = ""
    if request.method == "POST":
        message, error = _save_organization(request, org)

    org_signing = signing_status.for_organization(org)
    return render(request, "site_organization.html", {
        "user": user,
        "org": org,
        # One list, in the one order it edits.
        "fields": everify_fields.in_order(everify_fields.rows_for(org)),
        "known_fields": everify_fields.KNOWN_COUNT,
        "also_returned": len(everify_fields.FIELD_KEYS) - everify_fields.KNOWN_COUNT,
        # Only organizations that actually have a client are worth offering as
        # a source; the rest would copy nothing.
        "credential_sources": Organization.objects.exclude(pk=org.pk).exclude(
            everify_client_id="").exclude(everify_client_secret=""),
        "memberships": org.memberships.select_related("user"),
        "location_count": org.locations.count(),
        "type_count": org.transaction_types.count(),
        "transaction_count": Transaction.objects.filter(organization=org).count(),
        "roles": Membership.ROLE_CHOICES,
        "message": message,
        "error": error,
        "org_signing": org_signing,
        "signing_notice": signing.take_notice(request),
        # Who may publish and start its key here: a superuser's own login,
        # or any site admin where the signer's policy sets
        # `site_controls_all_keys`. Over the context processor's, which
        # never asks the signer.
        "may_switch_keys": user.may_switch_signing_keys(
            org_signing.get("site_controls_all_keys")),
    })


#: Every plain field of the organization form, with what it may hold. The
#: name and the issuer code are deliberately absent: each has a rule of its
#: own that decides whether the save happens at all. So are the secrets --
#: they are write-only and are never rendered back into a page.
_ORG_TEXT_FIELDS = (
    ("subtitle", 255),
    ("address_line1", 255),
    ("address_line2", 255),
    ("barangay", 120),
    ("municipality", 120),
    ("postal_code", 16),
    ("country", 120),
)

#: The fields Demo Mode redacts on the page. A value that comes back carrying
#: the mask character means "keep what is stored" -- otherwise saving while
#: presenting writes bullets over a real client id or a real phone number.
#: The guard keys on the character rather than on demo_mode, so somebody who
#: genuinely retypes a value during a presentation is still obeyed.
_ORG_MASKED_FIELDS = (
    ("everify_client_id", 255),
    ("contact_person", 255),
    ("contact_email", 254),
    ("contact_mobile", 32),
)


def _apply_organization_form(org, post):
    """Assign the plain fields of the organization form from a POST.

    Shared by the save and by the create page's redisplay after a refusal, so
    what the form holds is described in one place rather than two that drift.
    Assignment only: whether these values are allowed is decided before this
    is called.
    """
    for field, limit in _ORG_TEXT_FIELDS:
        setattr(org, field, (post.get(field) or "").strip()[:limit])
    for field, limit in _ORG_MASKED_FIELDS:
        value = (post.get(field) or "").strip()[:limit]
        if not is_demo_masked(value):
            setattr(org, field, value)
    org.mark_color = _clean_color(post.get("mark_color"), org.mark_color)
    # An unchecked checkbox is absent from the POST, so absence is "off".
    org.is_active = bool(post.get("is_active"))


def _save_organization(request, org):
    """Apply the site-admin form. Returns (message, error)."""
    name = (request.POST.get("name") or "").strip()
    if not name:
        return "", "Organization name is required."
    name_problem = org_names.problem(name, org)
    if name_problem:
        return "", name_problem

    # The code a credential names this organization by. Uppercase A-Z0-9 only:
    # the whole QR string has to stay inside the QR alphanumeric charset, and
    # anything outside it forces byte mode and costs ~45% of the capacity --
    # which on a payload already near the printable limit means a stamp that
    # will not scan.
    code = (request.POST.get("issuer_code") or "").strip().upper()
    if code:
        if not re.fullmatch(r"[A-Z0-9]{2,8}", code):
            return "", ("Issuer code must be 2 to 8 characters, "
                        "letters A-Z and digits only.")
        if Organization.objects.filter(issuer_code=code).exclude(
                pk=org.pk).exists():
            return "", f"Issuer code '{code}' is already used by another organization."
        org.issuer_code = code
    elif org.issuer_code:
        return "", ("Issuer code cannot be cleared: credentials already issued "
                    "name this organization by it.")
    elif org.pk is None:
        # An organization that has none names nobody inside a credential, and
        # nothing about filling in this form prompts an admin to think about
        # it. Suggested from the name, and editable here ever after.
        org.issuer_code = next_issuer_code(name)

    logo = org.logo_data
    if request.POST.get("clear_logo"):
        logo = ""
    elif request.POST.get("logo_data"):
        logo, logo_error = _clean_logo(request.POST.get("logo_data"))
        if logo_error:
            return "", logo_error

    # Demo Mode redacts these on the page. A redacted value posted back keeps
    # what is stored -- see is_demo_masked(). This page is the only one that
    # sets an organization's eVerify address; see accounts/everify_address.py.
    # A stored value is not re-judged, so a row saved before the https rule
    # does not block every other edit on this page.
    old_base_url = org.everify_base_url
    base_url = (request.POST.get("everify_base_url") or "").strip()
    if is_demo_masked(base_url):
        base_url = org.everify_base_url
    elif base_url != org.everify_base_url:
        base_url, base_url_error = everify_address.clean(base_url)
        if base_url_error:
            return "", base_url_error

    # The one new field with a shape worth refusing. A masked value is not
    # checked: it is not an address, it is the page saying "unchanged".
    email = (request.POST.get("contact_email") or "").strip()
    if email and not is_demo_masked(email):
        try:
            validate_email(email)
        except ValidationError:
            return "", f"'{email}' is not a valid email address."

    if org.pk is not None:
        org_names.log_rename(request.session.get("verify_user_id"), org, org.name, name)
    org.name = name
    org.logo_data = logo
    org.everify_base_url = base_url
    _apply_organization_form(org, request.POST)

    for field, clear_key in (("everify_client_secret", "clear_everify_secret"),
                             ("everify_public_api_key", "clear_everify_public_key")):
        if request.POST.get(clear_key):
            setattr(org, field, "")
        else:
            value = (request.POST.get(field) or "").strip()
            if value:
                setattr(org, field, value)
    org.save()
    everify_address.log_change(request.session.get("verify_user_id"),
                               f"organization {org.pk}", old_base_url, base_url)
    return "Organization saved.", ""


@require_http_methods(["POST"])
def site_copy_credentials(request, org_id):
    """Copy another organization's eVerify client onto this one.

    The request carries only the SOURCE ORGANIZATION'S ID -- never a secret.
    That is the whole point of doing this server-side: the client secret and
    public API key are write-only, never rendered back into a page, and a
    "copy" that worked by filling in the form field would have to send them to
    a browser and would quietly undo that.

    Both organizations end up sharing one eVerify client, so their
    verifications bill to the same account and cannot be told apart at the
    provider. That can be a legitimate thing to want, but it is a
    deliberate choice a site admin makes, not something the app should ever do
    on its own -- which is why there is no fallback between clients.
    """
    user, err = _site_admin_required(request)
    if err:
        return err

    target = Organization.objects.filter(pk=org_id).first()
    if target is None:
        return JsonResponse({"message": "Organization not found."}, status=404)

    data = _json_object(request)
    if data is None:
        return JsonResponse(INVALID_JSON, status=400)
    source_id = data.get("source_id")

    if str(source_id) == str(target.pk):
        return JsonResponse(
            {"message": "Choose a different organization to copy from."},
            status=400)

    source = Organization.objects.filter(pk=source_id).first()
    if source is None:
        return JsonResponse({"message": "Organization not found."}, status=404)
    if not source.everify_configured:
        return JsonResponse(
            {"message": f"{source.name} has no eVerify credentials to copy."},
            status=400)

    # A copy is a new setting for the target, so it meets today's rule even
    # when the source was saved before it.
    _, address_error = everify_address.clean(source.everify_base_url)
    if address_error:
        return JsonResponse(
            {"message": f"{source.name}'s eVerify base URL cannot be copied: {address_error}"},
            status=400)

    everify_address.log_change(user, f"organization {target.pk}",
                               target.everify_base_url, source.everify_base_url)
    target.everify_base_url = source.everify_base_url
    target.everify_client_id = source.everify_client_id
    target.everify_client_secret = source.everify_client_secret
    target.everify_public_api_key = source.everify_public_api_key
    target.save(update_fields=["everify_base_url", "everify_client_id",
                               "everify_client_secret",
                               "everify_public_api_key", "updated_at"])

    return JsonResponse({
        "status": "ok",
        "message": (f"Copied {source.name}'s eVerify client to "
                    f"{target.name}. Both now verify against it."),
        "configured": target.everify_configured,
    })


@require_http_methods(["POST"])
def site_assign_member(request, org_id):
    """Put somebody into any organization, as a site admin."""
    user, err = _site_admin_required(request)
    if err:
        return err
    org = Organization.objects.filter(pk=org_id).first()
    if org is None:
        return JsonResponse({"message": "Organization not found."}, status=404)
    data = _json_object(request)
    if data is None:
        return JsonResponse(INVALID_JSON, status=400)
    try:
        card_number, digital_id, id_error = _clean_member_ids(data)
        if id_error:
            return JsonResponse({"message": id_error}, status=400)
        role = data.get("role")
        if role not in (Membership.ROLE_OPERATOR, Membership.ROLE_ADMIN):
            role = Membership.ROLE_OPERATOR
        target, new_person = User.objects.get_or_create(
            national_id_card_number=card_number,
            defaults={"digital_national_id": digital_id})
        if new_person:
            # A site administrator adding somebody new is a site
            # administrator deciding their phones read holders' details, as
            # it was before grants were recorded: recorded as such.
            restricted_tier.grant(target, user, "site organization page, add")
        membership, created = Membership.objects.get_or_create(
            organization=org, user=target, defaults={"role": role})
        if not created and membership.role != role:
            with transaction.atomic():
                _lock_admins(org.pk)
                membership.refresh_from_db()
                if _last_admin(membership):
                    return JsonResponse({"message": LAST_ADMIN_MESSAGE}, status=400)
                membership.role = role
                membership.save(update_fields=["role"])
        return JsonResponse({"status": "ok",
                             "message": f"{card_number} assigned as {role}."})
    except Exception as exc:
        return JsonResponse({"message": f"Error: {exc}"}, status=500)


@require_http_methods(["POST"])
def site_restricted_tier(request, user_id):
    """Grant or withdraw the restricted tier on a person, as a site admin.

    `{"grant": true}` lets every phone the person has paired read holders'
    details from its next sync; `false` makes them confirm documents only.
    Site administrators only: the tier opens every organization's documents,
    so an organization admin cannot hand it out.

    The Site organization page posts JSON. Setup's list posts a form with
    `grant=0` and is sent back to the list.
    """
    actor, err = _site_admin_required(request)
    if err:
        return err
    from_setup = request.content_type != "application/json"
    if from_setup:
        grant = {"1": True, "0": False}.get(request.POST.get("grant"))
    else:
        try:
            data = json.loads(request.body)
        except ValueError:
            data = None
        grant = data.get("grant") if isinstance(data, dict) else None
    if not isinstance(grant, bool):
        return JsonResponse({"message": "Say grant true or false."}, status=400)
    person = User.objects.filter(pk=user_id).first()
    if person is None:
        return JsonResponse({"message": "Person not found."}, status=404)
    if person.is_holder_only:
        # A holder registered their own phone in idmanager, and those phones
        # stay capped whatever this says (Device.public_tier_only).
        return JsonResponse({"message": "A holder's phones read the public "
                             "tier only. Add them to an organization first."},
                            status=400)
    if grant:
        if not person.device_restricted_tier:
            restricted_tier.grant(person, actor, "site page")
        message = "Their phones read holders' details from their next sync."
    else:
        if person.device_restricted_tier:
            restricted_tier.withdraw(person, actor,
                                     "setup" if from_setup else "site page")
        message = "Their phones confirm documents only from their next sync."
    if from_setup:
        return redirect(reverse("setup") + "#restricted-tier")
    return JsonResponse({"status": "ok", "granted": person.device_restricted_tier,
                         "message": message})


@require_http_methods(["POST"])
def site_remove_member(request, org_id):
    user, err = _site_admin_required(request)
    if err:
        return err
    data = _json_object(request)
    if data is None:
        return JsonResponse(INVALID_JSON, status=400)
    try:
        membership = Membership.objects.filter(
            organization_id=org_id, user_id=data.get("user_id")).first()
        if membership is None:
            return JsonResponse({"message": "Not a member of this organization."},
                                status=404)
        with transaction.atomic():
            _lock_admins(org_id)
            membership.refresh_from_db()
            if _last_admin(membership):
                return JsonResponse({"message": LAST_ADMIN_MESSAGE}, status=400)
            membership.delete()
        return JsonResponse({"status": "ok", "message": "Removed."})
    except Exception as exc:
        return JsonResponse({"message": f"Error: {exc}"}, status=500)


@require_http_methods(["POST"])
def site_toggle_organization(request, org_id):
    """Enable or disable an organization.

    Disabling destroys nothing: people, locations and transactions stay. It
    stops the organization being selectable, and _current_organization()
    re-checks on every request, so sessions already inside it end at once.
    """
    user, err = _site_admin_required(request)
    if err:
        return err
    org = Organization.objects.filter(pk=org_id).first()
    if org is None:
        return JsonResponse({"message": "Organization not found."}, status=404)
    data = _json_object(request)
    if data is None:
        return JsonResponse(INVALID_JSON, status=400)
    org.is_active = bool(data.get("is_active"))
    org.save(update_fields=["is_active", "updated_at"])
    return JsonResponse({"status": "ok", "is_active": org.is_active,
                         "message": ("Enabled." if org.is_active else "Disabled.")})


def _history(org):
    """(transactions, issued credentials, phone log records) filed under
    `org`: what deleting it would leave belonging to no organization."""
    return (Transaction.objects.filter(organization=org).count(),
            IssuedCredential.objects.filter(organization=org).count(),
            DeviceLogEntry.objects.filter(organization=org).count())


def _plural(count, noun):
    return f"{count} {noun}{'' if count == 1 else 's'}"


@require_http_methods(["POST"])
def site_delete_organization(request, org_id):
    """Delete an organization outright.

    Disabling is the reversible answer and stays the usual one -- it keeps
    everything and only stops people signing in. This is for a row that should
    not exist at all: a mistyped name, a tenant that never started. It takes
    the organization's own lists with it -- memberships, locations,
    transaction types, field settings, fingerprint readers -- because each of
    those describes this organization and means nothing without it. Nobody's
    ACCOUNT goes: a person is site-wide and routinely belongs to another
    organization.

    **It refuses once anything has been verified under it, and that refusal is
    the point.** Transaction.organization and IssuedCredential.organization are
    SET_NULL, so deleting would not destroy those rows -- it would do something
    quieter and worse: leave transactions and issued credentials belonging to
    no organization, invisible to every organization-scoped screen and to the
    export, while the log still asserts somebody was verified. That is the
    orphaning migration 0018's unseed() goes out of its way to avoid, and a
    button on a web page must not be able to cause it. Disable it instead.
    Phones' activity-log records filed under it count the same way:
    DeviceLogEntry.organization is SET_NULL too. The
    phones' links to it are the organization's own and go with it.
    """
    user, err = _site_admin_required(request)
    if err:
        return err
    org = Organization.objects.filter(pk=org_id).first()
    if org is None:
        return JsonResponse({"message": "Organization not found."}, status=404)

    transactions, credentials, log_entries = _history(org)
    if transactions or credentials or log_entries:
        return JsonResponse({"message": (
            f"{org.name} has {_plural(transactions, 'transaction')}, "
            f"{_plural(credentials, 'issued credential')} and "
            f"{_plural(log_entries, 'phone log record')} on record. Deleting "
            "it would leave those belonging to no organization at all. "
            "Disable it instead: that keeps the history and stops anyone "
            "signing into it.")}, status=400)

    blocked, unpublished = _signing_keys_in_the_way(org)
    if blocked:
        return JsonResponse({"message": blocked}, status=400)
    from accounts import signer_client
    for key_id in unpublished:
        try:
            signer_client.discard(key_id)
        except signer_client.SignerError as exc:
            return JsonResponse({"message": (
                f"Key {key_id}, which was made for {org.name} and never "
                f"published, could not be discarded ({exc.reason}). Nothing "
                "was deleted; try again.")}, status=503)

    name = org.name
    org.delete()
    message = f"'{name}' deleted."
    if unpublished:
        message += (" Its unpublished signing key%s %s %s discarded."
                    % ("" if len(unpublished) == 1 else "s",
                       ", ".join(map(str, unpublished)),
                       "was" if len(unpublished) == 1 else "were"))
    return JsonResponse({"status": "ok", "message": message})


def _signing_keys_in_the_way(org):
    """(why it may not be deleted, or "", unpublished key ids to discard).

    An organization's signing key outlives the organization: deleted with a
    published or active key, the key would stay in every phone's bundle
    under an id no organization has, no page would offer a button for it,
    and an active one would keep the name from the deployment key, so a new
    organization of the same name would print the plain QR for good. So a
    key
    phones list stops the delete, naming the host command that ends it; one
    never published goes with the organization. A signer that does not
    answer stops it too: nothing is deleted on a guess."""
    from accounts import credential_keys, signer_client

    if not credential_keys.signer_mode():
        return "", []
    try:
        keys = signer_client.public(force=True).get("keys", [])
    except signer_client.SignerError:
        return (f"The signer did not answer, so whether {org.name} has a "
                "signing key cannot be checked. Nothing was deleted; try "
                "again."), []
    mine = [k for k in keys if k.get("organization") == str(org.signing_id)]
    listed = [k for k in mine if k["state"] in ("published", "active")]
    if listed:
        commands = "; ".join(
            "cl03signer retire %d%s" % (k["key_id"], " (a second operator "
                                      "confirms)" if k["state"] == "active"
                                      else "")
            for k in listed)
        return (f"{org.name} has signing key"
                f"{'' if len(listed) == 1 else 's'} "
                f"{', '.join(str(k['key_id']) for k in listed)} that phones "
                "list. Deleting it would leave the key signing for nobody, "
                "and its name taken. Disable it instead, or have an operator "
                f"on the signer host run {commands} first."), []
    return "", [k["key_id"] for k in mine
                if k["state"] in ("generated", "certified")]


def _as_order(raw, fallback):
    """A position from the browser, or the default when it sends nonsense."""
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return fallback
    return max(0, min(value, 999))


@require_http_methods(["POST"])
def site_save_fields(request, org_id):
    """Which eVerify fields this organization shows, records, and in what order.

    Site administration, not organization administration -- deliberately, and
    for the mirror of the reason the locations editor is NOT repeated on this
    page. A location list is an organization's own daily business. What is
    printed on a document that leaves the building, and what is kept in a log
    afterwards, is a decision about the deployment, and one screen owns it.

    The list of KEYS is not editable here at any price, and it does not grow
    by itself. It lives in accounts/everify_fields.py -- the set a real Tier
    II lookup returned -- because it is also the whitelist that decides what
    may come out of the response at all; a key this app has never heard of is
    ignored rather than stored.

    One order, shared by the document and the export. One list to edit means
    one position per field.
    """
    user, err = _site_admin_required(request)
    if err:
        return err
    org = Organization.objects.filter(pk=org_id).first()
    if org is None:
        return JsonResponse({"message": "Organization not found."}, status=404)
    data = _json_object(request)
    if data is None:
        return JsonResponse(INVALID_JSON, status=400)

    if data.get("reset"):
        org.field_settings.all().delete()
        return JsonResponse({"status": "ok",
                             "message": "Fields reset to the defaults."})

    posted = {row.get("key"): row for row in data.get("fields", [])
              if isinstance(row, dict)}
    defaults = [row for row in everify_fields.default_rows()
                if row["key"] in posted]
    if not defaults:
        return JsonResponse({"message": "No known fields submitted."},
                            status=400)

    for row in defaults:
        sent = posted[row["key"]]
        name = (sent.get("display_name") or "").strip()[:120]
        OrganizationFieldSetting.objects.update_or_create(
            organization=org, key=row["key"],
            defaults={
                # Storing "" for a name that matches the built-in keeps the
                # two in step if the built-in is ever corrected.
                "display_name": "" if name == row["name"] else name,
                "show_on_document": bool(sent.get("display")),
                # A field whose value cannot be readily logged has no Log
                # toggle on the page; refuse it here too, so a hand-made POST
                # cannot put a base64 image in an export.
                "include_in_log": bool(sent.get("log")) and row["loggable"],
                "position": _as_order(sent.get("position"), row["position"]),
            })
    return JsonResponse({"status": "ok", "message": "Field settings saved."})
