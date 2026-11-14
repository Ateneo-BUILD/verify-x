"""PSA eVerify API integration and transaction logging."""

import json
import logging
import os
import re
import time
from datetime import datetime

import requests

from django.conf import settings
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from django.urls import reverse

from accounts import (credential_keys, credentials, debug_store, devices,
                      everify_address, everify_face, everify_fields, minting,
                      throttle, user_records, verified_answer)
from accounts.models import (DebugCapture, IssuedCredential, SiteSettings,
                             Transaction)
from . import handoff, login_guard
from .helpers import (CARD_NUMBER, DIGITAL_ID, _current_organization,
                      _find_user, _get_session_user,
                      _log_context, _login_session, apply_demo_mask,
                      demo_mode_for, mask_name)


logger = logging.getLogger(__name__)

#: What a lookup that found nobody says. One constant because two paths
#: produce it -- a real eVerify miss, and the refusal given to a National ID
#: which names no registered operator -- and they have to be word for word
#: identical or the refusal announces itself.
NO_MATCH_MESSAGE = "No matching record found for the provided details."

#: What the document page is told when a credential made from the answer it
#: would log again has been revoked since.
REVOKED_SINCE_MESSAGE = (
    "A document made from this verification has been revoked. Verify the "
    "person again before logging another.")

def _logged_from_this_answer(session, org, user):
    """The transactions the answer kept for `org` has already made: this
    operator's successful rows here about the same person since it was
    kept. Empty when the answer names nobody User Records can key, or was
    kept before the time was recorded."""
    subject = verified_answer.subject(session, org)
    since = verified_answer.kept_at(session, org)
    if not subject or since is None:
        return []
    return list(Transaction.objects.filter(
        organization=org, operator=user, authentication_result="success",
        subject_key=subject, verification_timestamp__gte=since))


#: What the Verify page is told when its session ended while it was open.
SESSION_ENDED_MESSAGE = "Your session has ended. Sign in again to verify."

#: eVerify verified the person, but the card number it returned is not the
#: one this site holds for them -- see helpers._lookup_user.
CARD_MISMATCH_MESSAGE = (
    "eVerify confirmed this National ID, but its card number is not the one on "
    "file here. If the card was replaced, ask a site administrator to update it.")

# The .env values. Since organizations arrived these are only a FALLBACK for
# the site-level login client, used when the SiteSettings row has none -- so
# an upgrade cannot take National ID login down between the migration landing
# and an admin filling the Setup form. They are never a fallback for the
# per-organization verification client; see _org_everify().
EVERIFY_BASE_URL = os.environ.get('EVERIFY_BASE_URL', 'https://ws.everify.gov.ph/api')
EVERIFY_CLIENT_ID = os.environ.get('EVERIFY_CLIENT_ID', '')
EVERIFY_CLIENT_SECRET = os.environ.get('EVERIFY_CLIENT_SECRET', '')
EVERIFY_PUBLIC_API_KEY = os.environ.get('EVERIFY_PUBLIC_API_KEY', '')


class EverifyClient:
    """Which eVerify credentials a request runs against, and where they came from."""

    def __init__(self, base_url, client_id, client_secret, public_key, source):
        self.base_url = base_url or EVERIFY_BASE_URL
        self.client_id = client_id
        self.client_secret = client_secret
        self.public_key = public_key
        self.source = source
        #: https, on a host EVERIFY_ALLOWED_HOSTS lists. Judged here, where
        #: every request starts, as well as when an address is saved: a row
        #: written before the rule, or the .env fallback, must not be able to
        #: send the secret -- or take an answer -- anywhere else.
        self.address_allowed = everify_address.allowed(self.base_url)

    @property
    def configured(self):
        return bool(self.client_id and self.client_secret and self.address_allowed)

    def refusal(self, owner):
        """Why this client cannot run, in words for whoever has to fix it."""
        if not self.address_allowed:
            logger.error("eVerify address refused for %s: %r is not https on a host "
                         "in EVERIFY_ALLOWED_HOSTS", self.source, self.base_url)
            return (f"{owner}'s eVerify address is not one this server allows. "
                    "A site administrator must correct it.")
        return None


def _site_everify():
    """The client that SIGNS OPERATORS IN.

    Site-level by necessity: the login page runs before anybody has a session,
    so there is no organization yet whose client could be used.
    """
    site = SiteSettings.load()
    if site.everify_configured:
        return EverifyClient(site.everify_base_url, site.everify_client_id,
                             site.everify_client_secret,
                             site.everify_public_api_key, "site")
    return EverifyClient(EVERIFY_BASE_URL, EVERIFY_CLIENT_ID,
                         EVERIFY_CLIENT_SECRET, EVERIFY_PUBLIC_API_KEY, "env")


def _org_everify(org):
    """The client a VERIFICATION runs against, and what gets billed for it.

    No fallback, deliberately. An organization with no client of its own
    cannot verify; falling back to the site client would silently bill one
    organization's verifications to another's account and make a
    misconfiguration look like everything working.
    """
    if org is None:
        return None
    return EverifyClient(org.everify_base_url, org.everify_client_id,
                         org.everify_client_secret, org.everify_public_api_key,
                         "organization")


def _mock_login_allowed():
    """The self-verifying mock requires TWO independent opt-ins.

    _mock_everify_data() echoes the caller's own POST body back as a verified
    identity, and everify_query_api() then logs that identity in. So whoever can
    reach the mock can log in as anyone whose National ID they know. Gating that
    on DEBUG alone makes a single stray DJANGO_DEBUG=1 in the environment a full
    authentication bypass, with no loud symptom: the health check still returns
    200 and the login page still looks normal.
    """
    return bool(settings.DEBUG) and bool(
        getattr(settings, 'EVERIFY_ALLOW_MOCK_LOGIN', False)
    )


@require_http_methods(["POST"])
def everify_public_key(request):
    """Return the eVerify public API key for the liveness SDK.

    Which key depends on who is asking: the login page gets the site key, and
    a signed-in operator gets their organization's, so the liveness session
    the browser creates belongs to the same client the query will run against.
    With mock login enabled, return an empty key so the frontend skips liveness.
    """
    if _mock_login_allowed():
        return JsonResponse({'public_key': ''})
    user = _get_session_user(request)
    if user is not None:
        client = _org_everify(_current_organization(request, user))
        return JsonResponse({'public_key': client.public_key if client else ''})
    return JsonResponse({'public_key': _site_everify().public_key})


def get_everify_access_token(client, trace=None):
    """Get access token from the eVerify /auth endpoint for `client`.

    `trace` is the optional upstream call log -- see accounts/debug_store.py.
    It records the status and the round trip, never the token: a bearer in a
    JSON response to a browser would be a credential leak wearing a
    diagnostic hat. The count is what tells you one arrived.
    """
    if client is None or not client.configured:
        if trace is not None:
            trace.note("auth", detail="skipped: client not configured")
        return None
    url = f"{client.base_url}/auth"
    started = time.monotonic()
    try:
        # No redirects: a 307 or 308 would send the secret on to wherever it
        # pointed, past the host check (accounts/everify_address.py).
        response = requests.post(
            url,
            json={'client_id': client.client_id,
                  'client_secret': client.client_secret},
            headers={'Content-Type': 'application/json'},
            timeout=10,
            allow_redirects=False,
        )
        elapsed = (time.monotonic() - started) * 1000
        if response.status_code == 200:
            data = response.json()
            token = data.get('data', {}).get('access_token')
            if trace is not None:
                # The body is handed over unconditionally and UpstreamTrace
                # decides whether to keep it -- one place owns "only a
                # failure's body", rather than every call site remembering.
                trace.note("auth", method="POST", url=url,
                           status=response.status_code, ms=elapsed,
                           detail=("access token received, %d characters"
                                   % len(token) if token
                                   else "200, but no access_token in the body"),
                           body=response.text)
            return token
        else:
            logger.error(f"eVerify auth failed: Status={response.status_code}, Response={response.text}")
            if trace is not None:
                trace.note("auth", method="POST", url=url,
                           status=response.status_code, ms=elapsed,
                           body=response.text)
            return None
    except requests.RequestException as e:
        logger.error(f"eVerify connection error: {e}")
        if trace is not None:
            trace.note("auth", method="POST", url=url,
                       ms=(time.monotonic() - started) * 1000,
                       detail="connection error", body=str(e))
        return None


def _fetch_face_as_data_uri(face_url):
    """Download the face eVerify's answer points at, as a data URI, or None.

    Only from a public https host, and only an image: the answer chooses the
    URL and this server fetches it. The rules are in
    accounts/everify_face.py."""
    return everify_face.data_uri(face_url)


def _prepare_data_for_frontend(data, rows=None):
    """Turn eVerify's response into the rows this app carries.

    `rows` is one organization's field configuration; None is the LOGIN path,
    which runs before there is a session and therefore before there is an
    organization, and uses the built-in defaults. Nothing a organization
    configures may reach that path.

    Each row carries both names: `field` is eVerify's own key and is what
    every later decision matches on, `key` is what the document prints.
    Matching on the printed name was safe only while it was hard-coded; it
    is now editable, and a rename must not quietly stop a field being logged.

    A field switched off for BOTH document and log is not carried at all --
    for the face that also skips fetching the image.

    The age is worked out HERE, on the day of the verification, and its row
    carries that day as `as_of`: the document can be opened again later, and
    it must still say how old the person was when they stood at the counter.
    """
    rows = rows if rows is not None else everify_fields.default_rows()
    today = timezone.localdate()
    data = everify_fields.with_computed(data, today)

    result = []
    for row in everify_fields.processed_rows(rows):
        key = row['key']
        if key not in data or data[key] is None:
            continue
        value = data[key]
        if key == 'face_url':
            value = _fetch_face_as_data_uri(value)
            if not value:
                continue
        if key == 'birth_date' and isinstance(value, str):
            try:
                value = datetime.strptime(value, "%Y-%m-%d").strftime("%m/%d/%Y")
            except ValueError:
                pass
        result.append({
            'field': key,
            'key': everify_fields.label_for(row),
            'value': value,
            'show': row['display'],
        })
        if key in everify_fields.COMPUTED:
            result[-1]['as_of'] = everify_fields.as_of(today)
    return result


def _named_somebody(data):
    """Did eVerify's 200 actually name a person?

    Asked of the RAW response, never of an organization's configuration: an
    organization that has switched most fields off has not thereby made every
    verification a miss. Four identifying keys rather than "any known key",
    because the response also carries `token`, which is there whoever it does
    or does not describe.
    """
    return any(data.get(key) not in (None, '')
               for key in everify_fields.IDENTITY_KEYS)


def _mock_everify_data(data, rows=None):
    """Return mock eVerify data list for development/demo.

    Keyed the same way a real response is, and put through the same field
    configuration, so a organization testing its field list against the mock
    sees what it will get for real.
    """
    value = data.get('value', '').strip()
    stripped = re.sub(r'[-\s]', '', value)
    if re.match(r'^[A-Za-z]{3}\d{3,4}$', value):
        digital_id = value.upper()
        card_number = '1111-2222-3333-4444'
    elif re.match(r'^\d{16}$', stripped):
        digital_id = 'ABC1234'
        card_number = stripped
    else:
        digital_id = value.upper() if value else 'ABC1234'
        card_number = '1111-2222-3333-4444'

    # Every key the upstream returns, so a site admin who switches one of
    # the newer ones on can see what it looks like before trusting it.
    values = {
        'face_url': '/static/mock-face.png',
        'first_name': data.get('first_name', 'Martin'),
        'middle_name': data.get('middle_name', 'O'),
        'last_name': data.get('last_name', 'Bishop'),
        'reference': card_number,
        'code': digital_id,
        'gender': data.get('sex', 'Male'),
        'birth_date': data.get('birth_date', '01/15/1990'),
        'place_of_birth': 'Quezon City, Metro Manila',
        'marital_status': 'Single',
        'full_address': '123 Katipunan Ave, Loyola Heights, Quezon City 1108',
        'present_full_address': '456 Aurora Blvd, Cubao, Quezon City 1109',
        'blood_type': 'O+',
        'full_name': 'Martin O Bishop',
        'suffix': '',
        'email': 'mbishop@example.ph',
        'mobile_number': '+639170000000',
        'residency_status': 'Filipino Citizen',
        'address_line_1': '123 Katipunan Ave',
        'address_line_2': 'Loyola Heights',
        'barangay': 'Loyola Heights',
        'municipality': 'Quezon City',
        'province': 'Metro Manila',
        'postal_code': '1108',
        'country': 'Philippines',
        'present_address_line_1': '456 Aurora Blvd',
        'present_address_line_2': 'Cubao',
        'present_barangay': 'Socorro',
        'present_municipality': 'Quezon City',
        'present_province': 'Metro Manila',
        'present_postal_code': '1109',
        'present_country': 'Philippines',
        'pob_municipality': 'Quezon City',
        'pob_province': 'Metro Manila',
        'pob_country': 'Philippines',
        'token': 'mock-token',
    }
    today = timezone.localdate()
    values = everify_fields.with_computed(values, today)
    rows = rows if rows is not None else everify_fields.default_rows()
    result = [
        {'field': row['key'], 'key': everify_fields.label_for(row),
         'value': values[row['key']], 'show': row['display']}
        for row in everify_fields.processed_rows(rows) if row['key'] in values
    ]
    for item in result:
        if item['field'] in everify_fields.COMPUTED:
            item['as_of'] = everify_fields.as_of(today)
    return result


def _login_user_from_everify(request, data_list):
    """Look up a User from eVerify data and store in session. Backfills empty fields.

    Returns the User signed in, or None when the answer names nobody this
    site will sign in -- the caller must then refuse rather than report
    success."""
    # By eVerify's key, not by the name on the document: that name is now
    # editable per organization. This path never sees an organization's
    # configuration -- it runs before there is a session -- but reading the
    # identity out of an editable label is the kind of coupling that only
    # looks safe until somebody renames something.
    def get(field):
        for item in data_list:
            if everify_fields.field_of(item) == field:
                return item['value']
        return ''

    digital_id = str(get('code')).strip()
    if not digital_id:
        return None
    card_number = str(get('reference')).strip()
    given_name = str(get('first_name')).strip()
    middle_name = str(get('middle_name')).strip()
    last_name = str(get('last_name')).strip()

    user = _find_user(digital_id, pcn=card_number)
    if user is None:
        return None

    updated = False
    if not user.national_id_card_number and card_number:
        user.national_id_card_number = card_number
        updated = True
    if not user.given_name and given_name:
        user.given_name = given_name
        updated = True
    if not user.middle_name and middle_name:
        user.middle_name = middle_name
        updated = True
    if not user.last_name and last_name:
        user.last_name = last_name
        updated = True
    if not user.digital_national_id and digital_id:
        user.digital_national_id = digital_id
        updated = True
    if updated:
        user.save()

    _login_session(request, user)
    return user


def _as_id(value):
    """An integer primary key, or None. Guards every id that arrives as text:
    a non-numeric string handed to a pk lookup raises, it does not miss."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _resolve_location(org, raw):
    """(Location or None, display name) for a stored operator_location value.

    Scoped to the organization: an id belonging to another organization must
    not resolve, or a transaction would be logged against a location its own
    organization does not own.
    """
    raw = (raw or "").strip()
    if not raw or org is None:
        return None, raw
    loc_id = _as_id(raw)
    if loc_id is None:
        return None, raw
    loc = org.locations.filter(id=loc_id).first()
    return (loc, loc.name) if loc else (None, raw)


def _fit_to_columns(model, values):
    """`values` with every string cut to its column's max_length, less any NUL.

    SQLite stores an over-long string, or one holding a NUL, as it is;
    PostgreSQL refuses the whole INSERT. These rows are written from values
    nobody here chose -- the upstream's answer, a scanned QR's text -- so a value
    that does not fit its column must cost the end of that value, never the
    row: an unlogged failure is a gap in the audit trail, and an unlogged
    verification is an error page after a lookup that has already been billed.
    """
    fitted = {}
    for name, value in values.items():
        if isinstance(value, str):
            value = value.replace("\x00", "")
            limit = getattr(model._meta.get_field(name), "max_length", None)
            if limit and len(value) > limit:
                value = value[:limit]
        fitted[name] = value
    return fitted


#: What verify's pages post as text to the two endpoints anybody can reach,
#: /everify/ and /everify/log-liveness-failure/.
_TEXT_FIELDS = ("value", "first_name", "middle_name", "last_name", "suffix",
                "birth_date", "face_liveness_session_id", "login_photo",
                "operator_location", "failure_detail")


def _posted_object(request):
    """The JSON object posted, or None for a body verify's pages never send.

    Not UTF-8, not JSON, not an object, or a number, list or NUL where text
    belongs: answered 400 here rather than failing further in as a 500. These
    endpoints need no session, and every 500 is an ERROR in the app log and
    counts towards the site's server-error alarm.
    """
    try:
        data = json.loads(request.body)
    except ValueError:  # JSONDecodeError, and UnicodeDecodeError for non-UTF-8
        return None
    if not isinstance(data, dict):
        return None
    for name in _TEXT_FIELDS:
        value = data.get(name)
        if not (value is None or (isinstance(value, str) and "\x00" not in value)):
            return None
    return data


def _log_failure_transaction(request, data, failure_detail):
    """Log a failed liveness/verification attempt as a Transaction."""
    try:
        value = (data.get("value") or "").strip().replace("-", "").replace(" ", "")
        user = _get_session_user(request)
        org = _current_organization(request, user) if user else None
        org_ref, acting_as = _log_context(request, user, org)

        raw_location = (data.get("operator_location", "")
                        or request.session.get("operator_location", ""))
        # Only a location of this organization is written, by its own name.
        # The posted text itself never is: it went into the log, and from
        # there into an administrator's spreadsheet.
        loc_ref, _ = _resolve_location(org, raw_location)
        op_location = loc_ref.name if loc_ref is not None else ""

        # Likewise the typed ID reaches an ID column only in one of the two
        # shapes an ID has. Anything else was not an ID, and is not kept.
        is_card = bool(CARD_NUMBER.fullmatch(value))
        is_digital = not is_card and bool(DIGITAL_ID.fullmatch(value.upper()))

        # And only what the organization logs: a field with "Log" off is not
        # written for a failure either, just as for a success. Signed out
        # there is no organization, and the
        # defaults apply, as they do to signing in.
        logged = {row["key"] for row in
                  everify_fields.log_rows(everify_fields.rows_for(org))}

        def kept(field, typed):
            return typed if field in logged else ""

        Transaction.objects.create(**_fit_to_columns(Transaction, dict(
            organization=org_ref,
            **acting_as,
            operator_national_id_number=user.national_id_card_number if user else "",
            operator_location=op_location,
            national_id_card_number=kept("reference", value if is_card else ""),
            digital_national_id_number=kept(
                "code", value.upper() if is_digital else ""),
            given_name=kept("first_name", data.get("first_name") or ""),
            middle_name=kept("middle_name", data.get("middle_name") or ""),
            last_name=kept("last_name", data.get("last_name") or ""),
            date_of_birth=kept("birth_date", data.get("birth_date") or ""),
            authentication_result="failure",
            failure_detail=failure_detail[:255] if failure_detail else "",
            operator=user,
            location_ref=loc_ref,
        )))
    except Exception as e:
        logger.error(f"Failed to log failure transaction: {e}")


#: eVerify answers 401 for two different things and the difference is the
#: whole diagnosis: "Unauthenticated." means it did not recognise the token,
#: "Unauthorized." means it did and the client is not entitled to the
#: endpoint. Measured against the live service: a request with no
#: bearer, and one with a junk bearer, both say Unauthenticated, while a
#: real token on a client that cannot query says Unauthorized.
UPSTREAM_401_HINTS = (
    ("unauthenticated",
     "eVerify did not accept our credentials (401 Unauthenticated). "
     "Check the client ID and secret."),
    ("unauthorized",
     "eVerify accepted our credentials but refused the lookup "
     "(401 Unauthorized). The client is authenticated and not entitled to "
     "query -- that is a matter for PSA, not a setting here."),
)


def _upstream_message(response):
    """Say what the upstream refused, not merely which number it used.

    The status alone is not the finding; the upstream's own word for it is.
    """
    generic = f"eVerify API error: {response.status_code}"
    if response.status_code != 401:
        return generic
    # The `message` field, NOT a substring of the body.
    #
    # On the two bodies eVerify actually sends, a whole-text match happens to
    # agree -- both carry "error":"unauthorized", and only one also contains
    # "unauthenticated". That is luck, not a rule: it depends on the order of
    # UPSTREAM_401_HINTS and on `error` never disagreeing with `message`.
    # Read the field that carries the distinction and neither has to hold.
    try:
        body = response.json()
    except ValueError:
        return generic
    if not isinstance(body, dict):
        return generic
    said = str(body.get("message") or body.get("error_description") or "").lower()
    for needle, hint in UPSTREAM_401_HINTS:
        if needle in said:
            return hint
    return generic


def _capture_purpose(already_logged_in):
    """Which of the two things `POST /everify/` does produced this row.

    The same distinction the successful path makes, spelled once: signing an
    operator in runs against the site client, verifying runs against the
    organization's, and a failure is only readable if it says which.
    """
    return (DebugCapture.PURPOSE_VERIFY if already_logged_in
            else DebugCapture.PURPOSE_LOGIN)


@require_http_methods(["POST"])
def everify_query_api(request):
    """API endpoint for eVerify query. Handles QR, manual entry, and demographic queries."""
    started_at = time.monotonic()
    # What was asked of the upstream, and what came back. Returned to the
    # caller ONLY on a debugging instance -- attach_trace() is the gate. It
    # exists because a 401 from the query endpoint reached the login page as
    # "Server returned 401" one step after the camera closed, and read as a
    # liveness failure it was not.
    trace = debug_store.UpstreamTrace()
    # A page on another site posting here from somebody's browser is refused
    # before it is counted against their address. The CSRF token is required
    # as well: both pages that post here send it.
    refused = throttle.refuse_cross_site(request)
    if refused is not None:
        return refused
    try:
        data = _posted_object(request)
        if data is None:
            return JsonResponse({'message': 'Invalid JSON'}, status=400)

        user = _get_session_user(request)
        already_logged_in = user is not None
        org = _current_organization(request, user) if user else None

        # The Verify page says what it is asking. With no session behind it --
        # ended by the absolute limit or the idle one while the page stayed
        # open -- it is refused, not run as a sign-in: that would sign the
        # operator's browser in as the person at the counter.
        if data.get("purpose") == "verify" and not already_logged_in:
            return JsonResponse({"message": SESSION_ENDED_MESSAGE,
                                 "signed_out": True}, status=401)

        # A sign-in is limited per address. Counted here, before anything
        # looks at the ID, so a registered and an unregistered one are
        # refused alike and the limit says nothing about which is which.
        if not already_logged_in and not throttle.allow(request, "sign-in"):
            return throttle.refused_json()

        # Whoever the last verification named is not who this one is about.
        # Dropped before anything can fail, so a failure cannot leave the
        # previous person on file -- to be printed, logged, signed or have
        # their User Records shown -- behind it.
        #
        # And SAVED here, not left to the middleware: Django does not save a
        # session on a 5xx, and this view answers 5xx whenever eVerify or its
        # credentials fail. Unsaved, the drop would be undone by exactly the
        # failures it exists for. It writes only when something was on file,
        # which the Verify page has normally cleared already.
        if already_logged_in:
            verified_answer.forget(request.session)
            if request.session.modified:
                request.session.save()

        def _note_lookup_timing():
            """Record what a real signed-out lookup actually cost.

            The refusal's delay range has to match this or the stopwatch
            tells the two apart; logging it means the range in settings can
            be re-tuned from production rather than guessed at again.
            """
            if not already_logged_in:
                logger.info("signed-out lookup took %d ms",
                            int((time.monotonic() - started_at) * 1000))

        # The location comes from the chooser, which wrote it into the
        # session. A posted value is honoured only when it names a location
        # of the CURRENT organization -- never taken on trust, or a caller
        # could attribute their work to somebody else's site.
        posted_location = (data.get("operator_location") or "").strip()
        posted_id = _as_id(posted_location)
        if posted_id is not None and org is not None:
            if org.locations.filter(id=posted_id).exists():
                request.session["operator_location"] = str(posted_id)

        if _mock_login_allowed():
            mock_data = _mock_everify_data(
                data,
                everify_fields.rows_for(org if already_logged_in else None))
            if not already_logged_in:
                _login_user_from_everify(request, mock_data)
            elif org is not None:
                # The mock's "answer" is the caller's own body -- which is
                # why it needs two opt-ins -- so what is kept here is too.
                verified_answer.keep(request.session, org, mock_data,
                                     user_records.subject_from_rows(mock_data))
            return JsonResponse({
                'status': 'success',
                'message': 'Mock verification successful',
                'data': mock_data,
                'redirect': '/choose/' if not already_logged_in else '',
                'note': 'MOCK response -->' + data.get('value', 'Unknown'),
            })

        # Signing in is a site-level act; verifying is the organization's,
        # and is what its eVerify account is billed for.
        if already_logged_in:
            if org is None:
                return JsonResponse(
                    {'message': 'Choose an organization before verifying.'},
                    status=409)
            client = _org_everify(org)
            refusal = client.refusal(org.name)
            if refusal:
                _log_failure_transaction(request, data, refusal)
                return JsonResponse({'message': refusal}, status=503)
            if not client.configured:
                _log_failure_transaction(
                    request, data,
                    "Organization has no eVerify credentials configured.")
                return JsonResponse(
                    {'message': f'{org.name} has no eVerify credentials yet. '
                                f'An administrator must add them before '
                                f'verification can run.'},
                    status=503)
        else:
            # Signing in. The first question is not "what does eVerify say?"
            # but "is there anybody here to sign in?" -- an identifier that
            # names no row in Users cannot be given a session whatever the
            # upstream answers, because _login_user_from_everify() gives up
            # when _find_user() misses. Calling eVerify for it spends a
            # liveness session and a query to reach a foregone conclusion,
            # which is a quota-burn vector open to anyone who can reach the
            # login page.
            #
            # This is the ONLY place the question is asked. Nothing tells
            # the browser which check to run -- it runs the real liveness SDK
            # either way -- so there is no earlier decision to be consistent
            # with, and nothing for a caller to read ahead. Deliberately ahead
            # of the credentials check too, so the reply does not vary with
            # how the site happens to be configured.
            if login_guard.registered_operator(data.get('value', '')) is None:
                login_guard.record_refused_attempt(
                    request, data.get('value', ''), data.get('login_photo', ''))
                login_guard.sleep_to_match(started_at)
                return JsonResponse({'message': NO_MATCH_MESSAGE}, status=404)

            client = _site_everify()
            refusal = client.refusal("This site")
            if refusal:
                _log_failure_transaction(request, data, refusal)
                return JsonResponse({'message': refusal}, status=500)
            if not client.configured:
                _log_failure_transaction(request, data, "eVerify API credentials not configured.")
                return JsonResponse({'message': 'eVerify API credentials not configured.'}, status=500)

        # Which of the two clients this is, and where it points. The first
        # question in any eVerify failure, and the one the log made you go
        # and look up.
        trace.note("client",
                   detail=("organization client: %s" % org.name
                           if already_logged_in and org is not None
                           else "site client (sign-in)"),
                   url=client.base_url)

        access_token = get_everify_access_token(client, trace)
        if not access_token:
            _log_failure_transaction(request, data, "Failed to authenticate with eVerify API.")
            debug_store.capture_failure(
                purpose=_capture_purpose(already_logged_in),
                organization=org if already_logged_in else None,
                detail="no access token from /auth", trace=trace)
            return JsonResponse(debug_store.attach_trace(
                {'message': 'Failed to authenticate with eVerify API'}, trace),
                status=500)

        if 'value' in data:
            query_url = f"{client.base_url}/query/qr"
            payload = {'value': data.get('value')}
        elif 'first_name' in data or 'last_name' in data:
            query_url = f"{client.base_url}/query"
            payload = {
                'first_name': data.get('first_name', ''),
                'last_name': data.get('last_name', ''),
                'middle_name': data.get('middle_name', ''),
                'suffix': data.get('suffix', ''),
                'birth_date': data.get('birth_date', ''),
            }
        else:
            return JsonResponse({'message': 'No National ID or demographic data provided.'}, status=400)

        fingerprint = data.get('fingerprint')
        if fingerprint:
            payload['fingerprint'] = fingerprint
        else:
            payload['face_liveness_session_id'] = data.get('face_liveness_session_id', '')

        logger.info(f"eVerify query_url={query_url}, payload_keys={list(payload.keys())}")

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {access_token}'
        }

        max_retries = 3
        last_error = None

        for attempt in range(max_retries):
            try:
                attempt_started = time.monotonic()
                response = requests.post(query_url, json=payload, headers=headers,
                                         timeout=30, allow_redirects=False)
                # Every attempt, including the ones a retry hides. A run that
                # succeeded on the third go looks identical to one that
                # succeeded first time, and they are not the same health.
                trace.note("query", method="POST", url=query_url,
                           status=response.status_code,
                           ms=(time.monotonic() - attempt_started) * 1000,
                           detail="attempt %d of %d" % (attempt + 1, max_retries),
                           body=response.text)

                if response.status_code == 200:
                    result = response.json()
                    logger.info(f"eVerify raw response keys={list(result.keys())}")

                    if 'data' in result:
                        raw_verified = result['data'].get('verified')
                        logger.info(f"eVerify raw response-verified={raw_verified}")
                        is_verified = raw_verified is not False
                        named = _named_somebody(result['data'])
                        # The organization's own field list when it is
                        # verifying; the defaults when somebody is signing in,
                        # because there is no organization yet.
                        raw_data = dict(result['data'])
                        result['data'] = _prepare_data_for_frontend(
                            result['data'],
                            everify_fields.rows_for(org if already_logged_in
                                                    else None))
                        # Development instances keep the whole response so the
                        # document's sizing and quality work has real faces and
                        # real addresses to measure. Two opt-ins, no-op without
                        # both, and it cannot raise -- a verification is not
                        # worth losing to a debug facility.
                        debug_store.capture(
                            raw_data, result['data'],
                            purpose=(DebugCapture.PURPOSE_VERIFY
                                     if already_logged_in
                                     else DebugCapture.PURPOSE_LOGIN),
                            organization=org if already_logged_in else None,
                            outcome=(DebugCapture.OUTCOME_SUCCESS
                                     if named and is_verified
                                     else DebugCapture.OUTCOME_FAILURE),
                            detail=("" if named and is_verified
                                    else "named nobody" if not named
                                    else "verified=false"),
                            status_code=200)
                        if not named:
                            _log_failure_transaction(request, data, NO_MATCH_MESSAGE)
                            _note_lookup_timing()
                            return JsonResponse({'message': NO_MATCH_MESSAGE},
                                                status=404)
                        if is_verified:
                            if not already_logged_in:
                                if _login_user_from_everify(request, result['data']) is None:
                                    # Past the gate, so the typed ID names
                                    # somebody here -- but not the card
                                    # eVerify vouched for. Usually a replaced
                                    # card (helpers._lookup_user). Say so: a
                                    # "success" with no session only lands the
                                    # person back on this page.
                                    _log_failure_transaction(request, data, CARD_MISMATCH_MESSAGE)
                                    _note_lookup_timing()
                                    return JsonResponse({'message': CARD_MISMATCH_MESSAGE},
                                                        status=403)
                            else:
                                # The upstream's answer, kept HERE, and the
                                # only thing the document, the log, the
                                # credential and the card are ever made of.
                                # The rows are exactly what the page is sent;
                                # the person is keyed from the raw answer,
                                # before any field configuration -- the only
                                # source User Records trusts. See
                                # accounts/verified_answer.py.
                                verified_answer.keep(
                                    request.session, org, result['data'],
                                    user_records.subject_from_raw(raw_data))
                            result['status'] = 'success'
                            result['redirect'] = '/choose/' if not already_logged_in else ''
                        else:
                            _log_failure_transaction(request, data, "eVerify returned verified=false.")
                            result['status'] = 'error'
                    else:
                        # A 200 with no `data` is contract drift, and the
                        # kind that is invisible in a log: the caller sees
                        # an empty result and the server sees a success.
                        debug_store.capture_failure(
                            purpose=_capture_purpose(already_logged_in),
                            organization=org if already_logged_in else None,
                            detail="200 carried no data object",
                            status_code=200, trace=trace,
                            body=response.text)

                    _note_lookup_timing()
                    return JsonResponse(result, status=200)
                elif response.status_code >= 500 and attempt < max_retries - 1:
                    last_error = f"eVerify API returned {response.status_code}"
                    continue
                else:
                    logger.error(f"eVerify query failed: Status={response.status_code}, Response={response.text}")
                    _log_failure_transaction(request, data, f"eVerify API error: HTTP {response.status_code}")
                    # The refusal itself, kept: when the 401s began, and
                    # which 401 it is, can be read without shell access.
                    debug_store.capture_failure(
                        purpose=_capture_purpose(already_logged_in),
                        organization=org if already_logged_in else None,
                        detail=_upstream_message(response),
                        status_code=response.status_code, trace=trace,
                        body=response.text)
                    return JsonResponse(debug_store.attach_trace(
                        {'message': _upstream_message(response),
                         'details': response.text},
                        trace),
                        status=response.status_code
                    )

            except requests.RequestException as e:
                last_error = str(e)
                trace.note("query", method="POST", url=query_url,
                           ms=(time.monotonic() - attempt_started) * 1000,
                           detail="attempt %d of %d: connection error"
                                  % (attempt + 1, max_retries),
                           body=str(e))
                logger.error(f"eVerify request error (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    continue
                else:
                    break

        _log_failure_transaction(request, data, f"eVerify API error after {max_retries} attempts: {last_error}")
        debug_store.capture_failure(
            purpose=_capture_purpose(already_logged_in),
            organization=org if already_logged_in else None,
            detail=f"no answer after {max_retries} attempts", trace=trace,
            body=str(last_error))
        # The error itself names eVerify's address; it is in the log and the
        # failure row, and shown on a debugging instance (attach_trace).
        return JsonResponse(debug_store.attach_trace(
            {'message': f'eVerify did not answer after {max_retries} attempts. '
                        f'Try again shortly.'},
            trace),
            status=500
        )

    except json.JSONDecodeError:
        return JsonResponse({'message': 'Invalid JSON'}, status=400)
    except Exception as e:
        try:
            _log_failure_transaction(request, data, f"Server error: {str(e)}")
        except Exception:
            pass
        # The detail is in the log and the failure row. The caller may be
        # anybody at the sign-in page, and an exception's text describes the
        # server -- a column, a query, a path -- not their request.
        logger.exception("eVerify query failed with a server error")
        return JsonResponse(debug_store.attach_trace(
            {'message': 'Server error.'}, trace), status=500)


@require_http_methods(["POST"])
def log_liveness_failure(request):
    """Log a liveness SDK failure (cancelled or error) from the client."""
    data = _posted_object(request)
    if data is None:
        return JsonResponse({"status": "error"}, status=400)
    # Anybody at the login page can post this, and each call writes a row:
    # limited per address when signed out.
    if (_get_session_user(request) is None
            and not throttle.allow(request, "liveness-failure")):
        return throttle.refused_json()
    try:
        failure_detail = (data.get("failure_detail") or "Unknown liveness failure")[:255]
        _log_failure_transaction(request, data, failure_detail)
        return JsonResponse({"status": "ok"})
    except Exception as e:
        logger.error(f"Failed to log liveness failure: {e}")
        return JsonResponse({"status": "error"}, status=500)


def _face_data_uri(rows):
    """The face as `_prepare_data_for_frontend` left it, or "".

    Matched on eVerify's own key, never the label -- the label is editable and
    a rename must not quietly drop the portrait.
    """
    for row in rows or ():
        if everify_fields.field_of(row) == "face_url":
            return row.get("value") or ""
    return ""


def _card_rows(verification_data, rows, *, demo_mode):
    """The rows the DOCUMENT shows, masked exactly as the document masks them.

    Which fields those are is resolved HERE, from the organization's own
    configuration -- never from the rows' own "show" flag, the same rule that
    decides what is logged. The card is a copy of the document, so
    it must not be able to carry a field the document does not print.
    """
    displayed = {row["key"] for row in everify_fields.document_rows(rows)}
    data = (apply_demo_mask(verification_data) if demo_mode
            else verification_data)
    return [item for item in data
            if everify_fields.field_of(item) in displayed]


def _maybe_mask_name(text, demo_mode):
    return mask_name(text) if demo_mode and text else text


def _mint_credential(txn, org, location, verification_data, field_rows,
                     *, demo_mode=False):
    """Mint the offline credential for a logged verification, or None.

    NEVER raises. A document that cannot carry an offline credential is still
    a valid document -- it falls back to the plain QR, the bare transaction
    UUID, which resolves online. Losing the
    verification because a key file was unreadable would be a far worse
    failure than losing the offline half of the QR.
    """
    if org is None:
        return None
    if not credential_keys.configured():
        credential_keys.warn_if_half_configured()
        return None
    try:
        # Demo Mode reaches in here, and it has to.
        #
        # The page is masked and the transaction is logged truthfully -- that
        # split is deliberate and unchanged. But the credential is neither: it
        # rides ON the printed page, in a symbol beside the bullets, and it
        # was carrying the real name, birth date and ID numbers the whole
        # time. Anybody in the audience with the verifier app could read what
        # the projector was hiding.
        #
        # So the credential follows the DOCUMENT, not the log. Same three
        # conventions, same masked rows the page renders from.
        if demo_mode:
            verification_data = apply_demo_mask(verification_data)
        issued, expires = credential_keys.validity_window(
            txn.verification_timestamp)
        # Rendered BEFORE minting, because the credential carries its hash --
        # the two symbols have to be bound to the same bytes or a document
        # could be presented with somebody else's face beside it.
        # Fitted, not merely rendered: if nothing at the shipped resolution
        # fits the symbol, the resolution gives way rather than the document
        # going out without the face beside it.
        portrait, portrait_px = credentials.render_portrait_fitted(
            _face_data_uri(verification_data), redact=demo_mode)
        if portrait is not None and portrait_px != credentials.PORTRAIT_PX:
            logger.info("portrait fitted at %d px, not %d",
                        portrait_px, credentials.PORTRAIT_PX)
        # Recorded before it is signed, by mint_recorded: a credential that
        # exists in the world and not in IssuedCredential cannot be revoked,
        # and the QR is already on its way to a printer.
        minted = minting.mint_recorded(
            verification_data,
            transaction=txn,
            organization=org,
            # Whose ceiling it counts against, with a signer: the person
            # signed in, by id, never by the name the document prints.
            operator=str(getattr(txn, "operator_id", "") or ""),
            location_code=getattr(location, "code", "") or "",
            issued_at=issued,
            expires_at=expires,
            field_rows=field_rows,
            # What the phone shows. `transaction_type` is the name stored on
            # the transaction itself; `transaction_type_ref` is the configured
            # row it came from. Prefer the stored string -- it is what this
            # transaction was actually recorded as, and it outlasts the
            # configured type being renamed or deleted afterwards.
            transaction_type=(txn.transaction_type
                              or getattr(txn.transaction_type_ref, "name", "")
                              or ""),
            # Names, not codes. A person reading this on a phone needs the
            # organization and the desk spelled out; a code they cannot expand
            # tells them nothing.
            location_name=(getattr(location, "name", "")
                           or txn.operator_location or ""),
            # The operator is a person too, and the document's own footer
            # already masks them. mask_name, the same convention as the
            # corner of every signed-in page.
            operator_name=_maybe_mask_name(
                (txn.operator.public_name if txn.operator is not None else ""),
                demo_mode),
            portrait=portrait)
    except Exception:
        logger.exception("credential minting failed for transaction %s",
                         txn.transaction_id)
        return None

    # For the Wallet pass, which greys out when the credential lapses -- the
    # same value, in the same spelling, as a holder's pass carries.
    minted["expires_at"] = expires.isoformat()
    # And for the card, which prints it.
    minted["expires_on"] = handoff.expires_on_text(expires)

    # The portrait's own symbol, bound to the credential just minted.
    if portrait:
        minted["portrait_qr"] = credentials.portrait_qr(
            portrait, credential_id=minted["credential_id"])
        minted["portrait_stamp_mm"] = credentials.PORTRAIT_STAMP_MM
        # The same bytes, for the face printed ON the card the holder saves
        # to their phone. Deliberately these and not a second render of the
        # upstream photo: they are already grayscale, already resampled when
        # the operator is presenting, and already bound to this credential by
        # `portrait_hash`. A second face here would be a second thing to keep
        # in step with Demo Mode, which is exactly how the credential came to
        # be carrying an unmasked one.
        minted["portrait_data_uri"] = credentials.portrait_data_uri(portrait)

    if not minted["fits_at_stamp"]:
        # Not fatal -- it will still scan if printed larger -- but it means
        # the document is about to print something under-sized.
        logger.warning(
            "credential for %s needs %.1f mm but the document prints %.1f",
            txn.transaction_id, minted["min_stamp_mm"], credentials.STAMP_MM)
    return minted


@require_http_methods(["POST"])
def log_verification_transaction(request):
    """Log a verification transaction with transaction type."""
    try:
        # Only an operator acting for an organization verifies anybody --
        # POST /everify/ refuses the rest -- so only one may log a
        # verification. Without this, anybody holding the sign-in page's CSRF
        # cookie could write a "success" row about anybody into the log.
        user = _get_session_user(request)
        if user is None:
            return JsonResponse({"message": "Unauthorized."}, status=403)
        org = _current_organization(request, user)
        if org is None:
            return JsonResponse(
                {"message": "Choose an organization before verifying."},
                status=409)

        # Not UTF-8, not JSON, or not an object: a 400, never a 500 from
        # somewhere further in.
        try:
            data = json.loads(request.body)
        except ValueError:  # JSONDecodeError, and UnicodeDecodeError
            data = None
        if not isinstance(data, dict):
            return JsonResponse({"message": "Invalid JSON."}, status=400)
        transaction_type = data.get("transaction_type")
        transaction_type = (transaction_type.strip()
                            if isinstance(transaction_type, str) else "")
        if not transaction_type:
            return JsonResponse({"message": "Transaction type is required."}, status=400)

        # The person is NOT in this request. It is eVerify's answer to this
        # session's last verified lookup, kept on the server by
        # everify_query_api() and bound to the organization that asked.
        # Whatever the body says about anybody -- verification_data, result
        # -- is not read: a page that could say who was verified could say
        # it about anybody, and have a credential signed for it. See
        # accounts/verified_answer.py.
        answer = verified_answer.rows(request.session, org)
        if answer is None:
            return JsonResponse(
                {"message": "This verification is no longer on file; "
                            "verify the person again."},
                status=409)

        # One answer may be logged more than once, by decision -- but not
        # once a document made from it has been revoked: revoking would mean
        # little if the same answer printed a fresh credential a minute later
        # without anybody looking the person up again.
        # The answer goes, and the person is verified again.
        earlier = _logged_from_this_answer(request.session, org, user)
        if earlier and IssuedCredential.objects.filter(
                transaction__in=earlier, revoked_at__isnull=False).exists():
            verified_answer.forget(request.session)
            logger.warning("User %s tried to log again from an answer whose "
                           "document was revoked (organization %s); refused",
                           user.pk, org.pk)
            return JsonResponse({"message": REVOKED_SINCE_MESSAGE}, status=409)

        # One of this organization's own types, by id -- what
        # /api/lookup-data/ offers the picker -- and nothing else. The name
        # is signed into the credential, so free text here would be the
        # browser writing the credential.
        tt_id = _as_id(transaction_type)
        tt_ref = (org.transaction_types.filter(id=tt_id, is_active=True).first()
                  if tt_id is not None else None)
        if tt_ref is None:
            return JsonResponse(
                {"message": "Choose one of this organization's transaction types."},
                status=400)
        transaction_type = tt_ref.name

        org_ref, acting_as = _log_context(request, user, org)

        # Which of these values are kept is settled HERE, from the
        # organization's own configuration. A field with "Log" off is not
        # written to its column and not written to logged_fields, so it is
        # not in the row at all and cannot turn up in an export later.
        rows = everify_fields.rows_for(org)
        logged = {row["key"] for row in everify_fields.log_rows(rows)}

        values = {}
        for item in answer:
            field = everify_fields.field_of(item)
            if not field:
                continue
            value = item.get("value")
            if isinstance(value, bool):
                value = "Yes" if value else "No"
            values[field] = str(value) if value else ""

        def kept(field):
            """The answer's value, or "" when this organization does not log it."""
            return values.get(field, "") if field in logged else ""

        columns = {column: kept(field) for field, column
                   in everify_fields.TRANSACTION_COLUMNS.items()}
        columns["national_id_card_number"] = (
            columns["national_id_card_number"].replace("-", "").replace(" ", ""))

        # Everything logged, including the fields that have never had a column
        # of their own -- the addresses, Blood Type, the face.
        logged_fields = {
            field: value[:everify_fields.MAX_LOGGED_VALUE_CHARS]
            for field, value in values.items() if field in logged and value
        }

        # The desk the chooser put in the session, and only when it is one of
        # this organization's; blank otherwise. Never the body, and never raw
        # text: the location's name is signed into the credential too.
        loc_id = _as_id(request.session.get("operator_location", ""))
        loc_ref = (org.locations.filter(id=loc_id).first()
                   if loc_id is not None else None)
        operator_location = loc_ref.name if loc_ref is not None else ""

        txn = Transaction.objects.create(**_fit_to_columns(Transaction, dict(
            organization=org_ref,
            **acting_as,
            operator_national_id_number=user.national_id_card_number if user else "",
            operator_location=operator_location,
            # The OUTCOME is not one of the person's attributes and is not
            # configurable: a log entry that does not say whether it succeeded
            # is not a log entry, and the admin statistics count on it. An
            # answer is kept only for a verified lookup, so this is what it
            # is -- never what the body says.
            authentication_result="success",
            transaction_type=transaction_type,
            operator=user,
            location_ref=loc_ref,
            transaction_type_ref=tt_ref,
            logged_fields=logged_fields,
            # With the answer, keyed from the upstream's raw reply. Written
            # whether or not this organization logs the ID numbers.
            subject_key=verified_answer.subject(request.session, org),
            **columns,
        )))

        # Logged again from one answer: allowed, and said, so a run of them
        # stands out in the log.
        if earlier:
            logger.warning("User %s logged one answer again (organization %s): "
                           "transaction %s after %d earlier", user.pk, org.pk,
                           txn.transaction_id, len(earlier))

        verified_at_str = handoff.verified_at_text(txn.verification_timestamp)

        payload = {
            "status": "ok",
            "message": "Transaction logged successfully.",
            "transaction_id": str(txn.transaction_id),
            "verified_at": verified_at_str,
        }
        # Read from the OPERATOR, here, rather than trusted from the browser:
        # a page that told the server whether to redact would be a page that
        # could tell it not to.
        demo_mode = demo_mode_for(user)
        minted = _mint_credential(txn, org, loc_ref, answer, rows,
                                  demo_mode=demo_mode)
        if minted:
            # The document draws THIS instead of the bare UUID. It still
            # begins with the UUID, so a plain camera reads the same thing it
            # always did.
            payload["qr"] = minted["qr"]
            payload["credential_id"] = str(minted["credential_id"])
            # The face rides its own symbol. Absent when the verification
            # carried no portrait, or the organization does not display one.
            if minted.get("portrait_qr"):
                payload["portrait_qr"] = minted["portrait_qr"]
                payload["portrait_stamp_mm"] = minted["portrait_stamp_mm"]

            # The hand-off to the holder's own phone, and ONLY with a
            # credential: the card is the two symbols and their caption, and a
            # card with nothing offline on it is the card the document already
            # declines to print. Everything on it was settled here, where
            # there is a session -- which organization, which fields, and
            # whether the operator is presenting.
            card = handoff.payload_from_rows(
                _card_rows(answer, rows, demo_mode=demo_mode),
                organization=getattr(org, "name", "") or "",
                transaction_type=txn.transaction_type or "",
                location_name=(getattr(loc_ref, "name", "")
                               or txn.operator_location or ""),
                verified_at=verified_at_str,
                expires_on=minted.get("expires_on", ""),
                transaction_id=str(txn.transaction_id),
                qr=minted["qr"],
                portrait_qr=minted.get("portrait_qr", ""),
                face_data_uri=minted.get("portrait_data_uri", ""))
            # The document prints this SAME object, through the same renderer
            # the phone uses. One builder, two consumers: the page never
            # assembles a second version of the card and so can never
            # disagree with the photo in the holder's hand.
            #
            # It is also why the browser is given no say in what is on it --
            # which fields, whose organization and whether to mask were all
            # settled here, where there is a session to settle them with.
            payload["card"] = card
            # The hand-off also stores when the credential lapses, as a moment,
            # for the Wallet pass. The card prints the day, as `expires_on`.
            opened = handoff.open_handoff(
                dict(card, expires_at=minted.get("expires_at", "")))
            if opened is not None:
                # `devices.base_url()` rather than a second answer to the same
                # question: "what address does a phone reach this deployment
                # at" is already settled there, https upgrade and all.
                payload["handoff_url"] = (
                    devices.base_url(request)
                    + reverse("card_handoff", args=[opened.token]))
                payload["handoff_token"] = str(opened.token)
        return JsonResponse(payload)

    except Exception:
        # An exception's text describes the server -- a column, a query --
        # not the operator's request; the detail goes to the log.
        logger.exception("logging a verification failed")
        return JsonResponse({"message": "The verification could not be logged. "
                                        "The detail is in the app log."}, status=500)
