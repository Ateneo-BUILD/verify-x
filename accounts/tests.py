import base64
import csv
import datetime
import json
import os
import uuid
import shutil
import stat
import tempfile
import zipfile
from io import BytesIO, StringIO
from pathlib import Path
from unittest import skipIf
from unittest.mock import MagicMock, patch

from django.conf import settings
from django.contrib import admin
from django.contrib.auth.models import User as DjangoUser
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import migrations
from django.test import TestCase, override_settings
from django.utils import timezone
from django.urls import NoReverseMatch, reverse

from accounts import (credential_keys, credentials, debug_store,
                      devices as device_service, everify_fields,
                      revocation_feed, sample_data, sample_face, user_records,
                      verified_answer)
from accounts.models import (CardHandoff, CredentialEpochKey, DebugCapture,
                             Device, DeviceTicket,
                             FingerprintSettings, IssuedCredential,
                             IssuerKey,
                             Location, LoginAttempt,
                             Membership, next_issuer_code,
                             next_location_code, Organization,
                             OrganizationFieldSetting, SiteSettings,
                             Transaction, TransactionType, User, UserSettings)
from verify.views import login_guard, sso
from verify.views.everify import (NO_MATCH_MESSAGE, _named_somebody,
                                  _prepare_data_for_frontend)
from verify.views.helpers import (DEMO_MASK_CHAR, ORG_SESSION_KEY,
                                  _find_user, apply_demo_mask, is_demo_masked)
from verify.views.qr import _parse_national_id_payload


SESSION_KEY = "verify_user_id"



def _is_inside(page, outer_class, inner_id):
    """Is the element with ``inner_id`` a descendant of ``.outer_class``?

    String order is not enough here: what Save as PDF copies is
    ``docPage.outerHTML``, so the question is containment, and a card that
    merely appears later in the file is a card that never reaches the PDF.
    """
    from html.parser import HTMLParser

    class Scan(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.depth = None
            self.found = False

        def handle_starttag(self, tag, attrs):
            if tag != "div":
                return
            attrs = dict(attrs)
            if self.depth is not None:
                self.depth += 1
                if attrs.get("id") == inner_id:
                    self.found = True
            elif outer_class in (attrs.get("class") or "").split():
                self.depth = 1

        def handle_endtag(self, tag):
            if tag == "div" and self.depth is not None:
                self.depth -= 1
                if self.depth <= 0:
                    self.depth = None   # out of the container again

    scan = Scan()
    scan.feed(page)
    return scan.found


#: The eVerify hosts these fixtures name. The server allows PSA's host alone
#: by default (EVERIFY_ALLOWED_HOSTS); tests that tell one client from another
#: need hosts they can tell apart, and allow them explicitly.
TEST_EVERIFY_HOSTS = ["ws.everify.gov.ph", "site.example", "org.example",
                      "src.example", "everify.example"]

#: The SSO issuers the tests name. A real site lists its own in
#: SSO_ALLOWED_ISSUERS.
TEST_SSO_ISSUERS = ["https://sso.example.test/o", "https://id.example.org/o",
                    "https://sso.example/o"]


def make_org(name="Test Org", locations=("Main Office",), **kwargs):
    """An organization with a working eVerify client unless told otherwise."""
    fields = dict(everify_client_id="org-id", everify_client_secret="org-secret")
    fields.update(kwargs)
    org = Organization.objects.create(name=name, **fields)
    for location in locations:
        Location.objects.create(organization=org, name=location)
    return org


def join(org, user, role=Membership.ROLE_OPERATOR):
    return Membership.objects.create(organization=org, user=user, role=role)


def keep_answer(client, org, rows, subject=None):
    """Put `rows` in the client's session as eVerify's answer to a verified
    lookup for `org` -- what everify_query_api() keeps, and all the document
    and the log are ever made of. `subject` defaults to the User Records key
    the rows name, as the mock path computes it."""
    if subject is None:
        subject = user_records.subject_from_rows(rows)
    session = client.session
    verified_answer.keep(session, org, rows, subject)
    session.save()


class EverifyIdentitySourceTest(TestCase):
    """The identity a login is granted for must come only from what the UPSTREAM
    returned, never from the caller's own request body.

    The `verified` flag is NOT the control here and is deliberately permissive:
    eVerify only ever notifies `verified: false`, so a genuine success carries no
    `verified` key at all, and demanding `verified is True` would refuse every
    genuine login. The control these tests pin is the identifier source.
    """

    def setUp(self):
        self.victim = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="VIC1234",
            given_name="Victim",
            last_name="User",
        )
        self.other = User.objects.create(
            national_id_card_number="9999888877776666",
            digital_national_id="OTH5678",
            given_name="Other",
            last_name="Person",
        )

    def _post(self, value="1111222233334444"):
        return self.client.post(
            "/everify/",
            data=json.dumps({"value": value, "face_liveness_session_id": "sess"}),
            content_type="application/json",
        )

    def _upstream(self, data, status_code=200):
        resp = MagicMock(status_code=status_code)
        resp.json.return_value = {"data": data}
        return resp

    def _patched(self, upstream):
        """Patch out credentials + token so the view reaches the query branch."""
        return (
            patch("verify.views.everify.EVERIFY_CLIENT_ID", "id"),
            patch("verify.views.everify.EVERIFY_CLIENT_SECRET", "secret"),
            patch("verify.views.everify.get_everify_access_token", return_value="tok"),
            patch("verify.views.everify.requests.post", return_value=upstream),
        )

    def _run(self, upstream_data, value="1111222233334444"):
        patches = self._patched(self._upstream(upstream_data))
        for p in patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in patches])
        return self._post(value)

    # -- the success shape -------------------------------------------------

    def test_absent_verified_key_with_upstream_identifier_authenticates(self):
        """THE success shape, per the measured contract: HTTP 200, an identity,
        and no `verified` key. Refusing this refuses every genuine login."""
        resp = self._run({"reference": "1111222233334444", "code": "VIC1234"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.client.session.get(SESSION_KEY), self.victim.id)

    # -- fail-closed cases -------------------------------------------------

    def test_upstream_names_nobody_authenticates_nobody(self):
        """The sharpest case: upstream returns 200 and a non-empty payload, but
        no identifier. It must not fall back to the National ID the caller sent."""
        resp = self._run({"first_name": "Victim"})
        self.assertNotEqual(self.client.session.get(SESSION_KEY), self.victim.id)
        self.assertIsNone(self.client.session.get(SESSION_KEY))

    def test_empty_upstream_payload_is_no_matching_record(self):
        resp = self._run({})
        self.assertEqual(resp.status_code, 404)
        self.assertIsNone(self.client.session.get(SESSION_KEY))

    def test_explicit_verified_false_is_refused(self):
        resp = self._run(
            {"reference": "1111222233334444", "code": "VIC1234", "verified": False}
        )
        self.assertEqual(json.loads(resp.content)["status"], "error")
        self.assertIsNone(self.client.session.get(SESSION_KEY))

    def test_upstream_identifier_matching_no_user_authenticates_nobody(self):
        resp = self._run({"reference": "5555444433332222", "code": "NON9999"})
        self.assertIsNone(self.client.session.get(SESSION_KEY))

    def test_caller_value_is_not_the_identity(self):
        """Caller asks for the victim; upstream vouches for someone else. The
        session must follow the upstream, not the request body."""
        resp = self._run(
            {"reference": "9999888877776666", "code": "OTH5678"},
            value="1111222233334444",
        )
        self.assertEqual(self.client.session.get(SESSION_KEY), self.other.id)

    def test_backfill_cannot_touch_another_users_row(self):
        """A successful login backfills only the row the upstream named."""
        self._run({"reference": "9999888877776666", "code": "OTH5678",
                   "first_name": "Renamed", "last_name": "Attacker"})
        self.victim.refresh_from_db()
        self.assertEqual(self.victim.given_name, "Victim")
        self.assertEqual(self.victim.last_name, "User")


class EverifyMockGateTest(TestCase):
    """_mock_everify_data() echoes caller input back as a verified identity, so
    reaching it is a full authentication bypass. It needs two opt-ins."""

    def setUp(self):
        self.victim = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="VIC1234",
            given_name="Victim",
        )

    def _post(self):
        return self.client.post(
            "/everify/",
            data=json.dumps({"value": "1111-2222-3333-4444"}),
            content_type="application/json",
        )

    @override_settings(DEBUG=True, EVERIFY_ALLOW_MOCK_LOGIN=False)
    def test_debug_alone_does_not_enable_mock_login(self):
        resp = self._post()
        self.assertIsNone(self.client.session.get(SESSION_KEY))
        self.assertNotEqual(resp.status_code, 200)

    @override_settings(DEBUG=False, EVERIFY_ALLOW_MOCK_LOGIN=True)
    def test_flag_alone_does_not_enable_mock_login(self):
        resp = self._post()
        self.assertIsNone(self.client.session.get(SESSION_KEY))
        self.assertNotEqual(resp.status_code, 200)

    @override_settings(DEBUG=True, EVERIFY_ALLOW_MOCK_LOGIN=True)
    def test_both_opt_ins_enable_mock_login(self):
        resp = self._post()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.client.session.get(SESSION_KEY), self.victim.id)

    @override_settings(DEBUG=True, EVERIFY_ALLOW_MOCK_LOGIN=False)
    def test_liveness_sdk_still_loaded_when_mock_is_off(self):
        """The template's liveness gate must track the same switch, or the
        browser skips liveness while the server still demands a session id."""
        resp = self.client.get("/")
        self.assertFalse(resp.context["debug"])


class QrLoginEndpointRemovedTest(TestCase):
    """`POST /qr-login/` logged a user in from the request body with no eVerify
    exchange and no liveness check. It must not come back."""

    def setUp(self):
        User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="VIC1234",
            given_name="Victim",
        )

    def test_qr_login_route_is_gone(self):
        resp = self.client.post(
            "/qr-login/",
            data=json.dumps({"id_number": "VIC1234", "pcn": "1111222233334444"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 404)
        self.assertIsNone(self.client.session.get(SESSION_KEY))

    def test_qr_login_name_is_not_routable(self):
        with self.assertRaises(NoReverseMatch):
            reverse("qr_login")

    def test_decode_qr_does_not_start_a_session(self):
        """The QR decoder returns fields to the client; it is not a login."""
        resp = self.client.post("/decode-qr/")
        self.assertIsNone(self.client.session.get(SESSION_KEY))


class NationalIdQrDecodeTest(TestCase):
    """Every National ID code that carries a card number yields it.

    The PhilID card's back nests the person under `subject`, in PSA's own key
    names, and it is the code a card holder is most likely to hold up, so
    both pages read it. The holder is PSA's placeholder, never a real one --
    PSA's published samples carry real-looking people.
    """

    # PSA's indented JSON with the line breaks taken out, as the card prints
    # it. The signature is a stand-in: nothing here checks it.
    PHILID_CARD = (
        '{  "DateIssued": "12 February 2021",  "Issuer": "PSA",  "subject": {'
        '    "Suffix": "",    "lName": "DELA CRUZ",    "fName": "JUANA",'
        '    "mName": "MARTINEZ",    "sex": "Female",    "BF": "[6,2]",'
        '    "DOB": "January 01, 1990",'
        '    "POB": "City of Marikina, Metro Manila",'
        '    "PCN": "1234-5678-9101-1213"  },  "alg": "EDDSA",'
        '  "signature": "' + "A" * 86 + '=="}'
    )

    def _qr_png(self, text):
        import cv2
        img = cv2.QRCodeEncoder.create().encode(text)
        img = cv2.resize(img, None, fx=6, fy=6, interpolation=cv2.INTER_NEAREST)
        img = cv2.copyMakeBorder(img, 40, 40, 40, 40, cv2.BORDER_CONSTANT,
                                 value=255)
        ok, png = cv2.imencode(".png", img)
        self.assertTrue(ok)
        return SimpleUploadedFile("card.png", png.tobytes(),
                                  content_type="image/png")

    def test_the_philid_card_gives_its_card_number_bare(self):
        """Bare, as a scanned 16-digit code is: the card prints dashes."""
        fields = _parse_national_id_payload(self.PHILID_CARD)
        self.assertEqual(fields["pcn"], "1234567891011213")
        self.assertEqual(fields["last_name"], "DELA CRUZ")
        self.assertEqual(fields["first_name"], "JUANA")
        self.assertEqual(fields["date_of_birth"], "January 01, 1990")
        self.assertEqual(fields["issuer"], "PSA")
        self.assertNotIn("id_number", fields)

    def test_the_digital_national_id_back_is_read_as_before(self):
        fields = _parse_national_id_payload(json.dumps({
            "bd": "1990-01-01", "id": "ABC1234", "iss": "national-id.gov.ph",
            "n_f": "JUANA", "n_l": "DELA CRUZ", "pcn": "1234567891011213",
            "v": "1.0", "z": "A" * 86 + "=="}))
        self.assertEqual(fields["id_number"], "ABC1234")
        self.assertEqual(fields["pcn"], "1234567891011213")
        self.assertEqual(fields["last_name"], "DELA CRUZ")

    def test_the_endpoint_reads_the_card_from_a_picture(self):
        """The server fallback both pages use when jsQR cannot see the code."""
        resp = self.client.post("/decode-qr/",
                                {"qr_image": self._qr_png(self.PHILID_CARD)})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["data"]["pcn"], "1234567891011213")

    def test_both_pages_read_the_card_number_on_their_own(self):
        """jsQR decodes the card in the browser first, so the pages need the
        branch as well. On the Verify page the card's JSON would otherwise go
        to eVerify whole, and on a failure into the transaction's digital-ID
        column, name and birth date with it."""
        for page in ("login.html", "app.html"):
            source = (settings.BASE_DIR / "templates" / page).read_text(
                encoding="utf-8")
            extractor = source.split("function extractIdFromQrPayload(", 1)[1]
            extractor = extractor.split("\n        function ", 1)[0]
            with self.subTest(page=page):
                self.assertIn("if (parsed.subject && parsed.subject.PCN) {",
                              extractor)
                self.assertIn("return String(parsed.subject.PCN)"
                              ".replace(/[-\\s]/g, '');", extractor)


class FindUserIdentifierTest(TestCase):
    """_find_user resolves an identifier to a row. Every empty or degenerate
    identifier must resolve to None — one that matches "any user" is a bypass."""

    def setUp(self):
        self.user = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="VIC1234",
            given_name="Victim",
        )
        # A row with no digital ID: the non-unique default "" must not be a
        # wildcard that an empty lookup can land on.
        self.blank = User.objects.create(
            national_id_card_number="2222333344445555",
            digital_national_id="",
            given_name="Blank",
        )

    def test_empty_identifiers_match_nobody(self):
        self.assertIsNone(_find_user("", pcn=""))
        self.assertIsNone(_find_user(None, pcn=None))
        self.assertIsNone(_find_user("   ", pcn="   "))

    def test_punctuation_only_pcn_does_not_collapse_to_empty_lookup(self):
        """"-" strips to "", which would otherwise query for an unset ID."""
        self.assertIsNone(_find_user("", pcn="-"))
        self.assertIsNone(_find_user("", pcn="----"))

    def test_real_identifiers_still_resolve(self):
        self.assertEqual(_find_user("", pcn="1111-2222-3333-4444"), self.user)
        self.assertEqual(_find_user("VIC1234", pcn=""), self.user)
        self.assertEqual(_find_user("vic1234", pcn=""), self.user)


class AdminViewSiteLinkTest(TestCase):
    """"VIEW SITE" in the Django admin header points at the app itself.

    Django's default is "/", which is the login page. A Django staff or
    superuser is bridged to a verify User by _get_session_user(), so /app/
    renders for them without a separate eVerify login.
    """

    def setUp(self):
        # A site admin may enter any active organization, so one organization
        # with one location resolves the context without asking.
        self.org = make_org()
        self.admin = DjangoUser.objects.create_superuser(
            "siteadmin", "siteadmin@example.com", "pw-for-tests-only")
        self.client.force_login(self.admin)

    def test_view_site_link_targets_the_app(self):
        response = self.client.get("/admin/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(admin.site.site_url, "/app/")
        self.assertContains(response, 'href="/app/"')

    def test_admin_reaches_the_app_without_an_everify_login(self):
        """The link is useless if /app/ bounces the admin back to login."""
        response = self.client.get("/app/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("app.html", [t.name for t in response.templates])

    def test_django_superuser_is_bridged_to_a_site_admin(self):
        self.client.get("/app/")
        bridged = User.objects.get(digital_national_id="siteadmin")
        self.assertTrue(bridged.is_site_admin)


class DemoModeTest(TestCase):
    """Demo mode masks what the result page shows, not what it logs."""

    ROWS = [
        {"key": "Face Photo", "value": "data:image/jpeg;base64,AAAA"},
        {"key": "Given Name", "value": "Juan Carlos"},
        {"key": "Middle Name", "value": "Santos"},
        {"key": "Last Name", "value": "Dela Cruz"},
        {"key": "Date of Birth", "value": "01/15/1990"},
        {"key": "Place of Birth", "value": "Quezon City"},
        {"key": "Blood Type", "value": "O+"},
        {"key": "Marital Status", "value": "Single"},
        {"key": "Permanent Address", "value": "123 Rizal Street, Makati City"},
        {"key": "National ID Card Number", "value": "1111222233334444"},
        {"key": "Digital National ID Number", "value": "ABC1234"},
        {"key": "Verified", "value": True},
    ]

    def setUp(self):
        self.user = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="DEM1234",
            given_name="Demo",
            last_name="Operator",
        )
        self.org = make_org()
        join(self.org, self.user)
        self.settings = UserSettings.objects.create(user=self.user, demo_mode=True)
        session = self.client.session
        session["verify_user_id"] = self.user.id
        session[ORG_SESSION_KEY] = self.org.id
        verified_answer.keep(session, self.org, self.ROWS)
        session.save()

    def _rows(self, response):
        return {item["key"]: item["value"] for item in response.context["data"]}

    def test_masking_rules(self):
        rows = self._rows(self.client.get("/app/document/"))
        # First word kept, the rest redacted.
        self.assertRegex(rows["Given Name"], r"^Juan •+$")
        self.assertRegex(rows["Permanent Address"], r"^123 [• ]+$")
        self.assertNotIn("Rizal", rows["Permanent Address"])
        # Redacted outright.
        for key in ("Middle Name", "Date of Birth", "Place of Birth",
                    "Blood Type", "Marital Status"):
            # bullets and word gaps only -- a multi-word value keeps its spaces
            self.assertRegex(rows[key], r"^[• ]+$", key)
        # ID numbers: last two characters only.
        self.assertRegex(rows["National ID Card Number"], r"^•+4$")
        self.assertRegex(rows["Digital National ID Number"], r"^•+4$")
        self.assertNotIn("1111", rows["National ID Card Number"])
        self.assertNotIn("ABC", rows["Digital National ID Number"])
        # Untouched: the last name, by decision. Everything else is masked,
        # a field in no list included.
        self.assertEqual(rows["Last Name"], "Dela Cruz")
        self.assertRegex(rows["Verified"], r"^•+$")

    def test_photo_is_blurred_rather_than_replaced(self):
        # The portrait is the certificate's own, above the field list, rather
        # than a cell inside it -- but the rule is the one it always was: the
        # photo is the field that cannot be redacted as text, so it is
        # blurred and never swapped for something else.
        response = self.client.get("/app/document/")
        self.assertContains(response, 'class="doc-hero-face demo-blur"')
        # The image itself must still render, or there is nothing to blur.
        self.assertEqual(self._rows(response)["Face Photo"],
                         "data:image/jpeg;base64,AAAA")

    def test_logged_transaction_data_is_not_masked(self):
        """The page is masked and carries no copy of the answer; the log is
        made of the kept answer, so it records the real verification."""
        response = self.client.get("/app/document/")
        self.assertNotIn("data_json", response.context)
        self.assertNotContains(response, "Juan Carlos")
        self.assertNotContains(response, "01/15/1990")
        kind = TransactionType.objects.create(organization=self.org, name="Enrolment")
        self.client.post("/everify/log-transaction/",
                         data=json.dumps({"transaction_type": str(kind.id)}),
                         content_type="application/json")
        txn = Transaction.objects.get()
        self.assertEqual(txn.given_name, "Juan Carlos")
        self.assertEqual(txn.date_of_birth, "01/15/1990")

    def test_masking_is_off_by_default(self):
        self.settings.demo_mode = False
        self.settings.save()
        rows = self._rows(self.client.get("/app/document/"))
        self.assertEqual(rows["Given Name"], "Juan Carlos")
        self.assertEqual(rows["Date of Birth"], "01/15/1990")
        self.assertEqual(rows["National ID Card Number"], "1111222233334444")
        self.assertEqual(rows["Place of Birth"], "Quezon City")
        self.assertNotContains(self.client.get("/app/document/"),
                               'class="face-photo demo-blur"')

    def test_mask_length_does_not_give_away_the_value(self):
        """Bullet runs are jittered, so they must not track the real length."""
        seen = set()
        for _ in range(40):
            rows = self._rows(self.client.get("/app/document/"))
            seen.add(len(rows["Marital Status"]))          # "Single", 6 chars
        self.assertGreater(len(seen), 1, "mask length never varied")
        self.assertLessEqual(max(seen), 6 + 3)
        self.assertGreaterEqual(min(seen), 1)

    def test_setup_page_saves_the_toggle(self):
        self.client.post("/app/setup/", {
            "fingerprint_auth_endpoint": "", "serial_number": "0"})
        self.settings.refresh_from_db()
        self.assertFalse(self.settings.demo_mode, "absent checkbox means off")

        self.client.post("/app/setup/", {
            "fingerprint_auth_endpoint": "", "serial_number": "0",
            "demo_mode": "on"})
        self.settings.refresh_from_db()
        self.assertTrue(self.settings.demo_mode)


@override_settings(SSO_ALLOWED_ISSUERS=TEST_SSO_ISSUERS)
class SsoLoginTest(TestCase):
    """Single sign-on is a second session-creating path. It must obey the same rules
    as POST /everify/: the identity comes only from the provider, and only a
    pre-registered operator gets a session."""

    PROFILE = {
        "sub": "abc-123",
        "national_id": "1111222233334444",
        "digital_id": "OPR1234",
        "first_name": "Ada",
        "middle_name": "",
        "last_name": "Reyes",
    }

    def setUp(self):
        self.operator = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="OPR1234",
            given_name="Ada",
            last_name="Reyes",
        )
        self.org = make_org()
        join(self.org, self.operator)
        self.site = SiteSettings.load()
        self.site.login_mode = SiteSettings.LOGIN_SSO
        self.site.sso_issuer = "https://sso.example.test/o"
        self.site.sso_client_id = "verify"
        self.site.sso_client_secret = "s3cret"
        self.site.save()

    def _prime(self):
        """Put a matching state/verifier in the session, as sso_login would."""
        session = self.client.session
        session[sso.STATE_KEY] = "st4te"
        session[sso.VERIFIER_KEY] = "ver1fier"
        session.save()

    def _callback(self, profile=None, **params):
        query = {"state": "st4te", "code": "auth-code"}
        query.update(params)
        with patch.object(sso, "exchange",
                          return_value=profile or dict(self.PROFILE)):
            return self.client.get("/national-id/callback/", query)

    # -- the happy path ----------------------------------------------------

    def test_registered_operator_gets_a_session(self):
        """Sign-in lands on the chooser, which decides whether to ask anything.
        The location is no longer collected before leaving for the provider."""
        self._prime()
        response = self._callback()
        self.assertRedirects(response, "/choose/", fetch_redirect_response=False)
        self.assertEqual(self.client.session["verify_user_id"], self.operator.id)

    # -- the guarantee worth protecting ------------------------------------

    def test_unknown_identity_creates_no_account_and_no_session(self):
        before = User.objects.count()
        self._prime()
        stranger = dict(self.PROFILE, sub="zz", national_id="9999888877776666",
                        digital_id="STR9999")
        response = self._callback(stranger)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("verify_user_id", self.client.session)
        self.assertEqual(User.objects.count(), before, "auto-provisioned a user")

    def test_identity_in_the_request_is_ignored(self):
        """The callback must take the identity from the exchange, never from
        query parameters the caller controls."""
        self._prime()
        response = self._callback(
            dict(self.PROFILE, digital_id="", national_id=""),
            digital_id="OPR1234", pcn="1111222233334444")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("verify_user_id", self.client.session)

    # -- protections on the round trip -------------------------------------

    def test_state_mismatch_is_refused(self):
        self._prime()
        response = self._callback(state="wrong")
        self.assertNotIn("verify_user_id", self.client.session)
        self.assertContains(response, "expired or was invalid")

    def test_callback_without_a_started_flow_is_refused(self):
        response = self._callback()          # no _prime(): no state in session
        self.assertNotIn("verify_user_id", self.client.session)
        self.assertContains(response, "expired or was invalid")

    def test_state_is_consumed_by_the_first_callback(self):
        """Both halves are popped up front, so a code cannot be replayed
        against a state that is still sitting in the session."""
        self._prime()
        self._callback()
        self.assertNotIn(sso.STATE_KEY, self.client.session)
        self.assertNotIn(sso.VERIFIER_KEY, self.client.session)

    # -- the double gate ---------------------------------------------------

    def test_routes_are_dead_unless_sso_is_the_selected_mode(self):
        self.site.login_mode = SiteSettings.LOGIN_EVERIFY
        self.site.save()
        self._prime()
        self.assertRedirects(self._callback(), "/", fetch_redirect_response=False)
        self.assertNotIn("verify_user_id", self.client.session)

    def test_routes_are_dead_while_credentials_are_incomplete(self):
        self.site.sso_client_secret = ""
        self.site.save()
        self._prime()
        self.assertRedirects(self._callback(), "/", fetch_redirect_response=False)
        self.assertNotIn("verify_user_id", self.client.session)

    def test_sso_login_rejects_get(self):
        self.assertEqual(self.client.get("/sso/login/").status_code, 405)

    # -- which login page is served ----------------------------------------

    def test_login_page_switches_with_the_mode(self):
        self.assertTemplateUsed(self.client.get("/"), "login_sso.html")
        self.site.login_mode = SiteSettings.LOGIN_EVERIFY
        self.site.save()
        self.assertTemplateUsed(self.client.get("/"), "login.html")


class SiteOrganizationCreateTest(TestCase):
    """An organization appears when the form is submitted, and not before.

    A name box beside a button that posted straight to the database would
    leave a real row behind for anyone who wanted to see the form first, or
    who mistyped -- unconfigured, and describable only as a mistake by every
    screen that then had to list it.
    """

    def setUp(self):
        self.site_admin = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="SITE1", given_name="Sam", is_site_admin=True)

    def _as(self, user):
        session = self.client.session
        session[SESSION_KEY] = user.id
        session.save()

    def test_the_list_page_offers_a_button_and_no_name_box(self):
        self._as(self.site_admin)
        page = self.client.get("/app/site/").content.decode()
        self.assertIn('href="/app/site/organizations/new/"', page)
        # The name box and the endpoint that created from it are both gone.
        self.assertNotIn('id="new-org-name"', page)
        self.assertNotIn('id="btn-create-org"', page)

    def test_opening_the_form_creates_nothing(self):
        self._as(self.site_admin)
        response = self.client.get("/app/site/organizations/new/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Organization.objects.count(), 0)
        # The parts that need a saved row are not drawn yet.
        page = response.content.decode()
        self.assertIn("Create organization", page)
        self.assertNotIn('id="btn-assign"', page)
        self.assertNotIn('id="fl-list"', page)

    def test_submitting_the_form_creates_it_and_lands_on_its_page(self):
        self._as(self.site_admin)
        response = self.client.post(
            "/app/site/organizations/new/",
            {"name": "Beta Clinic", "subtitle": "Sub", "mark_color": "#123456",
             "everify_base_url": "https://ws.everify.gov.ph/api",
             "everify_client_id": "beta-id", "is_active": "on"})
        org = Organization.objects.get(name="Beta Clinic")
        self.assertRedirects(response, f"/app/site/organizations/{org.id}/",
                             fetch_redirect_response=False)
        self.assertEqual(org.mark_color, "#123456")
        self.assertTrue(org.is_active)
        # An issuer code is assigned now, exactly as the old create did: a
        # credential minted by an organization that has none names nobody.
        self.assertTrue(org.issuer_code)

    def test_a_rejected_form_creates_nothing(self):
        self._as(self.site_admin)
        make_org(name="Alpha")
        for payload in ({"name": ""}, {"name": "alpha"},
                        {"name": "Gamma", "issuer_code": "!!"}):
            response = self.client.post("/app/site/organizations/new/", payload)
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.context["error"])
        self.assertEqual(Organization.objects.count(), 1)

    def test_a_refused_create_hands_the_typing_back(self):
        """Nothing on this app clears an operator's typing by itself, and a
        form that empties itself on a rejected name is the same failure."""
        self._as(self.site_admin)
        response = self.client.post(
            "/app/site/organizations/new/",
            {"name": "Gamma Clinic", "subtitle": "Kept", "issuer_code": "!!",
             "everify_client_id": "gamma-id", "mark_color": "#123456"})
        page = response.content.decode()
        self.assertIn("Gamma Clinic", page)
        self.assertIn("Kept", page)
        self.assertIn("gamma-id", page)
        self.assertEqual(Organization.objects.count(), 0)

    def test_only_a_site_admin_may_open_or_submit_the_form(self):
        operator = User.objects.create(
            national_id_card_number="5555666677778888",
            digital_national_id="OP1", given_name="Ada")
        self._as(operator)
        self.assertRedirects(self.client.get("/app/site/organizations/new/"),
                             "/app/", fetch_redirect_response=False)
        self.assertRedirects(
            self.client.post("/app/site/organizations/new/", {"name": "Sneaky"}),
            "/app/", fetch_redirect_response=False)
        self.assertFalse(Organization.objects.filter(name="Sneaky").exists())



class OrganizationContactFieldsTest(TestCase):
    """An organization's postal address and who to ask about it.

    Nine optional fields on one form. Three of them are personal data about a
    named human being -- the first this page has ever held -- so they are
    masked under Demo Mode, and a masked value posted back must keep what is
    stored. Without that second half, presenting to an audience and pressing
    Save writes bullets over a real phone number, which is the self-inflicted
    outage the eVerify client id is already guarded against.
    """

    FIELDS = {
        "address_line1": "PSA Complex, East Avenue",
        "address_line2": "Diliman",
        "barangay": "Pinyahan",
        "municipality": "Quezon City",
        "postal_code": "1101",
        "country": "Philippines",
        "contact_person": "Maria Santos Dela Cruz",
        "contact_email": "records@example.ph",
        "contact_mobile": "+63 917 555 0142",
    }

    def setUp(self):
        self.site_admin = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="SITE1", given_name="Sam", is_site_admin=True)
        self.org = make_org(name="Alpha")
        self._as(self.site_admin)

    def _as(self, user):
        session = self.client.session
        session[SESSION_KEY] = user.id
        session.save()

    def _save(self, **overrides):
        payload = {"name": self.org.name, "mark_color": "#00386a",
                   "is_active": "on"}
        payload.update(self.FIELDS)
        payload.update(overrides)
        return self.client.post(f"/app/site/organizations/{self.org.id}/",
                                payload)

    def test_the_form_stores_all_nine(self):
        self._save()
        self.org.refresh_from_db()
        for field, value in self.FIELDS.items():
            self.assertEqual(getattr(self.org, field), value, field)

    def test_they_are_optional(self):
        """Deployments already have organizations, and a required address
        would stop an admin saving an unrelated change."""
        response = self.client.post(
            f"/app/site/organizations/{self.org.id}/",
            {"name": "Alpha", "mark_color": "#00386a", "is_active": "on"})
        self.assertEqual(response.context["error"], "")
        self.org.refresh_from_db()
        self.assertEqual(self.org.address_line1, "")
        self.assertEqual(self.org.contact_email, "")

    def test_a_masked_contact_value_keeps_what_is_stored(self):
        self._save()
        masked = DEMO_MASK_CHAR * 6
        self._save(contact_person=f"Maria {masked}", contact_email=masked,
                   contact_mobile=masked)
        self.org.refresh_from_db()
        self.assertEqual(self.org.contact_person, "Maria Santos Dela Cruz")
        self.assertEqual(self.org.contact_email, "records@example.ph")
        self.assertEqual(self.org.contact_mobile, "+63 917 555 0142")

    def test_somebody_who_retypes_a_value_while_presenting_is_obeyed(self):
        """The guard keys on the mask character, not on demo_mode."""
        self._save()
        UserSettings.objects.update_or_create(
            user=self.site_admin, defaults={"demo_mode": True})
        self._save(contact_mobile="+63 918 111 2222")
        self.org.refresh_from_db()
        self.assertEqual(self.org.contact_mobile, "+63 918 111 2222")

    def test_demo_mode_redacts_all_three_on_the_page(self):
        self._save()
        UserSettings.objects.update_or_create(
            user=self.site_admin, defaults={"demo_mode": True})
        page = self.client.get(
            f"/app/site/organizations/{self.org.id}/").content.decode()
        self.assertNotIn("Santos Dela Cruz", page)
        self.assertNotIn("records@example.ph", page)
        self.assertNotIn("917 555 0142", page)
        # Masked as one string, so the first word of the name is kept.
        self.assertIn("Maria", page)
        self.assertIn(DEMO_MASK_CHAR, page)

    def test_the_address_is_not_redacted(self):
        """Demo Mode hides people, not places. The address is the
        organization's own, and it is on every letterhead it prints."""
        self._save()
        UserSettings.objects.update_or_create(
            user=self.site_admin, defaults={"demo_mode": True})
        page = self.client.get(
            f"/app/site/organizations/{self.org.id}/").content.decode()
        self.assertIn("PSA Complex, East Avenue", page)
        self.assertIn("Quezon City", page)

    def test_an_email_that_is_not_one_is_refused(self):
        response = self._save(contact_email="not an address")
        self.assertIn("valid email", response.context["error"])
        self.org.refresh_from_db()
        self.assertEqual(self.org.contact_email, "")
        # And the refusal takes the whole save with it, so the row is not
        # half-written.
        self.assertEqual(self.org.address_line1, "")

    def test_the_create_form_carries_them_too(self):
        response = self.client.post(
            "/app/site/organizations/new/",
            dict({"name": "Beta Clinic", "mark_color": "#00386a",
                  "is_active": "on"}, **self.FIELDS))
        beta = Organization.objects.get(name="Beta Clinic")
        self.assertRedirects(response, f"/app/site/organizations/{beta.id}/",
                             fetch_redirect_response=False)
        self.assertEqual(beta.municipality, "Quezon City")
        self.assertEqual(beta.contact_email, "records@example.ph")

    def test_a_refused_create_hands_the_address_back(self):
        response = self.client.post(
            "/app/site/organizations/new/",
            dict({"name": "Beta Clinic", "issuer_code": "!!"}, **self.FIELDS))
        page = response.content.decode()
        self.assertIn("PSA Complex, East Avenue", page)
        self.assertIn("Maria Santos Dela Cruz", page)
        self.assertEqual(Organization.objects.count(), 1)


class OrganizationFormLayoutTest(TestCase):
    """One form, grouped, with the status row at its head.

    The Enabled switch is a form field and must stay INSIDE the form. Reaching
    it through a form= attribute would post nothing on a browser that did not
    honour that -- and absence is how an unchecked checkbox spells "disabled",
    so the failure is an organization that switches itself off every time
    anybody saves it.
    """

    def setUp(self):
        self.site_admin = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="SITE1", given_name="Sam", is_site_admin=True)
        self.org = make_org(name="Alpha")
        session = self.client.session
        session[SESSION_KEY] = self.site_admin.id
        session.save()

    def _form(self, url):
        page = self.client.get(url).content.decode()
        start = page.index('id="org-form"')
        return page[start:page.index("</form>", start)]

    def test_every_field_is_inside_the_one_form(self):
        for url in (f"/app/site/organizations/{self.org.id}/",
                    "/app/site/organizations/new/"):
            body = self._form(url)
            self.assertIn('name="is_active"', body, url)
            for field in OrganizationContactFieldsTest.FIELDS:
                self.assertIn('name="%s"' % field, body, "%s %s" % (url, field))

    def test_the_form_is_grouped_into_named_sections(self):
        for url in (f"/app/site/organizations/{self.org.id}/",
                    "/app/site/organizations/new/"):
            body = self._form(url)
            for heading in ("Identity", "Address", "Contact",
                            "eVerify credentials"):
                self.assertIn("<h3>%s</h3>" % heading, body, "%s %s" % (url, heading))

    def test_the_page_still_saves_everything_in_one_press(self):
        """One form, one POST: the regrouping must not have left a section
        outside it, which would save silently as blank."""
        self.client.post(
            f"/app/site/organizations/{self.org.id}/",
            {"name": "Alpha", "subtitle": "Sub", "mark_color": "#123456",
             "is_active": "on", "barangay": "Pinyahan",
             "contact_person": "Maria Santos", "issuer_code": "ALP",
             "everify_base_url": "https://ws.everify.gov.ph/api"})
        self.org.refresh_from_db()
        self.assertEqual(self.org.subtitle, "Sub")
        self.assertEqual(self.org.barangay, "Pinyahan")
        self.assertEqual(self.org.contact_person, "Maria Santos")
        self.assertEqual(self.org.issuer_code, "ALP")
        self.assertTrue(self.org.is_active)


class SiteOrganizationDeleteTest(TestCase):
    """Deleting is for a row that should not exist. History is what stops it.

    Transaction.organization and IssuedCredential.organization are SET_NULL, so
    a delete would not destroy them -- it would orphan them, which is quieter
    and worse. Disabling is the reversible answer and keeps everything.
    """

    def setUp(self):
        self.site_admin = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="SITE1", given_name="Sam", is_site_admin=True)
        self.operator = User.objects.create(
            national_id_card_number="5555666677778888",
            digital_national_id="OP1", given_name="Ada")
        self.org = make_org(name="Alpha")
        join(self.org, self.operator, Membership.ROLE_ADMIN)

    def _as(self, user, org=None):
        session = self.client.session
        session[SESSION_KEY] = user.id
        if org:
            session[ORG_SESSION_KEY] = org.id
        session.save()

    def _delete(self, org_id):
        return self.client.post(f"/app/site/organizations/{org_id}/delete/",
                                data="{}", content_type="application/json")

    def test_a_site_admin_deletes_an_organization_and_its_own_lists(self):
        self._as(self.site_admin)
        response = self._delete(self.org.id)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        self.assertFalse(Organization.objects.filter(pk=self.org.id).exists())
        self.assertFalse(Membership.objects.filter(organization_id=self.org.id).exists())
        self.assertFalse(Location.objects.filter(organization_id=self.org.id).exists())
        # The PERSON is site-wide and is kept: they routinely belong to
        # another organization.
        self.assertTrue(User.objects.filter(pk=self.operator.id).exists())

    def test_an_organization_with_transactions_is_refused(self):
        Transaction.objects.create(organization=self.org,
                                   authentication_result="success")
        self._as(self.site_admin)
        response = self._delete(self.org.id)
        self.assertEqual(response.status_code, 400)
        self.assertIn("Disable it instead", response.json()["message"])
        self.assertTrue(Organization.objects.filter(pk=self.org.id).exists())
        # And nothing was orphaned on the way to that refusal.
        self.assertEqual(
            Transaction.objects.filter(organization__isnull=True).count(), 0)

    def test_an_organization_with_issued_credentials_is_refused(self):
        IssuedCredential.objects.create(
            organization=self.org, credential_id=uuid.uuid4(),
            document_uuid=uuid.uuid4(), epoch=14, issuer_key_id=1,
            issued_at=timezone.now(),
            expires_at=timezone.now() + datetime.timedelta(days=365))
        self._as(self.site_admin)
        self.assertEqual(self._delete(self.org.id).status_code, 400)
        self.assertTrue(Organization.objects.filter(pk=self.org.id).exists())

    def test_the_row_offers_no_delete_once_there_is_history(self):
        self._as(self.site_admin)
        page = self.client.get("/app/site/").content.decode()
        self.assertIn('class="btn-delete-org"', page)

        Transaction.objects.create(organization=self.org,
                                   authentication_result="success")
        page = self.client.get("/app/site/").content.decode()
        self.assertNotIn('class="btn-delete-org"', page)
        self.assertIn('class="no-delete"', page)

    def test_an_org_admin_cannot_delete_their_own_organization(self):
        self._as(self.operator, self.org)
        self.assertEqual(self._delete(self.org.id).status_code, 403)
        self.assertTrue(Organization.objects.filter(pk=self.org.id).exists())

    def test_deleting_something_that_is_not_there(self):
        self._as(self.site_admin)
        self.assertEqual(self._delete(self.org.id + 999).status_code, 404)


@override_settings(SSO_ALLOWED_ISSUERS=TEST_SSO_ISSUERS)
class SiteSettingsAdminTest(TestCase):
    """Site administration is admin-only, and the secret is write-only."""

    BASE = {"fingerprint_auth_endpoint": "", "serial_number": "0"}

    def setUp(self):
        self.admin = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="ADM1", given_name="Admin",
            is_site_admin=True)
        self.operator = User.objects.create(
            national_id_card_number="5555666677778888",
            digital_national_id="OPR1", given_name="Operator")
        self.site = SiteSettings.load()
        self.site.sso_client_id = "verify"
        self.site.sso_client_secret = "existing-secret"
        self.site.save()

    def _as(self, user):
        session = self.client.session
        session["verify_user_id"] = user.id
        session.save()

    def test_secret_is_never_rendered_back(self):
        self._as(self.admin)
        response = self.client.get("/app/setup/")
        self.assertContains(response, "Site Administration")
        self.assertNotContains(response, "existing-secret")

    def test_blank_secret_keeps_the_stored_one(self):
        self._as(self.admin)
        self.client.post("/app/setup/", dict(
            self.BASE, login_mode="everify", sso_issuer="https://id.example.org/o",
            sso_client_id="verify", sso_client_secret=""))
        self.site.refresh_from_db()
        self.assertEqual(self.site.sso_client_secret, "existing-secret")

    def test_secret_can_be_replaced_and_cleared(self):
        self._as(self.admin)
        self.client.post("/app/setup/", dict(
            self.BASE, login_mode="everify", sso_issuer="https://id.example.org/o",
            sso_client_id="verify", sso_client_secret="new-secret"))
        self.site.refresh_from_db()
        self.assertEqual(self.site.sso_client_secret, "new-secret")

        self.client.post("/app/setup/", dict(
            self.BASE, login_mode="everify", sso_issuer="https://id.example.org/o",
            sso_client_id="verify", sso_clear_secret="1"))
        self.site.refresh_from_db()
        self.assertEqual(self.site.sso_client_secret, "")

    def test_org_admin_is_not_a_site_admin(self):
        """Administering an organization must not carry the site's login
        method with it — that is a different, wider capability."""
        org = make_org()
        join(org, self.operator, Membership.ROLE_ADMIN)
        self._as(self.operator)
        self.assertNotContains(self.client.get("/app/setup/"), "Site Administration")

    def test_non_admin_sees_nothing_and_changes_nothing(self):
        self._as(self.operator)
        response = self.client.get("/app/setup/")
        self.assertNotContains(response, "Site Administration")

        self.client.post("/app/setup/", dict(self.BASE, login_mode="sso",
                                             sso_client_id="hijacked"))
        self.site.refresh_from_db()
        self.assertEqual(self.site.login_mode, SiteSettings.LOGIN_EVERIFY)
        self.assertEqual(self.site.sso_client_id, "verify")

    def test_sso_cannot_be_selected_without_complete_credentials(self):
        self._as(self.admin)
        response = self.client.post("/app/setup/", dict(
            self.BASE, login_mode="sso", sso_issuer="https://id.example.org/o",
            sso_client_id="verify", sso_clear_secret="1"))
        self.assertContains(response, "needs an issuer, a client ID")
        self.site.refresh_from_db()
        self.assertEqual(self.site.login_mode, SiteSettings.LOGIN_EVERIFY)

    def test_issuer_must_be_https(self):
        self._as(self.admin)
        response = self.client.post("/app/setup/", dict(
            self.BASE, login_mode="everify", sso_issuer="http://id.example.org/o",
            sso_client_id="verify"))
        self.assertContains(response, "must be an https")


# ===========================================================================
# Multi-organization
# ===========================================================================

class OrganizationContextTest(TestCase):
    """Which organization a session acts for, and when the operator is asked.

    The skip rules matter as much as the chooser: the common case is one
    organization with one location, and that operator must never see an extra
    page.
    """

    def setUp(self):
        self.user = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="OPR1", given_name="Ada", last_name="Reyes")
        self._sign_in()

    def _sign_in(self):
        session = self.client.session
        session[SESSION_KEY] = self.user.id
        session.save()

    def test_one_org_one_location_never_shows_the_chooser(self):
        org = make_org(locations=("Main Office",))
        join(org, self.user)
        response = self.client.get("/app/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("app.html", [t.name for t in response.templates])
        self.assertEqual(self.client.session[ORG_SESSION_KEY], org.id)

    def test_one_org_several_locations_asks(self):
        org = make_org(locations=("North", "South"))
        join(org, self.user)
        self.assertRedirects(self.client.get("/app/"), "/choose/",
                             fetch_redirect_response=False)

    def test_several_orgs_asks(self):
        for name in ("Alpha", "Beta"):
            join(make_org(name=name), self.user)
        self.assertRedirects(self.client.get("/app/"), "/choose/",
                             fetch_redirect_response=False)

    def test_no_membership_means_no_context_and_no_org_pages(self):
        response = self.client.get("/choose/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "have not been added to any")
        self.assertNotIn(ORG_SESSION_KEY, self.client.session)

    def test_choosing_a_valid_pair_starts_the_context(self):
        org = make_org(locations=("North", "South"))
        join(org, self.user)
        north = org.locations.get(name="North")
        response = self.client.post("/choose/", {
            "organization": org.id, "location": north.id})
        self.assertRedirects(response, "/app/", fetch_redirect_response=False)
        self.assertEqual(self.client.session[ORG_SESSION_KEY], org.id)
        self.assertEqual(self.client.session["operator_location"], str(north.id))

    def test_choice_is_remembered_on_the_device_but_grants_nothing(self):
        org = make_org(locations=("North", "South"))
        join(org, self.user)
        north = org.locations.get(name="North")
        self.client.post("/choose/", {"organization": org.id, "location": north.id})
        self.assertIn("verify_last_context", self.client.cookies)

        # The cookie outlives a revoked membership, and still grants nothing:
        # it only pre-fills the form, it is never an authorisation.
        Membership.objects.filter(user=self.user).delete()
        self.assertIn("verify_last_context", self.client.cookies)
        response = self.client.get("/choose/")
        self.assertContains(response, "have not been added to any")
        self.assertNotIn(ORG_SESSION_KEY, self.client.session)

    def test_cannot_choose_an_organization_you_do_not_belong_to(self):
        mine = make_org(name="Mine", locations=("North", "South"))
        join(mine, self.user)
        theirs = make_org(name="Theirs")
        response = self.client.post("/choose/", {
            "organization": theirs.id,
            "location": theirs.locations.first().id})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Select an organization you belong to")
        self.assertNotIn(ORG_SESSION_KEY, self.client.session)

    def test_cannot_choose_another_organizations_location(self):
        mine = make_org(name="Mine", locations=("North", "South"))
        join(mine, self.user)
        theirs = make_org(name="Theirs", locations=("Elsewhere",))
        response = self.client.post("/choose/", {
            "organization": mine.id,
            "location": theirs.locations.first().id})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Select the location")
        self.assertNotIn(ORG_SESSION_KEY, self.client.session)

    def test_disabling_the_organization_ends_the_session_at_once(self):
        """Re-checked every request, not trusted from the session."""
        org = make_org(locations=("North", "South"))
        join(org, self.user)
        north = org.locations.get(name="North")
        self.client.post("/choose/", {"organization": org.id, "location": north.id})
        self.assertEqual(self.client.session[ORG_SESSION_KEY], org.id)

        org.is_active = False
        org.save()
        self.assertRedirects(self.client.get("/app/"), "/choose/",
                             fetch_redirect_response=False)
        self.assertNotIn(ORG_SESSION_KEY, self.client.session)

    def test_revoking_membership_ends_the_session_at_once(self):
        org = make_org(locations=("North", "South"))
        join(org, self.user)
        north = org.locations.get(name="North")
        self.client.post("/choose/", {"organization": org.id, "location": north.id})

        Membership.objects.filter(user=self.user, organization=org).delete()
        self.assertRedirects(self.client.get("/app/"), "/choose/",
                             fetch_redirect_response=False)
        self.assertNotIn(ORG_SESSION_KEY, self.client.session)

    def test_switch_drops_the_context(self):
        org = make_org(locations=("North", "South"))
        join(org, self.user)
        self.client.post("/choose/", {
            "organization": org.id, "location": org.locations.first().id})
        # A POST, from the context strip's form.
        self.assertRedirects(self.client.post("/choose/switch/"), "/choose/",
                             fetch_redirect_response=False)
        self.assertNotIn(ORG_SESSION_KEY, self.client.session)


class OrganizationIsolationTest(TestCase):
    """An admin of one organization must not be able to reach another.

    The organization is resolved from the SESSION, never from the request, so
    every one of these is an id that simply does not resolve.
    """

    def setUp(self):
        self.admin = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="ADM1", given_name="Ada")
        self.mine = make_org(name="Mine")
        self.theirs = make_org(name="Theirs", locations=("Their Office",))
        TransactionType.objects.create(organization=self.theirs, name="Their Type")
        join(self.mine, self.admin, Membership.ROLE_ADMIN)
        session = self.client.session
        session[SESSION_KEY] = self.admin.id
        session[ORG_SESSION_KEY] = self.mine.id
        session.save()

    def _post(self, url, payload):
        return self.client.post(url, data=json.dumps(payload),
                                content_type="application/json")

    def test_lookup_data_is_scoped_to_the_current_organization(self):
        Location.objects.create(organization=self.mine, name="My Second Office")
        body = json.loads(self.client.get("/api/lookup-data/").content)
        names = {row["name"] for row in body["locations"]}
        self.assertEqual(names, {"Main Office", "My Second Office"})
        self.assertNotIn("Their Office", names)
        self.assertEqual(body["transaction_types"], [])

    def test_lookup_data_refuses_a_caller_with_no_context(self):
        """Organization-scoped: with no context there is nothing to answer."""
        self.client.session.flush()
        response = self.client.get("/api/lookup-data/")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(json.loads(response.content)["locations"], [])

    def test_cannot_rename_another_organizations_location(self):
        target = self.theirs.locations.first()
        response = self._post("/app/admin/update-location/",
                              {"id": target.id, "name": "Hijacked"})
        self.assertEqual(response.status_code, 404)
        target.refresh_from_db()
        self.assertEqual(target.name, "Their Office")

    def test_cannot_delete_another_organizations_location(self):
        target = self.theirs.locations.first()
        response = self._post("/app/admin/remove-location/", {"id": target.id})
        self.assertEqual(response.status_code, 200)  # reports success, deletes nothing
        self.assertTrue(Location.objects.filter(pk=target.pk).exists())

    def test_cannot_rename_another_organizations_transaction_type(self):
        target = TransactionType.objects.get(name="Their Type")
        response = self._post("/app/admin/update-transaction-type/",
                              {"id": target.id, "name": "Hijacked"})
        self.assertEqual(response.status_code, 404)
        target.refresh_from_db()
        self.assertEqual(target.name, "Their Type")

    def test_adding_a_location_lands_in_the_current_organization(self):
        self._post("/app/admin/add-location/", {"name": "New Desk"})
        self.assertTrue(self.mine.locations.filter(name="New Desk").exists())
        self.assertFalse(self.theirs.locations.filter(name="New Desk").exists())

    def test_the_same_name_is_allowed_in_two_organizations(self):
        """Uniqueness is per organization now — both will want a Main Office."""
        response = self._post("/app/admin/add-location/", {"name": "Their Office"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.mine.locations.filter(name="Their Office").exists())

    def test_members_are_added_to_the_current_organization_only(self):
        self._post("/app/admin/add-user/",
                   {"national_id_card_number": "5555-6666-7777-8888",
                    "role": "admin"})
        added = User.objects.get(national_id_card_number="5555666677778888")
        self.assertTrue(Membership.objects.filter(
            organization=self.mine, user=added, role="admin").exists())
        self.assertFalse(Membership.objects.filter(organization=self.theirs,
                                                   user=added).exists())

    def test_removing_a_member_leaves_their_other_memberships(self):
        other = User.objects.create(national_id_card_number="5555666677778888")
        join(self.mine, other)
        join(self.theirs, other)
        self._post("/app/admin/remove-user/", {"user_id": other.id})
        self.assertFalse(Membership.objects.filter(organization=self.mine,
                                                   user=other).exists())
        self.assertTrue(Membership.objects.filter(organization=self.theirs,
                                                  user=other).exists())
        self.assertTrue(User.objects.filter(pk=other.pk).exists())

    def test_cannot_change_the_role_of_a_non_member(self):
        outsider = User.objects.create(national_id_card_number="5555666677778888")
        join(self.theirs, outsider, Membership.ROLE_OPERATOR)
        response = self._post("/app/admin/update-role/",
                              {"user_id": outsider.id, "role": "admin"})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(
            Membership.objects.get(organization=self.theirs, user=outsider).role,
            "operator")

    def test_an_operator_cannot_reach_the_admin_endpoints(self):
        operator = User.objects.create(national_id_card_number="9999888877776666")
        join(self.mine, operator, Membership.ROLE_OPERATOR)
        session = self.client.session
        session[SESSION_KEY] = operator.id
        session[ORG_SESSION_KEY] = self.mine.id
        session.save()
        for url, payload in (
            ("/app/admin/add-location/", {"name": "Nope"}),
            ("/app/admin/add-user/", {"national_id_card_number": "1212343456567878"}),
            ("/app/admin/profile/", {"name": "Renamed"}),
            ("/app/admin/everify/", {"everify_client_id": "stolen"}),
        ):
            self.assertEqual(self._post(url, payload).status_code, 403, url)
        self.mine.refresh_from_db()
        self.assertEqual(self.mine.name, "Mine")
        self.assertEqual(self.client.get("/app/admin/stats/").status_code, 403)

    def test_stats_count_only_the_current_organizations_transactions(self):
        Transaction.objects.create(organization=self.mine,
                                   authentication_result="success")
        Transaction.objects.create(organization=self.theirs,
                                   authentication_result="success")
        body = json.loads(self.client.get("/app/admin/stats/").content)
        self.assertEqual(body["total_verifications"], 1)

    def test_export_covers_only_the_current_organization(self):
        Transaction.objects.create(organization=self.mine, given_name="Mine")
        Transaction.objects.create(organization=self.theirs, given_name="Theirs")
        body = self.client.get("/app/admin/export-transactions/").content.decode()
        self.assertIn("Mine", body)
        self.assertNotIn("Theirs", body)


class SiteAdminTest(TestCase):
    """Site administration is a capability on the person, not a role in an
    organization — otherwise nobody could create the first one."""

    def setUp(self):
        self.site_admin = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="SITE1", given_name="Sam", is_site_admin=True)
        self.org_admin = User.objects.create(
            national_id_card_number="5555666677778888",
            digital_national_id="ADM1", given_name="Ada")
        self.org = make_org(name="Alpha")
        join(self.org, self.org_admin, Membership.ROLE_ADMIN)

    def _as(self, user, org=None):
        session = self.client.session
        session[SESSION_KEY] = user.id
        if org:
            session[ORG_SESSION_KEY] = org.id
        session.save()

    def _post(self, url, payload):
        return self.client.post(url, data=json.dumps(payload),
                                content_type="application/json")

    def test_org_admin_cannot_reach_site_administration(self):
        self._as(self.org_admin, self.org)
        self.assertRedirects(self.client.get("/app/site/"), "/app/",
                             fetch_redirect_response=False)
        self.assertRedirects(
            self.client.post("/app/site/organizations/new/", {"name": "Sneaky"}),
            "/app/", fetch_redirect_response=False)
        self.assertEqual(
            self._post(f"/app/site/organizations/{self.org.id}/toggle/",
                       {"is_active": False}).status_code, 403)
        self.org.refresh_from_db()
        self.assertTrue(self.org.is_active)
        self.assertFalse(Organization.objects.filter(name="Sneaky").exists())

    def test_site_admin_creates_and_configures_an_organization(self):
        self._as(self.site_admin)
        response = self.client.post("/app/site/organizations/new/",
                                    {"name": "Beta", "mark_color": "#123456",
                                     "is_active": "on"})
        beta = Organization.objects.get(name="Beta")
        self.assertRedirects(response, f"/app/site/organizations/{beta.id}/",
                             fetch_redirect_response=False)
        # Created before it is configured: that state has to be usable.
        self.assertFalse(beta.everify_configured)

        self._post(f"/app/site/organizations/{beta.id}/members/",
                   {"national_id_card_number": "1212-3434-5656-7878",
                    "role": "admin"})
        self.assertTrue(Membership.objects.filter(
            organization=beta, role="admin").exists())

    def test_site_admin_can_disable_an_organization(self):
        self._as(self.site_admin)
        self._post(f"/app/site/organizations/{self.org.id}/toggle/",
                   {"is_active": False})
        self.org.refresh_from_db()
        self.assertFalse(self.org.is_active)
        # Nothing is destroyed by disabling.
        self.assertTrue(Membership.objects.filter(organization=self.org).exists())
        self.assertTrue(self.org.locations.exists())

    def test_site_admin_may_enter_any_active_organization(self):
        self._as(self.site_admin)
        response = self.client.get("/app/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.session[ORG_SESSION_KEY], self.org.id)

    def test_a_disabled_organization_is_not_enterable_by_anyone(self):
        self.org.is_active = False
        self.org.save()
        self._as(self.site_admin)
        self.assertRedirects(self.client.get("/app/"), "/choose/",
                             fetch_redirect_response=False)
        response = self.client.get("/choose/")
        self.assertContains(response, "no active organizations")

    def test_the_site_organization_form_saves(self):
        self._as(self.site_admin)
        response = self.client.post(
            f"/app/site/organizations/{self.org.id}/",
            {"name": "Alpha Renamed", "subtitle": "Sub", "mark_color": "#123456",
             "everify_base_url": "https://ws.everify.gov.ph/api",
             "everify_client_id": "new-id", "is_active": "on"})
        self.assertEqual(response.status_code, 200)
        self.org.refresh_from_db()
        self.assertEqual(self.org.name, "Alpha Renamed")
        self.assertEqual(self.org.mark_color, "#123456")
        # Blank secret means keep, exactly as the SSO secret behaves.
        self.assertEqual(self.org.everify_client_secret, "org-secret")


@override_settings(EVERIFY_ALLOWED_HOSTS=TEST_EVERIFY_HOSTS)
class EverifyCredentialRoutingTest(TestCase):
    """Signing in is site-level; verifying runs against the organization's own
    client, with no fallback between them."""

    def setUp(self):
        self.operator = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="OPR1", given_name="Ada")
        site = SiteSettings.load()
        site.everify_base_url = "https://site.example/api"
        site.everify_client_id = "site-id"
        site.everify_client_secret = "site-secret"
        site.everify_public_api_key = "site-key"
        site.save()

    def _fake_requests(self, calls):
        def post(url, json=None, headers=None, timeout=None, **kwargs):
            calls.append((url, json))
            response = MagicMock(status_code=200)
            if url.endswith("/auth"):
                response.json.return_value = {"data": {"access_token": "tok"}}
            else:
                response.json.return_value = {"data": {
                    "reference": "1111222233334444", "code": "OPR1"}}
            return response
        return post

    def _query(self):
        return self.client.post(
            "/everify/",
            data=json.dumps({"value": "1111222233334444",
                             "face_liveness_session_id": "sess"}),
            content_type="application/json")

    def _sign_in(self, org):
        session = self.client.session
        session[SESSION_KEY] = self.operator.id
        session[ORG_SESSION_KEY] = org.id
        session.save()

    def test_signing_in_uses_the_site_client(self):
        calls = []
        with patch("verify.views.everify.requests.post",
                   side_effect=self._fake_requests(calls)):
            self._query()
        self.assertEqual(calls[0][0], "https://site.example/api/auth")
        self.assertEqual(calls[0][1]["client_id"], "site-id")

    def test_verifying_uses_the_organizations_client(self):
        org = make_org(everify_base_url="https://org.example/api",
                       everify_client_id="org-id",
                       everify_client_secret="org-secret")
        join(org, self.operator)
        self._sign_in(org)
        calls = []
        with patch("verify.views.everify.requests.post",
                   side_effect=self._fake_requests(calls)):
            self._query()
        self.assertEqual(calls[0][0], "https://org.example/api/auth")
        self.assertEqual(calls[0][1]["client_id"], "org-id")
        self.assertTrue(calls[1][0].startswith("https://org.example/api/query"))

    def test_an_organization_without_credentials_cannot_verify(self):
        """And must NOT quietly fall back to the site client — that would bill
        one organization's verifications to another's account."""
        org = make_org(everify_client_id="", everify_client_secret="")
        join(org, self.operator)
        self._sign_in(org)
        calls = []
        with patch("verify.views.everify.requests.post",
                   side_effect=self._fake_requests(calls)):
            response = self._query()
        self.assertEqual(response.status_code, 503)
        self.assertEqual(calls, [], "fell back to another client")
        self.assertIn("no eVerify credentials",
                      json.loads(response.content)["message"])

    def test_the_liveness_key_follows_the_same_split(self):
        org = make_org(everify_public_api_key="org-key")
        join(org, self.operator)
        signed_out = self.client.post("/everify/key/")
        self.assertEqual(json.loads(signed_out.content)["public_key"], "site-key")

        self._sign_in(org)
        signed_in = self.client.post("/everify/key/")
        self.assertEqual(json.loads(signed_in.content)["public_key"], "org-key")


class TransactionAttributionTest(TestCase):
    """Every transaction records which organization it belongs to, and whether
    a site admin performed it from outside."""

    ROWS = [
        {"key": "National ID Card Number", "value": "1111222233334444"},
        {"key": "Digital National ID Number", "value": "ABC1234"},
        {"key": "Given Name", "value": "Juan"},
        {"key": "Verified", "value": True},
    ]

    def setUp(self):
        self.org = make_org(name="Alpha")
        self.other = make_org(name="Beta", locations=("Their Desk",))
        self.member = User.objects.create(
            national_id_card_number="1111222233334444", given_name="Ada")
        join(self.org, self.member)
        self.site_admin = User.objects.create(
            national_id_card_number="5555666677778888", given_name="Sam",
            is_site_admin=True)
        self.type = TransactionType.objects.create(
            organization=self.org, name="New Enrollment")
        self.other_type = TransactionType.objects.create(
            organization=self.other, name="Their Type")

    def _as(self, user):
        session = self.client.session
        session[SESSION_KEY] = user.id
        session[ORG_SESSION_KEY] = self.org.id
        verified_answer.keep(session, self.org, self.ROWS)
        session.save()

    def _log(self, transaction_type):
        return self.client.post(
            "/everify/log-transaction/",
            data=json.dumps({"transaction_type": str(transaction_type),
                             "verification_data": self.ROWS}),
            content_type="application/json")

    def test_a_members_transaction_belongs_to_the_organization(self):
        self._as(self.member)
        self._log(self.type.id)
        txn = Transaction.objects.get()
        self.assertEqual(txn.organization, self.org)
        self.assertFalse(txn.acting_as_site_admin)
        self.assertEqual(txn.transaction_type, "New Enrollment")

    def test_a_site_admin_from_outside_is_stamped_as_one(self):
        """So an organization's log never shows an operator it never assigned."""
        self._as(self.site_admin)
        self._log(self.type.id)
        txn = Transaction.objects.get()
        self.assertEqual(txn.organization, self.org)
        self.assertTrue(txn.acting_as_site_admin)

    def test_a_site_admin_who_is_also_a_member_is_not_stamped(self):
        join(self.org, self.site_admin, Membership.ROLE_ADMIN)
        self._as(self.site_admin)
        self._log(self.type.id)
        self.assertFalse(Transaction.objects.get().acting_as_site_admin)

    def test_another_organizations_transaction_type_is_not_honoured(self):
        """Refused, not logged under its raw text: the type's name is signed
        into the credential."""
        self._as(self.member)
        response = self._log(self.other_type.id)
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Transaction.objects.exists())

    def test_another_organizations_location_is_not_honoured(self):
        """Neither from the body, nor out of a session that names another
        organization's desk: the location logs blank, never as raw text."""
        self._as(self.member)
        theirs = self.other.locations.first()
        session = self.client.session
        session["operator_location"] = str(theirs.id)
        session.save()
        self.client.post(
            "/everify/log-transaction/",
            data=json.dumps({"transaction_type": str(self.type.id),
                             "verification_data": self.ROWS,
                             "operator_location": str(theirs.id)}),
            content_type="application/json")
        txn = Transaction.objects.get()
        self.assertIsNone(txn.location_ref)
        self.assertEqual(txn.operator_location, "")


class OrganizationLogoTest(TestCase):
    """Logos are stored as data URIs on the row and validated against the real
    magic bytes, not the media type the caller claims."""

    PNG = ("data:image/png;base64,"
           "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")

    def setUp(self):
        self.admin = User.objects.create(
            national_id_card_number="1111222233334444", given_name="Ada")
        self.org = make_org()
        join(self.org, self.admin, Membership.ROLE_ADMIN)
        session = self.client.session
        session[SESSION_KEY] = self.admin.id
        session[ORG_SESSION_KEY] = self.org.id
        session.save()

    def _save(self, **extra):
        payload = {"name": self.org.name}
        payload.update(extra)
        return self.client.post("/app/admin/profile/", data=json.dumps(payload),
                                content_type="application/json")

    def test_a_real_png_is_accepted(self):
        self.assertEqual(self._save(logo_data=self.PNG).status_code, 200)
        self.org.refresh_from_db()
        self.assertTrue(self.org.logo_data.startswith("data:image/png;base64,"))

    def test_a_file_lying_about_its_type_is_refused(self):
        lie = "data:image/png;base64,SGVsbG8gd29ybGQsIG5vdCBhbiBpbWFnZQ=="
        response = self._save(logo_data=lie)
        self.assertEqual(response.status_code, 400)
        self.org.refresh_from_db()
        self.assertEqual(self.org.logo_data, "")

    def test_svg_is_refused(self):
        """It is a document format that can carry script, and this value is
        echoed into pages and into the printed document."""
        svg = "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4="
        self.assertEqual(self._save(logo_data=svg).status_code, 400)

    def test_an_oversized_logo_is_refused(self):
        big = "data:image/png;base64," + base64.b64encode(
            b"\x89PNG\r\n\x1a\n" + b"\x00" * (256 * 1024)).decode()
        self.assertEqual(self._save(logo_data=big).status_code, 400)

    def test_omitting_the_logo_leaves_it_alone(self):
        self._save(logo_data=self.PNG)
        self._save(name="Renamed Org")
        self.org.refresh_from_db()
        self.assertEqual(self.org.name, "Renamed Org")
        self.assertNotEqual(self.org.logo_data, "")

    def test_initials_fall_back_when_there_is_no_logo(self):
        self.assertEqual(Organization(name="Northport Clinic Group").initials, "NCG")
        self.assertEqual(Organization(name="Alpha").initials, "ALP")


class PageRendersTest(TestCase):
    """Every signed-in page actually renders for the role that can reach it.

    Cheap, but it is the only thing that catches a template referring to a
    context variable or url name that no longer exists — a class of breakage
    the view tests walk straight past.
    """

    def setUp(self):
        self.org = make_org(name="Alpha", locations=("North", "South"))
        self.operator = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="OPR1", given_name="Ada", last_name="Reyes")
        self.org_admin = User.objects.create(
            national_id_card_number="5555666677778888",
            digital_national_id="ADM1", given_name="Ben", last_name="Cruz")
        self.site_admin = User.objects.create(
            national_id_card_number="9999888877776666",
            digital_national_id="SITE1", given_name="Sam", last_name="Diaz",
            is_site_admin=True)
        join(self.org, self.operator)
        join(self.org, self.org_admin, Membership.ROLE_ADMIN)

    def _as(self, user, org=None):
        session = self.client.session
        session[SESSION_KEY] = user.id
        session[ORG_SESSION_KEY] = (org or self.org).id
        session["operator_location"] = str(self.org.locations.first().id)
        session.save()

    def _renders(self, url, template):
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, url)
        self.assertIn(template, [t.name for t in response.templates], url)
        return response

    def test_operator_pages(self):
        self._as(self.operator)
        self._renders("/app/", "app.html")
        self._renders("/validate/", "validate.html")
        self._renders("/app/setup/", "setup.html")

    def test_operator_does_not_see_admin_navigation(self):
        self._as(self.operator)
        body = self._renders("/app/", "app.html").content.decode()
        self.assertNotIn('href="/app/admin/"', body)
        self.assertNotIn('href="/app/site/"', body)

    def test_org_admin_pages(self):
        self._as(self.org_admin)
        body = self._renders("/app/", "app.html").content.decode()
        self.assertIn('href="/app/admin/"', body)
        self.assertNotIn('href="/app/site/"', body)
        self._renders("/app/admin/", "app_admin.html")

    def test_site_admin_pages(self):
        self._as(self.site_admin)
        body = self._renders("/app/", "app.html").content.decode()
        self.assertIn('href="/app/site/"', body)
        self._renders("/app/site/", "site_admin.html")
        self._renders(f"/app/site/organizations/{self.org.id}/",
                      "site_organization.html")

    def test_the_chooser_renders_with_several_organizations(self):
        join(make_org(name="Beta"), self.operator)
        self._as(self.operator)
        body = self._renders("/choose/", "choose.html").content.decode()
        self.assertIn("Alpha", body)
        self.assertIn("Beta", body)
        self.assertIn("North", body)

    def test_the_chooser_rows_out_specify_the_base_button_style(self):
        """base.html styles every button inside a .card as a primary button:
        blue background, white text, specificity (0,1,1). A bare `.pick` rule
        is (0,1,0) and loses the colour while winning the background, which
        would render the selected row as white text on #f5f9fd -- 1.06:1.

        Pinning the selector is crude, but it is the rule that matters.
        """
        join(make_org(name="Beta"), self.operator)
        self._as(self.operator)
        css = self._renders("/choose/", "choose.html").content.decode()
        self.assertIn("button.pick.selected", css)
        self.assertNotIn("\n    .pick {", css, "unscoped .pick rule is back")
        # The selected row must set its own colour, not inherit `white`.
        self.assertRegex(css, r"button\.pick\.selected\s*\{[^}]*color:")

    def test_the_banner_shows_the_organization(self):
        self._as(self.operator)
        body = self._renders("/app/", "app.html").content.decode()
        self.assertIn("Alpha", body)
        # No logo uploaded, so the initials mark stands in.
        self.assertIn("org-mark", body)

    def test_the_context_strip_appears_only_when_there_is_a_choice(self):
        self._as(self.operator)
        self.assertIn("Verifying at", self._renders("/app/", "app.html").content.decode())

        # One location: nothing to change, so the strip stays off the page.
        self.org.locations.filter(name="South").delete()
        self.assertNotIn("Verifying at",
                         self._renders("/app/", "app.html").content.decode())

    def test_an_organization_without_credentials_says_so_on_the_verify_page(self):
        self.org.everify_client_id = ""
        self.org.everify_client_secret = ""
        self.org.save()
        self._as(self.operator)
        self.assertContains(self.client.get("/app/"), "no eVerify credentials yet")

    def test_the_login_page_no_longer_asks_for_a_location(self):
        body = self.client.get("/").content.decode()
        self.assertNotIn("Operator Location", body)
        self.assertNotIn("location-search", body)

    def test_the_printed_document_carries_the_organization(self):
        self._as(self.operator)
        keep_answer(self.client, self.org, [
            {"key": "Given Name", "value": "Juan"},
            {"key": "National ID Card Number", "value": "1111222233334444"},
        ])
        self.assertContains(self.client.get("/app/document/"), "Alpha")


@override_settings(EVERIFY_ALLOWED_HOSTS=TEST_EVERIFY_HOSTS)
class CopyCredentialsTest(TestCase):
    """A site admin can put one organization's eVerify client onto another.

    The request carries only the source organization's ID. The secret and the
    public key are write-only and never rendered into a page, so a copy that
    worked by filling in the form field would have to send them to a browser
    -- which is exactly what this endpoint exists to avoid.
    """

    def setUp(self):
        self.site_admin = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="SITE1", given_name="Sam", is_site_admin=True)
        self.org_admin = User.objects.create(
            national_id_card_number="5555666677778888",
            digital_national_id="ADM1", given_name="Ada")

        self.source = make_org(name="Source",
                               everify_base_url="https://src.example/api",
                               everify_client_id="src-id",
                               everify_client_secret="src-secret",
                               everify_public_api_key="src-key")
        self.target = make_org(name="Target", everify_client_id="",
                               everify_client_secret="",
                               everify_public_api_key="")
        join(self.target, self.org_admin, Membership.ROLE_ADMIN)

    def _as(self, user, org=None):
        session = self.client.session
        session[SESSION_KEY] = user.id
        if org:
            session[ORG_SESSION_KEY] = org.id
        session.save()

    def _copy(self, target, source_id):
        return self.client.post(
            f"/app/site/organizations/{target.id}/copy-credentials/",
            data=json.dumps({"source_id": source_id}),
            content_type="application/json")

    def test_site_admin_copies_all_four_fields(self):
        self._as(self.site_admin)
        self.assertFalse(self.target.everify_configured)

        response = self._copy(self.target, self.source.id)
        self.assertEqual(response.status_code, 200)
        self.target.refresh_from_db()
        self.assertEqual(self.target.everify_base_url, "https://src.example/api")
        self.assertEqual(self.target.everify_client_id, "src-id")
        self.assertEqual(self.target.everify_client_secret, "src-secret")
        self.assertEqual(self.target.everify_public_api_key, "src-key")
        self.assertTrue(self.target.everify_configured)

    def test_the_source_is_left_alone(self):
        self._as(self.site_admin)
        self._copy(self.target, self.source.id)
        self.source.refresh_from_db()
        self.assertEqual(self.source.everify_client_secret, "src-secret")
        self.assertEqual(self.source.name, "Source")

    def test_nothing_else_about_the_target_is_touched(self):
        self.target.subtitle = "Keep me"
        self.target.mark_color = "#123456"
        self.target.save()
        self._as(self.site_admin)
        self._copy(self.target, self.source.id)
        self.target.refresh_from_db()
        self.assertEqual(self.target.subtitle, "Keep me")
        self.assertEqual(self.target.mark_color, "#123456")
        self.assertEqual(self.target.name, "Target")

    def test_the_response_never_carries_the_secret(self):
        """The whole point: secrets stay on the server."""
        self._as(self.site_admin)
        body = self._copy(self.target, self.source.id).content.decode()
        self.assertNotIn("src-secret", body)
        self.assertNotIn("src-key", body)

    def test_the_page_never_renders_a_secret_either(self):
        self._as(self.site_admin)
        self._copy(self.target, self.source.id)
        page = self.client.get(
            f"/app/site/organizations/{self.target.id}/").content.decode()
        self.assertNotIn("src-secret", page)
        self.assertNotIn("src-key", page)
        # The source is offered by name and id only.
        self.assertIn("Source", page)

    def test_an_org_admin_cannot_copy_credentials(self):
        """Even for the organization they administer -- this reaches across
        organizations, which is a site-admin capability."""
        self._as(self.org_admin, self.target)
        response = self._copy(self.target, self.source.id)
        self.assertEqual(response.status_code, 403)
        self.target.refresh_from_db()
        self.assertEqual(self.target.everify_client_id, "")

    def test_a_signed_out_caller_cannot_copy_credentials(self):
        response = self._copy(self.target, self.source.id)
        self.assertEqual(response.status_code, 403)
        self.target.refresh_from_db()
        self.assertEqual(self.target.everify_client_id, "")

    def test_copying_from_an_unconfigured_organization_is_refused(self):
        """Otherwise it would silently blank a working client."""
        blank = make_org(name="Blank", everify_client_id="",
                         everify_client_secret="")
        self.target.everify_client_id = "keep-id"
        self.target.everify_client_secret = "keep-secret"
        self.target.save()
        self._as(self.site_admin)
        response = self._copy(self.target, blank.id)
        self.assertEqual(response.status_code, 400)
        self.target.refresh_from_db()
        self.assertEqual(self.target.everify_client_secret, "keep-secret")

    def test_copying_onto_itself_is_refused(self):
        self._as(self.site_admin)
        response = self._copy(self.source, self.source.id)
        self.assertEqual(response.status_code, 400)

    def test_an_unknown_source_is_refused(self):
        self._as(self.site_admin)
        self.assertEqual(self._copy(self.target, 999999).status_code, 404)
        self.target.refresh_from_db()
        self.assertEqual(self.target.everify_client_id, "")

    def test_get_is_not_allowed(self):
        self._as(self.site_admin)
        response = self.client.get(
            f"/app/site/organizations/{self.target.id}/copy-credentials/")
        self.assertEqual(response.status_code, 405)

    def test_only_configured_organizations_are_offered_as_sources(self):
        make_org(name="Unconfigured", everify_client_id="",
                 everify_client_secret="")
        self._as(self.site_admin)
        response = self.client.get(f"/app/site/organizations/{self.target.id}/")
        names = [org.name for org in response.context["credential_sources"]]
        self.assertIn("Source", names)
        self.assertNotIn("Unconfigured", names)
        self.assertNotIn("Target", names, "an organization is not its own source")

    def test_both_organizations_verify_against_the_copied_client(self):
        """The point of copying, and the thing worth being deliberate about:
        their usage now bills together."""
        self._as(self.site_admin)
        self._copy(self.target, self.source.id)
        self.target.refresh_from_db()
        self.assertEqual(self.target.everify_client_id,
                         self.source.everify_client_id)


class TemplateJavaScriptTest(TestCase):
    """Every inline <script> in every template must parse.

    Not a full JS parser -- it catches one specific mistake: a string literal
    that runs off the end of a line. JS has no implicit line continuation
    inside a string, so that is a syntax error, and it disables every handler
    in the block rather than just the statement it appears in: a page whose
    buttons are all silently dead.
    """

    def test_no_unterminated_string_literals(self):
        import glob
        import io
        import os

        from accounts.js_lint import script_blocks, unterminated

        problems = []
        templates = glob.glob(
            os.path.join(settings.BASE_DIR, 'templates', '**', '*.html'),
            recursive=True)
        self.assertTrue(templates, "no templates found to scan")

        for path in sorted(templates):
            src = io.open(path, encoding='utf-8').read()
            for first_line, js in script_blocks(src):
                for line_no, text in unterminated(js, first_line):
                    problems.append('%s:%d  %s'
                                    % (os.path.basename(path), line_no, text))

        self.assertEqual(problems, [], 'unterminated JS string literal(s):\n'
                                       + '\n'.join(problems))

    def test_no_django_comment_spans_more_than_one_line(self):
        """`{# #}` is single-line only: the parser does not close it across a
        newline, so a multi-line one renders to the page as visible text.

        A multi-line note in the nav would appear in the header of every
        signed-in page, and one in the document would print onto the
        verification document. Nothing errors, which is why it needs a test.
        Use {% comment %}...{% endcomment %} for anything over one line.
        """
        import glob
        import io
        import os

        from accounts.js_lint import multiline_django_comments

        problems = []
        templates = glob.glob(
            os.path.join(settings.BASE_DIR, 'templates', '**', '*.html'),
            recursive=True)
        self.assertTrue(templates, "no templates found to scan")

        for path in sorted(templates):
            src = io.open(path, encoding='utf-8').read()
            for line_no, text in multiline_django_comments(src):
                problems.append('%s:%d  %s'
                                % (os.path.basename(path), line_no, text))

        self.assertEqual(
            problems, [],
            "multi-line Django comment(s) -- these render to the page as "
            "visible text: " + "; ".join(problems))

    def test_static_scripts_have_no_unterminated_string_literals(self):
        """The same scan over static/*.js. A break in one of these takes out
        every handler in the file without a sound."""
        import glob
        import io
        import os

        from accounts.js_lint import unterminated

        problems = []
        scripts = [path for path
                   in glob.glob(os.path.join(settings.BASE_DIR, 'static', '*.js'))
                   if not path.endswith('.min.js')]
        self.assertTrue(scripts, "no static scripts found to scan")

        for path in sorted(scripts):
            src = io.open(path, encoding='utf-8').read()
            for line_no, text in unterminated(src, 1):
                problems.append('%s:%d  %s'
                                % (os.path.basename(path), line_no, text))

        self.assertEqual(problems, [], 'unterminated JS string literal(s):\n'
                                       + '\n'.join(problems))


class FingerprintSettingsTest(TestCase):
    """The reader belongs to (operator, organization), not to the operator.

    Somebody who works at two organizations sits at two workstations with two
    readers. One row per user meant switching organization silently carried
    the wrong endpoint and serial across.
    """

    BASE = {"fingerprint_auth_endpoint": "", "serial_number": "0"}

    def setUp(self):
        self.operator = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="OPR1", given_name="Ada")
        self.alpha = make_org(name="Alpha")
        self.beta = make_org(name="Beta", locations=("Beta Desk",))
        join(self.alpha, self.operator)
        join(self.beta, self.operator)

    def _as(self, org):
        session = self.client.session
        session[SESSION_KEY] = self.operator.id
        session[ORG_SESSION_KEY] = org.id
        session.save()

    def _save(self, endpoint, serial):
        return self.client.post("/app/setup/", {
            "fingerprint_auth_endpoint": endpoint, "serial_number": serial})

    def test_each_organization_keeps_its_own_reader(self):
        self._as(self.alpha)
        self._save("http://127.0.0.1:4501/capture", "AAA-111")
        self._as(self.beta)
        self._save("http://127.0.0.1:9999/capture", "BBB-222")

        alpha = FingerprintSettings.objects.get(user=self.operator,
                                                organization=self.alpha)
        beta = FingerprintSettings.objects.get(user=self.operator,
                                               organization=self.beta)
        self.assertEqual(alpha.serial_number, "AAA-111")
        self.assertEqual(alpha.auth_endpoint, "http://127.0.0.1:4501/capture")
        self.assertEqual(beta.serial_number, "BBB-222")
        self.assertEqual(beta.auth_endpoint, "http://127.0.0.1:9999/capture")

    def test_setup_shows_the_reader_for_the_current_organization(self):
        FingerprintSettings.objects.create(
            user=self.operator, organization=self.alpha,
            auth_endpoint="http://alpha.local/capture", serial_number="AAA-111")
        FingerprintSettings.objects.create(
            user=self.operator, organization=self.beta,
            auth_endpoint="http://beta.local/capture", serial_number="BBB-222")

        self._as(self.alpha)
        body = self.client.get("/app/setup/").content.decode()
        self.assertIn("AAA-111", body)
        self.assertNotIn("BBB-222", body)

        self._as(self.beta)
        body = self.client.get("/app/setup/").content.decode()
        self.assertIn("BBB-222", body)
        self.assertNotIn("AAA-111", body)

    def test_two_operators_at_one_organization_are_separate(self):
        other = User.objects.create(national_id_card_number="5555666677778888")
        join(self.alpha, other)
        self._as(self.alpha)
        self._save("http://ada.local/capture", "ADA-1")

        session = self.client.session
        session[SESSION_KEY] = other.id
        session[ORG_SESSION_KEY] = self.alpha.id
        session.save()
        body = self.client.get("/app/setup/").content.decode()
        self.assertNotIn("ADA-1", body)

    def test_verify_page_offers_the_button_only_where_a_reader_is_set(self):
        FingerprintSettings.objects.create(
            user=self.operator, organization=self.alpha, serial_number="AAA-111")
        # The id also appears in the page's JS, so assert on the markup.
        self._as(self.alpha)
        self.assertContains(self.client.get("/app/"), 'id="start-fingerprint-btn"')

        # Beta has no reader at all.
        self._as(self.beta)
        self.assertNotContains(self.client.get("/app/"), 'id="start-fingerprint-btn"')

    def test_a_serial_of_zero_is_not_a_reader(self):
        """"0" is how "no reader" has always been spelled here."""
        FingerprintSettings.objects.create(
            user=self.operator, organization=self.alpha, serial_number="0")
        self._as(self.alpha)
        self.assertNotContains(self.client.get("/app/"), 'id="start-fingerprint-btn"')

    def test_saving_one_organization_does_not_touch_the_other(self):
        self._as(self.alpha)
        self._save("http://alpha.local/capture", "AAA-111")
        self._as(self.beta)
        self._save("http://beta.local/capture", "BBB-222")
        self._as(self.alpha)
        self._save("http://alpha.local/capture", "AAA-999")

        beta = FingerprintSettings.objects.get(user=self.operator,
                                               organization=self.beta)
        self.assertEqual(beta.serial_number, "BBB-222")
        self.assertEqual(
            FingerprintSettings.objects.filter(user=self.operator).count(), 2)

    def test_demo_mode_stays_per_operator(self):
        """It is a property of the person presenting, not of the desk."""
        self._as(self.alpha)
        self.client.post("/app/setup/", dict(self.BASE, demo_mode="on"))
        self.assertTrue(UserSettings.objects.get(user=self.operator).demo_mode)

        self._as(self.beta)
        self.assertTrue(UserSettings.objects.get(user=self.operator).demo_mode)
        self.assertEqual(UserSettings.objects.filter(user=self.operator).count(), 1)

    def test_an_invalid_endpoint_is_refused_and_saves_nothing(self):
        self._as(self.alpha)
        response = self._save("not-a-url", "AAA-111")
        self.assertContains(response, "must be a valid URL")
        self.assertFalse(FingerprintSettings.objects.filter(
            user=self.operator, organization=self.alpha).exists())

    def test_a_reader_row_is_not_created_just_by_viewing_setup(self):
        """A write on a read path; document() already avoids the same thing."""
        self._as(self.alpha)
        self.client.get("/app/setup/")
        self.assertFalse(FingerprintSettings.objects.filter(
            user=self.operator).exists())

    def test_a_site_admin_with_no_organization_sees_a_note_instead(self):
        admin = User.objects.create(national_id_card_number="9999888877776666",
                                    is_site_admin=True)
        self.alpha.is_active = False
        self.alpha.save()
        self.beta.is_active = False
        self.beta.save()
        session = self.client.session
        session[SESSION_KEY] = admin.id
        session.save()
        response = self.client.get("/app/setup/")
        self.assertContains(response, "Choose an organization first")


@override_settings(EVERIFY_DECOY_DELAY_SECONDS=(0, 0))
@override_settings(EVERIFY_ALLOWED_HOSTS=TEST_EVERIFY_HOSTS)
class LoginGateTest(TestCase):
    """A National ID that names no registered operator never reaches eVerify.

    It could never sign anybody in -- `_login_user_from_everify()` gives up
    when `_find_user()` misses -- but the lookup would still spend a query
    against the site's client on the way to that conclusion, which anyone
    who could reach the login page could do.

    These tests pin the two halves of the answer: eVerify is not called, and
    the caller cannot tell that from the reply. They do NOT pin the disguise
    against somebody reading the network tab, which it does not survive; see
    verify/views/login_guard.py.
    """

    PNG = ("data:image/png;base64,"
           "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")

    def setUp(self):
        self.operator = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="OPR1234", given_name="Ada")
        site = SiteSettings.load()
        site.everify_base_url = "https://site.example/api"
        site.everify_client_id = "site-id"
        site.everify_client_secret = "site-secret"
        site.everify_public_api_key = "site-key"
        site.save()

    # -- helpers -----------------------------------------------------------

    def _upstream(self, calls, payload=None):
        def post(url, json=None, headers=None, timeout=None, **kwargs):
            calls.append(url)
            response = MagicMock(status_code=200)
            if url.endswith("/auth"):
                response.json.return_value = {"data": {"access_token": "tok"}}
            else:
                response.json.return_value = {"data": payload if payload is not None
                                              else {"reference": "1111222233334444",
                                                    "code": "OPR1234"}}
            return response
        return post

    def _sign_in_attempt(self, value, upstream=None, **extra):
        """POST /everify/ signed out. Returns (response, upstream urls called)."""
        body = {"value": value, "face_liveness_session_id": "sess"}
        body.update(extra)
        calls = []
        with patch("verify.views.everify.requests.post",
                   side_effect=self._upstream(calls, upstream)):
            response = self.client.post("/everify/", data=json.dumps(body),
                                        content_type="application/json")
        return response, calls

    # -- the gate ----------------------------------------------------------

    def test_an_unregistered_id_never_reaches_everify(self):
        response, calls = self._sign_in_attempt("9999888877776666")
        self.assertEqual(calls, [], "spent an eVerify call on a stranger")
        self.assertEqual(response.status_code, 404)
        self.assertIsNone(self.client.session.get(SESSION_KEY))

    def test_a_registered_id_still_reaches_everify(self):
        """The half that matters more. A gate that refuses genuine operators
        is not a hardening, it is an outage."""
        response, calls = self._sign_in_attempt("1111222233334444")
        self.assertTrue(calls, "refused a registered operator")
        self.assertEqual(self.client.session.get(SESSION_KEY), self.operator.id)

    def test_either_of_the_two_id_numbers_gets_through(self):
        _, calls = self._sign_in_attempt("OPR1234")
        self.assertTrue(calls, "refused the digital ID of a registered operator")

    def test_punctuation_and_case_do_not_refuse_an_operator(self):
        """The form takes 1111-2222-3333-4444 and opr1234; Users holds neither
        spelling. Comparing without normalising locks people out for a dash."""
        _, calls = self._sign_in_attempt("1111-2222-3333-4444")
        self.assertTrue(calls, "refused a punctuated card number")
        self.client.session.flush()
        _, calls = self._sign_in_attempt("opr1234")
        self.assertTrue(calls, "refused a lower-case digital ID")

    def test_a_card_only_member_typing_their_digital_id_is_refused(self):
        """The one real cost of this gate, pinned so it stays visible.

        A member added by card number alone, who has never signed in and so
        has had nothing backfilled, is refused if they sign in with the
        digital ID printed on the same card. eVerify would have mapped one to
        the other, and we are no longer asking it.

        The fix is an admin adding that digital ID to the member -- which the
        logged attempt tells them to do. Do NOT 'fix' this by widening the
        gate to something that matches on less; that is how it stops being a
        gate.
        """
        User.objects.create(national_id_card_number="5555444433332222")
        response, calls = self._sign_in_attempt("NEW9999")
        self.assertEqual(calls, [])
        self.assertEqual(response.status_code, 404)
        self.assertEqual(LoginAttempt.objects.get().submitted_id, "NEW9999")

    def test_the_refusal_is_word_for_word_a_genuine_miss(self):
        """Same status and same body as eVerify answering 200 with nobody in
        it. If these ever drift apart the refusal announces itself."""
        genuine, calls = self._sign_in_attempt("1111222233334444", upstream={})
        self.assertTrue(calls)
        refused, _ = self._sign_in_attempt("9999888877776666")
        self.assertEqual(refused.status_code, genuine.status_code)
        self.assertEqual(refused.content, genuine.content)
        self.assertEqual(json.loads(refused.content)["message"], NO_MATCH_MESSAGE)

    def test_the_gate_does_not_apply_to_a_signed_in_operator(self):
        """A citizen at the counter is not, and must never need to be, a
        registered user of this app."""
        org = make_org()
        join(org, self.operator)
        session = self.client.session
        session[SESSION_KEY] = self.operator.id
        session[ORG_SESSION_KEY] = org.id
        session.save()
        _, calls = self._sign_in_attempt("9999888877776666")
        self.assertTrue(calls, "refused to verify a member of the public")

    def test_the_credentials_check_does_not_leak_past_the_gate(self):
        """Refused ahead of the credentials check, so the answer does not vary
        with how the site happens to be configured."""
        site = SiteSettings.load()
        site.everify_client_id = ""
        site.everify_client_secret = ""
        site.save()
        with patch("verify.views.everify.EVERIFY_CLIENT_ID", ""), \
             patch("verify.views.everify.EVERIFY_CLIENT_SECRET", ""):
            response, calls = self._sign_in_attempt("9999888877776666")
        self.assertEqual(calls, [])
        self.assertEqual(response.status_code, 404)
        self.assertEqual(json.loads(response.content)["message"], NO_MATCH_MESSAGE)

    # -- what gets written -------------------------------------------------

    def test_the_attempt_is_logged_with_the_id(self):
        self._sign_in_attempt("9999-8888-7777-6666",
                              HTTP_USER_AGENT="probe/1.0")
        attempt = LoginAttempt.objects.get()
        self.assertEqual(attempt.submitted_id, "9999888877776666")
        self.assertEqual(attempt.id_kind, LoginAttempt.KIND_CARD)
        self.assertEqual(attempt.photo_data, "")

    def test_the_captured_face_is_stored_with_it(self):
        self._sign_in_attempt("9999888877776666", login_photo=self.PNG)
        attempt = LoginAttempt.objects.get()
        self.assertEqual(attempt.photo_data, self.PNG)
        self.assertTrue(attempt.has_photo)

    def test_bare_base64_from_the_iframe_is_stored(self):
        """The iframe posts {photo, session_id, photo_url}; `photo` is not
        guaranteed to carry a data: prefix, so both forms are accepted."""
        bare = self.PNG.split(",", 1)[1]
        self._sign_in_attempt("9999888877776666", login_photo=bare)
        self.assertEqual(LoginAttempt.objects.get().photo_data, self.PNG)

    def test_the_declared_type_is_ignored_in_favour_of_the_bytes(self):
        """A JPEG announced as a PNG is stored as a JPEG. The label arrives in
        an unauthenticated request body and is simply not read."""
        jpeg = bytes.fromhex("ffd8ff") + b"body"
        mislabelled = ("data:image/png;base64,"
                       + base64.b64encode(jpeg).decode())
        self._sign_in_attempt("9999888877776666", login_photo=mislabelled)
        self.assertTrue(LoginAttempt.objects.get().photo_data.startswith(
            "data:image/jpeg;base64,"))

    def test_something_that_is_not_an_image_is_not_stored(self):
        lie = "data:image/png;base64,SGVsbG8gd29ybGQsIG5vdCBhbiBpbWFnZQ=="
        self._sign_in_attempt("9999888877776666", login_photo=lie)
        self.assertEqual(LoginAttempt.objects.get().photo_data, "")

    def test_an_svg_face_is_refused(self):
        svg = ("data:image/svg+xml;base64,"
               + base64.b64encode(b"<svg onload='alert(1)'/>").decode())
        self._sign_in_attempt("9999888877776666", login_photo=svg)
        self.assertEqual(LoginAttempt.objects.get().photo_data, "")

    def test_an_oversized_photo_is_refused(self):
        huge = ("data:image/jpeg;base64,"
                + base64.b64encode(b"\xff\xd8\xff" + b"x" * (login_guard.MAX_PHOTO_BYTES + 1)).decode())
        self._sign_in_attempt("9999888877776666", login_photo=huge)
        self.assertEqual(LoginAttempt.objects.get().photo_data, "")

    def test_a_photo_that_is_not_a_data_uri_at_all_is_refused(self):
        self._sign_in_attempt("9999888877776666",
                              login_photo="https://example.com/face.jpg")
        self.assertEqual(LoginAttempt.objects.get().photo_data, "")

    def test_a_registered_operator_is_not_logged_as_an_attempt(self):
        """This table is 'people who are not us tried to get in'. An
        operator's own sign-in does not belong in it, face or no face."""
        self._sign_in_attempt("1111222233334444")
        self.assertEqual(LoginAttempt.objects.count(), 0)

    def test_a_refused_attempt_is_not_a_transaction(self):
        """Transactions are an organization's verification log. A stranger at
        the login page has no organization, and must not appear in one."""
        self._sign_in_attempt("9999888877776666")
        self.assertEqual(Transaction.objects.count(), 0)
        self.assertEqual(LoginAttempt.objects.count(), 1)

    # -- no plan, and no branch ---------------------------------------------

    def test_the_login_page_runs_the_real_sdk_for_everyone(self):
        """The check the operator sees must be the real one whoever they are.

        An imitation cannot be made identical -- the spacing, the buttons and
        the camera handling would differ, and every one of those differences
        would tell the operator whether the ID they typed was registered. The
        site holds a valid public key, so it can simply run the genuine SDK,
        and then there is nothing left to match.
        """
        page = self.client.get("/").content.decode()
        self.assertIn("everify-liveness-sdk.min.js", page)
        self.assertIn("eKYC().start", page)

    def test_the_page_makes_no_decision_about_which_check_to_run(self):
        """The absence of a branch IS the feature. Anything that let the
        client know which check to run -- a mode in a response, a second
        script, a conditional -- would be the oracle in another form."""
        page = self.client.get("/").content.decode()
        for tell in ("login-plan", "LivenessCapture", "liveness-capture.js",
                     "'capture'", "plan.mode"):
            self.assertNotIn(tell, page,
                             "the login page branches on whether the ID is "
                             "registered: " + tell)

    def test_there_is_no_endpoint_that_says_which_check_to_run(self):
        self.assertEqual(
            self.client.post("/everify/login-plan/",
                             data=json.dumps({"value": "1111222233334444"}),
                             content_type="application/json").status_code, 404)
        with self.assertRaises(NoReverseMatch):
            reverse("everify_login_plan")

    def test_the_imitation_is_not_shipped_any_more(self):
        import os
        for path in ("static/liveness-capture.js", "static/liveness"):
            self.assertFalse(
                os.path.exists(os.path.join(settings.BASE_DIR, path)),
                path + " is back; the real SDK is what both paths run")

    # -- the wait ----------------------------------------------------------

    @override_settings(EVERIFY_DECOY_DELAY_SECONDS=(2.0, 5.0))
    def test_a_refusal_waits_as_long_as_a_lookup_would(self):
        with patch("verify.views.login_guard.time.sleep") as slept:
            self._sign_in_attempt("9999888877776666")
        self.assertEqual(slept.call_count, 1, "answered a stranger instantly")
        waited = slept.call_args[0][0]
        self.assertGreater(waited, 0)
        self.assertLessEqual(waited, 5.0)

    @override_settings(EVERIFY_DECOY_DELAY_SECONDS=(2.0, 5.0))
    def test_the_wait_is_anchored_to_the_start_not_added_on_top(self):
        """Storing a 40 KB capture is not free. Sleeping a flat interval after
        that work would leave the difference readable in the total."""
        import time as real_time
        with patch("verify.views.login_guard.time.sleep") as slept:
            login_guard.sleep_to_match(real_time.monotonic() - 10)
        self.assertEqual(slept.call_count, 0, "slept past a target already met")

    @override_settings(EVERIFY_DECOY_DELAY_SECONDS=(0, 0))
    def test_the_wait_can_be_switched_off(self):
        with patch("verify.views.login_guard.time.sleep") as slept:
            self._sign_in_attempt("9999888877776666")
        self.assertEqual(slept.call_count, 0)

    # -- the page ----------------------------------------------------------

    def test_the_photo_rides_every_attempt_not_just_refused_ones(self):
        """The liveness iframe posts the capture up to the parent, and the page
        forwards it whatever the ID turns out to be. Sending it selectively
        would tell the caller which case they were in."""
        page = self.client.get("/").content.decode()
        self.assertIn("login_photo", page)
        self.assertIn("resultField(liveness, 'photo')", page)


def _verify_js():
    """The shared static source both ID-masking pages wire into."""
    return (settings.BASE_DIR / "static" / "verify.js").read_text(
        encoding="utf-8")


class LoginIdMaskingTest(TestCase):
    """The typed National ID is masked on the login page, and only the
    operator pressing Show ID reveals it.

    The login form faces whoever is near it -- a queue, an audience, a
    projector -- and what is typed there is the same identifier Demo Mode
    redacts on every signed-in page. The masking is type="password", the
    platform's own, rather than a style that could quietly fail to apply
    and leave the ID readable. The flip and the echo mask live in
    verify.js, shared with the Verify page (VerifyPageIdMaskingTest).
    """

    def _page(self):
        return self.client.get("/").content.decode()

    def test_the_id_field_is_masked_by_default(self):
        self.assertIn('<input type="password" id="pcn-input"', self._page())

    def test_the_id_stays_out_of_autofill(self):
        """A password field remembered by the browser on a shared operator
        machine would offer one person's National ID to the next."""
        self.assertIn('id="pcn-input" placeholder="" autocomplete="off"',
                      self._page())

    def test_show_id_actually_flips_the_field(self):
        """Assert the lines that do the work: a button named Show ID over a
        handler that flips nothing has satisfied name-only assertions in
        this suite before. The flip lives in verify.js, shared with the
        Verify page -- so the page is asserted to WIRE it, with its
        arguments, and the shared source to actually flip."""
        page = self._page()
        self.assertIn('id="toggle-id-btn"', page)
        self.assertIn("Verify.idMaskToggle(input, "
                      "document.getElementById('toggle-id-btn'))", page)
        shared = _verify_js()
        self.assertIn("input.type = reveal ? 'text' : 'password'", shared)
        self.assertIn(
            "button.textContent = reveal ? 'Hide ID' : 'Show ID'", shared)

    def test_the_qr_echo_does_not_undo_the_mask(self):
        """The three scan paths must not print the whole scanned ID into the
        result box beside the field, which would put in the clear what the
        mask hides. The echo follows mask_identifier's convention: a bullet
        run of deliberately wrong length, last character kept."""
        page = self._page()
        self.assertNotIn("'QR scanned: ' + id.toUpperCase()", page)
        self.assertIn("'QR scanned: ' + Verify.maskId(id)", page)
        self.assertIn("'•••••' + s.charAt(s.length - 1)", _verify_js())


class VerifyPageIdMaskingTest(TestCase):
    """The Verify page's manual-entry ID is masked like the login page's,
    and its QR scan is echoed masked.

    Same field, same convention, one implementation: base.html holds the
    .masked-id styles and verify.js the flip and the echo mask, so the
    two pages cannot drift apart. The outcome screen's "what was searched
    for" rows are deliberately untouched -- that screen exists so an
    operator can find the typo in what they sent.
    """

    def setUp(self):
        self.user = User.objects.create(
            national_id_card_number="1212343456567878",
            given_name="MARIA", last_name="DELA CRUZ")
        self.org = make_org("Mask Org")
        join(self.org, self.user, Membership.ROLE_OPERATOR)
        session = self.client.session
        session[SESSION_KEY] = self.user.id
        session[ORG_SESSION_KEY] = self.org.id
        session.save()

    def _page(self):
        response = self.client.get(reverse("app"))
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    def test_the_id_field_is_masked_by_default(self):
        page = self._page()
        self.assertIn('<input type="password" id="pcn-input"', page)
        self.assertIn('id="pcn-input" placeholder="e.g., 1234-5678-9012-3456" '
                      'autocomplete="off"', page)

    def test_show_id_is_wired_to_the_shared_flip(self):
        """Assert the call with its arguments -- a guard standing over a
        body that wires nothing has satisfied name-only assertions in this
        suite before -- and that the shared source is on the page at all,
        because the wiring is dead without it."""
        page = self._page()
        self.assertIn('id="toggle-id-btn"', page)
        self.assertIn("Verify.idMaskToggle(pcnInput, "
                      "document.getElementById('toggle-id-btn'))", page)
        self.assertIn("verify.js", page)

    def test_the_scan_echo_does_not_undo_the_mask(self):
        """The camera scan's status line echoes the decoded ID masked, as the
        field beside it is, and never the whole ID through innerHTML."""
        page = self._page()
        self.assertNotIn("ID: ' + id.toUpperCase()", page)
        self.assertIn("ID: ' + Verify.maskId(id)", page)


class LivenessFrameChromeTest(TestCase):
    """Neither page forces geometry onto the liveness SDK's frame.

    The SDK's own chrome is already a consistent full screen -- overlay
    inset 0, iframe border 0 flex-filling it. Overrides tuned to another SDK
    build hide the right edge behind the scrollbar and squeeze the camera
    from the bottom, and a close-button matcher looking for 'X' or 'Cancel'
    stops firing, silently, when a build labels it '×'.
    Each page carries its own copy, so each is pinned."""

    GEOMETRY_TELLS = ("iframe.style.width", "iframe.style.height",
                      "iframe.style.paddingBottom", "iframe.style.border",
                      "iframe.style.position", "iframeOverlay.style.width")

    def _assert_frame_left_alone(self, page):
        for tell in self.GEOMETRY_TELLS:
            self.assertNotIn(tell, page,
                             "the page forces geometry onto the SDK's "
                             "frame again: " + tell)
        self.assertIn("['X', '×', 'Cancel']", page,
                      "the close-button matcher no longer recognises the "
                      "current SDK build's ×")

    def test_the_login_page_leaves_the_frame_alone(self):
        self._assert_frame_left_alone(self.client.get("/").content.decode())

    def test_the_verify_page_leaves_the_frame_alone(self):
        user = User.objects.create(
            national_id_card_number="1212343456567878",
            given_name="MARIA", last_name="DELA CRUZ")
        org = make_org("Frame Org")
        join(org, user, Membership.ROLE_OPERATOR)
        session = self.client.session
        session[SESSION_KEY] = user.id
        session[ORG_SESSION_KEY] = org.id
        session.save()
        self._assert_frame_left_alone(
            self.client.get(reverse("app")).content.decode())


class LivenessZoomHintTest(TestCase):
    """Both camera pages tell the operator to reset browser zoom -- before
    the camera opens, and only at a zoom that will draw lines around it.

    PSA's capture box is a fixed 640x480 CSS px; when display scaling x
    browser zoom puts it on a fractional number of device pixels, the mask
    leaves a 1-px ring of camera image exposed. Measured with REAL browser
    zoom on a 1.95x machine: lines at 80% and 110%, none at 100% and 125%.
    No page-side change removes them -- frame geometry, CSS zoom and a
    scale transform were each tested at 80% -- so the hint is the fix this
    app can make. The rule lives in one place, verify.js.
    """

    HINT = ('<p id="zoom-hint" class="zoom-hint" hidden>For a clean camera '
            'view, reset browser zoom (Ctrl+0).</p>')
    WIRING = "Verify.livenessZoomHint(document.getElementById('zoom-hint'))"

    def _verify_page(self):
        user = User.objects.create(
            national_id_card_number="1212343456567878",
            given_name="MARIA", last_name="DELA CRUZ")
        org = make_org("Zoom Org")
        join(org, user, Membership.ROLE_OPERATOR)
        session = self.client.session
        session[SESSION_KEY] = user.id
        session[ORG_SESSION_KEY] = org.id
        session.save()
        return self.client.get(reverse("app")).content.decode()

    def test_the_login_page_carries_the_hint_hidden_and_wired(self):
        """Hidden in the markup, so a zoom that draws no lines never
        flashes it; the wiring is what shows it, so assert the call."""
        page = self.client.get("/").content.decode()
        self.assertIn(self.HINT, page)
        self.assertIn(self.WIRING, page)

    def test_the_verify_page_carries_the_hint_hidden_and_wired(self):
        page = self._verify_page()
        self.assertIn(self.HINT, page)
        self.assertIn(self.WIRING, page)

    def test_the_hint_sits_under_the_face_camera_button(self):
        """Where the operator is looking when they press it -- not under
        the fingerprint button, which opens no camera."""
        page = self._verify_page()
        button = page.index('id="start-verification-btn"')
        self.assertLess(button, page.index('id="zoom-hint"'))
        self.assertLess(page.index('id="zoom-hint"') - button, 200)

    def test_the_rule_is_the_measured_one_and_follows_zoom_live(self):
        """Assert the lines that do the work: the box's common unit, the
        whole-pixel test with a tolerance for float noise only, the toggle,
        and the resize listener that re-evaluates on Ctrl+/-/0."""
        shared = _verify_js()
        self.assertIn("var LIVENESS_BOX_UNIT_PX = 160;", shared)
        self.assertIn("var units = LIVENESS_BOX_UNIT_PX * "
                      "(window.devicePixelRatio || 1);", shared)
        self.assertIn("return Math.abs(units - Math.round(units)) > 0.01;",
                      shared)
        self.assertIn("function update() { el.hidden = "
                      "!livenessZoomDrawsLines(); }", shared)
        self.assertIn("window.addEventListener('resize', update);", shared)


class PurgeLoginAttemptsTest(TestCase):
    """The refused-sign-in log holds faces, including the odd colleague who
    mistyped their own card number. It has to be possible to age it out."""

    def setUp(self):
        from django.utils import timezone
        self.now = timezone.now()
        for age_days, photo in ((200, "data:image/png;base64,AAA"),
                                (200, ""),
                                (5, "data:image/png;base64,BBB")):
            attempt = LoginAttempt.objects.create(
                submitted_id="9999888877776666", photo_data=photo)
            LoginAttempt.objects.filter(pk=attempt.pk).update(
                created_at=self.now - timezone.timedelta(days=age_days))

    def _run(self, *args):
        from io import StringIO

        from django.core.management import call_command
        out = StringIO()
        call_command("purge_login_attempts", *args, stdout=out, stderr=out)
        return out.getvalue()

    def test_old_attempts_go_and_recent_ones_stay(self):
        self._run("--days", "90")
        self.assertEqual(LoginAttempt.objects.count(), 1)

    def test_photos_only_keeps_the_row_and_drops_the_face(self):
        """The softer option: who tried, with what ID, from where -- without
        keeping a photograph of them."""
        self._run("--days", "90", "--photos-only")
        self.assertEqual(LoginAttempt.objects.count(), 3)
        self.assertEqual(LoginAttempt.objects.exclude(photo_data="").count(), 1)

    def test_a_dry_run_changes_nothing(self):
        output = self._run("--days", "90", "--dry-run")
        self.assertEqual(LoginAttempt.objects.count(), 3)
        self.assertIn("2 attempt(s) to delete", output)

    def test_the_default_window_is_ninety_days(self):
        self._run()
        self.assertEqual(LoginAttempt.objects.count(), 1)


@override_settings(SSO_ALLOWED_ISSUERS=TEST_SSO_ISSUERS)
class DemoModeAdminMaskingTest(TestCase):
    """Demo Mode is for presenting to an audience, and the audience can see
    every page -- not just Verify.

    The administration pages are the ones with real operators on them: their
    names, both their National ID numbers, and the URLs and client IDs the
    site signs in against. Masking the verification result and leaving those
    in the clear would just move the leak one tab across.

    Same three conventions as the Verify page, so an operator only has to
    learn one: a name keeps its first word, an identifier keeps its last
    character, a URL keeps its scheme.
    """

    CARD = "1111222233334444"
    DIGITAL = "OPR7788"

    def setUp(self):
        self.admin = User.objects.create(
            national_id_card_number=self.CARD,
            digital_national_id=self.DIGITAL,
            given_name="Ada", middle_name="Augusta", last_name="Lovelace",
            is_site_admin=True)
        self.org = make_org("Demo Org",
                            everify_base_url="https://org.example/api",
                            everify_client_id="ORGCLIENT9911",
                            everify_client_secret="org-secret")
        join(self.org, self.admin, Membership.ROLE_ADMIN)

        site = SiteSettings.load()
        site.everify_base_url = "https://site.example/api"
        site.everify_client_id = "SITECLIENT4422"
        site.everify_client_secret = "site-secret"
        site.sso_issuer = "https://sso.example/o"
        site.sso_client_id = "SSOCLIENT6633"
        site.sso_client_secret = "sso-secret"
        site.save()

        self.reader = FingerprintSettings.objects.create(
            user=self.admin, organization=self.org,
            auth_endpoint="https://reader.example/capture",
            serial_number="SERIAL5150")

        session = self.client.session
        session[SESSION_KEY] = self.admin.id
        session[ORG_SESSION_KEY] = self.org.id
        session.save()

    def _demo(self, on):
        settings_row, _ = UserSettings.objects.get_or_create(user=self.admin)
        settings_row.demo_mode = on
        settings_row.save()

    def _page(self, url):
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    # -- the operator's own name, top right --------------------------------

    def test_the_corner_name_is_masked_on_every_page(self):
        self._demo(True)
        for url in ("/app/", "/app/setup/", "/app/admin/"):
            page = self._page(url)
            self.assertNotIn("Lovelace", page, "surname shown in the corner of " + url)
            self.assertIn("Ada", page, "the operator should still know it is them")

    def test_the_corner_name_is_whole_when_demo_is_off(self):
        self._demo(False)
        self.assertIn("Ada Lovelace", self._page("/app/"))

    # -- the Organization page ---------------------------------------------

    def test_member_names_and_both_id_numbers_are_masked(self):
        self._demo(True)
        page = self._page("/app/admin/")
        for secret in ("Lovelace", "Augusta", self.DIGITAL,
                       "1111-2222-3333-4444", self.CARD):
            self.assertNotIn(secret, page, "leaked on the Organization page: " + secret)
        self.assertIn(DEMO_MASK_CHAR, page)

    def test_the_card_number_is_not_left_in_the_remove_handler(self):
        """The onclick argument carries it too. Masking only the visible span
        would leave the real number a right-click away."""
        self._demo(True)
        page = self._page("/app/admin/")
        self.assertNotIn("removeUser(%d, '1111-2222-3333-4444')" % self.admin.id, page)

    def test_the_organizations_everify_client_is_masked(self):
        self._demo(True)
        page = self._page("/app/admin/")
        self.assertNotIn("ORGCLIENT9911", page)
        self.assertNotIn("org.example", page)
        self.assertIn("https://", page, "the scheme is kept, as for any URL")

    def test_the_organization_page_is_readable_when_demo_is_off(self):
        self._demo(False)
        page = self._page("/app/admin/")
        self.assertIn("Lovelace", page)
        self.assertIn("ORGCLIENT9911", page)
        self.assertIn("1111-2222-3333-4444", page)

    # -- the Setup page ------------------------------------------------------

    def test_setup_masks_every_url_and_identifier(self):
        self._demo(True)
        page = self._page("/app/setup/")
        for secret in ("sso.example", "SSOCLIENT6633", "site.example",
                       "SITECLIENT4422", "reader.example", "SERIAL5150"):
            self.assertNotIn(secret, page, "leaked on Setup: " + secret)

    def test_setup_masks_the_host_in_the_redirect_uri(self):
        """The hint spells out this deployment's own address."""
        self._demo(True)
        page = self._page("/app/setup/")
        self.assertNotIn("testserver", page)
        self.assertIn("/national-id/callback/", page,
                      "the path is a fleet convention, not a secret")

    def test_setup_is_readable_when_demo_is_off(self):
        self._demo(False)
        page = self._page("/app/setup/")
        for value in ("sso.example", "SSOCLIENT6633", "SITECLIENT4422",
                      "reader.example", "SERIAL5150"):
            self.assertIn(value, page)

    def test_secrets_are_never_rendered_either_way(self):
        """They were already write-only. Demo Mode must not be what is
        keeping them off the page."""
        for demo in (True, False):
            self._demo(demo)
            page = self._page("/app/setup/")
            self.assertNotIn("sso-secret", page)
            self.assertNotIn("site-secret", page)

    def test_the_demo_toggle_itself_is_never_masked(self):
        """Whatever else is redacted, turning it back off has to work."""
        self._demo(True)
        page = self._page("/app/setup/")
        self.assertIn('id="demo_mode"', page)
        response = self.client.post("/app/setup/", {
            "fingerprint_auth_endpoint": self.reader.auth_endpoint,
            "serial_number": self.reader.serial_number,
            "login_mode": SiteSettings.LOGIN_EVERIFY,
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(UserSettings.objects.get(user=self.admin).demo_mode)

    # -- saving while masked must change nothing ---------------------------

    def test_a_masked_value_posted_back_is_not_saved(self):
        """The half that matters. The fields are readonly in the template, but
        that is a courtesy; this is the guard. Writing bullets into the
        sign-in client would take login down for everybody."""
        self._demo(True)
        masked = DEMO_MASK_CHAR * 12
        response = self.client.post("/app/setup/", {
            "demo_mode": "on",
            "fingerprint_auth_endpoint": "https://" + masked,
            "serial_number": masked,
            "login_mode": SiteSettings.LOGIN_EVERIFY,
            "sso_issuer": "https://" + masked,
            "sso_client_id": masked,
            "everify_base_url": "https://" + masked,
            "everify_client_id": masked,
        })
        self.assertEqual(response.status_code, 200)
        # The save must SUCCEED, not merely fail to change anything. Without
        # the guard the bullets reach the URL validators, the form comes back
        # with an error and nothing is written -- which leaves every value
        # below unchanged for entirely the wrong reason. Asserting the save
        # went through is what tells the two apart.
        self.assertEqual(response.context["error"], "")
        self.assertEqual(response.context["message"], "Setup saved.")

        site = SiteSettings.load()
        self.assertEqual(site.everify_client_id, "SITECLIENT4422")
        self.assertEqual(site.everify_base_url, "https://site.example/api")
        self.assertEqual(site.sso_client_id, "SSOCLIENT6633")
        self.assertEqual(site.sso_issuer, "https://sso.example/o")
        self.reader.refresh_from_db()
        self.assertEqual(self.reader.serial_number, "SERIAL5150")
        self.assertEqual(self.reader.auth_endpoint, "https://reader.example/capture")

    def test_a_real_edit_still_saves_with_demo_on(self):
        """The guard keys on the mask character, not on demo mode, so someone
        who genuinely types a new value is not silently ignored."""
        self._demo(True)
        self.client.post("/app/setup/", {
            "demo_mode": "on",
            "fingerprint_auth_endpoint": "https://new.example/capture",
            "serial_number": "NEWSERIAL",
            "login_mode": SiteSettings.LOGIN_EVERIFY,
            "sso_issuer": "https://sso.example/o",
            "sso_client_id": "NEWSSO",
            "everify_base_url": "https://site.example/api",
            "everify_client_id": "NEWCLIENT",
        })
        self.assertEqual(SiteSettings.load().everify_client_id, "NEWCLIENT")
        self.reader.refresh_from_db()
        self.assertEqual(self.reader.serial_number, "NEWSERIAL")

    def test_a_masked_organization_client_is_not_saved(self):
        self._demo(True)
        masked = DEMO_MASK_CHAR * 10
        response = self.client.post(
            "/app/admin/everify/",
            data=json.dumps({"everify_base_url": "https://" + masked,
                             "everify_client_id": masked}),
            content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.org.refresh_from_db()
        self.assertEqual(self.org.everify_client_id, "ORGCLIENT9911")
        self.assertEqual(self.org.everify_base_url, "https://org.example/api")

    # -- the Site page has the same data on it ------------------------------

    def test_the_printed_document_does_not_name_the_operator_in_full(self):
        """The whole document is masked in Demo Mode, so it is not one anybody
        would hand over. Leaving the operator's own surname on it while the
        same name is redacted in the corner of the same session is the
        inconsistency this is all about."""
        self._demo(True)
        keep_answer(self.client, self.org, [
            {"key": "Given Name", "value": "Juan"},
            {"key": "National ID Card Number", "value": "1111222233334444"},
        ])
        page = self.client.get("/app/document/").content.decode()
        self.assertNotIn("Lovelace", page)
        self.assertIn("Ada", page)

    def test_the_site_organization_page_is_masked_too(self):
        """Named for Organization and Setup, but the Site page lists the same
        members and the same client. Masking one and not the other would just
        move the leak one tab across -- and a site admin is exactly who ends
        up presenting."""
        self._demo(True)
        page = self._page("/app/site/organizations/%d/" % self.org.id)
        for secret in ("Lovelace", "1111-2222-3333-4444", self.DIGITAL,
                       "ORGCLIENT9911", "org.example"):
            self.assertNotIn(secret, page, "leaked on the Site page: " + secret)

    def test_the_site_page_shows_a_members_digital_id_when_there_is_one(self):
        """Both numbers, as the organization's own page lists them: the
        digital ID is how many people sign in, and a site admin matching a
        person to a row should not have to go and look it up. A member
        recorded by card number alone gets no empty separator."""
        import re
        card_only = User.objects.create(
            national_id_card_number="5555666677778888",
            given_name="Grace", last_name="Hopper")
        join(self.org, card_only, Membership.ROLE_OPERATOR)
        self._demo(False)
        page = self._page("/app/site/organizations/%d/" % self.org.id)
        ids = dict(re.findall(
            r'data-user="(\d+)">\s*<span class="who">.*?<span class="ids">(.*?)</span>',
            page, re.S))
        self.assertEqual(ids[str(self.admin.id)].split(),
                         ["&middot;", "1111-2222-3333-4444", "&middot;", self.DIGITAL])
        self.assertEqual(ids[str(card_only.id)].split(),
                         ["&middot;", "5555-6666-7777-8888"])

    def test_a_masked_value_is_not_saved_from_the_site_page(self):
        self._demo(True)
        masked = DEMO_MASK_CHAR * 10
        response = self.client.post(
            "/app/site/organizations/%d/" % self.org.id,
            {"name": self.org.name, "is_active": "on",
             "everify_base_url": "https://" + masked,
             "everify_client_id": masked})
        self.assertEqual(response.status_code, 200)
        self.org.refresh_from_db()
        self.assertEqual(self.org.everify_client_id, "ORGCLIENT9911")
        self.assertEqual(self.org.everify_base_url, "https://org.example/api")

    # -- the conventions themselves ----------------------------------------

    def test_the_conventions_match_the_verify_page(self):
        from verify.views.helpers import mask_identifier, mask_name, mask_url
        self.assertTrue(mask_name("Ada Lovelace").startswith("Ada "))
        self.assertNotIn("Lovelace", mask_name("Ada Lovelace"))
        self.assertTrue(mask_identifier("ABCD1234").endswith("4"))
        self.assertNotIn("ABCD123", mask_identifier("ABCD1234"))
        self.assertTrue(mask_url("https://host.example/x").startswith("https://"))
        self.assertNotIn("host.example", mask_url("https://host.example/x"))

    def test_is_demo_masked_only_fires_on_a_mask(self):
        self.assertTrue(is_demo_masked(DEMO_MASK_CHAR))
        self.assertTrue(is_demo_masked("https://" + DEMO_MASK_CHAR * 4))
        self.assertFalse(is_demo_masked("https://real.example/api"))
        self.assertFalse(is_demo_masked(""))
        self.assertFalse(is_demo_masked(None))

    def test_masking_is_display_only_and_the_row_is_untouched(self):
        """Demo Mode never edits stored data -- the same promise the Verify
        page makes when it logs the real verification behind a masked screen."""
        self._demo(True)
        self._page("/app/admin/")
        self._page("/app/setup/")
        self.admin.refresh_from_db()
        self.org.refresh_from_db()
        self.assertEqual(self.admin.last_name, "Lovelace")
        self.assertEqual(self.org.everify_client_id, "ORGCLIENT9911")


class OrganizationFieldConfigTest(TestCase):
    """Each organization decides which eVerify fields reach its verification
    document and its transaction log, under what name, and in what order.

    The whole feature rests on one thing staying true: every decision
    downstream matches on eVerify's OWN key, never on the label. The label is
    editable now, and a rename that quietly stopped a field being logged --
    or being redacted in Demo Mode -- would have no symptom at all.
    """

    #: A full eVerify success payload, keyed the way the upstream keys it.
    RESPONSE = {
        "first_name": "Juan", "middle_name": "Santos", "last_name": "Cruz",
        "reference": "1111222233334444", "code": "ABC1234",
        "gender": "Male", "birth_date": "1990-01-15",
        "place_of_birth": "Quezon City", "marital_status": "Single",
        "full_address": "123 Katipunan Ave",
        "present_full_address": "456 Aurora Blvd",
        "blood_type": "O+",
    }

    #: The default header, in the DOCUMENT's order: there is one order and
    #: the document is what a person reads. By default the log keeps only
    #: the minimum -- the name, both ID numbers, the date of birth and the
    #: age, and the two addresses (the decision) -- so sex, place of
    #: birth, marital status and blood type are columns only once a site
    #: admin switches them on.
    DEFAULT_HEADER = [
        "TRANSACTION_ID", "ORGANIZATION", "OPERATOR_NATIONAL_ID_NUMBER",
        "OPERATOR_LOCATION", "ACTING_AS_SITE_ADMIN", "AGE",
        "GIVEN_NAME", "MIDDLE_NAME", "LAST_NAME", "NATIONAL_ID_CARD_NUMBER",
        "DIGITAL_NATIONAL_ID_NUMBER", "DATE_OF_BIRTH", "PERMANENT_ADDRESS",
        "PRESENT_ADDRESS", "VERIFICATION_TIMESTAMP",
        "AUTHENTICATION_RESULT", "TRANSACTION_TYPE",
    ]

    #: What a verification shows when nobody has configured anything, and
    #: what it logs (the photograph cannot be). Widening either is a
    #: decision about what every new organization prints and keeps.
    SHOWN_BY_DEFAULT = {"face_url", "age", "first_name", "middle_name",
                        "last_name", "reference", "code", "birth_date",
                        "full_address", "present_full_address"}
    LOGGED_BY_DEFAULT = SHOWN_BY_DEFAULT - {"face_url"}

    #: Every key a Tier II lookup returns, as captured from a real one.
    CAPTURED = [
        "address_line_1", "address_line_2", "barangay", "birth_date",
        "blood_type", "code", "country", "email", "face_url", "first_name",
        "full_address", "full_name", "gender", "last_name", "marital_status",
        "middle_name", "mobile_number", "municipality", "place_of_birth",
        "pob_country", "pob_municipality", "pob_province", "postal_code",
        "present_address_line_1", "present_address_line_2", "present_barangay",
        "present_country", "present_full_address", "present_municipality",
        "present_postal_code", "present_province", "province", "reference",
        "residency_status", "suffix", "token",
    ]

    def setUp(self):
        self.org = make_org(name="Alpha")
        self.other = make_org(name="Beta", locations=("Their Desk",))
        self.admin = User.objects.create(
            national_id_card_number="1111222233334444",
            given_name="Ada", last_name="Lovelace")
        join(self.org, self.admin, Membership.ROLE_ADMIN)
        self.site_admin = User.objects.create(
            national_id_card_number="5555666677778888", given_name="Sam",
            is_site_admin=True)
        self.type = TransactionType.objects.create(
            organization=self.org, name="New Enrollment")

    # -- helpers ----------------------------------------------------------

    def _as(self, user, org=None):
        session = self.client.session
        session[SESSION_KEY] = user.id
        session[ORG_SESSION_KEY] = (org or self.org).id
        session.save()

    def _configure(self, org, **overrides):
        """Write field settings for every key, starting from the defaults."""
        for row in everify_fields.default_rows():
            changed = overrides.get(row["key"], {})
            OrganizationFieldSetting.objects.update_or_create(
                organization=org, key=row["key"],
                defaults={
                    "display_name": changed.get("name", ""),
                    "show_on_document": changed.get("display", row["display"]),
                    "include_in_log": changed.get("log", row["log"]),
                    "position": changed.get("position", row["position"]),
                })

    def _prepared(self, org):
        return _prepare_data_for_frontend(
            dict(self.RESPONSE), everify_fields.rows_for(org))

    def _log_transaction(self, rows):
        self._as(self.admin)
        keep_answer(self.client, self.org, rows)
        return self.client.post(
            "/everify/log-transaction/",
            data=json.dumps({"transaction_type": str(self.type.id),
                             "verification_data": rows}),
            content_type="application/json")

    def _doc_table(self):
        """Everything the sheet PRINTS, which is `.doc-body`.

        It was the field table alone while that was the whole of the
        document. The certificate states the holder above the list -- name,
        both ID numbers and the portrait -- so a slice of the list would now
        report those fields missing when they are simply printed somewhere
        better. The block above the cut line is the honest boundary: what is
        outside it is the card and the nav. No copy of the answer travels in
        the page any more -- the log reads it from the session."""
        page = self.client.get("/app/document/").content.decode()
        start = page.index('<div class="doc-body"')
        # Ends where the card below the cut line begins. That element is
        # always in the markup -- it is `display: none` until a credential is
        # minted -- so it is a boundary that exists on every document.
        return page[start:page.index('<div class="cut-card"', start)]

    def _export(self):
        self._as(self.admin)
        response = self.client.get("/app/admin/export-transactions/")
        self.assertEqual(response.status_code, 200)
        return list(csv.reader(StringIO(response.content.decode())))

    def _all_off(self):
        return {key: {"display": False, "log": False}
                for key in everify_fields.FIELD_KEYS}

    # -- the defaults are the minimum -------------------------------------

    def test_the_defaults_show_and_log_only_the_minimum(self):
        """With nothing configured a verification shows the name, both ID
        numbers, the date of birth and the age, the two addresses and the
        photograph, and logs the same less the photograph. Everything else --
        sex, place of birth, marital status, blood type and every other key
        -- starts off on both."""
        rows = everify_fields.default_rows()
        self.assertEqual({r["key"] for r in rows if r["display"]},
                         self.SHOWN_BY_DEFAULT)
        self.assertEqual({r["key"] for r in rows if r["log"]},
                         self.LOGGED_BY_DEFAULT)
        # An organization that has configured nothing gets exactly those.
        self.assertEqual([r["key"] for r in self._prepared(self.org)], [
            "Age", "Given Name", "Middle Name", "Last Name",
            "National ID Card Number", "Digital National ID Number",
            "Date of Birth", "Permanent Address", "Present Address"])

    def test_the_default_export_has_the_minimum_in_document_order(self):
        """One order, so the CSV follows the document, and by default it
        carries no column the defaults do not log."""
        self._log_transaction(self._prepared(self.org))
        header, row = self._export()
        self.assertEqual(header, self.DEFAULT_HEADER)
        for column in ("SEX", "PLACE_OF_BIRTH", "MARITAL_STATUS", "BLOOD_TYPE"):
            self.assertNotIn(column, header)
        self.assertEqual(row[header.index("PRESENT_ADDRESS")], "456 Aurora Blvd")
        txn = Transaction.objects.get()
        self.assertEqual((txn.sex, txn.place_of_birth, txn.marital_status),
                         ("", "", ""))

    def test_a_response_that_identifies_nobody_is_still_a_miss(self):
        """The captured response carries `token`, which is there whoever it
        does or does not describe. If "named somebody" meant "any known key
        came back", a payload of nothing but a token would read as a hit."""
        response = _prepare_data_for_frontend(
            {"token": "abc", "country": "Philippines"},
            everify_fields.rows_for(None))
        self.assertEqual(response, [])
        self.assertFalse(_named_somebody({"token": "abc",
                                          "country": "Philippines"}))
        self.assertTrue(_named_somebody({"reference": "1111222233334444"}))

    def test_the_field_list_is_exactly_what_the_lookup_returned(self):
        """Fixed, and not discovered at runtime: it is the captured set, and
        the one field this app works out itself."""
        self.assertEqual(sorted(everify_fields.FIELD_KEYS),
                         sorted(self.CAPTURED + ["age"]))
        self.assertEqual(everify_fields.COMPUTED, {"age": "birth_date"})
        self.assertNotIn("age", self.CAPTURED)
        self.assertNotIn("verified", everify_fields.FIELD_KEYS)

    def test_the_named_fields_lead_with_their_names_and_defaults(self):
        """The named fields are the reference: they say which keys start on
        top, in what order, under what name, and switched which way."""
        rows = everify_fields.in_order(everify_fields.rows_for(self.org))
        self.assertEqual(everify_fields.KNOWN_COUNT, 14)
        self.assertEqual([r["key"] for r in rows[:14]], [
            "face_url", "age", "first_name", "middle_name", "last_name",
            "reference", "code", "gender", "birth_date", "place_of_birth",
            "marital_status", "full_address", "present_full_address",
            "blood_type"])
        for row in rows[:14]:
            self.assertEqual(row["display"], row["key"] in self.SHOWN_BY_DEFAULT,
                             row["key"])
            self.assertEqual(row["log"], row["key"] in self.LOGGED_BY_DEFAULT,
                             row["key"])
            self.assertTrue(row["name"], row["key"])
        self.assertEqual(rows[2]["name"], "Given Name")
        self.assertEqual(rows[1]["name"], "Age")

        # Everything the app had never used starts off, and unnamed --
        # except the three whose keys read badly on a document.
        named = {"email": "Email Address", "mobile_number": "Mobile Number",
                 "residency_status": "Residency Status"}
        for row in rows[14:]:
            self.assertFalse(row["display"], row["key"])
            self.assertFalse(row["log"], row["key"])
            if row["key"] in named:
                self.assertEqual(row["name"], named[row["key"]])
                continue
            self.assertEqual(row["name"], "")
            self.assertEqual(everify_fields.label_for(row), row["key"])

    def test_a_newly_returned_field_changes_nothing_until_switched_on(self):
        carried = [r["field"] for r in self._prepared(self.org)]
        for key in ("email", "mobile_number", "token", "full_name"):
            self.assertNotIn(key, carried)

    def test_every_carried_row_has_the_key_as_well_as_the_label(self):
        for row in self._prepared(self.org):
            self.assertTrue(row["field"], row)
            self.assertIn(row["field"], everify_fields.FIELD_KEYS)

    # -- Display ----------------------------------------------------------

    def test_display_off_keeps_the_field_off_the_document(self):
        self._configure(self.org,
                        present_full_address={"display": False, "log": True},
                        place_of_birth={"display": True})
        session = self.client.session
        session[SESSION_KEY] = self.admin.id
        session[ORG_SESSION_KEY] = self.org.id
        verified_answer.keep(session, self.org, self._prepared(self.org))
        session.save()
        table = self._doc_table()
        self.assertNotIn("Present Address", table)
        self.assertNotIn("456 Aurora Blvd", table)
        self.assertIn("Place of Birth", table)
        self.assertIn("123 Katipunan Ave", table)

    def test_a_field_that_is_neither_shown_nor_logged_is_not_carried(self):
        """Not hidden downstream -- never taken from the response at all."""
        self._configure(self.org,
                        present_full_address={"display": False, "log": False})
        keys = [row["field"] for row in self._prepared(self.org)]
        self.assertNotIn("present_full_address", keys)
        self.assertNotIn("blood_type", keys)          # off by default
        self.assertIn("full_address", keys)

    # -- Log --------------------------------------------------------------

    def test_log_off_means_the_value_is_never_recorded(self):
        """Not merely left out of the CSV: absent from the row entirely, so
        it cannot be exported later by switching the toggle back on."""
        self._configure(self.org, birth_date={"log": False})
        self._log_transaction(self._prepared(self.org))
        txn = Transaction.objects.get()
        self.assertEqual(txn.date_of_birth, "")
        self.assertNotIn("birth_date", txn.logged_fields)
        self.assertEqual(txn.given_name, "Juan")

    def test_a_field_with_no_column_of_its_own_can_still_be_logged(self):
        """Blood Type has never had a column on Transaction."""
        self._configure(self.org, blood_type={"log": True})
        self._log_transaction(self._prepared(self.org))
        self.assertEqual(
            Transaction.objects.get().logged_fields["blood_type"], "O+")
        header, row = self._export()
        self.assertIn("BLOOD_TYPE", header)
        self.assertEqual(row[header.index("BLOOD_TYPE")], "O+")

    def test_the_browser_cannot_add_a_field_the_organization_does_not_log(self):
        """The rows carry values; they get no say in which are kept."""
        self._configure(self.org, blood_type={"log": False})
        rows = self._prepared(self.org) + [
            {"field": "blood_type", "key": "Blood Type", "value": "O+",
             "show": True}]
        self._log_transaction(rows)
        self.assertNotIn("blood_type", Transaction.objects.get().logged_fields)

    def test_the_outcome_is_recorded_whatever_the_field_settings_say(self):
        """A log entry that does not say whether it succeeded is not one, and
        the admin statistics count on it."""
        self._configure(self.org, **self._all_off())
        self._log_transaction(self._prepared(self.org))
        self.assertEqual(Transaction.objects.get().authentication_result,
                         "success")

    # -- order ------------------------------------------------------------

    def test_reordering_the_document_changes_the_printed_order(self):
        self._configure(self.org,
                        last_name={"position": 0},
                        first_name={"position": 1},
                        age={"position": 2})
        labels = [row["key"] for row in self._prepared(self.org)]
        self.assertEqual(labels[:2], ["Last Name", "Given Name"])

    def test_one_order_drives_the_document_and_the_csv_together(self):
        """The whole point of a single list: move a row once and both the
        printed page and the exported columns follow."""
        self._configure(self.org,
                        gender={"position": 0, "display": True, "log": True})
        self.assertEqual(self._prepared(self.org)[0]["key"], "Sex")
        self._log_transaction(self._prepared(self.org))
        header = self._export()[0]
        self.assertEqual(header[5], "SEX")
        self.assertLess(header.index("SEX"),
                        header.index("NATIONAL_ID_CARD_NUMBER"))

    # -- names ------------------------------------------------------------

    #: Place of birth, switched on as a site admin would, and renamed.
    BIRTHPLACE = {"name": "Birthplace", "display": True, "log": True}

    def test_renaming_a_field_renames_it_on_the_document_and_in_the_csv(self):
        self._configure(self.org, place_of_birth=self.BIRTHPLACE)
        labels = [row["key"] for row in self._prepared(self.org)]
        self.assertIn("Birthplace", labels)
        self.assertNotIn("Place of Birth", labels)
        self._log_transaction(self._prepared(self.org))
        self.assertIn("BIRTHPLACE", self._export()[0])

    def test_renaming_a_field_does_not_stop_it_being_logged(self):
        """What this design exists to prevent: matching the posted rows by the
        label printed on the document."""
        self._configure(self.org, place_of_birth=self.BIRTHPLACE,
                        first_name={"name": "Pangalan"})
        self._log_transaction(self._prepared(self.org))
        txn = Transaction.objects.get()
        self.assertEqual(txn.place_of_birth, "Quezon City")
        self.assertEqual(txn.given_name, "Juan")

    def test_a_renamed_field_is_still_redacted_in_demo_mode(self):
        """The same coupling one page over: a mask keyed on the label would
        unmask a renamed field with no symptom."""
        self._configure(self.org, middle_name={"name": "Second Name"})
        masked = apply_demo_mask(self._prepared(self.org))
        row = next(r for r in masked if r["field"] == "middle_name")
        self.assertNotIn("Santos", row["value"])
        self.assertIn(DEMO_MASK_CHAR, row["value"])

    def test_a_blank_name_falls_back_to_the_key(self):
        self.assertEqual(
            everify_fields.label_for({"key": "novel_field", "name": ""}),
            "novel_field")

    # -- scope ------------------------------------------------------------

    def test_one_organizations_configuration_does_not_touch_another(self):
        self._configure(self.org, blood_type={"display": True, "log": True},
                        full_address={"display": False, "log": False})
        self.assertIn("blood_type",
                      [row["field"] for row in self._prepared(self.org)])
        keys = [row["field"] for row in self._prepared(self.other)]
        self.assertNotIn("blood_type", keys)
        self.assertIn("full_address", keys)

    def test_the_login_path_ignores_every_organizations_configuration(self):
        """Sign-in runs before there is a session, so before there is an
        organization. Its field list is the built-in one and must stay so:
        the identity chain reads `reference` and `code` out of it."""
        for org in (self.org, self.other):
            self._configure(org, **self._all_off())
        rows = _prepare_data_for_frontend(dict(self.RESPONSE),
                                          everify_fields.rows_for(None))
        carried = [row["field"] for row in rows]
        self.assertIn("reference", carried)
        self.assertIn("code", carried)
        # The built-in defaults: the eight of the response's that are on, and
        # the age worked out from one of them.
        self.assertEqual(len(carried), 9)

    def test_a_signed_out_lookup_still_signs_the_operator_in(self):
        """The end-to-end version of the above, through the real view."""
        self._configure(self.org, **self._all_off())
        upstream = MagicMock(status_code=200)
        upstream.json.return_value = {
            "data": {"reference": "1111222233334444", "code": "ABC1234"}}
        patches = [
            patch("verify.views.everify.EVERIFY_CLIENT_ID", "id"),
            patch("verify.views.everify.EVERIFY_CLIENT_SECRET", "secret"),
            patch("verify.views.everify.get_everify_access_token",
                  return_value="tok"),
            patch("verify.views.everify.requests.post", return_value=upstream),
        ]
        for item in patches:
            item.start()
        self.addCleanup(lambda: [item.stop() for item in patches])
        response = self.client.post(
            "/everify/",
            data=json.dumps({"value": "1111222233334444",
                             "face_liveness_session_id": "sess"}),
            content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.session.get(SESSION_KEY), self.admin.id)

    # -- the editor -------------------------------------------------------

    def test_only_a_site_admin_may_change_the_fields(self):
        """An organization admin runs their own lists; what leaves on a
        document is site administration, and one screen owns it."""
        self._as(self.admin)
        response = self.client.post(
            "/app/site/organizations/%d/fields/" % self.org.id,
            data=json.dumps({"fields": [{"key": "blood_type", "log": True}]}),
            content_type="application/json")
        self.assertEqual(response.status_code, 403)
        self.assertFalse(OrganizationFieldSetting.objects.exists())

    def test_a_site_admin_saves_the_toggles_and_the_order(self):
        self._as(self.site_admin)
        response = self.client.post(
            "/app/site/organizations/%d/fields/" % self.org.id,
            data=json.dumps({"fields": [
                {"key": "blood_type", "display_name": "Blood Group",
                 "display": True, "log": True, "position": 0},
                {"key": "first_name", "display_name": "Given Name",
                 "display": True, "log": True, "position": 1},
            ]}),
            content_type="application/json")
        self.assertEqual(response.status_code, 200)
        row = OrganizationFieldSetting.objects.get(
            organization=self.org, key="blood_type")
        self.assertEqual(row.display_name, "Blood Group")
        self.assertTrue(row.include_in_log)
        self.assertEqual(row.position, 0)
        # A name equal to the built-in is stored blank, so it goes on tracking
        # the code if the built-in is ever corrected.
        self.assertEqual(OrganizationFieldSetting.objects.get(
            organization=self.org, key="first_name").display_name, "")

    def test_the_picture_cannot_be_logged_however_it_is_asked(self):
        """"When applicable" means the value can be readily logged. A face is
        a base64 image, so it has no Log toggle at all -- and a hand-made POST
        that sets one anyway is refused, because the page is a courtesy and
        the server is the guard."""
        self._as(self.site_admin)
        self.client.post(
            "/app/site/organizations/%d/fields/" % self.org.id,
            data=json.dumps({"fields": [
                {"key": "face_url", "display": True, "log": True,
                 "position": 0}]}),
            content_type="application/json")
        stored = OrganizationFieldSetting.objects.get(
            organization=self.org, key="face_url")
        self.assertFalse(stored.include_in_log)

        row = next(r for r in everify_fields.rows_for(self.org)
                   if r["key"] == "face_url")
        self.assertFalse(row["loggable"])
        self.assertFalse(row["log"])
        self.assertNotIn("face_url",
                         [r["key"] for r in everify_fields.log_rows(
                             everify_fields.rows_for(self.org))])

    def test_a_stored_row_cannot_make_the_picture_loggable_either(self):
        """The save endpoint refuses it, but a row could also be written by a
        migration, a shell, or a future editor. rows_for() is the place the
        invariant actually lives, so prove it there and not only at the door."""
        self._configure(self.org, face_url={"display": True, "log": True})
        self.assertTrue(OrganizationFieldSetting.objects.get(
            organization=self.org, key="face_url").include_in_log,
            "the test needs a stored row that really does say True")

        row = next(r for r in everify_fields.rows_for(self.org)
                   if r["key"] == "face_url")
        self.assertFalse(row["log"])
        self.assertNotIn("face_url", [
            r["key"] for r in everify_fields.log_rows(
                everify_fields.rows_for(self.org))])

        self._log_transaction(self._prepared(self.org))
        self.assertNotIn("face_url", Transaction.objects.get().logged_fields)

    def test_the_page_offers_no_log_toggle_for_the_picture(self):
        self._as(self.site_admin)
        page = self.client.get(
            "/app/site/organizations/%d/" % self.org.id).content.decode()
        row = page[page.index('data-key="face_url"'):]
        row = row[:row.index("</li>")]
        self.assertIn("fl-show", row)
        self.assertNotIn("fl-log", row)
        self.assertIn("cannot be readily logged", row)

    def test_a_key_this_app_does_not_know_is_ignored(self):
        """The whitelist is code, not something typed into a form."""
        self._as(self.site_admin)
        self.client.post(
            "/app/site/organizations/%d/fields/" % self.org.id,
            data=json.dumps({"fields": [
                {"key": "mothers_maiden_name", "display": True, "log": True},
                {"key": "blood_type", "display": True, "log": True},
            ]}),
            content_type="application/json")
        self.assertEqual(
            set(OrganizationFieldSetting.objects.values_list("key", flat=True)),
            {"blood_type"})

    def test_reset_restores_the_defaults(self):
        self._configure(self.org, blood_type={"display": True, "log": True},
                        full_address={"display": False, "log": False})
        self._as(self.site_admin)
        self.client.post(
            "/app/site/organizations/%d/fields/" % self.org.id,
            data=json.dumps({"reset": True}),
            content_type="application/json")
        self.assertFalse(OrganizationFieldSetting.objects.filter(
            organization=self.org).exists())
        keys = [row["field"] for row in self._prepared(self.org)]
        self.assertNotIn("blood_type", keys)
        self.assertIn("full_address", keys)

    def test_the_page_lists_every_field_once_in_one_list(self):
        self._as(self.site_admin)
        page = self.client.get(
            "/app/site/organizations/%d/" % self.org.id).content.decode()
        for key in everify_fields.FIELD_KEYS:
            self.assertEqual(page.count('data-key="%s"' % key), 1, key)
        self.assertEqual(page.count('class="fl-list"'), 1)

    # -- what was already there keeps working -----------------------------

    def test_an_export_of_rows_written_before_the_configuration_works(self):
        """Old rows have no logged_fields, so the export falls back to the
        named columns -- which is also why turning a field off does not blank
        the history."""
        Transaction.objects.create(
            organization=self.org, given_name="Older", last_name="Row",
            national_id_card_number="9999888877776666",
            authentication_result="success", transaction_type="Legacy")
        header, row = self._export()
        self.assertEqual(row[header.index("GIVEN_NAME")], "Older")

    def test_a_session_opened_before_the_upgrade_is_sent_back_to_verify(self):
        """Its rows were written by the browser, under the key that held them
        then, and are never read: that operator verifies again."""
        session = self.client.session
        session[SESSION_KEY] = self.admin.id
        session[ORG_SESSION_KEY] = self.org.id
        session["verification_data"] = [
            {"key": "Given Name", "value": "Juan"},
            {"key": "Blood Type", "value": "O+"},
        ]
        session.save()
        response = self.client.get("/app/document/")
        self.assertRedirects(response, "/app/", fetch_redirect_response=False)

    def test_label_only_rows_still_render(self):
        keep_answer(self.client, self.org, [
            {"key": "Given Name", "value": "Juan"},
            {"key": "Blood Type", "value": "O+"},
        ])
        self._as(self.admin)
        table = self._doc_table()
        self.assertIn("Juan", table)
        self.assertIn("O+", table)

    def test_an_old_session_row_is_still_logged_under_its_key(self):
        rows = [{"key": "Given Name", "value": "Juan"},
                {"key": "National ID Card Number", "value": "1111222233334444"}]
        self._log_transaction(rows)
        txn = Transaction.objects.get()
        self.assertEqual(txn.given_name, "Juan")
        self.assertEqual(txn.national_id_card_number, "1111222233334444")


class AgeFieldTest(TestCase):
    """The age: worked out from the date of birth on the day of the
    verification, printed after the name and in the details with the day it
    holds for, and logged as it was that day -- but never in the signed
    credential or on the phone card, because it stops being true on the
    holder's next birthday. On by default, with the date of birth."""

    #: Born 1990-01-15, so 36 on the day below.
    RESPONSE = OrganizationFieldConfigTest.RESPONSE
    TODAY = datetime.date(2026, 10, 27)

    def setUp(self):
        self.org = make_org(name="Alpha")
        self.admin = User.objects.create(
            national_id_card_number="1111222233334444",
            given_name="Ada", last_name="Lovelace")
        join(self.org, self.admin, Membership.ROLE_ADMIN)
        self.type = TransactionType.objects.create(
            organization=self.org, name="New Enrollment")
        today = patch("django.utils.timezone.localdate",
                      return_value=self.TODAY)
        self.today = today.start()
        self.addCleanup(today.stop)

    def _as(self, user=None):
        session = self.client.session
        session[SESSION_KEY] = (user or self.admin).id
        session[ORG_SESSION_KEY] = self.org.id
        session.save()

    def test_the_age_is_on_by_default_with_the_date_of_birth(self):
        """An organization that has configured nothing shows and logs it."""
        self.assertFalse(OrganizationFieldSetting.objects.exists())
        rows = self._prepared()
        self.assertEqual(self._age(rows)["value"], "36")
        self.assertIn("birth_date", [r["field"] for r in rows])
        age = next(r for r in everify_fields.default_rows() if r["key"] == "age")
        self.assertEqual((age["display"], age["log"]), (True, True))

    def _prepared(self, response=None):
        return _prepare_data_for_frontend(
            dict(self.RESPONSE if response is None else response),
            everify_fields.rows_for(self.org))

    @staticmethod
    def _age(rows):
        return next((row for row in rows if row["field"] == "age"), None)

    def _set(self, key, **changes):
        """One field's stored setting, the defaults for the rest of it."""
        row = next(r for r in everify_fields.default_rows() if r["key"] == key)
        OrganizationFieldSetting.objects.update_or_create(
            organization=self.org, key=key,
            defaults={"show_on_document": changes.get("display", row["display"]),
                      "include_in_log": changes.get("log", row["log"]),
                      "position": row["position"]})

    def _document(self):
        keep_answer(self.client, self.org, self._prepared())
        self._as()
        return self.client.get("/app/document/").content.decode()

    # -- the arithmetic ---------------------------------------------------

    def test_an_age_is_whole_years_and_counts_on_the_birthday(self):
        age_on = everify_fields.age_on
        self.assertEqual(age_on("1990-01-15", datetime.date(2026, 1, 14)), 35)
        self.assertEqual(age_on("1990-01-15", datetime.date(2026, 1, 15)), 36)
        # The document's own spelling, which the mock and samples carry.
        self.assertEqual(age_on("01/15/1990", datetime.date(2026, 1, 15)), 36)

    def test_a_leap_day_birthday_counts_on_the_first_of_march(self):
        age_on = everify_fields.age_on
        self.assertEqual(age_on("2000-02-29", datetime.date(2026, 2, 28)), 25)
        self.assertEqual(age_on("2000-02-29", datetime.date(2026, 3, 1)), 26)
        self.assertEqual(age_on("2000-02-29", datetime.date(2028, 2, 29)), 28)

    def test_no_usable_date_of_birth_is_no_age_rather_than_a_wrong_one(self):
        for bad in ("", None, "15 January 1990", "1990-02-30", "2027-01-01"):
            self.assertIsNone(everify_fields.age_on(bad, self.TODAY), bad)

    # -- carried ----------------------------------------------------------

    def test_the_age_is_worked_out_on_the_day_and_carries_that_day(self):
        rows = self._prepared()
        age = self._age(rows)
        self.assertEqual(age["value"], "36")
        self.assertEqual(age["as_of"], "10/27/2026")
        self.assertEqual(age["key"], "Age")
        self.assertTrue(age["show"])
        # Under the portrait, which this response does not carry.
        self.assertEqual(rows[0]["field"], "age")
        # Nothing else is given a date.
        self.assertEqual([r["field"] for r in rows if "as_of" in r], ["age"])

    def test_an_age_in_the_response_is_never_believed(self):
        self.assertEqual(
            self._age(self._prepared({**self.RESPONSE, "age": "99"}))["value"],
            "36")
        no_birth_date = {k: v for k, v in self.RESPONSE.items()
                         if k != "birth_date"}
        self.assertIsNone(self._age(self._prepared({**no_birth_date,
                                                    "age": "99"})))

    def test_the_age_does_not_need_the_date_of_birth_switched_on(self):
        """An organization may want the age without the date of birth; the
        age comes from the RAW response, not from the rows it keeps."""
        self._set("birth_date", display=False, log=False)
        rows = self._prepared()
        self.assertEqual(self._age(rows)["value"], "36")
        self.assertNotIn("birth_date", [r["field"] for r in rows])

    def test_the_mock_and_the_sample_carry_an_age_too(self):
        from verify.views.everify import _mock_everify_data

        mock = _mock_everify_data({"value": "ABC1234"},
                                  everify_fields.rows_for(self.org))
        self.assertEqual(self._age(mock)["value"], "36")   # 01/15/1990
        sample = sample_data.sample_rows(self.org)
        self.assertEqual(self._age(sample)["as_of"], "10/27/2026")

    # -- the field list ---------------------------------------------------

    NAMED = {"email": "Email Address", "mobile_number": "Mobile Number",
             "residency_status": "Residency Status"}

    def test_three_newer_keys_have_names_and_stay_off(self):
        rows = {r["key"]: r for r in everify_fields.rows_for(self.org)}
        for key, name in self.NAMED.items():
            self.assertEqual(rows[key]["name"], name)
            self.assertFalse(rows[key]["display"], key)
            self.assertFalse(rows[key]["log"], key)

    def test_a_saved_list_with_no_name_typed_takes_the_new_names(self):
        """What an organization that saved its fields already holds: a blank
        name, meaning "the built-in one" -- which is now these. A name somebody
        typed is theirs and stays."""
        for key in self.NAMED:
            self._set(key)
        OrganizationFieldSetting.objects.filter(
            organization=self.org, key="email").update(display_name="E-mail")
        rows = {r["key"]: r for r in everify_fields.rows_for(self.org)}
        self.assertEqual(rows["email"]["name"], "E-mail")
        self.assertEqual(rows["mobile_number"]["name"], "Mobile Number")
        self.assertEqual(rows["residency_status"]["name"], "Residency Status")

    def test_an_organization_that_saved_before_the_age_gets_it_under_the_portrait(self):
        """Its stored positions count places in the list WITHOUT the age, so
        the age's default position would land it wherever that number now
        falls. It goes after Face Photo instead, wherever that was moved, and
        takes the default switches, which are on."""
        before = [key for key in everify_fields.FIELD_KEYS if key != "age"]
        before.remove("first_name")
        before.insert(0, "first_name")          # Given Name moved above the face
        for position, key in enumerate(before):
            row = next(r for r in everify_fields.default_rows()
                       if r["key"] == key)
            OrganizationFieldSetting.objects.create(
                organization=self.org, key=key, position=position,
                show_on_document=row["display"], include_in_log=row["log"])
        rows = everify_fields.in_order(everify_fields.rows_for(self.org))
        self.assertEqual([r["key"] for r in rows[:4]],
                         ["first_name", "face_url", "age", "middle_name"])
        age = rows[2]
        self.assertTrue(age["display"])
        self.assertTrue(age["log"])

    def test_the_editor_says_where_the_age_comes_from(self):
        site_admin = User.objects.create(
            national_id_card_number="5555666677778888", given_name="Sam",
            is_site_admin=True)
        self._as(site_admin)
        page = self.client.get(
            reverse("site_organization", args=[self.org.id])).content.decode()
        self.assertIn(">from birth_date</span>", page)
        for name in self.NAMED.values():
            self.assertIn('value="%s"' % name, page)
        self.assertIn('<span class="fl-count">(23)</span>', page)

    # -- the document -----------------------------------------------------

    def test_the_document_prints_the_age_after_the_name(self):
        page = self._document()
        self.assertIn('<div class="doc-hero-name">Juan Santos Cruz, 36</div>',
                      page)

    def test_the_details_say_what_day_the_age_holds_for(self):
        page = self._document()
        self.assertIn('<div class="th">Age</div>', page)
        self.assertIn('36<span class="as-of">(as of 10/27/2026)</span>', page)

    def test_display_off_takes_the_age_off_the_name_and_the_details(self):
        self._set("age", display=False, log=True)
        page = self._document()
        self.assertIn('<div class="doc-hero-name">Juan Santos Cruz</div>', page)
        self.assertNotIn('<div class="th">Age</div>', page)
        self.assertNotIn('class="as-of"', page)

    def test_demo_mode_masks_the_age_with_the_date_of_birth(self):
        age = self._age(apply_demo_mask(self._prepared()))
        self.assertNotIn("36", age["value"])
        self.assertIn(DEMO_MASK_CHAR, age["value"])

    # -- the log ----------------------------------------------------------

    def test_the_age_is_logged_as_it_was_on_the_day(self):
        self._as()
        keep_answer(self.client, self.org, self._prepared())
        response = self.client.post(
            "/everify/log-transaction/",
            data=json.dumps({"transaction_type": str(self.type.id)}),
            content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Transaction.objects.get().logged_fields["age"], "36")

        # Exported after the birthday, it is still the age on the day.
        self.today.return_value = datetime.date(2027, 2, 1)
        export = self.client.get("/app/admin/export-transactions/")
        header, row = list(csv.reader(StringIO(export.content.decode())))[:2]
        self.assertEqual(row[header.index("AGE")], "36")

    # -- never on what outlives the day -----------------------------------

    def test_the_phone_card_carries_no_age(self):
        from verify.views import handoff

        card = handoff.payload_from_rows(
            self._prepared(), organization="Alpha", transaction_type="",
            location_name="", verified_at="", transaction_id="", qr="",
            portrait_qr="", face_data_uri="")
        self.assertEqual(card["holder"], "Juan Santos Cruz")
        self.assertNotIn("36", json.dumps(card))


class IssuerCodeTest(TestCase):
    """The short code a credential names an organization by.

    Stored, not derived. A credential is signed and outlives a rename, so a
    code computed from the name would make old and new credentials disagree
    about who issued them -- and initials collide.
    """

    def setUp(self):
        self.site_admin = User.objects.create(
            national_id_card_number="5555666677778888", given_name="Sam",
            is_site_admin=True)

    def _as_site_admin(self, org):
        session = self.client.session
        session[SESSION_KEY] = self.site_admin.id
        session[ORG_SESSION_KEY] = org.id
        session.save()

    def test_the_migration_seeded_a_code_from_the_initials(self):
        """0024 runs against organizations that already exist."""
        org = make_org(name="Philippine Statistics Authority")
        # make_org creates directly, so mimic what the migration did.
        org.issuer_code = next_issuer_code(org.name)
        org.save(update_fields=["issuer_code"])
        self.assertEqual(org.issuer_code, "PSA")

    def test_colliding_initials_get_different_codes(self):
        first = Organization.objects.create(
            name="Philippine Statistics Authority",
            issuer_code=next_issuer_code("Philippine Statistics Authority"))
        second_code = next_issuer_code("Public Service Agency")
        self.assertEqual(first.issuer_code, "PSA")
        self.assertNotEqual(second_code, "PSA")
        self.assertEqual(second_code, "PSA2")

    def test_a_new_organization_is_given_a_code_immediately(self):
        """A credential from an organization with no code names nobody, and
        nothing about creating one prompts an admin to think about it."""
        existing = make_org(name="Anything")
        self._as_site_admin(existing)
        self.client.post("/app/site/organizations/new/",
                         {"name": "Bureau of Immigration",
                          "mark_color": "#00386a", "is_active": "on"})
        created = Organization.objects.get(name="Bureau of Immigration")
        self.assertEqual(created.issuer_code, "BOI")

    def test_the_code_must_stay_inside_the_qr_alphanumeric_charset(self):
        """Lowercase or punctuation would force the QR into byte mode, which
        costs ~45% of the capacity -- on a payload already at the printable
        limit that is a stamp that will not scan."""
        org = make_org(name="Alpha")
        org.issuer_code = "ALP"
        org.save(update_fields=["issuer_code"])
        self._as_site_admin(org)
        for bad in ("psa!", "P S A", "A", "TOOLONGCODE", "PS-A"):
            response = self.client.post(
                "/app/site/organizations/%d/" % org.id,
                {"name": "Alpha", "issuer_code": bad, "mark_color": "#00386a"})
            self.assertIn("Issuer code", response.context["error"], bad)
            org.refresh_from_db()
            self.assertEqual(org.issuer_code, "ALP", bad)

    def test_a_code_is_uppercased_and_saved(self):
        org = make_org(name="Alpha")
        self._as_site_admin(org)
        response = self.client.post(
            "/app/site/organizations/%d/" % org.id,
            {"name": "Alpha", "issuer_code": "bi2", "mark_color": "#00386a"})
        self.assertEqual(response.context["error"], "")
        org.refresh_from_db()
        self.assertEqual(org.issuer_code, "BI2")

    def test_two_organizations_cannot_share_a_code(self):
        first = make_org(name="Alpha")
        first.issuer_code = "ALP"
        first.save(update_fields=["issuer_code"])
        second = make_org(name="Beta", locations=("Desk",))
        self._as_site_admin(second)
        response = self.client.post(
            "/app/site/organizations/%d/" % second.id,
            {"name": "Beta", "issuer_code": "ALP", "mark_color": "#00386a"})
        self.assertIn("already used", response.context["error"])

    def test_a_code_cannot_be_cleared_once_set(self):
        """Credentials already in circulation name the organization by it."""
        org = make_org(name="Alpha")
        org.issuer_code = "ALP"
        org.save(update_fields=["issuer_code"])
        self._as_site_admin(org)
        response = self.client.post(
            "/app/site/organizations/%d/" % org.id,
            {"name": "Alpha", "issuer_code": "", "mark_color": "#00386a"})
        self.assertIn("cannot be cleared", response.context["error"])
        org.refresh_from_db()
        self.assertEqual(org.issuer_code, "ALP")


class CredentialMintTest(TestCase):
    """The offline credential that rides in the document QR.

    The crypto is vendored verbatim from the sibling OfflineVerifier project;
    these tests are about what THIS app puts into it and how big the result
    gets, not about the wire format, which vectors/vectors.json pins.
    """

    ROWS = [
        {"field": "first_name", "key": "Given Name", "value": "JUAN", "show": True},
        {"field": "middle_name", "key": "Middle Name", "value": "SANTOS", "show": True},
        {"field": "last_name", "key": "Last Name", "value": "DELA CRUZ", "show": True},
        {"field": "reference", "key": "National ID Card Number",
         "value": "1111-2222-3333-4444", "show": True},
        {"field": "code", "key": "Digital National ID Number",
         "value": "ABC1234", "show": True},
        {"field": "gender", "key": "Sex", "value": "Male", "show": True},
        {"field": "birth_date", "key": "Date of Birth", "value": "01/15/1990",
         "show": True},
        {"field": "place_of_birth", "key": "Place of Birth",
         "value": "Quezon City", "show": True},
    ]

    UUID = "3f2b1c8e-9a4d-4f11-8e77-1a2b3c4d5e6f"

    def setUp(self):
        import datetime
        import os
        import stat
        import tempfile

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from ovcrypto import issuer as issuer_mod

        self.org = make_org(name="Philippine Statistics Authority")
        self.org.issuer_code = "PSA"
        self.org.save(update_fields=["issuer_code"])

        self.dir = tempfile.mkdtemp()
        self.pem = os.path.join(self.dir, "issuer.pem")
        key = ec.generate_private_key(ec.SECP256R1())
        with open(self.pem, "wb") as handle:
            handle.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        os.chmod(self.pem, stat.S_IRUSR | stat.S_IWUSR)
        self.addCleanup(lambda: (os.remove(self.pem), os.rmdir(self.dir)))

        self.signer = credentials.PemSigningBackend.from_path(self.pem, key_id=7)
        self.pub_priv = X25519PrivateKey.generate()
        self.res_priv = X25519PrivateKey.generate()
        self.epoch_keys = issuer_mod.EpochPublicKeys(
            42, self.pub_priv.public_key(), self.res_priv.public_key())
        self.issued = datetime.datetime.now(datetime.timezone.utc)
        self.expires = self.issued + datetime.timedelta(days=365)

    def _mint(self, rows=None, location="EASTAV", field_rows=None,
              transaction_type=""):
        return credentials.mint(
            rows if rows is not None else self.ROWS,
            organization=self.org, location_code=location,
            document_uuid=self.UUID, epoch_keys=self.epoch_keys,
            signer=self.signer, issued_at=self.issued,
            expires_at=self.expires, field_rows=field_rows,
            transaction_type=transaction_type)

    def _open(self, minted, restricted=True):
        import time

        from ovcrypto import verifier

        body = "CL03:" + minted["qr"].split(":CL03:", 1)[1]
        keys = {42: verifier.EpochPrivateKeys(
            42, self.pub_priv, self.res_priv if restricted else None)}
        return verifier.verify(
            body, epoch_keys=keys,
            trust_list=verifier.TrustList.bare({7: self.signer.public_key_der()}),
            now=int(time.time()))

    def test_a_key_file_another_account_can_open_is_a_credential_error(self):
        """The refusal reaches callers that catch CredentialError, on Windows
        as on Linux."""
        from ovcrypto import keystore

        if os.name == "nt":
            keystore._set_windows_dacl(self.pem, "D:P(A;;FA;;;%s)(A;;FR;;;BU)"
                                       % keystore._windows_user())
        else:
            os.chmod(self.pem, 0o644)
        with self.assertRaisesRegex(credentials.CredentialError,
                                    "group/world accessible|not only to this account"):
            credentials.PemSigningBackend.from_path(self.pem, key_id=7)

    # -- what the phone is told this credential is -------------------------

    def test_the_transaction_type_travels_as_text_and_verbatim(self):
        # `doc_type` cannot carry this. It is a bare uint8 with no registry,
        # and its values already mean other documents in the verifier app's
        # own table -- 2 is "Marriage certificate" there.
        from ovcrypto import wire

        result = self._open(self._mint(transaction_type="Employment"))
        self.assertEqual(result.public_claims[wire.T_TRANSACTION_TYPE],
                         b"Employment")

    def test_a_credential_without_one_is_still_well_formed(self):
        # Optional: OfflineVerifier's own credentials predate the claim, and a
        # phone must show the rest rather than refuse them.
        from ovcrypto import wire

        result = self._open(self._mint())
        self.assertNotIn(wire.T_TRANSACTION_TYPE, result.public_claims)
        self.assertEqual(result.verdict.value, "valid")

    def test_a_long_type_name_is_bounded_like_every_other_text_claim(self):
        # The payload sits at the edge of what a printed stamp can carry, and
        # TransactionType.name allows 255 characters.
        from ovcrypto import wire

        result = self._open(self._mint(transaction_type="T" * 400))
        self.assertEqual(
            len(result.public_claims[wire.T_TRANSACTION_TYPE]),
            credentials.MAX_TEXT)

    # -- the round trip ---------------------------------------------------

    @staticmethod
    def _fields(claims):
        """The displayed rows, label -> value, in document order."""
        from ovcrypto import wire

        return dict(wire.decode_fields(claims.get(wire.T_FIELDS, b"")))

    def test_the_age_is_printed_but_never_signed(self):
        """Not in the field list and not in the document hash: an age is true
        for a year, and the date of birth it came from is carried already."""
        from ovcrypto import wire

        age = {"field": "age", "key": "Age", "value": "36", "show": True,
               "as_of": "10/27/2026"}
        opened = self._open(self._mint(rows=[age] + self.ROWS))
        claims = {**opened.public_claims, **opened.restricted_claims}
        fields = self._fields(claims)
        self.assertNotIn("Age", fields)
        self.assertNotIn("36", fields.values())
        self.assertEqual(fields["Date of Birth"], "01/15/1990")
        self.assertEqual(claims[wire.T_DOCUMENT_HASH],
                         credentials.document_digest(self.ROWS))

    def test_a_minted_credential_opens_and_verifies(self):
        from ovcrypto import verifier, wire

        opened = self._open(self._mint())
        self.assertEqual(opened.verdict, verifier.Verdict.VALID)
        claims = {**opened.public_claims, **opened.restricted_claims}
        self.assertEqual(self._fields(claims)["Last Name"], "DELA CRUZ")
        self.assertEqual(claims[wire.T_DOC_NUMBER].decode(), self.UUID)

    def test_the_issuer_is_named_in_full_not_by_a_code(self):
        """The name, deliberately, not a code.

        A code would save ~40 characters of a budget already at its limit,
        and it would outlive a rename. But a code the reader cannot expand is
        worth nothing to the person holding the phone, and what the
        credential records is what the organization was called when it was
        issued -- arguably the more truthful answer.
        """
        from ovcrypto import wire

        claims = self._open(self._mint()).public_claims
        self.assertEqual(claims[wire.T_ISSUER_ID].decode(),
                         "Philippine Statistics Authority")

    def test_the_uuid_is_readable_in_the_clear_and_signed_inside(self):
        """A QR carries one string and the credential is ciphertext, so the
        UUID rides in front for a plain camera -- and inside as doc_number,
        where it is signed, so the visible half cannot be swapped."""
        from ovcrypto import wire

        minted = self._mint()
        head, _, _ = minted["qr"].partition(":CL03:")
        self.assertEqual(head, self.UUID.upper())
        self.assertEqual(
            self._open(minted).public_claims[wire.T_DOC_NUMBER].decode(),
            self.UUID)

    def test_a_public_tier_device_verifies_without_reading_the_person(self):
        from ovcrypto import verifier

        opened = self._open(self._mint(), restricted=False)
        self.assertEqual(opened.verdict, verifier.Verdict.VALID)
        self.assertFalse(opened.restricted_claims)

    # -- what goes in -----------------------------------------------------

    def test_the_credential_carries_what_the_organization_displays(self):
        from ovcrypto import wire

        rows = everify_fields.default_rows()
        for row in rows:
            if row["key"] == "place_of_birth":
                row["display"] = False
        fields = self._fields(
            self._open(self._mint(field_rows=rows)).restricted_claims)
        self.assertNotIn("Place of Birth", fields)
        self.assertIn("Last Name", fields)

    def test_a_renamed_field_still_reaches_the_credential(self):
        """Claims key off eVerify's key, never the label -- the same rule the
        rest of the pipeline follows."""
        from ovcrypto import wire

        rows = [dict(r) for r in self.ROWS]
        rows[2]["key"] = "Apelyido"
        fields = self._fields(
            self._open(self._mint(rows=rows)).restricted_claims)
        # Carried, and carried under the NEW label -- the list is what the
        # page shows, so a renamed column is renamed on the phone too.
        self.assertEqual(fields["Apelyido"], "DELA CRUZ")

    def test_the_birth_date_survives_the_page_reformat(self):
        """_prepare_data_for_frontend rewrites it to MM/DD/YYYY, so by the
        time a row is logged it is no longer the ISO string eVerify sent."""
        from ovcrypto import wire

        for value in ("01/15/1990", "1990-01-15"):
            rows = [dict(r) for r in self.ROWS]
            for row in rows:
                if row["field"] == "birth_date":
                    row["value"] = value
            fields = self._fields(
                self._open(self._mint(rows=rows)).restricted_claims)
            self.assertEqual(fields["Date of Birth"], value, value)

    def test_altering_a_printed_value_changes_the_document_hash(self):
        altered = [dict(r) for r in self.ROWS]
        altered[2]["value"] = "DELA CRUZA"
        self.assertNotEqual(credentials.document_digest(altered),
                            credentials.document_digest(self.ROWS))

    def test_renaming_a_field_does_not_change_the_document_hash(self):
        """Renaming is presentation. It must not invalidate a credential
        already in somebody's hand."""
        renamed = [dict(r) for r in self.ROWS]
        renamed[0]["key"] = "Pangalan"
        self.assertEqual(credentials.document_digest(renamed),
                         credentials.document_digest(self.ROWS))

    # -- size -------------------------------------------------------------

    def test_the_whole_qr_stays_inside_the_alphanumeric_charset(self):
        """Byte mode would cost ~45% of the capacity and push the stamp past
        45 mm, so nothing lowercase or punctuated may reach the string."""
        allowed = set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:")
        stray = sorted(set(self._mint()["qr"]) - allowed)
        self.assertEqual(stray, [], "outside the QR alphanumeric charset")

    #: Deliberately not "JUAN DELA CRUZ". A short name lands at exactly QR
    #: version 18's capacity with nothing to spare, so a size test built on
    #: one passes while ordinary documents fail in the field.
    LONG_ROWS = [
        {"field": "first_name", "key": "Given Name",
         "value": "MA. ANGELICA THERESA", "show": True},
        {"field": "middle_name", "key": "Middle Name",
         "value": "VILLANUEVA", "show": True},
        {"field": "last_name", "key": "Last Name",
         "value": "MACAPAGAL-ARROYO", "show": True},
        {"field": "reference", "key": "National ID Card Number",
         "value": "1111-2222-3333-4444", "show": True},
        {"field": "code", "key": "Digital National ID Number",
         "value": "ABC1234", "show": True},
        {"field": "gender", "key": "Sex", "value": "Female", "show": True},
        {"field": "birth_date", "key": "Date of Birth",
         "value": "01/15/1990", "show": True},
        {"field": "place_of_birth", "key": "Place of Birth",
         "value": "SAN ANTONIO, SAN FERNANDO, PAMPANGA", "show": True},
        # The tail of the default display list: the addresses are the longest
        # values eVerify returns, and a stamp figure measured without them
        # comes from convenient sample data.
        {"field": "marital_status", "key": "Marital Status",
         "value": "Married", "show": True},
        {"field": "full_address", "key": "Permanent Address",
         "value": "123 KATIPUNAN AVENUE, BARANGAY LOYOLA HEIGHTS, "
                  "QUEZON CITY, METRO MANILA 1108", "show": True},
        {"field": "present_full_address", "key": "Present Address",
         "value": "456 E. RODRIGUEZ SR. AVENUE, BARANGAY KRISTONG HARI, "
                  "QUEZON CITY, METRO MANILA 1112", "show": True},
        {"field": "blood_type", "key": "Blood Type", "value": "O+",
         "show": True},
    ]

    def test_it_fits_the_stamp_the_document_prints(self):
        """With the whole default display set, not a convenient subset."""
        minted = self._mint(rows=self.LONG_ROWS)
        # fits_at_stamp, not an arithmetic comparison of the rounded numbers.
        # A stamp of 46.8 mm against a rounded minimum of 46.8 would pass a
        # comparison while reporting itself unscannable: 46.8 / 117 modules is
        # a hair under 0.4 mm in binary floating point. Ask the question the
        # printer actually asks.
        self.assertTrue(
            minted["fits_at_stamp"],
            "needs %.1f mm but the document prints %.1f -- carry fewer "
            "fields, or raise STAMP_MM and the printed stamp with it"
            % (minted["min_stamp_mm"], credentials.STAMP_MM))

    def test_the_location_claim_stays_bounded(self):
        """Location.name is a 255-character field feeding a claim on a payload
        already at the printable limit.

        It now travels as the NAME rather than the code, because a code the
        reader cannot expand is worth nothing to them -- but the cap still has
        to hold, or one long desk name pushes the stamp past what the page
        prints. mint() caps whatever it is handed."""
        from ovcrypto import wire

        claims = self._open(self._mint(
            location="East Avenue District Office " + "x" * 200)).public_claims
        carried = claims[wire.T_ISSUER_LOCATION].decode()
        self.assertLessEqual(len(carried), credentials.MAX_TEXT)
        self.assertTrue(carried.startswith("East Avenue District Office"))

    def test_a_name_becomes_a_short_code_at_creation(self):
        org = make_org(name="Codes", locations=())
        first = Location.objects.create(
            organization=org, name="East Avenue Office",
            code=next_location_code(org, "East Avenue Office"))
        self.assertEqual(first.code, "EAO")
        # A second location whose initials collide is told apart.
        self.assertEqual(next_location_code(org, "East Ayala Office"), "EAO2")
        # Another organization is free to reuse it.
        other = make_org(name="Elsewhere", locations=())
        self.assertEqual(next_location_code(other, "East Avenue Office"), "EAO")

    def test_no_location_simply_leaves_the_claim_out(self):
        from ovcrypto import wire

        claims = self._open(self._mint(location="")).public_claims
        self.assertNotIn(wire.T_ISSUER_LOCATION, claims)

    # ---- attachments and the cap on QR codes ----

    def _mint_with(self, attachments, portrait=b"the rendered portrait"):
        return credentials.mint(
            self.ROWS, organization=self.org, location_code="EASTAV",
            document_uuid=self.UUID, epoch_keys=self.epoch_keys,
            signer=self.signer, issued_at=self.issued, expires_at=self.expires,
            portrait=portrait, attachments=attachments)

    def _split(self, size=2000):
        from ovcrypto import attachments
        return attachments.Attachment("Scan", "application/octet-stream",
                                      os.urandom(size), restricted=True)

    def test_a_document_prints_two_codes_at_most_by_default(self):
        """The credential and its portrait: an attachment rides inline or the
        document is refused, before anything is signed."""
        from ovcrypto import attachments
        self.assertEqual(settings.CREDENTIAL_MAX_QR_CODES, 2)
        with self.assertRaisesRegex(credentials.CredentialError, "at most 0"):
            self._mint_with([self._split()])
        minted = self._mint_with([attachments.Attachment(
            "Note", "text/plain", b"carried inline", inline=True)])
        self.assertEqual(minted["attachment_parts"], {})
        result = self._open(minted)
        self.assertTrue(result.ok, result.detail)
        self.assertEqual([e.content for e in result.attachments], [b"carried inline"])

    def test_without_a_portrait_two_codes_leave_one_part(self):
        from ovcrypto import attachments
        minted = self._mint_with([attachments.Attachment(
            "Note", "text/plain", b"a short note")], portrait=None)
        self.assertEqual([len(p) for p in minted["attachment_parts"].values()], [1])

    @override_settings(CREDENTIAL_MAX_QR_CODES=0)
    def test_with_no_cap_split_content_is_printed_beside_the_credential(self):
        from ovcrypto import attachments
        scan = self._split(3000)
        minted = self._mint_with([scan])
        parts = minted["attachment_parts"][1]
        self.assertGreater(len(parts), 1)
        collector = attachments.Collector.for_result(self._open(minted))
        for text in parts:
            self.assertEqual(collector.take(text), collector.TAKEN)
        self.assertEqual(collector.outcome(1).content, scan.content)

    def test_minting_without_attachments_is_unchanged(self):
        minted = self._mint_with(None)
        self.assertEqual(minted["attachment_parts"], {})
        self.assertEqual(self._open(minted).attachments, [])



class LocationCodeTest(TestCase):
    """The short code a credential names a desk by.

    Location.name is a 255-character field, and the credential's
    issuer_location claim rides on a QR payload already at the limit of what
    a printed stamp can carry.
    """

    def setUp(self):
        self.org = make_org(name="Alpha", locations=())
        self.admin = User.objects.create(
            national_id_card_number="1111222233334444", given_name="Ada")
        join(self.org, self.admin, Membership.ROLE_ADMIN)
        session = self.client.session
        session[SESSION_KEY] = self.admin.id
        session[ORG_SESSION_KEY] = self.org.id
        session.save()

    def _add(self, name):
        return self.client.post(
            "/app/admin/add-location/", data=json.dumps({"name": name}),
            content_type="application/json")

    def _set_code(self, location, code):
        return self.client.post(
            "/app/admin/update-location/",
            data=json.dumps({"id": location.id, "code": code}),
            content_type="application/json")

    def test_adding_a_location_assigns_a_code(self):
        self._add("East Avenue Office")
        self.assertEqual(Location.objects.get(name="East Avenue Office").code,
                         "EAO")

    def test_colliding_locations_get_different_codes(self):
        self._add("East Avenue Office")
        self._add("East Ayala Office")
        codes = set(Location.objects.filter(
            organization=self.org).values_list("code", flat=True))
        self.assertEqual(codes, {"EAO", "EAO2"})

    def test_a_code_outside_the_qr_charset_is_refused(self):
        """Lowercase is not here: it is normalised upward, like the issuer
        code, because a typed-in code arriving in the wrong case is a slip and
        not a decision. Anything that cannot be normalised INTO the charset is
        refused -- a space or a hyphen would force the QR into byte mode."""
        self._add("Main Office")
        location = Location.objects.get(name="Main Office")
        for bad in ("M O", "TOOLONG", "M-O", "M.O"):
            response = self._set_code(location, bad)
            self.assertEqual(response.status_code, 400, bad)
            location.refresh_from_db()
            self.assertEqual(location.code, "MO", bad)

    def test_a_code_is_uppercased_and_saved(self):
        self._add("Main Office")
        location = Location.objects.get(name="Main Office")
        self.assertEqual(self._set_code(location, "hq1").status_code, 200)
        location.refresh_from_db()
        self.assertEqual(location.code, "HQ1")

    def test_two_desks_in_one_organization_cannot_share_a_code(self):
        self._add("Main Office")
        self._add("Second Desk")
        second = Location.objects.get(name="Second Desk")
        response = self._set_code(second, "MO")
        self.assertEqual(response.status_code, 400)
        self.assertIn("already used", json.loads(response.content)["message"])

    def test_another_organization_may_reuse_the_code(self):
        """Unique within an organization, like the name -- two organizations
        will both want a Main Office."""
        self._add("Main Office")
        other = make_org(name="Beta", locations=())
        Location.objects.create(organization=other, name="Their Desk",
                                code="MO")
        self.assertEqual(
            Location.objects.filter(code="MO").count(), 2)


WRAP_KEY_HEX = "00112233445566778899aabbccddeeff" * 2


@override_settings(CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX,
                   CREDENTIAL_GENESIS=1750000000,
                   CREDENTIAL_EPOCH_SECONDS=2592000,
                   CREDENTIAL_OVERLAP_EPOCHS=3)
class CredentialKeyServiceTest(TestCase):
    """Epoch numbering and key custody.

    These numbers are NOT this app's to choose: they are the sibling
    OfflineVerifier deployment's, and a credential is permanently bound to the
    epoch number they produce. A different genesis silently renumbers
    everything and phones report device_stale for good documents.
    """

    def setUp(self):
        credential_keys.reset_caches()
        self.addCleanup(credential_keys.reset_caches)

    def test_the_epoch_schedule_matches_the_shipped_policy(self):
        """Genesis, 30-day epochs. Checked against a fixed timestamp so a
        change to any of the three fails here rather than in the field."""
        self.assertEqual(credential_keys.epoch_at(1750000000), 0)
        self.assertEqual(credential_keys.epoch_at(1750000000 + 2592000), 1)
        # A timestamp well inside epoch 14.
        self.assertEqual(credential_keys.epoch_at(1787000000), 14)
        self.assertEqual(credential_keys.epoch_start(14), 1786288000)

    def test_a_key_outlives_its_issuing_window_by_the_overlap(self):
        """Devices must still open what was minted under it. Three overlap
        epochs is why an offline credential is readable for roughly 90-120
        days and not for the year its expires_at claims."""
        end = credential_keys.epoch_end(14)
        self.assertEqual(credential_keys.readable_until(14),
                         end + 3 * 2592000)

    def test_epoch_keys_are_created_once_and_reused(self):
        first = credential_keys.epoch_key_row(14, credential_keys.TIER_PUBLIC)
        again = credential_keys.epoch_key_row(14, credential_keys.TIER_PUBLIC)
        self.assertEqual(first.pk, again.pk)
        self.assertEqual(CredentialEpochKey.objects.count(), 1)

    def test_the_private_half_is_stored_wrapped_not_raw(self):
        """db.sqlite3 rides the off-site database backups."""
        row = credential_keys.epoch_key_row(14, credential_keys.TIER_PUBLIC)
        stored = bytes(row.wrapped_private_key)
        self.assertNotEqual(len(stored), 32, "looks like a raw X25519 key")
        recovered = credential_keys.private_key(row)
        self.assertEqual(len(recovered), 32)
        self.assertNotIn(recovered, stored)

    def test_the_public_half_matches_the_private_one(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey)

        row = credential_keys.epoch_key_row(14, credential_keys.TIER_RESTRICTED)
        private = X25519PrivateKey.from_private_bytes(
            credential_keys.private_key(row))
        self.assertEqual(
            private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            bytes(row.public_key))

    def test_issuing_keys_uses_the_current_epoch_and_both_tiers(self):
        keys = credential_keys.issuing_keys()
        self.assertEqual(keys.epoch, credential_keys.current_epoch())
        self.assertIsNotNone(keys.public_tier)
        self.assertIsNotNone(keys.restricted_tier)
        self.assertEqual(CredentialEpochKey.objects.count(), 2)

    def test_the_wrapping_key_may_be_hex_base64_or_raw(self):
        """One value should paste into both deployments without anybody
        having to work out which encoding the other one wanted."""
        import base64

        raw = bytes.fromhex(WRAP_KEY_HEX)
        # Not raw bytes: an environment variable is text, and arbitrary key
        # bytes do not survive the round trip. OfflineVerifier accepts them
        # because it reads a file.
        for form in (WRAP_KEY_HEX, base64.b64encode(raw).decode()):
            with override_settings(CREDENTIAL_EPOCH_WRAP_KEY=form):
                credential_keys.reset_caches()
                self.assertEqual(credential_keys._wrapper().key, raw)

    def test_a_missing_wrapping_key_is_refused_not_invented(self):
        """Generating one would orphan every epoch key already stored."""
        with override_settings(CREDENTIAL_EPOCH_WRAP_KEY=""):
            credential_keys.reset_caches()
            with self.assertRaises(credentials.CredentialError):
                credential_keys._wrapper()

    def test_a_short_wrapping_key_is_refused(self):
        with override_settings(CREDENTIAL_EPOCH_WRAP_KEY="aabbcc"):
            credential_keys.reset_caches()
            with self.assertRaises(credentials.CredentialError):
                credential_keys._wrapper()

    def test_configured_reports_what_is_missing(self):
        with override_settings(CREDENTIAL_ISSUER_KEY_PATH="",
                               CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX):
            self.assertFalse(credential_keys.configured())
        with override_settings(CREDENTIAL_ISSUER_KEY_PATH="/x/key.pem",
                               CREDENTIAL_EPOCH_WRAP_KEY=""):
            self.assertFalse(credential_keys.configured())
        with override_settings(CREDENTIAL_ISSUER_KEY_PATH="/x/key.pem",
                               CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX):
            self.assertTrue(credential_keys.configured())


class LoadCredentialKeysTest(TestCase):
    """The command that pre-loads an OfflineVerifier deployment's keys.

    It refuses rather than guesses, because both things it copies fail
    silently: a mismatched issuer key produces credentials that read as
    `forged`, and a mismatched epoch policy produces `device_stale` -- neither
    with any symptom until a document is already printed and presented.
    """

    def setUp(self):
        credential_keys.reset_caches()
        self.addCleanup(credential_keys.reset_caches)
        self.source = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.source, True)
        self.target = os.path.join(tempfile.mkdtemp(), "issuer.pem")
        self.addCleanup(shutil.rmtree, os.path.dirname(self.target), True)

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        self.key = ec.generate_private_key(ec.SECP256R1())
        self.pem_path = os.path.join(self.source, "dev-issuer-key.pem")
        with open(self.pem_path, "wb") as handle:
            handle.write(self.key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        self.spki = self.key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        self._write_env()
        self._write_db(self.spki)

    def _write_env(self, genesis=1750000000, epoch_seconds=2592000,
                   overlap=3):
        with open(os.path.join(self.source, ".env"), "w",
                  encoding="utf-8") as handle:
            handle.write(
                "# a comment\n"
                "OV_GENESIS=%d\nOV_EPOCH_SECONDS=%d\nOV_OVERLAP_EPOCHS=%d\n"
                "OV_ISSUER_KEY_ID=1\nOV_EPOCH_WRAP_KEY=%s\n"
                % (genesis, epoch_seconds, overlap, WRAP_KEY_HEX))

    def _write_db(self, spki, epoch_rows=2):
        import sqlite3

        from ovcrypto import keystore as ks
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey)

        path = os.path.join(self.source, "db.sqlite3")
        if os.path.exists(path):
            os.remove(path)          # a test may rewrite it with another key
        connection = sqlite3.connect(path)
        connection.execute(
            "create table keys_issuerkey (key_id int, spki_der blob, "
            "is_active int, not_before text, not_after text)")
        connection.execute(
            "insert into keys_issuerkey values (?, ?, 1, ?, ?)",
            (1, spki, "2026-08-18 13:58:06", "2028-08-17 14:03:06"))
        connection.execute(
            "create table keys_epochkey (epoch int, tier int, "
            "public_key blob, wrapped_private_key blob, not_before text, "
            "not_after text)")
        wrapper = ks.FileKeyWrapper(bytes.fromhex(WRAP_KEY_HEX))
        for index in range(epoch_rows):
            private = X25519PrivateKey.generate()
            raw = private.private_bytes(serialization.Encoding.Raw,
                                        serialization.PrivateFormat.Raw,
                                        serialization.NoEncryption())
            connection.execute(
                "insert into keys_epochkey values (?, ?, ?, ?, ?, ?)",
                (14, index,
                 private.public_key().public_bytes(
                     serialization.Encoding.Raw,
                     serialization.PublicFormat.Raw),
                 wrapper.wrap(raw),
                 "2026-08-09 15:06:40", "2026-12-07 15:06:40"))
        connection.commit()
        connection.close()

    def _run(self, **kwargs):
        out = StringIO()
        call_command("load_credential_keys", "--from", self.source,
                     "--key-path", self.target, stdout=out, **kwargs)
        return out.getvalue()

    @override_settings(CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX)
    def test_it_copies_the_key_and_imports_the_epochs(self):
        output = self._run()
        self.assertIn("epoch policy matches", output)
        self.assertIn("registration matches the PEM", output)
        self.assertTrue(os.path.exists(self.target))
        self.assertEqual(CredentialEpochKey.objects.count(), 2)

    @override_settings(CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX)
    def test_the_imported_epoch_windows_are_read_as_utc(self):
        """Their rows are UTC, written naive. Stored through Django with
        USE_TZ on, a naive value is read in the LOCAL zone -- which on a box
        set to Asia/Manila moved every window eight hours early, so this app
        would stop shipping an epoch key eight hours before it expires."""
        import datetime as dt

        self._run()
        row = CredentialEpochKey.objects.first()
        self.assertEqual(
            row.not_before.astimezone(dt.timezone.utc),
            dt.datetime(2026, 8, 9, 15, 6, 40, tzinfo=dt.timezone.utc))
        self.assertEqual(
            row.not_after.astimezone(dt.timezone.utc),
            dt.datetime(2026, 12, 7, 15, 6, 40, tzinfo=dt.timezone.utc))

    @override_settings(CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX)
    def test_a_dry_run_really_does_write_nothing(self):
        """--dry-run says "Dry run: nothing written", and that has to be true
        of the trust entry too: whoever reaches for it is doing so on a box
        where being wrong about that matters."""
        from accounts.models import IssuerKey

        output = self._run(dry_run=True)
        self.assertIn("Dry run: nothing written", output)
        self.assertEqual(IssuerKey.objects.count(), 0)
        self.assertEqual(CredentialEpochKey.objects.count(), 0)
        self.assertFalse(os.path.exists(self.target))

    @override_settings(CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX)
    def test_the_imported_private_halves_are_the_same_keys(self):
        """Re-wrapped under this app's key, but the same key material -- or a
        phone could not open what this app mints."""
        import sqlite3

        from ovcrypto import keystore as ks

        self._run()
        theirs = ks.FileKeyWrapper(bytes.fromhex(WRAP_KEY_HEX))
        connection = sqlite3.connect(os.path.join(self.source, "db.sqlite3"))
        for epoch, tier, wrapped in connection.execute(
                "select epoch, tier, wrapped_private_key from keys_epochkey"):
            row = CredentialEpochKey.objects.get(epoch=epoch, tier=tier)
            self.assertEqual(credential_keys.private_key(row),
                             theirs.unwrap(bytes(wrapped)))
        connection.close()

    @override_settings(CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX)
    def test_a_dry_run_changes_nothing(self):
        self._run(dry_run=True)
        self.assertFalse(os.path.exists(self.target))
        self.assertEqual(CredentialEpochKey.objects.count(), 0)

    @override_settings(CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX,
                       CREDENTIAL_GENESIS=1600000000)
    def test_a_mismatched_epoch_policy_is_refused(self):
        """The failure this prevents has no symptom: every epoch number
        shifts, and phones call good documents device_stale."""
        with self.assertRaises(CommandError) as caught:
            self._run()
        self.assertIn("epoch policy", str(caught.exception).lower())
        self.assertEqual(CredentialEpochKey.objects.count(), 0)

    @override_settings(CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX)
    def test_a_pem_that_is_not_the_registered_key_is_refused(self):
        """A pasted key is exactly how a deployment ends up signing with
        something no phone trusts."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        other = ec.generate_private_key(ec.SECP256R1())
        self._write_db(other.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        with self.assertRaises(CommandError) as caught:
            self._run()
        self.assertIn("NOT this PEM", str(caught.exception))

    @override_settings(CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX)
    @skipIf(os.name != "posix",
            "Windows chmod only moves the read-only bit, so the group and "
            "other bits mean nothing here; this is asserted where it matters")
    def test_the_copied_key_is_not_group_readable(self):
        self._run()
        mode = stat.S_IMODE(os.stat(self.target).st_mode)
        self.assertEqual(mode & (stat.S_IRWXG | stat.S_IRWXO), 0)


class DocumentCredentialTest(TestCase):
    """Logging a verification mints the credential its document QR carries.

    The QR the page draws is `UUID:CL03:<credential>`. It begins with the same
    transaction id it always did, so a plain camera reads what it always read
    and the online check at /validate/ never depends on any of this.
    """

    ROWS = [
        {"field": "first_name", "key": "Given Name", "value": "JUAN", "show": True},
        {"field": "last_name", "key": "Last Name", "value": "DELA CRUZ", "show": True},
        {"field": "reference", "key": "National ID Card Number",
         "value": "1111-2222-3333-4444", "show": True},
        {"field": "code", "key": "Digital National ID Number",
         "value": "ABC1234", "show": True},
        {"field": "place_of_birth", "key": "Place of Birth",
         "value": "Quezon City", "show": True},
    ]

    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        credential_keys.reset_caches()
        self.addCleanup(credential_keys.reset_caches)

        self.org = make_org(name="Philippine Statistics Authority")
        self.org.issuer_code = "PSA"
        self.org.save(update_fields=["issuer_code"])
        self.location = self.org.locations.first()
        self.location.code = "MAIN"
        self.location.save(update_fields=["code"])
        self.user = User.objects.create(
            national_id_card_number="1111222233334444", given_name="Ada")
        join(self.org, self.user, Membership.ROLE_ADMIN)
        self.type = TransactionType.objects.create(
            organization=self.org, name="New Enrollment")

        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.pem = os.path.join(self.dir, "issuer.pem")
        self.key = ec.generate_private_key(ec.SECP256R1())
        with open(self.pem, "wb") as handle:
            handle.write(self.key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        os.chmod(self.pem, stat.S_IRUSR | stat.S_IWUSR)

        session = self.client.session
        session[SESSION_KEY] = self.user.id
        session[ORG_SESSION_KEY] = self.org.id
        session["operator_location"] = str(self.location.id)
        session.save()

    def _log(self, rows=None):
        rows = rows if rows is not None else self.ROWS
        keep_answer(self.client, self.org, rows)
        return self.client.post(
            "/everify/log-transaction/",
            data=json.dumps({
                "transaction_type": str(self.type.id),
                "verification_data": rows}),
            content_type="application/json")

    def _configured(self, **extra):
        settings_kwargs = dict(
            CREDENTIAL_ISSUER_KEY_PATH=self.pem,
            CREDENTIAL_ISSUER_KEY_ID=1,
            CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX)
        settings_kwargs.update(extra)
        return override_settings(**settings_kwargs)

    # -- Demo Mode reaches the credential ----------------------------------

    DEMO_ROWS = [
        {"field": "first_name", "key": "Given Name",
         "value": "MA. ANGELICA THERESA", "show": True},
        {"field": "middle_name", "key": "Middle Name",
         "value": "VILLANUEVA", "show": True},
        {"field": "reference", "key": "National ID Card Number",
         "value": "1234-5678-9012-3456", "show": True},
        {"field": "code", "key": "Digital National ID Number",
         "value": "CWD0842", "show": True},
        {"field": "birth_date", "key": "Date of Birth",
         "value": "05/14/1990", "show": True},
    ]

    def _demo(self, on=True):
        from accounts.models import UserSettings

        UserSettings.objects.update_or_create(user=self.user,
                                              defaults={"demo_mode": on})

    def test_a_demo_credential_carries_the_masked_values(self):
        """The page is masked and the credential rides ON the page, in a
        symbol beside the bullets. Unmasked, it would carry the real name,
        birth date and ID numbers -- anybody in the audience with the
        verifier app could read what the projector hides.

        Same conventions, because it is literally the same function the page
        renders through: first word of a given name, a National ID down to its
        last character, a birth date outright."""
        from ovcrypto import wire

        self._demo(True)
        with self._configured():
            claims = self._claims(
                json.loads(self._log(self.DEMO_ROWS).content))

        fields = dict(wire.decode_fields(claims.get(wire.T_FIELDS, b"")))
        self.assertNotIn("ANGELICA", fields["Given Name"])
        self.assertTrue(fields["Given Name"].startswith("MA."))
        self.assertNotIn("VILLANUEVA", fields["Middle Name"])
        self.assertNotIn("1234", fields["National ID Card Number"])
        self.assertNotIn("05/14/1990", fields["Date of Birth"])
        # ...and the identifiers keep their last character, as on screen.
        self.assertTrue(fields["National ID Card Number"].endswith("6"))

    def test_the_operator_is_masked_in_the_credential_too(self):
        """The document's own footer already masks whoever ran the
        verification, and the credential names them as well."""
        from ovcrypto import wire

        # A surname to lose: mask_name keeps the first word, so a one-word
        # operator is a test that passes while proving nothing.
        self.user.last_name = "Lovelace"
        self.user.save(update_fields=["last_name"])

        self._demo(True)
        with self._configured():
            claims = self._claims(
                json.loads(self._log(self.DEMO_ROWS).content))

        operator = claims.get(wire.T_OPERATOR, b"").decode()
        self.assertIn(DEMO_MASK_CHAR, operator)
        self.assertNotIn("Lovelace", operator)
        self.assertTrue(operator.startswith("Ada"))

    FACE_ROW = {"field": "face_url", "key": "Face Photo", "show": True}

    def _face(self):
        return dict(self.FACE_ROW, value=(
            "data:image/png;base64," + base64.b64encode(
                (settings.BASE_DIR / "static" / "mock-face.png").read_bytes()
            ).decode()))

    def test_the_face_is_resampled_away_rather_than_filtered(self):
        """Masking the text and leaving the face would move the leak, not
        close it -- the picture rides its own symbol beside the credential and
        carries it in full.

        And the distinction between resampling and blurring is the point. A
        blur is a FILTER: it attenuates detail and can be partly undone. This
        resamples to a 10 x 10 grid and enlarges again, which throws the
        information away.

        Tested by the mechanism rather than by how much detail is left,
        because "how much" depends on the face: on the cartoon in static/ the
        redaction leaves 0.05 per cent, but on five real captures it leaves
        0.6 to 1.1, and a 5 x 5 Gaussian leaves 3. A threshold that
        separated those two on one image would not on the other.

        So: an image that has ALREADY been reduced to a 10 x 10 grid is
        barely changed by being reduced again. A blurred one is changed,
        because it still holds detail finer than the grid. Measured -- 5.0
        against 14 to 16."""
        import cv2
        import numpy as np

        def decode(blob):
            return cv2.imdecode(np.frombuffer(blob, np.uint8),
                                cv2.IMREAD_GRAYSCALE)

        def resample(image):
            px = credentials.PORTRAIT_REDACT_PX
            small = cv2.resize(image, (px, px), interpolation=cv2.INTER_AREA)
            return cv2.resize(small, (image.shape[1], image.shape[0]),
                              interpolation=cv2.INTER_CUBIC)

        face = self._face()["value"]
        plain = credentials.render_portrait(face)
        redacted = credentials.render_portrait(face, redact=True)
        self.assertIsNotNone(plain)
        self.assertIsNotNone(redacted)
        self.assertNotEqual(plain, redacted)

        red = decode(redacted)
        survives = float(np.mean(np.abs(
            red.astype(float) - resample(red).astype(float))))

        blurred = cv2.GaussianBlur(decode(plain), (5, 5), 0)
        filtered = float(np.mean(np.abs(
            blurred.astype(float) - resample(blurred).astype(float))))

        self.assertLess(survives, 8.0,
                        "the redacted face is not a resample")
        self.assertGreater(filtered, survives * 2,
                           "the measure no longer tells a filter from a "
                           "resample; re-derive the threshold")

    def test_the_portrait_symbol_is_actually_redacted_in_demo_mode(self):
        """The mechanism being right is worth nothing if the mint does not ask
        for it. Two verifications of the same face, demo on and off: the
        images must differ."""
        rows = self.DEMO_ROWS + [self._face()]

        def portrait_of(response):
            body = json.loads(response.content)
            # CL03F1:<credential uuid>:<base45>. The uuid is fresh every time,
            # so compare the image and not the whole payload.
            return body["portrait_qr"].split(":", 2)[2]

        with self._configured():
            self._demo(False)
            plain = portrait_of(self._log(rows))
            self._demo(True)
            redacted = portrait_of(self._log(rows))

        self.assertNotEqual(plain, redacted,
                            "the portrait symbol carries the real face while "
                            "the page beside it is masked")

    def test_a_demo_verification_is_still_logged_truthfully(self):
        """The split that was already there and must stay: the PAGE is masked,
        the LOG is not. What changed is which side the credential is on -- it
        rides on the page, so it follows the page.

        If this ever fails, Demo Mode has started writing bullets into the
        transaction record, and an organization's log is fiction."""
        self._demo(True)
        with self._configured():
            self._log(self.DEMO_ROWS)

        txn = Transaction.objects.latest("verification_timestamp")
        self.assertEqual(txn.given_name, "MA. ANGELICA THERESA")
        self.assertEqual(txn.national_id_card_number, "1234567890123456")
        self.assertNotIn(DEMO_MASK_CHAR, txn.given_name)
        self.assertNotIn(DEMO_MASK_CHAR, txn.middle_name)

    def test_without_demo_mode_the_credential_is_unchanged(self):
        """The redaction is not a new default -- an ordinary verification puts
        the real values in the credential, which is the entire point of it."""
        from ovcrypto import wire

        self._demo(False)
        with self._configured():
            claims = self._claims(
                json.loads(self._log(self.DEMO_ROWS).content))

        fields = dict(wire.decode_fields(claims.get(wire.T_FIELDS, b"")))
        self.assertEqual(fields["Given Name"], "MA. ANGELICA THERESA")
        self.assertEqual(fields["Date of Birth"], "05/14/1990")

    def test_the_browser_does_not_decide_whether_to_redact(self):
        """Read from the OPERATOR on the server. A page that told the server
        whether to redact would be a page that could tell it not to -- and the
        request that mints the credential is one the browser composes.

        One flag, read a single time, governing BOTH the credential and the
        card the holder saves to their phone. Two reads could disagree."""
        source = (settings.BASE_DIR / "verify" / "views"
                  / "everify.py").read_text(encoding="utf-8")
        self.assertIn("demo_mode = demo_mode_for(user)", source)
        self.assertIn("demo_mode=demo_mode)", source)
        self.assertIn("_card_rows(answer, rows, "
                      "demo_mode=demo_mode)", source)
        self.assertNotIn('data.get("demo_mode"', source)
        self.assertNotIn('data.get("redact"', source)

    # -- the happy path ---------------------------------------------------

    def test_logging_a_verification_returns_a_credential_qr(self):
        with self._configured():
            body = json.loads(self._log().content)
        self.assertEqual(body["status"], "ok")
        self.assertIn("qr", body)
        self.assertTrue(body["qr"].startswith(body["transaction_id"].upper()))
        self.assertIn(":CL03:", body["qr"])

    def test_the_credential_opens_and_names_the_transaction(self):
        import time

        from ovcrypto import verifier, wire

        with self._configured():
            body = json.loads(self._log().content)
            keys = credential_keys.issuing_keys()
            rows = {
                tier: credential_keys.epoch_key_row(keys.epoch, tier)
                for tier in (credential_keys.TIER_PUBLIC,
                             credential_keys.TIER_RESTRICTED)}
            signer = credential_keys.signer()

        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey)

        device = {keys.epoch: verifier.EpochPrivateKeys(
            keys.epoch,
            X25519PrivateKey.from_private_bytes(
                credential_keys.private_key(rows[credential_keys.TIER_PUBLIC])),
            X25519PrivateKey.from_private_bytes(
                credential_keys.private_key(
                    rows[credential_keys.TIER_RESTRICTED])))}
        opened = verifier.verify(
            "CL03:" + body["qr"].split(":CL03:", 1)[1],
            epoch_keys=device,
            trust_list=verifier.TrustList.bare({1: signer.public_key_der()}),
            now=int(time.time()))

        self.assertEqual(opened.verdict, verifier.Verdict.VALID)
        claims = {**opened.public_claims, **opened.restricted_claims}
        self.assertEqual(claims[wire.T_DOC_NUMBER].decode(),
                         body["transaction_id"])
        # Names, in full, because a code the reader cannot expand tells
        # them nothing about the document in their hand.
        self.assertEqual(claims[wire.T_ISSUER_ID].decode(),
                         self.org.name)
        self.assertEqual(claims[wire.T_ISSUER_LOCATION].decode(),
                         self.location.name)
        fields = dict(wire.decode_fields(claims[wire.T_FIELDS]))
        self.assertEqual(fields["Last Name"], "DELA CRUZ")

    def test_every_credential_is_recorded_so_it_can_be_revoked(self):
        """One that exists in the world and not in this table cannot be
        withdrawn, and the QR is already on its way to a printer."""
        with self._configured():
            body = json.loads(self._log().content)
        record = IssuedCredential.objects.get()
        self.assertEqual(str(record.credential_id), body["credential_id"])
        self.assertEqual(str(record.document_uuid), body["transaction_id"])
        self.assertEqual(record.organization, self.org)
        self.assertEqual(record.transaction, Transaction.objects.get())
        self.assertEqual(record.epoch, credential_keys.current_epoch())
        self.assertIsNone(record.registered_at,
                          "not yet pushed to the verifier fleet")

    def test_the_credential_carries_what_the_organization_displays(self):
        from ovcrypto import wire

        field_rows = everify_fields.default_rows()
        for row in field_rows:
            if row["key"] == "place_of_birth":
                row["display"] = False
        for row in field_rows:
            OrganizationFieldSetting.objects.update_or_create(
                organization=self.org, key=row["key"],
                defaults={"display_name": "",
                          "show_on_document": row["display"],
                          "include_in_log": row["log"],
                          "position": row["position"]})
        with self._configured():
            body = json.loads(self._log().content)
        self.assertIn(":CL03:", body["qr"])
        # Decrypting is covered above; here it is enough that the claim the
        # organization hid did not make the payload.
        self.assertNotIn(wire.T_PLACE_OF_BIRTH, self._claims(body))

    def _claims(self, body):
        import time

        from ovcrypto import verifier

        keys = credential_keys.issuing_keys()
        rows = {t: credential_keys.epoch_key_row(keys.epoch, t)
                for t in (credential_keys.TIER_PUBLIC,
                          credential_keys.TIER_RESTRICTED)}
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey)
        device = {keys.epoch: verifier.EpochPrivateKeys(
            keys.epoch,
            X25519PrivateKey.from_private_bytes(
                credential_keys.private_key(rows[credential_keys.TIER_PUBLIC])),
            X25519PrivateKey.from_private_bytes(
                credential_keys.private_key(
                    rows[credential_keys.TIER_RESTRICTED])))}
        opened = verifier.verify(
            "CL03:" + body["qr"].split(":CL03:", 1)[1], epoch_keys=device,
            trust_list=verifier.TrustList.bare(
                {1: credential_keys.signer().public_key_der()}),
            now=int(time.time()))
        return {**opened.public_claims, **(opened.restricted_claims or {})}

    # -- it must never cost a verification --------------------------------

    def test_an_unconfigured_deployment_still_logs_and_still_prints(self):
        """The document falls back to the QR it has always had."""
        with override_settings(CREDENTIAL_ISSUER_KEY_PATH="",
                               CREDENTIAL_EPOCH_WRAP_KEY=""):
            body = json.loads(self._log().content)
        self.assertEqual(body["status"], "ok")
        self.assertNotIn("qr", body)
        self.assertEqual(Transaction.objects.count(), 1)
        self.assertEqual(IssuedCredential.objects.count(), 0)

    def test_a_broken_signing_key_does_not_lose_the_verification(self):
        """Losing the offline half of a QR is a far smaller failure than
        losing the record that somebody was verified at all."""
        with self._configured(CREDENTIAL_ISSUER_KEY_PATH=os.path.join(
                self.dir, "does-not-exist.pem")):
            body = json.loads(self._log().content)
        self.assertEqual(body["status"], "ok")
        self.assertNotIn("qr", body)
        self.assertEqual(Transaction.objects.count(), 1)
        self.assertEqual(IssuedCredential.objects.count(), 0)

    def test_an_organization_with_no_name_still_mints(self):
        """It names no issuer, which is a gap worth seeing -- not a reason to
        refuse somebody their document."""
        from ovcrypto import wire

        self.org.name = ""
        self.org.save(update_fields=["name"])
        with self._configured():
            body = json.loads(self._log().content)
        self.assertIn("qr", body)
        self.assertNotIn(wire.T_ISSUER_ID, self._claims(body))

    def test_a_face_that_needs_a_smaller_render_still_gets_its_symbol(self):
        """Where the resolution fallback has to happen: the minted response.

        `render_portrait_fitted()` is what `_mint_credential()` calls; the
        single-resolution `render_portrait()` there would send the document
        out with a credential and no face beside it.

        The hard-edged artwork is the fixture because it is the case: nothing
        at the shipped 160 px fits it (908 bytes at quality 1 against a
        701-byte budget). Deliberately NOT `data_uri()`: what the sample page
        shows is a presentation decision, and a photograph, which fits."""
        from accounts import credentials, sample_face

        self.assertIsNone(
            credentials.render_portrait(sample_face.unfittable_data_uri()),
            "the fixture no longer needs the fallback")
        rows = list(self.ROWS) + [
            {"field": "face_url", "key": "Face Photo",
             "value": sample_face.unfittable_data_uri(), "show": True}]
        with self._configured():
            body = json.loads(self._log(rows).content)
        self.assertEqual(body["status"], "ok")
        self.assertIn("portrait_qr", body)
        self.assertTrue(body["portrait_qr"].startswith("CL03F1:"))
        self.assertEqual(body["portrait_stamp_mm"],
                         credentials.PORTRAIT_STAMP_MM)

    # -- the page ---------------------------------------------------------

    def _page(self, rows=None):
        keep_answer(self.client, self.org,
                    rows if rows is not None else self.ROWS)
        return self.client.get("/app/document/").content.decode()

    def test_the_printed_sheet_declares_its_own_page_box(self):
        """Without @page the budget is whatever margin the browser happens to
        default to -- and the two paths out of this template disagreed, Print
        taking the browser's and Save as PDF writing its own 1.5 cm. One rule
        now governs both, so a height measured on one path holds on the other.

257 mm, not 259: page boxes round, and a block sized to meet the sheet
        exactly is a block that spills on the printer that rounds the other
        way. The same rule as the 0.4 mm module floor -- clear it, never meet
        it.

        The size is `auto` and must stay so. Naming A4 lays the page out as
        A4 and scales it onto Letter, and a 5% shrink puts the card's modules
        at 0.38 mm -- under the floor, on the one thing here that has to
        survive a camera."""
        page = self._page()
        self.assertIn("@page { size: auto; margin: 10mm; }", page)
        self.assertNotIn("size: A4", page)
        self.assertIn("height: 257mm", page)
        self.assertNotIn("min-height: 25cm", page)
        # And it reaches the OTHER path: printStylesheet() copies @page out
        # of this page's own stylesheet, so the PDF window is not left on the
        # browser's default margin -- which is the disagreement above.
        self.assertIn("printStylesheet()", page)

    def test_both_dimensions_clear_the_page_box_and_neither_meets_it(self):
        """At a 10 mm margin, on the two papers this sheet has to print on:

                            printable      the sheet takes   clear
            A4  210 x 297    190 x 277        188 x 257      2 / 20 mm
            Letter 216x279   196 x 259        188 x 257      8 /  2 mm

        A4 governs the width and Letter the height, so the sheet has to clear
        BOTH -- asserting it against A4 alone would let it be 273 mm tall,
        16 mm too tall for Letter, with every test passing.

        The width clears its limit as the height does: page boxes round, and
        a block sized to meet the sheet is a block that spills on the printer
        that rounds the other way.

        A horizontal overflow is the worse of the two to leave lying around,
        because it does not announce itself as a second sheet: it clips the
        right edge, or prints a second sheet carrying a 2 mm strip."""
        page = self._page()
        rule = page[page.index("    .doc-page {"):]
        rule = rule[:rule.index("}")]

        width = self._mm(rule, "width")
        height = self._mm(rule, "height")
        MARGIN = 10.0
        for paper, pw, ph in (("A4", 210.0, 297.0), ("Letter", 215.9, 279.4)):
            self.assertLess(width, pw - 2 * MARGIN,
                            "the sheet meets or exceeds %s's printable width"
                            % paper)
            self.assertLess(height, ph - 2 * MARGIN,
                            "the sheet meets or exceeds %s's printable height"
                            % paper)
            # Clearance worth having, not a rounding artefact.
            self.assertGreaterEqual(pw - 2 * MARGIN - width, 1.0, paper)
            self.assertGreaterEqual(ph - 2 * MARGIN - height, 1.0, paper)
        # It is still a sheet, not a strip: the cut-out card has to fit across
        # it, and the card is the widest fixed thing on the page.
        self.assertGreater(width, credentials.CARD_PRINT_H_MM + 5)

    @staticmethod
    def _css(block):
        """The DECLARATIONS, with the prose taken out.

        A selector named in a comment is not a rule, and an assertion that
        cannot tell the two apart is satisfied -- or defeated -- by writing
        about the thing instead of doing it."""
        import re
        return re.sub(r"/\*.*?\*/", " ", block, flags=re.S)

    @staticmethod
    def _mm(rule, prop):
        import re
        m = re.search(r"(?:^|[ ;{])%s:\s*([0-9.]+)mm" % prop, rule, re.M)
        assert m, "no %s in mm: %r" % (prop, rule[:200])
        return float(m.group(1))

    def test_the_preview_shows_the_margin_the_printer_gives_it(self):
        """A preview that misreports its own margins is worse than none.

        `.doc-page` is the printable AREA, not the page. On paper `@page`
        holds it away from the edge; on screen nothing did, so the header,
        the field rules and the footer ran clean off the left and right of
        the white and the operator was shown a layout the printer does not
        produce -- on the one screen somebody checks a document against
        before pressing Print.

        The insets are the ones the PDF measures, not the ones `@page`
        nominally asks for, and the difference is the whole point: the sheet
        is 2 mm narrower than the printable width and `margin: 0 auto`
        centres it, so it lands 11 mm from the paper edge and not 10. A
        preview drawn from the nominal margin would be wrong by exactly the
        amount that makes a preview worth having.

        Derived here from A4, the page box and the sheet rather than typed as
        four numbers, so moving any of those three moves the preview with
        them."""
        page = self._page()

        sheet = page[page.index("    .doc-page {"):]
        sheet = sheet[:sheet.index("}")]
        width = self._mm(sheet, "width")
        height = self._mm(sheet, "height")

        paper = page[page.index(".doc-paper {"):]
        paper = paper[:paper.index("}")]
        A4_W, A4_H, MARGIN = 210.0, 297.0, 10.0
        self.assertEqual(self._mm(paper, "width"), A4_W)
        self.assertEqual(self._mm(paper, "height"), A4_H)

        import re
        pad = re.search(r"padding:\s*([^;]+);", paper).group(1).split()
        pad = [float(v.replace("mm", "")) for v in pad]
        self.assertEqual(len(pad), 3, "top / sides / bottom: %r" % (pad,))
        top, sides, bottom = pad

        self.assertEqual(top, MARGIN, "the sheet is flush to the top of the page box")
        self.assertEqual(sides, MARGIN + (A4_W - 2 * MARGIN - width) / 2,
                         "the sheet is centred in the printable width")
        self.assertEqual(bottom, A4_H - MARGIN - height,
                         "the sheet does not reach the foot of the page box, "
                         "and the crop marks hang into what is left")

        # The ring must not take layout, or it shifts the sheet off the very
        # margin this box exists to draw honestly. Same reason the cut line is
        # an outline: a line drawn to show a boundary must not move it.
        self.assertIn("outline:", self._css(paper))
        self.assertNotIn("border:", self._css(paper))

    def test_the_paper_is_screen_only_and_can_never_reach_a_printer(self):
        """It is the one box here that is NOT the same in both media, and it
        has to be unreachable from print rather than merely overridden there.

        `@page` would apply its 10 mm to a 210 mm box inside a 190 mm
        printable area, so this element on paper is a guaranteed second
        sheet. Declared inside `@media screen` it cannot get there: print
        never evaluates the block, and `printStylesheet()` drops a
        screen-only query on its way to the Save-as-PDF window.

        An override in the print block would do the same job and would be one
        deletion away from that failure. A rule print never sees is not."""
        page = self._page()

        screen = page[page.index("    @media screen {"):]
        screen = screen[:screen.index("\n    }")]
        self.assertIn(".doc-paper {", self._css(screen),
                      "the paper is not inside the screen-only block")

        printed = page[page.index("@media print {"):]
        printed = printed[:printed.index("\n    }")]
        self.assertNotIn("doc-paper", self._css(printed),
                         "print must not have an opinion about the paper")

        # And the sheet it wraps is untouched -- everything the fitter
        # measures is inside `.doc-page`, whose box is the same in both media.
        self.assertTrue(_is_inside(page, "doc-paper", "doc-page"))
        sheet = page[page.index("    .doc-page {"):]
        sheet = sheet[:sheet.index("}")]
        self.assertNotIn("padding: 10mm", sheet)
        self.assertIn("padding: 0;", sheet)

    def test_the_card_is_pinned_to_the_foot_of_the_sheet(self):
        """The card's space below the cut line is RESERVED, not merely
        preferred.

        The reservation is now structural: the card is `flex: 0 0 auto`, so
        it takes its printed footprint and gives none of it back, and the
        block above is `flex: 1 1 auto` with `min-height: 0`, so IT is what
        absorbs.

        The card still has to be a CHILD of the sheet. As a sibling it would
        follow a 25 cm block onto page two, every time."""
        page = self._page()
        self.assertIn(".cut-card { display: none; flex: 0 0 auto; }", page)
        body = page[page.index("    .doc-body {"):]
        body = body[:body.index("}")]
        self.assertIn("flex: 1 1 auto;", body)
        self.assertIn("min-height: 0;", body)
        self.assertIn("display: flex;", page)
        self.assertIn("flex-direction: column;", page)
        self.assertTrue(_is_inside(page, "doc-page", "cut-card"))

    def test_the_upper_block_gives_way_and_never_the_card(self):
        """The other half of the reservation, and the reason it is safe.

        `.doc-body` is clipped rather than allowed to grow, which is what
        stops a long certificate pushing the card off the sheet. On its own
        that would trade a spilled page for silently missing rows -- so the
        fitter shrinks the block until it fits, and only ever clips if every
        floor in the stylesheet has bottomed out. Both halves have to be
        present: the overflow rule is the guarantee, the fitter is the
        mechanism.

        The card must NOT be inside the clipped block, or it would be clipped
        along with everything else the moment the certificate ran long."""
        page = self._page()
        body = page[page.index("    .doc-body {"):]
        body = body[:body.index("}")]
        self.assertIn("overflow: hidden;", body)
        self.assertTrue(_is_inside(page, "doc-page", "cut-card"))
        self.assertFalse(_is_inside(page, "doc-body", "cut-card"))

    def test_the_organization_banner_does_not_print(self):
        """It is a screen affordance -- which organization you are signed into
        -- and the document's own header already says so on paper. Left
        visible it sat ABOVE the page box and pushed the foot of the sheet
        onto page two, which is the whole of why a 13-field document needed
        two pages."""
        page = self._page()
        rule = page[page.index(".app-nav,"):]
        rule = rule[:rule.index("}")]
        self.assertIn(".org-banner", rule)

    def test_the_fit_is_measured_rather_than_stepped_off_the_row_count(self):
        """No density tiers: `--fit` is measured off the real layout.

        A tier picked from the ROW COUNT alone, in the markup -- `> 21` for
        6 pt and a 0.8 cm portrait, `> 15` for 7.5 pt -- is a poor proxy for
        a height: it cannot see a value that wraps to three lines, and the
        longest values eVerify returns are the two address fields, which are
        displayed by default. Thirteen fields with a 132-character holder
        name and a long present address is a taller block than twenty-two
        short ones, and a tier would call the first of those roomy.

        So the sheet carries no tier class at any field count."""
        row = dict(self.ROWS[0])

        def rows(n):
            return [dict(row, key="Field %d" % i) for i in range(n)]

        for count in (13, 16, 22, 36):
            body = self._page(rows(count)).split("</head>")[1]
            self.assertNotIn("doc-compact", body, count)
            self.assertNotIn("doc-dense", body, count)
        page = self._page()
        self.assertNotIn("--row-size:", page)
        self.assertIn("--fit: 1;", page)
        self.assertIn("function fitDocument()", page)

    def test_the_fitter_measures_the_block_it_is_shrinking(self):
        """It asks the browser rather than working it out.

        The fitter reads `scrollHeight` against `clientHeight` on the real
        block and steps down until it stops overflowing, rather than trusting
        arithmetic. It steps rather than binary searches because the
        predicate is not cleanly monotonic: a smaller type size can pull a
        wrapped value back onto one line and briefly undo an overflow."""
        page = self._page()
        step = page[page.index("function fitPass("):]
        step = step[:step.index("function fitDocument(")]
        self.assertIn("scrollHeight", page)
        self.assertIn("clientHeight", page)
        self.assertIn("setProperty('--fit'", step)
        # Stepped down from 1, with a floor, not solved for.
        self.assertIn("fit - FIT_STEP", step)
        self.assertIn("Math.max(FIT_MIN", step)

    def test_a_sheet_the_first_fit_cannot_make_changes_layout_not_size(self):
        """The second pass, and it is a different LAYOUT rather than a
        smaller one.

        Measured on the real document, both print paths, four field counts
        against four holder-name lengths: the centred certificate holds to 22
        displayed fields, and at 36 it is 17.3 mm over the page once EVERY
        floor in the stylesheet has bottomed out -- 5.5 pt rows, an 11 pt
        name, a 16 mm portrait. There is nothing left to shrink.

        What buys the sheet back is standing the portrait beside the name
        instead of above it, and pairing the field rows: 36 fields then
        prints at --fit 0.86 or better, so about 7.3 pt and a 26 mm portrait.

        Shrinking is tried first because the centred form is the better
        document. The row is what a 36-field organization gets instead of a
        clipped page."""
        page = self._page()
        body = page[page.index("function fitDocument()"):]
        body = body[:body.index("/* The three things")]
        # First the centred form, and only then the fallback.
        self.assertLess(body.index("classList.remove('doc-tight')"),
                        body.index("classList.add('doc-tight')"))
        # And it is measured AGAIN after the layout changes, or the fallback
        # would keep whatever fit the centred form bottomed out at.
        after = body[body.index("classList.add('doc-tight')"):]
        self.assertIn("fitPass(page, body)", after)
        # The fallback is a layout: the hero becomes a row and the fields
        # pair up. Both are what make 36 fields fit.
        self.assertIn(".doc-page.doc-tight .doc-hero {", page)
        hero = page[page.index(".doc-page.doc-tight .doc-hero {"):]
        self.assertIn("flex-direction: row;", hero[:hero.index("}")])
        fields = page[page.index(".doc-page.doc-tight .doc-fields {"):]
        self.assertIn("17% 33% 17% 33%", fields[:fields.index("}")])

    def test_the_certificate_does_not_repeat_itself_in_the_list(self):
        """The holder is stated a single time, at the top.

        The certificate prints the portrait, the name and both ID numbers, so
        the list underneath must not print them again -- the view lifts them
        out. Getting this wrong is not a crash and not a spill: it is a
        document that names somebody twice, which reads as a bug in the
        record rather than in the page."""
        from verify.views import handoff

        keep_answer(self.client, self.org, self.ROWS)
        response = self.client.get("/app/document/")
        printed = {everify_fields.field_of(row)
                   for row in response.context["doc_rows"]}
        for field in handoff.HOLDER_FIELDS + (handoff.FACE_FIELD,):
            self.assertNotIn(field, printed, field)
        # And they really are stated above it, or this passes by printing
        # nothing at all.
        self.assertEqual(response.context["holder_name"], "JUAN DELA CRUZ")
        self.assertEqual(
            [n["value"] for n in response.context["holder_numbers"]],
            ["1111-2222-3333-4444", "ABC1234"])
        # Printed under the organization's OWN labels, which are editable --
        # selected by key, rendered by label.
        self.assertEqual(
            [n["label"] for n in response.context["holder_numbers"]],
            ["National ID Card Number", "Digital National ID Number"])
        # The fields that are NOT the holder still print.
        self.assertIn("place_of_birth", printed)

    def test_the_portrait_has_a_floor_the_fit_cannot_push_it_through(self):
        """The reason this layout exists at all.

        A portrait in a table cell, shrunk with the rest, goes down to
        **0.8 cm** at 22+ fields, which is too small to compare against the
        face of the person standing at the counter. It is the document's
        subject, so it is the last thing to give way and it stops at 16 mm --
        measured at 36 fields, the worst case prints it at about 26 mm.

        Without the floor the fit simply scales it away again, and nothing
        else on the page would notice."""
        page = self._page()
        rule = page[page.index(".doc-hero-face {"):]
        rule = rule[:rule.index("}")]
        self.assertIn("max(16mm,", rule)
        self.assertIn("var(--fit)", rule)
        # The tier that produced the 8 mm portrait is gone with its --face-w.
        self.assertNotIn("--face-w", page)
        self.assertNotIn("0.8cm", page)

        # BOTH dimensions, and the image fitted inside them. With `height:
        # auto` the sheet's height budget depends on the aspect ratio of
        # whatever eVerify returned, which nothing here controls: this repo's
        # own sample portraits are square, so a square fixture measures a
        # layout that holds, while an ordinary 3:4 ID photograph is 10 mm
        # taller at the same width -- and in the row form the portrait's
        # height IS the hero's height. Measured both ways: with the box
        # fixed, a 3:4 capture gives the identical fit at every field count.
        self.assertIn("height: max(16mm,", rule)
        self.assertIn("object-fit: contain;", rule)
        self.assertNotIn("height: auto;", rule)

    def test_the_seal_and_the_symbol_never_give_way(self):
        """The certificate is what shrinks, and that is the whole doctrine:
        the two symbols on the card, the seal and the validation QR have a
        physical floor a reader's camera enforces, and text has none that
        cannot be recovered by looking closer.

        So nothing that scales with `--fit` may be a mark. Measured: the card
        is 79.77 mm on every one of the sixteen swept documents."""
        page = self._page()
        for selector in ("#doc-stamp {", "#doc-validate-qr canvas",
                         ".cut-block {", "#cut-canvas {"):
            rule = page[page.index(selector):]
            self.assertNotIn("var(--fit)", rule[:rule.index("}")], selector)

    def test_the_measured_fit_travels_to_the_pdf_window(self):
        """Save as PDF copies `docPage.outerHTML` into a window that has no
        fitter of its own, so the value has to be ON the element. A
        stylesheet rule would not travel, and the card would be pushed off
        the sheet on that path only -- a card missing from every PDF, with no
        test noticing."""
        page = self._page()
        self.assertIn("page.style.setProperty('--fit'", page)
        # And it is re-fitted immediately before the copy is taken.
        handler = page[page.index("btn-save-pdf').addEventListener"):]
        handler = handler[:handler.index("var docPage")]
        self.assertIn("fitDocument();", handler)

    def test_the_sheet_is_the_same_box_on_screen_as_on_paper(self):
        """What makes the fitter's measurement mean anything.

        The fitter reads this layout in the browser, so the box it measures
        has to be the box that prints. While the two media disagreed -- a
        45 px logo here against 34 px there, 0.8 rem rows against a tier's
        points -- nothing measured on screen said anything about paper.

        So the print block hides the surrounding chrome and stops: a rule
        added there that changes a height inside the sheet is a rule the
        fitter cannot see."""
        page = self._page()
        printed = page[page.index("@media print {"):]
        printed = printed[:printed.index("\n    }")]
        # It may hide chrome and drop the screen-only ring, and nothing else.
        for banned in ("#doc-stamp", "#doc-validate-qr", ".doc-fields",
                       ".doc-header img", "--fit", "height: 257mm"):
            self.assertNotIn(banned, printed, banned)

    # -- the validation QR beside the seal ---------------------------------

    def test_the_document_carries_a_symbol_a_webcam_can_read(self):
        """Beside the seal, above the cut line, and deliberately coarse.

        The card's credential symbol is 113 modules across 48.8 mm -- 0.432 mm
        each, which is what an offline payload costs. This one carries the
        transaction id and nothing else: 29 modules at 20 mm, **0.690 mm** per
        module, half as many again as the card's at 41% of the width. Fewer
        modules is what makes a symbol easy to read, not a bigger square.

        Measured by rendering the real document and reading the drawn canvas
        back with jsQR -- the same decoder the Validate page uses -- on 16
        pages across four field counts and four name lengths."""
        page = self._page()
        self.assertIn('id="doc-validate-qr"', page)
        self.assertIn("function generateValidateQR(", page)
        # To the RIGHT of the seal: the seal comes first in the row.
        footer = page[page.index('id="doc-stamp-qr"'):]
        footer = footer[:footer.index("</div>\n            </div>")]
        self.assertLess(footer.index('id="doc-stamp"'),
                        footer.index('id="doc-validate-qr"'))

    def test_that_symbol_carries_the_transaction_id_and_nothing_else(self):
        """Not the credential. The offline half is on the card, where it has
        the width to be; this is the online check, which is what a stranger
        with a camera can actually do."""
        page = self._page()
        call = page[page.index("generateValidateQR(resp."):]
        self.assertTrue(call.startswith("generateValidateQR(resp.transaction_id)"),
                        call[:60])
        body = page[page.index("function generateValidateQR("):]
        body = body[:body.index("function drawCutCard(")]
        self.assertNotIn("resp.qr", body)

    def test_that_symbol_is_uppercased_so_it_stays_alphanumeric(self):
        """Not cosmetic. The alphanumeric charset has no lowercase, so a
        lowercase uuid falls back to byte mode -- version 4 and 33 modules
        instead of version 3 and 29, measured with the page's own encoder.

        Safe because `/api/validate/` answers for either spelling, which is
        pinned separately, and the Validate page's pattern ignores case."""
        page = self._page()
        body = page[page.index("function generateValidateQR("):]
        body = body[:body.index("function drawCutCard(")]
        self.assertIn("toUpperCase()", body)
        self.assertIn("'Q'", body)

    def test_that_symbol_is_printed_big_enough_to_scan(self):
        """20 mm over 29 modules is 0.69 mm each, against the 0.4 mm floor
        this app enforces for a laser print photographed in the field.

        One size on every document: beside the text the marks cost the page
        nothing, so the symbol keeps the size that reads easiest. Measured
        on the real document: 19.36 mm of sheet spare at 36 fields."""
        page = self._page()
        # One rule, in millimetres, for both media.
        rules = page[page.index("#doc-validate-qr canvas"):]
        rules = rules[:rules.index("}")]
        self.assertIn("width: 20mm;", rules)
        self.assertIn("height: 20mm;", rules)
        self.assertGreater(20.0 / 29, 0.4)
        # It does not scale with the fit: the symbol's floor is a camera's,
        # which is precisely why the certificate is what gives way instead.
        self.assertNotIn("var(--fit)", rules)

    def test_the_seal_is_sized_to_match_the_symbol(self):
        """Equal BOXES are not equal marks. The seal is a round mark on a
        square canvas and its ink covers 85.2% of it -- measured -- so at an
        equal box it printed about 17 mm against the symbol's 20 and read as
        the smaller of the two. Its box is the symbol over 0.852."""
        page = self._page()
        stamp = page[page.index("    #doc-stamp {"):]
        stamp = stamp[:stamp.index("}")]
        self.assertIn("height: 23.5mm;", stamp)
        self.assertAlmostEqual(20.0 / 23.5, 0.852, places=2)
        # Said a single time, for both media: 23.5 mm, not 88.7 px on screen
        # beside 23.5 mm in print, which is the same mark twice over -- 23.5 x
        # 3.7795 = 88.82 -- and a pairing to check in two units.
        self.assertNotIn("88.7px", page)
        self.assertAlmostEqual(23.5 * 96 / 25.4, 88.8, places=1)
        # Like the symbol beside it, it holds its size whatever the fit.
        self.assertNotIn("var(--fit)", stamp)

    def test_the_footer_is_one_row_with_the_marks_on_the_right(self):
        """The lines on the left, the seal and the symbol on the right.

        Beside the text they cost nothing, which is also why the marks need
        no density tier of their own.

        The rule is in CSS rather than on the element, because the marks
        row's `display` is what the script switches on and an inline rule
        would be a second place to keep that in step."""
        page = self._page()
        footer = page[page.index(".doc-footer {"):]
        footer = footer[:footer.index("}")]
        self.assertIn("display: flex;", footer)
        self.assertIn("justify-content: space-between;", footer)
        self.assertNotIn("text-align: center;", footer)
        # The lines come first, so the flex rule puts them on the left.
        block = page[page.index('class="doc-footer"'):page.index('id="cut-card"')]
        self.assertLess(block.index("Verification performed by"),
                        block.index('id="doc-stamp-qr"'))
        # And nothing reorders them afterwards.
        self.assertNotIn("order:", block)
        self.assertNotIn("order: ", page[page.index("#doc-stamp-qr {"):
                                         page.index("#doc-stamp {")])

    def test_the_document_above_the_cut_line_still_says_it_in_full(self):
        """Trimming is only tolerable because nothing is actually lost: every
        string trimmed on the card is printed whole on the sheet above it."""
        long_name = ("Philippine Statistics Authority - Civil Registry "
                     "Service, National Capital Region")
        self.org.name = long_name
        self.org.save(update_fields=["name"])
        location = self.org.locations.first()
        location.name = ("PSA Quezon City East District Registry and "
                         "Verification Centre")
        location.save(update_fields=["name"])

        page = self._page()
        above = page[:page.index('id="cut-card"')]
        self.assertIn(long_name, above)
        self.assertIn(location.name, above)

    def test_the_pdf_window_reads_the_print_rules_off_the_page(self):
        """Two documents come out of this template -- Print uses the page, and
        Save as PDF builds a second one in a new window that inherits no
        styling.

        So it is read off this page instead. Nothing to keep in step."""
        page = self._page()
        self.assertIn("function printStylesheet()", page)
        self.assertIn("conditionText", page)
        self.assertIn("win.document.write(printStylesheet())", page)
        # The numbers are no longer typed a second time.
        self.assertNotIn("win.document.write('@page", page)
        self.assertNotIn("win.document.write('.cut-card-body {", page)

    def test_the_pdf_window_keeps_the_page_inside_its_container(self):
        """body is a centring flex column in this app's base stylesheet, so a
        .doc-page dropped straight into the new window shrinks to its content
        -- the table then wraps further and the sheet that fitted on the Print
        path spills on this one. Measured: 27 displayed fields did exactly
        that."""
        page = self._page()
        self.assertIn("'<div class=\"container\">' + docPage.outerHTML", page)

    def test_the_card_carries_no_photograph(self):
        """The face rides the symbol beside it. Printing it again spends card
        space on something the document above already shows -- and it would be
        a second thing to keep in step with Demo Mode."""
        rows = [dict(r) for r in self.ROWS] + [
            {"field": "face_url", "key": "Face Photo", "show": True,
             "value": "data:image/png;base64,DEADBEEF"}]
        page = self._page(rows)
        # Everything from the card marker to the scripts that follow the
        # markup: the photograph must not appear anywhere in it. (Not to the
        # footer: a site with no logos configured has none.)
        card = page.split('id="cut-card"', 1)[1].split('cardcanvas.js', 1)[0]
        self.assertNotIn("DEADBEEF", card)
        self.assertNotIn("cut-face", page)
        # The page no longer carries a second, unmasked copy of the answer
        # for the log to post back.
        self.assertEqual(page.count("DEADBEEF"), 1)

    def test_the_printed_symbols_ask_for_alphanumeric_mode(self):
        """qrcode-generator defaults addData to BYTE mode -- `mode = mode ||
        'Byte'` in the library -- and an uppercase payload does not change
        that. Byte costs ~45% of the capacity: it put the portrait past what
        any QR can hold, and drew the credential at a far higher version than
        the stamp was sized for. Below the 0.4 mm floor, on paper, silently.
        """
        page = self._page()
        self.assertIn("'Alphanumeric' : 'Byte'", page)
        self.assertIn("ALNUM.test(payload)", page)

    def test_both_payloads_stay_inside_the_alphanumeric_charset(self):
        """If either ever carried a lowercase character the drawing falls back
        to byte mode and the stamp silently stops matching its size."""
        import re

        alnum = re.compile(r"^[0-9A-Z $%*+\-./:]*$")
        with self._configured():
            body = json.loads(self._log().content)
        self.assertRegex(body["qr"], alnum)
        if body.get("portrait_qr"):
            self.assertRegex(body["portrait_qr"], alnum)

    def test_a_failure_is_not_reported_as_a_network_error(self):
        """The catch swallowed anything thrown while handling a perfectly good
        response and called it a network error, which sent somebody looking at
        the wrong thing for an hour."""
        page = self._page()
        self.assertNotIn("'Network error.'", page)
        self.assertIn("log-transaction failed:", page)


    # ---- the cut-out card: the phone card, printed on its side ----------
    #
    # The printed cut-out and the phone's card are one design from one
    # renderer, static/cardcanvas.js: somebody holding the paper beside the
    # photo on their phone sees the same card. The tests below are what has
    # to catch a change made for the PHONE that ruins the PAPER.

    def test_the_document_draws_no_card_of_its_own(self):
        """One renderer, loaded rather than copied.

        A second copy of the drawing code is the whole failure this change
        exists to remove: it would go on working, and go on diverging, with
        nothing failing anywhere."""
        page = self._page()
        self.assertIn("cardcanvas.js", page)
        self.assertIn("CardCanvas.render(card, upright", page)
        # None of the renderer's own vocabulary may reappear here.
        for copied in ("function drawSymbol(", "function drawFace(",
                       "MAX_MODULES", "MODULE_PX", "function caption("):
            self.assertNotIn(copied, page, copied)

    def test_the_card_prints_the_date_signed_into_its_credential(self):
        """From a real mint: the card's date is the credential's, 30 days from
        the verification unless the site says otherwise."""
        from verify.views import handoff

        with self._configured():
            card = self._log().json()["card"]
        issued = IssuedCredential.objects.get()
        self.assertEqual(issued.expires_at - issued.issued_at,
                         datetime.timedelta(days=30))
        self.assertEqual(card["expires_on"], handoff.expires_on_text(issued.expires_at))

    def test_the_card_is_what_the_server_returned(self):
        """`resp.card` is built by `handoff.payload_from_rows()` -- the same
        object the phone is given, from the one place that had a session to
        decide which fields, whose organization and whether to mask.

        The page passes it through and composes nothing, so the paper and the
        photo cannot come to disagree about what is on them."""
        page = self._page()
        self.assertIn("drawCutCard(resp.card)", page)
        # Not assembled here from anything the page happens to have.
        card_fn = page[page.index("function drawCutCard("):]
        card_fn = card_fn[:card_fn.index("/* --- The hand-off")]
        self.assertNotIn("holder", card_fn)
        self.assertNotIn("organization", card_fn)

        with self._configured():
            response = self._log()
        card = response.json()["card"]
        self.assertEqual(card["holder"], "JUAN DELA CRUZ")
        self.assertEqual(card["organization"],
                         "Philippine Statistics Authority")
        self.assertTrue(card["qr"].startswith(
            str(Transaction.objects.get().transaction_id).upper() + ":CL03:"))

    def test_the_printed_block_is_the_card_turned_on_its_side(self):
        """1080 x 2700 at 0.063 mm a pixel is 68.04 x 170.10 mm, and the long
        side lies ACROSS the sheet -- which is the only way a card this size
        fits a page that has 190 mm of width and about 25 mm of height left.

        The pixels are turned, not the box: x' = y, y' = height - x."""
        page = self._page()
        self.assertIn("width: %smm;" % credentials.CARD_PRINT_H_MM, page)
        self.assertIn("height: %smm;" % credentials.CARD_PRINT_W_MM, page)
        self.assertIn('<canvas id="cut-canvas" width="%d" height="%d">'
                      % (credentials.CARD_CANVAS_H_PX,
                         credentials.CARD_CANVAS_W_PX), page)
        self.assertIn("ctx.setTransform(0, -1, 1, 0, 0, canvas.height);", page)
        self.assertIn("ctx.imageSmoothingEnabled = false;", page)

    def test_the_card_box_is_the_box_that_prints(self):
        """A transform does not change layout. A portrait canvas turned with
        one is a 170 mm-tall box to the paginator however it looks: Chrome
        counted it as overflow, and Safari moved it past the page break, so
        the card went to page two on Letter and off the paper on A4."""
        page = self._css(self._page())
        canvas = page[page.index("#cut-canvas {"):]
        self.assertNotIn("transform", canvas[:canvas.index("}")])
        # The crop marks and the cut line sit OUTSIDE the printed rectangle.
        block = page[page.index("    .cut-block {"):]
        block = block[:block.index("}")]
        self.assertIn("outline: 1px dashed", block)
        page = self._page()
        self.assertIn(".cut-block::before { top: -1.5mm;", page)
        self.assertIn(".cut-block > .cut-marks { position: absolute;", page)

    def test_the_printed_card_clears_the_module_floor(self):
        """The reason the scale is one constant and not a number in CSS.

        A QR module is 8 canvas pixels, so the printed module is 8 x the
        scale: 0.504 mm, against a 0.4 mm floor. Clear it, never meet it --
        the same rule STAMP_MM follows, and the rule that caught five wrong
        stamp sizes."""
        from ovcrypto import qrsize

        self.assertEqual(
            credentials.CARD_PRINT_MODULE_MM,
            credentials.CARD_MODULE_PX * credentials.CARD_PRINT_MM_PER_PX)
        self.assertGreater(credentials.CARD_PRINT_MODULE_MM,
                           qrsize.MIN_MODULE_MM)
        # And it beats the card it replaces: 48.8 mm over 113 modules.
        self.assertGreater(credentials.CARD_PRINT_MODULE_MM,
                           credentials.STAMP_MM / 113)

    def test_the_printed_geometry_matches_the_renderer(self):
        """Two numbers that must agree, asserted rather than inferred.

        The scale means nothing unless the canvas really is 1080 x 2700 and a
        module really is 8 pixels of it. Change either in the renderer and the
        printed millimetres are quietly wrong -- on paper, silently, which is
        exactly how the stamp went under the floor before."""
        source = (settings.BASE_DIR / "static"
                  / "cardcanvas.js").read_text(encoding="utf-8")
        self.assertIn("var W = %d, H = %d," % (credentials.CARD_CANVAS_W_PX,
                                               credentials.CARD_CANVAS_H_PX),
                      source)
        self.assertIn("var MODULE_PX = %d;" % credentials.CARD_MODULE_PX,
                      source)

    def test_no_credential_still_means_no_cut_out(self):
        """A card with nothing offline on it is not worth cutting out, and
        `resp.card` comes back only with a mint -- so the two cannot drift.

        The document is still a document: the symbol beside the seal carries
        the transaction id and validates it online, mint or no mint."""
        page = self._page()
        self.assertIn(".cut-card { display: none; flex: 0 0 auto; }", page)
        self.assertIn(".cut-card.ready { display: block; }", page)
        body = page[page.index("function drawCutCard("):]
        body = body[:body.index("/* --- The hand-off")]
        self.assertIn("if (!card) {", body)
        self.assertIn("block.classList.remove('ready');", body)
        # And it is only marked ready once something is actually on it.
        self.assertIn("block.classList.add('ready');", body)
        # The card appearing is what shrinks the space the certificate has,
        # so the fit is taken again -- before either print path is reachable.
        ready = body[body.index("block.classList.add('ready');"):]
        self.assertIn("fitDocument();", ready[:400])

    def test_the_card_travels_to_the_pdf_window(self):
        """A canvas does not survive outerHTML, so each symbol becomes an
        <img> before the document is copied.

        The printed size is keyed to `#cut-canvas` by id, and what travels is
        an <img> that has replaced it -- so the print window is given the rule
        again. Without it the card prints at its pixel size."""
        page = self._page()
        self.assertIn("'#cut-canvas'", page)
        self.assertIn(".cut-block > img { display: block;", page)
        self.assertIn("width: %smm;" % credentials.CARD_PRINT_H_MM,
                      page[page.index(".cut-block > img {"):])
        # Put back afterwards, or the page is left holding images the next
        # print cannot resize.
        self.assertIn("replaceChild(pair[1], pair[0])", page)

    def test_safari_prints_the_sheet_at_true_size(self):
        """WebKit prints a CSS pixel at 0.8 pt or wider, and the sheet then
        does not fit Letter. Corrected only where that happens, and only on
        paper, because the fitter measures the box on screen."""
        css = self._css(self._page())
        rule = css[css.index("@supports (font: -apple-system-body)"):]
        self.assertIn(".doc-page { --print-zoom: 0.9375; }", rule[:120])
        self.assertIn("@media print { .doc-page { zoom: var(--print-zoom); } }",
                      rule[:180])
        # Save as PDF is Print there: Safari's copy in a new window lost the
        # certificate's lower half on Letter.
        self.assertIn("getPropertyValue('--print-zoom').trim()) {\n"
                      "            window.print();\n            return;", self._page())
        # Fitted at the size that prints, and left unzoomed for the screen
        # and for the copy Save as PDF takes.
        page = self._page()
        self.assertIn("getPropertyValue('--print-zoom')", page)
        self.assertIn("if (printZoom) { page.style.zoom = printZoom; }", page)
        self.assertIn("if (printZoom) { page.style.zoom = ''; }", page)
        before = css[:css.index("@supports (font: -apple-system-body)")]
        self.assertNotIn("zoom:", before)
        # 100vh is the window in Safari, which printed a blank second sheet,
        # and the base flex column squeezed the Save-as-PDF sheet on Letter.
        printed = before[before.index("@media print {"):]
        self.assertIn("display: block; padding: 0; margin: 0; min-height: 0;",
                      printed)

    def test_the_seal_symbol_is_untouched_by_the_new_card(self):
        """The 20 mm symbol beside the VERIFIED seal is the ONLINE check --
        the one an ordinary webcam reads from across a desk -- and it is
        above the cut line, so it stays whatever happens below it."""
        page = self._page()
        self.assertIn('id="doc-validate-qr"', page)
        self.assertIn("generateValidateQR(resp.transaction_id)", page)
        rule = page[page.index("#doc-validate-qr canvas, #doc-validate-qr img {"):]
        rule = rule[:rule.index("}")]
        self.assertIn("width: 20mm;", rule)
        self.assertIn("height: 20mm;", rule)


@override_settings(CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX,
                   CREDENTIAL_REVOCATION_TTL_SECONDS=86400,
                   CREDENTIAL_REVOCATION_REBUILD_SECONDS=300)
class RevocationFeedTest(TestCase):
    """The signed feed a configured device polls.

    Unauthenticated on purpose -- this app has no device registry, and the
    filter is a list of opaque fingerprints. The control is the SIGNATURE: an
    unsigned revocation list is strippable, and a stripped one turns every
    revoked credential back into a valid one.
    """

    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        credential_keys.reset_caches()
        revocation_feed.invalidate()
        self.addCleanup(credential_keys.reset_caches)
        self.addCleanup(revocation_feed.invalidate)

        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.pem = os.path.join(self.dir, "issuer.pem")
        self.key = ec.generate_private_key(ec.SECP256R1())
        with open(self.pem, "wb") as handle:
            handle.write(self.key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        os.chmod(self.pem, stat.S_IRUSR | stat.S_IWUSR)
        self.spki = self.key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)

        self.org = make_org(name="Alpha")
        self.settings_ctx = override_settings(
            CREDENTIAL_ISSUER_KEY_PATH=self.pem, CREDENTIAL_ISSUER_KEY_ID=1)
        self.settings_ctx.enable()
        self.addCleanup(self.settings_ctx.disable)

    def _credential(self, revoked=False):
        import datetime

        from django.utils import timezone

        record = IssuedCredential.objects.create(
            credential_id=uuid.uuid4(), organization=self.org,
            document_uuid=uuid.uuid4(), epoch=14, issuer_key_id=1,
            issued_at=timezone.now(),
            expires_at=timezone.now() + datetime.timedelta(days=365))
        if revoked:
            revocation_feed.revoke(record, reason="test")
        return record

    def _fetch(self):
        response = self.client.get("/api/v1/revocations/")
        return response, json.loads(response.content)

    def _verify_sig(self, feed):
        from ovcrypto import keystore

        blob = base64.b64decode(feed["filter"])
        return keystore.verify_p256(
            self.spki,
            revocation_feed.signed_bytes(feed["issued_at"], feed["not_after"],
                                         feed["key_id"], blob),
            base64.b64decode(feed["sig"]))

    # -- the feed ---------------------------------------------------------

    def test_the_feed_is_served_without_a_session(self):
        """A device is not signed in, and never will be."""
        response, feed = self._fetch()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(feed["format"], "CL03RL")
        self.assertEqual(feed["key_id"], 1)

    def test_the_signature_verifies_against_the_issuer_key(self):
        """The same key that signs credentials, so a device trusts nothing
        new -- it already carries this one or it could not read a credential
        at all."""
        _, feed = self._fetch()
        self.assertTrue(self._verify_sig(feed))

    def test_a_revoked_credential_is_in_the_filter_and_others_are_not(self):
        from ovcrypto import revocation as revocation_mod

        revoked = self._credential(revoked=True)
        untouched = self._credential()
        _, feed = self._fetch()
        parsed = revocation_mod.CuckooFilter.from_bytes(
            base64.b64decode(feed["filter"]))
        self.assertIn(revoked.credential_id.bytes, parsed)
        self.assertNotIn(untouched.credential_id.bytes, parsed)

    def test_tampering_with_the_filter_breaks_the_signature(self):
        """The whole reason it is signed: a stripped or swapped filter turns
        revoked credentials back into valid ones."""
        from ovcrypto import revocation as revocation_mod

        self._credential(revoked=True)
        _, feed = self._fetch()
        self.assertTrue(self._verify_sig(feed))

        empty = revocation_mod.build([]).to_bytes()
        feed["filter"] = base64.b64encode(empty).decode()
        self.assertFalse(self._verify_sig(feed))

    def test_the_expiry_is_inside_the_signed_bytes(self):
        """A signature alone does not stop yesterday's feed being replayed to
        hide today's revocation."""
        _, feed = self._fetch()
        self.assertGreater(feed["not_after"], feed["issued_at"])
        feed["not_after"] = feed["not_after"] + 86400 * 365
        self.assertFalse(self._verify_sig(feed))

    def test_the_key_id_is_inside_the_signed_bytes(self):
        _, feed = self._fetch()
        feed["key_id"] = 2
        self.assertFalse(self._verify_sig(feed))

    def test_a_feed_cannot_verify_as_a_credential(self):
        """Domain separation, as the sibling project does for its bundle."""
        from ovcrypto import wire

        self.assertNotEqual(revocation_feed.SIG_CONTEXT, wire.SIG_CONTEXT)
        self.assertTrue(
            revocation_feed.signed_bytes(1, 2, 1, b"x").startswith(
                revocation_feed.SIG_CONTEXT))

    # -- configuration ----------------------------------------------------

    def test_an_unconfigured_deployment_refuses_rather_than_serve_unsigned(self):
        """An unsigned feed is worse than no feed: it is strippable."""
        with override_settings(CREDENTIAL_ISSUER_KEY_PATH="",
                               CREDENTIAL_EPOCH_WRAP_KEY=""):
            credential_keys.reset_caches()
            response = self.client.get("/api/v1/revocations/")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("filter", json.loads(response.content))

    def test_a_broken_signing_key_is_a_503_not_an_unsigned_feed(self):
        with override_settings(
                CREDENTIAL_ISSUER_KEY_PATH=os.path.join(self.dir, "gone.pem")):
            credential_keys.reset_caches()
            response = self.client.get("/api/v1/revocations/")
        self.assertEqual(response.status_code, 503)

    # -- caching ----------------------------------------------------------

    def test_the_feed_is_cached_between_polls(self):
        """Rebuilding scans every revoked credential, and devices poll."""
        first = revocation_feed.current_feed()
        self._credential(revoked=False)
        second = revocation_feed.current_feed()
        self.assertIs(first, second)

    def test_revoking_invalidates_the_cache_immediately(self):
        """A revocation nobody is served is not a revocation."""
        from ovcrypto import revocation as revocation_mod

        revocation_feed.current_feed()
        record = self._credential(revoked=True)
        feed = revocation_feed.current_feed()
        parsed = revocation_mod.CuckooFilter.from_bytes(
            base64.b64decode(feed["filter"]))
        self.assertIn(record.credential_id.bytes, parsed)

    def test_revoking_twice_keeps_the_first_decision(self):
        record = self._credential(revoked=True)
        first = record.revoked_at
        revocation_feed.revoke(record, reason="again")
        record.refresh_from_db()
        self.assertEqual(record.revoked_at, first)
        self.assertEqual(record.revoked_reason, "test")


class RestrictedTierBackfillTest(TestCase):
    """Migration 0030 grants the restricted tier to the people already here.

    The flipped default alone changes nothing on a deployment that already has
    its operators -- which is every deployment -- so the backfill is what
    actually delivers this, and it gets exactly one attempt at it.

    The migration's own functions are called against real rows rather than
    the executor being driven through a shared test database: running
    migrations inside the suite leaves state behind that the tests after it
    inherit.
    """

    def setUp(self):
        from django.apps import apps as real_apps

        self.apps = real_apps
        self.org = make_org(name="PSA")
        # Explicitly off: this is the state the migration has to find, and the
        # model default is the very thing under test.
        self.member = User.objects.create(
            national_id_card_number="1111111111111111",
            device_restricted_tier=False)
        join(self.org, self.member)
        self.outsider = User.objects.create(
            national_id_card_number="3333333333333333",
            device_restricted_tier=False)

    def _migration(self):
        from importlib import import_module

        return import_module(
            "accounts.migrations.0030_restricted_tier_by_default")

    def test_it_grants_members_and_leaves_everyone_else_alone(self):
        """"Organization user" is what this is for, and somebody who belongs
        to no organization is not one. That distinction is not academic: the
        Devices page takes _require_login, not a context, so a person with no
        membership can still reach it and pair a phone."""
        self._migration().grant_to_members(self.apps, None)

        self.member.refresh_from_db()
        self.outsider.refresh_from_db()
        self.assertTrue(self.member.device_restricted_tier,
                        "the member was not granted the tier")
        self.assertFalse(self.outsider.device_restricted_tier,
                         "somebody in no organization was granted it")

    def test_rolling_back_fails_closed(self):
        """Nobody had the tier before this ran, so putting everybody back to
        off is its exact inverse. It discards a grant made in between, and
        that is the direction a reverse should fail."""
        module = self._migration()
        module.grant_to_members(self.apps, None)
        module.withdraw_from_everyone(self.apps, None)

        self.assertEqual(
            set(User.objects.values_list("device_restricted_tier", flat=True)),
            {False})

    def test_the_migration_actually_runs_them(self):
        """A backfill nothing calls is a default change wearing a costume."""
        module = self._migration()
        run_python = [op for op in module.Migration.operations
                      if isinstance(op, migrations.RunPython)]
        self.assertEqual(len(run_python), 1)
        self.assertIs(run_python[0].code, module.grant_to_members)
        self.assertIs(run_python[0].reverse_code, module.withdraw_from_everyone)


@override_settings(CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX,
                   DEVICE_PAIRING_TTL_SECONDS=900,
                   DEVICE_LEASE_SECONDS=2592000,
                   DEVICE_CHALLENGE_TTL_SECONDS=120,
                   DEVICE_REQUIRE_APP_ATTEST=False,
                   DEVICE_PAIRING_BASE_URL="https://verify.example.org")
class DevicePairingTest(TestCase):
    """Pairing a phone by QR, and what it is then given.

    The whole shape rests on two things: the QR carries a bootstrap and never
    keys, and nothing afterwards carries a bearer token -- a device proves
    itself by signing a single-use challenge with a key this server has never
    held.
    """

    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        credential_keys.reset_caches()
        self.addCleanup(credential_keys.reset_caches)

        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.pem = os.path.join(self.dir, "issuer.pem")
        self.issuer = ec.generate_private_key(ec.SECP256R1())
        with open(self.pem, "wb") as handle:
            handle.write(self.issuer.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        os.chmod(self.pem, stat.S_IRUSR | stat.S_IWUSR)
        self.spki = self.issuer.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)

        self.settings_ctx = override_settings(
            CREDENTIAL_ISSUER_KEY_PATH=self.pem, CREDENTIAL_ISSUER_KEY_ID=1)
        self.settings_ctx.enable()
        self.addCleanup(self.settings_ctx.disable)

        IssuerKey.objects.create(
            key_id=1, spki_der=self.spki, is_active=True,
            not_before=timezone.now() - datetime.timedelta(days=1),
            not_after=timezone.now() + datetime.timedelta(days=730))

        self.org = make_org(name="Alpha")
        self.user = User.objects.create(
            national_id_card_number="1111222233334444",
            given_name="Ada", last_name="Lovelace")
        join(self.org, self.user)
        self.other = User.objects.create(
            national_id_card_number="9999888877776666", given_name="Someone")

        # The phone's Secure Enclave key, which never leaves it.
        self.device_key = ec.generate_private_key(ec.SECP256R1())
        self.device_pub = self.device_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)

    def _sign_in(self, user=None):
        session = self.client.session
        session[SESSION_KEY] = (user or self.user).id
        session[ORG_SESSION_KEY] = self.org.id
        session.save()

    def _mint(self, label="Field team 3"):
        self._sign_in()
        self.client.post("/app/devices/ticket/",
                         {"purpose": "enrol", "label": label})
        return DeviceTicket.objects.filter(user=self.user).latest("created_at")

    def test_the_qr_is_shown_when_the_address_is_one_the_app_accepts(self):
        self._sign_in()
        with override_settings(
                DEVICE_PAIRING_BASE_URL="https://verify-test.example.org"):
            self.client.post("/app/devices/ticket/",
                             {"purpose": "enrol", "label": "Field team 3"})
            page = self.client.get("/app/devices/")

        self.assertContains(page, "pair-payload")
        self.assertContains(page, "https://verify-test.example.org")
        self.assertNotContains(page, "will refuse")

    def test_a_cleartext_page_still_yields_an_https_qr(self):
        # The app connects over https and nothing else, so copying the scheme
        # this page was served over produces a code no phone can use. The
        # address is upgraded instead: right wherever TLS exists, and no more
        # wrong where it does not.
        self._sign_in()
        with override_settings(
                DEVICE_PAIRING_BASE_URL="http://verify-test.example.org"):
            self.client.post("/app/devices/ticket/",
                             {"purpose": "enrol", "label": "Field team 3"})
            page = self.client.get("/app/devices/")

        self.assertContains(page, "https://verify-test.example.org")
        self.assertContains(page, "pair-payload")          # the QR is drawn
        self.assertNotContains(page, "will refuse")

    def test_the_upgrade_is_reported_rather_than_swallowed(self):
        # Reaching this page over http behind the load balancer means nginx is
        # overwriting X-Forwarded-Proto with $scheme, and the same fault leaves
        # is_secure() false for secure cookies and HSTS too. Rescuing the QR
        # must not hide the cause.
        self._sign_in()
        with override_settings(
                DEVICE_PAIRING_BASE_URL="http://verify-test.example.org"):
            self.client.post("/app/devices/ticket/",
                             {"purpose": "enrol", "label": "Field team 3"})
            page = self.client.get("/app/devices/")
        self.assertContains(page, "X-Forwarded-Proto")

    def test_an_https_page_draws_no_such_warning(self):
        self._sign_in()
        with override_settings(
                DEVICE_PAIRING_BASE_URL="https://verify-test.example.org"):
            self.client.post("/app/devices/ticket/",
                             {"purpose": "enrol", "label": "Field team 3"})
            page = self.client.get("/app/devices/")
        self.assertNotContains(page, "X-Forwarded-Proto")

    # -- the deployed shape: TLS terminated at the load balancer --------------------
    #
    # These use an https session rather than the test client's http default,
    # because https is what every real request to this app is. Without them the
    # suite only ever proves the *upgrade* works, and a regression in the proxy
    # handling would be invisible: both paths end in an https QR, and only one
    # of them also gives secure cookies, HSTS and a true `request.is_secure()`.

    BEHIND_PROXY = {"headers": {"x-forwarded-proto": "https"}}

    def _devices_page(self, **kwargs):
        """The page with the address derived from the request.

        `DEVICE_PAIRING_BASE_URL` is set in this environment, and while it is
        set nothing about the request matters -- which would make every
        assertion below pass for the wrong reason. Cleared here so these
        exercise the path a deployment without it actually takes.
        """
        self._sign_in()
        with override_settings(DEVICE_PAIRING_BASE_URL=""):
            self.client.post("/app/devices/ticket/",
                             {"purpose": "enrol", "label": "Field team 3"},
                             **kwargs)
            return self.client.get("/app/devices/", **kwargs)

    def test_the_alb_header_alone_yields_an_https_qr(self):
        # SECURE_PROXY_SSL_HEADER honours X-Forwarded-Proto, so the address is
        # already https before anything upgrades it.
        page = self._devices_page(**self.BEHIND_PROXY)
        self.assertContains(page, "https://testserver")
        self.assertContains(page, "pair-payload")

    def test_a_tls_session_needs_no_rescue(self):
        # The distinction this pins: reached over https, nothing was upgraded,
        # so no warning. If the proxy handling regressed, the QR would still be
        # https -- but this assertion would fail, which is the point.
        page = self._devices_page(**self.BEHIND_PROXY)
        self.assertNotContains(page, "X-Forwarded-Proto")

    def test_without_the_header_the_qr_is_rescued_and_the_fault_named(self):
        # nginx overwriting X-Forwarded-Proto with $scheme looks exactly like
        # this: an http request behind a TLS-terminating load balancer.
        page = self._devices_page()
        self.assertContains(page, "https://testserver")
        self.assertContains(page, "X-Forwarded-Proto")

    def test_an_https_session_is_secure_all_the_way_through(self):
        # Not just the QR: is_secure() is what drives secure cookies and HSTS,
        # and it is the thing the nginx fault actually breaks.
        self._sign_in()
        response = self.client.get("/app/devices/", **self.BEHIND_PROXY)
        self.assertTrue(response.wsgi_request.is_secure())
        with override_settings(DEVICE_PAIRING_BASE_URL=""):
            self.assertTrue(device_service.base_url(response.wsgi_request)
                            .startswith("https://"))
            self.assertFalse(device_service.was_upgraded(response.wsgi_request))

    def test_a_plain_session_is_not_secure_and_says_so(self):
        self._sign_in()
        response = self.client.get("/app/devices/")
        self.assertFalse(response.wsgi_request.is_secure())
        with override_settings(DEVICE_PAIRING_BASE_URL=""):
            self.assertTrue(device_service.was_upgraded(response.wsgi_request))

    def test_a_configured_base_url_ignores_the_request_entirely(self):
        # Worth pinning because it is what made the tests above pass for the
        # wrong reason before they cleared it: once set, the scheme of the
        # request cannot change the address in the QR.
        self._sign_in()
        response = self.client.get("/app/devices/")
        with override_settings(
                DEVICE_PAIRING_BASE_URL="https://pinned.example"):
            self.assertEqual(device_service.base_url(response.wsgi_request),
                             "https://pinned.example")
            self.assertFalse(device_service.was_upgraded(response.wsgi_request))

    def test_an_https_session_leaks_no_cleartext_urls_of_our_own(self):
        # The general form of the bug, not just the QR: every absolute URL
        # Django builds comes from the same is_secure() the load balancer header drives,
        # so one mishandled header turns all of them into http.
        page = self._devices_page(**self.BEHIND_PROXY)
        self.assertNotContains(page, "http://testserver")

    def test_upgrading_leaves_the_host_and_port_alone(self):
        # A proxy terminating TLS on a non-default port is a real deployment,
        # and inventing 443 here would break it.
        self.assertEqual(device_service.as_https("http://box.example:8443"),
                         "https://box.example:8443")
        self.assertEqual(device_service.as_https("https://box.example"),
                         "https://box.example")
        self.assertEqual(device_service.as_https("box.example"),
                         "https://box.example")

    def test_the_server_check_is_exactly_as_strict_as_the_client(self):
        for url in ["https://verify-test.example.org", "https://10.0.0.9:8443"]:
            self.assertTrue(device_service.phone_will_load(url), url)
        # Cleartext is refused wherever it points, the local network included,
        # as the app refuses it: a server rule more permissive than the client
        # would approve an address no phone can use.
        for url in ["http://verify-test.example.org", "http://192.168.7.2:8000",
                    "http://verifier.local", "verify-test.example.org"]:
            self.assertFalse(device_service.phone_will_load(url), url)

    def _enrol(self, code=None, public_key=None):
        return self.client.post(
            "/api/v1/device/enrol/",
            data=json.dumps({
                "enrolment_code": (code if code is not None
                                   else self._mint().code),
                "device_public_key": base64.b64encode(
                    public_key or self.device_pub).decode(),
                "label": "Field team 3 iPhone"}),
            content_type="application/json")

    def _sync(self, device_id, key=None, nonce=None, corrupt=False,
              code=None, extra=None):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

        if nonce is None:
            body = json.loads(self.client.post(
                "/api/v1/device/challenge/").content)
            nonce = body["challenge"]
        signer = key or self.device_key
        # DER over the DECODED challenge, which is what a Secure Enclave
        # key produces and what the verifier app already sends.
        der = signer.sign(base64.b64decode(nonce), ECDSA(hashes.SHA256()))
        if corrupt:
            der = der[:-1] + bytes([der[-1] ^ 0xFF])
        body = {"device_id": str(device_id), "challenge": nonce,
                "signature": base64.b64encode(der).decode()}
        if code is not None:
            body["code"] = code
        body.update(extra or {})
        return self.client.post(
            "/api/v1/device/keys/", data=json.dumps(body),
            content_type="application/json"), nonce

    # -- the page ---------------------------------------------------------

    def test_the_page_needs_a_signed_in_person(self):
        self.assertEqual(self.client.get("/app/devices/").status_code, 302)

    def test_pairing_shows_a_qr_carrying_the_url_and_the_code(self):
        self._sign_in()
        self.client.post("/app/devices/ticket/", {"label": "Field team 3"})
        page = self.client.get("/app/devices/").content.decode()
        code = DeviceTicket.objects.get()
        self.assertIn(code.code, page)
        self.assertIn("https://verify.example.org", page)
        self.assertIn("data-payload", page)

    def test_the_qr_payload_is_a_bootstrap_and_never_a_key(self):
        """78-odd characters: a server address and a one-time code. A key
        bundle is 1,899 characters and does not belong in a QR."""
        code = self._mint()
        payload = json.loads(device_service.ticket_payload(
            code, url="https://verify.example.org"))
        self.assertEqual(payload["v"], device_service.PAYLOAD_VERSION)
        self.assertEqual(payload["url"], "https://verify.example.org")
        self.assertEqual(payload["code"], code.code)
        self.assertEqual(payload["for"], "Ada Lovelace")
        self.assertLess(len(json.dumps(payload)), 200)
        for forbidden in ("key", "bundle", "epoch", "secret"):
            self.assertNotIn(forbidden, json.dumps(payload).lower())

    def test_the_code_is_not_left_in_the_session_to_be_shown_twice(self):
        """It is single-use; redisplaying a spent one would look valid."""
        self._sign_in()
        self.client.post("/app/devices/ticket/", {"label": "x"})
        first = self.client.get("/app/devices/").content.decode()
        second = self.client.get("/app/devices/").content.decode()
        code = DeviceTicket.objects.get().code
        self.assertIn(code, first)
        self.assertNotIn(code, second)

    # -- enrolment --------------------------------------------------------

    def test_a_code_binds_the_enclave_key_to_its_owner(self):
        response = self._enrol()
        self.assertEqual(response.status_code, 200)
        device = Device.objects.get()
        self.assertEqual(device.owner, self.user)
        self.assertEqual(bytes(device.public_key_der), self.device_pub)
        self.assertIsNotNone(DeviceTicket.objects.get().used_at)

    def test_a_code_works_exactly_once(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        code = self._mint().code
        self.assertEqual(self._enrol(code=code).status_code, 200)
        second = ec.generate_private_key(ec.SECP256R1()).public_key(
            ).public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
        again = self._enrol(code=code, public_key=second)
        self.assertEqual(again.status_code, 400)
        self.assertEqual(Device.objects.count(), 1)

    def test_an_expired_code_is_refused(self):
        code = self._mint()
        code.expires_at = timezone.now() - datetime.timedelta(seconds=1)
        code.save(update_fields=["expires_at"])
        self.assertEqual(self._enrol(code=code.code).status_code, 400)
        self.assertEqual(Device.objects.count(), 0)

    def test_a_made_up_code_is_refused_the_same_way_as_a_spent_one(self):
        """Telling them apart tells somebody guessing which ones were real."""
        spent = self._mint()
        self._enrol(code=spent.code)
        spent_msg = json.loads(self._enrol(code=spent.code).content)["error"]
        made_up = json.loads(self._enrol(code="ZZZZZZZZ").content)["error"]
        self.assertEqual(spent_msg, made_up)

    def test_rubbish_instead_of_a_public_key_is_refused(self):
        response = self._enrol(public_key=b"not a key at all")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(Device.objects.count(), 0)

    @override_settings(DEVICE_REQUIRE_APP_ATTEST=True)
    def test_requiring_attestation_refuses_rather_than_pretends(self):
        """The check is not written -- it needs a real device and Apple's
        root. A flag named "require" that waved everything through would be
        worse than no flag."""
        self.assertEqual(self._enrol().status_code, 400)
        self.assertEqual(Device.objects.count(), 0)

    # -- proving possession ----------------------------------------------

    def test_a_device_that_signs_the_challenge_gets_a_bundle(self):
        from ovcrypto import bundle as bundle_mod, keystore

        device_id = json.loads(self._enrol().content)["device_id"]
        response, _ = self._sync(device_id)
        self.assertEqual(response.status_code, 200)
        blob = base64.b64decode(json.loads(response.content)["bundle"])
        parsed = bundle_mod.Bundle.unpack(blob)
        self.assertTrue(parsed.verify({1: self.spki}))
        self.assertTrue(parsed.epoch_keys)
        self.assertEqual([t.key_id for t in parsed.trust], [1])

    def test_a_wrong_signature_gets_nothing(self):
        device_id = json.loads(self._enrol().content)["device_id"]
        response, _ = self._sync(device_id, corrupt=True)
        self.assertEqual(response.status_code, 403)

    def test_another_key_cannot_answer_for_this_device(self):
        """Naming a device id only changes which public key the signature is
        checked against."""
        from cryptography.hazmat.primitives.asymmetric import ec

        device_id = json.loads(self._enrol().content)["device_id"]
        response, _ = self._sync(
            device_id, key=ec.generate_private_key(ec.SECP256R1()))
        self.assertEqual(response.status_code, 403)

    def test_a_live_id_and_an_unknown_one_are_refused_in_the_same_words(self):
        """Holding an old QR or an export must not answer whether a phone has
        been revoked yet; the log says which it was."""
        import uuid

        device_id = json.loads(self._enrol().content)["device_id"]
        with self.assertLogs("verify.views.device_api", "INFO") as logs:
            live, _ = self._sync(device_id, corrupt=True)
        unknown, _ = self._sync(str(uuid.uuid4()), corrupt=True)
        self.assertEqual((live.status_code, unknown.status_code), (403, 403))
        self.assertEqual(live.content, unknown.content)
        self.assertEqual(json.loads(live.content)["error"],
                         device_service.UNKNOWN_DEVICE)
        self.assertIn("keys signature did not verify", logs.output[0])

    def test_a_malformed_request_is_answered_alike_for_any_id(self):
        """With no signature, or a challenge nobody issued, a live id and an
        unknown one get the same answer."""
        import uuid

        live = json.loads(self._enrol().content)["device_id"]
        nonce = json.loads(self.client.post(
            "/api/v1/device/challenge/").content)["challenge"]
        answers = []
        for device_id in (live, str(uuid.uuid4())):
            for body in ({"device_id": device_id, "challenge": nonce},
                         {"device_id": device_id, "challenge": "bm9wZQ==",
                          "signature": "c2ln"}):
                response = self.client.post(
                    "/api/v1/device/keys/", data=json.dumps(body),
                    content_type="application/json")
                answers.append((response.status_code, response.content))
        self.assertEqual(answers[0], answers[2])
        self.assertEqual(answers[1], answers[3])

    def test_a_sync_code_is_judged_only_after_the_signature(self):
        """A code is judged only after the signature verifies, so no answer
        tells a live id from an unknown one, or a code that is the phone's
        open sync from one that is not."""
        import uuid

        live = json.loads(self._enrol().content)["device_id"]
        answers = []
        for device_id in (live, str(uuid.uuid4())):
            response, _ = self._sync(device_id, corrupt=True, code="NOPE2345")
            answers.append((response.status_code, response.content))
        self.assertEqual(answers[0], answers[1])
        self.assertEqual(json.loads(answers[0][1])["error"],
                         device_service.UNKNOWN_DEVICE)

    # -- the server's signed time ----

    def test_a_sync_with_a_nonce_gets_the_time_signed_over_it(self):
        import os
        import time

        from ovcrypto import devicelog, keystore

        device_id = json.loads(self._enrol().content)["device_id"]
        nonce = os.urandom(16)
        response, _ = self._sync(device_id, extra={
            "time_nonce": base64.b64encode(nonce).decode()})
        self.assertEqual(response.status_code, 200, response.content)
        signed = json.loads(response.content)["time"]
        self.assertEqual((signed["format"], signed["version"], signed["sig_key_id"]),
                         ("CL03ST", 1, 1))
        self.assertLess(abs(signed["issued_at"] - time.time()), 5)
        message = devicelog.time_signed_bytes(
            Device.objects.get().device_id.bytes, nonce, signed["issued_at"], 1)
        self.assertTrue(keystore.verify(self.spki, message,
                                        base64.b64decode(signed["sig"])))
        # Over that nonce only: another sync's would not verify.
        other = devicelog.time_signed_bytes(
            Device.objects.get().device_id.bytes, os.urandom(16),
            signed["issued_at"], 1)
        self.assertFalse(keystore.verify(self.spki, other,
                                         base64.b64decode(signed["sig"])))

    def test_an_older_phone_sends_no_nonce_and_gets_no_time(self):
        device_id = json.loads(self._enrol().content)["device_id"]
        response, _ = self._sync(device_id)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("time", json.loads(response.content))

    def test_a_malformed_nonce_is_refused_alike_for_any_id(self):
        import uuid

        live = json.loads(self._enrol().content)["device_id"]
        answers = []
        for device_id in (live, str(uuid.uuid4())):
            for value in ("c2hvcnQ=", "not base64!", 16):
                response, _ = self._sync(device_id, extra={"time_nonce": value})
                answers.append((response.status_code, response.content))
        self.assertEqual(answers[:3], answers[3:])
        self.assertEqual({status for status, _ in answers}, {400})

    def test_with_a_signer_the_signer_signs_the_time(self):
        from unittest import mock

        from accounts import devices

        json.loads(self._enrol().content)
        device = Device.objects.get()
        with self.settings(SIGNER_SOCKET="/run/cl03-signer/app.sock"), \
                mock.patch("accounts.signer_client.sync_time",
                           return_value={"format": "CL03ST", "version": 1,
                                         "issued_at": 1, "sig_key_id": 16,
                                         "sig": "c2ln"}) as sync_time:
            signed = devices.sync_time(device, bytes(16))
        self.assertEqual(signed["sig_key_id"], 16)
        self.assertEqual(sync_time.call_args.kwargs,
                         {"device_id": device.device_id.bytes, "nonce": bytes(16)})

    def test_a_time_that_cannot_be_signed_is_left_out(self):
        from unittest import mock

        from accounts import devices

        json.loads(self._enrol().content)
        device = Device.objects.get()
        with mock.patch("accounts.credential_keys.signer",
                        side_effect=RuntimeError("no key")), \
                self.assertLogs("accounts.devices", "ERROR"):
            self.assertIsNone(devices.sync_time(device, bytes(16)))

    def test_a_nonce_cannot_be_replayed(self):
        device_id = json.loads(self._enrol().content)["device_id"]
        first, nonce = self._sync(device_id)
        self.assertEqual(first.status_code, 200)
        again, _ = self._sync(device_id, nonce=nonce)
        self.assertEqual(again.status_code, 400)

    def test_a_wrong_signature_still_spends_the_nonce(self):
        """Otherwise one captured nonce funds an unlimited grind."""
        device_id = json.loads(self._enrol().content)["device_id"]
        body = json.loads(self.client.post(
            "/api/v1/device/challenge/").content)
        self._sync(device_id, nonce=body["challenge"], corrupt=True)
        good, _ = self._sync(device_id, nonce=body["challenge"])
        self.assertEqual(good.status_code, 400)

    # -- the tier follows the person -------------------------------------

    def test_a_public_tier_owner_gets_no_restricted_keys(self):
        """Withdrawn on the person, so the phone is never SENT the restricted
        epoch key -- the separation is cryptographic, not a setting in an app.

        The owner is put on the public tier here rather than left there by the
        default: a test that leans on a default is a test that quietly changes
        meaning the day the default does."""
        from ovcrypto import bundle as bundle_mod

        self.user.device_restricted_tier = False
        self.user.save(update_fields=["device_restricted_tier"])
        device_id = json.loads(self._enrol().content)["device_id"]
        response, _ = self._sync(device_id)
        parsed = bundle_mod.Bundle.unpack(
            base64.b64decode(json.loads(response.content)["bundle"]))
        tiers = {entry.tier for entry in parsed.epoch_keys}
        self.assertEqual(tiers, {credential_keys.TIER_PUBLIC})

    def test_an_organization_member_reads_the_holder_by_default(self):
        """An operator's phone checks a document against the person holding
        it, and a verifier that cannot show the name it has just validated
        cannot make that comparison at all. Somebody trusted to run the
        verification on the web is already reading the same fields there.

        Migration 0030 grants it to the people a deployment already has,
        because a default alone would mean nothing on any deployment that
        already has its operators."""
        from ovcrypto import bundle as bundle_mod

        fresh = User.objects.create(national_id_card_number="5555444433332222",
                                    given_name="Newly")
        join(self.org, fresh)
        self.assertTrue(fresh.device_restricted_tier)

        device_id = json.loads(self._enrol().content)["device_id"]
        response, _ = self._sync(device_id)
        parsed = bundle_mod.Bundle.unpack(
            base64.b64decode(json.loads(response.content)["bundle"]))
        self.assertIn(credential_keys.TIER_RESTRICTED,
                      {entry.tier for entry in parsed.epoch_keys})

    def test_it_is_still_a_switch_and_not_a_grant_to_everybody(self):
        """On by default, and still a control: withdrawing it on the person
        reaches every phone they own, which is what keeps this a permission
        rather than an announcement."""
        self.assertIs(
            User._meta.get_field("device_restricted_tier").default, True)
        self.user.device_restricted_tier = False
        self.user.save(update_fields=["device_restricted_tier"])
        device = Device.objects.create(
            owner=self.user, label="Field team 3",
            public_key_der=self.device_pub)
        self.assertFalse(device.restricted_tier)

    def test_granting_the_person_reaches_a_phone_already_paired(self):
        """Read from the owner on every sync, never cached on the device --
        that is what makes granting and withdrawing reach every handset."""
        from ovcrypto import bundle as bundle_mod

        self.user.device_restricted_tier = False
        self.user.save(update_fields=["device_restricted_tier"])
        device_id = json.loads(self._enrol().content)["device_id"]
        self.user.device_restricted_tier = True
        self.user.save(update_fields=["device_restricted_tier"])
        response, _ = self._sync(device_id)
        parsed = bundle_mod.Bundle.unpack(
            base64.b64decode(json.loads(response.content)["bundle"]))
        self.assertIn(credential_keys.TIER_RESTRICTED,
                      {entry.tier for entry in parsed.epoch_keys})

    def test_withdrawing_it_reaches_the_phone_too(self):
        from ovcrypto import bundle as bundle_mod

        self.user.device_restricted_tier = True
        self.user.save(update_fields=["device_restricted_tier"])
        device_id = json.loads(self._enrol().content)["device_id"]
        self.user.device_restricted_tier = False
        self.user.save(update_fields=["device_restricted_tier"])
        response, _ = self._sync(device_id)
        parsed = bundle_mod.Bundle.unpack(
            base64.b64decode(json.loads(response.content)["bundle"]))
        self.assertEqual({entry.tier for entry in parsed.epoch_keys},
                         {credential_keys.TIER_PUBLIC})

    # -- revocation -------------------------------------------------------

    def test_revoking_a_device_stops_it_syncing(self):
        device_id = json.loads(self._enrol().content)["device_id"]
        self._sign_in()
        self.client.post("/app/devices/revoke/", {"device_id": device_id})
        self.assertIsNotNone(Device.objects.get().revoked_at)
        response, _ = self._sync(device_id)
        self.assertEqual(response.status_code, 403)

    def test_you_cannot_revoke_somebody_elses_device(self):
        device_id = json.loads(self._enrol().content)["device_id"]
        self._sign_in(self.other)
        self.client.post("/app/devices/revoke/", {"device_id": device_id})
        self.assertIsNone(Device.objects.get().revoked_at)

    def test_a_deployment_with_no_issuer_key_refuses_to_hand_out_a_bundle(self):
        """A bundle with an empty trust list is a phone that calls every
        credential forged."""
        device_id = json.loads(self._enrol().content)["device_id"]
        IssuerKey.objects.all().delete()
        response, _ = self._sync(device_id)
        self.assertEqual(response.status_code, 400)

    # -- the QR is a connection, and every operation uses the same one ----

    def _new_key(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())
        return key, key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)

    def _ticket(self, purpose, device_id=None, user=None):
        """Ask the page for a ticket, the way the buttons do."""
        self._sign_in(user)
        body = {"purpose": purpose}
        if device_id is not None:
            body["device_id"] = str(device_id)
        self.client.post("/app/devices/ticket/", body)
        return DeviceTicket.objects.filter(
            user=user or self.user, purpose=purpose).order_by(
                "-created_at").first()

    def _connect(self, code):
        return self.client.post(
            "/api/v1/device/connect/", data=json.dumps({"code": code}),
            content_type="application/json")

    def _paired(self):
        """One enrolled phone, and its id in the hyphenated spelling.

        The API answers in base64 of the sixteen bytes, which is what
        the app wants; the pages and the ORM want the other spelling.
        Both resolve, which is the point.
        """
        raw = json.loads(self._enrol().content)["device_id"]
        return str(uuid.UUID(bytes=base64.b64decode(raw)))

    def test_a_scanned_code_answers_with_where_to_talk_and_never_with_keys(self):
        """The whole point of the connect step: the symbol carries an address
        and a password, and the phone fetches the rest over HTTPS. A bundle is
        1,899 characters and would not fit in a symbol anyone can scan."""
        response = self._connect(self._mint().code)
        self.assertEqual(response.status_code, 200)
        body = json.loads(response.content)
        self.assertEqual(body["purpose"], "enrol")
        self.assertEqual(set(body["endpoints"]),
                         {"connect", "enrol", "challenge", "keys",
                          "revocations", "log-key", "logs"})
        self.assertTrue(body["api_base"].startswith("http"))
        for forbidden in ("bundle", "epoch", "secret", "private"):
            self.assertNotIn(forbidden, json.dumps(body).lower())

    def test_the_endpoints_it_names_are_the_ones_this_app_serves(self):
        """Built with reverse(), so a moved path cannot leave a fleet of
        phones talking to a URL that stopped existing."""
        from django.urls import resolve

        body = json.loads(self._connect(self._mint().code).content)
        base = body["api_base"]
        for name, url in body["endpoints"].items():
            self.assertTrue(url.startswith(base), name)
            # Raises Resolver404 if this app does not serve it.
            resolve(url[len(base):])

    def test_connecting_performs_nothing_and_spends_nothing(self):
        """It is a read. The endpoint that does the work spends the ticket,
        which is what keeps "one operation, once" true."""
        code = self._mint().code
        self.assertEqual(self._connect(code).status_code, 200)
        self.assertEqual(self._connect(code).status_code, 200)
        self.assertIsNone(DeviceTicket.objects.get().used_at)
        self.assertEqual(self._enrol(code=code).status_code, 200)
        self.assertEqual(Device.objects.count(), 1)

    def test_connect_refuses_a_made_up_code_exactly_as_it_refuses_a_spent_one(self):
        code = self._mint().code
        self._enrol(code=code)
        spent = json.loads(self._connect(code).content)["error"]
        made_up = json.loads(self._connect("ZZZZZZZZ").content)["error"]
        self.assertEqual(spent, made_up)

    def test_every_operation_uses_the_same_small_connection_qr(self):
        """Pairing, re-keying and syncing all fit in a symbol scanned across
        a desk, because none of them puts the operation's data in it."""
        device = Device.objects.get(device_id=self._paired())
        for purpose in ("enrol", "rekey", "sync"):
            ticket = self._ticket(purpose, device.device_id)
            payload = device_service.ticket_payload(
                ticket, url="https://verify.example.org")
            self.assertEqual(json.loads(payload)["op"], purpose)
            self.assertLess(len(payload), 220, purpose)
            for forbidden in ("bundle", "epoch", "secret", "private"):
                self.assertNotIn(forbidden, payload.lower())

    # -- a ticket authorises ONE operation --------------------------------

    def test_a_sync_ticket_cannot_enrol_a_phone(self):
        """Otherwise "one operation, once" would only mean "somebody signed in
        recently", and any live ticket would pair any handset."""
        device = Device.objects.get(device_id=self._paired())
        ticket = self._ticket("sync", device.device_id)
        _, new_pub = self._new_key()
        response = self._enrol(code=ticket.code, public_key=new_pub)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(Device.objects.count(), 1)
        ticket.refresh_from_db()
        self.assertIsNone(ticket.used_at)

    def test_an_enrol_ticket_cannot_close_out_a_sync(self):
        device_id = self._paired()
        response, _ = self._sync(device_id, code=self._mint().code)
        self.assertEqual(response.status_code, 400)

    def test_a_sync_ticket_names_one_phone_and_not_another(self):
        """Honouring it for a different handset would have the console report
        a sync that the phone in front of somebody never did."""
        first = Device.objects.get(device_id=self._paired())
        second_key, second_pub = self._new_key()
        second_id = json.loads(self._enrol(
            code=self._mint().code, public_key=second_pub).content)["device_id"]
        ticket = self._ticket("sync", first.device_id)
        response, _ = self._sync(second_id, key=second_key, code=ticket.code)
        self.assertEqual(response.status_code, 400)
        ticket.refresh_from_db()
        self.assertIsNone(ticket.used_at)

    def test_a_sync_ticket_is_not_what_authorises_the_sync(self):
        """The signature is. A stolen code buys nothing without the Enclave
        key -- which is why showing one on a screen is safe."""
        device_id = self._paired()
        ticket = self._ticket("sync", device_id)
        response, _ = self._sync(device_id, code=ticket.code, corrupt=True)
        self.assertEqual(response.status_code, 403)

    def test_a_sync_the_operator_asked_for_is_spent_by_the_sync(self):
        device_id = self._paired()
        ticket = self._ticket("sync", device_id)
        response, _ = self._sync(device_id, code=ticket.code)
        self.assertEqual(response.status_code, 200)
        ticket.refresh_from_db()
        self.assertIsNotNone(ticket.used_at)

    def test_a_phone_still_syncs_on_its_own_with_no_ticket_at_all(self):
        """The ticket closes out a request a human made on the web. It is not
        a requirement, or an unattended phone could never refresh its keys."""
        device_id = self._paired()
        response, _ = self._sync(device_id)
        self.assertEqual(response.status_code, 200)

    # -- re-keying a phone that lost its Enclave key ----------------------

    def test_a_rekey_rebinds_the_same_record_to_a_new_enclave_key(self):
        """A restored phone has no Enclave key. Without this the only way back
        is a fresh pairing, which leaves a dead row and loses the history."""
        device_id = self._paired()
        ticket = self._ticket("rekey", device_id)
        new_key, new_pub = self._new_key()
        response = self._enrol(code=ticket.code, public_key=new_pub)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(Device.objects.count(), 1)
        device = Device.objects.get()
        self.assertEqual(str(device.device_id), device_id)
        self.assertEqual(bytes(device.public_key_der), new_pub)
        # And the new key is the one that now answers for it.
        fresh, _ = self._sync(device_id, key=new_key)
        self.assertEqual(fresh.status_code, 200)

    def test_the_key_a_rekey_replaced_stops_answering(self):
        device_id = self._paired()
        ticket = self._ticket("rekey", device_id)
        self._enrol(code=ticket.code, public_key=self._new_key()[1])
        response, _ = self._sync(device_id)  # signs with the ORIGINAL key
        self.assertEqual(response.status_code, 403)

    def test_a_rekeyed_phone_reads_as_stale_until_it_syncs(self):
        """Everything it held was wrapped to the key it just replaced, so it
        holds nothing readable. A lease left running would claim otherwise."""
        device_id = self._paired()
        self._sync(device_id)
        ticket = self._ticket("rekey", device_id)
        self._enrol(code=ticket.code, public_key=self._new_key()[1])
        device = Device.objects.get()
        self.assertTrue(device.keys_stale)
        self.assertIsNone(device.last_sync_at)

    def test_the_rekey_confirmation_says_a_lost_phone_keeps_its_keys(self):
        """A re-key changes nothing on the handset it replaces, so the button
        says so, with the lease end, and points a lost phone at Revoke."""
        device_id = self._paired()
        self._sync(device_id)
        self._sign_in()
        page = self.client.get("/app/devices/").content.decode()
        lease = Device.objects.get().lease_expires_at
        self.assertIn("If the old phone was lost or stolen, neither a re-key "
                      "nor Revoke reaches it while it is offline", page)
        self.assertIn(timezone.localtime(lease).strftime("%-d %b %Y")
                      if os.name != "nt" else
                      timezone.localtime(lease).strftime("%#d %b %Y"), page)
        self.assertIn("Revoke a lost phone: that records it as lost and "
                      "stops it syncing again.", page)

    def test_a_rekey_ticket_is_never_minted_for_somebody_elses_phone(self):
        device_id = self._paired()
        self.assertIsNone(self._ticket("rekey", device_id, user=self.other))
        self.assertEqual(
            DeviceTicket.objects.filter(user=self.other).count(), 0)

    def test_a_revoked_phone_cannot_be_re_keyed_back_into_service(self):
        """Revocation is final. A re-key that undid one would be an un-revoke
        wearing a different name."""
        device_id = self._paired()
        self._sign_in()
        self.client.post("/app/devices/revoke/", {"device_id": device_id})
        self.assertIsNone(self._ticket("rekey", device_id))

    def test_a_device_scoped_ticket_is_refused_without_a_device(self):
        for purpose in ("rekey", "sync"):
            self.assertIsNone(self._ticket(purpose), purpose)

    def test_an_unknown_operation_mints_nothing(self):
        self._sign_in()
        self.client.post("/app/devices/ticket/", {"purpose": "grant-me-keys"})
        self.assertEqual(DeviceTicket.objects.count(), 0)

    def test_the_ticket_service_refuses_another_persons_phone_on_its_own(self):
        """The page filters to this person's devices, and this refuses again.

        Two layers on purpose: the view's filter is the same shape as the
        organization rule, and this is the backstop, because minting is the
        one place a ticket comes into existence.
        """
        device = Device.objects.get(device_id=self._paired())
        with self.assertRaises(device_service.PairingError):
            device_service.mint_ticket(self.other, "rekey", device=device)

    def test_a_rekey_ticket_is_not_quietly_spent_by_an_ordinary_sync(self):
        """A re-key ticket names the same phone a sync ticket would, so the
        purpose is the only thing separating them.

        Spending it here would cancel a re-key nobody performed: the page
        would stop offering the outstanding request, and the phone that lost
        its Enclave key would still have none.
        """
        device_id = self._paired()
        ticket = self._ticket("rekey", device_id)
        response, _ = self._sync(device_id, code=ticket.code)
        self.assertEqual(response.status_code, 400)
        ticket.refresh_from_db()
        self.assertIsNone(ticket.used_at)

    def test_the_page_offers_each_operation_on_the_phone_it_applies_to(self):
        device_id = self._paired()
        self._sign_in()
        page = self.client.get("/app/devices/").content.decode()
        self.assertIn('value="sync"', page)
        self.assertIn('value="rekey"', page)
        self.assertIn(device_id, page)

    def test_a_sync_qr_names_the_phone_and_escapes_what_it_was_called(self):
        """The name is typed by whoever paired it, and it is being put into
        markup. format_html, not %."""
        device_id = self._paired()
        Device.objects.filter(device_id=device_id).update(
            label='<script>alert(1)</script>')
        self._ticket("sync", device_id)
        page = self.client.get("/app/devices/").content.decode()
        self.assertIn("Refresh the keys on", page)
        self.assertNotIn("<script>alert(1)</script>", page)

    def test_a_revoked_phone_is_offered_no_operations_at_all(self):
        device_id = self._paired()
        self._sign_in()
        self.client.post("/app/devices/revoke/", {"device_id": device_id})
        page = self.client.get("/app/devices/").content.decode()
        self.assertNotIn('value="rekey"', page)
        self.assertNotIn('value="sync"', page)
        self.assertNotIn("/app/devices/rename/", page)

    # -- a malformed id is a refusal, never a crash -----------------------

    def test_a_device_id_that_is_not_a_uuid_is_refused_not_a_500(self):
        """Filtering a UUID column by junk raises rather than matching
        nothing, so without a guard an unauthenticated typo is a 500."""
        for value in ("", "not-a-uuid", "../etc/passwd", "1"):
            # A challenge this site issued, so the device id is what is
            # judged: the request's own inputs are checked before it.
            nonce = json.loads(self.client.post(
                "/api/v1/device/challenge/").content)["challenge"]
            response = self.client.post(
                "/api/v1/device/keys/",
                data=json.dumps({"device_id": value, "challenge": nonce,
                                 "signature": base64.b64encode(b"x").decode()}),
                content_type="application/json")
            self.assertEqual(response.status_code, 403, value)

    def test_an_empty_body_at_every_device_endpoint_is_refused_cleanly(self):
        for path in ("/api/v1/device/connect/", "/api/v1/device/enrol/",
                     "/api/v1/device/keys/"):
            response = self.client.post(path, data="{}",
                                        content_type="application/json")
            self.assertLess(response.status_code, 500, path)

    def test_a_junk_device_id_on_the_page_is_a_no_op(self):
        self._paired()
        self._sign_in()
        for path in ("/app/devices/revoke/", "/app/devices/ticket/",
                     "/app/devices/rename/"):
            response = self.client.post(
                path, {"purpose": "rekey", "device_id": "not-a-uuid",
                       "label": "Renamed by a typo"})
            self.assertEqual(response.status_code, 302, path)
        self.assertIsNone(Device.objects.get().revoked_at)
        self.assertFalse(DeviceTicket.objects.filter(purpose="rekey").exists())
        self.assertEqual(Device.objects.get().label, "Field team 3")

    # -- the name is the operator's, and it stays theirs -------------------

    def test_the_name_typed_at_pairing_beats_the_one_the_phone_sends(self):
        ticket = self._mint(label="Front desk iPad")
        self._enrol(code=ticket.code)        # the phone sends its own name
        self.assertEqual(Device.objects.get().label, "Front desk iPad")

    def test_the_phone_names_itself_only_when_nobody_typed_a_name(self):
        """A fallback, not a competitor: an unnamed pairing is better off with
        whatever the handset calls itself than with nothing."""
        ticket = self._mint(label="")
        self._enrol(code=ticket.code)
        self.assertEqual(Device.objects.get().label, "Field team 3 iPhone")

    def test_a_phone_neither_side_named_still_has_a_name(self):
        ticket = self._mint(label="")
        self.client.post(
            "/api/v1/device/enrol/",
            data=json.dumps({
                "enrolment_code": ticket.code,
                "device_public_key": base64.b64encode(
                    self.device_pub).decode()}),
            content_type="application/json")
        self.assertEqual(Device.objects.get().label, "Verifier device")

    def test_a_rekey_does_not_rename_the_phone(self):
        """A restored handset sends its own label again, and honouring it
        would undo a rename with no symptom at all -- the name simply changes
        back, on a screen nobody was watching."""
        device_id = self._paired()
        self._sign_in()
        self.client.post("/app/devices/rename/",
                         {"device_id": device_id, "label": "Counter 2"})
        ticket = self._ticket("rekey", device_id)
        self._enrol(code=ticket.code, public_key=self._new_key()[1])
        self.assertEqual(Device.objects.get().label, "Counter 2")

    def test_renaming_changes_what_the_list_is_read_by(self):
        device_id = self._paired()
        self._sign_in()
        response = self.client.post("/app/devices/rename/",
                                    {"device_id": device_id,
                                     "label": "Counter 2"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(Device.objects.get().label, "Counter 2")
        self.assertIn("Counter 2",
                      self.client.get("/app/devices/").content.decode())

    def test_you_cannot_rename_somebody_elses_device(self):
        """The same shape as every other operation on this page: another
        person's id does not resolve, so it is not forbidden -- it is absent."""
        device_id = self._paired()
        self._sign_in(self.other)
        self.client.post("/app/devices/rename/",
                         {"device_id": device_id, "label": "Mine now"})
        self.assertEqual(Device.objects.get().label, "Field team 3")

    def test_a_blank_rename_keeps_the_name_it_has(self):
        """`enrol()` guarantees every device has a name, so this must not be
        the one path that takes it away: a blank cell over a device id reads
        as a broken row rather than an unnamed one."""
        device_id = self._paired()
        self._sign_in()
        self.client.post("/app/devices/rename/",
                         {"device_id": device_id, "label": "   "})
        self.assertEqual(Device.objects.get().label, "Field team 3")

    def test_renaming_needs_a_signed_in_person(self):
        device_id = self._paired()
        # Pairing signs in on the way through, so the session has to go
        # before this asks its question -- otherwise it passes for the
        # reason every other test on this page passes.
        self.client.logout()
        response = self.client.post("/app/devices/rename/",
                                    {"device_id": device_id,
                                     "label": "Anyone's"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(Device.objects.get().label, "Field team 3")

    def test_the_page_offers_a_rename_carrying_the_name_it_has(self):
        """A control that opens on an empty box is one that renames a phone to
        whatever gets typed over nothing."""
        self._paired()
        self._sign_in()
        page = self.client.get("/app/devices/").content.decode()
        self.assertIn("/app/devices/rename/", page)
        self.assertIn('value="Field team 3"', page)

    def test_the_pairing_panel_says_what_the_phone_will_be_called(self):
        """The pairing panel names the phone being paired, so the operator
        sees that the name typed has taken."""
        self._sign_in()
        self.client.post("/app/devices/ticket/",
                         {"purpose": "enrol", "label": "Front desk iPad"})
        page = self.client.get("/app/devices/").content.decode()
        self.assertIn("<h2>Pair Front desk iPad</h2>", page)

    def test_an_unnamed_pairing_keeps_the_plain_heading(self):
        self._sign_in()
        self.client.post("/app/devices/ticket/", {"purpose": "enrol"})
        page = self.client.get("/app/devices/").content.decode()
        self.assertIn("<h2>Pair a phone</h2>", page)

    def test_the_pairing_panel_escapes_the_name_it_was_given(self):
        """Typed by a person and interpolated into markup. format_html."""
        self._sign_in()
        self.client.post("/app/devices/ticket/",
                         {"purpose": "enrol",
                          "label": "<script>alert(1)</script>"})
        page = self.client.get("/app/devices/").content.decode()
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("Pair &lt;script&gt;", page)

    # -- the wire is the verifier app's, not one of our own ---------------

    def test_the_field_names_are_the_ones_the_verifier_app_already_sends(self):
        """Every difference here is one branch in a client that has no reason
        to have one. The app's dialect is the incumbent; this one moved."""
        response = self._enrol()
        body = json.loads(response.content)
        self.assertEqual(set(body),
                         {"ok", "device_id", "label", "restricted_tier"})

        challenge = json.loads(
            self.client.post("/api/v1/device/challenge/").content)
        self.assertEqual(set(challenge), {"ok", "challenge"})
        # base64 of raw bytes, not hex: the app signs what it decodes.
        self.assertEqual(len(base64.b64decode(challenge["challenge"])), 24)

    def test_a_device_id_travels_as_sixteen_bytes_and_still_resolves(self):
        raw = json.loads(self._enrol().content)["device_id"]
        self.assertEqual(len(base64.b64decode(raw)), 16)
        # The same device, whichever spelling names it.
        hyphenated = str(uuid.UUID(bytes=base64.b64decode(raw)))
        self.assertEqual(device_service.parse_device_id(raw),
                         device_service.parse_device_id(hyphenated))
        self.assertEqual(self._sync(raw)[0].status_code, 200)

    def test_the_signature_is_der_over_the_decoded_challenge(self):
        """Two ways to get this wrong, and both fail identically as "signature
        did not verify" -- so both are pinned rather than left to be found."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
        from ovcrypto import keystore

        device_id = self._paired()

        def attempt(signature):
            nonce = json.loads(self.client.post(
                "/api/v1/device/challenge/").content)["challenge"]
            return self.client.post(
                "/api/v1/device/keys/",
                data=json.dumps({
                    "device_id": device_id, "challenge": nonce,
                    "signature": base64.b64encode(signature(nonce)).decode()}),
                content_type="application/json").status_code

        # Signing the base64 STRING instead of the bytes it stands for.
        self.assertEqual(attempt(lambda n: self.device_key.sign(
            n.encode(), ECDSA(hashes.SHA256()))), 403)
        # The 64-byte form ovcrypto uses internally, instead of DER.
        self.assertEqual(attempt(lambda n: keystore.der_to_raw_p256(
            self.device_key.sign(base64.b64decode(n),
                                 ECDSA(hashes.SHA256())))), 403)
        # And the one the app actually produces.
        self.assertEqual(attempt(lambda n: self.device_key.sign(
            base64.b64decode(n), ECDSA(hashes.SHA256()))), 200)


#: The device activity log's cross-language vector, from the sibling
#: OfflineVerifier's tests/test_devicelog.py. The iPhone's LogSeal.swift seals
#: this plaintext to this key, as key id 7, and must produce these bytes; this
#: deployment must open them. Change neither side alone.
LOG_VECTOR_PRIVATE = bytes([0x11] * 32)
LOG_VECTOR_PLAINTEXT = (
    '{"at":1759800000000,"build":"1.0 (1)","detail":{"verdict":"valid"},'
    '"event":"scan","outcome":"success","prev":"' + "00" * 32
    + '","seq":1,"v":1}').encode()
LOG_VECTOR_RECORD = bytes.fromhex(
    "434c30334c47010000000700000000000000010faa684ed28867b97f4a6a2dee"
    "5df8ce974e76b7018e3f22a1c4cf2678570f20ace2f496a1d6c1d34d935177ee"
    "447b3acb57b900fcb2f1e8e01437a3a6815dd7b14cd1c7c6f2b8125ece68ad95"
    "a5b552a3d8cb5db0124a4e8bb3cfcd4be17133fda4c7d4ea9de237f2f1790459"
    "9cdd3b2ad6e232c71c9c1c2363532182631d4ab96d1853d08006102815838898"
    "41fca207607bb4bd8e75fa957e3210759c2d8ff69ac0c9f746b383d15e9da6fa"
    "d1488094628861a63fbbd37b226ad180d9fd87dff62ee068282a4d7dc5bb01f5"
    "0717df07b8d202d856f44dadad7dcba1184024f795af0d938ea7cc787453c657"
    "7d")

_DEVICE_LOG_SETTINGS = dict(
    CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX,
    DEVICE_LEASE_SECONDS=2592000,
    DEVICE_CHALLENGE_TTL_SECONDS=120,
    DEVICE_REQUIRE_APP_ATTEST=False,
    DEVICE_PAIRING_BASE_URL="https://verify.example.org")


class _DeviceLogFixture:
    """An issuer key, a wrapping key and one paired phone -- DevicePairingTest's
    setUp, minus the pairing itself, which is not what these test."""

    #: A device-clock time in the past, in milliseconds, for records that
    #: should read as plausible.
    AT = 1_790_000_000_000

    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        credential_keys.reset_caches()
        self.addCleanup(credential_keys.reset_caches)

        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.pem = os.path.join(self.dir, "issuer.pem")
        self.issuer = ec.generate_private_key(ec.SECP256R1())
        with open(self.pem, "wb") as handle:
            handle.write(self.issuer.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        os.chmod(self.pem, stat.S_IRUSR | stat.S_IWUSR)
        self.spki = self.issuer.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)

        self.settings_ctx = override_settings(
            CREDENTIAL_ISSUER_KEY_PATH=self.pem, CREDENTIAL_ISSUER_KEY_ID=1)
        self.settings_ctx.enable()
        self.addCleanup(self.settings_ctx.disable)

        IssuerKey.objects.create(
            key_id=1, spki_der=self.spki, is_active=True,
            not_before=timezone.now() - datetime.timedelta(days=1),
            not_after=timezone.now() + datetime.timedelta(days=730))

        self.org = make_org(name="Alpha")
        self.user = User.objects.create(
            national_id_card_number="1111222233334444",
            given_name="Ada", middle_name="Byron", last_name="Lovelace")
        join(self.org, self.user)

        # The phone's Secure Enclave key, which never leaves it.
        self.device_key = ec.generate_private_key(ec.SECP256R1())
        self.device = Device.objects.create(
            label="Front desk iPhone", owner=self.user,
            public_key_der=self.device_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo),
            lease_expires_at=timezone.now() + datetime.timedelta(days=30))


@override_settings(**_DEVICE_LOG_SETTINGS)
class DeviceLogTest(_DeviceLogFixture, TestCase):
    """The device activity log: the key a phone seals to, and the upload.

    The phone holds no key that opens its own log -- each record is sealed to
    a public key handed out in an issuer-signed statement -- and uploads are
    signed by its Enclave key over the challenge AND the records. What is
    opened is stored with the chain judged, and no batch is ever refused for
    one bad record, because a phone whose upload is refused can never clear
    its database.
    """

    # -- helpers ------------------------------------------------------------

    def _statement(self):
        response = self.client.get("/api/v1/device/log-key/")
        return response, json.loads(response.content)

    def _log_key(self):
        """(key id, public key) as the phone would take them from the
        statement."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PublicKey)

        _, body = self._statement()
        return body["key_id"], X25519PublicKey.from_public_bytes(
            base64.b64decode(body["public_key"]))

    def _seal(self, number, previous, *, key=None, raw=None, **fields):
        """Seal record `number`, naming `previous` -- any field can be
        overridden, `seq` and `prev` included, to make it say something
        else."""
        from ovcrypto import devicelog

        key_id, public = key or self._log_key()
        if raw is None:
            body = {"v": 1, "seq": number, "prev": previous.hex(),
                    "at": self.AT + number * 1000, "event": "scan",
                    "outcome": "success", "build": "1.0 (323)",
                    "detail": {"verdict": "valid"}}
            body.update(fields)
            # Ellipsis drops a field, for the cases that leave one out.
            raw = json.dumps({k: v for k, v in body.items()
                              if v is not Ellipsis}).encode()
        return devicelog.seal(raw, key_id=key_id, seq=number,
                              recipient=public)

    def _chain(self, count, *, key=None):
        """Records 1..count, each naming the one before, as a phone writes
        them."""
        from ovcrypto import devicelog

        key = key or self._log_key()
        prev, records = devicelog.GENESIS, []
        for seq in range(1, count + 1):
            records.append(self._seal(seq, prev, key=key))
            prev = devicelog.record_hash(records[-1])
        return records

    def _challenge(self):
        return json.loads(self.client.post(
            "/api/v1/device/challenge/").content)["challenge"]

    def _der(self, message):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

        return self.device_key.sign(message, ECDSA(hashes.SHA256()))

    def _upload(self, records, *, device_id=None, nonce=None, signs=None,
                wire_records=None):
        """POST /logs/ the way the app does: a DER signature over
        `upload_signed_bytes(decoded challenge, records)`, unless `signs`
        says what to sign instead."""
        from ovcrypto import devicelog

        nonce = nonce or self._challenge()
        challenge = base64.b64decode(nonce)
        message = (signs(challenge) if signs
                   else devicelog.upload_signed_bytes(challenge, records))
        payload = {
            "device_id": (device_id if device_id is not None
                          else device_service.device_id_wire(self.device)),
            "challenge": nonce,
            "signature": base64.b64encode(self._der(message)).decode(),
            "records": (wire_records if wire_records is not None else
                        [base64.b64encode(r).decode() for r in records]),
        }
        response = self.client.post(
            "/api/v1/device/logs/", data=json.dumps(payload),
            content_type="application/json")
        return response, json.loads(response.content)

    def _assert_acknowledges(self, ack, through_seq, records):
        """The acknowledgement verifies with the issuer key over exactly this
        upload up to `through_seq`."""
        from ovcrypto import devicelog, keystore

        self.assertEqual((ack["format"], ack["version"], ack["sig_key_id"]),
                         ("CL03LA", 1, 1))
        signed = devicelog.ack_signed_bytes(
            self.device.device_id.bytes, through_seq,
            devicelog.upload_digest(records), ack["issued_at"], 1)
        self.assertTrue(keystore.verify(self.spki, signed,
                                        base64.b64decode(ack["sig"])))

    def _counts(self, body):
        return {key: body[key] for key in (
            "through_seq", "stored", "duplicates", "conflicts", "unreadable",
            "breaks")}

    def _entry(self, seq):
        from accounts.models import DeviceLogEntry

        return DeviceLogEntry.objects.get(device_uuid=self.device.device_id,
                                          seq=seq)

    # -- the key statement --------------------------------------------------

    def test_the_statement_is_signed_by_the_issuer_key_the_phone_pins(self):
        """A phone must refuse a log key nobody it trusts vouched for, or a
        server impersonator hands it a key whose private half it holds."""
        from ovcrypto import devicelog, keystore

        response, body = self._statement()
        self.assertEqual(response.status_code, 200, body)
        self.assertEqual(set(body), {"ok", "format", "version", "key_id",
                                     "public_key", "issued_at", "not_after",
                                     "sig_key_id", "sig"})
        self.assertEqual((body["format"], body["version"], body["sig_key_id"]),
                         ("CL03LK", 1, 1))
        public = base64.b64decode(body["public_key"])
        self.assertEqual(len(public), 32)
        self.assertEqual(body["not_after"] - body["issued_at"], 90 * 86400)
        self.assertTrue(response["Cache-Control"].startswith("public"))

        def verifies(key_id=body["key_id"], public=public,
                     issued_at=body["issued_at"],
                     not_after=body["not_after"]):
            return keystore.verify_p256(
                self.spki,
                devicelog.key_statement_bytes(key_id, public, issued_at,
                                              not_after, body["sig_key_id"]),
                base64.b64decode(body["sig"]))

        self.assertTrue(verifies())
        # Every field is inside the signature: change any one and it fails.
        self.assertFalse(verifies(key_id=body["key_id"] + 1))
        self.assertFalse(verifies(public=bytes(32)))
        self.assertFalse(verifies(issued_at=body["issued_at"] - 1))
        self.assertFalse(verifies(not_after=body["not_after"] + 1))

    def test_nothing_is_vouched_for_or_accepted_while_unconfigured(self):
        """An unsigned key would be worse than none. And an upload is
        refused BEFORE its challenge is spent: it is the server's fault."""
        from accounts.models import DeviceChallenge, DeviceLogKey

        with override_settings(CREDENTIAL_ISSUER_KEY_PATH=""):
            response, body = self._statement()
        self.assertEqual(response.status_code, 503)
        self.assertFalse(body["ok"])
        self.assertTrue(body["error"])
        self.assertFalse(DeviceLogKey.objects.exists())

        nonce = self._challenge()
        with override_settings(CREDENTIAL_EPOCH_WRAP_KEY=""):
            response, body = self._upload(
                [], nonce=nonce, wire_records=["T1ZMRw=="])
        self.assertEqual(response.status_code, 503)
        self.assertIsNone(DeviceChallenge.objects.get(nonce=nonce).used_at)

    def test_one_key_is_handed_out_until_it_is_retired(self):
        from accounts.models import DeviceLogKey

        _, first = self._statement()
        _, again = self._statement()
        self.assertEqual((first["key_id"], first["public_key"]),
                         (again["key_id"], again["public_key"]))
        self.assertEqual(DeviceLogKey.objects.count(), 1)

        DeviceLogKey.objects.update(retired_at=timezone.now())
        _, fresh = self._statement()
        self.assertNotEqual(fresh["key_id"], first["key_id"])
        self.assertNotEqual(fresh["public_key"], first["public_key"])

    def test_the_private_half_is_kept_wrapped_and_is_the_statements(self):
        """Wrapped exactly as an epoch key is, so it needs no new secret --
        and never stored in the clear."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey)
        from ovcrypto import kdf

        from accounts.models import DeviceLogKey

        _, body = self._statement()
        row = DeviceLogKey.objects.get()
        self.assertEqual(row.id, body["key_id"])
        raw = credential_keys._wrapper().unwrap(bytes(row.wrapped_private_key))
        self.assertNotIn(raw, bytes(row.wrapped_private_key))
        self.assertEqual(
            kdf.public_bytes(X25519PrivateKey.from_private_bytes(
                raw).public_key()),
            base64.b64decode(body["public_key"]))

    def test_a_retired_key_still_opens_what_was_sealed_to_it(self):
        """A phone seals to the statement it last fetched; retiring a key must
        not turn its unsent records into placeholders."""
        from ovcrypto import devicelog

        from accounts.models import DeviceLogKey

        old = self._log_key()
        first = self._seal(1, devicelog.GENESIS, key=old)
        DeviceLogKey.objects.filter(id=old[0]).update(
            retired_at=timezone.now())
        new = self._log_key()
        self.assertNotEqual(new[0], old[0])
        second = self._seal(2, devicelog.record_hash(first), key=new)

        response, body = self._upload([first, second])
        self.assertEqual(response.status_code, 200, body)
        self.assertEqual((body["stored"], body["unreadable"], body["breaks"]),
                         (2, 0, 0))
        self.assertEqual([self._entry(1).key_id, self._entry(2).key_id],
                         [old[0], new[0]])

    # -- an upload ----------------------------------------------------------

    def test_an_upload_is_opened_stored_and_acknowledged(self):
        from ovcrypto import devicelog

        from accounts.models import DeviceLogEntry, DeviceLogKey

        records = self._chain(2)
        before = timezone.now()
        response, body = self._upload(records)
        self.assertEqual(response.status_code, 200, body)
        ack = body.pop("ack")
        self.assertEqual(body, {"ok": True, "through_seq": 2, "stored": 2,
                                "duplicates": 0, "conflicts": 0,
                                "unreadable": 0, "breaks": 0, "refused": 0,
                                "deferred": 0})
        self._assert_acknowledges(ack, 2, records)
        self.assertEqual(response["Cache-Control"], "no-store")

        rows = list(DeviceLogEntry.objects.order_by("seq"))
        self.assertEqual([row.seq for row in rows], [1, 2])
        first = rows[0]
        self.assertEqual(first.device, self.device)
        self.assertEqual(first.device_uuid, self.device.device_id)
        self.assertEqual(first.device_label, "Front desk iPhone")
        self.assertEqual(first.owner, self.user)
        self.assertEqual(first.owner_name, "Ada Byron Lovelace")
        self.assertEqual(first.owner_national_id_number, "1111222233334444")
        self.assertEqual((first.event, first.outcome, first.app_build),
                         ("scan", "success", "1.0 (323)"))
        self.assertEqual(first.detail, {"verdict": "valid"})
        # Both clocks: the phone's claim and this server's receipt.
        self.assertEqual(first.occurred_at, datetime.datetime(
            2026, 9, 21, 14, 13, 21, tzinfo=datetime.timezone.utc))
        self.assertGreaterEqual(first.received_at, before)
        self.assertEqual([bytes(row.record_hash) for row in rows],
                         [devicelog.record_hash(r) for r in records])
        self.assertTrue(all(row.chain_ok and row.readable for row in rows))
        self.assertEqual({row.key_id for row in rows},
                         {DeviceLogKey.objects.get().id})

    def test_the_record_outlives_the_phone_and_its_owner(self):
        """Snapshots, so an audited party cannot erase the trail by being
        deleted -- removing a person cascades to their phones."""
        from accounts.models import DeviceLogEntry

        device_uuid = self.device.device_id
        self._upload(self._chain(1))
        self.user.delete()
        self.assertFalse(Device.objects.exists())

        entry = DeviceLogEntry.objects.get()
        self.assertIsNone(entry.device)
        self.assertIsNone(entry.owner)
        self.assertEqual(entry.device_uuid, device_uuid)
        self.assertEqual(entry.device_label, "Front desk iPhone")
        self.assertEqual(entry.owner_name, "Ada Byron Lovelace")
        self.assertEqual(entry.owner_national_id_number, "1111222233334444")

    def test_sending_the_same_batch_again_changes_nothing(self):
        """What makes a retry safe: a phone that lost the answer sends again."""
        from accounts.models import DeviceLogEntry

        records = self._chain(2)
        self._upload(records)
        response, body = self._upload(records)
        self.assertEqual(response.status_code, 200, body)
        self.assertEqual(self._counts(body), {
            "through_seq": 2, "stored": 0, "duplicates": 2, "conflicts": 0,
            "unreadable": 0, "breaks": 0})
        self.assertEqual(DeviceLogEntry.objects.count(), 2)

    def test_a_gap_is_kept_and_counted_as_a_break(self):
        """Record 3 never arrives. 4 is stored -- refusing it would hide the
        gap -- and marked as not following anything held."""
        from ovcrypto import devicelog

        records = self._chain(3)
        self._upload(records[:2])
        fourth = self._seal(4, devicelog.record_hash(records[2]))
        response, body = self._upload([fourth])
        self.assertEqual(response.status_code, 200, body)
        self.assertEqual((body["through_seq"], body["stored"],
                          body["breaks"]), (4, 1, 1))
        self.assertFalse(self._entry(4).chain_ok)
        self.assertTrue(self._entry(4).readable)

    def test_a_record_naming_a_rewritten_predecessor_is_a_break(self):
        """The number follows; the hash does not. The record before it was
        not the one this server holds."""
        from ovcrypto import devicelog

        first = self._chain(1)[0]
        self._upload([first])
        other = self._seal(1, devicelog.GENESIS,
                           detail={"verdict": "forged"})
        response, body = self._upload(
            [self._seal(2, devicelog.record_hash(other))])
        self.assertEqual(body["breaks"], 1)
        self.assertFalse(self._entry(2).chain_ok)

    def test_the_first_record_must_name_genesis(self):
        from ovcrypto import devicelog

        response, body = self._upload([self._seal(1, b"\x01" * 32)])
        self.assertEqual(body["breaks"], 1)
        self.assertFalse(self._entry(1).chain_ok)
        self.assertNotEqual(devicelog.GENESIS, b"\x01" * 32)

    def test_a_phone_whose_log_starts_past_one_is_a_break(self):
        from ovcrypto import devicelog

        response, body = self._upload([self._seal(2, devicelog.GENESIS)])
        self.assertEqual((body["stored"], body["breaks"]), (1, 1))

    def test_a_different_record_under_a_held_number_is_a_conflict(self):
        """The phone has rewritten its own history. The record held FIRST
        stands -- keeping it is what makes the rewrite visible -- and it is
        logged."""
        from ovcrypto import devicelog

        records = self._chain(2)
        self._upload(records)
        rewritten = self._seal(2, devicelog.record_hash(records[0]),
                               detail={"verdict": "forged"})
        with self.assertLogs("accounts.device_log", level="WARNING") as logs:
            response, body = self._upload([rewritten])
        self.assertEqual(response.status_code, 200, body)
        self.assertEqual(self._counts(body), {
            "through_seq": 2, "stored": 0, "duplicates": 0, "conflicts": 1,
            "unreadable": 0, "breaks": 0})
        kept = self._entry(2)
        self.assertEqual(bytes(kept.record_hash),
                         devicelog.record_hash(records[1]))
        self.assertEqual(kept.detail, {"verdict": "valid"})
        self.assertIn("sequence 2", logs.output[0])

    def test_a_record_that_does_not_open_is_kept_as_a_placeholder(self):
        """Never a refusal of the batch: a phone whose upload is refused can
        never clear its database. And the chain is over the SEALED bytes, so
        the record after it still links to it."""
        from ovcrypto import devicelog

        records = self._chain(2)
        broken = bytearray(records[1])
        broken[-1] ^= 0x01
        broken = bytes(broken)
        third = self._seal(3, devicelog.record_hash(broken))

        response, body = self._upload([records[0], broken, third])
        self.assertEqual(response.status_code, 200, body)
        self.assertEqual(self._counts(body), {
            "through_seq": 3, "stored": 3, "duplicates": 0, "conflicts": 0,
            "unreadable": 1, "breaks": 0})
        placeholder = self._entry(2)
        self.assertEqual(
            (placeholder.event, placeholder.outcome, placeholder.readable,
             placeholder.chain_ok, placeholder.occurred_at,
             placeholder.detail),
            ("unreadable", "failure", False, False, None,
             {"reason": "record does not open"}))
        self.assertEqual(bytes(placeholder.record_hash),
                         devicelog.record_hash(broken))
        self.assertTrue(self._entry(3).chain_ok)

    def test_a_record_sealed_to_a_key_never_made_here_is_a_placeholder(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey)
        from ovcrypto import devicelog

        stranger = X25519PrivateKey.generate().public_key()
        record = self._seal(1, devicelog.GENESIS, key=(4242, stranger))
        response, body = self._upload([record])
        self.assertEqual((body["stored"], body["unreadable"]), (1, 1))
        entry = self._entry(1)
        self.assertEqual(entry.key_id, 4242)
        self.assertIn("unknown log key 4242", entry.detail["reason"])

    def test_a_record_that_opens_to_something_malformed_is_a_placeholder(self):
        """Each of these opens -- the seal is good -- and says something the
        format does not allow. Each is kept under its number, unreadable."""
        cases = {
            "not JSON": b"\xff\xfe not json",
            "not an object": b"[1, 2]",
            "another version": {"v": 2},
            "true is not 1": {"v": True},
            "no version": {"v": ...},
            "a number the header does not carry": {"seq": 999},
            "uppercase prev": {"prev": "AB" * 32},
            "a short prev": {"prev": "ab" * 31},
            "a time as a string": {"at": "1790000000000"},
            "a time as a float": {"at": 1790000000000.5},
            "an event in capitals": {"event": "Scan"},
            "an event too long": {"event": "a" * 41},
            "no event": {"event": ...},
            "an outcome nobody defined": {"outcome": "maybe"},
            "a build too long": {"build": "x" * 41},
            "a build that is a number": {"build": 323},
            "no detail": {"detail": ...},
            "a detail that is a list": {"detail": ["verdict"]},
            "a float in detail": {"detail": {"score": 0.5}},
            "an object in detail": {"detail": {"a": {"b": 1}}},
            "too many detail keys": {"detail": {"k%d" % i: i
                                                for i in range(33)}},
            "a detail value too long": {"detail": {"note": "x" * 201}},
            "a detail key too long": {"detail": {"k" * 41: 1}},
            "an empty detail key": {"detail": {"": 1}},
        }
        records = []
        for seq, (name, case) in enumerate(cases.items(), start=1):
            if isinstance(case, bytes):
                records.append(self._seal(seq, b"", raw=case))
            else:
                records.append(self._seal(seq, bytes(32), **case))

        response, body = self._upload(records)
        self.assertEqual(response.status_code, 200, body)
        self.assertEqual((body["stored"], body["unreadable"]),
                         (len(cases), len(cases)))
        for seq, name in enumerate(cases, start=1):
            with self.subTest(name):
                entry = self._entry(seq)
                self.assertFalse(entry.readable)
                self.assertEqual(entry.event, "unreadable")
                self.assertTrue(entry.detail["reason"])

    def test_the_limits_themselves_are_accepted(self):
        """The boundaries are inclusive -- pinned so tightening one is a
        decision, not a slip."""
        from ovcrypto import devicelog

        detail = {"k%02d" % i: "x" * 200 for i in range(31)}
        detail["k" * 40] = None
        record = self._seal(1, devicelog.GENESIS, event="e" * 40,
                            build="b" * 40, detail=detail)
        flags = self._seal(2, devicelog.record_hash(record), outcome="notice",
                           detail={"yes": True, "no": False, "n": -5,
                                   "none": None})
        response, body = self._upload([record, flags])
        self.assertEqual(response.status_code, 200, body)
        self.assertEqual((body["unreadable"], body["breaks"]), (0, 0))
        self.assertEqual(self._entry(1).detail, detail)
        self.assertEqual(self._entry(2).detail,
                         {"yes": True, "no": False, "n": -5, "none": None})

    def test_an_event_this_deployment_never_heard_of_is_kept(self):
        """Forward compatible: a newer app records events, and adds fields,
        an older deployment does not know."""
        from ovcrypto import devicelog

        record = self._seal(1, devicelog.GENESIS, event="face_capture",
                            outcome="notice", added_later={"x": 1})
        response, body = self._upload([record])
        self.assertEqual(body["unreadable"], 0)
        entry = self._entry(1)
        self.assertTrue(entry.readable)
        self.assertEqual((entry.event, entry.outcome),
                         ("face_capture", "notice"))

    def test_a_record_with_no_readable_header_is_counted_not_stored(self):
        """It has no number to be filed under, and none to acknowledge."""
        from accounts.models import DeviceLogEntry

        good = self._chain(1)[0]
        junk = [b"CL03LG" + bytes(10),                    # too short
                b"XXXXXX" + good[6:],                   # not a log record
                good[:6] + b"\x02" + good[7:],          # another version
                good[:11] + bytes(8) + good[19:]]       # sequence number 0
        response, body = self._upload([good] + junk)
        self.assertEqual(response.status_code, 200, body)
        self.assertEqual((body["through_seq"], body["stored"],
                          body["unreadable"]), (1, 1, 4))
        self.assertEqual(DeviceLogEntry.objects.count(), 1)

        response, body = self._upload(junk[:1])
        self.assertEqual((body["through_seq"], body["stored"],
                          body["unreadable"]), (0, 0, 1))

    def test_a_time_the_phone_could_not_have_meant_is_kept_aside(self):
        """The phone's clock is the phone's to set. An implausible claim is
        neither believed nor thrown away."""
        from ovcrypto import devicelog

        now_ms = int(timezone.now().timestamp() * 1000)
        hour_ago = now_ms - 3600 * 1000
        first = self._seal(1, devicelog.GENESIS, at=0)
        second = self._seal(2, devicelog.record_hash(first),
                            at=now_ms + 2 * 86400 * 1000)
        third = self._seal(3, devicelog.record_hash(second), at=hour_ago)
        response, body = self._upload([first, second, third])
        self.assertEqual((body["unreadable"], body["breaks"]), (0, 0))

        for seq, claimed in ((1, 0), (2, now_ms + 2 * 86400 * 1000)):
            entry = self._entry(seq)
            self.assertIsNone(entry.occurred_at)
            self.assertEqual(entry.detail["claimed_at_ms"], claimed)
            self.assertTrue(entry.readable and entry.chain_ok)
        entry = self._entry(3)
        self.assertEqual(int(entry.occurred_at.timestamp() * 1000), hour_ago)
        self.assertNotIn("claimed_at_ms", entry.detail)

    # -- who may upload -----------------------------------------------------

    def test_a_signature_over_other_records_is_refused_and_spends_the_challenge(self):
        """The signature binds the records: a valid one cannot be kept and
        the records swapped under it. And the nonce is gone either way."""
        from ovcrypto import devicelog

        from accounts.models import DeviceLogEntry

        records = self._chain(2)
        nonce = self._challenge()
        response, body = self._upload(
            records, nonce=nonce,
            signs=lambda c: devicelog.upload_signed_bytes(c, records[:1]))
        self.assertEqual(response.status_code, 403)
        # The unknown-device text: the same as for an id never
        # registered.
        self.assertEqual(body["error"], device_service.UNKNOWN_DEVICE)
        self.assertFalse(DeviceLogEntry.objects.exists())

        response, body = self._upload(records, nonce=nonce)
        self.assertEqual(response.status_code, 400)
        self.assertFalse(DeviceLogEntry.objects.exists())

    def test_a_signature_over_the_bare_challenge_is_refused(self):
        """What /keys/ accepts binds no records, so it is not an upload."""
        from accounts.models import DeviceLogEntry

        response, body = self._upload(self._chain(1), signs=lambda c: c)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(DeviceLogEntry.objects.exists())

    def test_an_upload_signature_is_not_a_key_request(self):
        """Domain-separated: replayed at /keys/ it fails, while the ordinary
        /keys/ signature from the same phone still works."""
        from ovcrypto import devicelog

        records = self._chain(1)
        device_id = device_service.device_id_wire(self.device)

        def keys(signs):
            nonce = self._challenge()
            der = self._der(signs(base64.b64decode(nonce)))
            return self.client.post(
                "/api/v1/device/keys/", data=json.dumps({
                    "device_id": device_id, "challenge": nonce,
                    "signature": base64.b64encode(der).decode()}),
                content_type="application/json").status_code

        self.assertEqual(
            keys(lambda c: devicelog.upload_signed_bytes(c, records)), 403)
        self.assertEqual(keys(lambda c: c), 200)

    def test_an_unknown_revoked_or_unparseable_device_is_refused_alike(self):
        from accounts.models import DeviceLogEntry

        records = self._chain(1)
        for device_id in (base64.b64encode(uuid.uuid4().bytes).decode(),
                          "not-a-device"):
            response, body = self._upload(records, device_id=device_id)
            self.assertEqual(response.status_code, 403, device_id)
            self.assertEqual(body["error"], device_service.UNKNOWN_DEVICE)
        device_service.revoke(self.device)
        response, body = self._upload(records)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(body["error"], device_service.UNKNOWN_DEVICE)
        self.assertFalse(DeviceLogEntry.objects.exists())

    def test_the_upload_is_bounded_before_anything_is_decoded(self):
        from accounts.models import DeviceLogEntry

        good = base64.b64encode(self._chain(1)[0]).decode()
        oversize = base64.b64encode(b"CL03LG" + bytes(8187)).decode()
        cases = [
            ([], "1 to 1000"),
            ("not a list", "1 to 1000"),
            ([good] * 1001, "at most 1000"),
            ([good, oversize], "records[1] is over the 8192-byte limit"),
            (["not base64!"], "not valid base64"),
            ([123], "not a base64 string"),
        ]
        for records, message in cases:
            with self.subTest(message):
                response, body = self._upload([], wire_records=records)
                self.assertEqual(response.status_code, 400, body)
                self.assertIn(message, body["error"])
        self.assertFalse(DeviceLogEntry.objects.exists())

        response = self.client.post("/api/v1/device/logs/", data="[1]",
                                    content_type="application/json")
        self.assertEqual(response.status_code, 400)

    def test_a_record_of_exactly_the_limit_is_accepted(self):
        from ovcrypto import devicelog

        record = devicelog.header_bytes(1, 1) + bytes(8192 - 19)
        self.assertEqual(len(record), 8192)
        response, body = self._upload([record])
        self.assertEqual(response.status_code, 200, body)
        self.assertEqual((body["stored"], body["unreadable"]), (1, 1))

    def test_a_body_over_djangos_own_cap_is_answered_in_the_dialect(self):
        """DATA_UPLOAD_MAX_MEMORY_SIZE sits below 1000 full-size records. The
        phone is told, in JSON, to send fewer -- not handed an error page."""
        from accounts.models import DeviceLogEntry

        records = self._chain(2)
        with override_settings(DATA_UPLOAD_MAX_MEMORY_SIZE=200):
            response, body = self._upload(records)
        self.assertEqual(response.status_code, 413)
        self.assertFalse(body["ok"])
        self.assertIn("send fewer records", body["error"])
        self.assertFalse(DeviceLogEntry.objects.exists())

    def test_keys_this_deployment_cannot_unwrap_refuse_the_upload_whole(self):
        """The server's fault, not the phone's. Storing placeholders and
        acknowledging them would have the phone delete records this
        deployment ought to have read."""
        from accounts.models import DeviceLogEntry

        records = self._chain(1)
        with override_settings(CREDENTIAL_EPOCH_WRAP_KEY="ff" * 32):
            credential_keys.reset_caches()
            with self.assertLogs("verify.views.device_api", level="ERROR"):
                response, body = self._upload(records)
        credential_keys.reset_caches()
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("through_seq", body)
        self.assertFalse(DeviceLogEntry.objects.exists())

    def test_two_uploads_crossing_are_told_to_send_again(self):
        from django.db import IntegrityError

        from accounts.models import DeviceLogEntry

        records = self._chain(1)
        with patch.object(DeviceLogEntry.objects, "bulk_create",
                          side_effect=IntegrityError("unique")):
            response, body = self._upload(records)
        self.assertEqual(response.status_code, 409)
        self.assertNotIn("through_seq", body)

    def test_each_endpoint_takes_only_its_own_method(self):
        self.assertEqual(
            self.client.post("/api/v1/device/log-key/").status_code, 405)
        self.assertEqual(
            self.client.get("/api/v1/device/logs/").status_code, 405)

    # -- the format -----------------------------------------------------------

    def test_the_cross_language_vector_opens_here(self):
        """What the iPhone seals, this deployment opens -- byte for byte, with
        its verbatim copy of ovcrypto/devicelog.py."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey)
        from ovcrypto import devicelog, kdf

        from accounts.models import DeviceLogKey

        private = X25519PrivateKey.from_private_bytes(LOG_VECTOR_PRIVATE)
        opened = devicelog.open_record(LOG_VECTOR_RECORD, {7: private})
        self.assertEqual((opened.key_id, opened.seq), (7, 1))
        self.assertEqual(opened.plaintext, LOG_VECTOR_PLAINTEXT)

        # And end to end, through the upload, held as key id 7.
        DeviceLogKey.objects.create(
            id=7, public_key=kdf.public_bytes(private.public_key()),
            wrapped_private_key=credential_keys._wrapper().wrap(
                LOG_VECTOR_PRIVATE))
        response, body = self._upload([LOG_VECTOR_RECORD])
        self.assertEqual(response.status_code, 200, body)
        self.assertEqual((body["stored"], body["unreadable"], body["breaks"]),
                         (1, 0, 0))
        entry = self._entry(1)
        self.assertEqual(
            (entry.event, entry.outcome, entry.app_build, entry.detail,
             entry.key_id, entry.chain_ok, entry.readable),
            ("scan", "success", "1.0 (1)", {"verdict": "valid"}, 7, True,
             True))
        self.assertEqual(entry.occurred_at, datetime.datetime(
            2025, 10, 7, 1, 20, tzinfo=datetime.timezone.utc))

    def test_the_phone_is_told_where_both_endpoints_are(self):
        """Through `service_descriptor`, so a moved path cannot strand a
        fleet -- and both resolve here."""
        from django.urls import resolve

        from verify import views

        endpoints = device_service.service_descriptor(
            "https://verify.example.org")
        self.assertEqual(endpoints["log-key"],
                         "https://verify.example.org/api/v1/device/log-key/")
        self.assertEqual(endpoints["logs"],
                         "https://verify.example.org/api/v1/device/logs/")
        self.assertIs(resolve(reverse("device_log_key")).func,
                      views.device_log_key)
        self.assertIs(resolve(reverse("device_logs")).func, views.device_logs)
        self.assertIs(resolve(reverse("site_export_device_logs")).func,
                      views.site_export_device_logs)

    def test_the_log_is_read_only_in_the_django_admin(self):
        from accounts.models import DeviceLogEntry, DeviceLogKey

        self.assertNotIn(DeviceLogKey, admin.site._registry)
        model_admin = admin.site._registry[DeviceLogEntry]
        request = MagicMock()
        self.assertFalse(model_admin.has_add_permission(request))
        self.assertFalse(model_admin.has_change_permission(request))
        self.assertFalse(model_admin.has_delete_permission(request))

    # -- the signed acknowledgement -------------------

    def test_a_deferred_upload_is_acknowledged_only_as_far_as_it_was_stored(self):
        records = self._chain(5)
        with self.settings(DEVICE_LOG_DAILY_RECORDS=3):
            _, body = self._upload(records)
        self._assert_acknowledges(body["ack"], 3, records)

    def test_an_acknowledgement_that_cannot_be_signed_is_left_out(self):
        """The records are stored all the same; the phone keeps its copies
        and sends them again, which arrive as duplicates."""
        from unittest import mock

        records = self._chain(2)
        with mock.patch("accounts.credential_keys.signer",
                        side_effect=RuntimeError("no key")), \
                self.assertLogs("accounts.device_log", "ERROR"):
            response, body = self._upload(records)
        self.assertEqual(response.status_code, 200, body)
        self.assertNotIn("ack", body)
        self.assertEqual(self._stored(), 2)

    def test_with_a_signer_the_signer_signs_it(self):
        from unittest import mock

        records = self._chain(2)
        with self.settings(SIGNER_SOCKET="/run/cl03-signer/app.sock"), \
                mock.patch("accounts.signer_client.log_ack",
                           return_value={"format": "CL03LA", "version": 1,
                                         "issued_at": 1, "sig_key_id": 16,
                                         "sig": "c2ln"}) as log_ack:
            from accounts import device_log

            ack = device_log.acknowledgement(self.device, 2, records)
        self.assertEqual(ack["sig_key_id"], 16)
        self.assertEqual(log_ack.call_args.kwargs["through_seq"], 2)
        self.assertEqual(log_ack.call_args.kwargs["device_id"],
                         self.device.device_id.bytes)

    def test_nothing_numbered_is_nothing_to_acknowledge(self):
        response, body = self._upload([b"not a record at all, too short"])
        self.assertEqual(response.status_code, 200, body)
        self.assertEqual(body["through_seq"], 0)
        self.assertNotIn("ack", body)

    # -- limits ---------------------------------------

    def _stored(self):
        from accounts.models import DeviceLogEntry

        return DeviceLogEntry.objects.filter(
            device_uuid=self.device.device_id).count()

    def test_an_upload_past_the_daily_cap_keeps_the_oldest_and_defers_the_rest(self):
        """The phone deletes only what through_seq covers, so the two it
        sent past the cap stay on it for a later day."""
        with self.settings(DEVICE_LOG_DAILY_RECORDS=3):
            response, body = self._upload(self._chain(5))
        self.assertEqual(response.status_code, 200, body)
        self.assertEqual((body["through_seq"], body["stored"], body["deferred"]),
                         (3, 3, 2))
        self.assertEqual(self._stored(), 3)

    def test_a_phone_at_the_cap_is_answered_429_and_nothing_more_is_stored(self):
        records = self._chain(4)
        with self.settings(DEVICE_LOG_DAILY_RECORDS=2):
            self.assertEqual(self._upload(records[:2])[0].status_code, 200)
            with self.assertLogs("accounts.device_log", "WARNING") as logs:
                response, body = self._upload(records[2:])
                again, _ = self._upload(records[2:])
        self.assertEqual(response.status_code, 429, body)
        self.assertEqual(again.status_code, 429)
        self.assertEqual(response["Retry-After"], "3600")
        self.assertEqual(self._stored(), 2)
        # One line a day for a phone at its cap, however often it tries.
        self.assertEqual(sum("DEVICE_LOG_DAILY_RECORDS" in line
                             for line in logs.output), 1)

    def test_the_cap_counts_only_the_last_24_hours(self):
        from accounts.models import DeviceLogEntry

        records = self._chain(4)
        with self.settings(DEVICE_LOG_DAILY_RECORDS=2):
            self._upload(records[:2])
            DeviceLogEntry.objects.filter(device_uuid=self.device.device_id).update(
                received_at=timezone.now() - datetime.timedelta(hours=25))
            response, body = self._upload(records[2:])
        self.assertEqual(response.status_code, 200, body)
        self.assertEqual(body["stored"], 2)

    def test_a_number_further_ahead_than_any_phone_numbers_is_refused(self):
        from ovcrypto import devicelog

        far = self._seal(10 ** 15, devicelog.GENESIS)
        with self.assertLogs("accounts.device_log", "WARNING") as logs:
            response, body = self._upload([far])
        self.assertEqual(response.status_code, 200, body)
        self.assertEqual((body["refused"], body["stored"], body["through_seq"]),
                         (1, 0, 0))
        self.assertIn("further ahead than a phone numbers", logs.output[0])

    def test_a_rekey_numbering_from_the_clock_is_still_stored(self):
        """The one jump a phone makes on purpose: a re-key with no chain head
        numbers on from the current time in milliseconds, zero prev."""
        self._upload(self._chain(1))
        now_ms = int(timezone.now().timestamp() * 1000)
        response, body = self._upload([self._seal(now_ms, bytes(32))])
        self.assertEqual(response.status_code, 200, body)
        self.assertEqual((body["stored"], body["refused"]), (1, 0))

    def test_conflicts_are_one_warning_naming_the_numbers(self):
        records = self._chain(3)
        self._upload(records)
        others = [self._seal(seq, bytes(32), event="sync") for seq in (1, 2, 3)]
        with self.assertLogs("accounts.device_log", "WARNING") as logs:
            _, body = self._upload(others)
        self.assertEqual(body["conflicts"], 3)
        self.assertEqual(len(logs.output), 1)
        self.assertIn("sequence 1, 2, 3", logs.output[0])

    def test_a_purge_leaves_the_chain_and_what_it_took_recognised(self):
        """A purge keeps the chain's head: the next record is no break, a
        record sent again is not stored for another full period, and a
        rewritten one is still a conflict."""
        from accounts.models import DeviceLogEntry
        from ovcrypto import devicelog

        records = self._chain(4)
        self._upload(records[:3])
        DeviceLogEntry.objects.update(
            received_at=timezone.now() - datetime.timedelta(days=400))
        call_command("purge_device_logs", stdout=StringIO())
        self.assertFalse(DeviceLogEntry.objects.exists())

        _, body = self._upload(records[3:])
        self.assertEqual((body["stored"], body["breaks"]), (1, 0))
        self.assertTrue(self._entry(4).chain_ok)
        # Sent again, or rewritten: recognised, so the phone lets it go, and
        # not stored.
        rewritten = self._seal(3, devicelog.record_hash(records[1]), event="sync")
        for again in (records[1], rewritten):
            with self.assertLogs("accounts.device_log", "WARNING") as logs:
                _, body = self._upload([again])
            self.assertEqual((body["stored"], body["duplicates"]), (0, 1))
            self.assertIn("where its log was aged out", logs.output[0])
        self.assertEqual(list(DeviceLogEntry.objects.values_list("seq", flat=True)), [4])

        # A purge that leaves records keeps judging from the newest held.
        _, body = self._upload([self._seal(6, devicelog.record_hash(records[3]))])
        self.assertEqual(body["breaks"], 1)


class DeviceLogExportTest(TestCase):
    """Every phone's log, as CSV, for a site admin and nobody else.

    The WHOLE log is never an organization's: a phone belongs to a person,
    and a person may be a member of several organizations, so an
    organization-scoped view of everything would show one tenant what a
    phone did for another. (An organization exports only the records filed
    under it -- `OrganizationDeviceLogExportTest`.)
    """

    COLUMNS = ["DEVICE_ID", "DEVICE_LABEL", "OWNER",
               "OWNER_NATIONAL_ID_NUMBER", "OWNER_ORGANIZATIONS",
               "ORGANIZATION", "SEQUENCE", "OCCURRED_AT", "RECEIVED_AT",
               "EVENT", "OUTCOME", "DETAIL", "APP_BUILD", "CHAIN", "READABLE"]

    def setUp(self):
        self.alpha = make_org(name="Alpha")
        self.beta = make_org(name="Beta")
        self.site_admin = User.objects.create(
            national_id_card_number="1010202030304040", given_name="Sam",
            is_site_admin=True)
        self.org_admin = User.objects.create(
            national_id_card_number="5555666677778888", given_name="Olga")
        join(self.alpha, self.org_admin, Membership.ROLE_ADMIN)

        self.owner = User.objects.create(
            national_id_card_number="1111222233334444", given_name="Ada",
            middle_name="Byron", last_name="Lovelace")
        join(self.beta, self.owner)
        join(self.alpha, self.owner, Membership.ROLE_ADMIN)
        self.other = User.objects.create(
            national_id_card_number="9999888877776666", given_name="Grace",
            last_name="Hopper")

        # Fixed ids, so the export's order by device is predictable.
        self.phone = Device.objects.create(
            device_id=uuid.UUID(int=1), label="Front desk iPhone",
            owner=self.owner, public_key_der=b"phone-one")
        self.second = Device.objects.create(
            device_id=uuid.UUID(int=2), label="Gate iPad",
            owner=self.other, public_key_der=b"phone-two")

    def _at(self, *parts):
        return datetime.datetime(*parts, tzinfo=datetime.timezone.utc)

    def _entry(self, device, seq, *, occurred=None, received=None, **fields):
        from accounts.models import DeviceLogEntry

        owner = device.owner
        values = dict(
            device=device, device_uuid=device.device_id,
            device_label=device.label, owner=owner,
            owner_name=owner.display_name,
            owner_national_id_number=owner.national_id_card_number,
            seq=seq, key_id=1, event="scan", outcome="success",
            detail={"verdict": "valid"}, app_build="1.0 (323)",
            occurred_at=occurred, received_at=received or timezone.now(),
            record_hash=bytes(32), chain_ok=True, readable=True)
        values.update(fields)
        return DeviceLogEntry.objects.create(**values)

    def _as(self, user, org=None):
        session = self.client.session
        session[SESSION_KEY] = user.id
        if org:
            session[ORG_SESSION_KEY] = org.id
        session.save()

    def _export(self, query=""):
        response = self.client.get("/app/site/device-logs/export/" + query)
        rows = []
        if response.status_code == 200:
            rows = list(csv.reader(StringIO(response.content.decode())))
        return response, rows

    def test_a_site_admin_gets_every_phones_log_with_these_columns(self):
        self._entry(self.second, 1, occurred=self._at(2026, 9, 2, 1, 0),
                    received=self._at(2026, 9, 2, 1, 5))
        self._entry(self.phone, 2, occurred=self._at(2026, 9, 1, 3, 0),
                    received=self._at(2026, 9, 3, 4, 0), chain_ok=False,
                    event="sync", outcome="notice",
                    detail={"verdict": "valid", "reader": "camera",
                            "face": True, "count": 2, "note": None})
        self._entry(self.phone, 1, occurred=self._at(2026, 9, 1, 2, 0),
                    received=self._at(2026, 9, 1, 3, 30))
        self._entry(self.phone, 3, received=self._at(2026, 9, 3, 4, 0),
                    event="unreadable", outcome="failure",
                    detail={"reason": "record does not open"}, app_build="",
                    chain_ok=False, readable=False)

        self._as(self.site_admin)
        response, rows = self._export()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/csv")
        self.assertIn('filename="device_logs_all_all.csv"',
                      response["Content-Disposition"])
        self.assertEqual(rows[0], self.COLUMNS)

        phone = str(uuid.UUID(int=1))
        self.assertEqual(rows[1:], [
            [phone, "Front desk iPhone", "Ada Byron Lovelace",
             "1111222233334444", "Alpha; Beta", "", "1",
             "09/01/2026 10:00 AM", "09/01/2026 11:30 AM", "scan", "success",
             "verdict=valid", "1.0 (323)", "ok", "yes"],
            [phone, "Front desk iPhone", "Ada Byron Lovelace",
             "1111222233334444", "Alpha; Beta", "", "2",
             "09/01/2026 11:00 AM", "09/03/2026 12:00 PM", "sync", "notice",
             "count=2; face=true; note=null; reader=camera; verdict=valid",
             "1.0 (323)", "break", "yes"],
            [phone, "Front desk iPhone", "Ada Byron Lovelace",
             "1111222233334444", "Alpha; Beta", "", "3", "",
             "09/03/2026 12:00 PM", "unreadable", "failure",
             "reason=record does not open", "", "break", "no"],
            [str(uuid.UUID(int=2)), "Gate iPad", "Grace Hopper",
             "9999888877776666", "", "", "1", "09/02/2026 09:00 AM",
             "09/02/2026 09:05 AM", "scan", "success", "verdict=valid",
             "1.0 (323)", "ok", "yes"],
        ])

    def test_an_organization_admin_is_refused(self):
        """Not even the admin of an organization the owner belongs to."""
        self._entry(self.phone, 1)
        self._as(self.org_admin, self.alpha)
        response, rows = self._export()
        self.assertRedirects(response, "/app/", fetch_redirect_response=False)
        self.assertEqual(rows, [])

    def test_nobody_signed_in_gets_nothing(self):
        self._entry(self.phone, 1)
        response, rows = self._export()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(rows, [])

    def test_the_range_is_the_phones_time_falling_back_to_arrival(self):
        """GMT+8 days, inclusive. 00:30 on the 1st in Manila is still the
        31st in UTC, and belongs to the 1st."""
        self._entry(self.phone, 1, occurred=self._at(2026, 8, 31, 16, 30),
                    received=self._at(2026, 9, 10, 0, 0))
        self._entry(self.phone, 2, received=self._at(2026, 9, 5, 15, 0))
        self._entry(self.phone, 3, occurred=self._at(2026, 9, 5, 16, 0),
                    received=self._at(2026, 9, 5, 16, 1))
        self._entry(self.phone, 4, occurred=self._at(2026, 8, 31, 15, 59),
                    received=self._at(2026, 9, 2, 0, 0))

        self._as(self.site_admin)
        response, rows = self._export("?start=2026-09-01&end=2026-09-05")
        self.assertEqual([row[6] for row in rows[1:]], ["1", "2"])
        self.assertIn('filename="device_logs_2026-09-01_2026-09-05.csv"',
                      response["Content-Disposition"])

    def test_the_filename_never_carries_what_the_caller_typed(self):
        self._as(self.site_admin)
        response, _ = self._export('?start=x"y&end=2026-09-05')
        self.assertIn('filename="device_logs_all_2026-09-05.csv"',
                      response["Content-Disposition"])

    def test_demo_mode_does_not_mask_the_export(self):
        """A CSV is a data operation, not something on a projector."""
        UserSettings.objects.create(user=self.site_admin, demo_mode=True)
        self._entry(self.phone, 1)
        self._as(self.site_admin)
        response, rows = self._export()
        self.assertEqual(rows[1][2:4], ["Ada Byron Lovelace",
                                        "1111222233334444"])

    def test_a_formula_a_phone_wrote_is_not_a_formula_in_the_sheet(self):
        self._entry(self.phone, 1, detail={"=cmd": "x"}, app_build="=1+1")
        self._as(self.site_admin)
        _, rows = self._export()
        self.assertEqual(rows[1][11], "'=cmd=x")
        self.assertEqual(rows[1][12], "'=1+1")

    def test_the_site_admin_page_has_the_card(self):
        self._entry(self.phone, 1, received=self._at(2026, 9, 1, 3, 30))
        self._entry(self.phone, 2, received=self._at(2026, 9, 3, 4, 0))
        self._entry(self.second, 1, received=self._at(2026, 9, 2, 0, 0))
        self._as(self.site_admin)
        page = self.client.get("/app/site/")
        self.assertContains(page, "Device logs")
        self.assertContains(page, "Export device logs (CSV)")
        self.assertContains(page, reverse("site_export_device_logs"))
        self.assertEqual(page.context["device_log"]["entries"], 3)
        self.assertEqual(page.context["device_log"]["phones"], 2)
        self.assertContains(page, "09/03/2026 12:00 PM")

    def test_no_organization_page_offers_it(self):
        """The organization page has its OWN device-log export -- the
        records filed under it -- and never a way to the whole log."""
        self._as(self.org_admin, self.alpha)
        page = self.client.get("/app/admin/")
        self.assertEqual(page.status_code, 200)
        self.assertNotContains(page, "Export device logs")
        self.assertNotContains(page, reverse("site_export_device_logs"))
        self.assertContains(page, reverse("admin_export_device_logs"))

    def test_the_organization_column_says_what_the_record_was_filed_under(self):
        """The name it had on arrival; the id it claimed, marked, when the
        phone was never linked to it; nothing when it named none. A
        deleted organization keeps its name in the export."""
        self._entry(self.phone, 1, organization=self.alpha,
                    organization_name="Alpha",
                    claimed_organization_id=self.alpha.id)
        self._entry(self.phone, 2, claimed_organization_id=4242)
        self._entry(self.phone, 3)
        self._entry(self.phone, 4, organization=None,
                    organization_name="Gone Org", claimed_organization_id=77)

        self._as(self.site_admin)
        _, rows = self._export()
        column = self.COLUMNS.index("ORGANIZATION")
        self.assertEqual([row[column] for row in rows[1:]],
                         ["Alpha", "#4242 (not linked)", "", "Gone Org"])


class PurgeDeviceLogsTest(TestCase):
    """The log is an audit trail with a retention period, not a record kept
    by omission. Aged by when it ARRIVED -- a phone's claimed time must not
    let a record keep or expire itself."""

    def setUp(self):
        from accounts.models import DeviceLogEntry

        owner = User.objects.create(national_id_card_number="1111222233334444")
        device = Device.objects.create(label="Phone", owner=owner,
                                       public_key_der=b"phone")
        now = timezone.now()
        for seq, (received_days, occurred_days) in enumerate(
                ((400, 400), (100, 100), (5, 900)), start=1):
            DeviceLogEntry.objects.create(
                device=device, device_uuid=device.device_id, seq=seq,
                key_id=1, event="scan", outcome="success",
                occurred_at=now - datetime.timedelta(days=occurred_days),
                received_at=now - datetime.timedelta(days=received_days),
                record_hash=bytes(32), chain_ok=True)

    def _run(self, *args):
        out = StringIO()
        call_command("purge_device_logs", *args, stdout=out, stderr=out)
        return out.getvalue()

    def _left(self):
        from accounts.models import DeviceLogEntry

        return sorted(DeviceLogEntry.objects.values_list("seq", flat=True))

    def test_the_default_keeps_three_hundred_and_sixty_days(self):
        self._run()
        self.assertEqual(self._left(), [2, 3])

    def test_a_shorter_window_takes_more_and_never_by_the_phones_clock(self):
        self._run("--days", "50")
        self.assertEqual(self._left(), [3])

    def test_a_dry_run_changes_nothing(self):
        output = self._run("--days", "50", "--dry-run")
        self.assertEqual(self._left(), [1, 2, 3])
        self.assertIn("2 log entries to delete", output)

    def test_the_deployment_sets_the_period_the_timer_uses(self):
        """The timer runs it with no --days."""
        with override_settings(DEVICE_LOG_RETENTION_DAYS=1000):
            self._run()
            self.assertEqual(self._left(), [1, 2, 3])
            # One run's --days is that run's.
            self._run("--days", "200")
            self.assertEqual(self._left(), [2, 3])
        with override_settings(DEVICE_LOG_RETENTION_DAYS=50):
            self._run()
            self.assertEqual(self._left(), [3])

    def test_it_deletes_in_batches_and_marks_how_far_it_went(self):
        from accounts.management.commands import purge_device_logs
        from accounts.models import DeviceLogEntry, DeviceLogMark

        with patch.object(purge_device_logs, "BATCH", 1):
            self.assertIn("Deleted 2 log entries", self._run("--days", "50"))
        self.assertEqual(self._left(), [3])
        mark = DeviceLogMark.objects.get()
        self.assertEqual(mark.head_seq, 2)
        self._run("--days", "1")
        self.assertEqual(DeviceLogMark.objects.get().head_seq, 3)
        # A record numbered lower, aged out later, never moves it back.
        entry = DeviceLogEntry(device_uuid=mark.device_uuid, seq=1, key_id=1,
                               event="scan", outcome="success",
                               received_at=timezone.now() - datetime.timedelta(days=400),
                               record_hash=bytes(32), chain_ok=True)
        entry.save()
        self._run()
        self.assertEqual((DeviceLogMark.objects.count(),
                          DeviceLogMark.objects.get().head_seq), (1, 3))

    def test_the_deploy_checks_the_period_before_the_timer_uses_it(self):
        from accounts.checks import device_log_retention

        for days, found in ((360, []), (30, []), (29, ["accounts.W003"]),
                            (0, ["accounts.E003"]), (36501, ["accounts.E003"])):
            with override_settings(DEVICE_LOG_RETENTION_DAYS=days):
                self.assertEqual([m.id for m in device_log_retention()], found, days)
        with self.assertRaisesMessage(CommandError, "at most 36500"):
            self._run("--days", "36501")
        self.assertEqual(self._left(), [1, 2, 3])

    def test_a_period_under_a_day_is_refused_and_deletes_nothing(self):
        for days in ("0", "-1"):
            with self.assertRaisesMessage(CommandError, "at least 1"):
                self._run("--days", days)
        with override_settings(DEVICE_LOG_RETENTION_DAYS=0), \
                self.assertRaisesMessage(CommandError, "at least 1"):
            self._run()
        self.assertEqual(self._left(), [1, 2, 3])


# ---------------------------------------------------------------------------
# Device organizations: which ones a phone works for
# ---------------------------------------------------------------------------

def _link(device, org, *, by=None, ended=False):
    """One DeviceOrganization row, made directly; `ended` stamps it over."""
    from accounts.models import DeviceOrganization

    return DeviceOrganization.objects.create(
        device=device, organization=org, linked_by=by,
        unlinked_at=timezone.now() if ended else None)


class DeviceOrganizationModelTest(TestCase):
    """At most one CURRENT link per phone and organization, held by the
    database rather than by a view; ended links are history, and any number
    of them sit beside a current one."""

    def setUp(self):
        self.org = make_org(name="Alpha")
        self.user = User.objects.create(
            national_id_card_number="1111222233334444")
        join(self.org, self.user)
        self.device = Device.objects.create(
            label="Front desk iPhone", owner=self.user,
            public_key_der=b"phone-one")

    def test_a_second_current_link_is_refused_by_the_database(self):
        from django.db import IntegrityError, transaction

        _link(self.device, self.org)
        with self.assertRaises(IntegrityError), transaction.atomic():
            _link(self.device, self.org)

    def test_ended_links_sit_beside_a_current_one(self):
        from accounts.models import DeviceOrganization

        _link(self.device, self.org, ended=True)
        _link(self.device, self.org, ended=True)
        _link(self.device, self.org)
        links = DeviceOrganization.objects.filter(device=self.device)
        self.assertEqual(links.count(), 3)
        self.assertEqual(links.filter(unlinked_at__isnull=True).count(), 1)

    def test_the_context_chooser_and_the_phone_read_one_rule(self):
        """`_available_organizations` IS `organizations_open_to`: two copies
        would let a membership removed on one side still open the other."""
        from accounts.models import organizations_open_to
        from verify.views.helpers import _available_organizations

        beta = make_org(name="Beta")
        make_org(name="Closed", is_active=False)
        site_admin = User.objects.create(
            national_id_card_number="1010202030304040", is_site_admin=True)
        for person in (self.user, site_admin, None):
            self.assertEqual(list(_available_organizations(person)),
                             list(organizations_open_to(person)))
        self.assertEqual(list(organizations_open_to(self.user)), [self.org])
        self.assertEqual(list(organizations_open_to(site_admin)),
                         [self.org, beta])


class DeviceOrganizationBackfillTest(TestCase):
    """Migration 0038 links the phones already paired to the organizations
    they already work for -- otherwise every existing phone would wake up
    working for nobody.

    Called as RestrictedTierBackfillTest calls 0030's: the migration's own
    function against real rows, not the executor through the shared test
    database.
    """

    def setUp(self):
        from django.apps import apps as real_apps

        self.apps = real_apps
        alpha = make_org(name="Alpha")
        beta = make_org(name="Beta")
        closed = make_org(name="Closed", is_active=False)
        make_org(name="Elsewhere")      # nobody here is a member
        owner = User.objects.create(
            national_id_card_number="1111222233334444")
        join(alpha, owner)
        join(beta, owner, Membership.ROLE_ADMIN)
        join(closed, owner)
        Device.objects.create(label="Phone", owner=owner,
                              public_key_der=b"one")
        Device.objects.create(label="Revoked", owner=owner,
                              public_key_der=b"two",
                              revoked_at=timezone.now())
        Device.objects.create(label="Holder", owner=owner,
                              public_key_der=b"three", public_tier_only=True)
        site_admin = User.objects.create(
            national_id_card_number="1010202030304040", is_site_admin=True)
        Device.objects.create(label="Admin", owner=site_admin,
                              public_key_der=b"four")

    def _migration(self):
        from importlib import import_module

        return import_module("accounts.migrations.0038_device_organizations")

    def _links(self):
        from accounts.models import DeviceOrganization

        return set(DeviceOrganization.objects.values_list(
            "device__label", "organization__name"))

    def test_a_live_phone_is_linked_to_its_owners_active_organizations(self):
        """Not a revoked phone, not a holder's, not a disabled organization,
        and not a site admin's phone to everything they could enter."""
        self._migration().link_existing_devices(self.apps, None)
        self.assertEqual(self._links(), {("Phone", "Alpha"),
                                         ("Phone", "Beta")})

    def test_nobody_chose_these(self):
        from accounts.models import DeviceOrganization

        self._migration().link_existing_devices(self.apps, None)
        self.assertEqual(set(DeviceOrganization.objects.values_list(
            "linked_by", "unlinked_at")), {(None, None)})

    def test_running_it_again_adds_nothing(self):
        from accounts.models import DeviceOrganization

        module = self._migration()
        module.link_existing_devices(self.apps, None)
        module.link_existing_devices(self.apps, None)
        self.assertEqual(DeviceOrganization.objects.count(), 2)

    def test_the_migration_actually_runs_it_and_undoes_nothing_by_hand(self):
        """A backfill nothing calls is a model change wearing a costume. The
        reverse is a no-op because reversing CreateModel drops the table."""
        module = self._migration()
        operations = module.Migration.operations
        run_python = [op for op in operations
                      if isinstance(op, migrations.RunPython)]
        self.assertEqual(len(run_python), 1)
        self.assertIs(run_python[0].code, module.link_existing_devices)
        self.assertIs(run_python[0].reverse_code, migrations.RunPython.noop)
        # Last, so the table it writes to exists by then.
        self.assertIs(operations[-1], run_python[0])


@override_settings(DEVICE_PAIRING_TTL_SECONDS=900, **_DEVICE_LOG_SETTINGS)
class DeviceOrganizationsTest(_DeviceLogFixture, TestCase):
    """Which organizations a phone works for: ticked on the Devices page and
    the pairing form, told to the phone at /connect/ and /keys/.

    A context, never an access level -- nothing here changes what a phone
    may read -- and only ever organizations the owner may enter.
    """

    def setUp(self):
        super().setUp()
        # The fixture's Ada is an operator at Alpha; here she is also an
        # admin at Beta, and nothing at Outside.
        self.beta = make_org(name="Beta", subtitle="Field office")
        join(self.beta, self.user, Membership.ROLE_ADMIN)
        self.outside = make_org(name="Outside")
        self.other = User.objects.create(
            national_id_card_number="9999888877776666", given_name="Grace")

    # -- helpers ------------------------------------------------------------

    def _sign_in(self, user=None, org=None):
        session = self.client.session
        session[SESSION_KEY] = (user or self.user).id
        if org is not None:
            session[ORG_SESSION_KEY] = org.id
        session.save()

    def _mint(self, purpose="enrol", organizations=(), device=None):
        """Ask the page for a ticket, the way its forms do."""
        self._sign_in()
        body = {"purpose": purpose,
                "organizations": [str(org.id) for org in organizations]}
        if device is not None:
            body["device_id"] = str(device.device_id)
        self.client.post("/app/devices/ticket/", body)
        return DeviceTicket.objects.filter(
            user=self.user, purpose=purpose).latest("created_at")

    def _connect(self, code):
        response = self.client.post(
            "/api/v1/device/connect/", data=json.dumps({"code": code}),
            content_type="application/json")
        return json.loads(response.content)

    def _enrol(self, code):
        """A phone with a fresh Enclave key presenting `code`."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())
        public = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        body = json.loads(self.client.post(
            "/api/v1/device/enrol/",
            data=json.dumps({"enrolment_code": code,
                             "device_public_key":
                                 base64.b64encode(public).decode()}),
            content_type="application/json").content)
        return Device.objects.get(device_id=uuid.UUID(
            bytes=base64.b64decode(body["device_id"])))

    def _keys(self):
        """An ordinary sync: a DER signature over the decoded challenge."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

        nonce = json.loads(self.client.post(
            "/api/v1/device/challenge/").content)["challenge"]
        der = self.device_key.sign(base64.b64decode(nonce),
                                   ECDSA(hashes.SHA256()))
        response = self.client.post(
            "/api/v1/device/keys/", data=json.dumps({
                "device_id": device_service.device_id_wire(self.device),
                "challenge": nonce,
                "signature": base64.b64encode(der).decode()}),
            content_type="application/json")
        return response, json.loads(response.content)

    def _set(self, device, *organizations, user=None):
        """Post the phone's "Works for" boxes, ticked as given."""
        self._sign_in(user)
        return self.client.post("/app/devices/organizations/", {
            "device_id": str(device.device_id),
            "organizations": [str(org.id) for org in organizations]})

    def _current(self, device=None):
        from accounts.models import DeviceOrganization

        return set(DeviceOrganization.objects.filter(
            device=device or self.device, unlinked_at__isnull=True)
            .values_list("organization__name", flat=True))

    def _boxes(self, page):
        """Every "organizations" checkbox on the page, as (form action,
        the form's device id or None, organization id, ticked)."""
        from html.parser import HTMLParser

        class Scan(HTMLParser):
            def __init__(self):
                super().__init__(convert_charrefs=True)
                self.action, self.device, self.found = None, None, []

            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == "form":
                    self.action, self.device = attrs.get("action"), None
                elif tag == "input" and attrs.get("name") == "device_id":
                    self.device = attrs.get("value")
                elif tag == "input" and attrs.get("name") == "organizations":
                    self.found.append((self.action, self.device,
                                       int(attrs["value"]),
                                       "checked" in attrs))

        scan = Scan()
        scan.feed(page.content.decode())
        return scan.found

    # -- what the phone is told ---------------------------------------------

    def test_a_phone_is_told_its_links_by_name_and_how_to_draw_them(self):
        logo = ("data:image/png;base64,"
                + base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(100)).decode())
        Organization.objects.filter(pk=self.beta.pk).update(
            logo_data=logo, mark_color="#123456")
        _link(self.device, self.beta)
        _link(self.device, self.org)

        self.assertEqual(device_service.organizations_for(self.device), [
            {"id": self.org.id, "name": "Alpha", "subtitle": "",
             "role": "operator", "initials": "ALP", "mark_color": "#00386a",
             "logo": ""},
            {"id": self.beta.id, "name": "Beta", "subtitle": "Field office",
             "role": "admin", "initials": "BET", "mark_color": "#123456",
             "logo": logo},
        ])

    def test_a_link_whose_membership_ended_is_not_sent_and_not_deleted(self):
        """Not sent while it is out of reach, and back when the membership
        is: the link is the phone's, the rule is applied on the way out."""
        _link(self.device, self.org)
        _link(self.device, self.beta)
        Membership.objects.filter(user=self.user,
                                  organization=self.beta).delete()
        self.assertEqual([org["name"] for org in
                          device_service.organizations_for(self.device)],
                         ["Alpha"])
        self.assertEqual(self._current(), {"Alpha", "Beta"})

        join(self.beta, self.user)
        self.assertEqual([org["name"] for org in
                          device_service.organizations_for(self.device)],
                         ["Alpha", "Beta"])

    def test_a_link_to_a_disabled_organization_is_not_sent(self):
        _link(self.device, self.beta)
        Organization.objects.filter(pk=self.beta.pk).update(is_active=False)
        self.assertEqual(device_service.organizations_for(self.device), [])

    def test_an_ended_link_is_not_sent(self):
        _link(self.device, self.org, ended=True)
        self.assertEqual(device_service.organizations_for(self.device), [])

    def test_a_site_admin_with_no_membership_there_is_its_admin(self):
        self.user.is_site_admin = True
        self.user.save()
        _link(self.device, self.outside)
        _link(self.device, self.org)
        self.assertEqual(
            {org["name"]: org["role"]
             for org in device_service.organizations_for(self.device)},
            {"Alpha": "operator", "Outside": "admin"})

    def test_a_logo_over_64_kb_is_left_out(self):
        def uri(size):
            return "data:image/png;base64," + base64.b64encode(
                b"\x89PNG\r\n\x1a\n" + bytes(size - 8)).decode()

        _link(self.device, self.org)
        for size, sent in ((64 * 1024, True), (64 * 1024 + 1, False)):
            Organization.objects.filter(pk=self.org.pk).update(
                logo_data=uri(size))
            with self.subTest(size=size):
                self.assertEqual(
                    device_service.organizations_for(self.device)[0]["logo"],
                    uri(size) if sent else "")
        Organization.objects.filter(pk=self.org.pk).update(
            logo_data="https://example.org/logo.png")
        self.assertEqual(
            device_service.organizations_for(self.device)[0]["logo"], "")

    def test_keys_answers_with_the_organizations_beside_the_bundle(self):
        _link(self.device, self.org)
        _link(self.device, self.outside)      # out of reach: not sent
        response, body = self._keys()
        self.assertEqual(response.status_code, 200, body)
        self.assertTrue(body["bundle"])
        self.assertEqual(body["organizations"],
                         device_service.organizations_for(self.device))
        self.assertEqual([org["id"] for org in body["organizations"]],
                         [self.org.id])

    def test_keys_always_carries_the_key_even_with_none(self):
        """Absent means "this server has no organizations" to the app; this
        server has them, so it always says, even when the answer is none."""
        response, body = self._keys()
        self.assertEqual(response.status_code, 200, body)
        self.assertEqual(body["organizations"], [])

    def test_connect_for_a_pairing_names_what_the_ticket_will_link(self):
        ticket = self._mint(organizations=[self.beta, self.org])
        self.assertEqual(self._connect(ticket.code)["organizations"], [
            {"id": self.org.id, "name": "Alpha"},
            {"id": self.beta.id, "name": "Beta"}])

    def test_connect_for_a_pairing_drops_an_organization_left_since(self):
        ticket = self._mint(organizations=[self.org, self.beta])
        Membership.objects.filter(user=self.user,
                                  organization=self.beta).delete()
        self.assertEqual(self._connect(ticket.code)["organizations"],
                         [{"id": self.org.id, "name": "Alpha"}])

    def test_connect_for_a_sync_or_rekey_names_what_the_phone_works_for(self):
        _link(self.device, self.beta)
        _link(self.device, self.outside)
        for purpose in ("sync", "rekey"):
            with self.subTest(purpose):
                ticket = self._mint(purpose, device=self.device)
                self.assertEqual(self._connect(ticket.code)["organizations"],
                                 [{"id": self.beta.id, "name": "Beta"}])

    def test_connect_with_none_still_carries_the_key(self):
        ticket = self._mint()
        self.assertEqual(self._connect(ticket.code)["organizations"], [])

    # -- pairing ------------------------------------------------------------

    def test_pairing_links_the_new_phone_to_what_was_ticked(self):
        from accounts.models import DeviceOrganization

        phone = self._enrol(self._mint(
            organizations=[self.org, self.beta]).code)
        self.assertEqual(
            set(DeviceOrganization.objects.filter(device=phone).values_list(
                "organization_id", "linked_by_id", "unlinked_at")),
            {(self.org.id, self.user.id, None),
             (self.beta.id, self.user.id, None)})

    def test_a_ticket_never_names_an_organization_its_owner_cannot_enter(self):
        ticket = self._mint(organizations=[self.org, self.outside])
        self.assertEqual(list(ticket.organizations.all()), [self.org])

        # And at the service, where junk is dropped rather than raised.
        ticket = device_service.mint_ticket(
            self.user, organization_ids=[
                "x", "", "-3", "0", str(2 ** 40), str(self.outside.id),
                str(self.beta.id)])
        self.assertEqual(list(ticket.organizations.all()), [self.beta])

    def test_an_organization_left_between_the_qr_and_the_scan_is_not_linked(self):
        ticket = self._mint(organizations=[self.org, self.beta])
        Membership.objects.filter(user=self.user,
                                  organization=self.beta).delete()
        self.assertEqual(self._current(self._enrol(ticket.code)), {"Alpha"})

    def test_only_a_pairing_carries_organizations_and_a_rekey_keeps_links(self):
        _link(self.device, self.org)
        for purpose in ("sync", "rekey"):
            ticket = device_service.mint_ticket(
                self.user, purpose, device=self.device,
                organization_ids=[self.beta.id])
            self.assertEqual(ticket.organizations.count(), 0, purpose)

        rekeyed = self._enrol(self._mint("rekey", device=self.device,
                                         organizations=[self.beta]).code)
        self.assertEqual(rekeyed, self.device)
        self.assertEqual(self._current(), {"Alpha"})

    # -- the Devices page ---------------------------------------------------

    def test_the_pairing_form_starts_ticked_with_the_organization_in_use(self):
        self._sign_in(org=self.beta)
        page = self.client.get("/app/devices/")
        pairing = [box for box in self._boxes(page)
                   if box[0] == reverse("devices_ticket")]
        self.assertEqual(pairing, [
            (reverse("devices_ticket"), None, self.org.id, False),
            (reverse("devices_ticket"), None, self.beta.id, True)])

    def test_with_one_organization_and_none_in_use_that_one_is_ticked(self):
        Membership.objects.filter(user=self.user,
                                  organization=self.beta).delete()
        self._sign_in()
        page = self.client.get("/app/devices/")
        self.assertEqual(page.context["pairing_organizations"], {self.org.id})

    def test_with_several_and_none_in_use_none_is_ticked(self):
        """Not all of them: a site admin would otherwise pair every phone
        to the whole deployment."""
        self._sign_in()
        page = self.client.get("/app/devices/")
        self.assertEqual(page.context["pairing_organizations"], set())

    def test_each_phone_shows_what_it_works_for_and_offers_only_reachable_boxes(self):
        _link(self.device, self.beta)
        _link(self.device, self.outside)
        self._sign_in()
        page = self.client.get("/app/devices/")
        self.assertContains(page, "Works for")
        phone = [box[2:] for box in self._boxes(page)
                 if box[0] == reverse("devices_organizations")
                 and box[1] == str(self.device.device_id)]
        self.assertEqual(phone, [(self.org.id, False), (self.beta.id, True)])
        self.assertEqual([org.name for org in
                          page.context["devices"][0].works_for], ["Beta"])

    def test_the_pairing_panel_confirms_what_it_will_link(self):
        self._mint(organizations=[self.beta])
        page = self.client.get("/app/devices/")
        self.assertEqual(page.context["pairing"]["organizations"], [self.beta])

    def test_ticking_links_and_clearing_ends_the_link_without_deleting_it(self):
        from accounts.models import DeviceOrganization

        response = self._set(self.device, self.org, self.beta)
        self.assertRedirects(response, "/app/devices/",
                             fetch_redirect_response=False)
        self.assertEqual(self._current(), {"Alpha", "Beta"})

        self._set(self.device, self.beta)
        self.assertEqual(self._current(), {"Beta"})
        ended = DeviceOrganization.objects.get(device=self.device,
                                               organization=self.org)
        self.assertIsNotNone(ended.unlinked_at)
        self.assertEqual((ended.linked_by, ended.unlinked_by),
                         (self.user, self.user))

        # Ticking it again is a new period, not the old one reopened.
        self._set(self.device, self.org, self.beta)
        self.assertEqual(DeviceOrganization.objects.filter(
            device=self.device, organization=self.org).count(), 2)
        self.assertEqual(self._current(), {"Alpha", "Beta"})

    def test_saving_the_same_boxes_changes_nothing(self):
        from accounts.models import DeviceOrganization

        self._set(self.device, self.org)
        first = DeviceOrganization.objects.get()
        self._set(self.device, self.org)
        self.assertEqual(list(DeviceOrganization.objects.all()), [first])
        self.assertIsNone(DeviceOrganization.objects.get().unlinked_at)

    def test_an_organization_you_cannot_enter_cannot_be_linked(self):
        self._set(self.device, self.org, self.outside)
        self.assertEqual(self._current(), {"Alpha"})

    def test_a_link_out_of_reach_survives_a_save(self):
        """It is not on the form, so the form cannot have cleared it."""
        _link(self.device, self.beta)
        Membership.objects.filter(user=self.user,
                                  organization=self.beta).delete()
        self._set(self.device, self.org)
        self.assertEqual(self._current(), {"Alpha", "Beta"})

    def test_only_the_owner_changes_a_phones_organizations(self):
        """Through the page, the phone does not resolve for anybody else --
        even an admin of the organization -- and the service refuses on its
        own."""
        join(self.org, self.other, Membership.ROLE_ADMIN)
        self._set(self.device, self.org, user=self.other)
        self.assertEqual(self._current(), set())
        with self.assertRaises(device_service.PairingError):
            device_service.set_organizations(self.device, [self.org.id],
                                             actor=self.other)
        self.assertEqual(self._current(), set())

    def test_it_needs_a_signed_in_person_and_a_post(self):
        response = self.client.post("/app/devices/organizations/", {
            "device_id": str(self.device.device_id),
            "organizations": [str(self.org.id)]})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self._current(), set())
        self._sign_in()
        self.assertEqual(
            self.client.get("/app/devices/organizations/").status_code, 405)

    def test_a_revoked_phone_is_offered_no_boxes_and_takes_none(self):
        """Refused twice, as ownership is: the page does not resolve a
        revoked phone, and the service refuses one on its own."""
        device_service.revoke(self.device, actor=self.user)
        self._sign_in()
        page = self.client.get("/app/devices/")
        self.assertEqual([box for box in self._boxes(page)
                          if box[0] == reverse("devices_organizations")], [])
        self._set(self.device, self.org)
        self.assertEqual(self._current(), set())
        with self.assertRaises(device_service.PairingError):
            device_service.set_organizations(self.device, [self.org.id],
                                             actor=self.user)
        self.assertEqual(self._current(), set())

    def test_a_junk_device_id_is_a_no_op(self):
        self._sign_in()
        response = self.client.post("/app/devices/organizations/", {
            "device_id": "not-a-uuid", "organizations": [str(self.org.id)]})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self._current(), set())


@override_settings(**_DEVICE_LOG_SETTINGS)
class DeviceLogOrganizationTest(_DeviceLogFixture, TestCase):
    """A record names the organization the phone was working for, and is
    filed under it only when the phone has EVER been linked to it.

    The `org` is the phone's own claim; the link, made on the web by
    somebody who could enter the organization, is what stops a phone filing
    records into an organization's export. A claim that matches no link is
    kept, never refused.
    """

    # DeviceLogTest's helpers, borrowed rather than copied: sealing and
    # uploading are not what these tests are about.
    _statement = DeviceLogTest._statement
    _log_key = DeviceLogTest._log_key
    _seal = DeviceLogTest._seal
    _challenge = DeviceLogTest._challenge
    _der = DeviceLogTest._der
    _upload = DeviceLogTest._upload
    _entry = DeviceLogTest._entry

    def setUp(self):
        super().setUp()
        self.beta = make_org(name="Beta")
        self.outside = make_org(name="Outside")

    def _send(self, *orgs, **fields):
        """Records 1..n, chained, record i naming orgs[i]; Ellipsis leaves
        the key out altogether."""
        from ovcrypto import devicelog

        key = self._log_key()
        prev, records = devicelog.GENESIS, []
        for seq, org in enumerate(orgs, start=1):
            records.append(self._seal(seq, prev, key=key, org=org, **fields))
            prev = devicelog.record_hash(records[-1])
        response, body = self._upload(records)
        self.assertEqual(response.status_code, 200, body)
        return body

    def _filing(self, seq):
        entry = self._entry(seq)
        return (entry.organization, entry.organization_name,
                entry.claimed_organization_id)

    def test_a_record_for_an_organization_the_phone_works_for_is_filed_there(self):
        _link(self.device, self.org)
        body = self._send(self.org.id)
        self.assertEqual((body["stored"], body["unreadable"]), (1, 0))
        self.assertEqual(self._filing(1), (self.org, "Alpha", self.org.id))
        self.assertTrue(self._entry(1).readable)

        # The name is the one it had on arrival.
        Organization.objects.filter(pk=self.org.pk).update(name="Renamed")
        self.assertEqual(self._entry(1).organization_name, "Alpha")

    def test_a_link_since_ended_still_files_what_was_written_under_it(self):
        """Records queue offline: one written while the phone worked for
        Beta may arrive after the link ended, and is still Beta's."""
        _link(self.device, self.beta, ended=True)
        self._send(self.beta.id)
        self.assertEqual(self._filing(1), (self.beta, "Beta", self.beta.id))

    def test_an_organization_never_linked_is_a_claim_and_not_a_filing(self):
        _link(self.device, self.org)
        body = self._send(self.outside.id, 999999)
        self.assertEqual((body["stored"], body["unreadable"]), (2, 0))
        self.assertEqual(self._filing(1), (None, "", self.outside.id))
        self.assertEqual(self._filing(2), (None, "", 999999))
        self.assertTrue(self._entry(1).readable)

    def test_another_phones_link_files_nothing_for_this_one(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        other = Device.objects.create(
            label="Gate iPad", owner=self.user,
            public_key_der=ec.generate_private_key(ec.SECP256R1())
            .public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo))
        _link(other, self.beta)
        self._send(self.beta.id)
        self.assertEqual(self._filing(1), (None, "", self.beta.id))

    def test_no_org_and_a_null_one_both_mean_none(self):
        _link(self.device, self.org)
        body = self._send(..., None)
        self.assertEqual(body["unreadable"], 0)
        self.assertEqual(self._filing(1), (None, "", None))
        self.assertEqual(self._filing(2), (None, "", None))

    def test_an_org_that_is_not_an_organization_id_is_unreadable(self):
        """Typed exactly, like every other field: present and not an integer
        in 1..2^31-1 is a placeholder, and the batch still goes through."""
        _link(self.device, self.org)
        cases = {"a string": str(self.org.id), "zero": 0, "negative": -1,
                 "past 31 bits": 2 ** 31, "true": True, "a float": 1.5,
                 "a list": [self.org.id], "an object": {"id": self.org.id}}
        body = self._send(*cases.values())
        self.assertEqual((body["stored"], body["unreadable"]),
                         (len(cases), len(cases)))
        for seq, name in enumerate(cases, start=1):
            with self.subTest(name):
                entry = self._entry(seq)
                self.assertFalse(entry.readable)
                self.assertEqual(entry.detail["reason"],
                                 "org is not an organization id")
                self.assertEqual(self._filing(seq), (None, "", None))

    def test_the_largest_id_is_accepted(self):
        self._send(2 ** 31 - 1)
        self.assertTrue(self._entry(1).readable)
        self.assertEqual(self._filing(1), (None, "", 2 ** 31 - 1))

    def test_choosing_an_organization_is_an_ordinary_event(self):
        """`org_select` needs nothing of its own here: its detail is checked
        like any other, and the record names the organization like the
        records after it."""
        _link(self.device, self.org)
        self._send(self.org.id, event="org_select",
                   detail={"org": self.org.id})
        entry = self._entry(1)
        self.assertEqual((entry.event, entry.outcome, entry.detail),
                         ("org_select", "success", {"org": self.org.id}))
        self.assertEqual(entry.organization, self.org)


class OrganizationDeviceLogExportTest(TestCase):
    """An organization's admins export the records filed under it -- and
    nothing a phone did for anybody else, nor anything a phone merely
    claimed.

    The site's columns less OWNER_ORGANIZATIONS, which would tell this
    tenant where else a person works.
    """

    COLUMNS = [column for column in DeviceLogExportTest.COLUMNS
               if column != "OWNER_ORGANIZATIONS"]

    _at = DeviceLogExportTest._at
    _entry = DeviceLogExportTest._entry
    _as = DeviceLogExportTest._as

    def setUp(self):
        self.alpha = make_org(name="Alpha Org")
        self.beta = make_org(name="Beta")
        self.alpha_admin = User.objects.create(
            national_id_card_number="5555666677778888", given_name="Olga")
        join(self.alpha, self.alpha_admin, Membership.ROLE_ADMIN)
        self.alpha_operator = User.objects.create(
            national_id_card_number="4444555566667777", given_name="Otto")
        join(self.alpha, self.alpha_operator)
        self.beta_admin = User.objects.create(
            national_id_card_number="3333444455556666", given_name="Bea")
        join(self.beta, self.beta_admin, Membership.ROLE_ADMIN)
        self.site_admin = User.objects.create(
            national_id_card_number="1010202030304040", given_name="Sam",
            is_site_admin=True)

        self.owner = User.objects.create(
            national_id_card_number="1111222233334444", given_name="Ada",
            middle_name="Byron", last_name="Lovelace")
        join(self.alpha, self.owner)
        join(self.beta, self.owner)
        self.phone = Device.objects.create(
            device_id=uuid.UUID(int=1), label="Front desk iPhone",
            owner=self.owner, public_key_der=b"phone-one")

    def _export(self, query=""):
        response = self.client.get("/app/admin/export-device-logs/" + query)
        rows = []
        if response.status_code == 200:
            rows = list(csv.reader(StringIO(response.content.decode())))
        return response, rows

    def _filed(self, seq, org, **fields):
        return self._entry(self.phone, seq, organization=org,
                           organization_name=org.name,
                           claimed_organization_id=org.id, **fields)

    def test_an_admin_gets_only_what_was_filed_under_their_organization(self):
        self._filed(1, self.alpha, occurred=self._at(2026, 9, 1, 2, 0),
                    received=self._at(2026, 9, 1, 3, 30))
        self._filed(2, self.beta)
        # Claimed Alpha, never linked: not Alpha's, whatever it says.
        self._entry(self.phone, 3, claimed_organization_id=self.alpha.id)
        self._entry(self.phone, 4)

        self._as(self.alpha_admin, self.alpha)
        response, rows = self._export()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/csv")
        self.assertIn('filename="device_logs_alpha-org_all_all.csv"',
                      response["Content-Disposition"])
        self.assertEqual(rows, [self.COLUMNS, [
            str(uuid.UUID(int=1)), "Front desk iPhone", "Ada Byron Lovelace",
            "1111222233334444", "Alpha Org", "1", "09/01/2026 10:00 AM",
            "09/01/2026 11:30 AM", "scan", "success", "verdict=valid",
            "1.0 (323)", "ok", "yes"]])

    def test_another_organizations_admin_sees_none_of_it(self):
        self._filed(1, self.alpha)
        self._as(self.beta_admin, self.beta)
        _, rows = self._export()
        self.assertEqual(rows, [self.COLUMNS])

    def test_the_organization_comes_from_the_session_not_the_request(self):
        self._filed(1, self.alpha)
        self._as(self.beta_admin, self.beta)
        _, rows = self._export("?organization=%d&org=%d"
                               % (self.alpha.id, self.alpha.id))
        self.assertEqual(rows, [self.COLUMNS])

    def test_an_operator_is_refused(self):
        self._filed(1, self.alpha)
        self._as(self.alpha_operator, self.alpha)
        response, rows = self._export()
        self.assertRedirects(response, "/app/", fetch_redirect_response=False)
        self.assertEqual(rows, [])

    def test_nobody_signed_in_and_nobody_in_context_get_nothing(self):
        self._filed(1, self.alpha)
        response, rows = self._export()
        self.assertEqual(response.status_code, 302)
        self._as(self.alpha_admin)
        response, rows = self._export()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(rows, [])

    def test_a_site_admin_in_context_gets_that_organizations(self):
        self._filed(1, self.alpha)
        self._filed(2, self.beta)
        self._as(self.site_admin, self.beta)
        _, rows = self._export()
        self.assertEqual([row[5] for row in rows[1:]], ["2"])

    def test_the_range_is_the_phones_time_falling_back_to_arrival(self):
        """The site export's range, GMT+8 days, inclusive."""
        self._filed(1, self.alpha, occurred=self._at(2026, 8, 31, 16, 30),
                    received=self._at(2026, 9, 10, 0, 0))
        self._filed(2, self.alpha, received=self._at(2026, 9, 5, 15, 0))
        self._filed(3, self.alpha, occurred=self._at(2026, 9, 5, 16, 0),
                    received=self._at(2026, 9, 5, 16, 1))
        self._filed(4, self.alpha, occurred=self._at(2026, 8, 31, 15, 59),
                    received=self._at(2026, 9, 2, 0, 0))

        self._as(self.alpha_admin, self.alpha)
        response, rows = self._export("?start=2026-09-01&end=2026-09-05")
        self.assertEqual([row[5] for row in rows[1:]], ["1", "2"])
        self.assertIn(
            'filename="device_logs_alpha-org_2026-09-01_2026-09-05.csv"',
            response["Content-Disposition"])

    def test_the_organization_page_offers_it_beside_the_transactions(self):
        self._as(self.alpha_admin, self.alpha)
        page = self.client.get("/app/admin/")
        self.assertContains(page, "Export Device Logs (CSV)")
        content = page.content.decode()
        self.assertLess(content.index(reverse("admin_export_transactions")),
                        content.index(reverse("admin_export_device_logs")))

    def test_it_resolves_to_its_view(self):
        from django.urls import resolve

        from verify import views

        self.assertIs(resolve(reverse("admin_export_device_logs")).func,
                      views.admin_export_device_logs)
        self.assertIs(resolve(reverse("devices_organizations")).func,
                      views.devices_organizations)


class CredentialDigitalIdTest(TestCase):
    """The Digital National ID reaches the credential, under eVerify's key.

    It is read from `code`, eVerify's own key: `digital_id` is not one of the
    36 keys a Tier II lookup returns, and a value read from it would be
    silently absent -- twice over: the miss yields an empty value, an empty
    value is dropped, and the organization's field list has no such key
    either.

    It travels in the ordered T_FIELDS list like every other displayed
    field, under its printed label, which is what makes it readable rather
    than merely present.
    """

    def _fields(self, rows, field_rows=None):
        import datetime as dt

        from accounts import credentials
        from ovcrypto import wire

        now = dt.datetime.now(dt.timezone.utc)
        _, restricted = credentials.build_claims(
            [{"field": k, "key": lbl, "value": v} for k, lbl, v in rows],
            organization=None, location_code="MNL01",
            document_uuid="11111111-2222-3333-4444-555555555555",
            document_hash=b"0" * 32, issued_at=now, expires_at=now,
            field_rows=field_rows)
        return dict(wire.decode_fields(restricted.get(wire.T_FIELDS, b"")))

    def test_the_digital_national_id_is_carried(self):
        fields = self._fields(
            [("code", "Digital National ID Number", "CWD0842")])
        self.assertEqual(fields["Digital National ID Number"], "CWD0842")

    def test_it_is_matched_on_everify_s_key_not_a_made_up_one(self):
        """`digital_id` names nothing upstream. A row under that key is not a
        field this deployment knows, and carrying it would mean carrying
        whatever any caller invented."""
        rows = everify_fields.rows_for(None)
        fields = self._fields([("digital_id", "Digital ID", "CWD0842")],
                              field_rows=rows)
        self.assertEqual(fields, {})

    def test_an_organization_that_hides_it_does_not_embed_it(self):
        """The QR carries what the page carries -- for this field too."""
        rows = everify_fields.rows_for(None)
        for row in rows:
            if row["key"] == "code":
                row["display"] = False
        fields = self._fields(
            [("code", "Digital National ID Number", "CWD0842"),
             ("last_name", "Last Name", "DELA CRUZ")], field_rows=rows)
        self.assertNotIn("Digital National ID Number", fields)
        self.assertIn("Last Name", fields)

    def test_it_is_on_by_default_so_a_real_credential_carries_it(self):
        fields = self._fields(
            [("code", "Digital National ID Number", "CWD0842"),
             ("last_name", "Last Name", "DELA CRUZ")],
            field_rows=everify_fields.rows_for(None))
        self.assertEqual(fields["Digital National ID Number"], "CWD0842")


class CredentialContentTest(TestCase):
    """What the credential carries: every displayed field, in full text.

    The design question this settles is "codes or names". Codes have good
    reasons -- names are long and editable, and a signed credential outlives
    a rename -- but a person reading a verified document on a phone cannot
    expand a code, and a claim they cannot read is worth nothing to them.
    """

    ROWS = [
        ("first_name", "Given Name", "JUAN"),
        ("last_name", "Last Name", "DELA CRUZ"),
        ("gender", "Sex", "Male"),
        ("birth_date", "Date of Birth", "01/15/1990"),
        ("marital_status", "Marital Status", "Single"),
    ]

    def _displaying(self):
        """The field list of an organization that displays every row above:
        sex and marital status are off by default and switched on here."""
        rows = everify_fields.rows_for(None)
        for row in rows:
            if row["key"] in {k for k, _l, _v in self.ROWS}:
                row["display"] = True
        return rows

    def _claims(self, **kwargs):
        import datetime as dt

        from accounts import credentials

        now = dt.datetime.now(dt.timezone.utc)
        rows = [{"field": k, "key": lbl, "value": v}
                for k, lbl, v in kwargs.pop("rows", self.ROWS)]
        defaults = dict(
            organization=None, location_code="QC1",
            document_uuid="11111111-2222-3333-4444-555555555555",
            document_hash=b"0" * 32, issued_at=now, expires_at=now,
            field_rows=self._displaying())
        defaults.update(kwargs)
        return credentials.build_claims(rows, **defaults)

    def _fields(self, **kwargs):
        from ovcrypto import wire

        _, restricted = self._claims(**kwargs)
        return wire.decode_fields(restricted.get(wire.T_FIELDS, b""))

    def _mock_face_uri(self):
        import base64

        path = os.path.join(settings.BASE_DIR, "static", "mock-face.png")
        with open(path, "rb") as handle:
            return "data:image/png;base64," + base64.b64encode(
                handle.read()).decode()

    # -- the transaction, in words ----------------------------------------

    def test_the_transaction_is_described_in_full_text(self):
        from ovcrypto import wire

        class Org:
            name = "Philippine Statistics Authority"

        public, _ = self._claims(
            organization=Org(),
            transaction_type="Release of Certificate of Live Birth",
            operator_name="JUAN MIGUEL SANTOS DELA CRUZ",
            location_name="PSA Quezon City District Office")
        self.assertEqual(public[wire.T_ISSUER_ID].decode(),
                         "Philippine Statistics Authority")
        self.assertEqual(public[wire.T_ISSUER_LOCATION].decode(),
                         "PSA Quezon City District Office")
        self.assertEqual(public[wire.T_TRANSACTION_TYPE].decode(),
                         "Release of Certificate of Live Birth")
        self.assertEqual(public[wire.T_OPERATOR].decode(),
                         "JUAN MIGUEL SANTOS DELA CRUZ")

    def test_the_location_code_is_only_a_fallback(self):
        """A code beats an empty row, but only just."""
        from ovcrypto import wire

        public, _ = self._claims(location_code="QC1", location_name="")
        self.assertEqual(public[wire.T_ISSUER_LOCATION].decode(), "QC1")

    def test_no_typed_person_tags_are_emitted_any_more(self):
        """They would duplicate the list, and two of them -- ISO 5218 sex and
        days-since-epoch birth date -- are codes a reader cannot expand."""
        from ovcrypto import wire

        _, restricted = self._claims()
        for tag in (wire.T_SURNAME, wire.T_GIVEN_NAMES, wire.T_DATE_OF_BIRTH,
                    wire.T_SEX, wire.T_PCN, wire.T_DIGITAL_ID):
            self.assertNotIn(tag, restricted, hex(tag))

    # -- the field list ----------------------------------------------------

    def test_every_displayed_field_is_carried_in_document_order(self):
        """Order is the document's, so the phone shows the same rows in the
        same sequence as the paper beside it."""
        self.assertEqual(
            self._fields(),
            [("Given Name", "JUAN"), ("Last Name", "DELA CRUZ"),
             ("Sex", "Male"), ("Date of Birth", "01/15/1990"),
             ("Marital Status", "Single")])

    def test_a_field_the_organization_hides_is_not_carried(self):
        rows = self._displaying()
        for row in rows:
            if row["key"] == "marital_status":
                row["display"] = False
        labels = [label for label, _ in self._fields(field_rows=rows)]
        self.assertNotIn("Marital Status", labels)
        self.assertIn("Sex", labels)

    def test_by_default_the_credential_carries_only_the_minimum(self):
        """With nothing configured, sex and marital status are not displayed,
        so they are not signed into the credential either."""
        self.assertEqual(
            self._fields(field_rows=everify_fields.rows_for(None)),
            [("Given Name", "JUAN"), ("Last Name", "DELA CRUZ"),
             ("Date of Birth", "01/15/1990")])

    def test_the_face_is_never_in_the_credential(self):
        """It does not fit at any quality worth printing -- measured -- and it
        rides its own symbol instead."""
        rows = list(self.ROWS) + [("face_url", "Face Photo",
                                   "data:image/png;base64,AAAA")]
        labels = [label for label, _ in self._fields(rows=rows)]
        self.assertNotIn("Face Photo", labels)

    def test_values_stay_bounded(self):
        """One long address must not push the stamp past what the page
        prints."""
        from accounts import credentials

        rows = [("full_address", "Permanent Address", "x" * 400)]
        (_, value), = self._fields(rows=rows)
        self.assertLessEqual(len(value), credentials.MAX_TEXT)

    # -- the portrait symbol ----------------------------------------------

    def test_the_portrait_is_bound_to_the_credential_by_hash(self):
        """Without it the two symbols are independent, and a document could be
        presented with somebody else's face beside it -- both scanning."""
        import hashlib

        from ovcrypto import wire

        blob = b"pretend this is a webp"
        _, restricted = self._claims(portrait=blob)
        self.assertEqual(restricted[wire.T_PORTRAIT_HASH],
                         hashlib.sha256(blob).digest())

    def test_a_document_with_no_portrait_carries_no_hash(self):
        from ovcrypto import wire

        _, restricted = self._claims(portrait=None)
        self.assertNotIn(wire.T_PORTRAIT_HASH, restricted)

    def test_the_portrait_renders_grayscale_and_aspect_fit(self):
        """cv2 throughout: the WebP path must not depend on Pillow, which is
        declared for the AVIF encoder alone."""
        import cv2
        import numpy as np

        from accounts import credentials

        blob = credentials.render_portrait(self._mock_face_uri())
        self.assertEqual(blob[8:12], b"WEBP")
        decoded = cv2.imdecode(np.frombuffer(blob, np.uint8),
                               cv2.IMREAD_UNCHANGED)
        height, width = decoded.shape[:2]
        self.assertLessEqual(max(height, width), credentials.PORTRAIT_PX)
        # Gray CONTENT, not a single-channel image: WebP has no grayscale
        # mode, so it comes back with three equal channels. Assert what was
        # actually asked for -- that no colour is left -- not the container.
        if decoded.ndim == 3:
            channels = decoded[:, :, :3].astype(int)
            spread = channels.max(axis=2) - channels.min(axis=2)
            self.assertLessEqual(int(spread.max()), 2)

    def test_the_portrait_symbol_scans_at_the_size_it_is_printed(self):
        """Quality gives way, never the 0.4 mm floor: a sharper face on a
        symbol that will not scan is worth nothing."""
        import uuid as _uuid

        from accounts import credentials
        from ovcrypto import qrsize

        blob = credentials.render_portrait(self._mock_face_uri())
        text = credentials.portrait_qr(blob, credential_id=_uuid.uuid4())
        self.assertTrue(text.startswith("CL03F1:"))
        plan = qrsize.plan(len(text), credentials.PORTRAIT_STAMP_MM, "Q")
        self.assertTrue(plan["scannable"],
                        "portrait needs %.1f mm, printed at %.1f"
                        % (plan["min_stamp_mm"],
                           credentials.PORTRAIT_STAMP_MM))

    def test_the_render_resolution_is_what_the_stamp_can_afford(self):
        """PORTRAIT_PX follows the budget; it is not a constant that happens
        to work.

        At the matched 48.8 mm stamp the image budget is 701 bytes, half of
        what a 68 mm symbol held, and 200 x 200 stops fitting: measured on
        five real captures, the ladder ran out before anything fitted for TWO
        of them -- no portrait symbol at all, from a working encoder.

        Pinned here on noise rather than on a face, because it has to be
        deterministic and because noise is the harder case: nothing in an
        ordinary portrait compresses worse. static/mock-face.png cannot do
        this job at all -- a cartoon fits at any resolution."""
        import base64 as _b64

        import cv2
        import numpy as np

        from accounts import credentials

        rng = np.random.default_rng(7)
        ok, buf = cv2.imencode(".png", rng.integers(
            0, 255, (480, 480, 3), dtype=np.uint8))
        self.assertTrue(ok)
        uri = "data:image/png;base64," + _b64.b64encode(bytes(buf)).decode()

        self.assertIsNotNone(
            credentials.render_portrait(uri),
            "the shipped resolution does not fit the stamp it prints at")
        self.assertIsNone(
            credentials.render_portrait(uri, px=200),
            "200 px still fits, so this test no longer says anything -- "
            "re-measure the budget before trusting it")

    def test_the_quality_ladder_has_no_floor_to_bottom_out_on(self):
        """A ladder that stops above 1 has a floor it can reach without ever
        fitting, and a ladder that gives up while rungs remain is a working
        encoder that returns nothing."""
        from accounts import credentials

        ladder = list(credentials.PORTRAIT_QUALITY_LADDER)
        self.assertEqual(min(ladder), 1)
        self.assertEqual(ladder, sorted(ladder, reverse=True))
        self.assertEqual(len(ladder), len(set(ladder)))

    def test_the_resolution_gives_way_when_the_quality_ladder_has(self):
        """A face that fits at no quality at the shipped resolution gets a
        smaller render, not a document with no face on it.

        Largest rung that fits, and that is measured rather than assumed: on
        the cel-art sample face, every rung that fits
        scores worse than the one above it (SSIM 0.7774 at 136 px down to
        0.7473 at 80), so the first fit is also the best of them.

        This does not contradict PORTRAIT_PX, which is about two resolutions
        that BOTH fit. Here the larger one fits at no quality at all."""
        from accounts import credentials

        uri = sample_face.unfittable_data_uri()
        self.assertIsNone(credentials.render_portrait(uri))
        blob, px = credentials.render_portrait_fitted(uri)
        self.assertIsNotNone(blob)
        self.assertLess(px, credentials.PORTRAIT_PX)
        self.assertTrue(credentials.portrait_fits(blob))
        # Largest first, no rung skipped, and a floor a face can bear.
        ladder = list(credentials.portrait_px_ladder())
        self.assertEqual(ladder[0], credentials.PORTRAIT_PX)
        self.assertEqual(ladder, sorted(ladder, reverse=True))
        self.assertEqual(min(ladder), credentials.PORTRAIT_PX_FLOOR)
        self.assertGreaterEqual(credentials.PORTRAIT_PX_FLOOR, 80)
        # And the rung it chose is the largest one that fits.
        above = [step for step in ladder if step > px]
        for step in above:
            self.assertIsNone(credentials.render_portrait(uri, px=step))

    def test_a_sweep_still_answers_about_the_resolution_it_asked_about(self):
        """`render_portrait(px=...)` is the single-resolution primitive, and
        it has to stay one: `debug_sizes --px` is how PORTRAIT_PX is chosen,
        and a run whose rows quietly answer about some other resolution
        cannot choose anything. Only `render_portrait_fitted()` walks."""
        from accounts import credentials

        uri = sample_face.unfittable_data_uri()
        self.assertIsNone(credentials.render_portrait(uri, px=200))
        self.assertIsNone(credentials.render_portrait(uri, px=160))
        measured = debug_store.measure_portrait(uri, px=160)
        self.assertIsNone(measured["bytes"])
        self.assertEqual(measured["px"], 160)

    def test_rubbish_instead_of_a_portrait_costs_nothing(self):
        """A document that cannot carry a portrait is still a valid
        document -- the same rule minting itself follows."""
        from accounts import credentials

        self.assertIsNone(credentials.render_portrait("not an image"))
        self.assertIsNone(credentials.render_portrait(""))

    def test_a_portrait_past_qr_capacity_is_answered_not_raised(self):
        """The ladder asks about its largest rung first. A rung that raised
        would abort the whole render and give no portrait at all -- a working
        encoder yielding nothing."""
        from accounts import credentials

        self.assertFalse(credentials.portrait_fits(b"x" * 4000))

    def test_the_renderer_needs_no_undeclared_dependency(self):
        """The renderer imports no PIL: Pillow is declared for the AVIF
        encoder alone, and the WebP path must work where it is missing."""
        import accounts.credentials as module

        source = open(module.__file__, encoding="utf-8").read()
        self.assertNotIn("from PIL", source)
        self.assertNotIn("import PIL", source)



class DebugCaptureGateTest(TestCase):
    """`DebugCapture` keeps whole eVerify responses -- every field, and the
    face -- so the printed document's sizing and quality can be measured
    against real data instead of against `static/mock-face.png`, which is a
    cartoon smiley and has produced a wrong answer here before.

    That makes it a table of complete identity records of real people, written
    on the strength of a setting, into a database that rides the off-site database
    backups. So it needs TWO opt-ins, exactly as the self-verifying mock does
    and for the same reason: one stray DJANGO_DEBUG=1 must not be enough to
    start it, and there would be no loud symptom if it were -- the health check
    still returns 200 and every page still looks normal.
    """

    def setUp(self):
        self.user = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="VIC1234",
            given_name="Victim", last_name="User")

    def _post(self):
        return self.client.post(
            "/everify/",
            data=json.dumps({"value": "1111222233334444",
                             "face_liveness_session_id": "sess"}),
            content_type="application/json")

    def _run(self, upstream_data=None):
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"data": upstream_data or {
            "reference": "1111222233334444", "code": "VIC1234",
            "first_name": "VICTIM", "last_name": "USER"}}
        patches = (
            patch("verify.views.everify.EVERIFY_CLIENT_ID", "id"),
            patch("verify.views.everify.EVERIFY_CLIENT_SECRET", "secret"),
            patch("verify.views.everify.get_everify_access_token",
                  return_value="tok"),
            patch("verify.views.everify.requests.post", return_value=resp),
        )
        for one in patches:
            one.start()
        self.addCleanup(lambda: [one.stop() for one in patches])
        return self._post()

    # -- the gate ----------------------------------------------------------

    @override_settings(DEBUG=False, EVERIFY_DEBUG_CAPTURE=False)
    def test_a_production_deployment_keeps_nothing(self):
        self._run()
        self.assertEqual(DebugCapture.objects.count(), 0)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=False)
    def test_debug_alone_keeps_nothing(self):
        """The whole point of the second opt-in. DJANGO_DEBUG turned on to
        chase a bug must not silently begin recording identities."""
        self._run()
        self.assertEqual(DebugCapture.objects.count(), 0)

    @override_settings(DEBUG=False, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_flag_alone_keeps_nothing(self):
        """A stale line left in a production .env is not enough either."""
        self._run()
        self.assertEqual(DebugCapture.objects.count(), 0)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_both_opt_ins_keep_the_response(self):
        resp = self._run()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(DebugCapture.objects.count(), 1)

    # -- what a capture holds ----------------------------------------------

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_it_keeps_keys_the_app_does_not_carry(self):
        """The reason to keep the raw response rather than the prepared rows.

        `_prepare_data_for_frontend` narrows to the field whitelist; a study
        wanting to know what the upstream actually sends -- which is how the
        36-key list was measured in the first place -- has to see past it."""
        debug_store.capture(
            {"reference": "1111", "something_new": "a value nobody carries"},
            [], purpose=DebugCapture.PURPOSE_VERIFY)
        row = DebugCapture.objects.get()
        self.assertEqual(row.payload["something_new"],
                         "a value nobody carries")

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_expiring_url_goes_and_the_image_stays(self):
        """`face_url` is a signed URL that stops resolving, so keeping it
        would leave a store full of links to nothing. The bytes it pointed at
        have already been fetched by the time this runs, and those are what a
        sizing run needs."""
        debug_store.capture(
            {"reference": "1111", "face_url": "https://everify/tmp/abc?sig=x"},
            [{"field": "face_url", "key": "Face Photo",
              "value": "data:image/png;base64,AAAA"}],
            purpose=DebugCapture.PURPOSE_VERIFY)
        row = DebugCapture.objects.get()
        self.assertNotIn("face_url", row.payload)
        self.assertEqual(row.photo_data, "data:image/png;base64,AAAA")

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_a_broken_store_does_not_cost_the_verification(self):
        """Same rule `_mint_credential()` follows: a debug facility is never
        worth a verification. It logs and gives up."""
        with patch("accounts.models.DebugCapture.objects.create",
                   side_effect=RuntimeError("disk full")):
            resp = self._run()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.client.session.get(SESSION_KEY), self.user.id)
        self.assertEqual(DebugCapture.objects.count(), 0)

    # -- emptying it -------------------------------------------------------

    def _rows(self, n=3):
        for i in range(n):
            DebugCapture.objects.create(
                purpose=DebugCapture.PURPOSE_VERIFY,
                payload={"reference": str(i)},
                photo_data="data:image/png;base64,AAAA")

    def test_the_command_empties_the_store(self):
        self._rows()
        out = StringIO()
        call_command("debug_cleanup", stdout=out)
        self.assertEqual(DebugCapture.objects.count(), 0)
        self.assertIn("3", out.getvalue())

    def test_dropping_the_faces_keeps_the_rows(self):
        """The softer option, exactly as purge_login_attempts has: the field
        data is still enough for the credential half of the sizing work."""
        self._rows()
        call_command("debug_cleanup", "--photos-only", stdout=StringIO())
        self.assertEqual(DebugCapture.objects.count(), 3)
        self.assertEqual(DebugCapture.objects.exclude(photo_data="").count(), 0)

    def test_a_dry_run_changes_nothing(self):
        self._rows()
        call_command("debug_cleanup", "--dry-run", stdout=StringIO())
        self.assertEqual(DebugCapture.objects.count(), 3)


class DebugCleanupPageTest(TestCase):
    """`/debug-cleanup/` -- where the store is read and emptied."""

    def setUp(self):
        self.admin = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="ADM1234",
            given_name="Site", last_name="Admin", is_site_admin=True)
        self.operator = User.objects.create(
            national_id_card_number="2222333344445555",
            digital_national_id="OPR1234",
            given_name="Ordinary", last_name="Operator")

    def _sign_in(self, user):
        session = self.client.session
        session[SESSION_KEY] = user.id
        session.save()

    @override_settings(DEBUG=False, EVERIFY_DEBUG_CAPTURE=False)
    def test_the_page_is_absent_where_the_store_is(self):
        """404, not 403 and not a redirect. A page that refused politely would
        still answer "does this deployment keep identity records?" for anyone
        who asked, which is the question the gate exists to leave unanswered.
        """
        self._sign_in(self.admin)
        self.assertEqual(self.client.get("/debug-cleanup/").status_code, 404)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_being_signed_out_is_the_same_404(self):
        """Not the ordinary bounce to the login page. A redirect would answer
        "does this deployment keep identity records?" for anyone who asked --
        and answer it on the one deployment where the answer is yes."""
        self.assertEqual(self.client.get("/debug-cleanup/").status_code, 404)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_an_ordinary_operator_cannot_see_the_faces(self):
        """The gate says whether the store exists; the session says who may
        look at real people. Neither replaces the other -- a development
        server is still a site with real records on it."""
        self._sign_in(self.operator)
        self.assertEqual(self.client.get("/debug-cleanup/").status_code, 404)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_a_site_admin_sees_the_store(self):
        DebugCapture.objects.create(purpose=DebugCapture.PURPOSE_VERIFY,
                                    payload={"reference": "1"})
        self._sign_in(self.admin)
        resp = self.client.get("/debug-cleanup/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "debug-cleanup")

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_button_empties_it(self):
        DebugCapture.objects.create(purpose=DebugCapture.PURPOSE_VERIFY,
                                    payload={"reference": "1"},
                                    photo_data="data:image/png;base64,AAAA")
        self._sign_in(self.admin)
        resp = self.client.post("/debug-cleanup/", {"scope": "all"})
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(DebugCapture.objects.count(), 0)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_softer_button_keeps_the_fields(self):
        DebugCapture.objects.create(purpose=DebugCapture.PURPOSE_VERIFY,
                                    payload={"reference": "1"},
                                    photo_data="data:image/png;base64,AAAA")
        self._sign_in(self.admin)
        self.client.post("/debug-cleanup/", {"scope": "photos"})
        self.assertEqual(DebugCapture.objects.count(), 1)
        self.assertEqual(DebugCapture.objects.get().photo_data, "")

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_a_face_is_not_shown_to_an_audience(self):
        """Demo Mode covers every page, and this one is a wall of faces."""
        face = "data:image/png;base64," + base64.b64encode(
            (settings.BASE_DIR / "static" / "mock-face.png").read_bytes()
        ).decode()
        DebugCapture.objects.create(purpose=DebugCapture.PURPOSE_VERIFY,
                                    payload={"reference": "1"},
                                    photo_data=face)
        self._sign_in(self.admin)
        self.assertContains(self.client.get("/debug-cleanup/"), face[:64])

        UserSettings.objects.update_or_create(
            user=self.admin, defaults={"demo_mode": True})
        self.assertNotContains(self.client.get("/debug-cleanup/"), face[:64])

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_one_row_can_be_dropped_without_the_rest(self):
        """The store is a scratch pad, and a study usually wants a handful of
        what it holds. Without this the only way to be rid of one capture is
        to be rid of all of them and run the lookups again."""
        keep = DebugCapture.objects.create(
            purpose=DebugCapture.PURPOSE_VERIFY, payload={"reference": "1"})
        drop = DebugCapture.objects.create(
            purpose=DebugCapture.PURPOSE_VERIFY, payload={"reference": "2"})
        self._sign_in(self.admin)
        resp = self.client.post("/debug-cleanup/",
                                {"scope": "one", "capture": drop.pk})
        self.assertEqual(resp.status_code, 302)
        self.assertEqual([row.pk for row in DebugCapture.objects.all()],
                         [keep.pk])

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_an_unparseable_id_deletes_nothing_and_does_not_raise(self):
        """`pk` is an integer column, so filtering it by junk raises rather
        than matching nothing -- the lesson `/api/v1/device/keys/` learned by
        answering a 500. Parsed before it is queried, and junk means the same
        as "no such row"."""
        DebugCapture.objects.create(purpose=DebugCapture.PURPOSE_VERIFY,
                                    payload={"reference": "1"})
        self._sign_in(self.admin)
        for junk in ("", "not-a-number", "1; drop table", None):
            resp = self.client.post(
                "/debug-cleanup/",
                {"scope": "one", "capture": junk} if junk is not None
                else {"scope": "one"})
            self.assertEqual(resp.status_code, 302)
        self.assertEqual(DebugCapture.objects.count(), 1)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_dropping_one_row_leaves_the_rest_of_the_store_alone(self):
        """A per-row delete that quietly emptied the table would look exactly
        like the button above it, and the confirmation says otherwise."""
        for n in range(3):
            DebugCapture.objects.create(purpose=DebugCapture.PURPOSE_VERIFY,
                                        payload={"reference": str(n)})
        first = DebugCapture.objects.first()
        self._sign_in(self.admin)
        self.client.post("/debug-cleanup/", {"scope": "one",
                                             "capture": first.pk})
        self.assertEqual(DebugCapture.objects.count(), 2)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_an_ordinary_operator_cannot_drop_a_row(self):
        """The same two checks the page itself makes. A delete that ran for
        anybody signed in would be a way to destroy a study from an account
        that may not even read it."""
        capture = DebugCapture.objects.create(
            purpose=DebugCapture.PURPOSE_VERIFY, payload={"reference": "1"})
        self._sign_in(self.operator)
        resp = self.client.post("/debug-cleanup/",
                                {"scope": "one", "capture": capture.pk})
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(DebugCapture.objects.count(), 1)


class DebugSizingTest(TestCase):
    """The report is the reason the store exists: real faces and real
    addresses, measured against the two symbols the card prints."""

    def _face(self):
        return "data:image/png;base64," + base64.b64encode(
            (settings.BASE_DIR / "static" / "mock-face.png").read_bytes()
        ).decode()

    def test_it_measures_the_shipped_settings_by_default(self):
        """Called with neither px nor stamp it answers "is what we deploy
        right for this face", which is the question worth asking most often."""
        measured = debug_store.measure_portrait(self._face())
        self.assertEqual(measured["px"], credentials.PORTRAIT_PX)
        self.assertEqual(measured["stamp_mm"], credentials.PORTRAIT_STAMP_MM)
        self.assertTrue(measured["scannable"])
        self.assertGreaterEqual(measured["module_mm"], 0.4)

    def test_it_can_be_asked_about_a_size_that_is_not_shipped(self):
        """What a sweep needs. 200 px does not fit the stamp this build
        prints -- see PORTRAIT_PX -- and the report has to be able to say so
        rather than only ever agreeing with the constants."""
        wide = debug_store.measure_portrait(self._face(), stamp_mm=68.0)
        self.assertEqual(wide["stamp_mm"], 68.0)
        self.assertGreater(wide["bytes"], 0)

    def test_no_face_is_answered_not_raised(self):
        self.assertIsNone(debug_store.measure_portrait(""))
        self.assertIsNone(debug_store.measure_portrait(None))

    def test_the_command_runs_on_an_empty_store(self):
        out = StringIO()
        call_command("debug_sizes", stdout=out)
        self.assertIn("0 capture(s)", out.getvalue())

    def test_the_command_reports_what_is_there(self):
        DebugCapture.objects.create(purpose=DebugCapture.PURPOSE_VERIFY,
                                    payload={"reference": "1111"},
                                    photo_data=self._face())
        out = StringIO()
        call_command("debug_sizes", stdout=out)
        text = out.getvalue()
        self.assertIn("1 capture(s), 1 with a face", text)
        self.assertIn("PORTRAIT", text)



class DebugCaptureSwitchTest(TestCase):
    """The switch on the Setup page: it can pause the store, and that is all.

    The gate is two environment opt-ins and stays there. A switch that could
    turn capture ON would be a way to start recording complete identity
    records -- names, both ID numbers, addresses, faces -- on a deployment
    whose environment says it must not have them, from a web form, on the
    strength of one admin session. So the switch is read BEHIND the gate,
    never instead of it.
    """

    def setUp(self):
        self.admin = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="ADM1234",
            given_name="Site", last_name="Admin", is_site_admin=True)
        self.operator = User.objects.create(
            national_id_card_number="2222333344445555",
            digital_national_id="OPR1234",
            given_name="Ordinary", last_name="Operator")
        self.org = make_org()
        join(self.org, self.admin)
        join(self.org, self.operator)

    def _sign_in(self, user):
        session = self.client.session
        session[SESSION_KEY] = user.id
        session[ORG_SESSION_KEY] = self.org.id
        session.save()

    def _capture(self):
        return debug_store.capture({"reference": "1111"}, [],
                                   purpose=DebugCapture.PURPOSE_VERIFY)

    @override_settings(DEBUG=False, EVERIFY_DEBUG_CAPTURE=False)
    def test_the_switch_cannot_open_a_store_the_environment_refuses(self):
        """The whole point. Turning it on where the gate is shut changes
        nothing -- otherwise a stray row in the settings table would be a
        third opt-in nobody audited."""
        SiteSettings.objects.update_or_create(
            pk=1, defaults={"debug_capture_enabled": True})
        self.assertFalse(debug_store.capture_enabled())
        self._capture()
        self.assertEqual(DebugCapture.objects.count(), 0)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_off_stops_the_store_taking_rows(self):
        SiteSettings.objects.update_or_create(
            pk=1, defaults={"debug_capture_enabled": False})
        self.assertFalse(debug_store.capture_enabled())
        self._capture()
        self.assertEqual(DebugCapture.objects.count(), 0)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_on_is_the_default_where_the_gate_is_open(self):
        """An instance that was capturing before there was a switch goes on
        capturing after it. A new column must not quietly stop a study."""
        # Nothing saved: the field's own default is what answers, and
        # load() does not create a row on a read path.
        SiteSettings.objects.all().delete()
        self.assertTrue(SiteSettings().debug_capture_enabled)
        self.assertTrue(debug_store.capture_enabled())
        self._capture()
        self.assertEqual(DebugCapture.objects.count(), 1)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_turning_it_off_keeps_what_is_already_stored(self):
        """Pausing is not purging. There is a separate button for that, and
        it asks first."""
        self._capture()
        self._sign_in(self.admin)
        self.client.post("/debug-cleanup/",
                         {"scope": "switch", "next": "setup"})
        self.assertFalse(SiteSettings.load().debug_capture_enabled)
        self.assertEqual(DebugCapture.objects.count(), 1)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_switch_comes_back_on(self):
        SiteSettings.objects.update_or_create(
            pk=1, defaults={"debug_capture_enabled": False})
        self._sign_in(self.admin)
        self.client.post("/debug-cleanup/",
                         {"scope": "switch", "enabled": "1"})
        self.assertTrue(SiteSettings.load().debug_capture_enabled)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_an_ordinary_operator_cannot_touch_the_switch(self):
        """Same 404 the page gives. The store is site-admin business, and a
        refusal that explained itself would say the store is here."""
        self._sign_in(self.operator)
        resp = self.client.post("/debug-cleanup/", {"scope": "switch"})
        self.assertEqual(resp.status_code, 404)
        self.assertTrue(debug_store.capture_enabled())

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_setup_page_carries_the_store_for_a_site_admin(self):
        DebugCapture.objects.create(purpose=DebugCapture.PURPOSE_VERIFY,
                                    payload={"reference": "1"},
                                    detail="named nobody",
                                    outcome=DebugCapture.OUTCOME_FAILURE)
        self._sign_in(self.admin)
        page = self.client.get("/app/setup/")
        self.assertContains(page, "Development capture store")
        self.assertContains(page, "debug_capture_enabled")
        self.assertContains(page, "named nobody")

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_an_ordinary_operator_does_not_see_the_section(self):
        self._sign_in(self.operator)
        page = self.client.get("/app/setup/")
        self.assertEqual(page.status_code, 200)
        self.assertNotContains(page, "Development capture store")

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_faces_are_not_even_fetched_for_an_ordinary_operator(self):
        """The template checks the same thing, deliberately: that is defence
        in depth. This one pins the view: an operator's page must not be
        built holding a list of real people's faces, even one it does not
        render."""
        DebugCapture.objects.create(purpose=DebugCapture.PURPOSE_VERIFY,
                                    payload={"reference": "1"},
                                    photo_data="data:image/png;base64,AAAA")
        self._sign_in(self.operator)
        page = self.client.get("/app/setup/")
        self.assertIsNone(page.context.get("captures"))
        self.assertIsNone(page.context.get("with_photos"))

    @override_settings(DEBUG=False, EVERIFY_DEBUG_CAPTURE=False)
    def test_production_setup_says_nothing_about_a_store(self):
        """The section is not merely empty on production -- it is absent,
        along with any hint that such a thing exists."""
        self._sign_in(self.admin)
        page = self.client.get("/app/setup/")
        self.assertEqual(page.status_code, 200)
        self.assertNotContains(page, "Development capture store")
        self.assertNotContains(page, "debug-cleanup")

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_each_row_offers_the_document_the_validation_and_a_delete(self):
        """The store's whole point is real data to look at, and the table is
        where somebody is standing when they want to look at it. Assert the
        row's own id in each, not merely that the words appear: a link to the
        sample with no capture on it opens the synthetic person and reads as
        working."""
        capture = DebugCapture.objects.create(
            purpose=DebugCapture.PURPOSE_VERIFY,
            payload={"reference": "1", "first_name": "REAL"})
        self._sign_in(self.admin)
        body = self.client.get("/app/setup/").content.decode()
        self.assertIn("/debug-sample/?capture=%d" % capture.pk, body)
        self.assertIn("/debug-sample/validate/?capture=%d" % capture.pk, body)
        self.assertIn('name="capture" value="%d"' % capture.pk, body)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_a_failed_row_offers_no_document(self):
        """A failure holds an upstream error body, not a person. Offering to
        open a document of one would offer a document with nobody in it --
        and the page would quietly show the synthetic person instead."""
        capture = DebugCapture.objects.create(
            purpose=DebugCapture.PURPOSE_LOGIN,
            outcome=DebugCapture.OUTCOME_FAILURE,
            payload={"response": "unauthorized"}, status_code=401)
        self._sign_in(self.admin)
        body = self.client.get("/app/setup/").content.decode()
        self.assertNotIn("/debug-sample/?capture=%d" % capture.pk, body)
        # It can still be dropped -- that is what a failure row is for.
        self.assertIn('name="capture" value="%d"' % capture.pk, body)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_dropping_a_row_from_setup_comes_back_to_setup(self):
        capture = self._capture()
        self._sign_in(self.admin)
        resp = self.client.post(
            "/debug-cleanup/",
            {"scope": "one", "capture": capture.pk, "next": "setup"})
        self.assertEqual(resp["Location"], "/app/setup/")
        self.assertEqual(DebugCapture.objects.count(), 0)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_purge_button_on_setup_comes_back_to_setup(self):
        self._capture()
        self._sign_in(self.admin)
        resp = self.client.post("/debug-cleanup/",
                                {"scope": "all", "next": "setup"})
        self.assertEqual(resp["Location"], "/app/setup/")
        self.assertEqual(DebugCapture.objects.count(), 0)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_way_back_is_a_choice_of_two_pages_not_a_url(self):
        """A redirect target read out of a POST body is a redirect to
        anywhere. Only the two names this app knows are honoured."""
        self._sign_in(self.admin)
        resp = self.client.post(
            "/debug-cleanup/",
            {"scope": "all", "next": "https://example.invalid/"})
        self.assertEqual(resp["Location"], "/debug-cleanup/")


class DebugCaptureFailureTest(TestCase):
    """A lookup that produced no identity is kept too, and for its own reason.

    A row here is the evidence of an upstream that stopped answering: which
    401 it was, kept where a site admin can read it rather than gone by the
    time anybody looks.

    It carries no identity: eVerify's error bodies are {error,
    error_description, message}, and nothing from the caller's own request is
    written. That is what makes failures the half of the store worth keeping
    after the faces are dropped.
    """

    def setUp(self):
        self.user = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="VIC1234",
            given_name="Victim", last_name="User")

    def _post(self):
        return self.client.post(
            "/everify/",
            data=json.dumps({"value": "1111222233334444",
                             "face_liveness_session_id": "sess"}),
            content_type="application/json")

    def _run(self, response):
        patches = (
            patch("verify.views.everify.EVERIFY_CLIENT_ID", "id"),
            patch("verify.views.everify.EVERIFY_CLIENT_SECRET", "secret"),
            patch("verify.views.everify.get_everify_access_token",
                  return_value="tok"),
            patch("verify.views.everify.requests.post",
                  return_value=response),
        )
        for one in patches:
            one.start()
        self.addCleanup(lambda: [one.stop() for one in patches])
        return self._post()

    def _refusal(self, status=401):
        body = ('{"error":"unauthorized","message":"Unauthenticated.",'
                '"error_description":"Unauthenticated."}')
        resp = MagicMock(status_code=status, text=body)
        resp.json.return_value = json.loads(body)
        return resp

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_an_upstream_refusal_is_kept(self):
        self._run(self._refusal())
        row = DebugCapture.objects.get()
        self.assertEqual(row.outcome, DebugCapture.OUTCOME_FAILURE)
        self.assertEqual(row.status_code, 401)
        self.assertIn("credentials", row.detail)
        self.assertEqual(row.purpose, DebugCapture.PURPOSE_LOGIN)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_a_failure_carries_what_the_upstream_said(self):
        """Which is the whole value of it: "Unauthenticated" and
        "Unauthorized" are different diagnoses, and the difference is in the
        body."""
        self._run(self._refusal())
        row = DebugCapture.objects.get()
        self.assertIn("Unauthenticated", row.payload["response"])
        self.assertTrue(row.payload["trace"])

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_a_failure_holds_no_identity_and_no_face(self):
        """Not even the National ID that was typed. The caller's own request
        body is where an identity would come from, and none of it is written
        here -- which is why a failure row is not an identity record."""
        self._run(self._refusal())
        row = DebugCapture.objects.get()
        self.assertEqual(row.photo_data, "")
        self.assertNotIn("1111222233334444", json.dumps(row.payload))

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_a_200_that_names_nobody_is_a_failure(self):
        """It is a lookup that did not identify anyone. Filing it as a
        success would make the two counts on the page a lie."""
        resp = MagicMock(status_code=200, text="{}")
        resp.json.return_value = {"data": {"token": "t"}}
        self._run(resp)
        row = DebugCapture.objects.get()
        self.assertEqual(row.outcome, DebugCapture.OUTCOME_FAILURE)
        self.assertEqual(row.detail, "named nobody")

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_a_verified_false_is_a_failure_and_keeps_its_data(self):
        """The one failure that does carry the person: the upstream named
        them and then declined to vouch for them."""
        resp = MagicMock(status_code=200, text="{}")
        resp.json.return_value = {"data": {
            "reference": "1111222233334444", "code": "VIC1234",
            "first_name": "VICTIM", "last_name": "USER", "verified": False}}
        self._run(resp)
        row = DebugCapture.objects.get()
        self.assertEqual(row.outcome, DebugCapture.OUTCOME_FAILURE)
        self.assertEqual(row.detail, "verified=false")
        self.assertEqual(row.payload["reference"], "1111222233334444")

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_a_success_is_still_a_success(self):
        resp = MagicMock(status_code=200, text="{}")
        resp.json.return_value = {"data": {
            "reference": "1111222233334444", "code": "VIC1234",
            "first_name": "VICTIM", "last_name": "USER"}}
        self._run(resp)
        row = DebugCapture.objects.get()
        self.assertEqual(row.outcome, DebugCapture.OUTCOME_SUCCESS)
        self.assertEqual(row.detail, "")

    @override_settings(DEBUG=False, EVERIFY_DEBUG_CAPTURE=False)
    def test_production_keeps_no_failures_either(self):
        """The gate is the gate. A failure carries no identity, but a table
        of them on production is still a table nobody signed up for."""
        self._run(self._refusal())
        self.assertEqual(DebugCapture.objects.count(), 0)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_a_broken_store_does_not_change_what_the_caller_is_told(self):
        """Same rule the success path follows: a debug facility is never
        worth a verification, or a sensible error message."""
        with patch("accounts.models.DebugCapture.objects.create",
                   side_effect=RuntimeError("disk full")):
            resp = self._run(self._refusal())
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(DebugCapture.objects.count(), 0)


class SampleDocumentTest(TestCase):
    """`/debug-sample/` -- a finished document with nobody in it.

    It answers the looking half of what the debug store answers the measuring
    half of, and it does it with no identity record involved: constants, and
    a face that is drawn rather than photographed.
    """

    def setUp(self):
        self.admin = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="ADM1234",
            given_name="Site", last_name="Admin", is_site_admin=True)
        self.operator = User.objects.create(
            national_id_card_number="2222333344445555",
            digital_national_id="OPR1234",
            given_name="Ordinary", last_name="Operator")
        self.org = make_org()
        join(self.org, self.admin)
        join(self.org, self.operator)

    def _sign_in(self, user):
        session = self.client.session
        session[SESSION_KEY] = user.id
        session[ORG_SESSION_KEY] = self.org.id
        session["operator_location"] = str(self.org.locations.first().id)
        session.save()

    @override_settings(DEBUG=False, EVERIFY_DEBUG_CAPTURE=False)
    def test_it_is_absent_where_the_store_is(self):
        """Same 404 as the cleanup page, for the same reason: this is a
        development affordance, and production must not answer questions
        about which ones it has."""
        self._sign_in(self.admin)
        self.assertEqual(self.client.get("/debug-sample/").status_code, 404)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_an_ordinary_operator_cannot_reach_it(self):
        self._sign_in(self.operator)
        self.assertEqual(self.client.get("/debug-sample/").status_code, 404)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_it_renders_a_document(self):
        self._sign_in(self.admin)
        resp = self.client.get("/debug-sample/", follow=True)
        self.assertEqual(resp.status_code, 200)
        rows = {item["key"]: item["value"] for item in resp.context["data"]}
        self.assertEqual(rows["Given Name"], "LISA ROSE")
        self.assertTrue(rows["Face Photo"].startswith("data:image/jpeg;base64,"))

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_nothing_about_the_person_comes_from_the_request(self):
        """The difference between this and `_mock_everify_data()`, which
        echoes the caller's own POST body back as a verified identity and
        needs two opt-ins for exactly that reason. This one has nothing to
        echo: no query string, no body, no header changes what it renders."""
        self._sign_in(self.admin)
        resp = self.client.get(
            "/debug-sample/?first_name=INJECTED&value=9999888877776666",
            follow=True)
        rendered = json.dumps(resp.context["data"])
        self.assertNotIn("INJECTED", rendered)
        self.assertNotIn("9999888877776666", rendered)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_it_goes_through_this_organizations_field_list(self):
        """Which is most of the reason to look at a sample: a field just
        switched on has to appear, under the name it was given."""
        OrganizationFieldSetting.objects.create(
            organization=self.org, key="present_barangay",
            display_name="Barangay (present)", show_on_document=True,
            include_in_log=False, position=99)
        self._sign_in(self.admin)
        resp = self.client.get("/debug-sample/", follow=True)
        rows = {item["key"]: item["value"] for item in resp.context["data"]}
        self.assertEqual(rows["Barangay (present)"],
                         "Barangay Loyola Heights")

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_looking_at_a_sample_does_not_log_a_transaction(self):
        """A sample is not a verification. An organization's log must not
        acquire rows for people who do not exist."""
        self._sign_in(self.admin)
        self.client.get("/debug-sample/", follow=True)
        self.assertEqual(Transaction.objects.count(), 0)
        self.assertEqual(DebugCapture.objects.count(), 0)

    def test_the_rows_carry_the_key_not_only_the_label(self):
        """Every decision downstream -- logging, demo masking, the face
        branch, the credential -- matches on eVerify's own key. A sample row
        without one would render and then behave differently from a real
        one, which is the one thing it must not do."""
        for row in sample_data.sample_rows(None):
            self.assertTrue(row["field"], row)
            self.assertIn(row["field"], everify_fields.FIELD_KEYS)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_validate_page_can_be_shown_filled(self):
        self._sign_in(self.admin)
        page = self.client.get("/debug-sample/validate/")
        self.assertEqual(page.status_code, 200)
        filled = page.context["prefill"]["transaction"]
        self.assertEqual(filled["given_name"], "LISA ROSE")
        self.assertEqual(filled["national_id_card_number"],
                         "0000-1111-2222-3333")
        self.assertContains(page, "This is a sample, not a validation")

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_sample_record_resolves_to_nothing(self):
        """The one rule this page must not break. `/api/validate/` is
        unauthenticated and is what a printed QR resolves to, so an endpoint
        whose whole job is "this record exists" must never say so about a
        record that does not -- a third party checking a document is exactly
        who would be misled."""
        self._sign_in(self.admin)
        page = self.client.get("/debug-sample/validate/")
        uuid_shown = page.context["prefill"]["transaction_id"]
        answer = self.client.get("/api/validate/%s/" % uuid_shown)
        self.assertEqual(json.loads(answer.content)["status"], "not_found")
        self.assertEqual(Transaction.objects.count(), 0)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_it_can_be_filled_from_a_stored_response(self):
        """Which is what the store is for: real values to look at."""
        capture = DebugCapture.objects.create(
            purpose=DebugCapture.PURPOSE_VERIFY,
            payload={"first_name": "REAL", "last_name": "PERSON",
                     "reference": "9999888877776666", "code": "RLP0001"})
        self._sign_in(self.admin)
        page = self.client.get("/debug-sample/validate/?capture=%d"
                               % capture.pk)
        filled = page.context["prefill"]["transaction"]
        self.assertEqual(filled["given_name"], "REAL")
        self.assertEqual(filled["national_id_card_number"],
                         "9999-8888-7777-6666")

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_demo_mode_does_not_swap_the_record_for_a_different_person(self):
        """Demo Mode masks what is rendered. It never changes WHICH record is
        rendered: a click on a row shows that row, never somebody else.

        `/validate/`, the page this fills, renders a real scanned transaction
        in the clear whether Demo Mode is on or off, so a stored response is
        treated the same way."""
        capture = DebugCapture.objects.create(
            purpose=DebugCapture.PURPOSE_VERIFY,
            payload={"first_name": "REAL", "last_name": "PERSON"})
        UserSettings.objects.update_or_create(
            user=self.admin, defaults={"demo_mode": True})
        self._sign_in(self.admin)
        page = self.client.get("/debug-sample/validate/?capture=%d"
                               % capture.pk)
        filled = page.context["prefill"]["transaction"]
        self.assertEqual(filled["given_name"], "REAL")
        self.assertIn("capture #%d" % capture.pk, page.context["prefill_source"])

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_a_failed_capture_cannot_fill_it(self):
        """A failure holds an error body, not a person. Filling the page from
        one would show a validated record with nobody in it."""
        capture = DebugCapture.objects.create(
            purpose=DebugCapture.PURPOSE_LOGIN,
            outcome=DebugCapture.OUTCOME_FAILURE,
            payload={"response": "unauthorized"}, status_code=401)
        self._sign_in(self.admin)
        page = self.client.get("/debug-sample/validate/?capture=%d"
                               % capture.pk)
        self.assertEqual(page.context["prefill"]["transaction"]["given_name"],
                         "LISA ROSE")

    @override_settings(DEBUG=False, EVERIFY_DEBUG_CAPTURE=False)
    def test_the_filled_page_is_absent_on_production(self):
        self._sign_in(self.admin)
        resp = self.client.get("/debug-sample/validate/")
        self.assertEqual(resp.status_code, 404)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_an_ordinary_operator_cannot_fill_it_either(self):
        self._sign_in(self.operator)
        resp = self.client.get("/debug-sample/validate/")
        self.assertEqual(resp.status_code, 404)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_filled_page_renders_through_the_real_payload_builder(self):
        """The sample has to be a sample of the page that exists. Handing an
        unsaved Transaction to the same `transaction_payload()` the API uses
        is what guarantees the dashes, the +08 timestamp and the key names
        cannot drift apart from the real thing."""
        from verify.views import core as core_views

        txn = sample_data.sample_transaction(organization=self.org,
                                             operator=self.admin)
        payload = core_views.transaction_payload(txn)
        self._sign_in(self.admin)
        page = self.client.get("/debug-sample/validate/")
        self.assertEqual(set(page.context["prefill"]["transaction"]),
                         set(payload))
        self.assertEqual(page.context["prefill"]["transaction"]["organization"],
                         self.org.name)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_document_shows_the_chosen_portrait(self):
        """`static/sample-face.png`, not the drawn stand-in. The two are for
        different jobs -- see `sample_face` -- and the page is the looking
        one."""
        self._sign_in(self.admin)
        resp = self.client.get("/debug-sample/", follow=True)
        rows = {item["key"]: item["value"] for item in resp.context["data"]}
        self.assertEqual(rows["Face Photo"], sample_face.data_uri())
        self.assertNotEqual(rows["Face Photo"], sample_face.drawn_data_uri())

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_drawn_face_is_still_reachable(self):
        """Because it is the one that compresses like skin, and the store is
        empty on a fresh instance -- which is exactly when somebody wants to
        measure something."""
        self._sign_in(self.admin)
        resp = self.client.get("/debug-sample/?face=drawn", follow=True)
        rows = {item["key"]: item["value"] for item in resp.context["data"]}
        self.assertEqual(rows["Face Photo"], sample_face.drawn_data_uri())

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_document_can_be_filled_from_a_stored_response(self):
        """The document half of what `?capture=` already did for the
        validation page, and the whole reason the store keeps whole
        responses: what a real payload does to a real document."""
        capture = DebugCapture.objects.create(
            purpose=DebugCapture.PURPOSE_VERIFY,
            payload={"first_name": "REAL", "last_name": "PERSON",
                     "reference": "9999888877776666", "code": "RLP0001",
                     "full_address": "12 Real Street, Quezon City"})
        self._sign_in(self.admin)
        resp = self.client.get("/debug-sample/?capture=%d" % capture.pk,
                               follow=True)
        rows = {item["key"]: item["value"] for item in resp.context["data"]}
        self.assertEqual(rows["Given Name"], "REAL")
        self.assertEqual(rows["National ID Card Number"], "9999888877776666")
        self.assertNotIn("LISA ROSE", rows.values())

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_stored_face_comes_back_out_of_its_own_column(self):
        """`capture()` drops `face_url` -- a signed URL that expires -- and
        keeps the bytes in `photo_data`. Putting them back under that key is
        what makes a stored response the same shape as a live one, so the row
        builder needs no branch for it and the document prints a face."""
        face = "data:image/png;base64," + base64.b64encode(
            (settings.BASE_DIR / "static" / "mock-face.png").read_bytes()
        ).decode()
        capture = DebugCapture.objects.create(
            purpose=DebugCapture.PURPOSE_VERIFY,
            payload={"first_name": "REAL", "last_name": "PERSON"},
            photo_data=face)
        self._sign_in(self.admin)
        resp = self.client.get("/debug-sample/?capture=%d" % capture.pk,
                               follow=True)
        rows = {item["key"]: item["value"] for item in resp.context["data"]}
        self.assertEqual(rows["Face Photo"], face)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_a_stored_response_goes_through_this_organizations_field_list(self):
        """Not through the list the capturing organization had. What a
        document view is opened to answer is what THIS deployment would print
        of that payload, in its order and under its labels."""
        OrganizationFieldSetting.objects.create(
            organization=self.org, key="present_barangay",
            display_name="Barangay (present)", show_on_document=True,
            include_in_log=False, position=99)
        capture = DebugCapture.objects.create(
            purpose=DebugCapture.PURPOSE_VERIFY,
            payload={"first_name": "REAL",
                     "present_barangay": "Barangay Totally Real"})
        self._sign_in(self.admin)
        resp = self.client.get("/debug-sample/?capture=%d" % capture.pk,
                               follow=True)
        rows = {item["key"]: item["value"] for item in resp.context["data"]}
        self.assertEqual(rows["Barangay (present)"], "Barangay Totally Real")

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_demo_mode_masks_a_stored_response_rather_than_replacing_it(self):
        """The row you clicked, redacted -- not somebody else, unredacted.

        The stored response is retrieved and then goes through the document's
        own `apply_demo_mask()`, exactly as a real verification does."""
        face = "data:image/png;base64," + base64.b64encode(
            (settings.BASE_DIR / "static" / "mock-face.png").read_bytes()
        ).decode()
        capture = DebugCapture.objects.create(
            purpose=DebugCapture.PURPOSE_VERIFY,
            payload={"first_name": "REAL", "last_name": "PERSON",
                     "middle_name": "MIDDLENAME",
                     "reference": "9999888877776666"},
            photo_data=face)
        self._sign_in(self.admin)

        # The session holds what was retrieved: this row, unmasked, exactly
        # as a live verification leaves it there.
        self.client.get("/debug-sample/?capture=%d" % capture.pk, follow=True)
        stored = json.dumps(self.client.session[verified_answer.KEY]["rows"])
        self.assertIn("REAL", stored)
        self.assertNotIn("LISA ROSE", stored)

        # What the page renders is masked -- the document's own doing, and
        # the same masking a real verification gets.
        UserSettings.objects.update_or_create(
            user=self.admin, defaults={"demo_mode": True})
        resp = self.client.get("/debug-sample/?capture=%d" % capture.pk,
                               follow=True)
        rows = {item["field"]: item["value"] for item in resp.context["data"]}
        self.assertNotEqual(rows["middle_name"], "MIDDLENAME")
        self.assertNotEqual(rows["reference"], "9999888877776666")
        self.assertIn(DEMO_MASK_CHAR, rows["reference"])
        self.assertTrue(resp.context["demo_mode"])
        # And it is still this capture that is being shown, not a stand-in.
        self.assertNotIn("LISA ROSE", json.dumps(resp.context["data"]))

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_a_failed_capture_cannot_fill_the_document_either(self):
        """A failure row holds an upstream error body, not a person."""
        capture = DebugCapture.objects.create(
            purpose=DebugCapture.PURPOSE_LOGIN,
            outcome=DebugCapture.OUTCOME_FAILURE,
            payload={"response": "unauthorized"}, status_code=401)
        self._sign_in(self.admin)
        resp = self.client.get("/debug-sample/?capture=%d" % capture.pk,
                               follow=True)
        rows = {item["key"]: item["value"] for item in resp.context["data"]}
        self.assertEqual(rows["Given Name"], "LISA ROSE")

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_an_unparseable_capture_id_falls_back_rather_than_raising(self):
        """`pk` is an integer column: filtering it by junk raises rather than
        matching nothing. Junk, a failure and a row that does not exist all
        mean the same thing here, which is the synthetic person."""
        self._sign_in(self.admin)
        for junk in ("not-a-number", "999999", "1;drop"):
            resp = self.client.get("/debug-sample/?capture=%s" % junk,
                                   follow=True)
            self.assertEqual(resp.status_code, 200)
            rows = {item["key"]: item["value"]
                    for item in resp.context["data"]}
            self.assertEqual(rows["Given Name"], "LISA ROSE")

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_looking_at_a_stored_response_does_not_log_or_capture(self):
        """Opening a document is still looking, whoever is in it."""
        capture = DebugCapture.objects.create(
            purpose=DebugCapture.PURPOSE_VERIFY,
            payload={"first_name": "REAL", "last_name": "PERSON"})
        self._sign_in(self.admin)
        self.client.get("/debug-sample/?capture=%d" % capture.pk, follow=True)
        self.assertEqual(Transaction.objects.count(), 0)
        self.assertEqual(DebugCapture.objects.count(), 1)

    def test_the_chosen_portrait_fits_at_the_shipped_resolution(self):
        """The sample document prints BOTH symbols, at full resolution.

        The cel art cannot: hard black outlines, which an encoder pays for at
        every quality -- 908 bytes at quality 1 against a 701-byte budget, so
        nothing at the shipped 160 px fits and only the fallback's 136 px
        gets a symbol at all. A sample document exists to be looked at.

        A photograph needs none of that. `sample-id1.png` fits at the full
        160 px, so no rung is spent and the sample now prints what a real
        verification prints. The fallback is still exercised, by the artwork
        that still needs it."""
        from accounts import credentials

        chosen = debug_store.measure_portrait(sample_face.data_uri())
        self.assertTrue(chosen["scannable"])
        self.assertGreaterEqual(chosen["module_mm"], 0.4)
        self.assertEqual(chosen["px"], credentials.PORTRAIT_PX,
                         "the sample portrait needed a smaller render")
        self.assertIsNotNone(
            credentials.render_portrait(sample_face.data_uri()),
            "the sample portrait no longer fits at the shipped resolution -- "
            "the budget or the artwork moved, and sample_face's note is stale")

        # The hard-edged artwork keeps the fallback honest.
        self.assertIsNone(
            credentials.render_portrait(sample_face.unfittable_data_uri()))
        fell = debug_store.measure_portrait(sample_face.unfittable_data_uri())
        self.assertTrue(fell["scannable"])
        self.assertLess(fell["px"], credentials.PORTRAIT_PX)

        drawn = debug_store.measure_portrait(sample_face.drawn_data_uri())
        self.assertTrue(drawn["scannable"])
        self.assertGreaterEqual(drawn["module_mm"], 0.4)
        self.assertEqual(drawn["px"], credentials.PORTRAIT_PX)

    def test_the_face_is_drawn_the_same_way_twice(self):
        """Deterministic, so a test can assert on it and two people
        comparing a document are comparing the same document."""
        self.assertEqual(sample_face.jpeg_bytes(), sample_face.jpeg_bytes())

    def test_the_drawn_face_costs_what_a_photograph_costs(self):
        """The reason it is drawn rather than reused from `static/`.
        `mock-face.png` is a cartoon smiley: flat vector art, which collapses
        at high quality where skin does not, so measuring on it gives wrong
        answers. Real captures encode to 3508-4884 bytes at q90; the cartoon
        manages 2386.
        """
        import cv2
        import numpy as np

        def cost(image):
            grey = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            small = cv2.resize(grey, (200, 200),
                               interpolation=cv2.INTER_AREA)
            return len(cv2.imencode(".webp", small,
                                    [cv2.IMWRITE_WEBP_QUALITY, 90])[1])

        def decoded(blob):
            return cv2.imdecode(np.frombuffer(blob, np.uint8),
                                cv2.IMREAD_COLOR)

        # What the document is actually handed, not what build() drew: the
        # face reaches the page through jpeg_bytes(), and a test that skips
        # that step cannot tell whether the page is getting this face at all.
        drawn = cost(decoded(sample_face.jpeg_bytes()))
        cartoon = cost(decoded(
            (settings.BASE_DIR / "static" / "mock-face.png").read_bytes()))
        self.assertGreater(drawn, cartoon)
        self.assertGreaterEqual(drawn, 3508)
        self.assertLessEqual(drawn, 4884)



class UpstreamTraceTest(TestCase):
    """What the app asked eVerify, carried back to the page that asked.

    An upstream refusal of the identity lookup must not read as a liveness
    failure: by then liveness has already succeeded and handed back a session
    id, so the page is told which call was refused and what eVerify said.
    """

    UNAUTHORIZED = ('{"error":"unauthorized","message":"Unauthorized.",'
                    '"error_description":"Unauthorized."}')
    UNAUTHENTICATED = ('{"error":"unauthorized","message":"Unauthenticated.",'
                       '"error_description":"Unauthenticated."}')
    TOKEN = "TOKEN-that-must-never-be-echoed"
    SECRET = "SECRET-that-must-never-be-echoed"

    def setUp(self):
        self.user = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="VIC1234", given_name="Victim",
            last_name="User")

    def _upstream(self, query_body=UNAUTHORIZED, query_status=401):
        def post(url, **kwargs):
            resp = MagicMock()
            if url.endswith("/auth"):
                resp.status_code = 200
                resp.text = '{"data":{"access_token":"%s"}}' % self.TOKEN
                resp.json.return_value = {
                    "data": {"access_token": self.TOKEN}}
                return resp
            resp.status_code = query_status
            resp.text = query_body
            resp.json.return_value = json.loads(query_body)
            return resp
        return post

    def _post(self, **kwargs):
        patches = (
            patch("verify.views.everify.EVERIFY_CLIENT_ID", "client-id"),
            patch("verify.views.everify.EVERIFY_CLIENT_SECRET", self.SECRET),
            patch("verify.views.everify.requests.post",
                  side_effect=self._upstream(**kwargs)),
        )
        for one in patches:
            one.start()
        self.addCleanup(lambda: [one.stop() for one in patches])
        return self.client.post(
            "/everify/",
            data=json.dumps({"value": "1111222233334444",
                             "face_liveness_session_id": "sess"}),
            content_type="application/json")

    # -- the trace ---------------------------------------------------------

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_trace_names_the_client_the_auth_and_the_query(self):
        """All three, because the first question in any eVerify failure is
        which of the two clients was used, and the second is whether it got a
        token before it was refused."""
        resp = self._post()
        self.assertEqual(resp.status_code, 401)
        body = json.loads(resp.content)
        steps = {step["step"]: step for step in body["trace"]}
        self.assertEqual(set(steps), {"client", "auth", "query"})
        # Signed out, so this is the SITE client -- the one that signs
        # operators in, not an organization's.
        self.assertIn("site client", steps["client"]["detail"])
        self.assertEqual(steps["auth"]["status"], 200)
        self.assertEqual(steps["query"]["status"], 401)
        self.assertIn("Unauthorized.", steps["query"]["body"])
        self.assertIn("attempt 1 of 3", steps["query"]["detail"])

    @override_settings(DEBUG=False, EVERIFY_DEBUG_CAPTURE=False)
    def test_a_deployment_that_is_not_debugging_gets_no_trace(self):
        """A production operator must not be shown eVerify's URLs and raw
        error bodies in a modal. Same switch as the response store."""
        resp = self._post()
        self.assertEqual(resp.status_code, 401)
        self.assertNotIn("trace", json.loads(resp.content))

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_trace_never_carries_a_credential(self):
        """A bearer token in a JSON response to a browser would be a
        credential leak wearing a diagnostic hat. The token is COUNTED, and
        the client secret is not in here at any length."""
        resp = self._post()
        text = resp.content.decode()
        self.assertNotIn(self.TOKEN, text)
        self.assertNotIn(self.SECRET, text)
        steps = {step["step"]: step for step in json.loads(text)["trace"]}
        self.assertIn(str(len(self.TOKEN)), steps["auth"]["detail"])

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_only_a_failed_call_records_its_body(self):
        """A 200's body is the person. The auth step succeeded, so it carries
        a count and no body; the query failed, so it carries what was said."""
        body = json.loads(self._post().content)
        steps = {step["step"]: step for step in body["trace"]}
        self.assertNotIn("body", steps["auth"])
        self.assertIn("body", steps["query"])

    # -- saying which 401 it is -------------------------------------------

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_two_401s_are_told_apart(self):
        """eVerify answers 401 for two different things and the difference is
        the whole diagnosis. Measured against the live service: a request
        with no bearer and one with a junk bearer both say "Unauthenticated";
        a real token on a client that may not query says "Unauthorized".

        Told apart by the `message` field and NOT by a substring of the body:
        BOTH carry "error":"unauthorized", so matching anywhere in the text
        would call every refusal a credentials problem."""
        refused = json.loads(self._post().content)["message"]
        self.assertIn("refused the lookup", refused)
        self.assertIn("not entitled", refused)

        self.client = self.client_class()
        rejected = json.loads(
            self._post(query_body=self.UNAUTHENTICATED).content)["message"]
        self.assertIn("did not accept our credentials", rejected)
        self.assertNotEqual(refused, rejected)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_message_field_decides_and_not_the_whole_body(self):
        """A body whose `error` disagrees with its `message`.

        On the two bodies eVerify actually sends, matching anywhere in the
        text happens to give the same answer, but only while `error` agrees
        with `message` and while the hints are searched in one particular
        order. `message` is the field that carries the distinction, so that
        is the field to read."""
        body = json.loads(self._post(query_body=(
            '{"error":"unauthenticated","message":"Unauthorized.",'
            '"error_description":"Unauthorized."}')).content)
        self.assertIn("refused the lookup", body["message"])
        self.assertNotIn("did not accept our credentials", body["message"])

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_any_other_status_keeps_the_plain_wording(self):
        """The hint is for the one status that means two things. Inventing an
        explanation for the rest would be the renaming-a-fault mistake in the
        other direction."""
        body = json.loads(self._post(query_body='{"message":"boom"}',
                                     query_status=503).content)
        self.assertIn("503", body["message"])


class UpstreamTraceUiTest(TestCase):
    """The two pages that call /everify/, and the one renderer they share."""

    def setUp(self):
        SiteSettings.objects.update_or_create(
            pk=1, defaults={"login_mode": "everify"})

    def test_the_login_page_reads_the_body_on_a_non_2xx(self):
        """It threw the body away and showed the status number, so the
        server's own explanation never reached the screen. That is what made
        an upstream refusal look like a liveness failure."""
        page = self.client.get("/").content.decode()
        self.assertNotIn("if (!r.ok) throw new Error('Server returned '",
                         page)
        # The CONDITION, not merely the handler's text.
        self.assertIn("if (!r.ok) {", page)
        self.assertIn("err.handled = true", page)
        self.assertIn("body.message", page)

    def test_both_pages_render_a_trace_through_the_same_function(self):
        """Two implementations of one renderer would drift, and one of the
        two would be the one nobody looked at."""
        login = self.client.get("/").content.decode()
        self.assertIn("renderUpstreamTrace", login)
        self.assertIn('id="error-trace"', login)

        user = User.objects.create(
            national_id_card_number="2222333344445555",
            digital_national_id="OPR1234", given_name="Op", last_name="Er")
        org = Organization.objects.create(name="Org", everify_client_id="x",
                                          everify_client_secret="y")
        Membership.objects.create(organization=org, user=user,
                                  role=Membership.ROLE_OPERATOR)
        session = self.client.session
        session[SESSION_KEY] = user.id
        session[ORG_SESSION_KEY] = org.id
        session.save()
        verify = self.client.get("/app/").content.decode()
        self.assertIn("renderUpstreamTrace", verify)
        self.assertIn('id="verify-trace"', verify)

    def test_the_trace_is_built_with_text_not_markup(self):
        """Every line of it is a response body from a service this app does
        not control, and the Verify page's own showStatus() writes innerHTML
        -- which is exactly why the trace is rendered beside the status box
        instead of being folded into the message."""
        source = (settings.BASE_DIR / "templates" / "includes"
                  / "upstream_trace.html").read_text(encoding="utf-8")
        # The comment above the code says the word, so read the code.
        code = source.split("{% endcomment %}", 1)[-1]
        self.assertIn("textContent", code)
        self.assertNotIn("innerHTML", code)



class CardHandoffTest(TestCase):
    """The finished verification, handed to the holder's own phone.

    The document page draws a QR beside Print Document; the phone scans it,
    draws the portrait card and saves it to Photos. Two properties carry the
    whole feature, and they pull in opposite directions:

    **The phone has no session and cannot get one.** It is a member of the
    public's handset, not an operator's. So the token in the path IS the
    authorisation, and this is the one endpoint in the app that serves an
    identity unauthenticated -- unlike the revocation feed, whose payload is
    opaque 16-bit fingerprints with nothing in it to protect.

    **Which is exactly why it is short-lived.** Unguessable, five minutes,
    released the moment the operator leaves the document, purged when
    expired, and never listed anywhere. The steady state of `card_handoffs`
    is empty.

    Everything ON the card is chosen in the view that had a session: which
    organization, which fields, and whether the operator is presenting. The
    phone draws what it is given and chooses nothing.
    """

    ROWS = [
        {"field": "first_name", "key": "Given Name", "value": "JUAN",
         "show": True},
        {"field": "middle_name", "key": "Middle Name", "value": "SANTOS",
         "show": True},
        {"field": "last_name", "key": "Last Name", "value": "DELA CRUZ",
         "show": True},
        {"field": "reference", "key": "National ID Card Number",
         "value": "1111-2222-3333-4444", "show": True},
        {"field": "code", "key": "Digital National ID Number",
         "value": "ABC1234", "show": True},
    ]

    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        credential_keys.reset_caches()
        self.addCleanup(credential_keys.reset_caches)

        self.org = make_org(name="Philippine Statistics Authority")
        self.location = self.org.locations.first()
        self.user = User.objects.create(
            national_id_card_number="1111222233334444", given_name="Ada",
            last_name="Lovelace")
        join(self.org, self.user, Membership.ROLE_ADMIN)
        self.type = TransactionType.objects.create(
            organization=self.org, name="New Enrollment")

        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.pem = os.path.join(self.dir, "issuer.pem")
        key = ec.generate_private_key(ec.SECP256R1())
        with open(self.pem, "wb") as handle:
            handle.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        os.chmod(self.pem, stat.S_IRUSR | stat.S_IWUSR)

        session = self.client.session
        session[SESSION_KEY] = self.user.id
        session[ORG_SESSION_KEY] = self.org.id
        session["operator_location"] = str(self.location.id)
        session.save()

    def _configured(self, **extra):
        kwargs = dict(CREDENTIAL_ISSUER_KEY_PATH=self.pem,
                      CREDENTIAL_ISSUER_KEY_ID=1,
                      CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX)
        kwargs.update(extra)
        return override_settings(**kwargs)

    def _log(self, rows=None):
        rows = rows if rows is not None else self.ROWS
        keep_answer(self.client, self.org, rows)
        return json.loads(self.client.post(
            "/everify/log-transaction/",
            data=json.dumps({
                "transaction_type": str(self.type.id),
                "verification_data": rows}),
            content_type="application/json").content)

    def _open(self, rows=None):
        """Log a verification and return (response body, the stored payload)."""
        with self._configured():
            body = self._log(rows)
        self.assertIn("handoff_token", body)
        row = CardHandoff.objects.get(token=body["handoff_token"])
        return body, row.payload

    def _demo(self, on=True):
        UserSettings.objects.update_or_create(user=self.user,
                                              defaults={"demo_mode": on})

    # -- opening one -------------------------------------------------------

    def test_logging_a_verification_opens_a_hand_off(self):
        body, payload = self._open()
        self.assertEqual(CardHandoff.objects.count(), 1)
        self.assertEqual(payload["holder"], "JUAN SANTOS DELA CRUZ")
        self.assertEqual(payload["organization"],
                         "Philippine Statistics Authority")
        self.assertEqual(payload["transaction_type"], "New Enrollment")
        self.assertEqual(payload["transaction_id"], body["transaction_id"])

    def test_the_url_is_built_from_the_route_and_is_https(self):
        """`reverse()`, so moving the path cannot strand a QR somebody is
        looking at, and https because the phone connects over it or not at
        all -- the same rule the device pairing QR follows."""
        body, _ = self._open()
        self.assertTrue(body["handoff_url"].startswith("https://"))
        self.assertTrue(body["handoff_url"].endswith(
            reverse("card_handoff", args=[body["handoff_token"]])))

    def test_the_card_carries_both_symbol_payloads(self):
        """The card IS the two symbols. The credential still begins with the
        transaction UUID, so a plain camera reads what it always read."""
        body, payload = self._open()
        self.assertTrue(
            payload["qr"].startswith(body["transaction_id"].upper()))
        self.assertIn(":CL03:", payload["qr"])

    def test_no_credential_means_no_hand_off(self):
        """A card with nothing offline on it is the card the document already
        declines to print, so there is nothing to send to a phone either."""
        body = self._log()                      # no issuer key configured
        # Logged -- or a refusal would pass every assertion below.
        self.assertEqual(body["status"], "ok")
        self.assertNotIn("qr", body)
        self.assertNotIn("handoff_url", body)
        self.assertEqual(CardHandoff.objects.count(), 0)

    # -- fetching one ------------------------------------------------------

    def test_the_phone_needs_no_session(self):
        """The whole point: this is a member of the public's handset, and it
        has no account here."""
        body, _ = self._open()
        stranger = self.client_class()          # no session at all
        response = stranger.get(
            reverse("card_handoff", args=[body["handoff_token"]]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "DELA CRUZ")

    def test_the_page_is_never_cached_or_indexed(self):
        """It is an identity, on a link that is about to stop working."""
        body, _ = self._open()
        response = self.client.get(
            reverse("card_handoff", args=[body["handoff_token"]]))
        self.assertIn("no-store", response["Cache-Control"])
        self.assertIn("noindex", response["X-Robots-Tag"])

    def test_the_values_travel_as_json_not_as_markup(self):
        """The payload is somebody's name and their transaction type. A quote
        in one of them interpolated into a script would end the statement --
        the same reason the sample Validate page uses json_script."""
        source = (settings.BASE_DIR / "templates"
                  / "card.html").read_text(encoding="utf-8")
        self.assertIn("json_script", source)

    # -- and losing one ----------------------------------------------------

    def test_leaving_the_document_releases_it(self):
        body, _ = self._open()
        token = body["handoff_token"]
        self.assertEqual(self.client.post(
            reverse("card_handoff_release", args=[token])).status_code, 200)
        self.assertEqual(CardHandoff.objects.count(), 0)
        self.assertEqual(self.client.get(
            reverse("card_handoff", args=[token])).status_code, 404)

    def test_the_release_beacon_needs_no_csrf_token(self):
        """`navigator.sendBeacon()` cannot set a CSRF header, and it is what
        still fires when the tab is closing -- which is the moment this has to
        work. What the exemption exposes is a caller DESTROYING a hand-off it
        already knows the token of, and anyone holding that token could fetch
        the card instead."""
        body, _ = self._open()
        strict = self.client_class(enforce_csrf_checks=True)
        response = strict.post(
            reverse("card_handoff_release", args=[body["handoff_token"]]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(CardHandoff.objects.count(), 0)

    def test_an_expired_hand_off_is_refused_and_dropped(self):
        body, _ = self._open()
        CardHandoff.objects.update(
            expires_at=timezone.now() - datetime.timedelta(seconds=1))
        self.assertEqual(self.client.get(
            reverse("card_handoff", args=[body["handoff_token"]])
        ).status_code, 404)
        self.assertEqual(CardHandoff.objects.count(), 0)

    def test_expired_released_and_never_existed_are_one_answer(self):
        """Telling them apart tells somebody feeding in guesses which ones
        were real -- the rule `devices.TICKET_REFUSED` already follows."""
        body, _ = self._open()
        live = reverse("card_handoff", args=[body["handoff_token"]])
        never = reverse("card_handoff", args=[uuid.uuid4()])
        self.assertEqual(self.client.get(never).status_code, 404)
        self.client.post(
            reverse("card_handoff_release", args=[body["handoff_token"]]))
        self.assertEqual(self.client.get(live).status_code, 404)

    def test_a_malformed_token_never_reaches_a_query(self):
        """Filtering a UUID column by junk RAISES rather than matching
        nothing -- which is how `/api/v1/device/keys/` once answered a
        malformed id with a 500. The route takes a uuid, so a malformed one
        does not match at all."""
        self.assertEqual(self.client.get("/card/not-a-uuid/").status_code, 404)

    def test_opening_one_purges_the_ones_nobody_collected(self):
        """This table is a hand-off, not a record. Past its expiry a row can
        never be served again, so holding the identity in it buys nothing."""
        stale = CardHandoff.objects.create(
            payload={"holder": "SOMEBODY ELSE"},
            expires_at=timezone.now() - datetime.timedelta(minutes=1))
        self._open()
        self.assertFalse(
            CardHandoff.objects.filter(token=stale.token).exists())

    # -- what may be on it -------------------------------------------------

    def test_it_cannot_carry_a_field_the_organization_does_not_display(self):
        """Resolved from the organization's own configuration, never from the
        rows' own "show" flag -- the same rule that decides what is logged.
        The card is a copy of the document, so it must not be able to print a
        field the document does not."""
        OrganizationFieldSetting.objects.update_or_create(
            organization=self.org, key="middle_name",
            defaults={"show_on_document": False, "include_in_log": False,
                      "position": 1})
        _, payload = self._open()
        self.assertEqual(payload["holder"], "JUAN DELA CRUZ")
        self.assertNotIn("SANTOS", payload["holder"])

    def test_the_browser_cannot_add_a_field_by_asking(self):
        """A row claiming `show` on a field this organization has switched
        off changes nothing: the display set is resolved here."""
        OrganizationFieldSetting.objects.update_or_create(
            organization=self.org, key="code",
            defaults={"show_on_document": False, "include_in_log": False,
                      "position": 4})
        _, payload = self._open()
        self.assertEqual(payload["digital_id"], "")
        self.assertEqual(payload["card_number"], "1111-2222-3333-4444")

    # -- Demo Mode ---------------------------------------------------------

    def test_a_demo_hand_off_carries_the_masked_values(self):
        """The card follows the DOCUMENT, exactly as the credential does. A
        photo saved off a masked page must not be the unmasked one -- it is
        the same leak the credential had, one screen further on."""
        self._demo(True)
        _, payload = self._open()
        self.assertIn(DEMO_MASK_CHAR, payload["holder"])
        self.assertNotIn("SANTOS", payload["holder"])
        self.assertIn(DEMO_MASK_CHAR, payload["card_number"])
        self.assertTrue(payload["card_number"].endswith("4"))

    def test_demo_mode_is_read_from_the_operator_not_the_request(self):
        """The browser composes the request that opens the hand-off. A page
        that could tell the server to redact could tell it not to."""
        self._demo(True)
        keep_answer(self.client, self.org, self.ROWS)
        with self._configured():
            body = json.loads(self.client.post(
                "/everify/log-transaction/",
                data=json.dumps({
                    "transaction_type": str(self.type.id),
                    "demo_mode": False,     # ignored, and this pins that
                    "verification_data": self.ROWS}),
                content_type="application/json").content)
        payload = CardHandoff.objects.get(token=body["handoff_token"]).payload
        self.assertIn(DEMO_MASK_CHAR, payload["holder"])

    FACE_ROW = {"field": "face_url", "key": "Face Photo", "show": True}

    def _face_rows(self):
        return self.ROWS + [dict(self.FACE_ROW, value=(
            "data:image/png;base64," + base64.b64encode(
                (settings.BASE_DIR / "static" / "mock-face.png").read_bytes()
            ).decode()))]

    def test_the_face_on_the_card_is_the_one_the_symbol_carries(self):
        """Deliberately the rendered portrait and not a second render of the
        upstream photo: it is already grayscale, already resampled when the
        operator is presenting, and already bound to this credential by
        `portrait_hash`. A second face would be a second thing to keep in step
        with Demo Mode -- which is how the credential came to carry an
        unmasked one."""
        _, payload = self._open(self._face_rows())
        self.assertTrue(payload["face"].startswith("data:image/webp;base64,"))
        self.assertTrue(payload["portrait_qr"].startswith("CL03F1:"))

    def test_the_handoff_stores_when_the_credential_lapses(self):
        """For the Wallet pass's expirationDate: the value a holder's pass
        carries, in the same spelling, read off the same issuance."""
        _, payload = self._open()
        issued = IssuedCredential.objects.get()
        self.assertEqual(payload["expires_at"], issued.expires_at.isoformat())

    def test_an_avif_face_reaches_the_card_as_the_symbols_own_picture(self):
        """With PORTRAIT_FORMAT=avif the symbol carries the compact form and
        the card draws the same picture inside the container -- one face, two
        wrappings, never a second render."""
        from accounts import portrait_avif
        from ovcrypto import base45

        if not portrait_avif.available():
            self.skipTest("Pillow without AVIF support")
        with override_settings(PORTRAIT_FORMAT="avif"):
            _, payload = self._open(self._face_rows())
        self.assertTrue(payload["portrait_qr"].startswith("CL03F2:"))
        self.assertTrue(payload["face"].startswith("data:image/avif;base64,"))
        compact = base45.decode(payload["portrait_qr"].split(":", 2)[2])
        self.assertEqual(base64.b64decode(payload["face"].split(",", 1)[1]),
                         portrait_avif.expand(compact))

    def test_a_demo_card_does_not_carry_the_real_face(self):
        _, clear = self._open(self._face_rows())
        CardHandoff.objects.all().delete()
        self._demo(True)
        _, masked = self._open(self._face_rows())
        self.assertTrue(masked["face"].startswith("data:image/webp;base64,"))
        self.assertNotEqual(masked["face"], clear["face"])

    # -- the two pages -----------------------------------------------------

    def test_the_document_page_shows_the_qr_and_releases_it_on_leaving(self):
        """A third control on the row that already exists. And a link
        that outlives the page it was shown on is a link nobody is watching --
        `pagehide` rather than `unload`, because it is the one that still
        fires on iOS Safari."""
        source = (settings.BASE_DIR / "templates"
                  / "document.html").read_text(encoding="utf-8")
        self.assertIn("showHandoff(resp.handoff_url, resp.handoff_token)",
                      source)
        # The CALL, not the mention.
        self.assertIn("addEventListener('pagehide'", source)
        self.assertIn("navigator.sendBeacon(url)", source)
        self.assertIn("'/card/' + handoffToken + '/release/'", source)

    def test_the_card_is_sized_for_the_worst_symbol_the_app_can_mint(self):
        """Not for a sample. 48.8 mm at the 0.4 mm floor allows at most 121
        modules -- version 26 -- for either symbol on any document at any
        field count, so nothing on this card shrinks when an organization
        switches fields on.

        A size measured against convenient sample data is wrong for the
        documents an organization actually prints."""
        from ovcrypto import qrsize

        ceiling = credentials.STAMP_MM / qrsize.MIN_MODULE_MM
        self.assertLessEqual(qrsize.modules(26), ceiling)
        self.assertGreater(qrsize.modules(27), ceiling)

        # The renderer is static/cardcanvas.js, which the document prints
        # below its cut line too. The pin follows the code: a test reading
        # card.html would pass on a page that draws nothing.
        source = (settings.BASE_DIR / "static"
                  / "cardcanvas.js").read_text(encoding="utf-8")
        self.assertIn("var MAX_MODULES = 121", source)
        self.assertIn("var SYM = MAX_MODULES * MODULE_PX", source)

    def test_the_two_symbols_read_as_one_size(self):
        """An integer module means a symbol measures `cells x unit`, so two
        symbols of different versions are different SIZES -- measured on the
        drawn canvas, a 113-module credential is 904 px of ink inside the
        same 968 box a 121-module portrait fills exactly. Side by side that
        reads as a mistake, and the document's printed card has never had it,
        because there each symbol is scaled into a fixed 48.8 mm box whatever
        its version.

        So the BOX is drawn, around both. The ink is untouched -- what
        changes is that the eye is given the square rather than the symbol."""
        # The renderer is static/cardcanvas.js, which the document prints
        # below its cut line too. The pin follows the code: a test reading
        # card.html would pass on a page that draws nothing.
        source = (settings.BASE_DIR / "static"
                  / "cardcanvas.js").read_text(encoding="utf-8")
        frame = source[source.index("function drawSymbol("):]
        frame = frame[:frame.index("function drawFace(")]
        # The frame is the BOX, not the ink: `size` would put it around the
        # symbol and bring the difference straight back.
        self.assertIn("ctx.strokeRect(x + 1, y + 1, box - 2, box - 2)", frame)
        self.assertNotIn("strokeRect(ox", frame)

    def test_that_frame_is_light_enough_to_be_quiet_zone(self):
        """A worst-case symbol FILLS its box, so the frame touches its
        modules -- and that is only safe because a quiet zone has to be free
        of DARK marks. #dfe6ec is 88% luminance, which a binariser reads as
        background exactly like the paper around it.

        Measured rather than assumed: with the frame drawn, 120 simulated
        inkjet captures decode at the same rate as without it -- 40 of 40 at
        close range, every print setting, every rotation.

        A dark rule would have had to sit four modules clear of the ink, which
        costs the card 128 px of height and moves every fit-to-screen
        figure."""
        # The renderer is static/cardcanvas.js, which the document prints
        # below its cut line too. The pin follows the code: a test reading
        # card.html would pass on a page that draws nothing.
        source = (settings.BASE_DIR / "static"
                  / "cardcanvas.js").read_text(encoding="utf-8")
        frame = source[source.index("function drawSymbol("):]
        frame = frame[:frame.index("function drawFace(")]
        self.assertIn("ctx.strokeStyle = '#dfe6ec'", frame)
        # Never the ink colour, and never the deep blues: those are marks a
        # binariser would count against the quiet zone.
        for dark in ("strokeStyle = INK", "strokeStyle = BLUE",
                     "strokeStyle = DEEP", "strokeStyle = '#000"):
            self.assertNotIn(dark, frame)

    def test_the_symbols_are_drawn_on_an_integer_module(self):
        """Otherwise every edge lands mid-pixel and the whole symbol softens
        -- the printed stamp's 0.4 mm floor, in the screen's units."""
        # The renderer is static/cardcanvas.js, which the document prints
        # below its cut line too. The pin follows the code: a test reading
        # card.html would pass on a page that draws nothing.
        source = (settings.BASE_DIR / "static"
                  / "cardcanvas.js").read_text(encoding="utf-8")
        self.assertIn("Math.floor(box / cells)", source)

    def test_the_card_asks_for_the_qr_mode_rather_than_assuming_it(self):
        """qrcode-generator defaults addData to BYTE -- and nothing about an
        uppercase payload changes that. Byte mode costs about 45% of the
        capacity, which is what put the portrait symbol past what any QR can
        hold on the document."""
        # The renderer is static/cardcanvas.js, which the document prints
        # below its cut line too. The pin follows the code: a test reading
        # card.html would pass on a page that draws nothing.
        source = (settings.BASE_DIR / "static"
                  / "cardcanvas.js").read_text(encoding="utf-8")
        self.assertIn("Alphanumeric", source)
        self.assertIn("Byte", source)

    def test_saving_goes_through_the_share_sheet_on_ios(self):
        """The only route that reaches the camera roll on iOS. An `<a
        download>` lands the file in Files, and the holder then has to find it
        and save it a second time -- which is the thing this feature exists to
        avoid. The long-press hint is the fallback when the browser will not
        take a file.
        """
        source = (settings.BASE_DIR / "templates"
                  / "card.html").read_text(encoding="utf-8")
        self.assertIn("navigator.canShare({files: [file]})", source)
        self.assertIn("navigator.share({files: [file], title:", source)
        # The fallback, pinned as the ELEMENT and the words the holder reads
        # -- "hint-longpress" alone is satisfied by a getElementById() call
        # standing over markup that no longer has one.
        self.assertIn('id="hint-longpress"', source)
        self.assertIn("Add to Photos", source)
        self.assertIn("hint.hidden = false", source)

    def test_android_saves_by_downloading_rather_than_sharing(self):
        """Android's system share sheet is a list of apps to send the file TO
        and has no save action in it at all -- on that platform saving an
        image IS a download. Chrome writes it to /Download, MediaStore indexes
        it, and the gallery lists it under the device's Download folder.

        So the share sheet is not a route to the camera roll there, and the
        card must not be routed into it.
        """
        source = (settings.BASE_DIR / "templates"
                  / "card.html").read_text(encoding="utf-8")
        self.assertIn('id="btn-download"', source)
        # The anchor is armed, and with the same filename the File gets --
        # a blob URL downloads as a uuid otherwise.
        self.assertIn("link.href = url", source)
        self.assertIn("link.download = name", source)
        self.assertIn("link.hidden = false", source)
        # ...and the Android branch RETURNS, so it can never fall through
        # into the share sheet that has nothing in it for this platform.
        android = source.split("if (androidPhone()) {", 1)[1]
        self.assertLess(android.index("return;"),
                        android.index("navigator.canShare"))

    def test_the_platform_is_tested_rather_than_the_feature(self):
        """No capability test separates the two: Chrome and Safari both answer
        yes to canShare({files}), and what differs is what the OS sheet
        CONTAINS. This is the one place in the app that reads the platform,
        and sharing is the default -- an unknown platform lands on the
        behaviour that at least reaches a sheet."""
        source = (settings.BASE_DIR / "templates"
                  / "card.html").read_text(encoding="utf-8")
        body = (source.split("function androidPhone() {", 1)[1]
                      .split("\n    }", 1)[0])
        self.assertIn("navigator.userAgentData", body)
        self.assertIn("=== 'Android'", body)
        # The user-agent string is the fallback, because userAgentData is
        # absent on every browser that is not Chromium.
        self.assertIn("/Android/i.test(navigator.userAgent", body)
        # Only Android is named. Deciding it the other way round -- test for
        # iOS, download otherwise -- would send every unrecognised handset
        # down the download path, which on iOS is the Files dead end. (The
        # word appears elsewhere in the file, in the mm-per-module
        # measurements, so this looks only at the branch itself.)
        self.assertNotIn("iPhone", body)
        self.assertNotIn("iPad", body)

    def test_both_platforms_keep_the_long_press_route(self):
        """It is the floor under both saves, and the verb differs: iOS offers
        "Add to Photos", Android offers "Download image" into the same indexed
        folder. On Android it is shown BESIDE the button rather than instead
        of it, because there it is a second real route and not a
        consolation."""
        source = (settings.BASE_DIR / "templates"
                  / "card.html").read_text(encoding="utf-8")
        self.assertIn('id="hint-longpress-android"', source)
        self.assertIn("Download image", source)
        # Shown on the Android path, where the button is showing too.
        android = source.split("if (androidPhone()) {", 1)[1]
        self.assertLess(android.index("androidHint.hidden = false"),
                        android.index("return;"))


class VerifyOutcomeScreenTest(TestCase):
    """How a verification that did not succeed ends.

    A failure must not end by clearing the form: a `401` from eVerify would
    then destroy an operator's typing as thoroughly as a genuine miss does.

    Two properties, and they are separate:

    **Two failures wear one costume.** eVerify answering "nobody" is a
    statement about the person. A 401, a 500, a dropped connection or a
    cancelled camera are statements about this deployment, made about
    somebody the service never looked at. Saying "cannot verify this person"
    after the second would be a lie, so the title, the mark, the hint and the
    primary action all follow the kind.

    **Nothing clears itself.** The outcome screen replaces the two step cards
    and stays until an operator presses Edit Details (keep everything) or
    Start Over (keep nothing). Every error box on the page carries a dismiss
    for the same reason.
    """

    def setUp(self):
        self.org = make_org(name="Alpha")
        self.operator = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="OPR1", given_name="Ada", last_name="Reyes")
        join(self.org, self.operator)
        session = self.client.session
        session[SESSION_KEY] = self.operator.id
        session[ORG_SESSION_KEY] = self.org.id
        session.save()

    def page(self):
        response = self.client.get("/app/")
        self.assertEqual(response.status_code, 200)
        return response.content.decode()

    @staticmethod
    def source():
        return (settings.BASE_DIR / "templates" / "app.html").read_text(
            encoding="utf-8")

    # ---------------------------------------------------------------- shape

    def test_the_outcome_screen_replaces_the_steps_rather_than_joining_them(self):
        """A panel under the form can be left on screen half-read while the
        next person walks up. The whole point of this shape is that the
        verification is over and the screen says so."""
        page = self.page()
        self.assertIn('id="verify-outcome"', page)
        self.assertIn('id="verify-steps"', page)
        source = self.source()
        self.assertIn("verifySteps.hidden = true;", source)
        self.assertIn("verifyOutcome.hidden = false;", source)

    def test_the_failure_modal_is_gone(self):
        """A modal says one sentence, offers OK, and can empty the form behind
        it. Two surfaces telling one story is how they come to disagree."""
        page = self.page()
        self.assertNotIn("verification-failed-overlay", page)
        self.assertNotIn("Verification Unsuccessful", page)

    def test_nothing_clears_itself_after_a_failure(self):
        """The form still holds what the operator typed. Which of Edit
        Details and Start Over happens is theirs to decide."""
        source = self.source()
        # resetApplicationState() is reached from startOver() and nowhere
        # else -- an operator action, never a failure branch.
        calls = source.count("resetApplicationState();")
        self.assertEqual(calls, 1, "reset is called from more than startOver()")
        after = source.split("function startOver() {", 1)[1]
        self.assertLess(after.index("resetApplicationState();"),
                        after.index("}"))

    def test_an_error_box_can_be_cleared_by_hand(self):
        """Every alert on this page is dismissed, never timed out."""
        source = self.source()
        self.assertIn("status-dismiss", source)
        self.assertIn("dismiss.addEventListener('click'", source)
        self.assertIn("function() { element.innerHTML = ''; }", source)

    # ----------------------------------------------------------- the kinds

    def test_a_service_error_is_not_a_statement_about_the_person(self):
        """`Unauthenticated.` means this deployment's credentials are wrong.
        Nobody was looked up, so nothing is known about the person in front
        of the operator, and the screen must not say otherwise."""
        source = self.source()
        self.assertIn("title: 'Verification could not be completed'", source)
        incomplete = source.split("incomplete: {", 1)[1].split("}", 1)[0]
        self.assertIn("person: false", incomplete)
        self.assertIn("says nothing about", source)

    def test_the_two_person_kinds_both_say_cannot_verify(self):
        """A 404 and a `verified: false` are different answers from eVerify
        and the same answer to the operator's question."""
        source = self.source()
        self.assertEqual(source.count("title: 'Cannot verify this person'"), 2)

    def test_the_kind_is_read_from_the_status_and_the_flag(self):
        """`verified: false` arrives as a 200 carrying data, so a check that
        only looked at the body would file it as a success."""
        source = self.source()
        self.assertIn("var verified = result.status !== 'error';", source)
        self.assertIn("httpStatus === 404 ? 'nomatch'", source)
        self.assertIn("!verified ? 'unverified'", source)

    def test_the_primary_action_follows_the_kind(self):
        """Retrying a `verified: false` returns the same answer, so it does
        not offer one; a 401 is worth retrying and does."""
        source = self.source()
        self.assertIn("primary.textContent = spec.person ? 'Start Over'", source)
        self.assertIn("secondary.textContent = spec.person ? 'Edit Details' "
                      ": 'Start Over';", source)

    def test_every_input_tab_gets_the_same_treatment(self):
        """The QR and Manual tabs fail the same way the demographic form
        does, and the outcome names what was actually looked up."""
        source = self.source()
        details = source.split("function fillOutcomeDetails()", 1)[1]
        details = details.split("function stampNow", 1)[0]
        # The branch has to BUILD the row, not merely exist.
        self.assertIn("rows.push(['Scanned ID', qrCodeValue || '']);", details)
        self.assertIn("rows.push(['National ID', pcnInput.value]);", details)
        self.assertIn("rows.push(['Birth Date', "
                      "document.getElementById('birth-date').value]);", details)
        hints = source.split("var OUTCOME_HINTS", 1)[1].split("};", 1)[0]
        for tab in ("demographic-tab", "pcn-tab", "qr-tab"):
            self.assertIn("'%s':" % tab, hints)

    def test_the_outcome_is_written_as_text_and_never_as_markup(self):
        """The message is a response body from a service this app does not
        control and the rows are the operator's own typing. showStatus()
        writes innerHTML; this must not."""
        source = self.source()
        body = source.split("function showOutcome(kind, info) {", 1)[1]
        body = body.split("function hideOutcome()", 1)[0]
        self.assertIn("textContent", body)
        self.assertNotIn("innerHTML", body)
        rows = source.split("function outcomeRow(label, value) {", 1)[1]
        rows = rows.split("}", 1)[0]
        self.assertIn("th.textContent = label;", rows)
        self.assertIn("td.textContent = value;", rows)

    def test_the_outcome_reports_the_biometric_that_was_SENT(self):
        """A face check the person walked away from is not a confirmed one.
        Reading the intended method rather than the sent one had the screen
        printing `Face check: Confirmed` under a cancelled camera."""
        source = self.source()
        self.assertIn("lastBiometric = payload.fingerprint ? 'fingerprint'",
                      source)
        details = source.split("function fillOutcomeDetails()", 1)[1]
        self.assertIn("lastBiometric === 'face'", details)
        self.assertNotIn("lastMethod === 'liveness'", details)


class HeldFaceCheckTest(TestCase):
    """Verifying again without putting the person back in front of the camera.

    A demographic miss is most often a typo, and the person who just passed
    the liveness check is still standing there. So the session id eVerify
    returned is held for a short window and offered back: Verify Without New
    Face Scan sends the corrected details with the same face check.

    **Reusing it is safe for the same reason sending it once is.** The
    session id is eVerify's, the server passes it through untouched, and
    eVerify decides whether it is still good and whether the face belongs to
    the record it found. Nothing here decides who anybody is -- the rule
    "the identity comes only from what the upstream returned" is
    not touched.

    **What it must never outlive is the person.** Start Over means the next
    person, and the next person's face has not been checked. That is the one
    rule this feature rests on.
    """

    @staticmethod
    def source():
        return (settings.BASE_DIR / "templates" / "app.html").read_text(
            encoding="utf-8")

    def test_start_over_drops_the_held_face_check(self):
        """The whole feature turns on this. A held check that outlived Start
        Over would let the next person be verified against the last person's
        face."""
        source = self.source()
        body = source.split("function startOver() {", 1)[1].split("}", 1)[0]
        self.assertIn("releaseLiveness();", body)

    def test_a_verified_person_releases_it_too(self):
        """They are leaving for the document; there is nothing left to reuse
        it for, and it must not be waiting when the next person steps up."""
        source = self.source()
        success = source.split("if (verified && result.data", 1)[1]
        success = success.split("showOutcome(", 1)[0]
        self.assertIn("releaseLiveness();", success)

    def test_the_reuse_does_not_open_the_camera(self):
        """That is the entire point: the check already passed."""
        source = self.source()
        body = source.split("function verifyWithHeldLiveness() {", 1)[1]
        body = body.split("verifyHeldBtn.addEventListener", 1)[0]
        self.assertIn("sendVerifyQuery(buildPayload(heldLiveness.sessionId))",
                      body)
        self.assertNotIn("eKYC", body)

    def test_it_refuses_before_it_sends_anything(self):
        source = self.source()
        body = source.split("function verifyWithHeldLiveness() {", 1)[1]
        self.assertLess(body.index("if (!canReuseFaceCheck())"),
                        body.index("sendVerifyQuery"))

    def test_the_window_expires_and_takes_the_offer_with_it(self):
        """The window is this app's own limit, not eVerify's -- nothing here
        knows when their session lapses. If theirs goes first the reused
        attempt is refused and lands on the outcome screen like any other."""
        source = self.source()
        self.assertIn("var LIVENESS_REUSE_MS = 180000;", source)
        render = source.split("function renderHeldLiveness() {", 1)[1]
        render = render.split("function resetApplicationState", 1)[0]
        self.assertIn("heldLiveness = null;", render)
        self.assertIn("heldBox.hidden = true;", render)

    def test_the_hidden_attribute_actually_hides(self):
        """`.held-liveness` sets `display: flex`. A class selector outranks the
        UA stylesheet's `[hidden] { display: none }`, so `heldBox.hidden =
        true` set a property and changed nothing that renders -- countdown
        text empty, button live, on every visit.

        The rule lives in base.html rather than beside the one class that
        tripped over it: any class setting `display` defeats the attribute
        the same way, and the next one will not announce itself either.
        """
        base = (settings.BASE_DIR / "templates" / "base.html").read_text(
            encoding="utf-8")
        self.assertIn("[hidden] { display: none !important; }", base)

    def test_the_strip_declares_a_display_that_needs_that_rule(self):
        """Why the rule cannot quietly be dropped: this is the declaration
        that outranks the UA stylesheet."""
        source = self.source()
        strip = source.split(".held-liveness {", 1)[1].split("}", 1)[0]
        self.assertIn("display: flex", strip)

    def test_the_offer_is_WITHDRAWN_when_it_cannot_be_taken_not_disabled(self):
        """A disabled button under a strip still on screen would show "Face
        check confirmed" over a control that does nothing when pressed, with
        no way to tell which of the two is broken. The offer is shown, or it
        is not there."""
        source = self.source()
        # Nothing disables it any more; visibility carries the state.
        self.assertNotIn("verifyHeldBtn.disabled", source)
        predicate = source.split("function canReuseFaceCheck() {", 1)[1]
        predicate = predicate.split("}", 1)[0]
        self.assertIn("heldLiveness", predicate)
        self.assertIn("livenessRemainingMs() > 0", predicate)
        self.assertIn("verifyDataReady()", predicate)
        # And the renderer hides the whole section on that predicate.
        render = source.split("function renderHeldLiveness() {", 1)[1]
        render = render.split("function resetApplicationState", 1)[0]
        self.assertIn("if (!canReuseFaceCheck()) {", render)
        self.assertIn("heldBox.hidden = true;", render)

    def test_readiness_is_asked_in_one_place(self):
        """The offer showing under different rules from the button inside it
        is how it came to stand over a dead one."""
        source = self.source()
        self.assertIn("function verifyDataReady() {", source)
        buttons = source.split("function updateVerificationButtonState() {",
                               1)[1].split("}", 1)[0]
        self.assertIn("var isDataReady = verifyDataReady();", buttons)
        self.assertIn("renderHeldLiveness();", buttons)

    def test_a_form_that_is_merely_incomplete_does_not_burn_the_check(self):
        """Withdrawing the offer and dropping the face check are different
        things: putting the form back in order must bring the offer back,
        and only the window running out may discard the check itself."""
        source = self.source()
        render = source.split("function renderHeldLiveness() {", 1)[1]
        render = render.split("var secs", 1)[0]
        self.assertIn("if (left <= 0) heldLiveness = null;", render)
        # Every discard in that block is guarded: no line is a bare reset.
        bare = [line for line in render.splitlines()
                if line.strip() == "heldLiveness = null;"]
        self.assertEqual(bare, [], "the face check is discarded unguarded")

    def test_pressing_a_stale_offer_never_fails_silently(self):
        """It re-renders, so the strip goes and the operator sees why."""
        source = self.source()
        body = source.split("function verifyWithHeldLiveness() {", 1)[1]
        body = body.split("lastMethod", 1)[0]
        self.assertIn("if (!canReuseFaceCheck()) { renderHeldLiveness(); return; }",
                      body)

    def test_the_offer_is_hidden_until_a_check_has_passed(self):
        org = make_org(name="Beta")
        user = User.objects.create(
            national_id_card_number="2222333344445555",
            digital_national_id="OPR2", given_name="Bea", last_name="Cruz")
        join(org, user)
        session = self.client.session
        session[SESSION_KEY] = user.id
        session[ORG_SESSION_KEY] = org.id
        session.save()
        page = self.client.get("/app/").content.decode()
        held = page.split('id="held-liveness"', 1)[1].split(">", 1)[0]
        self.assertIn("hidden", held)


class LivenessPhotoNotShownTest(TestCase):
    """The captured face does not go on the screen.

    A failure has no reason to show a face, on a screen the next person in
    the queue walks up to. A success prints the portrait on the document,
    which is where a face belongs.
    """

    def test_no_page_carries_an_element_for_it(self):
        for name in ("app.html", "base.html", "login.html"):
            source = (settings.BASE_DIR / "templates" / name).read_text(
                encoding="utf-8")
            self.assertNotIn("liveness-photo", source, name)

    def test_the_session_id_is_kept_and_the_image_is_not(self):
        """The completion handler takes the one thing a second attempt needs
        and drops the one thing that must not be displayed."""
        source = (settings.BASE_DIR / "templates" / "app.html").read_text(
            encoding="utf-8")
        handler = source.split("if (data && data.status === 'COMPLETED') {",
                               1)[1].split("} else {", 1)[0]
        self.assertIn("var sessionId = data.result.session_id;", handler)
        self.assertIn("holdLiveness(sessionId);", handler)
        self.assertNotIn("data.result.photo", handler)


class CornerNameTest(TestCase):
    """The top-right corner names whose session this is, in as few words as
    that takes: one word of the given name and the whole surname.

    Two halves, and only the first is arithmetic. The surname is never cut
    -- DELA CRUZ and DE LOS SANTOS are one surname each, and taking their
    last word alone puts a different and very common surname on the screen.
    And a given word too short to be a name is skipped, because "MA." names
    nobody; measured in letters, or the full stop makes it three and the
    rule never fires on the case it exists for.

    Everything else that carries an operator's name -- the document footer,
    the member lists, a minted credential -- is deliberately untouched.
    """

    def _user(self, given, last, middle=""):
        return User(given_name=given, middle_name=middle, last_name=last)

    def test_it_keeps_one_given_word_and_the_whole_surname(self):
        self.assertEqual(
            self._user("MARIA CLARA", "DELA CRUZ").short_name,
            "MARIA DELA CRUZ")

    def test_a_compound_surname_is_never_cut_down_to_its_last_word(self):
        """Taking the last word would rename people: DELA CRUZ -> CRUZ,
        DE LOS SANTOS -> SANTOS. Both are somebody else's surname."""
        for given, last in (("MARIA CLARA", "DELA CRUZ"),
                            ("ANGELO MIGUEL", "DE LOS SANTOS"),
                            ("MA. CRISTINA", "SANTOS-LOPEZ")):
            self.assertTrue(self._user(given, last).short_name.endswith(last),
                            f"{given} {last}")

    def test_a_single_word_given_name_is_left_alone(self):
        self.assertEqual(self._user("JOSE", "RIZAL").short_name, "JOSE RIZAL")

    def test_a_given_word_too_short_to_be_a_name_gives_way(self):
        """The next word that IS long enough, not merely the second one --
        "MA. T. CRISTINA" would otherwise land back on the abbreviation."""
        self.assertEqual(self._user("MA. CRISTINA", "REYES").short_name,
                         "CRISTINA REYES")
        self.assertEqual(self._user("MA CRISTINA", "REYES").short_name,
                         "CRISTINA REYES")
        self.assertEqual(self._user("MA. T. CRISTINA", "REYES").short_name,
                         "CRISTINA REYES")

    def test_the_length_is_counted_in_letters_not_characters(self):
        """"MA." is three characters and two letters. Counting characters
        keeps it, which is the one case the rule was added for."""
        self.assertEqual(len("MA."), 3)
        self.assertEqual(self._user("MA. CRISTINA", "REYES").short_name,
                         "CRISTINA REYES")

    def test_a_long_enough_first_word_wins_over_a_later_one(self):
        self.assertEqual(self._user("JUAN PAULO", "REYES").short_name,
                         "JUAN REYES")

    def test_a_word_that_is_kept_is_rendered_as_it_is_stored(self):
        """Measuring is not rewriting: the punctuation stays on the page."""
        self.assertEqual(self._user("MA. T.", "REYES").short_name,
                         "MA. REYES")

    def test_all_short_still_names_somebody_rather_than_nobody(self):
        self.assertEqual(self._user("J. P.", "REYES").short_name,
                         "J. REYES")

    def test_a_missing_half_leaves_no_stray_space(self):
        self.assertEqual(self._user("", "CRUZ").short_name, "CRUZ")
        self.assertEqual(self._user("ANNA", "").short_name, "ANNA")

    def test_the_middle_name_is_not_in_it(self):
        user = self._user("MARIA CLARA", "DELA CRUZ", middle="SANTOS")
        self.assertNotIn("SANTOS", user.short_name)

    def test_the_record_names_are_untouched(self):
        """short_name is the badge; these are the record, and the document
        footer, the member lists and a credential still carry them."""
        user = self._user("MARIA CLARA", "DELA CRUZ", middle="SANTOS")
        self.assertEqual(user.full_name, "MARIA CLARA DELA CRUZ")
        self.assertEqual(user.display_name, "MARIA CLARA SANTOS DELA CRUZ")


class CornerNameOnThePageTest(TestCase):
    """The corner actually renders the short name, and Demo Mode still
    redacts it -- asserted through a rendered page, because a property
    nothing reads is not a corner name."""

    def setUp(self):
        self.user = User.objects.create(
            national_id_card_number="1212343456567878",
            given_name="MARIA CLARA", middle_name="SANTOS",
            last_name="DELA CRUZ")
        self.org = make_org("Corner Org")
        join(self.org, self.user, Membership.ROLE_OPERATOR)
        session = self.client.session
        session[SESSION_KEY] = self.user.id
        session[ORG_SESSION_KEY] = self.org.id
        session.save()

    def _demo(self, on):
        row, _ = UserSettings.objects.get_or_create(user=self.user)
        row.demo_mode = on
        row.save()

    def _corner(self):
        response = self.client.get(reverse("app"))
        self.assertEqual(response.status_code, 200)
        page = response.content.decode()
        return page.split('class="user-name">', 1)[1].split("<", 1)[0]

    def test_the_corner_shows_the_short_name(self):
        self.assertEqual(self._corner().strip(), "MARIA DELA CRUZ")

    def test_the_full_name_is_not_in_the_corner(self):
        self.assertNotIn("MARIA CLARA", self._corner())

    def test_demo_mode_still_keeps_only_the_first_word(self):
        """The trim runs first and keeps a first word, so the mask has one
        to keep."""
        self._demo(True)
        corner = self._corner().strip()
        self.assertTrue(corner.startswith("MARIA"), corner)
        self.assertIn(DEMO_MASK_CHAR, corner)
        self.assertNotIn("DELA", corner)
        self.assertNotIn("CRUZ", corner)


class ChooseSignedInBadgeTest(TestCase):
    """/choose/ renders BEFORE any organization is picked, and its
    "Signed in as" line is the same badge the nav corner carries once a
    context starts: session_display_name, the short name masked under the
    operator's own Demo Mode.

    Demo Mode is a property of the person (UserSettings is one row per
    user), so there is nothing to resolve per membership here: the flag
    that will govern every page after the choice is the flag that governs
    the chooser.
    """

    def setUp(self):
        self.user = User.objects.create(
            national_id_card_number="1212343456567878",
            given_name="MARIA CLARA", middle_name="SANTOS",
            last_name="DELA CRUZ")
        # Two organizations, so /choose/ actually renders the chooser
        # rather than resolving the context silently.
        for name in ("Alpha Org", "Beta Org"):
            join(make_org(name=name), self.user, Membership.ROLE_OPERATOR)
        session = self.client.session
        session[SESSION_KEY] = self.user.id
        session.save()

    def _demo(self, on):
        row, _ = UserSettings.objects.get_or_create(user=self.user)
        row.demo_mode = on
        row.save()

    def _badge(self):
        response = self.client.get("/choose/")
        self.assertEqual(response.status_code, 200)
        page = response.content.decode()
        self.assertIn("Signed in as", page)
        return page, page.split("Signed in as", 1)[1].split("&middot;")[0]

    def test_the_badge_is_the_corner_name(self):
        page, badge = self._badge()
        self.assertEqual(badge.strip(), "MARIA DELA CRUZ")

    def test_demo_mode_masks_the_badge(self):
        self._demo(True)
        page, badge = self._badge()
        self.assertTrue(badge.strip().startswith("MARIA"), badge)
        self.assertIn(DEMO_MASK_CHAR, badge)
        self.assertNotIn("DELA", badge)
        self.assertNotIn("CRUZ", badge)

    def test_the_names_are_not_rendered_separately_anywhere(self):
        """The full given name and the surname must be off the WHOLE page
        while presenting, not merely out of the badge -- rendering them
        separately again would pass a badge-only assertion."""
        self._demo(True)
        page, _ = self._badge()
        self.assertNotIn("CLARA", page)
        self.assertNotIn("DELA CRUZ", page)


class ValidateScanTest(TestCase):
    """The Validate page has to read the symbol this app prints.

    `UUID_PATTERN` must not be anchored at both ends: a document with a
    credential draws `<UUID>:CL03:<credential>`, and a scanner that tested
    the whole payload against the pattern would ignore every such card,
    silently, for the full thirty seconds, looking exactly like a camera that
    could not focus.
    """

    ROWS = [
        {"field": "first_name", "key": "Given Name", "value": "JUAN",
         "show": True},
        {"field": "last_name", "key": "Last Name", "value": "DELA CRUZ",
         "show": True},
        {"field": "reference", "key": "National ID Card Number",
         "value": "1111-2222-3333-4444", "show": True},
        {"field": "code", "key": "Digital National ID Number",
         "value": "ABC1234", "show": True},
    ]

    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        credential_keys.reset_caches()
        self.addCleanup(credential_keys.reset_caches)

        self.org = make_org(name="Philippine Statistics Authority")
        self.org.issuer_code = "PSA"
        self.org.save(update_fields=["issuer_code"])
        self.location = self.org.locations.first()
        self.user = User.objects.create(
            national_id_card_number="1111222233334444", given_name="Ada")
        join(self.org, self.user, Membership.ROLE_ADMIN)
        self.type = TransactionType.objects.create(
            organization=self.org, name="New Enrollment")

        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.pem = os.path.join(self.dir, "issuer.pem")
        key = ec.generate_private_key(ec.SECP256R1())
        with open(self.pem, "wb") as handle:
            handle.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        # The signing backend refuses a group- or world-readable issuer key,
        # deliberately -- so a fixture that does not chmod it mints nothing.
        # On Windows the check cannot fail and this passed for free; on the
        # instances it did not, and the whole class errored on a missing
        # "qr". The five other classes that write a PEM already do this.
        os.chmod(self.pem, stat.S_IRUSR | stat.S_IWUSR)

        session = self.client.session
        session[SESSION_KEY] = self.user.id
        session[ORG_SESSION_KEY] = self.org.id
        session["operator_location"] = str(self.location.id)
        session.save()

    def _page(self):
        page = self.client.get("/validate/")
        self.assertEqual(page.status_code, 200)
        return page.content.decode()

    def _minted(self):
        from accounts import sample_face

        rows = list(self.ROWS) + [
            {"field": "face_url", "key": "Face Photo",
             "value": sample_face.data_uri(drawn=True), "show": True}]
        keep_answer(self.client, self.org, rows)
        with override_settings(CREDENTIAL_ISSUER_KEY_PATH=self.pem,
                               CREDENTIAL_ISSUER_KEY_ID=1,
                               CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX):
            body = json.loads(self.client.post(
                "/everify/log-transaction/",
                data=json.dumps({"transaction_type": str(self.type.id),
                                 "verification_data": rows}),
                content_type="application/json").content)
        self.assertEqual(body["status"], "ok")
        return body

    # -- what the page reads ---------------------------------------------

    def test_the_scanner_reads_the_id_out_of_a_credential_payload(self):
        """`<UUID>:CL03:<credential>` -- the id first, which is the whole
        reason the credential was appended rather than substituted.

        Split on the first separator, and what precedes it still has to look
        like a UUID before it is sent anywhere."""
        page = self._page()
        self.assertIn("CREDENTIAL_SEPARATOR = ':CL03:'", page)
        self.assertIn("function transactionIdFrom(", page)
        scan = page[page.index("function scanFrame("):]
        scan = scan[:scan.index("btnStartScan.addEventListener")]
        self.assertIn("transactionIdFrom(data)", scan)
        self.assertIn("lookupTransaction(transactionId)", scan)
        self.assertNotIn("UUID_PATTERN.test(data)", scan)
        # And what precedes the separator is CHECKED, not merely taken: a
        # parser that returns anything at all before the separator would send
        # whatever a stranger's QR happened to carry to the lookup.
        parser = page[page.index("function transactionIdFrom("):]
        parser = parser[:parser.index("function isFaceSymbol(")]
        self.assertIn("UUID_PATTERN.test(text.slice(0, at))", parser)
        # The FIRST separator: Base45 can spell it by chance.
        self.assertIn("text.indexOf(CREDENTIAL_SEPARATOR)", parser)

    def test_a_bare_uuid_still_scans(self):
        """A document with no credential draws one, and did before any of
        this existed."""
        page = self._page()
        parser = page[page.index("function transactionIdFrom("):]
        parser = parser[:parser.index("function isFaceSymbol(")]
        self.assertIn("if (UUID_PATTERN.test(text)) { return text; }", parser)

    def test_the_face_symbol_says_which_square_to_scan(self):
        """The card carries two symbols the same size, so the wrong one is an
        easy thing to point a camera at. The face symbol names the credential
        rather than the transaction, so there is nothing here to look up --
        and a scanner that ignores it looks broken."""
        page = self._page()
        # Both markers: CL03F1 carries the face as WebP and CL03F2 as AVIF, and a
        # scanner that knew only one would hunt silently at the other.
        self.assertIn("PORTRAIT_PREFIXES = ['CL03F1:', 'CL03F2:']", page)
        self.assertIn("function isFaceSymbol(", page)
        scan = page[page.index("function scanFrame("):]
        scan = scan[:scan.index("btnStartScan.addEventListener")]
        self.assertIn("isFaceSymbol(data)", scan)
        self.assertIn("That is the photo symbol", scan)
        body = page[page.index("function isFaceSymbol("):]
        body = body[:body.index("}")]
        self.assertIn("PORTRAIT_PREFIXES.some(", body)
        self.assertIn("return text.indexOf(prefix) === 0;", body)
        # showStatus writes innerHTML, so only fixed strings of ours may
        # reach it -- never anything that was scanned.
        self.assertNotIn("+ data", scan)

    # -- what the scan then asks for -------------------------------------

    def test_the_api_answers_for_the_uppercase_id_the_symbol_carries(self):
        """The credential symbol is encoded in ALPHANUMERIC mode, whose
        charset is uppercase only, so the id read off a card comes back
        `AAEA5BF5-...` and not `aaea5bf5-...`.

        A fix that parsed the payload and stopped there would have swapped a
        silent no-op for "Transaction not found" on a perfectly good
        document."""
        body = self._minted()
        lower = body["transaction_id"]
        self.assertRegex(lower, r"^[0-9a-f-]+$")
        for spelling in (lower, lower.upper()):
            answer = self.client.get("/api/validate/%s/" % spelling)
            self.assertEqual(answer.status_code, 200, spelling)
            self.assertEqual(json.loads(answer.content)["status"], "found",
                             "the id as the card spells it: %s" % spelling)

    def test_the_symbol_the_document_draws_carries_that_id_first(self):
        """The property the parser rests on, asserted where it is produced
        rather than assumed in a browser."""
        body = self._minted()
        self.assertTrue(
            body["qr"].startswith(body["transaction_id"].upper() + ":CL03:"),
            body["qr"][:80])
        self.assertTrue(body["portrait_qr"].startswith("CL03F1:"))


class WalletPassTest(TestCase):
    """The Apple Wallet pass builder.

    What is pinned here is the two ways a pass is silently rejected by a
    handset, both of which cost a round trip to a phone to discover
    otherwise.
    """

    @staticmethod
    def _throwaway_certificate():
        """A self-signed pair, so the signing path can be exercised offline."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes as h
        from cryptography.hazmat.primitives import serialization as s
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Pass")])
        now = timezone.now()
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .sign(key, h.SHA256()))
        return (cert.public_bytes(s.Encoding.PEM),
                key.private_bytes(s.Encoding.PEM,
                                  s.PrivateFormat.TraditionalOpenSSL,
                                  s.NoEncryption()))

    def _build(self):
        from accounts import wallet_pass

        cert_pem, key_pem = self._throwaway_certificate()
        pass_json = wallet_pass.build_pass_json(
            pass_type_id="pass.test", team_id="ABCDE12345", serial="abc-123",
            organization_name="Org", description="Test",
            barcode_message="aaea5bf5-1d4c:CL03:ABC", holder="LISA ROSE CRUZ",
            card_number="0000-1111-2222-3333", digital_id="SMP0001",
            transaction_type="Type", location="Window 3",
            verified_at="04/09/2026")
        blob = wallet_pass.build(
            pass_json, {"icon.png": b"\x89PNG\r\n\x1a\nnot-really"},
            certificate_pem=cert_pem, private_key_pem=key_pem,
            wwdr_pem=cert_pem)
        return zipfile.ZipFile(BytesIO(blob))

    def test_the_signature_covers_the_manifest_byte_for_byte(self):
        """`Binary` off means S/MIME rewrites the newlines before signing.

        The digest then covers bytes that are not the bytes in the zip, and
        the pass will not add -- with no message on the device saying so. The
        signed digest is checked here rather than the option, because an
        option asserted by name proves nothing about what was signed.
        """
        import hashlib

        archive = self._build()
        manifest = archive.read("manifest.json")
        signature = archive.read("signature")

        self.assertIn(hashlib.sha256(manifest).digest(), signature,
                      "the signature does not cover the manifest as stored")
        self.assertNotIn(
            hashlib.sha256(manifest.replace(b"\n", b"\r\n")).digest(),
            signature,
            "the manifest was canonicalised before signing -- pass Binary")

    def test_every_file_in_the_pass_is_in_the_manifest(self):
        archive = self._build()
        manifest = json.loads(archive.read("manifest.json"))
        listed = set(archive.namelist()) - {"manifest.json", "signature"}
        self.assertEqual(listed, set(manifest))
        for name, digest in manifest.items():
            self.assertEqual(
                __import__("hashlib").sha1(archive.read(name)).hexdigest(),
                digest, name)

    def test_a_pass_without_an_icon_is_refused_here_not_on_the_phone(self):
        from accounts import wallet_pass

        cert_pem, key_pem = self._throwaway_certificate()
        with self.assertRaises(ValueError):
            wallet_pass.build(
                {"formatVersion": 1}, {"logo.png": b"x"},
                certificate_pem=cert_pem, private_key_pem=key_pem,
                wwdr_pem=cert_pem)

    def test_no_pass_carries_a_header(self):
        """No header: there is one pass, so nothing to tell apart."""
        from accounts import wallet_pass

        built = wallet_pass.build_pass_json(
            pass_type_id="pass.test", team_id="T", serial="s",
            organization_name="Org", description="d",
            barcode_message="A:CL03:B", holder="H", card_number="",
            digital_id="", transaction_type="", location="", verified_at="")
        self.assertNotIn("headerFields", built["generic"])

    def test_the_barcode_message_is_uppercased(self):
        """Lowercase drops the symbol into byte mode, at about 45% less
        capacity -- the rule `drawQR()` already follows on the document."""
        from accounts import wallet_pass

        built = wallet_pass.build_pass_json(
            pass_type_id="pass.test", team_id="T", serial="s",
            organization_name="Org", description="d",
            barcode_message="aaea5bf5-1d4c-4e3b:cl03:abc", holder="H",
            card_number="", digital_id="", transaction_type="",
            location="", verified_at="")
        message = built["barcodes"][0]["message"]
        self.assertEqual(message, message.upper())
        self.assertEqual(built["barcodes"][0]["format"], "PKBarcodeFormatQR")

    def test_the_sizing_report_answers_in_modules_and_millimetres(self):
        """The report is the whole reason the demo exists: whether a
        credential-length payload is legible from a wallet screen."""
        from accounts import wallet_pass
        from accounts.management.commands import make_wallet_pass

        payload = make_wallet_pass.synthetic_payload()
        self.assertEqual(len(payload), make_wallet_pass.WORST_CASE_CHARS)
        self.assertEqual(wallet_pass.modules_for(payload), 113)
        self.assertIn("113 modules", wallet_pass.barcode_report(payload))
        self.assertIsNone(wallet_pass.modules_for("a" * 5000))


@override_settings(WALLET_PASS_TYPE_ID="pass.test", WALLET_TEAM_ID="ABCDE12345")
class WalletHandoffTest(TestCase):
    """The card hand-off, offered to an iPhone as ONE Apple Wallet pass.

    The pass idmanager gives a holder, exactly: the offline credential as
    its barcode and the face as its picture -- the portrait symbol's own
    image, which is what the credential's `portrait_hash` covers.
    """

    TRANSACTION_ID = "aaea5bf5-1d4c-4e3b-9c21-8b7f0a2d6e14"

    PAYLOAD = {
        "organization": "Philippine Statistics Authority",
        "holder": "LISA ROSE REYES CRUZ",
        "card_number": "0000-1111-2222-3333",
        "digital_id": "SMP0001",
        "transaction_type": "Civil registry document request",
        "location": "Window 3",
        "verified_at": "04/09/2026 10:42 AM",
        "transaction_id": TRANSACTION_ID,
        "qr": TRANSACTION_ID + ":CL03:ABC123",
        "portrait_qr": credentials.portrait_qr(
            b"not really a face", credential_id=uuid.UUID(int=7)),
        "face": "",
    }

    def setUp(self):
        cert_pem, key_pem = WalletPassTest._throwaway_certificate()
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.cert = os.path.join(self.dir, "cert.pem")
        self.key = os.path.join(self.dir, "key.pem")
        self.wwdr = os.path.join(self.dir, "wwdr.pem")
        for path, blob in ((self.cert, cert_pem), (self.key, key_pem),
                           (self.wwdr, cert_pem)):
            with open(path, "wb") as handle:
                handle.write(blob)
        self.paths = dict(WALLET_CERT_PATH=self.cert, WALLET_KEY_PATH=self.key,
                          WALLET_WWDR_PATH=self.wwdr)

    def _handoff(self, payload=None):
        return CardHandoff.objects.create(
            payload=payload if payload is not None else dict(self.PAYLOAD),
            expires_at=timezone.now() + datetime.timedelta(seconds=300))

    def _fetch(self, row):
        response = self.client.get(reverse("card_handoff_pass", args=[row.token]))
        self.assertEqual(response.status_code, 200)
        return response

    def _pass(self, row):
        """The one pass the holder gets, read the way Wallet reads it -- by
        the content type -- so anything served as a bundle fails here."""
        response = self._fetch(row)
        self.assertEqual(response["Content-Type"],
                         "application/vnd.apple.pkpass")
        return zipfile.ZipFile(BytesIO(response.content))

    @staticmethod
    def _face():
        """A real portrait symbol and the image it carries."""
        blob = credentials.render_portrait(sample_face.data_uri())
        assert blob is not None
        return credentials.portrait_qr(blob, credential_id=uuid.uuid4()), blob

    @staticmethod
    def _body(archive):
        return json.loads(archive.read("pass.json"))

    # -- whether the button exists at all ---------------------------------

    def test_an_unconfigured_deployment_offers_no_pass(self):
        """No certificate, no button -- rather than one that fails when
        pressed. The same shape the fingerprint reader and the credential
        mint already use."""
        from accounts import wallet_pass

        with override_settings(WALLET_CERT_PATH="", WALLET_KEY_PATH="",
                               WALLET_WWDR_PATH=""):
            self.assertFalse(wallet_pass.configured())
            row = self._handoff()
            page = self.client.get(reverse("card_handoff", args=[row.token]))
            # The id, not the words: the phrase also appears in a CSS comment
            # on that page, so asserting it proves nothing about the control.
            self.assertNotContains(page, 'id="btn-wallet"')
            self.assertEqual(
                self.client.get(
                    reverse("card_handoff_pass", args=[row.token])).status_code,
                404)

    def test_half_configured_is_not_configured(self):
        """The certificate files present and the Pass Type ID missing.

        Asked of the SERVICE, not through the page, and it is the case that
        distinguishes the guard from the accident: with no paths at all,
        opening the certificate fails and the pass is refused whether or not
        anything checked first. Here the files open perfectly well, so only
        `configured()` stands between an admin who filled in half the form
        and a signed pass naming nobody.
        """
        from accounts import wallet_pass

        with override_settings(WALLET_PASS_TYPE_ID="", **self.paths):
            self.assertFalse(wallet_pass.configured())
            self.assertIsNone(wallet_pass.from_handoff(dict(self.PAYLOAD)))

        with override_settings(WALLET_TEAM_ID="", **self.paths):
            self.assertFalse(wallet_pass.configured())
            self.assertIsNone(wallet_pass.from_handoff(dict(self.PAYLOAD)))

    def test_a_configured_deployment_draws_the_button(self):
        with override_settings(**self.paths):
            row = self._handoff()
            page = self.client.get(reverse("card_handoff", args=[row.token]))
            self.assertContains(page, 'id="btn-wallet"')
            self.assertContains(
                page, reverse("card_handoff_pass", args=[row.token]))

    def test_no_credential_means_no_pass(self):
        """A card with nothing offline on it is not one to put in a wallet --
        the same rule that stops the document printing an empty cut-out. A
        portrait symbol on its own does not change that: it is bound to a
        credential and checks nothing without one."""
        from accounts import wallet_pass

        payload = dict(self.PAYLOAD, qr="")
        with override_settings(**self.paths):
            self.assertIsNone(wallet_pass.from_handoff(payload))
            # Each layer on its own: the page's check with a builder that
            # would build anything, and the builder's own refusal.
            with patch.object(wallet_pass, "card_pass", return_value=b"x"):
                self.assertIsNone(wallet_pass.from_handoff(payload))
            self.assertIsNone(wallet_pass.card_pass(payload, message=""))
            row = self._handoff(payload)
            page = self.client.get(reverse("card_handoff", args=[row.token]))
            # The id, not the words: the phrase also appears in a CSS comment
            # on that page, so asserting it proves nothing about the control.
            self.assertNotContains(page, 'id="btn-wallet"')

    # -- the endpoint ------------------------------------------------------

    def test_the_card_arrives_as_one_signed_pass(self):
        with override_settings(**self.paths):
            response = self._fetch(self._handoff())
            self.assertEqual(response["Content-Type"],
                             "application/vnd.apple.pkpass")
            self.assertIn('filename="Verification Card.pkpass"',
                          response["Content-Disposition"])
            self.assertIn("no-store", response["Cache-Control"])
            archive = zipfile.ZipFile(BytesIO(response.content))
            self.assertIn("signature", archive.namelist())
            self.assertIn("icon.png", archive.namelist())
            body = self._body(archive)
            self.assertEqual(body["passTypeIdentifier"], "pass.test")
            # The transaction id, so a pass added before is updated, not
            # duplicated -- including one added as the old pair's first pass.
            self.assertEqual(body["serialNumber"], self.TRANSACTION_ID)

    def test_an_expired_handoff_serves_no_pass(self):
        with override_settings(**self.paths):
            row = self._handoff()
            row.expires_at = timezone.now() - datetime.timedelta(seconds=1)
            row.save(update_fields=["expires_at"])
            self.assertEqual(
                self.client.get(
                    reverse("card_handoff_pass", args=[row.token])).status_code,
                404)

    def test_fetching_a_pass_does_not_release_the_handoff(self):
        """The pass and the picture are different objects and the holder may
        reasonably want both, so one must not spend the other."""
        with override_settings(**self.paths):
            row = self._handoff()
            self.client.get(reverse("card_handoff_pass", args=[row.token]))
            self.assertTrue(CardHandoff.objects.filter(pk=row.pk).exists())
            self.assertEqual(
                self.client.get(
                    reverse("card_handoff", args=[row.token])).status_code, 200)

    # -- what is on it ----------------------------------------------------

    def test_it_is_the_pass_a_holder_gets_from_idmanager(self):
        """One builder, so the card page and
        idmanager cannot drift apart. Same words, same barcode, same photo,
        same expiry -- everything but the signature, which is timestamped."""
        from accounts import wallet_pass

        symbol, image = self._face()
        payload = dict(self.PAYLOAD, portrait_qr=symbol,
                       expires_at="2027-10-05T08:00:00+00:00")
        with override_settings(**self.paths):
            here = self._pass(self._handoff(payload))
            holder = zipfile.ZipFile(BytesIO(wallet_pass.for_holder(
                payload, message=payload["qr"], face=image,
                expires_at=payload["expires_at"])))
        self.assertEqual(self._body(here), self._body(holder))
        names = sorted(set(here.namelist()) - {"manifest.json", "signature"})
        self.assertEqual(names, sorted(set(holder.namelist())
                                       - {"manifest.json", "signature"}))
        for name in names:
            self.assertEqual(here.read(name), holder.read(name), name)

    def test_the_credential_is_the_one_barcode(self):
        """Not the face symbol and not the transaction id the online check
        uses -- and no header, because there is nothing to tell apart."""
        with override_settings(**self.paths):
            body = self._body(self._pass(self._handoff()))
        self.assertEqual(len(body["barcodes"]), 1)
        self.assertEqual(body["barcodes"][0]["message"],
                         self.PAYLOAD["qr"].upper())
        self.assertNotIn("CL03F", json.dumps(body))
        self.assertNotIn("headerFields", body["generic"])
        shown = body["generic"]["secondaryFields"] \
            + body["generic"]["auxiliaryFields"]
        self.assertLessEqual(len(shown), 4)
        self.assertIn("Window 3", [f["value"] for f in shown])

    def test_the_photo_is_the_image_the_portrait_symbol_carries(self):
        """The bytes `portrait_hash` covers, at 1x, 2x and 3x."""
        from accounts import wallet_pass

        symbol, image = self._face()
        with override_settings(**self.paths):
            archive = self._pass(self._handoff(
                dict(self.PAYLOAD, portrait_qr=symbol)))
        for scale, name in ((1, "thumbnail.png"), (2, "thumbnail@2x.png"),
                            (3, "thumbnail@3x.png")):
            expected = wallet_pass._png_photo(image, 90 * scale)
            self.assertIsNotNone(expected, name)
            self.assertEqual(archive.read(name), expected, name)

    def test_the_photo_never_comes_from_the_cards_face_field(self):
        """`face` is the same picture wrapped for a browser. Taking the
        symbol's bytes means the photo can only ever be the face the
        credential binds; a payload whose `face` said otherwise would not
        move it."""
        from accounts import wallet_pass

        symbol, image = self._face()
        other = credentials.render_portrait(sample_face.data_uri(drawn=True))
        uri = "data:image/webp;base64," + base64.b64encode(other).decode()
        with override_settings(**self.paths):
            archive = self._pass(self._handoff(
                dict(self.PAYLOAD, portrait_qr=symbol, face=uri)))
        self.assertEqual(archive.read("thumbnail@2x.png"),
                         wallet_pass._png_photo(image, 180))
        self.assertNotEqual(archive.read("thumbnail@2x.png"),
                            wallet_pass._png_photo(other, 180))

    def test_without_a_portrait_symbol_the_pass_has_no_photo(self):
        """The face did not fit, or there was none: the credential alone."""
        with override_settings(**self.paths):
            archive = self._pass(self._handoff(
                dict(self.PAYLOAD, portrait_qr="")))
        self.assertIn(":CL03:", self._body(archive)["barcodes"][0]["message"])
        self.assertEqual({n for n in archive.namelist() if n.endswith(".png")},
                         {"icon.png", "icon@2x.png", "icon@3x.png"})

    def test_only_a_portrait_symbol_gives_a_photo(self):
        from accounts import wallet_pass
        from ovcrypto import base45

        symbol, image = self._face()
        self.assertEqual(wallet_pass._symbol_image(symbol), image)
        tail = symbol.split(":", 1)[1]
        for text in ("CL03F9:" + tail, "CL03:" + tail, "", None,
                     "CL03F1:" + str(uuid.uuid4()) + ":"):
            self.assertIsNone(wallet_pass._symbol_image(text), text)
        self.assertEqual(base45.decode(symbol.split(":", 2)[2]), image)

    def test_a_face_that_will_not_decode_costs_only_the_photo(self):
        """PAYLOAD's symbol carries bytes that are not an image."""
        with override_settings(**self.paths):
            archive = self._pass(self._handoff())
        self.assertFalse([n for n in archive.namelist()
                          if n.startswith("thumbnail")])
        self.assertIn(":CL03:", self._body(archive)["barcodes"][0]["message"])

    def test_the_pass_carries_the_credentials_expiry(self):
        """Wallet greys a pass out on its `expirationDate` -- the same date
        the credential stops verifying. Absent from an older hand-off, and
        then absent from the pass rather than invented."""
        with override_settings(**self.paths):
            dated = self._body(self._pass(self._handoff(
                dict(self.PAYLOAD, expires_at="2027-10-05T08:00:00+00:00"))))
            undated = self._body(self._pass(self._handoff()))
        self.assertEqual(dated["expirationDate"], "2027-10-05T08:00:00+00:00")
        self.assertNotIn("expirationDate", undated)

    def test_the_pass_is_built_from_the_stored_payload(self):
        """Masked values ride into the pass, because the payload was masked
        where there was a session to decide it. Composing a pass from
        anything else is Demo Mode leaking into a wallet, permanently."""
        masked = dict(self.PAYLOAD, holder="LISA ••••",
                      card_number="••••-3")
        with override_settings(**self.paths):
            body = self._body(self._pass(self._handoff(masked)))
        # The parsed values, not a dumped string: json.dumps escapes the
        # mask character to • and the assertion passes on nothing.
        values = [f["value"] for group in body["generic"].values()
                  for f in group]
        self.assertIn("LISA ••••", values)
        self.assertIn("••••-3", values)
        self.assertNotIn("LISA ROSE REYES CRUZ", values)
        self.assertNotIn("0000-1111-2222-3333", values)

    def test_the_button_is_shown_only_on_an_apple_handset(self):
        """A .pkpass on anything else downloads a file the device cannot
        open, so an unrecognised phone gets no button. That is the OPPOSITE
        direction to the save path's test, deliberately: there, sharing is
        the default an unknown platform falls back to."""
        with override_settings(**self.paths):
            row = self._handoff()
            source = self.client.get(
                reverse("card_handoff", args=[row.token])).content.decode()
            self.assertIn("if (wallet && applePhone()) { wallet.hidden = false; }",
                          source)
            self.assertIn("navigator.maxTouchPoints > 1", source)

class BrandingTest(TestCase):
    """A site carries the name and logos its operator gives it, and no one
    else's. This repository is published so that other organizations can
    run their own sites; a page titled with, or a footer drawing, the marks
    of whoever wrote the code would be wrong on every one of them -- and
    those marks are not licensed to anybody else in the first place."""

    def test_an_unbranded_site_is_titled_verify_and_has_no_footer(self):
        page = self.client.get("/").content.decode()
        self.assertIn("<title>Verify: Login</title>", page)
        self.assertNotIn('class="branding-footer"', page)
        for mark in ("Experience Center", "TRL", "Ateneo"):
            self.assertNotIn(mark, page)

    @override_settings(SITE_TITLE="Acme Verify", SITE_FOOTER_LABEL="Operated by",
                       SITE_FOOTER_LOGOS="acme.png|https://www.acme.example|Acme;"
                                         "partner.webp")
    def test_the_operators_name_and_logos_are_drawn(self):
        page = self.client.get("/").content.decode()
        self.assertIn("<title>Acme Verify: Login</title>", page)
        self.assertIn('<div class="developer-label">Operated by</div>', page)
        self.assertIn('<a href="https://www.acme.example" target="_blank" rel="noopener">'
                      '<img src="/static/branding/acme.png" alt="Acme"></a>', page)
        # No link and no text: the image alone, named after its file.
        self.assertIn('<img src="/static/branding/partner.webp" alt="partner">', page)

    @override_settings(SITE_FOOTER_LOGOS='ok.png|https://ok.example|"><script>x()</script>')
    def test_operator_text_is_never_markup(self):
        page = self.client.get("/").content.decode()
        self.assertIn('alt="&quot;&gt;&lt;script&gt;x()&lt;/script&gt;"', page)
        self.assertNotIn("<script>x()", page)

    def test_an_entry_that_is_not_a_plain_image_and_web_link_is_dropped(self):
        from verify.branding import footer_logos
        with self.assertLogs("verify.branding", "WARNING"):
            logos = footer_logos(
                "../outside.png|https://x.example;"   # leaves the branding folder
                "mark.svg|https://x.example;"         # SVG can carry script
                "ok.png|javascript:alert(1);"         # not a web link
                "ok.png|https://x.example|alt|extra;"  # not file|link|alt
                "good.jpg|https://good.example|Good")
        self.assertEqual(logos, [{"src": "branding/good.jpg",
                                  "href": "https://good.example", "alt": "Good"}])

    def test_the_branding_folder_is_published_under_static(self):
        import subprocess
        import sys
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder, True)
        code = ("import verify.settings as s; "
                "print([d for d in s.STATICFILES_DIRS if isinstance(d, tuple)])")
        with_folder = subprocess.run([sys.executable, "-c", code], cwd=str(settings.BASE_DIR),
                                     env=dict(os.environ, BRANDING_DIR=folder),
                                     capture_output=True, text=True)
        self.assertEqual(with_folder.returncode, 0, with_folder.stderr)
        self.assertIn("('branding', %r)" % folder, with_folder.stdout)
        missing = subprocess.run([sys.executable, "-c", code], cwd=str(settings.BASE_DIR),
                                 env=dict(os.environ, BRANDING_DIR=folder + "-missing"),
                                 capture_output=True, text=True)
        self.assertEqual(missing.stdout.strip(), "[]", missing.stderr)

    def test_no_template_or_static_file_carries_an_organizations_branding(self):
        base = settings.BASE_DIR
        for path in (base / "templates").rglob("*.html"):
            text = path.read_text(encoding="utf-8")
            # Assembled, so this test does not itself carry the address.
            for mark in ("Experience Center", "trl-logo", "ateneo", "trl" + ".ph"):
                self.assertNotIn(mark, text.lower() if mark.islower() else text,
                                 "%s carries %s" % (path.name, mark))
        for name in ("ateneo-build-logo.jpg", "trl-logo.png", "logo.png"):
            self.assertFalse((base / "static" / name).exists(), name)


class DeployExcludeTest(TestCase):
    """rsync does not read .gitignore, so what stays OFF a server is whatever
    deploy.sh's exclude list names, and nothing else. One script, told which
    server by a site config, cannot drift from itself."""

    def _source(self):
        return (settings.BASE_DIR / "deploy" / "deploy.sh").read_text(
            encoding="utf-8")

    def _excludes(self):
        import re
        block = re.search(r"^EXCLUDES=\((.*?)^\)", self._source(),
                          re.S | re.M).group(1)
        # A path named in a comment is not an exclusion.
        return set(re.findall(r"^\s*'([^']+)'\s*$", block, re.M))

    def test_there_is_one_deploy_script(self):
        self.assertFalse((settings.BASE_DIR / "deploy" / "deploy-dev.sh").exists())

    def test_nothing_private_reaches_a_server(self):
        excludes = self._excludes()
        for path in ("dbbackup/", "backups/", "db.sqlite3", ".env", ".env.*", "demo/",
                     "secrets/", "*.pem", "*.key", "deploy/", "terraform/",
                     "site/"):
            self.assertIn(path, excludes, "deploy.sh ships " + path)

    def test_the_list_is_what_rsync_is_given(self):
        """A list is only a list until something hands it over."""
        source = self._source()
        self.assertIn('for e in "${EXCLUDES[@]}"; do '
                      'RSYNC_EXCLUDES+=(--exclude "$e"); done', source)
        self.assertIn('rsync -avz --delete -e "ssh $SSH_OPTS" '
                      '"${RSYNC_EXCLUDES[@]}"', source)


class DeployKitTest(TestCase):
    """terraform/ and deploy/ build a new Verify site on AWS from one
    configuration file, and they are published. So they must be complete --
    every setting the application reads can be given in that file -- and they
    must carry no deployment's settings: an account id, a resource id or an
    address committed here is everybody's, and a default for one is a setting
    everybody inherits without noticing."""

    def _read(self, *parts):
        return settings.BASE_DIR.joinpath(*parts).read_text(encoding="utf-8")

    def _block(self, text, header):
        """The body of one HCL block, found by its header line."""
        import re
        match = re.search(re.escape(header) + r" \{\n(.*?)\n\}\n", text, re.S)
        self.assertIsNotNone(match, header)
        return match.group(1)

    def _kit_files(self):
        base = settings.BASE_DIR
        files = [base / "docs" / "deploy-aws.md"]
        for top in ("terraform", "deploy"):
            for path in sorted((base / top).rglob("*")):
                # Terraform's own working files are git-ignored and are not
                # what this repository publishes.
                if path.is_file() and not any(
                        part.startswith(".terraform") for part in path.parts):
                    files.append(path)
        return files

    def _deploy_keys(self, name):
        import re
        source = self._read("deploy", "deploy.sh")
        block = re.search(r'^%s="(.*?)"' % name, source, re.S | re.M).group(1)
        return set(block.split())

    # --- one file, complete ---------------------------------------------------

    def test_the_configuration_carries_exactly_what_the_application_reads(self):
        """deploy.sh writes the server's .env from APP_KEYS and refuses any
        other key, so a setting missing from it could not be given at all."""
        import re
        base = settings.BASE_DIR
        sources = [base / "deploy" / "deploy.sh"]
        for top in ("verify", "accounts"):
            sources += [p for p in (base / top).rglob("*.py")
                        if not p.name.startswith("tests")]
        read = set()
        for path in sources:
            text = path.read_text(encoding="utf-8")
            read |= set(re.findall(
                r"os\.environ\.get\(\s*['\"]([A-Z][A-Z0-9_]+)['\"]", text))
            read |= set(re.findall(
                r"_setting\(\s*dotenv,\s*['\"]([A-Z][A-Z0-9_]+)['\"]", text))
        self.assertGreater(len(read), 30, "the scan found no settings at all")
        self.assertEqual(self._deploy_keys("APP_KEYS"), read)

    def test_the_example_documents_every_key_the_tool_accepts(self):
        import re
        documented = set(re.findall(r"^#? ?([A-Z][A-Z0-9_]+)=",
                                    self._read("deploy", "site.conf.example"), re.M))
        accepted = (self._deploy_keys("INFRA_KEYS") | self._deploy_keys("DEPLOY_KEYS")
                    | self._deploy_keys("APP_KEYS"))
        self.assertEqual(accepted - documented, set())
        self.assertEqual(documented - accepted, set())

    def test_the_example_writes_values_bare_and_holds_no_secret(self):
        import re
        example = self._read("deploy", "site.conf.example")
        self.assertEqual(
            re.findall(r"^#? ?([A-Z][A-Z0-9_]+)=[\"']", example, re.M), [])
        for key in ("DJANGO_SECRET_KEY", "DJANGO_SUPERUSER_PASSWORD",
                    "EVERIFY_CLIENT_SECRET", "AWS_ACCOUNT_ID", "AWS_REGION",
                    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
            self.assertRegex(example, r"(?m)^%s=$" % key)

    # --- what Terraform builds ------------------------------------------------

    def test_the_server_is_built_from_the_templates_in_deploy(self):
        """The configuration a server runs is the configuration this
        repository holds, not a second copy typed into the boot script."""
        main = self._read("terraform", "main.tf")
        for path in ("../deploy/nginx.conf.tftpl",
                     "../deploy/gunicorn.service.tftpl",
                     "../deploy/gunicorn.conf.py"):
            self.assertIn(path, main)
        boot = self._read("terraform", "user_data.sh.tftpl")
        for slot in ("${nginx_conf}", "${gunicorn_service}", "${gunicorn_conf}"):
            self.assertIn(slot, boot)
        # A Windows checkout can hand the templates over with CRLF endings.
        self.assertIn('user_data = replace(templatefile(', main)
        self.assertIn('}), "\\r", "")', main)

    def test_only_the_load_balancer_and_the_bastion_reach_the_server(self):
        main = self._read("terraform", "main.tf")
        app_sg = self._block(main, 'resource "aws_security_group" "app"')
        ingress = app_sg.split("egress")[0]
        self.assertNotIn("cidr_blocks", ingress)
        self.assertIn("security_groups = [aws_security_group.alb.id]", ingress)
        self.assertIn("security_groups = [aws_security_group.bastion.id]", ingress)
        bastion_sg = self._block(main, 'resource "aws_security_group" "bastion"')
        self.assertIn("cidr_blocks = var.ssh_allowed_cidrs",
                      bastion_sg.split("egress")[0])
        server = self._block(main, 'resource "aws_instance" "app"')
        self.assertIn("subnet_id              = aws_subnet.private.id", server)
        self.assertNotIn("associate_public_ip_address", server)
        private = self._block(main, 'resource "aws_route_table" "private"')
        self.assertIn("nat_gateway_id = aws_nat_gateway.main.id", private)

    def test_nothing_routine_replaces_the_server_holding_the_database(self):
        """A newer Amazon Linux image, or an edit to the boot script, would
        otherwise rebuild the server -- and its disk is the database."""
        server = self._block(self._read("terraform", "main.tf"),
                             'resource "aws_instance" "app"')
        self.assertIn("ignore_changes = [ami, user_data]", server)

    def test_the_servers_disk_is_encrypted_and_snapshotted_daily(self):
        main = self._read("terraform", "main.tf")
        server = self._block(main, 'resource "aws_instance" "app"')
        self.assertIn("encrypted             = true", server)
        self.assertIn('http_tokens   = "required"', server)
        self.assertIn("VerifyBackup = var.site_name", server)
        policy = self._block(main, 'resource "aws_dlm_lifecycle_policy" "daily"')
        self.assertIn("target_tags    = { VerifyBackup = var.site_name }", policy)
        self.assertIn("count = var.snapshot_retention_days", policy)

    def test_the_state_is_kept_beside_the_configuration_not_here(self):
        self.assertIn('backend "local" {}', self._read("terraform", "main.tf"))
        deploy = self._read("deploy", "deploy.sh")
        self.assertIn('-backend-config="path=$(native "$SITE_DIR/terraform.tfstate")"', deploy)
        self.assertIn('TF_DATA_DIR="$(native "$SITE_DIR/.terraform")"', deploy)

    def test_the_layout_is_the_same_everywhere(self):
        import re
        main = self._read("terraform", "main.tf")
        self.assertRegex(main, r'app_user\s*=\s*"ec2-user"')
        self.assertRegex(main, r'app_dir\s*=\s*"/home/ec2-user/app"')
        deploy = self._read("deploy", "deploy.sh")
        self.assertIn('REMOTE_USER="${REMOTE_USER:-ec2-user}"', deploy)
        self.assertIn('APP_DIR="${APP_DIR:-/home/$REMOTE_USER/app}"', deploy)
        # The commands run on the server take the directory they are given.
        for block in re.findall(r"<<'REMOTE'\n(.*?)\nREMOTE\n", deploy, re.S):
            self.assertNotIn("/home/", block)

    def test_nginx_passes_the_load_balancers_scheme_through(self):
        conf = self._read("deploy", "nginx.conf.tftpl")
        self.assertIn("proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;", conf)
        self.assertNotIn("X-Forwarded-Proto $scheme", conf)

    # --- no settings, no secrets ----------------------------------------------

    def test_the_boot_script_and_terraform_carry_no_secret(self):
        """User data is readable by anyone allowed to describe the instance,
        and Terraform state by anyone who holds it."""
        boot = self._read("terraform", "user_data.sh.tftpl")
        # A comment may name a setting; only the commands write anything.
        code = "\n".join(line for line in boot.splitlines()
                         if not line.lstrip().startswith("#"))
        for word in ("SECRET", "PASSWORD", "CLIENT_ID", "API_KEY", "/.env\" <<"):
            self.assertNotIn(word, code)
        self.assertNotIn("sensitive", self._read("terraform", "variables.tf"))

    def test_what_belongs_to_one_site_has_no_default(self):
        variables = self._read("terraform", "variables.tf")
        for name in ("aws_account_id", "aws_region", "site_name", "domain_name",
                     "ssh_allowed_cidrs", "ssh_public_key"):
            self.assertNotIn("default", self._block(variables, 'variable "%s"' % name), name)

    def test_no_account_id_resource_id_or_address_is_committed(self):
        import ipaddress
        import re
        documentation = [ipaddress.ip_network(n) for n in
                         ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
        for path in self._kit_files():
            text = path.read_text(encoding="utf-8", errors="replace")
            name = str(path.relative_to(settings.BASE_DIR))
            self.assertIsNone(re.search(r"(?<![0-9])[0-9]{12}(?![0-9])", text),
                              name + " carries an account id")
            self.assertIsNone(re.search(
                r"\b(?:subnet|sg|vpc|i|ami|eni|vol|snap|lt|igw|nat|eipalloc)-[0-9a-f]{8,17}\b",
                text), name + " carries a resource id")
            for found, prefix in re.findall(
                    r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(/\d{1,2})?(?![\w.])", text):
                address = ipaddress.ip_address(found)
                # A private network written as a range is a layout, not a
                # machine; a bare private address is somebody's server.
                self.assertTrue(
                    address.is_loopback or address.is_unspecified
                    or any(address in net for net in documentation)
                    or (prefix and address.is_private),
                    name + " carries the address " + found)

    # --- the tool, driven for real against stand-in commands -------------------

    SECRET = "Xk2pV9qLm4Rt7Wz1Bc6Nd3Fg8Hj5Ks0Ya2Ue7Io4Pl9Qw3Er6Ty1Ui8Op5As2Df"

    STUBS = {
        # Records its arguments, and keeps a copy of the .env it is handed.
        "rsync": '#!/bin/sh\necho "$@" >> "$STUB_DIR/log"\n'
                 'for last; do :; done\n'
                 'case "$last" in *:*/.env.incoming) eval "src=\\${$(($#-1))}"; '
                 'cp "$src" "$STUB_DIR/env" ;; esac\nexit 0\n',
        "ssh": '#!/bin/sh\necho "$@" >> "$STUB_DIR/log"\n'
               'cat >> "$STUB_DIR/remote-scripts"\nexit 0\n',
        "curl": '#!/bin/sh\nfor a; do case "$a" in *lookup-data*) printf 403; '
                'exit 0 ;; esac; done\nprintf 200\n',
        "terraform": '#!/bin/sh\necho "terraform $@" >> "$STUB_DIR/log"\n'
                     'env | grep -E "^(TF_|AWS_)" >> "$STUB_DIR/terraform-env"\n'
                     'case "$*" in *instance_id*) printf "i-fedcba9876543210f" ;; esac\n'
                     'exit 0\n',
        # The EC2 console a test writes to $STUB_DIR/console; the account
        # for everything else.
        "aws": '#!/bin/sh\necho "aws $@" >> "$STUB_DIR/log"\n'
               'case "$*" in *get-console-output*) cat "$STUB_DIR/console" 2>/dev/null; '
               'exit 0 ;; esac\n'
               'printf "%s\\n" "${STUB_ACCOUNT:-123456789012}"\n',
    }

    def _bash(self):
        """bash, and the directories its tools live in.

        On Windows, Git's own usr/bin/bash.exe: not System32's bash.exe,
        which is WSL and cannot read C:/ paths, and not Git's bin/bash.exe,
        a launcher that puts Git's folders ahead of the stand-ins on PATH."""
        import sys
        if sys.platform == "win32":
            git = shutil.which("git")
            if git:
                for root in list(Path(git).resolve().parents)[:3]:
                    candidate = root / "usr" / "bin" / "bash.exe"
                    if candidate.exists():
                        return str(candidate), [str(root / "usr" / "bin")]
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("needs bash")
        return bash, []

    #: A real public key, so ssh-keygen can find it: a throwaway's, never used.
    HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID2DIoWzim9kwH9aN3tETa2vOoSQCs1ON2ZYr6u1cTNY"

    def _site(self, conf_text, *, pinned=("server", "bastion")):
        """A site folder with a key pair, an issuer key, the servers' host keys
        pinned under `pinned`, and this configuration."""
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "keys").mkdir()
        (tmp / "keys" / "verify").write_text("not a real key\n", encoding="utf-8")
        (tmp / "keys" / "verify.pub").write_text(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyOnly test\n", encoding="utf-8")
        (tmp / "secrets").mkdir()
        (tmp / "secrets" / "verify-issuer.pem").write_text("not a real pem\n", encoding="utf-8")
        (tmp / "site.conf").write_text(conf_text, encoding="utf-8", newline="\n")
        if pinned:
            (tmp / "known_hosts").write_text(
                "".join("%s %s\n" % (name, self.HOST_KEY) for name in pinned),
                encoding="utf-8", newline="\n")
        return tmp

    def _run(self, site, *args, env=None, cwd=None):
        import os as _os
        import subprocess
        stubs = site / "stubs"
        stubs.mkdir(exist_ok=True)
        for name, body in self.STUBS.items():
            (stubs / name).write_text(body, encoding="utf-8", newline="\n")
            (stubs / name).chmod(0o755)
        bash, tools = self._bash()
        child = dict(_os.environ, STUB_DIR=stubs.as_posix(),
                     PATH=_os.pathsep.join([str(stubs)] + tools
                                           + [_os.environ.get("PATH", "")]))
        child.update(env or {})
        result = subprocess.run(
            [bash, (settings.BASE_DIR / "deploy" / "deploy.sh").as_posix(),
             "--config", (site / "site.conf").as_posix(), *args],
            cwd=str(cwd or site), env=child, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=120)
        return result

    AWS_SECRET = "wJalrXUtnFEMI0K7MDENG0bPxRfiCYTESTKEY0001"

    GOOD = ("SITE_NAME=verify-test\nDOMAIN=verify-test.example.org\n"
            "AWS_ACCOUNT_ID=123456789012\nAWS_REGION=test-region-1\n"
            "AWS_ACCESS_KEY_ID=AKIATESTSITEKEY00001\n"
            "AWS_SECRET_ACCESS_KEY=" + AWS_SECRET + "\n"
            "SSH_ALLOWED_CIDRS=203.0.113.10/32, 198.51.100.0/24\n"
            "SSH_PUBLIC_KEY_FILE=keys/verify.pub\nSSH_PRIVATE_KEY_FILE=keys/verify\n"
            "DJANGO_SECRET_KEY=" + SECRET + "\nEVERIFY_CLIENT_ID=client\n")

    def test_a_complete_configuration_validates_and_no_value_is_printed(self):
        result = self._run(self._site(self.GOOD), "validate")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("server .env:", result.stdout)
        self.assertNotIn(self.SECRET, result.stdout + result.stderr)

    def test_a_configuration_without_a_secret_key_is_refused(self):
        conf = self.GOOD.replace("DJANGO_SECRET_KEY=%s\n" % self.SECRET, "")
        result = self._run(self._site(conf), "validate")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DJANGO_SECRET_KEY: missing or empty", result.stderr)

    def test_a_quoted_value_is_refused_by_name_and_not_printed(self):
        result = self._run(self._site(self.GOOD + "EVERIFY_CLIENT_SECRET='%s'\n" % self.SECRET),
                           "validate")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("EVERIFY_CLIENT_SECRET is quoted", result.stderr)
        self.assertNotIn(self.SECRET, result.stdout + result.stderr)

    def test_an_unknown_key_is_refused(self):
        """A typo must not fall back to a default quietly."""
        result = self._run(self._site(self.GOOD + "EVERIFY_CLIENTSECRET=x\n"), "validate")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown key EVERIFY_CLIENTSECRET", result.stderr)

    def test_the_mock_and_debug_together_are_refused(self):
        """Together they let anybody sign in as anybody."""
        result = self._run(self._site(self.GOOD + "DJANGO_DEBUG=True\n"
                                      "EVERIFY_ALLOW_MOCK_LOGIN=1\n"), "validate")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("anybody could sign in as anybody", result.stderr)

    def test_a_server_path_inside_the_code_directory_is_refused(self):
        """Every deploy rewrites that directory with rsync --delete."""
        result = self._run(self._site(self.GOOD + "CREDENTIAL_ISSUER_KEY_PATH="
                                      "/home/ec2-user/app/verify/issuer.pem\n"), "validate")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CREDENTIAL_ISSUER_KEY_PATH: inside the code directory", result.stderr)

    def test_the_configuration_is_parsed_never_sourced(self):
        """It is data. A line in it must not run on the operator's machine."""
        site = self._site(self.GOOD + "VERIFY_DEFAULT_ORG_NAME=$(touch ran)\n")
        result = self._run(site, "validate")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((site / "ran").exists())

    def test_a_deploy_writes_the_servers_env_from_the_configuration(self):
        site = self._site(self.GOOD.replace("EVERIFY_CLIENT_ID=client",
                                            "EVERIFY_CLIENT_ID = client")
                          + "SERVER_IP=192.0.2.20\nJUMP_HOST=192.0.2.10\n"
                          "ISSUER_KEY_FILE=secrets/verify-issuer.pem\n"
                          "CREDENTIAL_EPOCH_WRAP_KEY=%s\n"
                          "DJANGO_SUPERUSER_PASSWORD=pa#ss\n"
                          "VERIFY_DEFAULT_ORG_NAME=Acme Verification Office\n"
                          % ("ab" * 32))
        # A setting in the operator's own shell must not reach the server.
        result = self._run(site, "deploy", env={"EVERIFY_CLIENT_SECRET": "from-the-shell"})
        self.assertEqual(result.returncode, 0, result.stderr)
        env = (site / "stubs" / "env").read_text(encoding="utf-8")
        lines = {line.split("=", 1)[0]: line.split("=", 1)[1]
                 for line in env.splitlines() if line and not line.startswith("#")}
        self.assertEqual(lines, {
            "DJANGO_SECRET_KEY": self.SECRET,
            "DJANGO_ALLOWED_HOSTS": "verify-test.example.org",
            "DJANGO_SUPERUSER_PASSWORD": "pa#ss",
            "EVERIFY_CLIENT_ID": "client",
            "VERIFY_DEFAULT_ORG_NAME": "Acme Verification Office",
            "CREDENTIAL_ISSUER_KEY_PATH": "/home/ec2-user/secrets/verify-issuer.pem",
            "CREDENTIAL_EPOCH_WRAP_KEY": "ab" * 32,
        })
        log = (site / "stubs" / "log").read_text(encoding="utf-8")
        self.assertIn("target:/home/ec2-user/secrets/verify-issuer.pem", log)
        self.assertNotIn(self.SECRET, result.stdout + result.stderr + log)

    def test_an_issuer_key_without_a_wrap_key_is_a_problem(self):
        """No document would carry a credential."""
        site = self._site(self.GOOD + "SERVER_IP=192.0.2.20\nJUMP_HOST=192.0.2.10\n"
                          "ISSUER_KEY_FILE=secrets/verify-issuer.pem\n")
        result = self._run(site, "deploy")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CREDENTIAL_EPOCH_WRAP_KEY is empty, but an issuer key is set",
                      result.stderr)

    def test_a_deploy_copies_the_branding_folder_and_names_it(self):
        site = self._site(self.GOOD + "SERVER_IP=192.0.2.20\nJUMP_HOST=192.0.2.10\n"
                          "SITE_TITLE=Acme Verify\nBRANDING_FOLDER=branding\n"
                          "SITE_FOOTER_LOGOS=acme.png|https://www.acme.example|Acme Corp\n")
        (site / "branding").mkdir()
        (site / "branding" / "acme.png").write_bytes(b"\x89PNG")
        result = self._run(site, "deploy")
        self.assertEqual(result.returncode, 0, result.stderr)
        env = (site / "stubs" / "env").read_text(encoding="utf-8")
        self.assertIn("SITE_TITLE=Acme Verify\n", env)
        self.assertIn("SITE_FOOTER_LOGOS=acme.png|https://www.acme.example|Acme Corp\n", env)
        self.assertIn("BRANDING_DIR=/home/ec2-user/app/branding\n", env)
        log = (site / "stubs" / "log").read_text(encoding="utf-8")
        self.assertIn("target:/home/ec2-user/app/branding/", log)

    def test_a_logo_missing_from_the_branding_folder_is_refused(self):
        site = self._site(self.GOOD + "BRANDING_FOLDER=branding\n"
                          "SITE_FOOTER_LOGOS=acme.png|https://www.acme.example;mark.svg\n")
        (site / "branding").mkdir()
        result = self._run(site, "validate")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("acme.png is not in BRANDING_FOLDER", result.stderr)
        self.assertIn("mark.svg is not a plain PNG, JPEG, GIF or WebP file name", result.stderr)

    def test_terraform_is_given_the_site_and_never_a_secret(self):
        site = self._site(self.GOOD)
        # Whatever the operator's shell holds belongs to somebody else.
        result = self._run(site, "infra", "plan", env={
            "AWS_PROFILE": "another-deployment", "AWS_ACCESS_KEY_ID": "AKIASHELL0000000000",
            "AWS_SESSION_TOKEN": "SHELLTOKEN000000", "AWS_DEFAULT_PROFILE": "another-default",
            "TF_VAR_extra": "from-the-shell", "TF_CLI_ARGS_plan": "-target=x"})
        self.assertEqual(result.returncode, 0, result.stderr)
        handed = (site / "stubs" / "terraform-env").read_text(encoding="utf-8")
        self.assertIn('TF_VAR_ssh_allowed_cidrs=["203.0.113.10/32","198.51.100.0/24"]', handed)
        self.assertIn("TF_VAR_ssh_public_key=ssh-ed25519 ", handed)
        self.assertIn("TF_VAR_site_name=verify-test", handed)
        self.assertIn("TF_VAR_aws_account_id=123456789012", handed)
        self.assertIn("AWS_ACCESS_KEY_ID=AKIATESTSITEKEY00001", handed)
        for foreign in ("another-deployment", "another-default", "AKIASHELL",
                        "SHELLTOKEN", "from-the-shell", "-target=x"):
            self.assertNotIn(foreign, handed)
        # With access keys, this machine's own AWS configuration is hidden too.
        self.assertRegex(handed, r"(?m)^AWS_CONFIG_FILE=.*/\.aws-empty$")
        self.assertRegex(handed, r"(?m)^AWS_SHARED_CREDENTIALS_FILE=.*/\.aws-empty$")
        # Credentials reach Terraform's provider, never a variable, so they
        # cannot land in its state.
        variables = "\n".join(l for l in handed.splitlines() if l.startswith("TF_VAR_"))
        self.assertNotIn(self.SECRET, variables)
        self.assertNotIn(self.AWS_SECRET, variables)
        log = (site / "stubs" / "log").read_text(encoding="utf-8")
        self.assertIn("aws sts get-caller-identity", log)
        self.assertIn("init -input=false -reconfigure -backend-config=path=", log)
        # The state goes beside the configuration file, never into the repository.
        self.assertIn(site.name + "/terraform.tfstate", log)
        self.assertIn("plan -input=false", log)

    def test_another_accounts_credentials_stop_everything(self):
        """Credentials that resolve to any account but the site's own -- a
        default profile on a machine that also runs another deployment, say
        -- must not get as far as Terraform."""
        site = self._site(self.GOOD)
        result = self._run(site, "infra", "plan", env={"STUB_ACCOUNT": "999999999999"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("belong to AWS account 999999999999, not this site's", result.stderr)
        self.assertNotIn("terraform", (site / "stubs" / "log").read_text(encoding="utf-8"))

    def test_a_site_without_aws_credentials_of_its_own_is_refused(self):
        """With none, the AWS tools would fall back to this machine's own."""
        conf = "\n".join(l for l in self.GOOD.splitlines()
                         if not l.startswith(("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"))) + "\n"
        result = self._run(self._site(conf), "validate")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("this machine's default credentials", result.stderr)

    def test_terraform_refuses_any_account_but_the_sites(self):
        main = self._read("terraform", "main.tf")
        self.assertIn("allowed_account_ids = [var.aws_account_id]",
                      self._block(main, 'provider "aws"'))

    def test_a_new_site_points_at_nobody_elses_sign_on_provider(self):
        """Single sign-on is off until a site administrator names a provider;
        no default may point at another deployment's."""
        site = SiteSettings()
        self.assertEqual(site.sso_issuer, "")
        self.assertEqual(site.login_mode, SiteSettings.LOGIN_EVERIFY)
        self.assertNotIn("trl", dict(SiteSettings.LOGIN_MODES)[SiteSettings.LOGIN_SSO].lower())
        from accounts.management.commands.make_wallet_pass import Command
        org = Command().create_parser("manage.py", "make_wallet_pass").parse_args([]).org
        self.assertNotIn("trl", org.lower())


def _rmtree(path):
    """Git marks pack files read-only, which Windows refuses to delete."""
    def retry(func, target, _exc):
        os.chmod(target, stat.S_IWRITE)
        func(target)
    shutil.rmtree(path, onerror=retry)


class PrePushGuardTest(TestCase):
    """tools/hooks/pre-push refuses a push that would publish a secret.

    A credential pushed once stays in the history it was pushed with, so
    this runs before anything leaves. Driven for real: a
    throwaway repository, a bare remote, the hook installed through
    core.hooksPath exactly as a clone enables it, and `git push`."""

    SECRET = "Zq8vN3kLw0pR7tYx2mBc5hJd9fGs4aEu"

    def setUp(self):
        import subprocess
        self.run_ = subprocess.run
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(_rmtree, self.tmp)
        self.remote = os.path.join(self.tmp, "remote.git")
        self.work = os.path.join(self.tmp, "work")
        self.git(self.tmp, "init", "-q", "--bare", self.remote)
        self.git(self.tmp, "init", "-q", "-b", "main", self.work)
        self.git(self.work, "config", "core.hooksPath",
                 str(settings.BASE_DIR / "tools" / "hooks"))
        self.git(self.work, "remote", "add", "origin", self.remote)
        self.write(".gitignore", ".env\n")
        self.write(".env", "EVERIFY_CLIENT_SECRET=%s\nDEBUG=1\n"
                           "DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1\n"
                           "PRIVATE_KEY_PATH=/srv/secrets/issuer.pem\n"
                           "KIOSK_PASSWORD=1234\n"
                           % self.SECRET)
        self.commit("start", ".gitignore")

    def git(self, cwd, *args):
        return self.run_(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                          *args], cwd=cwd, capture_output=True, text=True)

    def write(self, name, text):
        with open(os.path.join(self.work, name), "w", encoding="utf-8") as f:
            f.write(text)

    def commit(self, message, *paths):
        self.git(self.work, "add", *paths)
        self.git(self.work, "commit", "-q", "-m", message)

    def push(self, **env):
        return self.run_(["git", "push", "-q", "origin", "main"], cwd=self.work,
                         env=dict(os.environ, **env), capture_output=True, text=True)

    def test_a_clean_push_goes_through(self):
        self.write("app.py", "SECRET = os.environ['EVERIFY_CLIENT_SECRET']\n")
        self.commit("read it from the environment", "app.py")
        result = self.push()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_value_from_env_is_refused(self):
        self.write("app.py", "SECRET = '%s'\n" % self.SECRET)
        self.commit("hardcode it", "app.py")
        result = self.push()
        self.assertNotEqual(result.returncode, 0, "pushed a live secret")
        self.assertIn("app.py", result.stderr)
        self.assertNotIn(self.SECRET, result.stderr + result.stdout,
                         "the guard printed what it caught")
        self.assertEqual(self.git(self.work, "ls-remote", self.remote).stdout,
                         "", "the remote received it anyway")

    def test_a_value_from_the_site_configuration_is_refused(self):
        """A site's secrets live in its configuration file, outside the
        checkout, where nothing else here would know them."""
        other = "Pq3wE8rT1yU6iO0pA5sD9fG2hJ7kL4zX"
        site = os.path.join(self.tmp, "site.conf")
        with open(site, "w", encoding="utf-8") as f:
            f.write("SITE_NAME=verify\nDJANGO_SECRET_KEY=%s\n" % other)
        self.write("app.py", "KEY = '%s'\n" % other)
        self.commit("hardcode the site's key", "app.py")
        result = self.push(VERIFY_SITE=site)
        self.assertNotEqual(result.returncode, 0, "pushed the site's secret")
        self.assertNotIn(other, result.stderr + result.stdout)
        self.assertEqual(self.git(self.work, "ls-remote", self.remote).stdout,
                         "", "the remote received it anyway")
        # And it was the site configuration that knew it: unnamed, it passes.
        self.assertEqual(self.push().returncode, 0)

    def test_a_secret_in_an_older_commit_is_still_refused(self):
        """Deleting it in the next commit does not take it out of the one
        before, and both leave in the same push."""
        self.write("app.py", "SECRET = '%s'\n" % self.SECRET)
        self.commit("hardcode it", "app.py")
        self.write("app.py", "SECRET = ''\n")
        self.commit("take it out again", "app.py")
        self.assertNotEqual(self.push().returncode, 0)

    def test_a_secret_in_a_commit_message_is_refused(self):
        self.write("app.py", "x = 1\n")
        self.commit("rotated to %s" % self.SECRET, "app.py")
        self.assertNotEqual(self.push().returncode, 0)

    def test_a_private_key_block_is_refused(self):
        # Assembled at run time: the literal header in this file would be
        # refused by the very guard it tests.
        header = "-----BEGIN " + "EC PRIVATE KEY-----"
        self.write("key.txt", header + "\nMHcCAQEE\n")
        self.commit("a key", "key.txt")
        self.assertNotEqual(self.push().returncode, 0)

    def test_short_values_are_not_matched_even_under_a_credential_name(self):
        """A four-digit PIN matches every year and port number in the tree;
        matching it would refuse every push, and a guard that always refuses
        gets switched off."""
        self.write("app.py", "PORT = 1234\n")
        self.commit("a port", "app.py")
        self.assertEqual(self.push().returncode, 0)

    def test_only_credentials_are_matched_not_every_env_value(self):
        """A host list and a key path are not secrets: DJANGO_ALLOWED_HOSTS's
        value is also the default in settings.py, and matching it would
        refuse every commit of this repository."""
        self.write("settings.py", "ALLOWED_HOSTS = 'localhost,127.0.0.1'\n"
                                  "KEY = '/srv/secrets/issuer.pem'\n")
        self.commit("defaults", "settings.py")
        result = self.push()
        self.assertEqual(result.returncode, 0, result.stderr)


class PublishedDefaultsTest(TestCase):
    """This repository is published, so any default a script or the settings
    fall back on is known to everybody who can read it."""

    def _settings_with(self, **env):
        """Import verify.settings in a fresh interpreter with exactly this
        environment for the two variables that matter."""
        import subprocess
        import sys
        child = {k: v for k, v in os.environ.items()
                 if k not in ("DJANGO_SECRET_KEY", "DJANGO_ALLOWED_HOSTS")}
        child.update(env)
        return subprocess.run(
            [sys.executable, "-c",
             "import verify.settings as s; print(s.SECRET_KEY[:16])"],
            cwd=str(settings.BASE_DIR), env=child, capture_output=True,
            text=True)

    def test_a_reachable_site_refuses_to_start_without_a_key(self):
        """Signing sessions with a key printed in this repository is a login
        as anybody, with no symptom at all."""
        result = self._settings_with(DJANGO_ALLOWED_HOSTS="verify.example.org")
        self.assertNotEqual(result.returncode, 0, "started on the published key")
        self.assertIn("ImproperlyConfigured", result.stderr)

    def test_a_local_checkout_still_runs_without_one(self):
        """Tests, `manage.py check` and the measuring tools need no setup."""
        result = self._settings_with()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_key_from_the_environment_is_used(self):
        result = self._settings_with(DJANGO_ALLOWED_HOSTS="verify.example.org",
                                     DJANGO_SECRET_KEY="k" * 50)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "k" * 16)

    def test_the_deploy_script_carries_no_default_password(self):
        """No first superuser with a fixed password when none is configured:
        it would be a password written in a published file."""
        source = (settings.BASE_DIR / "deploy" / "deploy.sh").read_text(
            encoding="utf-8")
        self.assertIn("password = os.environ.get('DJANGO_SUPERUSER_PASSWORD')\n",
                      source)
        self.assertIn("    if password:\n        User.objects.create_superuser(",
                      source, "creates a superuser unconditionally")

    def test_the_demo_exports_carry_no_real_looking_phone_number(self):
        """A randomly drawn mobile number is some real subscriber's."""
        import glob
        import re
        for path in glob.glob(str(settings.BASE_DIR / "demo" / "exports" / "*.csv")):
            text = open(path, encoding="utf-8").read()
            numbers = set(re.findall(r"\+639\d{9}", text))
            self.assertLessEqual(numbers, {"+639170000000"}, path)


class StampSplitTest(TestCase):
    """`credentials.split_stamp`: a stamp is `<UUID>:CL03:<base45>`, and the
    first marker in the string is the real one."""

    UUID_TEXT = "0B7E4C1A-2F3D-4E5A-9B6C-7D8E9F0A1B2C"

    def test_the_marker_splits_at_the_uuid(self):
        from accounts import credentials
        self.assertEqual(credentials.split_stamp(self.UUID_TEXT + ":CL03:ABC"),
                         (self.UUID_TEXT, "CL03:", "ABC"))

    def test_the_reserved_marker_is_not_read(self):
        from accounts import credentials
        from ovcrypto import wire
        self.assertIsNone(credentials.split_stamp(
            self.UUID_TEXT + ":" + wire.LEGACY_QR_PREFIX + "ABC"))

    def test_the_first_marker_wins(self):
        from accounts import credentials
        self.assertEqual(credentials.split_stamp(self.UUID_TEXT + ":CL03:AB:CL03:CD"),
                         (self.UUID_TEXT, "CL03:", "AB:CL03:CD"))

    def test_no_marker_is_none(self):
        from accounts import credentials
        for text in ("", self.UUID_TEXT, "CL03:ABC", self.UUID_TEXT + ":CL03F1:ABC"):
            self.assertIsNone(credentials.split_stamp(text), text)

    def test_what_is_minted_says_cl03(self):
        from accounts import credentials
        from ovcrypto import wire
        self.assertEqual(wire.QR_PREFIX, "CL03:")
        self.assertEqual(credentials.compose("0b7e4c1a-2f3d-4e5a-9b6c-7d8e9f0a1b2c", "CL03:ABC"),
                         self.UUID_TEXT + ":CL03:ABC")
