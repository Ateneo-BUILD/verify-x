"""The tenant boundary: the eVerify address, and what an admin types.

Whatever answers at an organization's eVerify address decides who a verified
person is, so an admin who could point it at a server of their own could
have this site sign credentials, valid on every phone, for people who do not
exist. So:

  * the Organization page never writes the address, for anybody, and a
    request that tries is refused whole rather than half-applied;
  * the Site page, Setup and Django admin -- site administrators and staff
    -- are the only writers, they take https only (a copy too), and every
    change is logged with who made it;
  * a value stored before the https rule does not block other edits;
  * an organization admin cannot reach the address the long way round, by
    attaching an accomplice's digital ID to a site admin's row and letting
    the sign-in fallback do the rest.

A "card number" an organization admin types must never run as script in
another admin's browser, site administrators included. So:

  * both add-member endpoints take a 16-digit card number and a digital ID of
    letters and digits, nothing else;
  * the member list carries the number in a data attribute, so even a row
    stored before the rule renders as text;
  * and the page's Content-Security-Policy would refuse such a script
    anyway: no template has an inline handler at all (accounts/tests_csp.py).
"""

import json
import re
from unittest.mock import MagicMock, patch

from django.conf import settings
from django.forms import modelform_factory
from django.test import Client, TestCase, override_settings

from accounts import everify_address
from accounts.admin import OrganizationAdminForm
from accounts.models import Membership, Organization, SiteSettings, User
from accounts.tests import join, make_org
from verify.views.helpers import ORG_SESSION_KEY

SESSION_KEY = "verify_user_id"

PSA = "https://ws.everify.gov.ph/api"
ROGUE = "https://answers-anything.example/api"
PAYLOAD = "');alert(1)//"
LOGGER = "accounts.everify_address"


class TenantBoundaryBase(TestCase):
    def setUp(self):
        self.admin = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="ADM1234", given_name="Ada")
        self.org = make_org(name="Mine", everify_base_url=PSA,
                            everify_client_id="ORGCLIENT")
        join(self.org, self.admin, Membership.ROLE_ADMIN)
        self._sign_in(self.admin)

    def _sign_in(self, user):
        session = self.client.session
        session[SESSION_KEY] = user.id
        session[ORG_SESSION_KEY] = self.org.id
        session.save()

    def _post(self, url, payload):
        return self.client.post(url, data=json.dumps(payload),
                                content_type="application/json")

    def _site_admin(self):
        site_admin = User.objects.create(
            national_id_card_number="9999000011112222",
            digital_national_id="SIT1234", given_name="Sam", is_site_admin=True)
        self._sign_in(site_admin)
        return site_admin


#: A second host on the list, so that a change can be told from no change.
PSA2 = "https://ws2.everify.gov.ph/api"


@override_settings(EVERIFY_ALLOWED_HOSTS=["ws.everify.gov.ph", "ws2.everify.gov.ph"])
class EverifyAddressTest(TenantBoundaryBase):
    """The address is a site administrator's decision, within the hosts the
    server's operator allows."""

    def test_an_organization_admin_cannot_move_the_address(self):
        response = self._post("/app/admin/everify/",
                              {"everify_base_url": ROGUE,
                               "everify_client_id": "NEWCLIENT"})
        self.assertEqual(response.status_code, 403)
        self.org.refresh_from_db()
        self.assertEqual(self.org.everify_base_url, PSA)
        # Refused whole: nothing else in the request was applied either.
        self.assertEqual(self.org.everify_client_id, "ORGCLIENT")

    def test_nor_clear_it(self):
        response = self._post("/app/admin/everify/", {"everify_base_url": ""})
        self.assertEqual(response.status_code, 403)
        self.org.refresh_from_db()
        self.assertEqual(self.org.everify_base_url, PSA)

    def test_nor_can_a_site_admin_from_the_organization_page(self):
        """One writer, the Site page, whoever is asking."""
        self._site_admin()
        response = self._post("/app/admin/everify/", {"everify_base_url": ROGUE})
        self.assertEqual(response.status_code, 403)
        self.org.refresh_from_db()
        self.assertEqual(self.org.everify_base_url, PSA)

    def test_the_rest_of_the_client_still_saves_here(self):
        """The page no longer sends the address; an older page that sends it
        unchanged is not refused."""
        for payload in ({"everify_client_id": "NEWCLIENT",
                         "everify_client_secret": "new-secret"},
                        {"everify_base_url": PSA,
                         "everify_client_id": "NEWCLIENT2"}):
            response = self._post("/app/admin/everify/", payload)
            self.assertEqual(response.status_code, 200, payload)
        self.org.refresh_from_db()
        self.assertEqual(self.org.everify_base_url, PSA)
        self.assertEqual(self.org.everify_client_id, "NEWCLIENT2")
        self.assertEqual(self.org.everify_client_secret, "new-secret")

    def test_the_page_shows_the_address_and_does_not_send_it(self):
        page = self.client.get("/app/admin/").content.decode()
        field = re.search(r'<input[^>]*id="ev-base-url"[^>]*>', page).group(0)
        self.assertIn("readonly", field)
        self.assertIn(PSA, field)
        self.assertNotIn("everify_base_url:", page)
        self.assertIn("Set by a site administrator", page)
        # Only a site admin is pointed at the page that can change it.
        self.assertNotIn("Site page</a>", page)
        self._site_admin()
        page = self.client.get("/app/admin/").content.decode()
        self.assertIn(f'<a href="/app/site/organizations/{self.org.id}/">', page)
        self.assertIn("Site page</a>", page)

    def _site_page(self, base_url, **extra):
        form = {"name": self.org.name, "is_active": "on",
                "issuer_code": self.org.issuer_code or "",
                "everify_base_url": base_url}
        form.update(extra)
        return self.client.post(f"/app/site/organizations/{self.org.id}/", form)

    def test_the_site_page_sets_it_and_logs_who_did(self):
        site_admin = self._site_admin()
        new = PSA2
        with self.assertLogs(LOGGER, level="WARNING") as logs:
            self._site_page(new)
        self.org.refresh_from_db()
        self.assertEqual(self.org.everify_base_url, new)
        self.assertEqual(len(logs.records), 1)
        line = logs.output[0]
        self.assertIn(f"organization {self.org.id}", line)
        self.assertIn(f"user {site_admin.id}", line)
        self.assertIn(PSA, line)
        self.assertIn(new, line)

    def test_the_site_page_takes_https_only(self):
        self._site_admin()
        for bad in ("http://ws.everify.gov.ph/api", "ftp://x.example/",
                    "javascript:alert(1)", "https://", "not a url",
                    PSA + "/" + "a" * 240):
            response = self._site_page(bad)
            self.assertEqual(response.status_code, 200, bad)
            self.assertIn("eVerify base URL", response.content.decode(), bad)
            self.org.refresh_from_db()
            self.assertEqual(self.org.everify_base_url, PSA, bad)

    def test_an_unchanged_address_is_not_logged(self):
        self._site_admin()
        with self.assertNoLogs(LOGGER, level="WARNING"):
            self._site_page(PSA, subtitle="Edited")
        self.org.refresh_from_db()
        self.assertEqual(self.org.subtitle, "Edited")

    def test_a_stored_http_address_does_not_block_other_edits(self):
        """Rows saved before the https rule are not re-judged."""
        self.org.everify_base_url = "http://legacy.example/api"
        self.org.save()
        self._site_admin()
        self._site_page("http://legacy.example/api", subtitle="Edited")
        self.org.refresh_from_db()
        self.assertEqual(self.org.subtitle, "Edited")
        self.assertEqual(self.org.everify_base_url, "http://legacy.example/api")

    def _setup(self, base_url):
        return self.client.post("/app/setup/", {
            "login_mode": SiteSettings.LOGIN_EVERIFY,
            "everify_base_url": base_url,
            "everify_client_id": "SITECLIENT"})

    def test_setup_takes_https_only_and_logs_the_change(self):
        site_admin = self._site_admin()
        response = self._setup("http://ws.everify.gov.ph/api")
        self.assertIn("must be an https:// address", response.content.decode())
        self.assertNotEqual(SiteSettings.load().everify_base_url,
                            "http://ws.everify.gov.ph/api")
        new = PSA2
        with self.assertLogs(LOGGER, level="WARNING") as logs:
            self._setup(new)
        self.assertEqual(SiteSettings.load().everify_base_url, new)
        self.assertIn("site sign-in", logs.output[0])
        self.assertIn(f"user {site_admin.id}", logs.output[0])

    def test_the_rule_itself(self):
        self.assertEqual(everify_address.clean(f"  {PSA}  "), (PSA, ""))
        self.assertEqual(everify_address.clean(""), ("", ""))
        self.assertEqual(everify_address.clean(None), ("", ""))
        for bad in ("http://ws.everify.gov.ph/api", "//ws.everify.gov.ph",
                    "ws.everify.gov.ph/api", "https:///api"):
            url, error = everify_address.clean(bad)
            self.assertEqual(url, "", bad)
            self.assertTrue(error, bad)
        # A well-formed address that does not fit the column.
        self.assertEqual(everify_address.clean(PSA + "/" + "a" * 240),
                         ("", "The eVerify base URL is too long."))

    def test_a_malformed_request_is_refused_not_a_crash(self):
        self.assertEqual(self._post("/app/admin/everify/", [ROGUE]).status_code, 400)
        response = self._post("/app/admin/everify/", {"everify_base_url": [ROGUE]})
        self.assertEqual(response.status_code, 403)
        response = self._post("/app/admin/everify/", {"everify_client_id": 12345})
        self.assertEqual(response.status_code, 200)
        self.org.refresh_from_db()
        self.assertEqual(self.org.everify_base_url, PSA)
        self.assertEqual(self.org.everify_client_id, "12345")

    def test_a_copy_meets_the_rule_too(self):
        """Copying is a new setting for the target, even from a row saved
        before the rule."""
        self._site_admin()
        legacy = make_org(name="Legacy", everify_base_url="http://legacy.example/api")
        response = self._post(f"/app/site/organizations/{self.org.id}/copy-credentials/",
                              {"source_id": legacy.id})
        self.assertEqual(response.status_code, 400)
        self.assertIn("https://", json.loads(response.content)["message"])
        self.org.refresh_from_db()
        self.assertEqual(self.org.everify_base_url, PSA)
        good = make_org(name="Good", everify_base_url=PSA2)
        with self.assertLogs(LOGGER, level="WARNING"):
            response = self._post(
                f"/app/site/organizations/{self.org.id}/copy-credentials/",
                {"source_id": good.id})
        self.assertEqual(response.status_code, 200)
        self.org.refresh_from_db()
        self.assertEqual(self.org.everify_base_url, PSA2)

    def test_django_admin_meets_the_rule(self):
        form_class = modelform_factory(Organization, form=OrganizationAdminForm,
                                       fields=["everify_base_url"])
        self.assertFalse(form_class(data={"everify_base_url": PSA2.replace(
            "https", "http")}, instance=self.org).is_valid())
        self.assertFalse(form_class(data={"everify_base_url": ROGUE},
                                    instance=self.org).is_valid())
        self.assertTrue(form_class(data={"everify_base_url": PSA2},
                                   instance=self.org).is_valid())
        self.org.everify_base_url = "http://legacy.example/api"
        self.org.save()
        self.assertTrue(form_class(data={"everify_base_url": "http://legacy.example/api"},
                                   instance=self.org).is_valid())

    def test_django_admin_logs_the_change(self):
        from django.contrib.admin.sites import site
        from django.contrib.auth.models import User as DjangoUser
        from django.test import RequestFactory
        request = RequestFactory().post("/admin/")
        request.user = DjangoUser.objects.create_superuser("root", password="x")
        form_class = modelform_factory(Organization, form=OrganizationAdminForm,
                                       fields=["everify_base_url"])
        form = form_class(data={"everify_base_url": PSA2},
                          instance=self.org)
        self.assertTrue(form.is_valid())
        with self.assertLogs(LOGGER, level="WARNING") as logs:
            site._registry[Organization].save_model(
                request, form.save(commit=False), form, change=True)
        self.assertIn(f"django:{request.user.pk}", logs.output[0])
        self.assertIn(PSA, logs.output[0])


class AllowedHostsTest(TenantBoundaryBase):
    """The second layer: the hosts are the server operator's list, and no
    page -- not even a site administrator's -- can send a lookup elsewhere."""

    def test_the_default_list_is_psas_host_alone(self):
        self.assertEqual(settings.EVERIFY_ALLOWED_HOSTS, ["ws.everify.gov.ph"])
        self.assertTrue(everify_address.allowed(PSA))
        self.assertFalse(everify_address.allowed(PSA2))
        self.assertFalse(everify_address.allowed("http://ws.everify.gov.ph/api"))
        self.assertFalse(everify_address.allowed("https://ws.everify.gov.ph.evil.example/api"))
        self.assertFalse(everify_address.allowed("https://user@evil.example/ws.everify.gov.ph"))

    @override_settings(EVERIFY_ALLOWED_HOSTS=[])
    def test_an_empty_list_allows_nothing(self):
        self.assertFalse(everify_address.allowed(PSA))

    def test_a_site_admin_cannot_save_a_host_off_the_list(self):
        self._site_admin()
        response = self.client.post(f"/app/site/organizations/{self.org.id}/", {
            "name": self.org.name, "is_active": "on",
            "issuer_code": self.org.issuer_code or "", "everify_base_url": ROGUE})
        self.assertIn("EVERIFY_ALLOWED_HOSTS", response.content.decode())
        self.org.refresh_from_db()
        self.assertEqual(self.org.everify_base_url, PSA)
        self.client.post("/app/setup/", {"login_mode": SiteSettings.LOGIN_EVERIFY,
                                         "everify_base_url": ROGUE})
        self.assertNotEqual(SiteSettings.load().everify_base_url, ROGUE)
        rogue = make_org(name="Rogue", everify_base_url=ROGUE)
        response = self._post(f"/app/site/organizations/{self.org.id}/copy-credentials/",
                              {"source_id": rogue.id})
        self.assertEqual(response.status_code, 400)

    def test_a_stored_host_off_the_list_sends_nothing(self):
        """A row saved before the list, or written behind the pages' backs."""
        Organization.objects.filter(pk=self.org.pk).update(everify_base_url=ROGUE)
        operator = User.objects.create(national_id_card_number="6000000000000001")
        join(self.org, operator)
        self._sign_in(operator)
        with patch("verify.views.everify.requests.post") as post, \
                self.assertLogs("verify.views.everify", level="ERROR"):
            response = self.client.post("/everify/", data=json.dumps(
                {"value": "1234567890123456", "face_liveness_session_id": "sess"}),
                content_type="application/json")
        self.assertEqual(response.status_code, 503)
        self.assertIn("not one this server allows", json.loads(response.content)["message"])
        post.assert_not_called()

    def test_nor_does_a_sign_in_client_off_the_list(self):
        site = SiteSettings.load()
        site.everify_base_url, site.everify_client_id = ROGUE, "id"
        site.everify_client_secret = "secret"
        site.save()
        User.objects.create(national_id_card_number="6000000000000002")
        with patch("verify.views.everify.requests.post") as post, \
                self.assertLogs("verify.views.everify", level="ERROR"):
            response = Client().post("/everify/", data=json.dumps(
                {"value": "6000000000000002", "face_liveness_session_id": "sess"}),
                content_type="application/json")
        self.assertEqual(response.status_code, 500)
        self.assertIn("This site's eVerify address is not one this server allows",
                      json.loads(response.content)["message"])
        post.assert_not_called()

    def test_no_request_starts_for_an_address_off_the_list(self):
        """The client itself refuses, whichever view holds it."""
        from verify.views.everify import EverifyClient, get_everify_access_token
        client = EverifyClient(ROGUE, "id", "secret", "", "organization")
        self.assertFalse(client.configured)
        with patch("verify.views.everify.requests.post") as post:
            self.assertIsNone(get_everify_access_token(client))
        post.assert_not_called()
        self.assertTrue(EverifyClient(PSA, "id", "secret", "", "organization").configured)

    #: Read as PSA's host by one parser and as another by the next, or carrying
    #: something no eVerify address needs. The first is the one that worked:
    #: urlparse said ws.everify.gov.ph, requests connected to evil.example.
    TRICKS = ("https://evil.example\\@ws.everify.gov.ph/api",
              "https://evil.example@ws.everify.gov.ph/api",
              "https://user:pw@ws.everify.gov.ph/api",
              "https://ws.everify.gov.ph\\@evil.example/api",
              "https://ws.everify.gov.ph /api", "https://ws.everify.gov.ph\t/api",
              "https://ws.everify.gov.ph\r\n/api", "https://ws.everify.gov.ph\x00/api",
              "https:\\\\ws.everify.gov.ph/api", "https://evil.example#@ws.everify.gov.ph")

    def test_no_parser_trick_passes(self):
        for url in self.TRICKS:
            self.assertFalse(everify_address.allowed(url), repr(url))
            self.assertTrue(everify_address.clean(url)[1], repr(url))
        self.assertTrue(everify_address.allowed("https://WS.everify.gov.ph:443/api"))

    def test_the_two_parsers_must_agree(self):
        """No known address splits them once the unsafe characters are gone;
        this is the net for the one nobody has found yet."""
        from urllib3.util import parse_url
        with patch("accounts.everify_address.parse_url",
                   return_value=parse_url("https://evil.example/api")):
            self.assertFalse(everify_address.allowed(PSA))

    def test_a_site_admin_cannot_save_one(self):
        self._site_admin()
        for url in self.TRICKS[:2]:
            self.client.post(f"/app/site/organizations/{self.org.id}/", {
                "name": self.org.name, "is_active": "on",
                "issuer_code": self.org.issuer_code or "", "everify_base_url": url})
            self.client.post("/app/setup/", {"login_mode": SiteSettings.LOGIN_EVERIFY,
                                             "everify_base_url": url})
        self.org.refresh_from_db()
        self.assertEqual(self.org.everify_base_url, PSA)
        self.assertNotIn("evil", SiteSettings.load().everify_base_url)

    def test_no_redirect_is_followed_with_the_secret(self):
        """A 307 or 308 would carry the body -- the secret -- wherever it pointed."""
        from verify.views.everify import EverifyClient, get_everify_access_token
        with patch("verify.views.everify.requests.post",
                   return_value=MagicMock(status_code=307, text="")) as post:
            get_everify_access_token(EverifyClient(PSA, "id", "secret", "", "site"))
        self.assertIs(post.call_args.kwargs.get("allow_redirects"), False)
        import inspect
        from verify.views import everify
        source = inspect.getsource(everify)
        self.assertEqual(source.count("requests.post("), 2)
        self.assertEqual(source.count("allow_redirects=False"), 2)


def _upstream(data):
    response = MagicMock(status_code=200)
    response.json.return_value = {"data": data}
    return response


class EverifySignInMixin:
    """Sign in through /everify/ with the upstream mocked to answer `code`
    and `reference`."""

    ACCOMPLICE_CARD = "7777888899990000"

    def _everify_sign_in(self, client, code, reference):
        patches = (
            patch("verify.views.everify.EVERIFY_CLIENT_ID", "id"),
            patch("verify.views.everify.EVERIFY_CLIENT_SECRET", "secret"),
            patch("verify.views.everify.get_everify_access_token", return_value="tok"),
            patch("verify.views.everify.requests.post",
                  return_value=_upstream({"reference": reference, "code": code,
                                          "first_name": "Acc", "last_name": "Omplice"})),
        )
        for p in patches:
            p.start()
        try:
            return client.post("/everify/", data=json.dumps(
                {"value": code, "face_liveness_session_id": "sess"}),
                content_type="application/json")
        finally:
            for p in patches:
                p.stop()


class DigitalIdTest(EverifySignInMixin, TenantBoundaryBase):
    """Sign-in falls back to the digital ID when eVerify's card number matches
    no row, so an organization admin who could attach an accomplice's
    digital ID to a site admin's row could have the accomplice sign in as
    the site admin -- who sets the address."""

    def test_an_admin_cannot_plant_a_digital_id_on_a_site_admin(self):
        target = User.objects.create(national_id_card_number="9999000011112222",
                                     given_name="Sam", is_site_admin=True)
        self._post("/app/admin/add-user/",
                   {"national_id_card_number": "9999-0000-1111-2222",
                    "digital_national_id": "ACC1234"})
        target.refresh_from_db()
        self.assertEqual(target.digital_national_id, "")
        accomplice = Client()
        self._everify_sign_in(accomplice, code="ACC1234", reference=self.ACCOMPLICE_CARD)
        self.assertNotEqual(accomplice.session.get(SESSION_KEY), target.id)

    def test_nor_on_anybody_else_already_claimed(self):
        other_org = make_org(name="Theirs")
        claimed = {
            "theirs": User.objects.create(national_id_card_number="2000000000000001"),
            "signed in": User.objects.create(national_id_card_number="2000000000000002"),
            "holder": User.objects.create(national_id_card_number="2000000000000003",
                                          registered_via=User.REGISTERED_VIA_IDMANAGER),
        }
        join(other_org, claimed["theirs"])
        claimed["signed in"].last_login = claimed["signed in"].date_created
        claimed["signed in"].save()
        for name, row in claimed.items():
            self._post("/app/admin/add-user/",
                       {"national_id_card_number": row.national_id_card_number,
                        "digital_national_id": "ACC1234"})
            row.refresh_from_db()
            self.assertEqual(row.digital_national_id, "", name)

    def test_their_own_card_only_member_can_still_be_given_one(self):
        """The page's own advice: post a "card number only" member again with
        the digital ID printed on the same card."""
        member = User.objects.create(national_id_card_number="3000000000000001")
        join(self.org, member)
        response = self._post("/app/admin/add-user/",
                              {"national_id_card_number": "3000000000000001",
                               "digital_national_id": "MEM1234"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("MEM1234 added", json.loads(response.content)["message"])
        member.refresh_from_db()
        self.assertEqual(member.digital_national_id, "MEM1234")
        # And a new person's digital ID is kept as typed.
        self._post("/app/admin/add-user/",
                   {"national_id_card_number": "3000000000000002",
                    "digital_national_id": "NEW1234"})
        self.assertEqual(User.objects.get(
            national_id_card_number="3000000000000002").digital_national_id, "NEW1234")


class SignInCardMismatchTest(EverifySignInMixin, TenantBoundaryBase):
    """The digital ID is a fallback, never a way into a row that holds a
    different card number."""

    def setUp(self):
        super().setUp()
        self.member = User.objects.create(national_id_card_number="4000000000000001",
                                          digital_national_id="MEM1234")
        join(self.org, self.member)

    def _signed_in_as(self, code, reference):
        client = Client()
        self.last_response = self._everify_sign_in(client, code=code, reference=reference)
        return client.session.get(SESSION_KEY)

    def test_a_different_card_is_refused_and_logged(self):
        with self.assertLogs("verify.views.helpers", level="WARNING") as logs:
            who = self._signed_in_as("MEM1234", self.ACCOMPLICE_CARD)
        self.assertIsNone(who)
        self.assertIn(f"user {self.member.id}", logs.output[0])
        self.assertIn("ends 0001", logs.output[0])
        self.assertNotIn(self.ACCOMPLICE_CARD, logs.output[0])

    def test_the_refused_person_is_told_why(self):
        """Not a "success" that lands them back on the sign-in page."""
        from verify.views.everify import CARD_MISMATCH_MESSAGE
        self._signed_in_as("MEM1234", self.ACCOMPLICE_CARD)
        self.assertEqual(self.last_response.status_code, 403)
        body = json.loads(self.last_response.content)
        self.assertEqual(body["message"], CARD_MISMATCH_MESSAGE)
        self.assertNotIn("redirect", body)

    def test_the_same_card_signs_in(self):
        self.assertEqual(self._signed_in_as("MEM1234", "4000000000000001"), self.member.id)

    def test_no_card_to_compare_still_falls_back(self):
        """The upstream returned no card number: the digital ID is all there is."""
        self.assertEqual(self._signed_in_as("MEM1234", ""), self.member.id)

    def test_a_row_without_a_card_falls_back_and_learns_it(self):
        bare = User.objects.create(national_id_card_number="", digital_national_id="BAR1234")
        join(self.org, bare)
        self.assertEqual(self._signed_in_as("BAR1234", "4000000000000009"), bare.id)
        bare.refresh_from_db()
        self.assertEqual(bare.national_id_card_number, "4000000000000009")

    def test_sso_meets_the_same_rule(self):
        from verify.views.helpers import _find_user
        self.assertIsNone(_find_user("MEM1234", pcn=self.ACCOMPLICE_CARD))
        self.assertEqual(_find_user("mem1234", pcn="4000-0000-0000-0001"), self.member)


class DjangoBridgeTest(EverifySignInMixin, TenantBoundaryBase):
    """A Django staff account is bound to the row the bridge made for it,
    found by the card number only the bridge writes -- and that row is
    reached by a Django login and nothing else."""

    def _staff_opens_the_app(self, username):
        from django.contrib.auth.models import User as DjangoUser
        staff = DjangoUser.objects.create_user(username, password="x", is_staff=True)
        client = Client()
        client.force_login(staff)
        client.get("/app/")
        return staff, client

    def test_a_planted_row_is_not_adopted(self):
        self._post("/app/admin/add-user/",
                   {"national_id_card_number": "5555666677778888",
                    "digital_national_id": "OPSADMIN"})
        planted = User.objects.get(national_id_card_number="5555666677778888")
        staff, client = self._staff_opens_the_app("OPSADMIN")
        planted.refresh_from_db()
        self.assertFalse(planted.is_site_admin)
        bridged = User.objects.get(pk=client.session[SESSION_KEY])
        self.assertNotEqual(bridged.pk, planted.pk)
        self.assertEqual(bridged.national_id_card_number, "ADMIN%011d" % staff.id)
        # Staff, not a superuser: an admin of every organization.
        self.assertTrue(bridged.is_all_org_admin)

    def test_the_bridge_finds_its_own_row_again(self):
        staff, first = self._staff_opens_the_app("opsadmin")
        again = Client()
        again.force_login(staff)
        again.get("/app/")
        self.assertEqual(first.session[SESSION_KEY], again.session[SESSION_KEY])
        self.assertEqual(User.objects.filter(
            national_id_card_number="ADMIN%011d" % staff.id).count(), 1)

    def test_sign_in_never_reaches_a_bridge_row(self):
        """Its digital ID is the staff username, so an upstream answer naming
        that and no card would otherwise sign in as a site admin."""
        from verify.views import login_guard
        from verify.views.helpers import _find_user
        staff, client = self._staff_opens_the_app("ZZZ9999")
        bridged = User.objects.get(pk=client.session[SESSION_KEY])
        for code, reference in (("ZZZ9999", ""), ("ZZZ9999", bridged.national_id_card_number)):
            outsider = Client()
            self._everify_sign_in(outsider, code=code, reference=reference)
            self.assertNotEqual(outsider.session.get(SESSION_KEY), bridged.pk)
        self.assertIsNone(_find_user("ZZZ9999", pcn=""))
        self.assertIsNone(_find_user("", pcn=bridged.national_id_card_number))
        self.assertIsNone(login_guard.registered_operator("ZZZ9999"))
        self.assertIsNone(login_guard.registered_operator(bridged.national_id_card_number))

    def test_rows_the_old_bridge_may_have_promoted_are_reported(self):
        """Not changed: nothing can tell a planted row from a real site admin."""
        from django.contrib.auth.models import User as DjangoUser
        from django.core import checks
        DjangoUser.objects.create_user("OPSADMIN", password="x", is_staff=True)
        promoted = User.objects.create(national_id_card_number="5555666677778888",
                                       digital_national_id="OPSADMIN", is_site_admin=True)
        User.objects.create(national_id_card_number="5555666677770000",
                            digital_national_id="NOTSTAFF", is_site_admin=True)
        DjangoUser.objects.create_user("OPSPLAIN", password="x", is_staff=True)
        User.objects.create(national_id_card_number="5555666677771111",
                            digital_national_id="OPSPLAIN")  # not a site admin
        self._staff_opens_the_app("opsbridge")  # its own ADMIN row: not reported
        found = [m for m in checks.run_checks(databases=["default"],
                                              tags=[checks.Tags.database])
                 if m.id == "accounts.W001"]
        self.assertEqual(len(found), 1)
        self.assertIn(f"verify user {promoted.pk} (card ending 8888)", found[0].msg)
        promoted.refresh_from_db()
        self.assertTrue(promoted.is_site_admin)

    def test_the_check_never_stops_a_migrate(self):
        """migrate runs it before applying anything, on whatever schema is there."""
        from django.core import checks
        from django.db import OperationalError
        with patch("accounts.models.User.objects") as objects:
            objects.filter.side_effect = OperationalError("no such column: Users.new_thing")
            messages = checks.run_checks(databases=["default"], tags=[checks.Tags.database])
        self.assertFalse([m for m in messages if m.id == "accounts.W001"])


class MemberIdTest(TenantBoundaryBase):
    """What an admin types is held to the shapes sign-in reads."""

    def test_an_organization_admin_cannot_store_script_as_a_card_number(self):
        response = self._post("/app/admin/add-user/",
                              {"national_id_card_number": PAYLOAD, "role": "admin"})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(User.objects.filter(national_id_card_number=PAYLOAD).exists())

    def test_nor_can_a_site_admin(self):
        self._site_admin()
        response = self._post(f"/app/site/organizations/{self.org.id}/members/",
                              {"national_id_card_number": PAYLOAD})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(User.objects.filter(national_id_card_number=PAYLOAD).exists())

    def test_card_numbers_are_sixteen_digits(self):
        site_admin = self._site_admin()
        for bad in ("123456789012345", "12345678901234567", "1234-5678-9012-345X",
                    "ADMIN00000000001", "１２３４５６７８９０１２３４５６"):
            for url, who in (("/app/admin/add-user/", self.admin),
                             (f"/app/site/organizations/{self.org.id}/members/",
                              site_admin)):
                self._sign_in(who)
                response = self._post(url, {"national_id_card_number": bad})
                self.assertEqual(response.status_code, 400, (bad, url))
        self.assertEqual(User.objects.count(), 2)

    def test_a_printed_card_number_is_still_accepted(self):
        response = self._post("/app/admin/add-user/",
                              {"national_id_card_number": " 5555-6666 7777-8888 ",
                               "digital_national_id": "abc1234"})
        self.assertEqual(response.status_code, 200)
        added = User.objects.get(national_id_card_number="5555666677778888")
        self.assertEqual(added.digital_national_id, "ABC1234")

    def test_digital_ids_are_letters_and_digits(self):
        for bad in ("ABC 1234", "ABC'1234", "<b>", "A" * 21):
            response = self._post("/app/admin/add-user/",
                                  {"national_id_card_number": "5555666677778888",
                                   "digital_national_id": bad})
            self.assertEqual(response.status_code, 400, bad)
        self.assertFalse(User.objects.filter(
            national_id_card_number="5555666677778888").exists())

    def test_a_row_stored_before_the_rule_renders_as_text(self):
        """The output side holds on its own: a stored value never reaches a
        handler's script, only an attribute the HTML escaping protects."""
        legacy = User.objects.create(national_id_card_number=PAYLOAD)
        join(self.org, legacy)
        page = self.client.get("/app/admin/").content.decode()
        button = re.search(
            r'<button class="btn-remove" data-remove-user="%d"[^>]*>' % legacy.id,
            page).group(0)
        self.assertIn('data-remove-label="&#x27;);alert(1)//"', button)
        self.assertNotIn("onclick", button)
        for script in re.findall(r"<script\b[^>]*>(.*?)</script>", page, re.S):
            self.assertNotIn("alert(1)", script)
