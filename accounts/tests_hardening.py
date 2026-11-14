"""The transactions export's cells, who may grant the restricted tier, the
single sign-on issuers a site allows, the Django-admin bridge, what Django
admin may change and revoke, and the per-address limits on what anybody
can reach without signing in.
"""

import csv
import io
import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from accounts import sso_issuer
from accounts.models import (Membership, SiteSettings, Transaction, User,
                             bridge_card)
from accounts.tests import join, make_org
from verify.views import sso
from verify.views.helpers import ORG_SESSION_KEY

SESSION_KEY = "verify_user_id"


def sign_in(client, user, org=None):
    session = client.session
    session[SESSION_KEY] = user.id
    if org is not None:
        session[ORG_SESSION_KEY] = org.id
    session.save()


class TransactionExportFormulaTest(TestCase):
    """Every cell of the transactions export is guarded, and the filename
    takes only real dates."""

    def setUp(self):
        self.admin = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="ADM1234", given_name="Ada")
        self.org = make_org(name="Mine")
        join(self.org, self.admin, Membership.ROLE_ADMIN)
        sign_in(self.client, self.admin, self.org)

    def _export(self, query=""):
        response = self.client.get("/app/admin/export-transactions/" + query)
        self.assertEqual(response.status_code, 200)
        return response, list(csv.reader(io.StringIO(response.content.decode())))

    def _cells(self, rows):
        return [cell for row in rows[1:] for cell in row]

    def test_no_cell_of_any_row_leaves_as_a_formula(self):
        Transaction.objects.create(
            organization=self.org, given_name="=HYPERLINK(\"x\")",
            last_name="+1", middle_name="-2", date_of_birth="@SUM(A1)",
            operator_location="\t=cmd", transaction_type="=tt",
            operator_national_id_number="=op", authentication_result="failure")
        _, rows = self._export()
        cells = self._cells(rows)
        for lead in ("=", "+", "-", "@", "\t"):
            self.assertFalse([c for c in cells if c.startswith(lead)],
                             "a cell starts with %r" % lead)
        self.assertIn("'=HYPERLINK(\"x\")", cells)
        self.assertIn("'=tt", cells)
        self.assertIn("'=op", cells)
        self.assertIn("'\t=cmd", cells)

    def test_plain_text_is_left_alone(self):
        Transaction.objects.create(organization=self.org, given_name="Juan",
                                   authentication_result="success")
        _, rows = self._export()
        self.assertIn("Juan", self._cells(rows))
        self.assertIn("success", self._cells(rows))

    def test_the_filename_takes_only_real_dates(self):
        response, _ = self._export('?start=2026-11-01&end=x";evil=1')
        self.assertEqual(
            response["Content-Disposition"],
            'attachment; filename="transactions_mine_2026-11-01_all.csv"')


class FailureRowTest(TestCase):
    """What a failed attempt writes into the log."""

    def setUp(self):
        self.operator = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="OPS1234", given_name="Ops")
        self.org = make_org(name="Mine", locations=("Front Desk",))
        self.other = make_org(name="Other", locations=("Their Desk",))
        join(self.org, self.operator)
        sign_in(self.client, self.operator, self.org)

    def _fail(self, **body):
        body.setdefault("failure_detail", "cancelled")
        response = self.client.post("/everify/log-liveness-failure/",
                                    data=json.dumps(body),
                                    content_type="application/json")
        self.assertEqual(response.status_code, 200)
        return Transaction.objects.latest("verification_timestamp")

    def test_posted_location_text_is_never_written(self):
        row = self._fail(operator_location="=HYPERLINK(\"evil\")")
        self.assertEqual(row.operator_location, "")
        self.assertIsNone(row.location_ref)

    def test_another_organizations_location_is_not_written(self):
        theirs = self.other.locations.get()
        row = self._fail(operator_location=str(theirs.id))
        self.assertEqual(row.operator_location, "")

    def test_a_location_of_the_organization_is_written_by_name(self):
        mine = self.org.locations.get()
        row = self._fail(operator_location=str(mine.id))
        self.assertEqual(row.operator_location, "Front Desk")
        self.assertEqual(row.location_ref, mine)

    def test_a_card_number_goes_in_the_card_column(self):
        row = self._fail(value="1234-5678-9012-3456")
        self.assertEqual(row.national_id_card_number, "1234567890123456")
        self.assertEqual(row.digital_national_id_number, "")

    def test_a_digital_id_goes_in_the_digital_column(self):
        row = self._fail(value="abc1234")
        self.assertEqual(row.digital_national_id_number, "ABC1234")
        self.assertEqual(row.national_id_card_number, "")

    def test_anything_else_goes_in_neither(self):
        for value in ("=1+1", "@SUM(A1)", "+63 917", "ab.c", "A" * 21):
            row = self._fail(value=value)
            self.assertEqual(row.national_id_card_number, "", value)
            self.assertEqual(row.digital_national_id_number, "", value)


class RestrictedTierGrantTest(TestCase):
    """Only a site administrator grants the restricted tier, and every grant
    is recorded with who and when."""

    def setUp(self):
        self.org = make_org(name="Mine")
        self.org_admin = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="ADM1234", given_name="Ada")
        join(self.org, self.org_admin, Membership.ROLE_ADMIN)
        self.site_admin = User.objects.create(
            national_id_card_number="9999888877776666",
            digital_national_id="SITE123", given_name="Sam", is_site_admin=True)

    def _post(self, url, payload):
        return self.client.post(url, data=json.dumps(payload),
                                content_type="application/json")

    def _tier_url(self, person):
        return reverse("site_restricted_tier", args=[person.pk])

    def test_a_person_an_organization_admin_adds_starts_without_it(self):
        sign_in(self.client, self.org_admin, self.org)
        with self.assertLogs("verify.views.orgs", "WARNING") as logs:
            response = self._post("/app/admin/add-user/",
                                  {"national_id_card_number": "5555666677778888"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("site administrator", response.json()["message"])
        added = User.objects.get(national_id_card_number="5555666677778888")
        self.assertFalse(added.device_restricted_tier)
        self.assertIsNone(added.restricted_tier_granted_at)
        self.assertIn("added new user %s" % added.pk, logs.output[0])

    def test_an_existing_person_keeps_what_they_have(self):
        known = User.objects.create(national_id_card_number="5555666677778888")
        sign_in(self.client, self.org_admin, self.org)
        response = self._post("/app/admin/add-user/",
                              {"national_id_card_number": "5555666677778888"})
        self.assertEqual(response.json()["message"], "5555666677778888 added.")
        known.refresh_from_db()
        self.assertTrue(known.device_restricted_tier)

    def test_a_site_admins_add_is_the_grant_and_is_recorded(self):
        sign_in(self.client, self.site_admin)
        response = self._post(reverse("site_assign_member", args=[self.org.pk]),
                              {"national_id_card_number": "5555666677778888"})
        self.assertEqual(response.status_code, 200)
        added = User.objects.get(national_id_card_number="5555666677778888")
        self.assertTrue(added.device_restricted_tier)
        self.assertEqual(added.restricted_tier_granted_by, self.site_admin)
        self.assertIsNotNone(added.restricted_tier_granted_at)

    def test_a_site_admins_add_of_somebody_known_grants_nothing(self):
        known = User.objects.create(national_id_card_number="5555666677778888",
                                    device_restricted_tier=False)
        sign_in(self.client, self.site_admin)
        self._post(reverse("site_assign_member", args=[self.org.pk]),
                   {"national_id_card_number": "5555666677778888"})
        known.refresh_from_db()
        self.assertFalse(known.device_restricted_tier)

    def test_an_organization_admin_cannot_grant_it(self):
        person = User.objects.create(national_id_card_number="5555666677778888",
                                     device_restricted_tier=False)
        join(self.org, person)
        sign_in(self.client, self.org_admin, self.org)
        response = self._post(self._tier_url(person), {"grant": True})
        self.assertEqual(response.status_code, 403)
        person.refresh_from_db()
        self.assertFalse(person.device_restricted_tier)

    def test_a_site_admin_grants_and_withdraws_on_the_record(self):
        person = User.objects.create(national_id_card_number="5555666677778888",
                                     device_restricted_tier=False)
        sign_in(self.client, self.site_admin)
        with self.assertLogs("accounts.restricted_tier", "WARNING") as logs:
            response = self._post(self._tier_url(person), {"grant": True})
        self.assertEqual(response.json()["granted"], True)
        person.refresh_from_db()
        self.assertTrue(person.device_restricted_tier)
        self.assertEqual(person.restricted_tier_granted_by, self.site_admin)
        self.assertIn("granted to user %s by user %s" % (person.pk, self.site_admin.pk),
                      logs.output[0])

        response = self._post(self._tier_url(person), {"grant": False})
        self.assertEqual(response.json()["granted"], False)
        person.refresh_from_db()
        self.assertFalse(person.device_restricted_tier)
        self.assertIsNone(person.restricted_tier_granted_by)
        self.assertIsNone(person.restricted_tier_granted_at)

    def test_only_true_or_false_is_an_answer(self):
        person = User.objects.create(national_id_card_number="5555666677778888",
                                     device_restricted_tier=False)
        sign_in(self.client, self.site_admin)
        for body in ({"grant": "yes"}, {"grant": 1}, {}, ["grant"]):
            self.assertEqual(self._post(self._tier_url(person), body).status_code,
                             400, body)
        person.refresh_from_db()
        self.assertFalse(person.device_restricted_tier)

    def test_a_holder_is_refused(self):
        holder = User.objects.create(
            national_id_card_number="5555666677778888", device_restricted_tier=False,
            registered_via=User.REGISTERED_VIA_IDMANAGER)
        sign_in(self.client, self.site_admin)
        self.assertEqual(self._post(self._tier_url(holder), {"grant": True}).status_code,
                         400)

    def test_setup_lists_everybody_who_has_it_and_withdraws_there(self):
        granted = User.objects.create(national_id_card_number="5555666677778888",
                                      given_name="Gina")
        User.objects.create(national_id_card_number="4444555566667777",
                            given_name="Nora", device_restricted_tier=False)
        sign_in(self.client, self.site_admin)
        page = self.client.get(reverse("setup"))
        people = page.context["restricted_people"]
        self.assertIn(granted, people)
        self.assertNotIn("Nora", [p.given_name for p in people])
        self.assertContains(page, "Granted before grants were recorded")
        self.assertContains(page, self._tier_url(granted))

        response = self.client.post(self._tier_url(granted), {"grant": "0"})
        self.assertRedirects(response, reverse("setup") + "#restricted-tier",
                             fetch_redirect_response=False)
        granted.refresh_from_db()
        self.assertFalse(granted.device_restricted_tier)

    def test_setup_shows_no_list_to_anybody_else(self):
        sign_in(self.client, self.org_admin, self.org)
        page = self.client.get(reverse("setup"))
        self.assertNotIn("restricted_people", page.context)
        self.assertNotContains(page, 'id="restricted-tier"')

    def test_the_site_organization_page_has_the_switch(self):
        person = User.objects.create(national_id_card_number="5555666677778888",
                                     device_restricted_tier=False)
        join(self.org, person)
        sign_in(self.client, self.site_admin)
        page = self.client.get(reverse("site_organization", args=[self.org.pk]))
        self.assertContains(page, 'data-tier-url="%s"' % self._tier_url(person))
        self.assertContains(page, "Phones read details")

    def test_a_change_in_django_admin_is_recorded(self):
        root = get_user_model().objects.create_superuser("root", "r@example.org", "pw")
        actor = User.objects.create(national_id_card_number=bridge_card(root.pk),
                                    is_site_admin=True)
        person = User.objects.create(national_id_card_number="5555666677778888",
                                     device_restricted_tier=False)
        self.client.force_login(root)
        url = reverse("admin:accounts_user_change", args=[person.pk])
        response = self.client.post(url, {
            "national_id_card_number": person.national_id_card_number,
            "digital_national_id": "", "given_name": "", "middle_name": "",
            "last_name": "", "device_restricted_tier": "on",
            "memberships-TOTAL_FORMS": "0", "memberships-INITIAL_FORMS": "0",
            "memberships-MIN_NUM_FORMS": "0", "memberships-MAX_NUM_FORMS": "1000",
        })
        self.assertEqual(response.status_code, 302)
        person.refresh_from_db()
        self.assertTrue(person.device_restricted_tier)
        self.assertEqual(person.restricted_tier_granted_by, actor)
        self.assertIsNotNone(person.restricted_tier_granted_at)


ALLOWED_ISSUER = "https://sso.example.ph/o"
ROGUE_ISSUER = "https://rogue.example/o"


@override_settings(SSO_ALLOWED_ISSUERS=[ALLOWED_ISSUER])
class SsoIssuerTest(TestCase):
    """The issuer is the server's to allow."""

    BASE = {"fingerprint_auth_endpoint": "", "serial_number": "0"}

    def setUp(self):
        self.site_admin = User.objects.create(
            national_id_card_number="9999888877776666",
            digital_national_id="SITE123", given_name="Sam", is_site_admin=True)
        self.operator = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="OPR1234", given_name="Ada")
        self.org = make_org()
        join(self.org, self.operator)
        self.site = SiteSettings.load()
        # Migration 0015 seeded the row with an issuer; start from none.
        self.site.sso_issuer = ""
        self.site.sso_client_id = "verify"
        self.site.sso_client_secret = "s3cret"
        self.site.save()

    def _store(self, issuer, mode=SiteSettings.LOGIN_SSO):
        SiteSettings.objects.filter(pk=self.site.pk).update(sso_issuer=issuer,
                                                            login_mode=mode)
        self.site.refresh_from_db()

    def _setup(self, **fields):
        sign_in(self.client, self.site_admin)
        return self.client.post(reverse("setup"), dict(self.BASE, **fields))

    def test_only_a_listed_https_issuer_is_allowed(self):
        self.assertTrue(sso_issuer.allowed(ALLOWED_ISSUER))
        self.assertTrue(sso_issuer.allowed(ALLOWED_ISSUER + "/"))
        for issuer in (ROGUE_ISSUER, "http://sso.example.ph/o", "https://sso.example.ph/o/x",
                       "https://sso.example.ph", "https://evil\\@sso.example.ph/o",
                       "https://x@sso.example.ph/o", "", None):
            self.assertFalse(sso_issuer.allowed(issuer), issuer)

    @override_settings(SSO_ALLOWED_ISSUERS=[])
    def test_an_empty_list_allows_nothing(self):
        self.assertFalse(sso_issuer.allowed(ALLOWED_ISSUER))
        issuer, error = sso_issuer.clean(ALLOWED_ISSUER)
        self.assertEqual(issuer, "")
        self.assertIn("SSO_ALLOWED_ISSUERS", error)

    def test_setup_will_not_save_an_issuer_the_server_does_not_list(self):
        response = self._setup(login_mode="everify", sso_issuer=ROGUE_ISSUER,
                               sso_client_id="verify")
        self.assertContains(response, "SSO issuer must be one this server allows")
        self.site.refresh_from_db()
        self.assertEqual(self.site.sso_issuer, "")

    def test_setup_saves_a_listed_issuer_and_logs_who(self):
        with self.assertLogs("accounts.sso_issuer", "WARNING") as logs:
            self._setup(login_mode="sso", sso_issuer=ALLOWED_ISSUER, sso_client_id="verify")
        self.site.refresh_from_db()
        self.assertEqual(self.site.sso_issuer, ALLOWED_ISSUER)
        self.assertEqual(self.site.login_mode, SiteSettings.LOGIN_SSO)
        self.assertIn("changed by user %s" % self.site_admin.pk, logs.output[0])

    def test_setup_lists_the_allowed_issuers(self):
        sign_in(self.client, self.site_admin)
        self.assertContains(self.client.get(reverse("setup")), ALLOWED_ISSUER)

    def test_a_stored_issuer_that_is_not_listed_is_not_sso(self):
        self._store(ROGUE_ISSUER)
        self.assertFalse(self.site.sso_login_active)
        self.assertTrue(self.site.sso_issuer_refused)
        # The login page offers eVerify instead of handing sign-in over...
        page = self.client.get("/")
        self.assertTemplateUsed(page, "login.html")
        self.assertNotContains(page, "rogue.example")
        # ...and the routes do nothing.
        self.assertRedirects(self.client.post(reverse("sso_login")), "/",
                             fetch_redirect_response=False)
        with patch.object(sso, "exchange") as exchange:
            response = self.client.get(reverse("sso_callback"),
                                       {"state": "s", "code": "c"})
        exchange.assert_not_called()
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertEqual(response.status_code, 302)

    def test_a_stored_issuer_does_not_block_other_settings(self):
        self._store(ROGUE_ISSUER, mode=SiteSettings.LOGIN_EVERIFY)
        response = self._setup(login_mode="everify", sso_issuer=ROGUE_ISSUER,
                               sso_client_id="renamed")
        self.assertNotContains(response, "must be one this server allows")
        self.site.refresh_from_db()
        self.assertEqual(self.site.sso_client_id, "renamed")
        self.assertContains(self.client.get(reverse("setup")),
                            "The stored issuer is not one this server allows")

    def test_sso_cannot_be_selected_with_an_issuer_the_server_refuses(self):
        self._store(ROGUE_ISSUER, mode=SiteSettings.LOGIN_EVERIFY)
        response = self._setup(login_mode="sso", sso_issuer=ROGUE_ISSUER,
                               sso_client_id="verify")
        self.assertContains(response, "single sign-on cannot be selected")
        self.site.refresh_from_db()
        self.assertEqual(self.site.login_mode, SiteSettings.LOGIN_EVERIFY)

    def test_the_network_calls_check_again(self):
        self._store(ROGUE_ISSUER)
        with patch.object(sso, "discovery") as discovery:
            with self.assertRaises(sso.SsoAuthError):
                sso.auth_url(self.site, "https://x/cb", "s", "c")
            with self.assertRaises(sso.SsoAuthError):
                sso.exchange(self.site, "code", "https://x/cb", "v")
        discovery.assert_not_called()

    def test_an_sso_session_records_its_path_and_subject(self):
        self._store(ALLOWED_ISSUER)
        session = self.client.session
        session[sso.STATE_KEY] = "st4te"
        session[sso.VERIFIER_KEY] = "ver1fier"
        session.save()
        profile = {"sub": "abc-123", "national_id": "1111222233334444",
                   "digital_id": "OPR1234", "first_name": "", "middle_name": "",
                   "last_name": ""}
        with patch.object(sso, "exchange", return_value=profile):
            with self.assertLogs("verify.views.helpers", "INFO") as logs:
                self.client.get(reverse("sso_callback"),
                                {"state": "st4te", "code": "c"})
        session = self.client.session
        self.assertEqual(session[SESSION_KEY], self.operator.pk)
        self.assertEqual(session["verify_sign_in"], "sso")
        self.assertEqual(session["verify_sign_in_sub"], "abc-123")
        self.assertEqual(session["verify_sign_in_issuer"], ALLOWED_ISSUER)
        self.assertIn("via sso", "\n".join(logs.output))


class DjangoBridgeSessionTest(TestCase):
    """A bridge session lives as long as its Django login, and the bridge
    row loses its role when the account does. A staff account that is not
    a superuser, so the role is admin of every organization; the chooser
    is a page it can open with no organization chosen."""

    def setUp(self):
        self.staff = get_user_model().objects.create_user(
            "staffer", "s@example.org", "pw-1", is_staff=True)
        self.client.force_login(self.staff)
        # Opening the site's own pages makes the bridge row and the session.
        self.assertEqual(self.client.get(reverse("choose")).status_code, 200)
        self.row = User.objects.get(national_id_card_number=bridge_card(self.staff.pk))
        self.assertTrue(self.row.is_all_org_admin)
        self.assertFalse(self.row.is_site_admin)
        self.assertEqual(self.client.session[SESSION_KEY], self.row.pk)
        self.assertEqual(self.client.session["verify_sign_in"], "django")

    def _still_in(self):
        response = self.client.get(reverse("choose"))
        return response.status_code == 200

    def test_the_session_holds_while_the_login_does(self):
        self.assertTrue(self._still_in())
        self.assertTrue(self._still_in())

    def test_deactivating_the_account_ends_it_and_demotes_the_row(self):
        self.staff.is_active = False
        with self.assertLogs("accounts.django_bridge", "WARNING"):
            self.staff.save()
        self.assertFalse(self._still_in())
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.row.refresh_from_db()
        self.assertFalse(self.row.is_all_org_admin)

    def test_taking_staff_away_ends_it_and_demotes_the_row(self):
        self.staff.is_staff = False
        self.staff.save()
        self.assertFalse(self._still_in())
        self.row.refresh_from_db()
        self.assertFalse(self.row.is_all_org_admin)

    def test_a_password_change_ends_it(self):
        self.staff.set_password("pw-2")
        self.staff.save()
        self.assertFalse(self._still_in())
        self.assertNotIn(SESSION_KEY, self.client.session)

    def test_logging_out_of_django_admin_ends_it(self):
        self.client.post(reverse("admin:logout"))
        self.assertFalse(self._still_in())

    def test_logging_out_here_ends_both(self):
        self.client.post(reverse("logout"))
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertFalse(self._still_in())

    def test_deleting_the_account_demotes_the_row(self):
        self.staff.delete()
        self.row.refresh_from_db()
        self.assertFalse(self.row.is_all_org_admin)

    def test_another_django_login_does_not_carry_the_row(self):
        other = get_user_model().objects.create_user(
            "other", "o@example.org", "pw", is_staff=True)
        session = self.client.session
        # The bridge row's session, under a different Django login.
        self.client.force_login(other)
        session = self.client.session
        session[SESSION_KEY] = self.row.pk
        session.save()
        self.client.get(reverse("choose"))
        self.assertNotEqual(self.client.session.get(SESSION_KEY), self.row.pk)

    def test_signing_in_as_staff_again_gives_the_role_back(self):
        self.staff.is_staff = False
        self.staff.save()
        self.staff.is_staff = True
        self.staff.save()
        self.client.force_login(self.staff)
        self.assertTrue(self._still_in())
        self.row.refresh_from_db()
        self.assertTrue(self.row.is_all_org_admin)

    def test_an_operators_own_session_needs_no_django_login(self):
        operator = User.objects.create(national_id_card_number="1111222233334444")
        join(make_org("Org A"), operator)
        client = self.client_class()
        sign_in(client, operator)
        self.assertEqual(client.get(reverse("choose")).status_code, 200)

    def test_saving_an_operator_django_account_touches_nothing_else(self):
        bystander = User.objects.create(national_id_card_number="1111222233334444",
                                        digital_national_id="STAFFER",
                                        is_site_admin=True)
        self.staff.is_staff = False
        self.staff.save()
        bystander.refresh_from_db()
        self.assertTrue(bystander.is_site_admin)


def staff_with(*codenames, superuser=False):
    """A Django staff account holding exactly these accounts permissions."""
    from django.contrib.auth.models import Permission

    model = get_user_model()
    if superuser:
        return model.objects.create_superuser("root", "r@example.org", "pw")
    staff = model.objects.create_user("staffer", "s@example.org", "pw", is_staff=True)
    staff.user_permissions.set(Permission.objects.filter(
        content_type__app_label="accounts", codename__in=codenames))
    return staff


class DjangoAdminAuditTrailTest(TestCase):
    """The verification log, the eVerify secrets, and who a person is."""

    def setUp(self):
        self.org = make_org(name="Mine", everify_client_secret="TOP-SECRET-1",
                            everify_public_api_key="PUBLIC-KEY-2")

    def test_the_verification_log_cannot_be_changed_or_deleted(self):
        txn = Transaction.objects.create(organization=self.org, given_name="Juan",
                                         authentication_result="success")
        self.client.force_login(staff_with(superuser=True))
        change = reverse("admin:accounts_transaction_change", args=[txn.pk])
        self.client.post(change, {"given_name": "Pedro"})
        txn.refresh_from_db()
        self.assertEqual(txn.given_name, "Juan")
        self.client.post(reverse("admin:accounts_transaction_delete", args=[txn.pk]),
                         {"post": "yes"})
        self.assertTrue(Transaction.objects.filter(pk=txn.pk).exists())
        self.client.post(reverse("admin:accounts_transaction_changelist"),
                         {"action": "delete_selected", "_selected_action": [txn.pk],
                          "post": "yes"})
        self.assertTrue(Transaction.objects.filter(pk=txn.pk).exists())
        self.assertEqual(
            self.client.get(reverse("admin:accounts_transaction_add")).status_code, 403)
        # Still readable.
        self.assertContains(self.client.get(change), "Juan")

    def test_the_secrets_are_never_shown_back(self):
        self.client.force_login(staff_with(superuser=True))
        page = self.client.get(reverse("admin:accounts_organization_change",
                                       args=[self.org.pk]))
        self.assertEqual(page.status_code, 200)
        self.assertNotContains(page, "TOP-SECRET-1")
        self.assertNotContains(page, "PUBLIC-KEY-2")
        self.assertContains(page, "client secret set, public API key set")

    def _save_org(self, **extra):
        data = {"name": "Mine", "subtitle": "", "mark_color": self.org.mark_color,
                "logo_data": "", "everify_base_url": self.org.everify_base_url,
                "everify_client_id": self.org.everify_client_id, "is_active": "on",
                "memberships-TOTAL_FORMS": "0", "memberships-INITIAL_FORMS": "0",
                "memberships-MIN_NUM_FORMS": "0", "memberships-MAX_NUM_FORMS": "1000"}
        data.update(extra)
        response = self.client.post(
            reverse("admin:accounts_organization_change", args=[self.org.pk]), data)
        self.assertEqual(response.status_code, 302,
                         response.context and response.context["adminform"].form.errors)
        self.org.refresh_from_db()

    def test_a_blank_secret_keeps_it_a_new_one_replaces_it_and_clear_clears_it(self):
        self.client.force_login(staff_with(superuser=True))
        self._save_org()
        self.assertEqual(self.org.everify_client_secret, "TOP-SECRET-1")
        with self.assertLogs("accounts.admin", "WARNING") as logs:
            self._save_org(new_client_secret="NEW-SECRET")
        self.assertEqual(self.org.everify_client_secret, "NEW-SECRET")
        self.assertIn("everify_client_secret replaced", logs.output[0])
        self.assertNotIn("NEW-SECRET", "\n".join(logs.output))
        self._save_org(clear_public_api_key="on")
        self.assertEqual(self.org.everify_public_api_key, "")
        self.assertEqual(self.org.everify_client_secret, "NEW-SECRET")

    def _person_page(self, staff, person):
        self.client.force_login(staff)
        return self.client.get(reverse("admin:accounts_user_change", args=[person.pk]))

    def test_only_a_superuser_changes_who_a_person_is_or_what_they_may_do(self):
        person = User.objects.create(national_id_card_number="5555666677778888")
        staff = staff_with("view_user", "change_user")
        fields = self._person_page(staff, person).context["adminform"].form.fields
        for name in ("national_id_card_number", "digital_national_id",
                     "is_site_admin", "device_restricted_tier"):
            self.assertNotIn(name, fields, name)
        self.assertIn("given_name", fields)
        fields = self._person_page(staff_with(superuser=True), person
                                   ).context["adminform"].form.fields
        # A superuser also designates a person's role (accounts/admin_roles).
        for name in ("national_id_card_number", "device_restricted_tier",
                     "is_site_admin", "is_all_org_admin"):
            self.assertIn(name, fields, name)

    def test_staff_who_add_a_person_grant_them_nothing(self):
        self.client.force_login(staff_with("view_user", "add_user", "change_user"))
        response = self.client.post(reverse("admin:accounts_user_add"), {
            "national_id_card_number": "5555666677778888", "digital_national_id": "",
            "given_name": "", "middle_name": "", "last_name": "",
            "memberships-TOTAL_FORMS": "0", "memberships-INITIAL_FORMS": "0",
            "memberships-MIN_NUM_FORMS": "0", "memberships-MAX_NUM_FORMS": "1000"})
        self.assertEqual(response.status_code, 302)
        added = User.objects.get(national_id_card_number="5555666677778888")
        self.assertFalse(added.device_restricted_tier)
        self.assertFalse(added.is_site_admin)

    def test_a_superusers_card_correction_is_logged(self):
        person = User.objects.create(national_id_card_number="5555666677778888")
        self.client.force_login(staff_with(superuser=True))
        with self.assertLogs("accounts.admin", "WARNING") as logs:
            self.client.post(reverse("admin:accounts_user_change", args=[person.pk]), {
                "national_id_card_number": "5555666677770000", "digital_national_id": "",
                "given_name": "", "middle_name": "", "last_name": "",
                "device_restricted_tier": "on",
                "memberships-TOTAL_FORMS": "0", "memberships-INITIAL_FORMS": "0",
                "memberships-MIN_NUM_FORMS": "0", "memberships-MAX_NUM_FORMS": "1000"})
        person.refresh_from_db()
        self.assertEqual(person.national_id_card_number, "5555666677770000")
        self.assertIn("national_id_card_number changed", logs.output[0])


class DjangoAdminRevokeTest(TestCase):
    """Revoking from Django admin asks first, is capped, needs more than view
    permission, and records who."""

    def setUp(self):
        self.org = make_org(name="Mine")
        self.credentials = [self._credential() for _ in range(3)]
        self.url = reverse("admin:accounts_issuedcredential_changelist")

    def _credential(self):
        import datetime
        import uuid

        from django.utils import timezone

        from accounts.models import IssuedCredential
        return IssuedCredential.objects.create(
            organization=self.org, credential_id=uuid.uuid4(),
            document_uuid=uuid.uuid4(), epoch=14, issuer_key_id=1,
            issued_at=timezone.now(),
            expires_at=timezone.now() + datetime.timedelta(days=365))

    def _revoke(self, credentials, **extra):
        data = {"action": "revoke_selected",
                "_selected_action": [c.pk for c in credentials]}
        data.update(extra)
        return self.client.post(self.url, data)

    def _revoked(self):
        return [c for c in self.credentials
                if type(c).objects.get(pk=c.pk).revoked_at is not None]

    def test_view_only_staff_are_not_offered_it_and_cannot_run_it(self):
        self.client.force_login(staff_with("view_issuedcredential"))
        page = self.client.get(self.url)
        self.assertNotContains(page, "revoke_selected")
        self._revoke(self.credentials, post="yes", reason="because")
        self.assertEqual(self._revoked(), [])

    def test_it_asks_first_and_revokes_nothing_until_answered(self):
        self.client.force_login(staff_with("view_issuedcredential",
                                           "change_issuedcredential"))
        page = self._revoke(self.credentials[:2])
        self.assertTemplateUsed(page, "admin/accounts/issuedcredential/revoke_confirmation.html")
        self.assertContains(page, "Revoke <strong>2</strong> credentials?")
        self.assertEqual(self._revoked(), [])
        page = self._revoke(self.credentials[:2], post="yes", reason="", shown="2")
        self.assertContains(page, "Say why")
        self.assertEqual(self._revoked(), [])

    def test_an_answered_revoke_records_who_and_why(self):
        staff = staff_with("view_issuedcredential", "change_issuedcredential")
        actor = User.objects.create(national_id_card_number=bridge_card(staff.pk))
        self.client.force_login(staff)
        with self.assertLogs("accounts.admin", "WARNING") as logs:
            self._revoke(self.credentials[:2], post="yes", reason="lost wallet",
                         shown="2")
        revoked = self._revoked()
        self.assertEqual(len(revoked), 2)
        for credential in revoked:
            credential.refresh_from_db()
            self.assertEqual(credential.revoked_by, actor)
            self.assertEqual(credential.revoked_reason, "Django admin: lost wallet")
        self.assertEqual(len(logs.output), 2)
        from django.contrib.admin.models import LogEntry
        self.assertEqual(LogEntry.objects.filter(user=staff).count(), 2)

    def test_more_than_the_cap_is_refused(self):
        from accounts.admin import IssuedCredentialAdmin
        self.client.force_login(staff_with(superuser=True))
        with patch.object(IssuedCredentialAdmin, "REVOKE_CAP", 2):
            response = self._revoke(self.credentials, post="yes", reason="x")
        self.assertEqual(self._revoked(), [])
        self.assertEqual(response.status_code, 302)

    def test_a_forged_id_added_by_hand_records_who(self):
        import uuid

        from accounts.models import RevokedCredentialId
        root = staff_with(superuser=True)
        actor = User.objects.create(national_id_card_number=bridge_card(root.pk))
        self.client.force_login(root)
        forged = uuid.uuid4()
        self.client.post(reverse("admin:accounts_revokedcredentialid_add"),
                         {"credential_id": str(forged), "reason": "forged"})
        self.assertEqual(RevokedCredentialId.objects.get(credential_id=forged).added_by,
                         actor)


def tiny_limits(**scopes):
    """Every limit at 2 per window unless named."""
    from accounts.throttle import LIMITS
    limits = {scope: (2, window) for scope, (_, window) in LIMITS.items()}
    limits.update(scopes)
    return override_settings(RATE_LIMITS=limits)


@tiny_limits()
class RateLimitTest(TestCase):
    """What anybody can reach without signing in is limited per client
    address."""

    ALB = "10.0.0.250"

    def _from(self, address, spoofed=None):
        chain = ", ".join(([spoofed] if spoofed else []) + [address, self.ALB])
        return {"HTTP_X_FORWARDED_FOR": chain}

    def _sign_in(self, value="1111222233334444", **headers):
        return self.client.post("/everify/", data=json.dumps({"value": value}),
                                content_type="application/json", **headers)

    def test_the_client_is_the_address_the_load_balancer_appended(self):
        from django.test import RequestFactory

        from accounts.throttle import client_address
        factory = RequestFactory()
        self.assertEqual(client_address(factory.get(
            "/", HTTP_X_FORWARDED_FOR="203.0.113.9, 10.0.0.250")), "203.0.113.9")
        # A forwarded-for the client wrote itself comes first, and is ignored.
        self.assertEqual(client_address(factory.get(
            "/", HTTP_X_FORWARDED_FOR="1.2.3.4, 203.0.113.9, 10.0.0.250")),
            "203.0.113.9")
        self.assertEqual(client_address(factory.get(
            "/", HTTP_X_FORWARDED_FOR="not-an-ip, 10.0.0.250")), "unknown")
        self.assertEqual(client_address(factory.get("/", REMOTE_ADDR="192.0.2.7")),
                         "192.0.2.7")
        with override_settings(VERIFY_PROXY_HOPS=1):
            self.assertEqual(client_address(factory.get(
                "/", HTTP_X_FORWARDED_FOR="1.2.3.4, 203.0.113.9")), "203.0.113.9")

    @patch("verify.views.login_guard.time.sleep")
    def test_sign_in_is_limited_per_address_alike_for_any_id(self, _sleep):
        User.objects.create(national_id_card_number="1111222233334444")
        here = self._from("203.0.113.9")
        self._sign_in("1111222233334444", **here)
        self._sign_in("9999888877776666", **here)
        registered = self._sign_in("1111222233334444", **here)
        unregistered = self._sign_in("9999888877776666", **here)
        self.assertEqual(registered.status_code, 429)
        self.assertEqual(unregistered.status_code, 429)
        self.assertEqual(registered.content, unregistered.content)
        self.assertIn("Too many attempts", registered.json()["message"])

    @patch("verify.views.login_guard.time.sleep")
    def test_spoofing_the_forwarded_for_does_not_reset_the_count(self, _sleep):
        for spoof in ("1.1.1.1", "2.2.2.2"):
            self._sign_in(**self._from("203.0.113.9", spoofed=spoof))
        response = self._sign_in(**self._from("203.0.113.9", spoofed="3.3.3.3"))
        self.assertEqual(response.status_code, 429)
        # Another address is not affected.
        self.assertNotEqual(self._sign_in(**self._from("198.51.100.4")).status_code, 429)

    @patch("verify.views.login_guard.time.sleep")
    def test_a_refusal_writes_nothing(self, _sleep):
        from accounts.models import LoginAttempt, RateLimitHit
        here = self._from("203.0.113.9")
        self._sign_in(**here)
        self._sign_in(**here)
        attempts = LoginAttempt.objects.count()
        hits = RateLimitHit.objects.count()
        for _ in range(5):
            self.assertEqual(self._sign_in(**here).status_code, 429)
        self.assertEqual(LoginAttempt.objects.count(), attempts)
        self.assertEqual(RateLimitHit.objects.count(), hits)

    def test_a_signed_in_operator_is_not_counted(self):
        operator = User.objects.create(national_id_card_number="1111222233334444")
        org = make_org()
        join(org, operator)
        sign_in(self.client, operator, org)
        body = {"failure_detail": "cancelled"}
        for _ in range(4):
            response = self.client.post("/everify/log-liveness-failure/",
                                        data=json.dumps(body),
                                        content_type="application/json")
            self.assertEqual(response.status_code, 200)

    def test_liveness_failures_are_limited_when_signed_out(self):
        here = self._from("203.0.113.9")
        codes = [self.client.post("/everify/log-liveness-failure/",
                                  data=json.dumps({"failure_detail": "x"}),
                                  content_type="application/json", **here).status_code
                 for _ in range(3)]
        self.assertEqual(codes, [200, 200, 429])
        self.assertEqual(Transaction.objects.count(), 2)

    def test_qr_decoding_is_limited_when_signed_out(self):
        here = self._from("203.0.113.9")
        codes = [self.client.post("/decode-qr/", {}, **here).status_code
                 for _ in range(3)]
        self.assertEqual(codes, [400, 400, 429])

    def test_device_challenges_are_limited(self):
        here = self._from("203.0.113.9")
        codes = [self.client.post("/api/v1/device/challenge/", **here).status_code
                 for _ in range(3)]
        self.assertEqual(codes, [200, 200, 429])

    def test_django_admin_login_is_limited(self):
        get_user_model().objects.create_superuser("root", "r@example.org", "pw")
        here = self._from("203.0.113.9")
        url = reverse("admin:login")
        codes = [self.client.post(url, {"username": "root", "password": "wrong"},
                                  **here).status_code for _ in range(3)]
        self.assertEqual(codes, [200, 200, 429])
        # Not even the right password gets through until the window passes.
        self.assertEqual(self.client.post(url, {"username": "root", "password": "pw"},
                                          **here).status_code, 429)
        # The login page itself still loads.
        self.assertEqual(self.client.get(url, **here).status_code, 200)


class RefusedPhotoCapTest(TestCase):
    """A flood of refused sign-ins from one address stops storing faces."""

    def test_after_five_faces_an_hour_from_one_address_none_are_kept(self):
        import base64

        from django.test import RequestFactory

        from accounts.models import LoginAttempt
        from verify.views import login_guard
        photo = "data:image/png;base64," + base64.b64encode(
            b"\x89PNG\r\n\x1a\n" + b"0" * 64).decode()
        request = RequestFactory().post(
            "/everify/", HTTP_X_FORWARDED_FOR="203.0.113.9, 10.0.0.250")
        for _ in range(7):
            login_guard.record_refused_attempt(request, "9999888877776666", photo)
        rows = list(LoginAttempt.objects.order_by("created_at", "pk"))
        self.assertEqual(len(rows), 7)
        self.assertEqual([bool(r.photo_data) for r in rows], [True] * 5 + [False] * 2)
        self.assertEqual({r.ip_address for r in rows}, {"203.0.113.9"})


class NginxRateLimitTest(TestCase):
    """The nginx half: the site kit limits the public paths per client
    address."""

    #: How a map's regular-expression entry starts: a quote and a tilde.
    REGEX_ENTRY = '"' + chr(126)

    def _limit_lines(self, text):
        keep = ("map ", "limit_req", "default ", self.REGEX_ENTRY)
        return [line.strip() for line in text.splitlines()
                if line.strip().startswith(keep)]

    def _read(self, *parts):
        from django.conf import settings as django_settings
        return django_settings.BASE_DIR.joinpath(*parts).read_text(encoding="utf-8")

    def test_the_kit_limits_the_admin_login_by_the_appended_address(self):
        conf = self._read("deploy", "nginx.conf.tftpl")
        self.assertIn("limit_req_zone $verify_limit_key zone=verify_admin_login", conf)
        self.assertIn("limit_req zone=verify_admin_login", conf)
        self.assertIn("limit_req_status 429;", conf)
        self.assertIn('"/admin/login/"  1;', conf)
        # nginx cannot tell a signed-in operator; the application limits the
        # other paths, signed out only.
        for path in ("everify/", "decode-qr/", "device/challenge/"):
            self.assertNotIn(path, conf)
        # No template interpolation but the one placeholder Terraform fills.
        self.assertEqual(conf.count("$" + "{"), conf.count("$" + "{app_dir}"))

    def test_the_address_pattern_is_anchored_and_linear(self):
        """Unanchored, an 8 KB header would take about half a second."""
        import re
        import time
        conf = self._read("deploy", "nginx.conf.tftpl")
        line = next(l.strip() for l in conf.splitlines()
                    if l.strip().startswith(self.REGEX_ENTRY + "^(?:"))
        pattern = re.compile(line.split('"')[1][1:].replace("(?<", "(?P<"))
        started = time.perf_counter()
        match = pattern.search("a" * 8000 + ", 203.0.113.9")
        self.assertLess(time.perf_counter() - started, 0.05)
        self.assertEqual(match.group("last"), "203.0.113.9")
        self.assertEqual(pattern.search("1.2.3.4, 203.0.113.9 ").group("last"),
                         "203.0.113.9")


class SignInEdgeCasesTest(TestCase):

    def test_a_number_that_is_not_sixteen_ascii_digits_is_no_card(self):
        operator = User.objects.create(national_id_card_number="1111222233334444")
        org = make_org()
        join(org, operator)
        sign_in(self.client, operator, org)
        for value in ("12345678901234567", "１" * 16):
            self.client.post("/everify/log-liveness-failure/",
                             data=json.dumps({"value": value, "failure_detail": "x"}),
                             content_type="application/json")
            row = Transaction.objects.latest("verification_timestamp")
            self.assertEqual(row.national_id_card_number, "", value)

    @override_settings(SSO_ALLOWED_ISSUERS=["https://evil\\@sso.example.ph/o",
                                            "https://user@sso.example.ph/o"])
    def test_an_issuer_naming_two_hosts_is_refused_even_if_listed(self):
        self.assertFalse(sso_issuer.allowed("https://evil\\@sso.example.ph/o"))
        self.assertFalse(sso_issuer.allowed("https://user@sso.example.ph/o"))

    @override_settings(AUTHENTICATION_BACKENDS=[
        "django.contrib.auth.backends.AllowAllUsersModelBackend"])
    def test_an_inactive_account_ends_the_session_whatever_the_backend(self):
        staff = get_user_model().objects.create_user(
            "staffer", "s@example.org", "pw", is_staff=True)
        self.client.force_login(staff)
        self.assertEqual(self.client.get(reverse("choose")).status_code, 200)
        get_user_model().objects.filter(pk=staff.pk).update(is_active=False)
        self.assertNotEqual(self.client.get(reverse("choose")).status_code, 200)

    def test_a_refused_sign_in_records_the_appended_address_not_the_first(self):
        from django.test import RequestFactory

        from accounts.models import LoginAttempt
        from verify.views import login_guard
        request = RequestFactory().post(
            "/everify/", HTTP_X_FORWARDED_FOR="1.2.3.4, 203.0.113.9, 10.0.0.250")
        login_guard.record_refused_attempt(request, "9999888877776666", "")
        self.assertEqual(LoginAttempt.objects.get().ip_address, "203.0.113.9")


class AdminEdgeCasesTest(TestCase):

    def _post(self, url, body, **headers):
        return self.client.post(url, data=json.dumps(body),
                                content_type="application/json", **headers)

    # Another site's page cannot spend an office's limit.

    def test_a_cross_site_browser_request_is_refused_and_not_counted(self):
        from accounts.models import RateLimitHit
        for headers in ({"HTTP_ORIGIN": "https://evil.example"},
                        {"HTTP_SEC_FETCH_SITE": "cross-site"},
                        {"HTTP_ORIGIN": "null"}):
            self.assertEqual(self._post("/everify/", {"value": "1"}, **headers).status_code,
                             403, headers)
            self.assertEqual(self.client.post("/decode-qr/", {}, **headers).status_code,
                             403, headers)
            self.assertEqual(self.client.post("/api/v1/device/challenge/",
                                              **headers).status_code, 403, headers)
        self.assertEqual(RateLimitHit.objects.count(), 0)

    def test_this_sites_own_pages_and_phones_are_not_refused(self):
        same = {"HTTP_ORIGIN": "http://testserver", "HTTP_SEC_FETCH_SITE": "same-origin"}
        self.assertNotEqual(self.client.post("/decode-qr/", {}, **same).status_code, 403)
        # A phone sends no Origin at all.
        self.assertEqual(self.client.post("/api/v1/device/challenge/").status_code, 200)

    # A bridge row's phones do not keep the restricted tier.

    def _bridge(self):
        staff = get_user_model().objects.create_user(
            "staffer", "s@example.org", "pw", is_staff=True)
        self.client.force_login(staff)
        self.client.get(reverse("choose"))
        return staff, User.objects.get(national_id_card_number=bridge_card(staff.pk))

    def test_a_new_bridge_row_starts_without_the_tier(self):
        _, row = self._bridge()
        self.assertTrue(row.is_all_org_admin)
        self.assertFalse(row.device_restricted_tier)

    def test_ending_the_account_withdraws_a_granted_tier(self):
        from accounts import restricted_tier
        staff, row = self._bridge()
        restricted_tier.grant(row, None, "test")
        staff.is_active = False
        staff.save()
        row.refresh_from_db()
        self.assertFalse(row.is_site_admin)
        self.assertFalse(row.device_restricted_tier)

    # A card number typed in Django admin has the typed shape.

    def _add_person(self, card, superuser=True):
        user = (get_user_model().objects.create_superuser("root", "r@example.org", "pw")
                if superuser else
                staff_with("view_user", "add_user", "change_user"))
        self.client.force_login(user)
        return self.client.post(reverse("admin:accounts_user_add"), {
            "national_id_card_number": card, "digital_national_id": "",
            "given_name": "", "middle_name": "", "last_name": "",
            "memberships-TOTAL_FORMS": "0", "memberships-INITIAL_FORMS": "0",
            "memberships-MIN_NUM_FORMS": "0", "memberships-MAX_NUM_FORMS": "1000"})

    def test_nobody_types_a_bridge_card_in_django_admin(self):
        for superuser in (False, True):
            response = self._add_person("ADMIN00000000099", superuser=superuser)
            self.assertEqual(response.status_code, 200, superuser)
            self.assertContains(response, "16 digits")
            self.assertFalse(User.objects.filter(
                national_id_card_number="ADMIN00000000099").exists())
            self.client.logout()
            get_user_model().objects.all().delete()

    def test_a_sixteen_digit_card_is_accepted(self):
        self.assertEqual(self._add_person("1234567890123456").status_code, 302)
        self.assertTrue(User.objects.filter(
            national_id_card_number="1234567890123456").exists())

    def test_a_stored_card_that_is_not_changed_is_not_judged(self):
        row = User.objects.create(national_id_card_number="ADMIN00000000777")
        root = get_user_model().objects.create_superuser("root", "r@example.org", "pw")
        self.client.force_login(root)
        response = self.client.post(reverse("admin:accounts_user_change", args=[row.pk]), {
            "national_id_card_number": "ADMIN00000000777", "digital_national_id": "",
            "given_name": "Renamed", "middle_name": "", "last_name": "",
            "memberships-TOTAL_FORMS": "0", "memberships-INITIAL_FORMS": "0",
            "memberships-MIN_NUM_FORMS": "0", "memberships-MAX_NUM_FORMS": "1000"})
        self.assertEqual(response.status_code, 302)
        row.refresh_from_db()
        self.assertEqual(row.given_name, "Renamed")


class RevokeSelectAllTest(DjangoAdminRevokeTest):
    """"Select all" revokes what the confirmation showed, nothing more."""

    def test_the_confirmation_posts_back_only_what_it_listed(self):
        self.client.force_login(staff_with(superuser=True))
        page = self.client.post(self.url, {"action": "revoke_selected",
                                           "_selected_action": [self.credentials[0].pk],
                                           "select_across": "1"})
        self.assertContains(page, "Revoke <strong>3</strong> credentials?")
        self.assertContains(page, 'name="select_across" value="0"')
        listed = sorted(c.pk for c in self.credentials)
        for pk in listed:
            self.assertContains(page, 'name="_selected_action" value="%d"' % pk)
        # Minted while the reason was typed: not on the page, so not revoked.
        late = self._credential()
        self.client.post(self.url, {"action": "revoke_selected", "select_across": "0",
                                    "_selected_action": listed, "post": "yes",
                                    "reason": "batch", "shown": "3"})
        late.refresh_from_db()
        self.assertIsNone(late.revoked_at)
        self.assertEqual(len(self._revoked()), 3)

    def test_a_changed_selection_is_asked_again(self):
        self.client.force_login(staff_with(superuser=True))
        page = self._revoke(self.credentials, post="yes", reason="batch", shown="2")
        self.assertContains(page, "The selection changed")
        self.assertEqual(self._revoked(), [])
