"""Site admins are Django superusers, and nobody else; other Django staff
administer every organization and nothing site-wide. And /api/validate/
names nobody to a caller who is not signed in.
"""

import importlib
import io
from contextlib import redirect_stdout
from unittest.mock import patch

from django.apps import apps
from django.db import DatabaseError
from django.contrib import admin as django_admin
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from django.urls import reverse

from accounts.admin import DeviceAdmin, OrganizationAdmin, UserAdmin
from accounts.checks import roles_outside_the_bridge
from accounts.models import (Device, Organization, SiteSettings, Transaction, User,
                             bridge_card, bridge_roles, organizations_open_to)
from accounts.tests import join, make_org
from verify.views.core import _acting_as
from verify.views.helpers import ORG_SESSION_KEY, _is_org_admin, _log_context

SESSION_KEY = "verify_user_id"
DjangoUser = get_user_model()


def bridged(client, django_user):
    """Sign a Django account in and open the site's pages, which makes its
    bridge row and the session."""
    client.force_login(django_user)
    client.get(reverse("app"))
    return User.objects.get(national_id_card_number=bridge_card(django_user.pk))


def enter(client, org):
    session = client.session
    session[ORG_SESSION_KEY] = org.pk
    session.save()


class BridgeRolesTest(TestCase):

    def test_superuser_site_admin_staff_every_organization_else_neither(self):
        self.assertEqual(bridge_roles(DjangoUser(is_active=True, is_superuser=True,
                                                 is_staff=True)), (True, False))
        self.assertEqual(bridge_roles(DjangoUser(is_active=True, is_staff=True)),
                         (False, True))
        self.assertEqual(bridge_roles(DjangoUser(is_active=True)), (False, False))
        self.assertEqual(bridge_roles(DjangoUser(is_active=False, is_superuser=True,
                                                 is_staff=True)), (False, False))
        self.assertEqual(bridge_roles(None), (False, False))


class SuperuserTest(TestCase):

    def setUp(self):
        self.org = make_org("Org A")
        self.root = DjangoUser.objects.create_superuser("root", "r@example.org", "pw")
        self.row = bridged(self.client, self.root)

    def test_is_a_site_admin_only(self):
        self.assertEqual((self.row.is_site_admin, self.row.is_all_org_admin),
                         (True, False))
        self.assertEqual(self.client.get(reverse("site_admin")).status_code, 200)

    def test_losing_superuser_leaves_an_admin_of_every_organization(self):
        self.root.is_superuser = False
        with self.assertLogs("accounts.django_bridge", "WARNING"):
            self.root.save()
        self.row.refresh_from_db()
        self.assertEqual((self.row.is_site_admin, self.row.is_all_org_admin),
                         (False, True))
        self.assertNotEqual(self.client.get(reverse("site_admin")).status_code, 200)

    def test_a_change_no_signal_saw_takes_effect_at_the_next_request(self):
        DjangoUser.objects.filter(pk=self.root.pk).update(is_superuser=False)
        with self.assertLogs("verify.views.helpers", "WARNING"):
            self.client.get(reverse("app"))
        self.row.refresh_from_db()
        self.assertEqual((self.row.is_site_admin, self.row.is_all_org_admin),
                         (False, True))

    def test_made_superuser_again_is_a_site_admin_again(self):
        DjangoUser.objects.filter(pk=self.root.pk).update(is_superuser=False)
        self.client.get(reverse("app"))
        self.root.refresh_from_db()
        self.root.is_superuser = True
        self.root.save()
        self.row.refresh_from_db()
        self.assertEqual((self.row.is_site_admin, self.row.is_all_org_admin),
                         (True, False))

    def test_deactivating_takes_both_roles(self):
        self.root.is_active = False
        with self.assertLogs("accounts.django_bridge", "WARNING"):
            self.root.save()
        self.row.refresh_from_db()
        self.assertEqual((self.row.is_site_admin, self.row.is_all_org_admin),
                         (False, False))

    def test_publishes_organization_keys(self):
        with patch("verify.views.signing.signer_client.org_publish") as publish:
            self.client.post(reverse("signing_publish", args=[7]))
        publish.assert_called_once()

    def test_starts_organization_keys(self):
        with patch("verify.views.signing.signer_client.org_activate") as activate:
            self.client.post(reverse("signing_activate", args=[7]))
        activate.assert_called_once()

    def test_stamped_as_site_admin_where_not_a_member(self):
        self.assertEqual(_log_context(None, self.row, self.org)[1],
                         {"acting_as_site_admin": True, "acting_as_all_org_admin": False})


class StaffTest(TestCase):
    """Staff that is not a superuser: every organization, nothing site-wide."""

    def setUp(self):
        self.a = make_org("Org A")
        self.b = make_org("Org B")
        self.staff = DjangoUser.objects.create_user("staffer", "s@example.org", "pw",
                                                    is_staff=True)
        self.row = bridged(self.client, self.staff)

    def test_is_an_admin_of_every_organization_not_a_site_admin(self):
        self.assertEqual((self.row.is_site_admin, self.row.is_all_org_admin),
                         (False, True))

    def test_enters_every_organization_as_its_admin(self):
        self.assertEqual(set(organizations_open_to(self.row)), {self.a, self.b})
        self.assertTrue(_is_org_admin(self.row, self.a))
        enter(self.client, self.b)
        response = self.client.get(reverse("app_admin"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Admin, every organization")

    def test_reaches_no_site_page(self):
        self.assertNotEqual(self.client.get(reverse("site_admin")).status_code, 200)
        enter(self.client, self.a)
        response = self.client.get(reverse("setup"))
        self.assertNotContains(response, 'id="restricted-tier"')
        self.assertNotContains(response, 'href="/app/site/"')

    def test_grants_no_restricted_tier(self):
        person = User.objects.create(national_id_card_number="1111222233334444",
                                     device_restricted_tier=False)
        response = self.client.post(reverse("site_restricted_tier", args=[person.pk]),
                                    {"grant": True}, content_type="application/json")
        self.assertEqual(response.status_code, 403)
        person.refresh_from_db()
        self.assertFalse(person.device_restricted_tier)

    def test_exports_no_device_logs(self):
        self.assertNotEqual(
            self.client.get(reverse("site_export_device_logs")).status_code, 200)

    def test_changes_no_site_setting_from_setup(self):
        before = SiteSettings.load()
        enter(self.client, self.a)
        self.client.post(reverse("setup"), {
            "login_mode": "sso", "everify_base_url": "https://evil.example/api"})
        after_ = SiteSettings.load()
        self.assertEqual(after_.login_mode, before.login_mode)
        self.assertEqual(after_.everify_base_url, before.everify_base_url)

    def test_cannot_publish_or_start_an_organization_key(self):
        """One Django staff password does not put a certified name on every
        phone; only a superuser's row may."""
        with patch("verify.views.signing.signer_client.org_publish") as publish, \
                patch("verify.views.signing.signer_client.org_activate") as activate:
            self.client.post(reverse("signing_publish", args=[7]))
            self.client.post(reverse("signing_activate", args=[7]))
        publish.assert_not_called()
        activate.assert_not_called()

    def test_stamped_with_its_own_role_where_not_a_member(self):
        self.assertEqual(_log_context(None, self.row, self.a)[1],
                         {"acting_as_site_admin": False, "acting_as_all_org_admin": True})
        join(self.a, self.row)
        self.assertEqual(_log_context(None, self.row, self.a)[1],
                         {"acting_as_site_admin": False, "acting_as_all_org_admin": False})

    def test_made_superuser_becomes_a_site_admin(self):
        self.staff.is_superuser = True
        with self.assertLogs("accounts.django_bridge", "WARNING"):
            self.staff.save()
        self.row.refresh_from_db()
        self.assertEqual((self.row.is_site_admin, self.row.is_all_org_admin),
                         (True, False))

    def test_a_row_from_before_gets_its_role_at_the_next_login(self):
        """A bridge row made under the old rule (staff was a site admin),
        reached from a Django login already open -- one from before the
        deploy, so no login or save signal runs: re-derived on the way in,
        not only once a verify session exists. (The row is made after
        force_login, whose last_login save would otherwise fix it first.)"""
        other = DjangoUser.objects.create_user("other", "o@example.org", "pw",
                                               is_staff=True)
        client = self.client_class()
        client.force_login(other)
        stale = User.objects.create(national_id_card_number=bridge_card(other.pk),
                                    is_site_admin=True)
        with self.assertLogs("verify.views.helpers", "WARNING"):
            self.assertNotEqual(client.get(reverse("site_admin")).status_code, 200)
        stale.refresh_from_db()
        self.assertEqual((stale.is_site_admin, stale.is_all_org_admin), (False, True))

    def test_losing_staff_ends_the_session_and_the_role(self):
        self.staff.is_staff = False
        self.staff.save()
        self.client.get(reverse("app"))
        self.assertNotIn(SESSION_KEY, self.client.session)
        self.row.refresh_from_db()
        self.assertFalse(self.row.is_all_org_admin)


class ExportLabelTest(TestCase):

    def test_site_admin_stays_yes_and_the_other_role_has_its_word(self):
        self.assertEqual(_acting_as(Transaction(acting_as_site_admin=True)), "Yes")
        self.assertEqual(_acting_as(Transaction(acting_as_all_org_admin=True)),
                         "Admin of every organization")
        self.assertEqual(_acting_as(Transaction()), "")


class Migration0046Test(TestCase):
    """The data step: every row's two flags re-derived from its Django
    account, and a ticked row that is no Django account's cleared."""

    def test_rederives_every_row(self):
        migration = importlib.import_module(
            "accounts.migrations.0046_site_admins_are_superusers")
        root = DjangoUser.objects.create_superuser("root", "r@example.org", "pw")
        staff = DjangoUser.objects.create_user("staffer", "s@example.org", "pw",
                                               is_staff=True)
        ticked = User.objects.create(national_id_card_number="1111222233334444",
                                     is_site_admin=True)
        member = User.objects.create(national_id_card_number="5555666677778888")
        root_row = User.objects.create(national_id_card_number=bridge_card(root.pk))
        staff_row = User.objects.create(national_id_card_number=bridge_card(staff.pk),
                                        is_site_admin=True)
        orphan = User.objects.create(national_id_card_number=bridge_card(99999),
                                     is_site_admin=True)
        out = io.StringIO()
        with redirect_stdout(out):
            migration.rederive(apps, None)
        flags = {row.pk: (row.is_site_admin, row.is_all_org_admin)
                 for row in User.objects.all()}
        self.assertEqual(flags[ticked.pk], (False, False))
        self.assertEqual(flags[member.pk], (False, False))
        self.assertEqual(flags[root_row.pk], (True, False))
        self.assertEqual(flags[staff_row.pk], (False, True))
        self.assertEqual(flags[orphan.pk], (False, False))
        self.assertIn(f"user {ticked.pk} (card ending 4444) is no longer a site admin",
                      out.getvalue())
        self.assertIn("now an admin of every organization", out.getvalue())

    def test_a_demoted_row_with_no_membership_loses_the_restricted_tier(self):
        migration = importlib.import_module(
            "accounts.migrations.0046_site_admins_are_superusers")
        alone = User.objects.create(national_id_card_number="1111222233334444",
                                    is_site_admin=True, device_restricted_tier=True)
        member = User.objects.create(national_id_card_number="5555666677778888",
                                     is_site_admin=True, device_restricted_tier=True)
        join(make_org("Org A"), member)
        out = io.StringIO()
        with redirect_stdout(out):
            migration.rederive(apps, None)
        alone.refresh_from_db()
        member.refresh_from_db()
        self.assertFalse(alone.device_restricted_tier)
        self.assertIsNone(alone.restricted_tier_granted_at)
        self.assertTrue(member.device_restricted_tier)
        self.assertIn("restricted tier is withdrawn", out.getvalue())
        self.assertEqual(out.getvalue().count("withdrawn"), 1)

    def test_a_card_that_only_looks_like_digits_does_not_stop_it(self):
        migration = importlib.import_module(
            "accounts.migrations.0046_site_admins_are_superusers")
        odd = User.objects.create(national_id_card_number="ADMIN0000000000\u00b2",
                                  is_site_admin=True)
        with redirect_stdout(io.StringIO()):
            migration.rederive(apps, None)
        odd.refresh_from_db()
        self.assertFalse(odd.is_site_admin)


class RolesOutsideTheBridgeCheckTest(TestCase):

    def test_reports_either_flag_on_a_row_that_is_no_django_accounts(self):
        site = User.objects.create(national_id_card_number="1111222233334444",
                                   is_site_admin=True)
        every = User.objects.create(national_id_card_number="5555666677778888",
                                    is_all_org_admin=True)
        User.objects.create(national_id_card_number=bridge_card(5), is_site_admin=True)
        found = roles_outside_the_bridge(databases=["default"])
        self.assertEqual([w.id for w in found], ["accounts.W002", "accounts.W002"])
        self.assertIn(f"verify user {site.pk} ", found[0].msg)
        self.assertIn(f"verify user {every.pk} ", found[1].msg)

    def test_quiet_without_databases(self):
        self.assertEqual(roles_outside_the_bridge(), [])

    def test_before_0046_it_still_reports_site_admins(self):
        """migrate runs checks before it applies 0046, when is_all_org_admin
        is not a column yet: that query steps aside, the other still runs."""
        User.objects.create(national_id_card_number="1111222233334444",
                            is_site_admin=True)
        real = User.objects.filter

        def filter_(*args, **kwargs):
            if "is_all_org_admin" in kwargs:
                raise DatabaseError("no such column: is_all_org_admin")
            return real(*args, **kwargs)

        with patch.object(User.objects, "filter", side_effect=filter_):
            found = roles_outside_the_bridge(databases=["default"])
        self.assertEqual(len(found), 1)
        self.assertIn("is a site admin", found[0].msg)


class DjangoAdminTest(TestCase):

    def test_a_bridge_rows_roles_are_nobodys_to_set(self):
        """It follows its Django account; even a superuser cannot set it.
        (A person's row is a superuser's to designate: tests_designated_admins.)"""
        request = RequestFactory().get("/")
        request.user = DjangoUser.objects.create_superuser("root", "r@example.org", "pw")
        target = User.objects.create(national_id_card_number=bridge_card(42))
        readonly = UserAdmin(User, django_admin.site).get_readonly_fields(request, target)
        self.assertIn("is_site_admin", readonly)
        self.assertIn("is_all_org_admin", readonly)
        self.assertNotIn("device_restricted_tier", readonly)

    def test_only_a_superuser_changes_an_organizations_everify_address(self):
        org = make_org("Org A")
        request = RequestFactory().get("/")
        request.user = DjangoUser.objects.create_user("staffer", "s@example.org", "pw",
                                                      is_staff=True)
        admin_ = OrganizationAdmin(Organization, django_admin.site)
        self.assertIn("everify_base_url", admin_.get_readonly_fields(request, org))
        request.user = DjangoUser.objects.create_superuser("root", "r@example.org", "pw")
        self.assertNotIn("everify_base_url", admin_.get_readonly_fields(request, org))

    def test_revoking_devices_needs_the_change_permission(self):
        self.assertEqual(DeviceAdmin.revoke_selected.allowed_permissions, ["change"])


class ValidateApiTest(TestCase):
    """The record exists and how it came out, to anybody; whom it
    names, to a signed-in operator."""

    IDENTITY = ("DELA CRUZ", "JUAN MIGUEL", "3916-0983-2403-5936", "CWD0842",
                "Main Office", "OPERATOR")

    def setUp(self):
        self.org = make_org("Org A")
        self.operator = User.objects.create(national_id_card_number="1111222233334444",
                                            given_name="OPERATOR", last_name="ONE")
        join(self.org, self.operator)
        self.txn = Transaction.objects.create(
            organization=self.org, operator=self.operator, operator_location="Main Office",
            given_name="JUAN MIGUEL", last_name="DELA CRUZ",
            national_id_card_number="3916098324035936",
            digital_national_id_number="CWD0842",
            authentication_result="success", transaction_type="Walk-in")
        self.url = reverse("validate_api", args=[self.txn.transaction_id])

    def test_without_a_session_only_the_outcome(self):
        response = self.client.get(self.url)
        body = response.json()
        self.assertEqual(body["status"], "found")
        self.assertEqual(set(body["transaction"]),
                         {"organization", "verification_timestamp", "transaction_type",
                          "authentication_result", "identity_withheld"})
        self.assertEqual(body["transaction"]["authentication_result"], "success")
        self.assertEqual(body["transaction"]["organization"], "Org A")
        for value in self.IDENTITY:
            self.assertNotContains(response, value)

    def test_a_signed_in_operator_gets_every_field(self):
        session = self.client.session
        session[SESSION_KEY] = self.operator.pk
        session.save()
        response = self.client.get(self.url)
        transaction = response.json()["transaction"]
        self.assertNotIn("identity_withheld", transaction)
        for value in self.IDENTITY:
            self.assertContains(response, value)

    def test_an_unknown_id_is_not_found(self):
        response = self.client.get(reverse(
            "validate_api", args=["00000000-0000-4000-8000-000000000000"]))
        self.assertEqual(response.json(), {"status": "not_found"})

    def _as(self, user):
        session = self.client.session
        session[SESSION_KEY] = user.pk
        session.save()
        return self.client.get(self.url)

    def test_another_organizations_operator_gets_the_outcome_only(self):
        stranger = User.objects.create(national_id_card_number="5555666677778888")
        join(make_org("Org B"), stranger)
        response = self._as(stranger)
        self.assertTrue(response.json()["transaction"]["identity_withheld"])
        for value in self.IDENTITY:
            self.assertNotContains(response, value)

    def test_somebody_in_no_organization_gets_the_outcome_only(self):
        nobody = User.objects.create(national_id_card_number="5555666677778888")
        self.assertTrue(self._as(nobody).json()["transaction"]["identity_withheld"])

    def test_an_admin_of_every_organization_gets_every_field(self):
        staff = DjangoUser.objects.create_user("staffer", "s@example.org", "pw",
                                               is_staff=True)
        bridged(self.client, staff)
        response = self.client.get(self.url)
        self.assertNotIn("identity_withheld", response.json()["transaction"])
        self.assertContains(response, "DELA CRUZ")

    def test_a_record_with_no_organization_names_nobody_to_a_member(self):
        self.txn.organization = None
        self.txn.save(update_fields=["organization"])
        self.assertTrue(self._as(self.operator).json()["transaction"]["identity_withheld"])

    def test_a_record_with_no_organization_names_its_holder_to_a_site_admin(self):
        self.txn.organization = None
        self.txn.save(update_fields=["organization"])
        bridged(self.client, DjangoUser.objects.create_superuser("root", "r@example.org", "pw"))
        response = self.client.get(self.url)
        self.assertNotIn("identity_withheld", response.json()["transaction"])
        self.assertContains(response, "DELA CRUZ")

    def test_never_cached(self):
        for response in (self.client.get(self.url), self._as(self.operator)):
            self.assertIn("no-store", response["Cache-Control"])
            self.assertIn("private", response["Cache-Control"])
