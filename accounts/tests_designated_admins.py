"""A superuser may designate any person -- an eVerify sign-in -- a site admin
or an admin of every organization, recorded; a designated site admin has
every site power but publishing or starting an organization's signing key.
"""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from accounts import admin_roles
from accounts.checks import roles_outside_the_bridge
from accounts.models import User, bridge_card, organizations_open_to
from accounts.tests import make_org
from verify.views.helpers import ORG_SESSION_KEY, _is_org_admin

SESSION_KEY = "verify_user_id"
DjangoUser = get_user_model()

#: The rest of Django admin's change form for a person with no memberships.
FORM = {"digital_national_id": "", "given_name": "", "middle_name": "", "last_name": "",
        "memberships-TOTAL_FORMS": "0", "memberships-INITIAL_FORMS": "0",
        "memberships-MIN_NUM_FORMS": "0", "memberships-MAX_NUM_FORMS": "1000"}


def sign_in(client, user, org=None):
    """An eVerify session, as sign-in leaves it."""
    session = client.session
    session[SESSION_KEY] = user.pk
    if org is not None:
        session[ORG_SESSION_KEY] = org.pk
    session.save()


class DesignatingInDjangoAdminTest(TestCase):

    def setUp(self):
        self.root = DjangoUser.objects.create_superuser("root", "r@example.org", "pw")
        self.client.force_login(self.root)
        self.client.get(reverse("app"))  # the superuser's own row, the actor
        self.root_row = User.objects.get(national_id_card_number=bridge_card(self.root.pk))
        self.person = User.objects.create(national_id_card_number="1111222233334444",
                                          device_restricted_tier=False)

    def _post(self, client=None, **roles):
        data = dict(FORM, national_id_card_number=self.person.national_id_card_number,
                    **{k: "on" for k, v in roles.items() if v})
        return (client or self.client).post(
            reverse("admin:accounts_user_change", args=[self.person.pk]), data)

    def test_a_superuser_designates_a_site_admin_and_it_is_recorded(self):
        with self.assertLogs("accounts.admin_roles", "WARNING") as logs:
            self.assertEqual(self._post(is_site_admin=True).status_code, 302)
        self.person.refresh_from_db()
        self.assertTrue(self.person.is_site_admin)
        self.assertFalse(self.person.is_all_org_admin)
        self.assertEqual(self.person.admin_role_granted_by, self.root_row)
        self.assertIsNotNone(self.person.admin_role_granted_at)
        self.assertIn("designated site_admin by user %d" % self.root_row.pk, logs.output[0])

    def test_and_an_admin_of_every_organization(self):
        self._post(is_all_org_admin=True)
        self.person.refresh_from_db()
        self.assertEqual((self.person.is_site_admin, self.person.is_all_org_admin),
                         (False, True))
        self.assertEqual(self.person.admin_role_granted_by, self.root_row)

    def test_taking_it_away_clears_the_record(self):
        self._post(is_site_admin=True)
        self._post()
        self.person.refresh_from_db()
        self.assertEqual((self.person.is_site_admin, self.person.is_all_org_admin),
                         (False, False))
        self.assertIsNone(self.person.admin_role_granted_by)
        self.assertIsNone(self.person.admin_role_granted_at)

    def test_not_both(self):
        response = self._post(is_site_admin=True, is_all_org_admin=True)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "not both")
        self.person.refresh_from_db()
        self.assertFalse(self.person.is_site_admin)

    def test_staff_cannot_designate(self):
        from django.contrib.auth.models import Permission
        staff = DjangoUser.objects.create_user("staffer", "s@example.org", "pw",
                                               is_staff=True)
        staff.user_permissions.set(Permission.objects.filter(
            content_type__app_label="accounts", codename__in=["view_user", "change_user"]))
        client = self.client_class()
        client.force_login(staff)
        self._post(client, is_site_admin=True)
        self.person.refresh_from_db()
        self.assertFalse(self.person.is_site_admin)

    def test_a_bridge_row_is_not_designated(self):
        with self.assertRaises(ValueError):
            admin_roles.designate(self.root_row, None, self.root_row, "test")


class DesignatedSiteAdminTest(TestCase):
    """An eVerify sign-in a superuser designated: a site admin in all but
    the signing keys."""

    def setUp(self):
        self.a = make_org("Org A")
        self.b = make_org("Org B")
        self.person = User.objects.create(national_id_card_number="1111222233334444")
        admin_roles.designate(self.person, "site_admin", None, "test")
        sign_in(self.client, self.person, self.a)

    def test_has_the_site_pages_without_any_django_login(self):
        self.assertEqual(self.client.get(reverse("site_admin")).status_code, 200)
        self.assertEqual(set(organizations_open_to(self.person)), {self.a, self.b})

    def test_has_the_other_site_powers(self):
        other = User.objects.create(national_id_card_number="5555666677778888",
                                    device_restricted_tier=False)
        response = self.client.post(reverse("site_restricted_tier", args=[other.pk]),
                                    {"grant": True}, content_type="application/json")
        self.assertEqual(response.status_code, 200)
        other.refresh_from_db()
        self.assertTrue(other.device_restricted_tier)

    def test_cannot_publish_or_start_an_organization_key(self):
        with patch("verify.views.signing.signer_client.org_publish") as publish, \
                patch("verify.views.signing.signer_client.org_activate") as activate:
            self.client.post(reverse("signing_publish", args=[7]))
            self.client.post(reverse("signing_activate", args=[7]))
        publish.assert_not_called()
        activate.assert_not_called()
        self.assertFalse(self.person.switches_signing_keys)

    def test_pages_do_not_offer_the_keys(self):
        response = self.client.get(reverse("app"))
        self.assertIs(response.context["may_switch_keys"], False)

    def test_cannot_designate_anybody(self):
        """No site page sets either flag, and in Django admin only a
        superuser does: a designated site admin has no Django login."""
        other = User.objects.create(national_id_card_number="5555666677778888")
        self.client.post(reverse("admin:accounts_user_change", args=[other.pk]),
                         dict(FORM, national_id_card_number=other.national_id_card_number,
                              is_site_admin="on"))
        other.refresh_from_db()
        self.assertFalse(other.is_site_admin)

    def test_not_reported_by_w002(self):
        self.assertEqual(roles_outside_the_bridge(databases=["default"]), [])

    def test_the_superusers_row_still_switches_keys(self):
        root = DjangoUser.objects.create_superuser("root", "r@example.org", "pw")
        client = self.client_class()
        client.force_login(root)
        client.get(reverse("app"))
        row = User.objects.get(national_id_card_number=bridge_card(root.pk))
        self.assertTrue(row.switches_signing_keys)
        with patch("verify.views.signing.signer_client.org_publish") as publish:
            client.post(reverse("signing_publish", args=[7]))
        publish.assert_called_once()


class DesignatedAdminOfEveryOrganizationTest(TestCase):

    def setUp(self):
        self.a = make_org("Org A")
        self.b = make_org("Org B")
        self.person = User.objects.create(national_id_card_number="1111222233334444")
        admin_roles.designate(self.person, "all_org_admin", None, "test")
        sign_in(self.client, self.person, self.b)

    def test_enters_every_organization_as_its_admin_and_no_site_page(self):
        self.assertEqual(set(organizations_open_to(self.person)), {self.a, self.b})
        self.assertTrue(_is_org_admin(self.person, self.a))
        self.assertEqual(self.client.get(reverse("app_admin")).status_code, 200)
        self.assertNotEqual(self.client.get(reverse("site_admin")).status_code, 200)


class UndesignatedRoleTest(TestCase):

    def test_w002_still_reports_a_role_nobody_designated(self):
        User.objects.create(national_id_card_number="1111222233334444", is_site_admin=True)
        found = roles_outside_the_bridge(databases=["default"])
        self.assertEqual([w.id for w in found], ["accounts.W002"])
        self.assertIn("no superuser's designation is recorded", found[0].msg)
