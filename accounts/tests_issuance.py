"""Issuance and tenant defaults: who may rename an organization once it has
verified anybody, how a nameless operator is named, and what may still be
logged from an answer whose document was revoked.
"""

import json
import uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from accounts import (admin_roles, devices, org_names, user_records,
                      verified_answer)
from accounts.models import (DeviceTicket, IssuedCredential, Membership,
                             Organization, Transaction, TransactionType, User)
from accounts.tests import join, make_org
from verify.views import everify
from verify.views.helpers import ORG_SESSION_KEY

SESSION_KEY = "verify_user_id"
REPO = Path(settings.BASE_DIR)
ROWS = [{"field": "reference", "key": "National ID Card Number",
         "value": "3916098324035936"},
        {"field": "first_name", "key": "Given Name", "value": "JUAN MIGUEL"},
        {"field": "last_name", "key": "Last Name", "value": "DELA CRUZ"}]


def sign_in(client, user, org=None):
    session = client.session
    session[SESSION_KEY] = user.id
    if org is not None:
        session[ORG_SESSION_KEY] = org.id
    session.save()


def post_json(client, path, body):
    return client.post(path, data=json.dumps(body), content_type="application/json")


def issued(org):
    """The org has verified somebody."""
    return Transaction.objects.create(organization=org, authentication_result="success",
                                      transaction_type="Visit")


class OrganizationNameTest(TestCase):

    def setUp(self):
        self.org = make_org("Alpha Clinic")
        self.admin = User.objects.create(national_id_card_number="1111222233334444")
        join(self.org, self.admin, Membership.ROLE_ADMIN)
        self.site = User.objects.create(national_id_card_number="9999000011112222")
        admin_roles.designate(self.site, "site_admin", None, "test")

    def _rename(self, user, name):
        sign_in(self.client, user, self.org)
        return post_json(self.client, "/app/admin/profile/",
                         {"name": name, "subtitle": "", "mark_color": "#00386a"})

    def test_before_anything_is_issued_its_admins_set_it_up(self):
        with self.assertLogs("accounts.org_names", "WARNING") as logs:
            self.assertEqual(self._rename(self.admin, "Alpha Health").status_code, 200)
        self.org.refresh_from_db()
        self.assertEqual(self.org.name, "Alpha Health")
        self.assertIn("renamed by user %d: 'Alpha Clinic' -> 'Alpha Health'"
                      % self.admin.pk, logs.output[0])

    def test_once_it_has_verified_anybody_they_cannot(self):
        issued(self.org)
        response = self._rename(self.admin, "Philippine Statistics Authority")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(json.loads(response.content)["message"], org_names.LOCKED_MESSAGE)
        self.org.refresh_from_db()
        self.assertEqual(self.org.name, "Alpha Clinic")

    def test_an_issued_credential_counts_too(self):
        IssuedCredential.objects.create(
            credential_id=uuid.uuid4(), organization=self.org, document_uuid=uuid.uuid4(),
            epoch=1, issuer_key_id=1, issued_at=timezone.now(),
            expires_at=timezone.now() + timedelta(days=1))
        self.assertEqual(self._rename(self.admin, "Other").status_code, 403)

    def test_but_the_rest_of_the_profile_still_saves(self):
        issued(self.org)
        sign_in(self.client, self.admin, self.org)
        response = post_json(self.client, "/app/admin/profile/",
                             {"name": "Alpha Clinic", "subtitle": "Second floor",
                              "mark_color": "#112233"})
        self.assertEqual(response.status_code, 200)
        self.org.refresh_from_db()
        self.assertEqual(self.org.subtitle, "Second floor")

    def test_a_site_admin_still_renames_it_and_it_is_logged(self):
        issued(self.org)
        with self.assertLogs("accounts.org_names", "WARNING") as logs:
            self.assertEqual(self._rename(self.site, "Alpha Health").status_code, 200)
        self.assertIn("by user %d" % self.site.pk, logs.output[0])

    def test_the_site_page_logs_a_rename(self):
        issued(self.org)
        sign_in(self.client, self.site, self.org)
        form = {"name": "Alpha Health", "issuer_code": self.org.issuer_code or "ALPHA",
                "is_active": "on"}
        with self.assertLogs("accounts.org_names", "WARNING") as logs:
            self.client.post(reverse("site_organization", args=[self.org.pk]), form)
        self.org.refresh_from_db()
        self.assertEqual(self.org.name, "Alpha Health")
        self.assertIn("'Alpha Clinic' -> 'Alpha Health'", logs.output[0])

    def test_the_page_greys_the_name_out_when_it_is_locked(self):
        sign_in(self.client, self.admin, self.org)
        page = self.client.get("/app/admin/").content.decode()
        self.assertNotRegex(page, r'id="org-name"[^>]*\s+disabled')
        issued(self.org)
        page = self.client.get("/app/admin/").content.decode()
        self.assertRegex(page, r'id="org-name" value="Alpha Clinic" maxlength="255"\s+disabled')

    def test_django_admin_staff_cannot_rename_it_either(self):
        issued(self.org)
        staff = get_user_model().objects.create_user("staffer", "s@example.org", "pw",
                                                     is_staff=True)
        from django.contrib import admin as django_admin
        model_admin = django_admin.site._registry[Organization]
        request = type("R", (), {"user": staff})()
        self.assertIn("name", model_admin.get_readonly_fields(request, self.org))
        root = get_user_model().objects.create_superuser("root", "r@example.org", "pw")
        request.user = root
        self.assertNotIn("name", model_admin.get_readonly_fields(request, self.org))


class NamelessOperatorTest(TestCase):

    def setUp(self):
        self.org = make_org("Alpha Clinic")
        self.nameless = User.objects.create(national_id_card_number="1234567890123456")

    def test_the_public_name_is_never_the_id_number(self):
        self.assertEqual(self.nameless.public_name, "Operator %d" % self.nameless.pk)
        named = User.objects.create(national_id_card_number="2222333344445555",
                                    given_name="JUAN", last_name="DELA CRUZ")
        self.assertEqual(named.public_name, "JUAN DELA CRUZ")

    def test_the_credential_names_them_by_it(self):
        txn = Transaction.objects.create(
            organization=self.org, operator=self.nameless, authentication_result="success",
            operator_national_id_number="1234567890123456", transaction_type="Visit")
        with patch.object(everify.credential_keys, "configured", return_value=True), \
                patch.object(everify.minting, "mint_recorded", return_value=MagicMock()) as mint:
            everify._mint_credential(txn, self.org, None, ROWS, None)
        operator_name = mint.call_args.kwargs["operator_name"]
        self.assertEqual(operator_name, "Operator %d" % self.nameless.pk)
        self.assertNotIn("1234567890123456", json.dumps(
            {k: str(v) for k, v in mint.call_args.kwargs.items()}))

    def test_the_pairing_code_and_connect_too(self):
        ticket = DeviceTicket.objects.create(
            user=self.nameless, purpose=DeviceTicket.PURPOSE_ENROL,
            expires_at=timezone.now() + timedelta(minutes=10))
        payload = json.loads(devices.ticket_payload(ticket, url="https://verify.example.ph"))
        self.assertEqual(payload["for"], "Operator %d" % self.nameless.pk)
        source = (REPO / "verify" / "views" / "device_api.py").read_text(encoding="utf-8")
        self.assertIn('"for": owner.public_name[:60],', source)
        self.assertNotIn("owner.national_id_card_number)[:60]", source)


class RevokedAnswerTest(TestCase):

    CARD = "3916098324035936"

    def setUp(self):
        self.org = make_org("Alpha Clinic")
        self.operator = User.objects.create(national_id_card_number="1111222233334444",
                                            given_name="Ada", last_name="Lovelace")
        join(self.org, self.operator)
        self.type = TransactionType.objects.create(organization=self.org, name="Visit")
        self.other_type = TransactionType.objects.create(organization=self.org,
                                                         name="Claim")
        sign_in(self.client, self.operator, self.org)
        self._keep()

    def _keep(self):
        session = self.client.session
        verified_answer.keep(session, self.org, ROWS, user_records.subject_key(self.CARD))
        session.save()

    def _log(self, kind=None):
        return post_json(self.client, "/everify/log-transaction/",
                         {"transaction_type": str((kind or self.type).id)})

    def _credential_for(self, txn, revoked=False):
        return IssuedCredential.objects.create(
            credential_id=uuid.uuid4(), transaction=txn, organization=self.org,
            document_uuid=txn.transaction_id, epoch=1, issuer_key_id=1,
            issued_at=timezone.now(), expires_at=timezone.now() + timedelta(days=1),
            revoked_at=timezone.now() if revoked else None)

    def _revoke_the_first(self):
        self._credential_for(Transaction.objects.order_by("id").first(), revoked=True)

    def test_an_answer_may_still_be_logged_twice(self):
        """A lost response is retryable, and one person may be logged for
        two types."""
        self.assertEqual(self._log().status_code, 200)
        with self.assertLogs("verify.views.everify", "WARNING") as logs:
            self.assertEqual(self._log(self.other_type).status_code, 200)
        self.assertEqual(Transaction.objects.count(), 2)
        self.assertIn("logged one answer again", logs.output[0])
        self.assertIn("after 1 earlier", logs.output[0])

    def test_not_once_its_document_was_revoked(self):
        self.assertEqual(self._log().status_code, 200)
        self._revoke_the_first()
        with self.assertLogs("verify.views.everify", "WARNING"):
            response = self._log()
        self.assertEqual(response.status_code, 409)
        self.assertEqual(json.loads(response.content)["message"],
                         everify.REVOKED_SINCE_MESSAGE)
        self.assertEqual(Transaction.objects.count(), 1)
        self.assertIsNone(verified_answer.rows(self.client.session, self.org))

    def test_a_document_still_valid_does_not_stop_it(self):
        self._log()
        self._credential_for(Transaction.objects.get(), revoked=False)
        self.assertEqual(self._log().status_code, 200)

    def test_a_new_lookup_starts_afresh(self):
        self._log()
        self._revoke_the_first()
        Transaction.objects.update(
            verification_timestamp=timezone.now() - timedelta(seconds=5))
        self._keep()
        self.assertEqual(self._log().status_code, 200)

    def test_another_persons_revocation_is_not_this_ones(self):
        other = Transaction.objects.create(
            organization=self.org, operator=self.operator, authentication_result="success",
            subject_key=user_records.subject_key("9999888877776666"))
        self._credential_for(other, revoked=True)
        self._log()
        self.assertEqual(self._log().status_code, 200)

    def test_another_operators_revocation_is_not_this_ones(self):
        colleague = User.objects.create(national_id_card_number="2222333344445555")
        theirs = Transaction.objects.create(
            organization=self.org, operator=colleague, authentication_result="success",
            subject_key=user_records.subject_key(self.CARD))
        self._credential_for(theirs, revoked=True)
        self.assertEqual(self._log().status_code, 200)

    def test_logging_writes_no_session(self):
        """The answer records when it was kept; the log adds nothing to it,
        because the session carries the person's rows and face."""
        from django.db import connection
        from django.test.utils import CaptureQueriesContext
        self._log()
        with CaptureQueriesContext(connection) as queries:
            self.assertEqual(self._log().status_code, 200)
        self.assertFalse([q for q in queries.captured_queries
                          if q["sql"].startswith("UPDATE \"django_session\"")])

    def test_an_answer_kept_before_the_time_was_recorded_still_logs(self):
        session = self.client.session
        answer = dict(session[verified_answer.KEY])
        answer.pop("kept_at")
        session[verified_answer.KEY] = answer
        session.save()
        self.assertIsNone(verified_answer.kept_at(self.client.session, self.org))
        self.assertEqual(self._log().status_code, 200)


class OrganizationNameSpellingTest(TestCase):
    """One organization per name in any spelling, and one script per name:
    a phone shows "alpha clinic", "ALPHA  CLINIC." and a fullwidth form
    alike, and SQLite's case-insensitive match folds only ASCII."""

    def setUp(self):
        self.taken = make_org("Alpha Clinic")
        self.org = make_org("Beta Office")
        self.admin = User.objects.create(national_id_card_number="1111222233334444")
        join(self.org, self.admin, Membership.ROLE_ADMIN)
        self.site = User.objects.create(national_id_card_number="9999000011112222")
        admin_roles.designate(self.site, "site_admin", None, "test")

    def _rename(self, name, user=None):
        sign_in(self.client, user or self.admin, self.org)
        return post_json(self.client, "/app/admin/profile/",
                         {"name": name, "subtitle": "", "mark_color": "#00386a"})

    def test_another_spelling_of_a_taken_name_is_refused(self):
        for name in ("alpha clinic", "ALPHA  CLINIC.", "Ａlpha Clinic",
                     "Alpha-Clinic"):
            with self.subTest(name=name):
                response = self._rename(name)
                self.assertEqual(response.status_code, 400)
                self.assertIn("'Alpha Clinic' already exists",
                              json.loads(response.content)["message"])

    def test_a_name_mixing_scripts_is_refused(self):
        response = self._rename("Аlpha Health")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.content)["message"],
                         org_names.MIXED_SCRIPT_MESSAGE)

    def test_its_own_name_respelled_is_fine(self):
        self.assertEqual(self._rename("BETA OFFICE").status_code, 200)

    def test_the_site_page_and_django_admin_hold_the_same_rule(self):
        sign_in(self.client, self.site, self.org)
        page = self.client.post(reverse("site_organization", args=[self.org.pk]),
                                {"name": "alpha  clinic", "is_active": "on",
                                 "issuer_code": self.org.issuer_code or "BETA"})
        self.assertContains(page, "already exists")
        from accounts.admin import OrganizationAdminForm
        form = OrganizationAdminForm(instance=self.org, data={"name": "ALPHA CLINIC"})
        form.is_valid()
        self.assertIn("name", form.errors)

    def test_verify_and_the_signer_compare_names_alike(self):
        from signer import registry
        for name in ("Alpha Clinic", "ALPHA  CLINIC.", "Ａlpha Clinic",
                     "Nuestra Señora, Inc.", "Альфа",
                     "Beta Office", ""):
            with self.subTest(name=name):
                self.assertEqual(org_names.name_key(name), registry.name_key(name))
                self.assertEqual(org_names.mixed_script(name),
                                 registry.mixed_script(name))
        self.assertTrue(org_names.mixed_script("Αlpha"))
        self.assertEqual(org_names.CONFUSABLE_SCRIPTS, registry.CONFUSABLE_SCRIPTS)


class FailureDoesNotLockTheNameTest(TestCase):

    def test_a_failed_attempt_puts_the_name_on_nothing(self):
        org = make_org("Alpha Clinic")
        Transaction.objects.create(organization=org, authentication_result="failure")
        self.assertFalse(org_names.has_issued(org))
        issued(org)
        self.assertTrue(org_names.has_issued(org))


class RevokeShowsTheSparesTest(TestCase):
    """An answer logged twice makes two credentials; whoever revokes one is
    shown the other and may revoke it too."""

    def setUp(self):
        self.org = make_org("Alpha Clinic")
        self.operator = User.objects.create(national_id_card_number="1111222233334444")
        key = user_records.subject_key("3916098324035936")
        self.first, self.spare = (self._issued(key) for _ in range(2))
        self.other_person = self._issued(user_records.subject_key("9999888877776666"))
        self.long_ago = self._issued(key, hours_ago=48)
        root = get_user_model().objects.create_superuser("root", "r@example.org", "pw")
        self.client.force_login(root)
        self.url = reverse("admin:accounts_issuedcredential_changelist")

    def _issued(self, subject, hours_ago=0):
        txn = Transaction.objects.create(
            organization=self.org, operator=self.operator,
            authentication_result="success", subject_key=subject)
        Transaction.objects.filter(pk=txn.pk).update(
            verification_timestamp=timezone.now() - timedelta(hours=hours_ago))
        return IssuedCredential.objects.create(
            credential_id=uuid.uuid4(), transaction=txn, organization=self.org,
            document_uuid=txn.transaction_id, epoch=1, issuer_key_id=1,
            issued_at=timezone.now(), expires_at=timezone.now() + timedelta(days=1))

    def _revoke(self, **extra):
        data = {"action": "revoke_selected", "_selected_action": [self.first.pk]}
        data.update(extra)
        return self.client.post(self.url, data)

    def test_the_confirmation_lists_the_spare_and_nothing_else(self):
        page = self._revoke()
        self.assertEqual([c.pk for c in page.context["siblings"]], [self.spare.pk])
        self.assertContains(page, 'name="also" value="%d"' % self.spare.pk)

    def test_ticking_it_revokes_it_too(self):
        self._revoke(post="yes", reason="spare copies", shown="1",
                     also=[str(self.spare.pk)])
        for credential, revoked in ((self.first, True), (self.spare, True),
                                    (self.other_person, False), (self.long_ago, False)):
            credential.refresh_from_db()
            self.assertEqual(credential.revoked_at is not None, revoked, credential.pk)

    def test_not_ticking_it_leaves_it(self):
        self._revoke(post="yes", reason="one copy", shown="1")
        self.spare.refresh_from_db()
        self.assertIsNone(self.spare.revoked_at)

    def test_a_posted_id_that_is_no_spare_is_ignored(self):
        self._revoke(post="yes", reason="x", shown="1", also=[str(self.other_person.pk)])
        self.other_person.refresh_from_db()
        self.assertIsNone(self.other_person.revoked_at)
