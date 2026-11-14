"""User Records: a verified person's transactions, across organizations.

What these pin, in the order the feature depends on them:

  * the key names nobody, is the same for the same card however it is
    typed, and the migration's copy of it agrees with the module's;
  * the person comes ONLY from eVerify's answer in this session -- never from
    the request, so nobody's history can be read by typing their number;
  * the key is written whatever the organization's field settings say;
  * the list is successful rows only, from every organization, newest first;
  * the organization's switch, and who may change it.
"""

import datetime
import importlib
import json
from unittest.mock import MagicMock, patch

from django.apps import apps
from django.conf import settings
from django.test import TestCase, override_settings
from django.utils import timezone

from accounts import admin_roles, user_records, verified_answer
from accounts.models import (Location, Membership, Organization,
                             OrganizationFieldSetting, SiteSettings,
                             Transaction, TransactionType, User, UserSettings)
from accounts.tests_holders import HolderTestBase
from verify.views.helpers import DEMO_MASK_CHAR, ORG_SESSION_KEY

SESSION_KEY = "verify_user_id"

PERSON = "1234567890123456"
OTHER = "9999888877776666"


def make_org(name, **kwargs):
    fields = dict(everify_client_id="org-id", everify_client_secret="org-secret")
    fields.update(kwargs)
    org = Organization.objects.create(name=name, **fields)
    Location.objects.create(organization=org, name="Main Office")
    return org


def join(org, user, role=Membership.ROLE_OPERATOR):
    return Membership.objects.create(organization=org, user=user, role=role)


def sign_in(client, user, org):
    session = client.session
    session[SESSION_KEY] = user.id
    session[ORG_SESSION_KEY] = org.id
    session.save()


def verified(client, card_number):
    """Leave the session as a successful verification of `card_number`, for
    the organization signed in, does: eVerify's answer kept, with its key."""
    session = client.session
    org = Organization.objects.get(pk=session[ORG_SESSION_KEY])
    verified_answer.keep(
        session, org,
        [{"field": "reference", "key": "National ID Card Number",
          "value": card_number},
         {"field": "first_name", "key": "Given Name", "value": "Juan"}],
        user_records.subject_key(card_number))
    session.save()


def subject(client, org):
    """The User Records key the session holds for `org`, or ""."""
    return verified_answer.subject(client.session, org)


def record(org, operator, card_number, *, when, result="success",
           transaction_type="Visitor Access", **extra):
    """A logged row, linked to its organization's type as a verification links
    it: a row with no link is one whose type was deleted, which other
    organizations' User Records do not name."""
    if org is not None and "transaction_type_ref" not in extra:
        extra["transaction_type_ref"], _ = TransactionType.objects.get_or_create(
            organization=org, name=transaction_type)
    txn = Transaction.objects.create(
        organization=org, operator=operator, authentication_result=result,
        transaction_type=transaction_type,
        subject_key=user_records.subject_key(card_number), **extra)
    Transaction.objects.filter(pk=txn.pk).update(verification_timestamp=when)
    txn.refresh_from_db()
    return txn


class UserRecordsKeyTest(TestCase):
    """The key names one person, and nobody can read the number out of it."""

    def test_the_same_card_however_it_is_typed(self):
        self.assertEqual(user_records.subject_key("1234-5678-9012-3456"),
                         user_records.subject_key(PERSON))
        self.assertEqual(user_records.subject_key("1234 5678 9012 3456"),
                         user_records.subject_key(PERSON))

    def test_two_people_are_two_keys(self):
        self.assertNotEqual(user_records.subject_key(PERSON),
                            user_records.subject_key(OTHER))

    def test_the_key_does_not_carry_the_number(self):
        key = user_records.subject_key(PERSON)
        self.assertEqual(len(key), 64)
        self.assertNotIn(PERSON, key)
        self.assertNotIn(PERSON[-8:], key)

    def test_the_card_number_wins_over_the_digital_id(self):
        self.assertEqual(user_records.subject_key(PERSON, "ABC1234"),
                         user_records.subject_key(PERSON))

    def test_the_digital_id_is_used_when_there_is_no_card_number(self):
        key = user_records.subject_key("", "abc1234")
        self.assertTrue(key)
        self.assertEqual(key, user_records.subject_key("", "ABC1234"))
        self.assertNotEqual(key, user_records.subject_key(PERSON))

    def test_nothing_to_key_on_is_no_key(self):
        self.assertEqual(user_records.subject_key("", ""), "")
        self.assertEqual(user_records.subject_key(None, None), "")
        self.assertEqual(user_records.subject_key("123", ""), "")

    def test_the_key_depends_on_this_servers_secret(self):
        before = user_records.subject_key(PERSON)
        with override_settings(USER_RECORDS_KEY="another-instance"):
            self.assertNotEqual(user_records.subject_key(PERSON), before)

    def test_the_migrations_copy_agrees_with_the_module(self):
        migration = importlib.import_module("accounts.migrations.0039_user_records")
        for card, code in ((PERSON, ""), ("1234-5678-9012-3456", "X"),
                           ("", "abc1234"), ("", ""), ("12", "")):
            self.assertEqual(migration.subject_key(card, code),
                             user_records.subject_key(card, code))
        with override_settings(USER_RECORDS_KEY="another-instance"):
            self.assertEqual(migration.subject_key(PERSON, ""),
                             user_records.subject_key(PERSON))


class BackfillTest(TestCase):
    """Existing successful rows that kept a number are keyed by the migration."""

    def test_backfill(self):
        migration = importlib.import_module("accounts.migrations.0039_user_records")
        org = make_org("Alpha")
        kept = Transaction.objects.create(
            organization=org, authentication_result="success",
            national_id_card_number=PERSON)
        by_digital_id = Transaction.objects.create(
            organization=org, authentication_result="success",
            digital_national_id_number="ABC1234")
        not_logged = Transaction.objects.create(
            organization=org, authentication_result="success")
        failed = Transaction.objects.create(
            organization=org, authentication_result="failure",
            national_id_card_number=PERSON)

        migration.backfill(apps, None)

        for txn in (kept, by_digital_id, not_logged, failed):
            txn.refresh_from_db()
        self.assertEqual(kept.subject_key, user_records.subject_key(PERSON))
        self.assertEqual(by_digital_id.subject_key,
                         user_records.subject_key("", "ABC1234"))
        self.assertEqual(not_logged.subject_key, "")
        self.assertEqual(failed.subject_key, "",
                         "a failed attempt's number is whatever was typed")


class VerifiedSubjectComesFromTheUpstreamTest(TestCase):
    """The session's person is eVerify's answer, and only a successful one."""

    def setUp(self):
        self.operator = User.objects.create(
            national_id_card_number="1111222233334444", given_name="Ada")
        self.org = make_org("Alpha")
        join(self.org, self.operator)
        site = SiteSettings.load()
        site.everify_base_url = "https://site.example/api"
        site.everify_client_id = "site-id"
        site.everify_client_secret = "site-secret"
        site.save()

    def _upstream(self, data):
        def post(url, json=None, headers=None, timeout=None, **kwargs):
            response = MagicMock(status_code=200)
            if url.endswith("/auth"):
                response.json.return_value = {"data": {"access_token": "tok"}}
            else:
                response.json.return_value = {"data": dict(data)}
            return response
        return post

    def _query(self, value, data):
        with patch("verify.views.everify.requests.post",
                   side_effect=self._upstream(data)):
            return self.client.post(
                "/everify/",
                data=json.dumps({"value": value,
                                 "face_liveness_session_id": "sess"}),
                content_type="application/json")

    def test_a_successful_verification_names_the_person_everify_returned(self):
        """The QR said OTHER; eVerify said PERSON. PERSON is who was verified."""
        sign_in(self.client, self.operator, self.org)
        self._query(OTHER, {"reference": PERSON, "code": "ABC1234",
                            "first_name": "Juan"})
        self.assertEqual(subject(self.client, self.org),
                         user_records.subject_key(PERSON))

    def test_a_failed_verification_drops_the_previous_person(self):
        sign_in(self.client, self.operator, self.org)
        verified(self.client, OTHER)
        self._query(PERSON, {"reference": PERSON, "first_name": "Juan",
                             "verified": False})
        self.assertNotIn(verified_answer.KEY, self.client.session)

    def test_a_verification_that_named_nobody_drops_it_too(self):
        sign_in(self.client, self.operator, self.org)
        verified(self.client, OTHER)
        self._query(PERSON, {"token": "t"})
        self.assertNotIn(verified_answer.KEY, self.client.session)

    def test_signing_in_is_not_verifying_anybody(self):
        self._query("1111222233334444", {"reference": "1111222233334444",
                                         "first_name": "Ada"})
        self.assertNotIn(verified_answer.KEY, self.client.session)


class LoggedTransactionsCarryTheKeyTest(TestCase):
    """The key on a logged row is the session's, whatever the page posted and
    whatever the organization logs."""

    def setUp(self):
        self.operator = User.objects.create(
            national_id_card_number="1111222233334444", given_name="Ada")
        self.org = make_org("Alpha")
        join(self.org, self.operator)
        self.type = TransactionType.objects.create(
            organization=self.org, name="Visitor Access")
        sign_in(self.client, self.operator, self.org)

    def _log(self, card_number):
        return self.client.post(
            "/everify/log-transaction/",
            data=json.dumps({
                "transaction_type": str(self.type.id),
                "result": "success",
                "verification_data": [
                    {"field": "reference", "key": "National ID Card Number",
                     "value": card_number},
                    {"field": "first_name", "key": "Given Name", "value": "Juan"},
                ]}),
            content_type="application/json")

    def test_the_row_is_keyed_to_who_was_verified(self):
        verified(self.client, PERSON)
        self._log(PERSON)
        self.assertEqual(Transaction.objects.get().subject_key,
                         user_records.subject_key(PERSON))

    def test_the_posted_number_does_not_choose_the_key(self):
        """A page that posted somebody else's number cannot file this
        transaction in their history."""
        verified(self.client, PERSON)
        self._log(OTHER)
        self.assertEqual(Transaction.objects.get().subject_key,
                         user_records.subject_key(PERSON))

    def test_keyed_even_when_the_organization_logs_no_id_number(self):
        for key in ("reference", "code"):
            OrganizationFieldSetting.objects.create(
                organization=self.org, key=key, include_in_log=False)
        verified(self.client, PERSON)
        self._log(PERSON)
        txn = Transaction.objects.get()
        self.assertEqual(txn.national_id_card_number, "",
                         "Log off must still mean the number is not kept")
        self.assertEqual(txn.subject_key, user_records.subject_key(PERSON))

    def test_no_verified_person_is_no_transaction(self):
        """With nothing on file to log, nothing is logged at all -- not even a
        row without a key."""
        response = self._log(PERSON)
        self.assertEqual(response.status_code, 409)
        self.assertFalse(Transaction.objects.exists())

    def test_an_answer_naming_no_number_is_no_key(self):
        session = self.client.session
        verified_answer.keep(
            session, self.org,
            [{"field": "first_name", "key": "Given Name", "value": "Juan"}], "")
        session.save()
        self._log(PERSON)
        self.assertEqual(Transaction.objects.get().subject_key, "")


class UserRecordsApiTest(TestCase):
    """GET /app/user-records/: the session's person, every organization,
    successful rows, newest first."""

    def setUp(self):
        self.here = make_org("Ateneo BUILD-TRL")
        self.clinic = make_org("Community Health Clinic")
        self.office = make_org("Social Welfare Office")
        self.operator = User.objects.create(
            national_id_card_number="1111222233334444",
            given_name="Maria", last_name="Reyes")
        join(self.here, self.operator)
        self.nurse = User.objects.create(
            national_id_card_number="2222333344445555",
            given_name="Liza", last_name="Mendoza")
        join(self.clinic, self.nurse)
        self.clerk = User.objects.create(
            national_id_card_number="3333444455556666",
            given_name="Andres", last_name="Bautista")
        join(self.office, self.clerk)

        tz = timezone.get_current_timezone()
        self.newest = record(
            self.clinic, self.nurse, PERSON,
            transaction_type="Medical Consultation",
            when=datetime.datetime(2026, 10, 5, 14, 14, tzinfo=tz))
        self.middle = record(
            self.office, self.clerk, PERSON,
            transaction_type="Cash Assistance Claim",
            when=datetime.datetime(2026, 9, 12, 9, 41, tzinfo=tz))
        self.oldest = record(
            self.here, self.operator, PERSON,
            when=datetime.datetime(2026, 8, 30, 15, 55, tzinfo=tz))
        # Not listed: a failure for the same person, and somebody else.
        record(self.office, self.clerk, PERSON, result="failure",
               when=datetime.datetime(2026, 10, 6, 8, 0, tzinfo=tz))
        record(self.clinic, self.nurse, OTHER,
               when=datetime.datetime(2026, 10, 6, 9, 0, tzinfo=tz))

        sign_in(self.client, self.operator, self.here)
        verified(self.client, PERSON)

    def _get(self, query=""):
        return self.client.get("/app/user-records/" + query)

    def _records(self, query=""):
        response = self._get(query)
        self.assertEqual(response.status_code, 200)
        return json.loads(response.content)

    def test_every_organization_newest_first(self):
        data = self._records()
        self.assertTrue(data["available"])
        self.assertEqual(
            [(r["organization"], r["transaction_type"], r["operator"])
             for r in data["records"]],
            [("Community Health Clinic", "Medical Consultation", "Liza Mendoza"),
             ("Social Welfare Office", "Cash Assistance Claim", "Andres Bautista"),
             ("Ateneo BUILD-TRL", "Visitor Access", "Maria Reyes")])
        self.assertEqual(data["organizations"], 3)
        self.assertFalse(data["truncated"])

    def test_the_time_is_spelled_as_the_document_spells_it(self):
        self.assertEqual(self._records()["records"][0]["when"],
                         "Oct 05 2026 02:14 PM")

    def test_failures_and_other_people_are_not_listed(self):
        self.assertEqual(len(self._records()["records"]), 3)

    def test_the_request_cannot_choose_whose_records(self):
        other = user_records.subject_key(OTHER)
        for query in ("?subject=" + other, "?key=" + other,
                      "?pcn=" + OTHER, "?card_number=" + OTHER):
            names = [r["operator"] for r in self._records(query)["records"]]
            self.assertEqual(len(names), 3, query)

    def test_no_verified_person_is_not_the_same_as_no_history(self):
        session = self.client.session
        verified_answer.forget(session)
        session.save()
        data = self._records()
        self.assertFalse(data["available"])
        self.assertEqual(data["records"], [])

    def test_a_person_verified_for_another_organization_is_not_reported(self):
        """The answer belongs to the organization that asked. Switching to
        another must not carry the person across -- least of all to one
        whose User Records is on when the first one's was off."""
        session = self.client.session
        verified_answer.keep(session, self.clinic, [],
                             user_records.subject_key(PERSON))
        session.save()
        data = self._records()
        self.assertFalse(data["available"])
        self.assertEqual(data["records"], [])

    def test_the_transaction_just_logged_is_marked(self):
        data = self._records("?current=" + str(self.oldest.transaction_id))
        self.assertEqual([r["current"] for r in data["records"]],
                         [False, False, True])

    def test_off_for_this_organization_is_refused(self):
        self.here.check_user_records = False
        self.here.save()
        self.assertEqual(self._get().status_code, 403)

    def test_another_organizations_switch_does_not_hide_its_records(self):
        self.clinic.check_user_records = False
        self.clinic.save()
        names = [r["organization"] for r in self._records()["records"]]
        self.assertIn("Community Health Clinic", names)

    def test_signed_out_is_refused(self):
        self.client.logout()
        session = self.client.session
        session[verified_answer.KEY] = {
            "organization": self.here.pk, "rows": [],
            "subject": user_records.subject_key(PERSON)}
        session.save()
        self.assertEqual(self._get().status_code, 403)

    def test_not_cached(self):
        self.assertEqual(self._get()["Cache-Control"], "no-store")

    def test_demo_mode_masks_operator_names(self):
        UserSettings.objects.create(user=self.operator, demo_mode=True)
        operators = [r["operator"] for r in self._records()["records"]]
        self.assertEqual(operators[0].split()[0], "Liza")
        for name in operators:
            self.assertIn(DEMO_MASK_CHAR, name)
        self.assertNotIn("Mendoza", json.dumps(operators))

    def test_a_site_admin_from_outside_says_so(self):
        admin = User.objects.create(
            national_id_card_number="4444555566667777",
            given_name="Sam", last_name="Cruz", is_site_admin=True)
        record(self.clinic, admin, PERSON, acting_as_site_admin=True,
               when=timezone.now())
        self.assertEqual(self._records()["records"][0]["operator"],
                         "Sam Cruz (site admin)")

    def test_an_admin_of_every_organization_from_outside_says_so(self):
        admin = User.objects.create(
            national_id_card_number="4444555566667777",
            given_name="Sam", last_name="Cruz", is_all_org_admin=True)
        record(self.clinic, admin, PERSON, acting_as_all_org_admin=True,
               when=timezone.now())
        self.assertEqual(self._records()["records"][0]["operator"],
                         "Sam Cruz (admin of every organization)")

    def test_a_self_verification_is_named_by_its_issuer(self):
        record(None, None, PERSON, transaction_type="Self-verification",
               operator_location="Self-verified with idmanager",
               when=timezone.now())
        first = self._records()["records"][0]
        self.assertEqual(first["organization"], "Self-verified with idmanager")
        self.assertEqual(first["operator"], "—")

    def test_a_deleted_organizations_row_keeps_its_place(self):
        gone = make_org("Gone")
        record(gone, self.nurse, PERSON, when=timezone.now())
        gone.delete()
        first = self._records()["records"][0]
        self.assertEqual(first["organization"], "Deleted organization")

    def test_only_the_newest_are_sent_and_the_page_is_told(self):
        with patch.object(user_records, "MAX_RECORDS", 2):
            data = self._records()
        self.assertEqual(len(data["records"]), 2)
        self.assertTrue(data["truncated"])
        self.assertEqual(data["limit"], 2)


class DocumentPageCardTest(TestCase):
    """The card is on the document page when the switch is on, and never on
    paper."""

    def setUp(self):
        self.org = make_org("Alpha")
        self.operator = User.objects.create(
            national_id_card_number="1111222233334444", given_name="Ada")
        join(self.org, self.operator)
        sign_in(self.client, self.operator, self.org)
        session = self.client.session
        verified_answer.keep(session, self.org, [
            {"field": "first_name", "key": "Given Name", "value": "Juan"}])
        session.save()

    def test_shown_when_on(self):
        page = self.client.get("/app/document/").content.decode()
        self.assertIn('id="user-records"', page)
        self.assertIn("/app/user-records/", page)

    def test_absent_when_off(self):
        self.org.check_user_records = False
        self.org.save()
        page = self.client.get("/app/document/").content.decode()
        self.assertNotIn('id="user-records"', page)
        self.assertNotIn("/app/user-records/", page)

    def test_hidden_from_print_and_outside_the_sheet(self):
        from accounts.tests import _is_inside

        page = self.client.get("/app/document/").content.decode()
        self.assertRegex(page, r"@media print \{[^}]*\.user-records[^}]*display: none")
        self.assertFalse(_is_inside(page, "doc-page", "user-records"),
                         "inside the sheet, it would be in the PDF")


class CheckUserRecordsSwitchTest(TestCase):
    """A site admin turns it on and off, one organization at a time."""

    def setUp(self):
        self.org = make_org("Alpha")
        self.other = make_org("Beta")
        self.admin = User.objects.create(
            national_id_card_number="1111222233334444", given_name="Ada")
        admin_roles.designate(self.admin, "site_admin", None, "test")
        join(self.org, self.admin, Membership.ROLE_ADMIN)
        join(self.other, self.admin, Membership.ROLE_ADMIN)
        self.operator = User.objects.create(
            national_id_card_number="2222333344445555", given_name="Ben")
        join(self.org, self.operator)

    def _save(self, value):
        return self.client.post("/app/admin/verification/",
                                data=json.dumps({"check_user_records": value}),
                                content_type="application/json")

    def test_on_by_default(self):
        self.assertTrue(Organization.objects.create(name="New").check_user_records)

    def test_an_admin_turns_it_off_and_on(self):
        sign_in(self.client, self.admin, self.org)
        self.assertEqual(self._save(False).status_code, 200)
        self.org.refresh_from_db()
        self.assertFalse(self.org.check_user_records)
        self._save(True)
        self.org.refresh_from_db()
        self.assertTrue(self.org.check_user_records)

    def test_only_the_sessions_organization_changes(self):
        sign_in(self.client, self.admin, self.org)
        self._save(False)
        self.other.refresh_from_db()
        self.assertTrue(self.other.check_user_records)

    def test_an_operator_cannot(self):
        sign_in(self.client, self.operator, self.org)
        self.assertEqual(self._save(False).status_code, 403)
        self.org.refresh_from_db()
        self.assertTrue(self.org.check_user_records)

    def test_only_a_real_boolean(self):
        """"false" is a truthy string: it must not turn the switch on."""
        sign_in(self.client, self.admin, self.org)
        self._save(False)
        for value in ("false", "true", 1, None):
            self.assertEqual(self._save(value).status_code, 400, value)
        self.org.refresh_from_db()
        self.assertFalse(self.org.check_user_records)

    def test_the_organization_page_shows_the_switch_as_it_is(self):
        sign_in(self.client, self.admin, self.org)
        page = self.client.get("/app/admin/").content.decode()
        self.assertRegex(page, r'id="check-user-records"\s+checked')
        self.org.check_user_records = False
        self.org.save()
        page = self.client.get("/app/admin/").content.decode()
        self.assertIn('id="check-user-records"', page)
        self.assertNotRegex(page, r'id="check-user-records"\s+checked')


class HolderSelfVerificationIsKeyedTest(HolderTestBase):
    """A holder's own self-verification belongs in their User Records."""

    def test_keyed_to_the_holder(self):
        self.register()
        txn = Transaction.objects.get()
        self.assertEqual(txn.subject_key,
                         user_records.subject_key("1234567890123456"))


class RepeatAlertApiTest(TestCase):
    """Which rows COUNT AS A REPEAT is the server's: logged here, by
    organization id, inside this organization's window, with the alert on.
    Whether the type matches is the page's, so it is not decided here."""

    def setUp(self):
        self.here = make_org("Alpha")
        self.clinic = make_org("Clinic")
        self.operator = User.objects.create(
            national_id_card_number="1111222233334444",
            given_name="Maria", last_name="Reyes")
        join(self.here, self.operator)
        sign_in(self.client, self.operator, self.here)
        verified(self.client, PERSON)
        self.now = timezone.now()

    def days_ago(self, days, org=None, **extra):
        return record(org or self.here, self.operator, PERSON,
                      when=self.now - datetime.timedelta(days=days), **extra)

    def _data(self, query=""):
        response = self.client.get("/app/user-records/" + query)
        self.assertEqual(response.status_code, 200)
        return json.loads(response.content)

    def _counts(self, query=""):
        return [r["counts_as_repeat"] for r in self._data(query)["records"]]

    def test_here_inside_the_window_counts(self):
        self.days_ago(10)
        self.days_ago(89)
        self.assertEqual(self._counts(), [True, True])

    def test_here_outside_the_window_does_not(self):
        self.days_ago(91)
        self.assertEqual(self._counts(), [False])

    def test_another_organizations_row_never_counts(self):
        self.days_ago(1, org=self.clinic)
        self.assertEqual(self._counts(), [False])

    def test_here_is_the_organization_not_its_name(self):
        """A self-verification is listed under its issuer's text, which can
        read exactly like this organization's name. It was not logged here."""
        record(None, None, PERSON, transaction_type="Self-verification",
               operator_location="Alpha", when=self.now)
        data = self._data()
        self.assertEqual(data["records"][0]["organization"], "Alpha")
        self.assertEqual(self._counts(), [False])

    def test_zero_days_is_any_time(self):
        self.here.repeat_alert_days = 0
        self.here.save()
        self.days_ago(2000)
        self.assertEqual(self._counts(), [True])
        self.assertEqual(self._data()["repeat_alert"], {"days": 0})

    def test_the_window_is_this_organizations(self):
        self.here.repeat_alert_days = 30
        self.here.save()
        self.days_ago(20)
        self.days_ago(40)
        self.assertEqual(self._counts(), [True, False])
        self.assertEqual(self._data()["repeat_alert"], {"days": 30})

    def test_on_and_ninety_days_unless_changed(self):
        self.assertEqual(self._data()["repeat_alert"], {"days": 90})

    def test_off_counts_nothing_and_says_so(self):
        self.here.repeat_alert = False
        self.here.save()
        self.days_ago(1)
        data = self._data()
        self.assertIsNone(data["repeat_alert"])
        self.assertEqual(self._counts(), [False])

    def test_the_row_just_logged_is_not_a_repeat_of_itself(self):
        logged = self.days_ago(0)
        self.days_ago(5)
        data = self._data("?current=" + str(logged.transaction_id))
        self.assertEqual([(r["current"], r["counts_as_repeat"])
                          for r in data["records"]],
                         [(True, False), (False, True)])

    def test_the_type_is_left_to_the_page(self):
        self.days_ago(1, transaction_type="Medical Assistance")
        self.days_ago(2, transaction_type="Burial Assistance")
        self.assertEqual(self._counts(), [True, True])

    def test_the_window_opens_where_the_days_say(self):
        now = timezone.now()
        self.assertEqual(user_records.repeat_window(self.here, now),
                         (True, now - datetime.timedelta(days=90)))
        self.here.repeat_alert_days = 0
        self.assertEqual(user_records.repeat_window(self.here, now),
                         (True, None))
        self.here.repeat_alert = False
        self.assertEqual(user_records.repeat_window(self.here, now),
                         (False, None))


class RepeatAlertSettingTest(TestCase):
    """The organization's own admins set the alert and its window, with
    nothing but a real boolean and a whole number of days."""

    def setUp(self):
        self.org = make_org("Alpha")
        self.other = make_org("Beta")
        self.admin = User.objects.create(
            national_id_card_number="1111222233334444", given_name="Ada")
        join(self.org, self.admin, Membership.ROLE_ADMIN)
        join(self.other, self.admin, Membership.ROLE_ADMIN)
        self.operator = User.objects.create(
            national_id_card_number="2222333344445555", given_name="Ben")
        join(self.org, self.operator)

    def _save(self, **body):
        body.setdefault("check_user_records", True)
        return self.client.post("/app/admin/verification/",
                                data=json.dumps(body),
                                content_type="application/json")

    def _stored(self):
        self.org.refresh_from_db()
        return (self.org.check_user_records, self.org.repeat_alert,
                self.org.repeat_alert_days)

    def test_on_and_ninety_days_by_default(self):
        org = Organization.objects.create(name="New")
        self.assertTrue(org.repeat_alert)
        self.assertEqual(org.repeat_alert_days, 90)

    def test_an_admin_sets_both(self):
        sign_in(self.client, self.admin, self.org)
        self.assertEqual(self._save(repeat_alert=False,
                                    repeat_alert_days=30).status_code, 200)
        self.assertEqual(self._stored(), (True, False, 30))

    def test_the_ends_of_the_range_are_accepted(self):
        sign_in(self.client, self.admin, self.org)
        for days in (0, user_records.MAX_REPEAT_ALERT_DAYS):
            self.assertEqual(self._save(repeat_alert_days=days).status_code,
                             200, days)
            self.assertEqual(self._stored()[2], days)

    def test_left_out_keeps_what_is_stored(self):
        """A page loaded before the alert existed still saves the switch."""
        self.org.repeat_alert = False
        self.org.repeat_alert_days = 14
        self.org.save()
        admin_roles.designate(self.admin, "site_admin", None, "test")
        sign_in(self.client, self.admin, self.org)
        self.assertEqual(self._save(check_user_records=False).status_code, 200)
        self.assertEqual(self._stored(), (False, False, 14))

    def test_only_the_sessions_organization_changes(self):
        sign_in(self.client, self.admin, self.org)
        self._save(repeat_alert=False, repeat_alert_days=7)
        self.other.refresh_from_db()
        self.assertEqual((self.other.repeat_alert, self.other.repeat_alert_days),
                         (True, 90))

    def test_an_operator_cannot(self):
        sign_in(self.client, self.operator, self.org)
        self.assertEqual(self._save(repeat_alert=False,
                                    repeat_alert_days=7).status_code, 403)
        self.assertEqual(self._stored(), (True, True, 90))

    def test_only_a_real_boolean_switches_it(self):
        sign_in(self.client, self.admin, self.org)
        for value in ("false", "true", 0, 1, None):
            self.assertEqual(self._save(repeat_alert=value).status_code,
                             400, value)
        self.assertEqual(self._stored(), (True, True, 90))

    def test_only_whole_days_in_range(self):
        """True is an int in Python and would quietly mean one day."""
        sign_in(self.client, self.admin, self.org)
        for days in ("90", 90.5, -1, user_records.MAX_REPEAT_ALERT_DAYS + 1,
                     True, None):
            self.assertEqual(self._save(repeat_alert_days=days).status_code,
                             400, days)
        self.assertEqual(self._stored()[2], 90)

    def test_a_refusal_takes_the_whole_save_with_it(self):
        sign_in(self.client, self.admin, self.org)
        self._save(check_user_records=False, repeat_alert=False,
                   repeat_alert_days=-5)
        self.assertEqual(self._stored(), (True, True, 90))

    def test_the_organization_page_shows_both_as_they_are(self):
        sign_in(self.client, self.admin, self.org)
        page = self.client.get("/app/admin/").content.decode()
        self.assertRegex(page, r'id="repeat-alert"\s+checked')
        self.assertRegex(page, r'id="repeat-alert-days"[^>]*value="90"')
        self.assertRegex(page, r'id="repeat-alert-days"[^>]*max="%d"'
                         % user_records.MAX_REPEAT_ALERT_DAYS)
        self.org.repeat_alert = False
        self.org.repeat_alert_days = 21
        self.org.save()
        page = self.client.get("/app/admin/").content.decode()
        self.assertNotRegex(page, r'id="repeat-alert"\s+checked')
        self.assertRegex(page, r'id="repeat-alert-days"[^>]*value="21"')

    def test_the_page_sends_both(self):
        source = (settings.BASE_DIR / "templates" / "app_admin.html").read_text(
            encoding="utf-8")
        self.assertIn("body.repeat_alert = repeatAlert.checked;", source)
        self.assertIn("body.repeat_alert_days = days;", source)
        # Greyed out with the list off, and the window with the alert off.
        self.assertIn("repeatAlert.disabled = !listOn;", source)
        self.assertIn("repeatDays.disabled = !listOn || !repeatAlert.checked;",
                      source)


class RepeatAlertPageTest(TestCase):
    """The document page: the type follows the picker, the line sits beside
    Log Transaction and only informs, and every value is text.

    A source assertion cannot tell whether the page works; these pin the
    source it depends on."""

    def setUp(self):
        self.org = make_org("Alpha")
        self.operator = User.objects.create(
            national_id_card_number="1111222233334444", given_name="Ada")
        join(self.org, self.operator)
        sign_in(self.client, self.operator, self.org)
        session = self.client.session
        verified_answer.keep(session, self.org, [
            {"field": "first_name", "key": "Given Name", "value": "Juan"}])
        session.save()

    def page(self):
        return self.client.get("/app/document/").content.decode()

    @staticmethod
    def source():
        return (settings.BASE_DIR / "templates" / "document.html").read_text(
            encoding="utf-8")

    def records_script(self):
        """The User Records script alone, so a pin on it cannot be satisfied
        by the picker's script above it."""
        source = self.source()
        start = source.index("/* User Records. The server decides")
        return source[start:source.index("</script>", start)]

    def test_the_line_sits_in_the_transaction_type_bar(self):
        from accounts.tests import _is_inside

        page = self.page()
        self.assertIn('id="ur-repeat"', page)
        self.assertTrue(_is_inside(page, "transaction-controls", "ur-repeat"),
                        "the bar is where the type is picked and Log pressed")
        self.assertRegex(page, r'id="ur-repeat"[^>]*\shidden')

    def test_absent_with_user_records_off(self):
        self.org.check_user_records = False
        self.org.save()
        self.assertNotIn('id="ur-repeat"', self.page())

    def test_the_picker_announces_the_type_and_its_clearing(self):
        source = self.source()
        self.assertIn("document.dispatchEvent(new CustomEvent('verify:transaction-type',",
                      source)
        self.assertIn("docTtDisplay.textContent = tt.name;\n"
                      "                announceType(tt.name);",
                      source.replace("\r\n", "\n"))
        self.assertIn("docTtDisplay.textContent = '-';\n"
                      "        announceType('');",
                      source.replace("\r\n", "\n"))
        self.assertIn("transactionType: ttSearch.value", source)
        script = self.records_script()
        self.assertIn("document.addEventListener('verify:transaction-type'", script)
        self.assertIn("picked = (e.detail && e.detail.name) || '';", script)

    def test_types_match_by_name_ignoring_capitals_and_spacing(self):
        script = self.records_script()
        self.assertIn(
            "function norm(s) { return String(s || '').trim()"
            ".replace(/\\s+/g, ' ').toLowerCase(); }", script)
        self.assertIn("return norm(a) !== '' && norm(a) === norm(b);", script)

    def test_the_server_decides_what_counts_as_a_repeat(self):
        script = self.records_script()
        self.assertIn("if (r.current || !sameName(r.transaction_type, picked)) "
                      "{ return ''; }", script)
        self.assertIn("return r.counts_as_repeat ? 'again' : 'same';", script)
        self.assertIn("repeatAlert = d.repeat_alert || null;", script)

    def test_nothing_is_said_without_an_answer(self):
        self.assertIn(
            "if (!loaded || !repeatAlert || !picked) { repeatEl.hidden = true; return; }",
            self.records_script())

    def test_it_informs_and_never_blocks(self):
        import re

        script = self.records_script()
        for touch in ("btn-log", "btnLog", "pre-log-controls", "preventDefault"):
            self.assertNotIn(touch, script, touch)
        # The only controls it disables are its own pager's.
        self.assertEqual(set(re.findall(r"(\w+)\.disabled\s*=", script)),
                         {"prev", "next"})

    def test_every_value_is_text(self):
        """Other organizations' names, types and operators."""
        script = self.records_script()
        self.assertNotIn("innerHTML", script)
        self.assertNotIn("insertAdjacentHTML", script)

    def test_the_line_follows_the_controls_once_logged(self):
        self.assertIn("if (repeatEl && postLog) { postLog.appendChild(repeatEl); }",
                      self.records_script())

    def test_the_link_pages_to_the_row(self):
        script = self.records_script()
        self.assertIn("page = pageSize === 0 ? 1 : Math.floor(i / pageSize) + 1;",
                      script)
        self.assertIn("link.addEventListener('click', function () { reveal(target); });",
                      script)

    def test_marks_are_never_colour_alone(self):
        script = self.records_script()
        self.assertIn("symbol('ur-warn', '⚠', 'Same type, logged here before')",
                      script)
        self.assertIn("symbol('ur-dot', '', 'Same transaction type')", script)
        self.assertIn("span.setAttribute('aria-label', label);", script)
