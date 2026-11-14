"""Validity is the site's to set, the card prints the date, and a phone that
syncs can read a card for as long as the card is valid."""

import datetime
import importlib
import os
import uuid
from unittest.mock import patch

from django.apps import apps
from django.conf import settings
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from accounts import credential_keys, credentials, devices, minting, signer_client
from accounts.models import (CredentialEpochKey, IssuedCredential, SiteSettings,
                             Transaction, User)
from accounts.tests_operations import _KeysFixture
from signer.service import MAX_EPOCH_KEYS
from verify.views import handoff


def days(n):
    return datetime.timedelta(days=n)


class ValidityTest(TestCase):

    def _set(self, value):
        site = SiteSettings.load()
        site.credential_validity_days = value
        site.save()

    def test_a_new_site_issues_for_thirty_days(self):
        self.assertEqual(SiteSettings.load().credential_validity_days, 30)
        # The row comes from a migration, so the model's own default is a second
        # statement of the same number, and a site that lost its row reads it.
        self.assertEqual(SiteSettings.DEFAULT_CREDENTIAL_VALIDITY_DAYS, 30)
        self.assertEqual(
            SiteSettings._meta.get_field("credential_validity_days").default, 30)
        issued = timezone.now()
        self.assertEqual(credential_keys.validity_window(issued), (issued, issued + days(30)))

    def test_the_site_chooses(self):
        self._set(90)
        issued = timezone.now()
        self.assertEqual(credential_keys.validity_window(issued)[1], issued + days(90))

    def test_a_stored_value_is_held_inside_the_ceiling(self):
        self._set(400)
        self.assertEqual(credential_keys.validity_days(), 365)
        with override_settings(CREDENTIAL_MAX_VALIDITY_DAYS=60):
            self.assertEqual(credential_keys.validity_days(), 60)

    def test_a_signer_with_a_lower_limit_lowers_the_ceiling(self):
        """It refuses anything longer, and a refused credential prints no card."""
        self._set(90)
        with patch.object(credential_keys, "signer_mode", return_value=True), \
                patch.object(signer_client, "public",
                             return_value={"credential_max_days": 45}):
            self.assertEqual(credential_keys.validity_ceiling_days(), 45)
            self.assertEqual(credential_keys.validity_days(), 45)

    def test_a_signer_that_does_not_answer_leaves_the_sites_ceiling(self):
        with patch.object(credential_keys, "signer_mode", return_value=True), \
                patch.object(signer_client, "public", side_effect=OSError("no socket")), \
                self.assertLogs("accounts.credential_keys", "WARNING"):
            self.assertEqual(credential_keys.validity_ceiling_days(),
                             settings.CREDENTIAL_MAX_VALIDITY_DAYS)


class KeyLifetimeTest(_KeysFixture):
    """What a sync gives a phone: `devices.epochs_for`, which is `not_after`."""

    def setUp(self):
        super().setUp()
        self.now = timezone.now()
        self.epoch = credential_keys.current_epoch(self.now)
        credential_keys.issuing_keys()
        self.rows = CredentialEpochKey.objects.filter(epoch=self.epoch)
        self.floor = credential_keys.readable_until(self.epoch)

    def _held_at(self, when):
        with patch("django.utils.timezone.now", return_value=when):
            return {row.epoch for row in devices.epochs_for(self.device)}

    def _not_afters(self):
        return {int(row.not_after.timestamp()) for row in self.rows}

    def test_the_default_changes_nothing_a_phone_holds(self):
        """Thirty days is inside the overlap, so the date does not move."""
        credential_keys.keep_readable_until(self.epoch, self.now + days(30))
        self.assertEqual(self._not_afters(), {self.floor})

    def test_a_longer_card_keeps_both_tiers_of_its_epochs_key(self):
        expires = self.now + days(365)
        credential_keys.keep_readable_until(self.epoch, expires)
        self.assertEqual(self.rows.count(), 2)
        self.assertEqual(self._not_afters(), {int(expires.timestamp())})

    def test_a_phone_that_syncs_can_read_it_until_it_expires(self):
        expires = self.now + days(365)
        credential_keys.keep_readable_until(self.epoch, expires)
        self.assertIn(self.epoch, self._held_at(self.now + days(300)))
        self.assertNotIn(self.epoch, self._held_at(expires + days(1)))

    def test_an_epoch_with_no_long_card_leaves_on_schedule(self):
        """Only the epoch that needs it: the overlap is not raised for all."""
        self.assertIn(self.epoch, self._held_at(self.now + days(60)))
        self.assertNotIn(self.epoch, self._held_at(self.now + days(300)))

    def test_it_only_ever_moves_a_date_on(self):
        credential_keys.keep_readable_until(self.epoch, self.now + days(365))
        credential_keys.keep_readable_until(self.epoch, self.now + days(200))
        self.assertEqual(self._not_afters(), {int((self.now + days(365)).timestamp())})

    def test_minting_keeps_the_key_before_it_signs(self):
        """A credential that exists must be one a phone can be given the key to,
        so a mint that dies in the signer has still moved the date."""
        txn = Transaction.objects.create(authentication_result="success")
        expires = self.now + days(365)
        with patch.object(minting.credentials, "mint", side_effect=RuntimeError("signer")), \
                self.assertRaises(RuntimeError):
            minting.mint_recorded([], transaction=txn, organization=None,
                                  issued_at=self.now, expires_at=expires)
        self.assertEqual(self._not_afters(), {int(expires.timestamp())})

    def test_the_longest_validity_still_fits_a_bundle(self):
        """The worst case: a card minted under the first epoch, read in the last
        it can reach, with every epoch between holding one. Both tiers, plus the
        epoch a partial period adds at each end."""
        epoch_days = settings.CREDENTIAL_EPOCH_SECONDS // 86400
        epochs = settings.CREDENTIAL_MAX_VALIDITY_DAYS // epoch_days + 2
        self.assertLessEqual(epochs * 2, MAX_EPOCH_KEYS)

    def test_what_is_already_issued_is_kept_by_the_migration(self):
        migration = importlib.import_module(
            "accounts.migrations.0051_credential_validity_days")
        txn = Transaction.objects.create(authentication_result="success")
        expires = self.now + days(365)
        for offset in (10, 365):
            IssuedCredential.objects.create(
                credential_id=uuid.uuid4(), transaction=txn,
                document_uuid=txn.transaction_id, epoch=self.epoch, issuer_key_id=1,
                issued_at=self.now, expires_at=self.now + days(offset))
        migration.keep_keys_for_issued_credentials(apps, None)
        self.assertEqual(self._not_afters(), {int(expires.timestamp())})


class SetupFieldTest(TestCase):

    BASE = {"fingerprint_auth_endpoint": "", "serial_number": "0", "login_mode": "everify"}

    def setUp(self):
        self.admin = User.objects.create(
            national_id_card_number="1111222233334444", digital_national_id="ADM1",
            given_name="Admin", is_site_admin=True)
        self.operator = User.objects.create(
            national_id_card_number="5555666677778888", digital_national_id="OPR1",
            given_name="Operator")

    def _as(self, user):
        session = self.client.session
        session["verify_user_id"] = user.id
        session.save()

    def _stored(self):
        return SiteSettings.load().credential_validity_days

    def test_a_site_admin_sees_it_with_its_limits(self):
        self._as(self.admin)
        response = self.client.get("/app/setup/")
        self.assertContains(response, 'name="credential_validity_days"')
        self.assertContains(response, 'max="365"')
        self.assertContains(response, 'value="30"')

    def test_an_operator_does_not(self):
        self._as(self.operator)
        self.assertNotContains(self.client.get("/app/setup/"), "credential_validity_days")

    def test_a_site_admin_changes_it_and_it_is_logged(self):
        self._as(self.admin)
        with self.assertLogs("verify.views.core", "WARNING") as logs:
            self.client.post("/app/setup/", dict(self.BASE, credential_validity_days="90"))
        self.assertEqual(self._stored(), 90)
        self.assertIn("from 30 to 90 days", logs.output[0])

    def test_anything_outside_the_range_is_refused(self):
        self._as(self.admin)
        for bad in ("0", "366", "-5", "abc", "", "30.5", "٣٠"):
            response = self.client.post("/app/setup/",
                                        dict(self.BASE, credential_validity_days=bad))
            self.assertContains(response, "whole number of days from 1 to 365")
            self.assertEqual(self._stored(), 30, bad)

    def test_a_post_without_the_field_leaves_it_alone(self):
        self._as(self.admin)
        self.client.post("/app/setup/", dict(self.BASE, credential_validity_days="90"))
        response = self.client.post("/app/setup/", self.BASE, follow=True)
        self.assertNotContains(response, "whole number of days")
        self.assertEqual(self._stored(), 90)

    def test_an_operator_cannot_set_it_by_posting(self):
        self._as(self.operator)
        self.client.post("/app/setup/", dict(self.BASE, credential_validity_days="90"))
        self.assertEqual(self._stored(), 30)


class CardDateTest(TestCase):

    def test_the_day_is_spelled_as_the_verified_line_is_in_the_sites_zone(self):
        when = datetime.datetime(2026, 12, 5, 20, 0, tzinfo=datetime.timezone.utc)
        with timezone.override("Asia/Manila"):
            self.assertEqual(handoff.expires_on_text(when), "Dec 06 2026")
            self.assertTrue(handoff.verified_at_text(when).startswith("Dec 06 2026 "))

    def test_a_holders_card_carries_the_date_its_credential_was_signed_with(self):
        txn = Transaction.objects.create(authentication_result="success")
        self.assertEqual(handoff.holder_card(txn)["expires_on"], "")
        expires = timezone.now() + days(30)
        IssuedCredential.objects.create(
            credential_id=uuid.uuid4(), transaction=txn,
            document_uuid=txn.transaction_id, epoch=1, issuer_key_id=1,
            issued_at=timezone.now(), expires_at=expires)
        self.assertEqual(handoff.holder_card(txn)["expires_on"],
                         handoff.expires_on_text(expires))


class RendererTest(SimpleTestCase):
    """`DocumentCredentialTest` holds the geometry; this holds the header."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        path = os.path.join(settings.BASE_DIR, "static", "cardcanvas.js")
        with open(path, encoding="utf-8") as handle:
            cls.source = handle.read()

    def test_the_date_is_in_the_header_with_the_title_held_to_one_line(self):
        branch = self.source[self.source.index("if (card.expires_on)"):]
        branch = branch[:branch.index("} else {")]
        self.assertIn("'Expires '", branch)
        self.assertIn("card.expires_on", branch)
        self.assertIn("line('National ID Authentication Result'", branch)
        self.assertNotIn("block(", branch)

    def test_a_card_with_no_date_draws_the_header_it_always_did(self):
        rest = self.source[self.source.index("if (card.expires_on)"):]
        rest = rest[rest.index("} else {"):]
        rest = rest[:rest.index("// --- the rule")]
        self.assertIn("block('National ID Authentication Result'", rest)
        self.assertIn("top + 104", rest)

    def test_the_card_is_the_size_it_was(self):
        """The date costs no height, so nothing the printed size rests on moved."""
        self.assertEqual(credentials.CARD_CANVAS_H_PX, 2700)
