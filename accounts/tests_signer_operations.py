"""The credential signer's operating safety, from this side. The signer's
half is signer/tests/test_operations.py.
"""

import datetime
import hashlib
import json
import unittest
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import reverse

from accounts import admin_roles, credential_keys, signing_status
from accounts.models import User
from accounts.tests import make_org
from accounts.tests_web_security import sign_in
from verify.views import signer_api

WRAP = "ab" * 32


class HalfConfiguredTest(TestCase):

    @override_settings(SIGNER_SOCKET="/run/cl03-signer/app.sock",
                       CREDENTIAL_EPOCH_WRAP_KEY="")
    def test_a_signer_without_a_wrap_key_is_named_missing(self):
        self.assertFalse(credential_keys.configured())
        self.assertEqual(credential_keys.missing(), ["CREDENTIAL_EPOCH_WRAP_KEY"])

    @override_settings(SIGNER_SOCKET="", CREDENTIAL_ISSUER_KEY_PATH="/k.pem",
                       CREDENTIAL_EPOCH_WRAP_KEY="")
    def test_so_is_a_key_file_without_one(self):
        self.assertEqual(credential_keys.missing(), ["CREDENTIAL_EPOCH_WRAP_KEY"])

    @override_settings(SIGNER_SOCKET="", CREDENTIAL_ISSUER_KEY_PATH="",
                       CREDENTIAL_EPOCH_WRAP_KEY="")
    def test_no_issuer_key_at_all_is_not_half_configured(self):
        self.assertEqual(credential_keys.missing(), [])

    @override_settings(SIGNER_SOCKET="/run/cl03-signer/app.sock",
                       CREDENTIAL_EPOCH_WRAP_KEY=WRAP)
    def test_a_complete_one_misses_nothing(self):
        self.assertEqual(credential_keys.missing(), [])

    @override_settings(SIGNER_SOCKET="/run/cl03-signer/app.sock",
                       CREDENTIAL_EPOCH_WRAP_KEY="")
    def test_a_document_without_its_credential_is_logged_once(self):
        from accounts.models import Transaction
        from verify.views.everify import _mint_credential
        org = make_org("Alpha")
        txn = Transaction.objects.create(organization=org,
                                         authentication_result="success")
        with patch.object(credential_keys, "_warned_missing", False):
            with self.assertLogs("accounts.credential_keys", "ERROR") as logs:
                self.assertIsNone(_mint_credential(txn, org, None, [], None))
            self.assertIn("CREDENTIAL_EPOCH_WRAP_KEY", logs.output[0])
            with self.assertNoLogs("accounts.credential_keys", "ERROR"):
                _mint_credential(txn, org, None, [], None)


class SetupSaysSoTest(TestCase):

    def setUp(self):
        self.org = make_org("Alpha")
        self.site = User.objects.create(national_id_card_number="9999000011112222")
        admin_roles.designate(self.site, "site_admin", None, "test")
        sign_in(self.client, self.site, self.org)

    @override_settings(SIGNER_SOCKET="/nonexistent/app.sock",
                       CREDENTIAL_EPOCH_WRAP_KEY="")
    def test_setup_names_the_missing_setting_in_red(self):
        # The signer is not there either: the notice comes first anyway.
        down = signing_status.signer_client.Unavailable("unavailable: no socket")
        with patch.object(signing_status.signer_client, "public", side_effect=down):
            page = self.client.get(reverse("setup")).content.decode()
        self.assertIn("No credential can be minted", page)
        self.assertIn("<code>CREDENTIAL_EPOCH_WRAP_KEY</code>", page)

    @override_settings(SIGNER_SOCKET="", CREDENTIAL_ISSUER_KEY_PATH="",
                       CREDENTIAL_EPOCH_WRAP_KEY="")
    def test_not_when_there_is_no_issuer_key(self):
        page = self.client.get(reverse("setup")).content.decode()
        self.assertNotIn("No credential can be minted", page)

    @override_settings(SIGNER_SOCKET="/run/cl03-signer/app.sock",
                       CREDENTIAL_EPOCH_WRAP_KEY=WRAP)
    def test_the_signers_failure_count_reaches_setup(self):
        public = {"keys": [], "organization_cas": []}
        status = {"now": 1, "internal_failures": {"in_a_row": 4, "last": None}}
        with patch.object(signing_status.signer_client, "public", return_value=public), \
                patch.object(signing_status.signer_client, "status", return_value=status):
            overview = signing_status.overview()
            self.assertEqual(overview["failing"], 4)
            self.assertEqual(overview["missing"], [])
            page = self.client.get(reverse("setup")).content.decode()
        self.assertIn("refused the last 4 requests", page)


class HolderMintWarnsTest(TestCase):

    @override_settings(SIGNER_SOCKET="/run/cl03-signer/app.sock",
                       CREDENTIAL_EPOCH_WRAP_KEY="")
    def test_a_holders_credential_lost_the_same_way_is_logged_too(self):
        from accounts import holders
        with patch.object(credential_keys, "_warned_missing", False), \
                self.assertLogs("accounts.credential_keys", "ERROR"):
            self.assertIsNone(holders.mint_for_holder({"person": {}}))


TOKEN = "report-token-for-tests"


@override_settings(SIGNER_REPORT_TOKEN_SHA256=hashlib.sha256(TOKEN.encode()).hexdigest())
class ReportSpanTest(TestCase):

    def _report(self, since):
        response = self.client.get("/api/v1/signer/report/", {"since": since},
                                   HTTP_AUTHORIZATION="Bearer " + TOKEN)
        self.assertEqual(response.status_code, 200)
        return json.loads(response.content)

    def test_the_report_says_where_it_starts(self):
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        recent = now - 3600
        self.assertEqual(self._report(recent)["since"], recent)
        long_ago = now - 30 * 86400
        got = self._report(long_ago)["since"]
        self.assertGreater(got, long_ago)
        self.assertAlmostEqual(got, now - signer_api.MAX_SPAN_SECONDS, delta=60)
