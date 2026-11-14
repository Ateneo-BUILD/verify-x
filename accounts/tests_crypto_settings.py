"""The settings every bundle is made from, checked at deploy, and a sync that
meets them wrong answered 503. The rest is in ovcrypto and the signer:
signer/tests, and accounts/tests_holders.py for `open_own`.
"""

from django.core import checks
from django.test import override_settings

from accounts import devices
from accounts.checks import MIN_LEASE_SECONDS, bundle_settings
from accounts.tests_operations import _KeysFixture
from ovcrypto import bundle as bundle_mod


class BundleSettingsCheckTest(_KeysFixture):
    """A lease that ends as it starts, or the key id that a bundle's
    chains digest takes, is a deploy error, not a sync's 500."""

    def _ids(self):
        return [found.id for found in bundle_settings()]

    def test_this_sites_settings_pass(self):
        self.assertEqual(self._ids(), [])

    def test_a_lease_under_an_hour_is_an_error(self):
        for lease in (0, -60, MIN_LEASE_SECONDS - 1):
            with self.subTest(lease=lease), override_settings(DEVICE_LEASE_SECONDS=lease):
                self.assertEqual(self._ids(), ["accounts.E001"])
        with override_settings(DEVICE_LEASE_SECONDS=MIN_LEASE_SECONDS):
            self.assertEqual(self._ids(), [])

    def test_the_chains_digest_id_is_no_key_id(self):
        for key_id in (0, bundle_mod.CHAINS_DIGEST_ID):
            with self.subTest(key_id=key_id), override_settings(
                    CREDENTIAL_ISSUER_KEY_ID=key_id):
                self.assertEqual(self._ids(), ["accounts.E002"])

    def test_it_runs_with_every_other_check(self):
        with override_settings(DEVICE_LEASE_SECONDS=0):
            self.assertIn("accounts.E001",
                          [found.id for found in checks.run_checks()])

    def test_a_sync_meeting_them_is_a_503_not_a_500(self):
        with override_settings(DEVICE_LEASE_SECONDS=0), \
                self.assertLogs("accounts.devices", "ERROR"):
            reply = self._sync()
        self.assertEqual(reply.status_code, 503)
        self.assertEqual(reply.json()["error"], devices.BUNDLE_SETTINGS_WRONG)
