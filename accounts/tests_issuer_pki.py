"""Managed-PKI groundwork in verify: what holds before any signer exists.

Each test names the failure it pins: a credential that exists with no row, a
revocation one worker serves and another does not, a signature on every
anonymous fetch, a race that mints two log keys, an admin that can un-revoke
by deleting.
"""

import base64
import datetime
import os
import shutil
import stat
import tempfile
import time
import uuid
from unittest import mock

from django.core.management import CommandError, call_command
from django.test import RequestFactory, TestCase, override_settings
from django.utils import timezone

from accounts import (credential_keys, credentials, debug_store, device_log,
                      minting, revocation_feed)
from accounts.admin import (IssuedCredentialAdmin, IssuerKeyAdmin,
                            RevokedCredentialIdAdmin)
from accounts.models import (DeviceLogKey, IssuedCredential, IssuerKey,
                             Organization, RevocationState,
                             RevokedCredentialId, Transaction)

WRAP_KEY_HEX = "00112233445566778899aabbccddeeff" * 2

ROWS = [
    {"field": "first_name", "key": "Given Name", "value": "JUAN", "show": True},
    {"field": "last_name", "key": "Last Name", "value": "DELA CRUZ",
     "show": True},
]


@override_settings(CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX)
class _KeyedTest(TestCase):
    """A PEM issuer key on private storage, as a deployment has one."""

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
        key = ec.generate_private_key(ec.SECP256R1())
        with open(self.pem, "wb") as handle:
            handle.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        os.chmod(self.pem, stat.S_IRUSR | stat.S_IWUSR)
        ctx = override_settings(CREDENTIAL_ISSUER_KEY_PATH=self.pem,
                                CREDENTIAL_ISSUER_KEY_ID=1)
        ctx.enable()
        self.addCleanup(ctx.disable)
        self.org = Organization.objects.create(name="Alpha Registry")

    def _txn(self):
        return Transaction.objects.create(organization=self.org,
                                          authentication_result="success")

    def _mint(self, txn, **extra):
        now = timezone.now()
        return minting.mint_recorded(
            ROWS, transaction=txn, organization=self.org, location_code="Q1",
            issued_at=now, expires_at=now + datetime.timedelta(days=365),
            **extra)


class MintOrderingTest(_KeyedTest):
    """The row is written before the signature is asked for."""

    def test_the_row_exists_as_pending_while_signing(self):
        seen = {}
        real = credentials.mint

        def spy(*args, **kwargs):
            seen["state"] = IssuedCredential.objects.get(
                credential_id=kwargs["credential_id"]).state
            return real(*args, **kwargs)

        with mock.patch.object(credentials, "mint", side_effect=spy):
            minted = self._mint(self._txn())
        self.assertEqual(seen["state"], IssuedCredential.STATE_PENDING)
        row = IssuedCredential.objects.get(
            credential_id=minted["credential_id"])
        self.assertEqual(row.state, IssuedCredential.STATE_SIGNED)

    def test_the_recorded_id_is_the_one_signed(self):
        """Chosen first, so the row and the QR cannot disagree."""
        minted = self._mint(self._txn())
        self.assertTrue(IssuedCredential.objects.filter(
            credential_id=minted["credential_id"]).exists())
        self.assertEqual(IssuedCredential.objects.count(), 1)

    def test_a_failed_signature_leaves_no_row(self):
        with mock.patch.object(credentials, "mint",
                               side_effect=RuntimeError("key unreadable")):
            with self.assertRaises(RuntimeError):
                self._mint(self._txn())
        self.assertEqual(IssuedCredential.objects.count(), 0)

    def test_a_lost_reply_keeps_the_row_as_unknown(self):
        """The signer may have signed: the row is what lets it be found."""
        lost = RuntimeError("timed out after sending")
        lost.reply_lost = True
        with mock.patch.object(credentials, "mint", side_effect=lost):
            with self.assertRaises(RuntimeError):
                self._mint(self._txn())
        self.assertEqual(IssuedCredential.objects.get().state,
                         IssuedCredential.STATE_UNKNOWN)

    def test_the_key_id_is_read_once(self):
        """The id in the row is the id of the key that signed."""
        minted = self._mint(self._txn())
        row = IssuedCredential.objects.get(credential_id=minted["credential_id"])
        self.assertEqual(row.issuer_key_id, 1)

    def test_an_issuer_name_override_is_what_the_credential_names(self):
        from ovcrypto import wire

        captured = {}
        real = credentials.build_claims

        def spy(*args, **kwargs):
            public, restricted = real(*args, **kwargs)
            captured["issuer"] = public.get(wire.T_ISSUER_ID)
            return public, restricted

        with mock.patch.object(credentials, "build_claims", side_effect=spy):
            self._mint(self._txn(), issuer_name="Alpha Registry (certified)")
        self.assertEqual(captured["issuer"], b"Alpha Registry (certified)")


class RevocationGenerationTest(_KeyedTest):
    """Every worker serves a revocation at its next request."""

    def _issued(self, revoked=False):
        row = IssuedCredential.objects.create(
            credential_id=uuid.uuid4(), organization=self.org,
            document_uuid=uuid.uuid4(), epoch=14, issuer_key_id=1,
            issued_at=timezone.now(),
            expires_at=timezone.now() + datetime.timedelta(days=365))
        if revoked:
            revocation_feed.revoke(row, reason="test")
        return row

    def _in_feed(self, feed, cid):
        from ovcrypto import revocation

        f = revocation.CuckooFilter.from_bytes(base64.b64decode(feed["filter"]))
        return cid.bytes in f

    def test_revoking_bumps_the_generation(self):
        before = revocation_feed.generation()
        self._issued(revoked=True)
        self.assertEqual(revocation_feed.generation(), before + 1)

    def test_another_workers_revocation_is_served_without_invalidate(self):
        """Its own cache is reset by revoke(); another worker's is not."""
        revocation_feed.current_feed()
        row = self._issued()
        row.revoked_at = timezone.now()
        row.save(update_fields=["revoked_at"])
        revocation_feed.bump()              # what the other worker's revoke did
        self.assertTrue(self._in_feed(revocation_feed.current_feed(),
                                      row.credential_id))

    def test_an_unchanged_set_keeps_the_same_feed(self):
        first = revocation_feed.current_feed()
        self._issued(revoked=False)
        self.assertIs(revocation_feed.current_feed(), first)

    def test_a_forged_id_is_revoked_without_an_issued_row(self):
        cid = uuid.uuid4()
        self.assertEqual(revocation_feed.add_forged([cid], reason="forgery"), 1)
        self.assertTrue(self._in_feed(revocation_feed.current_feed(), cid))
        self.assertFalse(IssuedCredential.objects.filter(
            credential_id=cid).exists())

    def test_adding_a_forged_id_twice_changes_nothing(self):
        cid = uuid.uuid4()
        revocation_feed.add_forged([cid])
        generation = revocation_feed.generation()
        self.assertEqual(revocation_feed.add_forged([cid]), 0)
        self.assertEqual(revocation_feed.generation(), generation)

    def test_an_id_in_both_tables_counts_once(self):
        row = self._issued(revoked=True)
        revocation_feed.add_forged([row.credential_id])
        self.assertEqual(revocation_feed.revoked_ids().count(
            row.credential_id.bytes), 1)

    def test_the_same_set_gives_the_same_filter_whatever_the_order(self):
        for _ in range(5):
            self._issued(revoked=True)
        first = revocation_feed.build_filter()
        IssuedCredential.objects.update(issued_at=timezone.now())
        self.assertEqual(revocation_feed.build_filter(), first)

    def test_the_state_row_is_seeded_by_the_migration(self):
        self.assertTrue(RevocationState.objects.filter(pk=1).exists())


class StatementMemoTest(_KeyedTest):
    """An anonymous fetch of /log-key/ does not cost a signature each time."""

    def test_repeated_fetches_reuse_one_signature(self):
        device_log._statements.clear()
        real = credential_keys.signer()
        with mock.patch.object(credential_keys, "signer", return_value=real):
            with mock.patch.object(real, "sign", wraps=real.sign) as sign:
                first = device_log.key_statement()
                for _ in range(20):
                    again = device_log.key_statement()
        self.assertEqual(sign.call_count, 1)
        self.assertEqual(first["sig"], again["sig"])

    def test_a_retired_log_key_gets_a_fresh_statement(self):
        device_log._statements.clear()
        first = device_log.key_statement()
        DeviceLogKey.objects.update(retired_at=timezone.now())
        fresh = device_log.key_statement()
        self.assertNotEqual(fresh["key_id"], first["key_id"])

    def test_an_explicit_now_is_always_fresh(self):
        statement = device_log.key_statement(now=1_800_000_000)
        self.assertEqual(statement["issued_at"], 1_800_000_000)

    def test_racing_first_keys_settle_on_the_oldest(self):
        """A signer alerts on each new log key, so the race must end at one."""
        first = device_log.current_key()
        extra = DeviceLogKey.objects.create(
            public_key=bytes(32), wrapped_private_key=first.wrapped_private_key)
        self.assertEqual(device_log.current_key().pk, first.pk)
        extra.refresh_from_db()
        self.assertIsNotNone(extra.retired_at)


class SigningIdTest(TestCase):

    def test_every_organization_gets_its_own(self):
        a = Organization.objects.create(name="A")
        b = Organization.objects.create(name="B")
        self.assertIsNotNone(a.signing_id)
        self.assertNotEqual(a.signing_id, b.signing_id)


class AdminTest(TestCase):
    """No un-revoking by deletion, and no editing a trusted key."""

    def setUp(self):
        from django.contrib.admin.sites import AdminSite

        self.site = AdminSite()
        self.request = RequestFactory().get("/")

    def test_issued_credentials_cannot_be_deleted(self):
        admin = IssuedCredentialAdmin(IssuedCredential, self.site)
        self.assertFalse(admin.has_delete_permission(self.request))

    def test_issuer_keys_are_read_only(self):
        admin = IssuerKeyAdmin(IssuerKey, self.site)
        self.assertFalse(admin.has_add_permission(self.request))
        self.assertFalse(admin.has_change_permission(self.request))
        self.assertFalse(admin.has_delete_permission(self.request))

    def test_forged_ids_can_only_be_added(self):
        admin = RevokedCredentialIdAdmin(RevokedCredentialId, self.site)
        self.assertFalse(admin.has_change_permission(self.request))
        self.assertFalse(admin.has_delete_permission(self.request))

    def test_adding_a_forged_id_in_the_admin_bumps_the_generation(self):
        admin = RevokedCredentialIdAdmin(RevokedCredentialId, self.site)
        before = revocation_feed.generation()
        obj = RevokedCredentialId(credential_id=uuid.uuid4(), reason="x")
        admin.save_model(self.request, obj, form=None, change=False)
        self.assertEqual(revocation_feed.generation(), before + 1)
        self.assertTrue(RevokedCredentialId.objects.filter(
            credential_id=obj.credential_id).exists())


class MeasureCredentialTest(_KeyedTest):
    """Sizing signs with a throwaway key, never the issuer's."""

    def test_the_issuer_key_is_never_used(self):
        payload = {"first_name": "JUAN", "last_name": "DELA CRUZ"}
        with mock.patch.object(credential_keys, "signer",
                               side_effect=AssertionError("issuer key used")):
            result = debug_store.measure_credential(payload)
        self.assertIsNotNone(result)


class LoadCredentialKeysSignerModeTest(TestCase):

    @override_settings(SIGNER_SOCKET="/run/cl03-signer/app.sock")
    def test_a_full_load_is_refused_with_a_signer(self):
        source = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, source, True)
        with self.assertRaisesRegex(CommandError, "epochs-only"):
            call_command("load_credential_keys", "--from", source)


class MakeTestPkiTest(TestCase):
    """The development PKI issues exactly the profiles phones will check."""

    def setUp(self):
        from io import StringIO

        self.out = os.path.join(tempfile.mkdtemp(), "pki")
        self.addCleanup(shutil.rmtree, os.path.dirname(self.out), True)
        self.stdout = StringIO()
        call_command("make_test_pki", "--init", "--out", self.out,
                     stdout=self.stdout)

    def _ca_der(self):
        with open(os.path.join(self.out, "ca.der"), "rb") as handle:
            return handle.read()

    def _csr(self, domains=(), curve=None):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(curve or ec.SECP256R1())
        builder = (x509.CertificateSigningRequestBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(
                       NameOID.COMMON_NAME, "signer")])))
        if domains:
            builder = builder.add_extension(x509.SubjectAlternativeName(
                [x509.DNSName(d) for d in domains]), critical=False)
        csr = builder.sign(key, hashes.SHA256())
        path = os.path.join(os.path.dirname(self.out), "signer.csr")
        with open(path, "wb") as handle:
            handle.write(csr.public_bytes(serialization.Encoding.PEM))
        return path

    def _sign(self, *extra, domains=()):
        from io import StringIO

        cert = os.path.join(os.path.dirname(self.out), "signer.crt")
        call_command("make_test_pki", "--sign-csr", self._csr(domains), "--out",
                     self.out, "--cert-out", cert, *extra, stdout=StringIO())
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        with open(cert, "rb") as handle:
            return x509.load_pem_x509_certificate(handle.read()).public_bytes(
                serialization.Encoding.DER)

    def test_a_request_for_another_curve_is_refused_not_raised(self):
        """Every phone requires P-256."""
        from io import StringIO

        from cryptography.hazmat.primitives.asymmetric import ec

        cert = os.path.join(os.path.dirname(self.out), "signer.crt")
        with self.assertRaisesRegex(CommandError, "not P-256"):
            call_command("make_test_pki", "--sign-csr",
                         self._csr(curve=ec.SECP384R1()), "--out", self.out,
                         "--cert-out", cert, stdout=StringIO())
        self.assertFalse(os.path.exists(cert))

    def test_the_issuing_ca_has_room_for_the_organization_ca_only(self):
        from cryptography import x509

        ca = x509.load_der_x509_certificate(self._ca_der())
        bc = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
        self.assertTrue(bc.ca)
        self.assertEqual(bc.path_length, 1)

    SITE = "verify.example.ph"
    SEEN = {"domain": SITE, "issuer": "Test Web CA",
            "not_after": "Mar 26 23:59:59 2027 GMT"}

    def test_it_certifies_the_organization_ca_the_phone_accepts(self):
        from ovcrypto import chain

        with mock.patch("signer.sitecheck.check",
                        return_value=self.SEEN) as check:
            der = self._sign("--org-ca", "--domain", self.SITE,
                             domains=(self.SITE,))
        check.assert_called_once_with(self.SITE)
        got = chain.validate_organization_ca(der, [self._ca_der()],
                                             int(time.time()),
                                             domain=self.SITE)
        self.assertEqual(got.name, "verify.example.ph System CA")
        self.assertEqual(got.domains, (self.SITE,))
        self.assertGreater(got.not_after - int(time.time()), 4 * 365 * 86400)

    def test_the_organization_ca_needs_the_site_domain(self):
        for extra in ((), ("--domain", "Verify.Example.PH"),
                      ("--domain", "localhost")):
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(CommandError, "needs --domain"):
                    self._sign("--org-ca", *extra, domains=(self.SITE,))

    def test_a_request_for_another_site_is_not_certified(self):
        for domains in ((), ("elsewhere.example.ph",),
                        (self.SITE, "elsewhere.example.ph")):
            with self.subTest(domains=domains):
                with mock.patch("signer.sitecheck.check") as check, \
                        self.assertRaisesRegex(CommandError,
                                               "The request is for"):
                    self._sign("--org-ca", "--domain", self.SITE,
                               domains=domains)
                check.assert_not_called()

    def test_a_site_without_a_valid_https_certificate_gets_nothing(self):
        from signer import sitecheck

        failed = sitecheck.SiteCheckFailed(
            "https://%s/ has no certificate valid for %s" % (self.SITE,
                                                             self.SITE))
        cert = os.path.join(os.path.dirname(self.out), "signer.crt")
        with mock.patch("signer.sitecheck.check", side_effect=failed), \
                self.assertRaisesRegex(CommandError, "Nothing was certified"):
            self._sign("--org-ca", "--domain", self.SITE, domains=(self.SITE,))
        self.assertFalse(os.path.exists(cert))

    def test_a_domain_is_only_for_the_organization_ca(self):
        with self.assertRaisesRegex(CommandError, "--domain goes with --org-ca"):
            self._sign("--domain", self.SITE)

    def test_org_and_org_ca_are_one_or_the_other(self):
        with self.assertRaisesRegex(CommandError, "not both"):
            self._sign("--org", str(uuid.uuid4()), "--org-ca")

    def test_it_prints_the_fingerprint_and_the_swift_literal(self):
        import hashlib

        text = self.stdout.getvalue()
        self.assertIn("CREDENTIAL_ISSUER_CA_FINGERPRINTS=%s"
                      % hashlib.sha256(self._ca_der()).hexdigest(), text)
        self.assertIn(base64.b64encode(self._ca_der()).decode(), text)

    def test_a_deployment_leaf_carries_both_ekus(self):
        from ovcrypto import chain

        got = chain.validate(self._sign(), [self._ca_der()], int(time.time()))
        self.assertEqual(got.classes, {chain.INFRASTRUCTURE, chain.CREDENTIAL})
        self.assertIsNone(got.organization)

    def test_an_organization_leaf_names_the_organization(self):
        from ovcrypto import chain

        org = Organization.objects.create(name="Beta Records")
        got = chain.validate(self._sign("--org", str(org.signing_id)),
                             [self._ca_der()], int(time.time()))
        self.assertEqual(got.classes, {chain.CREDENTIAL})
        self.assertEqual(got.organization, "Beta Records")
        self.assertEqual(got.organization_id, str(org.signing_id))

    def test_an_unknown_organization_is_refused(self):
        with self.assertRaisesRegex(CommandError, "signing_id"):
            self._sign("--org", str(uuid.uuid4()))

    def test_it_will_not_write_inside_a_repository(self):
        from django.conf import settings

        with self.assertRaisesRegex(CommandError, "inside a repository"):
            call_command("make_test_pki", "--init", "--out",
                         os.path.join(str(settings.BASE_DIR), "pki"))

    def test_it_will_not_replace_a_ca_every_dev_build_pins(self):
        with self.assertRaisesRegex(CommandError, "already holds"):
            call_command("make_test_pki", "--init", "--out", self.out)

    def test_the_keys_are_this_accounts_alone_and_checked_before_use(self):
        """A chmod does nothing on Windows, so the test CA's keys get an
        access list of this account's own, and are checked before use."""
        from ovcrypto import keystore

        parent = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, parent, True)
        # Opened up, as an ordinary folder on a second drive is.
        if os.name == "nt":
            keystore._set_windows_dacl(parent, "D:P(A;OICI;FA;;;%s)(A;OICI;FR;;;BU)"
                                       % keystore._windows_user())
        else:
            os.chmod(parent, 0o755)
        self.out = os.path.join(parent, "pki")
        call_command("make_test_pki", "--init", "--out", self.out, stdout=self.stdout)

        for name in ("root.key.pem", "ca.key.pem"):
            keystore._require_private_mode(os.path.join(self.out, name))
        if os.name == "nt":
            self.assertEqual(keystore._windows_others(self.out), [])
        else:
            self.assertEqual(stat.S_IMODE(os.stat(self.out).st_mode), 0o700)
        self._sign()

        ca_key = os.path.join(self.out, "ca.key.pem")
        if os.name == "nt":
            keystore._set_windows_dacl(ca_key, "D:P(A;;FA;;;%s)(A;;FR;;;BU)"
                                       % keystore._windows_user())
        else:
            os.chmod(ca_key, 0o644)
        with self.assertRaisesRegex(CommandError,
                                    "group/world accessible|not only to this account"):
            self._sign()

    def test_an_open_folder_that_was_there_is_refused_and_left_as_it_was(self):
        """--init leaves a folder that was already there as it was: on
        Windows, restricting it would rewrite the access of everything in it.
        A folder open to others is refused, or the keys would be open from
        their first byte."""
        from ovcrypto import keystore

        parent = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, parent, True)
        if os.name == "nt":
            keystore._set_windows_dacl(parent, "D:P(A;OICI;FA;;;%s)(A;OICI;FR;;;BU)"
                                       % keystore._windows_user())
        else:
            os.chmod(parent, 0o755)
        beside = os.path.join(parent, "notes.txt")
        with open(beside, "w") as handle:
            handle.write("not the PKI's")
        before = (keystore._windows_others(beside) if os.name == "nt"
                  else os.stat(parent).st_mode)
        with self.assertRaisesRegex(CommandError, "Not writing a test CA there"):
            call_command("make_test_pki", "--init", "--out", parent, stdout=self.stdout)
        self.assertEqual(sorted(os.listdir(parent)), ["notes.txt"])
        self.assertEqual(keystore._windows_others(beside) if os.name == "nt"
                         else os.stat(parent).st_mode, before)

        # A private one is used.
        private = os.path.join(parent, "private")
        os.mkdir(private)
        keystore.restrict_to_owner(private)
        call_command("make_test_pki", "--init", "--out", private, stdout=self.stdout)
        keystore._require_private_mode(os.path.join(private, "ca.key.pem"))

