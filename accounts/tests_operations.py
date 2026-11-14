"""Putting another database in the live one's place, the keys it must open,
and the deploy scripts that carry it, run against stubs.
"""

import base64
import datetime
import hashlib
import io
import json
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
import uuid
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from django.conf import settings
from django.core.management import CommandError, call_command
from django.db import connection
from django.template.loader import render_to_string
from django.test import TestCase, override_settings
from django.utils import timezone

from accounts import credential_keys, database_swap, devices, signing_status
from accounts.credentials import CredentialError
from accounts.models import (CredentialEpochKey, Device, DeviceLogKey,
                             IssuedCredential, IssuerKey, RevokedCredentialId,
                             User)
# The module, not the class: a TestCase named here runs here too.
from accounts import tests as kit_tests
from ovcrypto import keystore

WRAP = "ab" * 32
OTHER_WRAP = "cd" * 32
SITE = "verify-test.example.org"


class _KeysFixture(TestCase):
    """A site minting from a key file, with one paired phone."""

    def setUp(self):
        credential_keys.reset_caches()
        self.addCleanup(credential_keys.reset_caches)
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        pem = os.path.join(self.dir, "issuer.pem")
        issuer = ec.generate_private_key(ec.SECP256R1())
        with open(pem, "wb") as handle:
            handle.write(issuer.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        os.chmod(pem, stat.S_IRUSR | stat.S_IWUSR)
        ctx = override_settings(CREDENTIAL_ISSUER_KEY_PATH=pem,
                                CREDENTIAL_ISSUER_KEY_ID=1, SIGNER_SOCKET="",
                                CREDENTIAL_EPOCH_WRAP_KEY=WRAP,
                                ALLOWED_HOSTS=[SITE, "10.0.0.9", "localhost", "testserver"])
        ctx.enable()
        self.addCleanup(ctx.disable)
        IssuerKey.objects.create(
            key_id=1, is_active=True,
            spki_der=issuer.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo),
            not_before=timezone.now() - datetime.timedelta(days=1),
            not_after=timezone.now() + datetime.timedelta(days=730))
        self.owner = User.objects.create(national_id_card_number="5555666677778888",
                                         given_name="Owner", last_name="One")
        self.device_key = ec.generate_private_key(ec.SECP256R1())
        self.device = Device.objects.create(
            owner=self.owner, label="Field 1",
            public_key_der=self.device_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo))

    def _sync(self, device_id=None):
        nonce = json.loads(self.client.post(
            "/api/v1/device/challenge/").content)["challenge"]
        der = self.device_key.sign(base64.b64decode(nonce),
                                   ec.ECDSA(hashes.SHA256()))
        return self.client.post("/api/v1/device/keys/", data=json.dumps({
            "device_id": str(device_id or self.device.device_id),
            "challenge": nonce, "signature": base64.b64encode(der).decode()}),
            content_type="application/json")

    def _other_wrap_key(self):
        """The site's wrap key changed under its stored keys: a database
        brought from a site with another one."""
        ctx = override_settings(CREDENTIAL_EPOCH_WRAP_KEY=OTHER_WRAP)
        ctx.enable()
        self.addCleanup(ctx.disable)
        credential_keys.reset_caches()


class UnreadableKeysTest(_KeysFixture):
    """Keys this site cannot open are refused where they would be used, and
    said, never a 500."""

    def test_readable_keys_sync(self):
        self.assertEqual(self._sync().status_code, 200)

    def test_a_sync_is_a_503_naming_the_site_not_a_500(self):
        credential_keys.issuing_keys()
        self._other_wrap_key()
        with self.assertLogs("accounts.devices", "ERROR"):
            reply = self._sync()
        self.assertEqual(reply.status_code, 503)
        self.assertEqual(reply.json()["error"], devices.KEYS_UNAVAILABLE)

    def test_an_older_epoch_still_carried_counts_too(self):
        """Phones are given every epoch still readable, not only the current
        one: one of those that does not open is a 503 as well."""
        credential_keys.issuing_keys()
        older = credential_keys.epoch_key_row(credential_keys.current_epoch() - 1,
                                              credential_keys.TIER_PUBLIC)
        older.wrapped_private_key = b"\x00" * 60
        older.save()
        with self.assertLogs("accounts.devices", "ERROR"):
            reply = self._sync()
        self.assertEqual(reply.status_code, 503)

    def test_a_mint_refuses_keys_it_cannot_open(self):
        credential_keys.issuing_keys()
        self._other_wrap_key()
        with self.assertRaisesMessage(CredentialError, "cannot be opened"):
            credential_keys.issuing_keys()

    def test_setup_says_so_in_red(self):
        credential_keys.issuing_keys()
        self.assertEqual(signing_status.overview()["unreadable"], [])
        self._other_wrap_key()
        epoch = credential_keys.current_epoch()
        card = signing_status.overview()
        self.assertEqual(card["unreadable"], ["epoch %d public" % epoch,
                                              "epoch %d restricted" % epoch])
        html = render_to_string("includes/signing_setup.html", {"signing": card})
        self.assertIn("This site cannot open its own document keys", html)

    def test_halves_that_do_not_belong_together_are_unreadable(self):
        """Both open, but each is the other's: as a copy that mixed rows
        would leave them."""
        keys = credential_keys.issuing_keys()
        rows = list(CredentialEpochKey.objects.filter(epoch=keys.epoch))
        a, b = rows
        a.wrapped_private_key, b.wrapped_private_key = (
            bytes(b.wrapped_private_key), bytes(a.wrapped_private_key))
        a.save()
        b.save()
        credential_keys.reset_caches()
        self.assertEqual(len(credential_keys.unreadable_epoch_keys()), 2)
        with self.assertRaises(CredentialError):
            credential_keys.issuing_keys()

    def test_no_wrap_key_is_missing_not_unreadable(self):
        credential_keys.issuing_keys()
        with override_settings(CREDENTIAL_EPOCH_WRAP_KEY=""):
            credential_keys.reset_caches()
            self.assertEqual(credential_keys.unreadable_epoch_keys(), [])
            self.assertEqual(credential_keys.missing(),
                             ["CREDENTIAL_EPOCH_WRAP_KEY"])


class EpochForkTest(_KeysFixture):
    """An epoch whose keys are gone is not given new ones."""

    def _credential(self, epoch):
        now = timezone.now()
        IssuedCredential.objects.create(
            credential_id=uuid.uuid4(), document_uuid=uuid.uuid4(), epoch=epoch,
            issuer_key_id=1, issued_at=now, expires_at=now)

    def test_an_epoch_with_credentials_is_not_made_again(self):
        epoch = credential_keys.current_epoch()
        self._credential(epoch)
        with self.assertLogs("accounts.credential_keys", "ERROR"):
            with self.assertRaisesMessage(CredentialError, "put back"):
                credential_keys.issuing_keys()
        self.assertFalse(CredentialEpochKey.objects.exists())

    def test_a_sync_meeting_it_is_a_503(self):
        self._credential(credential_keys.current_epoch())
        with self.assertLogs("accounts", "ERROR"):
            reply = self._sync()
        self.assertEqual(reply.status_code, 503)

    def test_another_epochs_credentials_do_not_stop_it(self):
        self._credential(credential_keys.current_epoch() - 1)
        self.assertEqual(credential_keys.issuing_keys().epoch,
                         credential_keys.current_epoch())

    def test_keys_made_late_are_logged_on_a_site_with_history(self):
        epoch = credential_keys.current_epoch()
        # A site's first keys: late by the clock, and nothing to say.
        with self.assertNoLogs("accounts.credential_keys", "WARNING"):
            credential_keys.epoch_key_row(epoch - 2, credential_keys.TIER_PUBLIC)
        with self.assertLogs("accounts.credential_keys", "WARNING") as logs:
            credential_keys.epoch_key_row(epoch - 1, credential_keys.TIER_PUBLIC)
        self.assertIn("days after it began", logs.output[0])
        with self.assertNoLogs("accounts.credential_keys", "WARNING"):
            credential_keys.epoch_key_row(epoch + 1, credential_keys.TIER_PUBLIC)


class LostKeysTest(_KeysFixture):
    """Keys refused for an epoch documents were made in show on Setup, and
    there is a way on when no backup has them."""

    def setUp(self):
        super().setUp()
        now = timezone.now()
        IssuedCredential.objects.create(
            credential_id=uuid.uuid4(), document_uuid=uuid.uuid4(),
            epoch=credential_keys.current_epoch(), issuer_key_id=1,
            issued_at=now, expires_at=now)

    def test_setup_names_the_lost_keys(self):
        epoch = credential_keys.current_epoch()
        card = signing_status.overview()
        self.assertEqual(card["lost"], ["epoch %d public" % epoch,
                                        "epoch %d restricted" % epoch])
        html = render_to_string("includes/signing_setup.html", {"signing": card})
        self.assertIn("are missing from this database", html)
        self.assertIn("remake_epoch_keys", html)

    def test_keys_never_made_are_not_lost(self):
        IssuedCredential.objects.all().delete()
        self.assertEqual(credential_keys.lost_epoch_keys(), [])

    def test_remaking_them_takes_the_sites_name_and_brings_minting_back(self):
        for confirm in ([], ["--confirm", "localhost"]):
            with self.assertRaisesMessage(CommandError, "name this site"):
                call_command("remake_epoch_keys", *confirm, stdout=io.StringIO())
        with self.assertRaises(CredentialError):
            credential_keys.issuing_keys()
        out = io.StringIO()
        with self.assertLogs("accounts.credential_keys", "ERROR"):
            call_command("remake_epoch_keys", "--confirm", SITE, stdout=out)
        self.assertIn("no longer open", out.getvalue())
        self.assertEqual(credential_keys.issuing_keys().epoch,
                         credential_keys.current_epoch())
        self.assertEqual(credential_keys.lost_epoch_keys(), [])
        with self.assertRaisesMessage(CommandError, "No key of the current epoch is lost"):
            call_command("remake_epoch_keys", "--confirm", SITE, stdout=io.StringIO())

    def test_the_current_epochs_keys_count_whatever_their_row_says(self):
        IssuedCredential.objects.all().delete()
        credential_keys.issuing_keys()
        CredentialEpochKey.objects.update(
            not_after=timezone.now() - datetime.timedelta(days=1),
            wrapped_private_key=b"\x00" * 60)
        credential_keys.reset_caches()
        self.assertEqual(len(credential_keys.unreadable_epoch_keys()), 2)


class SiteNamesTest(TestCase):
    """An address, localhost or a wildcard names no site."""

    def test_only_host_names_count(self):
        self.assertEqual(
            database_swap.site_names([SITE, "10.0.0.9", "localhost", "*",
                                      ".example.org", "[::1]", "VERIFY.example.ORG"]),
            [SITE, "verify.example.org"])

    def test_the_command_refuses_them(self):
        with override_settings(ALLOWED_HOSTS=[SITE, "10.0.0.9", "localhost", "*"]):
            for name in ("10.0.0.9", "localhost", "*"):
                with self.assertRaisesMessage(CommandError, "its host name"):
                    call_command("replace_database", __file__, "--confirm", name,
                                 stdout=io.StringIO())


class UnknownDeviceTest(_KeysFixture):
    """The app shows the refusal as it stands, so it says what to do."""

    def test_an_unknown_or_revoked_phone_is_told_to_reset_and_pair(self):
        for device_id in (uuid.uuid4(), None):
            if device_id is None:
                devices.revoke(self.device)
            reply = self._sync(device_id)
            self.assertEqual(reply.status_code, 403)
            self.assertEqual(reply.json()["error"], devices.UNKNOWN_DEVICE)
        self.assertIn("reset its keys", devices.UNKNOWN_DEVICE)
        self.assertIn("pair it with a new code", devices.UNKNOWN_DEVICE)

    def test_the_refusal_is_a_pairing_error(self):
        """Every view that catches PairingError still catches it."""
        self.assertTrue(issubclass(devices.UnknownDevice, devices.PairingError))


class _SwapFixture(_KeysFixture):
    """Database files made from the test database, to swap between."""

    def setUp(self):
        super().setUp()
        credential_keys.issuing_keys()
        key = X25519PrivateKey.generate()
        # An id no fresh row would get, so a carried key keeps it on purpose.
        DeviceLogKey.objects.create(
            id=7, public_key=key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            wrapped_private_key=credential_keys._wrapper().wrap(key.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption())))
        now = timezone.now()
        self.credential = IssuedCredential.objects.create(
            credential_id=uuid.uuid4(), document_uuid=uuid.uuid4(),
            epoch=credential_keys.current_epoch(), issuer_key_id=1,
            issued_at=now, expires_at=now, revoked_at=now)
        self.files = Path(self.dir) / "files"
        self.files.mkdir()
        self.live = self._file("live.sqlite3")
        self.copy = self._file("copy.sqlite3")
        self.now = int(timezone.now().timestamp())

    def _file(self, name):
        """The test database as it is now, as a file."""
        path = self.files / name
        connection.ensure_connection()
        # A dump, not Connection.backup: the test's own transaction holds the
        # in-memory database, and a backup would wait on it for ever.
        target = sqlite3.connect(str(path))
        target.executescript("\n".join(connection.connection.iterdump()))
        target.close()
        return path

    def _edit(self, path, *statements):
        db = sqlite3.connect(str(path))
        with db:
            for statement in statements:
                db.execute(*statement) if isinstance(statement, tuple) else db.execute(statement)
        db.close()

    def _rows(self, path, sql):
        db = sqlite3.connect(str(path))
        try:
            return db.execute(sql).fetchall()
        finally:
            db.close()

    def _replace(self, **kwargs):
        return database_swap.replace(self.live, self.copy, self.files / "backups",
                                     now=self.now, **kwargs)


class DatabaseSwapTest(_SwapFixture):

    def test_a_copy_under_another_wrap_key_is_refused(self):
        """In place, every phone sync would have failed."""
        other = keystore.FileKeyWrapper(bytes.fromhex(OTHER_WRAP))
        for row in CredentialEpochKey.objects.all():
            self._edit(self.copy, (
                "UPDATE credential_epoch_keys SET wrapped_private_key = ? WHERE id = ?",
                (other.wrap(credential_keys.private_key(row)), row.id)))
        before = self._rows(self.live, "SELECT COUNT(*) FROM devices")
        with self.assertRaises(database_swap.SwapRefused) as refused:
            self._replace()
        self.assertIn("do not open with this site's", str(refused.exception))
        self.assertEqual(self._rows(self.live, "SELECT COUNT(*) FROM devices"), before)
        self.assertFalse((self.files / "backups").exists())

    def test_an_unreadable_log_key_is_refused_too(self):
        self._edit(self.copy, "UPDATE device_log_keys SET wrapped_private_key = x'00'")
        with self.assertRaisesMessage(database_swap.SwapRefused, "device log key"):
            self._replace()

    def test_this_sites_keys_the_copy_lacks_are_carried_in(self):
        """An older copy does not fork the current epoch."""
        log_key = DeviceLogKey.objects.get()
        self._edit(self.copy, "DELETE FROM credential_epoch_keys",
                   "DELETE FROM device_log_keys")
        report = self._replace()
        self.assertEqual(len(report["carry_epochs"]), 2)
        theirs = dict(((e, t), bytes(k)) for e, t, k in self._rows(
            self.live, "SELECT epoch, tier, public_key FROM credential_epoch_keys"))
        ours = {(r.epoch, r.tier): bytes(r.public_key)
                for r in CredentialEpochKey.objects.all()}
        self.assertEqual(theirs, ours)
        # A log key keeps its id: it is the key_id in every record sealed to it.
        self.assertEqual(self._rows(self.live, "SELECT id, public_key FROM device_log_keys"),
                         [(log_key.id, bytes(log_key.public_key))])
        self.assertIn("carried into it", "\n".join(database_swap.describe(report)))

    def test_other_keys_under_the_same_epoch_are_refused_unless_taken(self):
        row = CredentialEpochKey.objects.get(tier=credential_keys.TIER_PUBLIC)
        key = X25519PrivateKey.generate()
        self._edit(self.copy, (
            "UPDATE credential_epoch_keys SET public_key = ?, wrapped_private_key = ? "
            "WHERE id = ?",
            (key.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw),
             credential_keys._wrapper().wrap(key.private_bytes(
                 serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                 serialization.NoEncryption())), row.id)))
        with self.assertRaisesMessage(database_swap.SwapRefused, "--take-incoming-keys"):
            self._replace()
        report = self._replace(take_incoming_keys=True)
        self.assertEqual(report["keys_given_up"], ["epoch %d public" % row.epoch])
        self.assertIn("no longer opens", "\n".join(database_swap.describe(report)))

    def test_what_the_copy_lacks_is_said(self):
        """Phones, document records and revocations made since."""
        self._edit(self.copy, "DELETE FROM devices", "DELETE FROM issued_credentials")
        report = self._replace()
        self.assertEqual(report["lost_devices"], ["Field 1"])
        self.assertEqual(report["lost_credentials"], 1)
        self.assertEqual(report["lost_revocations"], 1)
        said = "\n".join(database_swap.describe(report))
        self.assertIn("1 phone paired here is not in the copy: Field 1", said)
        self.assertIn("must reset its keys and pair again", said)
        self.assertIn("revoke those documents again", said)

    def test_a_revocation_planted_by_id_counts_too(self):
        RevokedCredentialId.objects.create(credential_id=uuid.uuid4(), reason="lost")
        self.live = self._file("live2.sqlite3")
        self.assertEqual(self._replace()["lost_revocations"], 1)

    def test_the_live_database_is_backed_up_first_and_the_copy_left_alone(self):
        self._edit(self.copy, "DELETE FROM devices")
        copy_sum = hashlib.sha256(self.copy.read_bytes()).hexdigest()
        report = self._replace()
        backup = Path(report["backup"])
        self.assertEqual(self._rows(backup, "SELECT label FROM devices"), [("Field 1",)])
        self.assertEqual(self._rows(self.live, "SELECT COUNT(*) FROM devices"), [(0,)])
        self.assertEqual(report["backup_sha256"],
                         hashlib.sha256(backup.read_bytes()).hexdigest())
        self.assertEqual(hashlib.sha256(self.copy.read_bytes()).hexdigest(), copy_sum)
        self.assertEqual(sorted(p.name for p in self.files.iterdir()),
                         ["backups", "copy.sqlite3", "live.sqlite3"])
        if sys.platform != "win32":
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)

    def test_what_is_not_a_verify_database_is_refused(self):
        self.copy.write_bytes(b"not a database at all" * 100)
        with self.assertRaisesMessage(database_swap.SwapRefused, "not a database"):
            self._replace()
        self.copy.unlink()
        sqlite3.connect(str(self.copy)).execute("CREATE TABLE t (x)").connection.close()
        with self.assertRaisesMessage(database_swap.SwapRefused, "not a verify database"):
            self._replace()

    def test_an_empty_journal_beside_the_live_file_is_cleared(self):
        """It carries nothing; refusing over it would refuse for ever."""
        journal = Path(str(self.live) + "-journal")
        journal.write_bytes(b"")
        self._edit(self.copy, "DELETE FROM devices")
        self._replace()
        self.assertFalse(journal.exists())
        self.assertEqual(self._rows(self.live, "SELECT COUNT(*) FROM devices"), [(0,)])

    def test_a_writer_appearing_meanwhile_stops_the_swap(self):
        real = database_swap._insert

        def and_a_writer(conn, table, rows, *, keep_id):
            Path(str(self.live) + "-wal").write_bytes(b"x")
            return real(conn, table, rows, keep_id=keep_id)

        with patch.object(database_swap, "_insert", and_a_writer):
            with self.assertRaisesMessage(database_swap.SwapRefused, "something is writing"):
                self._replace()
        Path(str(self.live) + "-wal").unlink()
        self.assertEqual(self._rows(self.live, "SELECT COUNT(*) FROM devices"), [(1,)])
        self.assertFalse(any(p.name.startswith("live.sqlite3.incoming")
                             for p in self.files.iterdir()))

    def test_a_site_restarted_meanwhile_stops_the_swap(self):
        calls = []

        def second_look(path):
            calls.append(path)
            return [] if len(calls) == 1 else [4243]

        with patch.object(database_swap, "in_use", second_look):
            with self.assertRaisesMessage(database_swap.SwapRefused, "4243"):
                self._replace()
        self.assertEqual(len(calls), 2)
        self.assertEqual(self._rows(self.live, "SELECT COUNT(*) FROM devices"), [(1,)])

    def _journal_mode(self, path):
        return self._rows(path, "PRAGMA journal_mode")[0][0].lower()

    def test_a_wal_copy_leaves_a_live_file_the_next_swap_takes(self):
        """A WAL copy put in place must not wedge every later swap over the
        -wal a read-only open leaves beside it."""
        self._edit(self.copy, "PRAGMA journal_mode=WAL")
        self.assertEqual(self._journal_mode(self.copy), "wal")
        self._replace()
        self.assertEqual(self._journal_mode(self.live), "delete")
        self._edit(self.copy, "DELETE FROM devices")
        self._replace()
        self.assertEqual(self._rows(self.live, "SELECT COUNT(*) FROM devices"), [(0,)])
        # Read as it stands: nothing left beside the copy.
        for suffix in ("-wal", "-shm"):
            self.assertFalse(Path(str(self.copy) + suffix).exists(), suffix)

    def test_a_wal_live_file_left_by_a_read_only_open_is_settled(self):
        self._edit(self.live, "PRAGMA journal_mode=WAL")
        reader = database_swap._open(self.live)
        reader.execute("SELECT COUNT(*) FROM devices").fetchone()
        reader.close()
        self._replace()
        self.assertEqual(self._journal_mode(self.live), "delete")
        for suffix in ("-wal", "-journal"):
            self.assertFalse(Path(str(self.live) + suffix).exists(), suffix)

    def test_the_live_files_mode_carries_over(self):
        if sys.platform == "win32":
            self.skipTest("POSIX modes")
        os.chmod(self.live, 0o640)
        self._replace()
        self.assertEqual(stat.S_IMODE(self.live.stat().st_mode), 0o640)

    def test_a_copy_trusting_another_issuer_key_is_refused(self):
        """In file mode phones are told to trust the copy's key 1, and the
        site signs with its own: every document would fail."""
        other = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self._edit(self.copy, ("UPDATE issuer_keys SET spki_der = ?", (other,)))
        with self.assertRaisesMessage(database_swap.SwapRefused, "lists another issuer key 1"):
            self._replace()
        self._edit(self.copy, "DELETE FROM issuer_keys")
        with self.assertRaisesMessage(database_swap.SwapRefused, "does not list issuer key 1"):
            self._replace()
        # With a signer the site keeps those rows itself.
        with override_settings(SIGNER_SOCKET="/run/cl03-signer/app.sock"):
            self._replace()

    def test_lost_verifications_and_phone_records_are_said(self):
        """Phones delete their records once the site has them: in a copy
        without them, they are only in the backup."""
        from accounts.models import DeviceLogEntry, Transaction
        Transaction.objects.create()
        DeviceLogEntry.objects.create(device_uuid=self.device.device_id, seq=1,
                                      key_id=7, event="verify", outcome="ok",
                                      record_hash=b"h" * 32, chain_ok=True)
        self.live = self._file("live3.sqlite3")
        report = database_swap.plan(self.live, self.copy, now=self.now)
        self.assertEqual((report["lost_transactions"], report["lost_log_records"]), (1, 1))
        said = "\n".join(database_swap.describe(report))
        self.assertIn("1 verification made here is not in the copy", said)
        self.assertIn("1 phone activity record is not in the copy", said)

    def test_a_running_site_is_refused(self):
        with patch.object(database_swap, "in_use", return_value=[4242]):
            with self.assertRaisesMessage(database_swap.SwapRefused,
                                          "4242 still has the database open"):
                self._replace()

    def test_the_live_file_is_not_its_own_copy(self):
        with self.assertRaisesMessage(database_swap.SwapRefused, "live database itself"):
            database_swap.replace(self.live, self.live, self.files, now=self.now)

    def test_a_server_with_no_database_yet_takes_the_copy(self):
        self.live.unlink()
        report = self._replace()
        self.assertEqual(report["backup"], "")
        self.assertEqual(self._rows(self.live, "SELECT label FROM devices"), [("Field 1",)])

    def test_a_site_without_a_wrap_key_takes_only_a_copy_without_keys(self):
        with override_settings(CREDENTIAL_EPOCH_WRAP_KEY=""):
            credential_keys.reset_caches()
            with self.assertRaisesMessage(database_swap.SwapRefused,
                                          "no CREDENTIAL_EPOCH_WRAP_KEY"):
                self._replace()
            for path in (self.live, self.copy):
                self._edit(path, "DELETE FROM credential_epoch_keys",
                           "DELETE FROM device_log_keys")
            self.assertEqual(self._replace()["carry_epochs"], [])

    def test_an_expired_epoch_key_does_not_stop_a_copy(self):
        """Phones are no longer given an old epoch's key, so whether it opens
        does not matter."""
        self._edit(self.copy, (
            "INSERT INTO credential_epoch_keys (epoch, tier, public_key, "
            "wrapped_private_key, not_before, not_after, created_at) "
            "VALUES (?, 0, x'00', x'00', ?, ?, ?)",
            (credential_keys.current_epoch() - 6, "2001-01-01 00:00:00",
             "2001-01-02 00:00:00", "2001-01-01 00:00:00")))
        self._replace()

    def test_the_current_epochs_keys_are_judged_whatever_their_row_says(self):
        """Every mint and sync opens them, expired in the copy or not."""
        self._edit(self.copy, (
            "UPDATE credential_epoch_keys SET wrapped_private_key = x'00', "
            "not_after = ?", ("2001-01-01 00:00:00",)))
        with self.assertRaisesMessage(database_swap.SwapRefused, "do not open"):
            self._replace()


class ReplaceDatabaseCommandTest(_SwapFixture):
    """The command a deploy and an operator run."""

    def _call(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(database_swap, "live_path", return_value=self.live):
            call_command("replace_database", str(self.copy), *args,
                         backup_dir=str(self.files / "backups"),
                         stdout=out, stderr=err)
        return out.getvalue(), err.getvalue()

    def test_it_names_the_site_or_does_nothing(self):
        for confirm in ([], ["--confirm", "verify.other.example"], ["--confirm", "*"]):
            with self.assertRaisesMessage(CommandError, "DJANGO_ALLOWED_HOSTS"):
                self._call(*confirm)
        self.assertFalse((self.files / "backups").exists())

    def test_check_changes_nothing(self):
        self._edit(self.copy, "DELETE FROM devices")
        out, _ = self._call("--check")
        self.assertIn("1 phone paired here is not in the copy", out)
        self.assertIn("nothing was changed", out)
        self.assertEqual(self._rows(self.live, "SELECT COUNT(*) FROM devices"), [(1,)])

    def test_it_replaces_and_says_where_the_old_one_went(self):
        self._edit(self.copy, "DELETE FROM devices")
        out, _ = self._call("--confirm", SITE.upper())
        self.assertIn("The database it replaced is in", out)
        self.assertIn("Next: python manage.py migrate", out)
        self.assertEqual(self._rows(self.live, "SELECT COUNT(*) FROM devices"), [(0,)])

    def test_a_refusal_says_why_and_changes_nothing(self):
        self._edit(self.copy, "UPDATE device_log_keys SET wrapped_private_key = x'00'")
        out = io.StringIO()
        with self.assertRaisesMessage(CommandError, "Nothing was changed"):
            with patch.object(database_swap, "live_path", return_value=self.live):
                call_command("replace_database", str(self.copy), "--confirm", SITE,
                             stderr=out, stdout=io.StringIO())
        self.assertIn("Refused: the copy's keys do not open", out.getvalue())


#: Stand-ins for what a remote script calls on the server. Each says what it
#: was asked into $LOG, so a test reads back the order things happened in.
REMOTE_STUBS = {
    "sudo": '#!/bin/bash\nif [ "$1" = systemctl ]; then echo "systemctl $2 $3" >> "$LOG"; exit 0; fi\n'
            'if [ "$1" = nginx ]; then exit 0; fi\n"$@"\n',
    # Not "active", as a unit waiting to restart after a failure is not.
    "systemctl": '#!/bin/bash\necho "systemctl $*" >> "$LOG"\n'
                 '[ "$1" != is-active ] || exit 3\nexit 0\n',
    "pip": '#!/bin/bash\necho pip >> "$LOG"\nexit "${PIP_RC:-0}"\n',
    "python": '#!/bin/bash\ncase "$*" in\n'
              '  *replace_database*) echo "replace $*" >> "$LOG"; exit "${REPLACE_RC:-0}" ;;\n'
              '  *rewrap_keys*) echo "rewrap $*" >> "$LOG"; exit "${REWRAP_RC:-0}" ;;\n'
              '  *migrate*) echo migrate >> "$LOG"; exit "${MIGRATE_RC:-0}" ;;\n'
              '  *"shell -c"*) exit 1 ;;\n'
              '  *) exit 0 ;;\nesac\n',
}


def run_remote_script(test, text, **env):
    """Run `text`, a script a deploy sends to the server, here: an app folder
    with an incoming database beside it, and stubs for what it calls.
    Returns (completed process, log lines, app folder)."""
    import subprocess

    from accounts.tests_web_security import BASH, CAN_RUN_DEPLOY
    if not CAN_RUN_DEPLOY:
        test.skipTest("needs Git Bash or a POSIX bash")
    tmp = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, tmp, True)
    app, stubs = tmp / "app", tmp / "bin"
    for folder in (app / "verify", app / "venv" / "bin", stubs):
        folder.mkdir(parents=True)
    (app / "venv" / "bin" / "activate").write_text("", newline="\n")
    (app / ".env").write_text("DJANGO_SECRET_KEY=x\n", newline="\n")
    (app / "db.sqlite3.incoming").write_bytes(b"a database")
    # What `rewrap-key` sends.
    (app / "new-wrap.key").write_text("cd" * 32 + "\n", newline="\n")
    # What a deploy ships beside the code: the activity log purge's
    # installer, standing in for itself.
    (app / "units").mkdir()
    (app / "units" / "install-purge-timer.sh").write_text(
        'echo "install-purge-timer $*" >> "$LOG"\nexit "${PURGE_RC:-0}"\n', newline="\n")
    for name, body in REMOTE_STUBS.items():
        (stubs / name).write_text(body, newline="\n")
    (app / "venv" / "bin" / "python").write_text(REMOTE_STUBS["python"], newline="\n")
    child = dict(os.environ, APP_DIR=app.as_posix(), LOG=(tmp / "log").as_posix(),
                 SYNC_HOST=SITE, INSTALL_NGINX="",
                 PATH=str(stubs) + os.pathsep + os.environ.get("PATH", ""))
    child.update({k: str(v) for k, v in env.items()})
    run = subprocess.run([BASH, "-s"], input=text, env=child, capture_output=True,
                         text=True, timeout=60)
    log = tmp / "log"
    return run, (log.read_text().splitlines() if log.exists() else []), app


class EnvFileReadAsSystemdTest(TestCase):
    """Every script that loads .env to run manage.py on a server reads it as
    gunicorn's systemd EnvironmentFile= does, so the command sees the values
    the site runs on: a value's single trailing '=' is kept (every base64 key
    of 32 bytes ends in one), the quotes systemd takes off are taken off, a
    last line with no newline is read, a CR at a line's end goes and a line
    with an empty key is skipped, as systemd does."""

    SCRIPTS = {("deploy", "deploy.sh"): 6}
    HEAD = 'while IFS= read -r line || [ -n "$line" ]; do'

    @staticmethod
    def _text(*parts):
        return Path(settings.BASE_DIR, *parts).read_text(encoding="utf-8")

    def _loops(self, text):
        """Each loop that reads a server's .env, from its `while` to its
        `done`, without its indent. (deploy.sh's own parser of the site's
        configuration file starts the same way and reads that file.)"""
        lines, found = text.splitlines(), []
        for n, line in enumerate(lines):
            if line.strip() != self.HEAD:
                continue
            indent = line[:len(line) - len(line.lstrip())]
            block = []
            for body in lines[n:]:
                block.append(body[len(indent):])
                if body.strip().startswith("done <"):
                    break
            if block[-1] in ('done < "$APP_DIR/.env"', 'done < "$ENV"'):
                found.append(block)
        return found

    def test_every_script_reads_env_with_the_one_loop(self):
        first = self._loops(self._text("deploy", "deploy.sh"))[0]
        for parts, count in self.SCRIPTS.items():
            text = self._text(*parts)
            self.assertNotIn("IFS='=' read", text, parts)
            loops = self._loops(text)
            self.assertEqual(len(loops), count, parts)
            for block in loops:
                # What a line is read as: the same five lines everywhere.
                self.assertEqual(block[:5], first[:5], parts)

    def test_values_come_out_as_systemd_gives_them(self):
        import subprocess

        from accounts.tests_web_security import BASH, CAN_RUN_DEPLOY
        if not CAN_RUN_DEPLOY:
            self.skipTest("needs Git Bash or a POSIX bash")
        block = self._loops(self._text("deploy", "deploy.sh"))[0]
        self.assertTrue(block[-1].startswith("done <"))
        block[-1] = 'done < "$ENVFILE"'
        wrap = base64.b64encode(bytes(range(32))).decode()
        self.assertTrue(wrap.endswith("=") and not wrap.endswith("=="))
        expected = {
            "WRAP": wrap, "TWO": "QUJD==", "URL": "https://x.example/?a=b&c=d",
            "DQ": "two words", "SQ": "single", "EMPTY": "", "INNER": 'say "hi"',
            "LAST": "no newline after me", "CR": "edited on Windows",
            "CRQ": "quoted, on Windows",
        }
        env_text = ("# a comment=with an equals sign\n; a comment=too\n\n"
                    "WRAP=%s\nTWO=QUJD==\nURL=https://x.example/?a=b&c=d\n"
                    'DQ="two words"\nSQ=\'single\'\nEMPTY=""\nINNER=say "hi"\n'
                    "NOEQUALS\n=orphan\nCR=edited on Windows\r\n"
                    'CRQ="quoted, on Windows"\r\nLAST=no newline after me' % wrap)
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / ".env").write_text(env_text, encoding="utf-8", newline="")
        names = list(expected) + ["NOEQUALS"]
        script = ("set -euo pipefail\n" + "\n".join(block) + "\n"
                  'for n in %s; do printf "%%s=[%%s]\\n" "$n" "${!n-UNSET}"; done\n'
                  % " ".join(names))
        run = subprocess.run([BASH, "-s"], input=script, capture_output=True, text=True,
                             env=dict(os.environ, ENVFILE=(tmp / ".env").as_posix()),
                             timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr)
        got = dict(line.split("=", 1) for line in run.stdout.splitlines())
        for name, value in expected.items():
            self.assertEqual(got[name], "[%s]" % value, name)
        self.assertEqual(got["NOEQUALS"], "[UNSET]")


class KitHostKeysTest(TestCase):
    """DeployKitTest's site and runner, borrowed, so its own tests do
    not run twice."""

    STUBS = kit_tests.DeployKitTest.STUBS
    SECRET = kit_tests.DeployKitTest.SECRET
    GOOD = kit_tests.DeployKitTest.GOOD
    HOST_KEY = kit_tests.DeployKitTest.HOST_KEY
    _bash = kit_tests.DeployKitTest._bash
    _site = kit_tests.DeployKitTest._site
    _run = kit_tests.DeployKitTest._run

    SERVER = "SERVER_IP=192.0.2.20\nJUMP_HOST=192.0.2.10\n"

    def _log(self, site):
        path = site / "stubs" / "log"
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def test_without_pinned_keys_nothing_connects(self):
        for pinned, name in (((), "server"), (("server",), "bastion")):
            site = self._site(self.GOOD + self.SERVER, pinned=pinned)
            result = self._run(site, "deploy")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("no SSH host key for the %s" % name, result.stderr)
            self.assertNotIn("target", self._log(site))

    def test_ssh_trusts_only_the_pinned_file(self):
        source = (settings.BASE_DIR / "deploy" / "deploy.sh").read_text(encoding="utf-8")
        self.assertNotIn("StrictHostKeyChecking no", source)
        self.assertEqual(source.count("StrictHostKeyChecking yes"), 2)
        self.assertIn("HostKeyAlias server", source)
        self.assertIn("HostKeyAlias bastion", source)

    def test_hostkeys_reads_them_from_the_console(self):
        site = self._site(self.GOOD, pinned=())
        # A server rebuilt since: its old key goes, the bastion's line too.
        (site / "known_hosts").write_text(
            "server ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEvAXtRx0SwCyycI+5GTFtEuqkuOtvoJXFaegOOaE0XJ\n",
            encoding="utf-8", newline="\n")
        (site / "terraform.tfstate").write_text("{}", encoding="utf-8")
        (site / "stubs").mkdir()
        (site / "stubs" / "console").write_text(
            "boot noise\n-----BEGIN SSH HOST KEY KEYS-----\n%s root@ip-10-0-0-5\n"
            "-----END SSH HOST KEY KEYS-----\nmore noise\n" % self.HOST_KEY,
            encoding="utf-8", newline="\n")
        result = self._run(site, "hostkeys")
        self.assertEqual(result.returncode, 0, result.stderr)
        pinned = (site / "known_hosts").read_text(encoding="utf-8")
        self.assertEqual(pinned, "bastion %s\nserver %s\n" % (self.HOST_KEY, self.HOST_KEY))
        self.assertIn("get-console-output --instance-id i-fedcba9876543210f", self._log(site))
        self.assertIn("ED25519", result.stdout)

    def test_hostkeys_needs_the_infra_state(self):
        result = self._run(self._site(self.GOOD), "hostkeys")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("by hand", result.stderr)

    def test_sync_db_must_name_this_site(self):
        site = self._site(self.GOOD + self.SERVER)
        result = self._run(site, "deploy", "--sync-db")
        self.assertIn("name the site", result.stderr)
        result = self._run(site, "deploy", "--sync-db=verify.other.example")
        self.assertIn("is not this site", result.stderr)
        self.assertEqual(self._log(site), "")

    def test_restore_names_the_site_and_goes_through_the_command(self):
        site = self._site(self.GOOD + self.SERVER)
        (site / "backups").mkdir()
        (site / "backups" / "db-1.sqlite3").write_bytes(b"x")
        for args, said in ((["restore"], "needs the database file"),
                           (["restore", "backups/nothing.sqlite3"], "no such file"),
                           (["restore", "backups/db-1.sqlite3"], "--confirm=HOST"),
                           (["restore", "backups/db-1.sqlite3", "--confirm=other.example"],
                            "is not this site")):
            result = self._run(site, *args)
            self.assertNotEqual(result.returncode, 0, args)
            self.assertIn(said, result.stderr, args)
        self.assertEqual(self._log(site), "")
        for name in ("localhost", "10.0.0.9", "*"):
            result = self._run(site, "restore", "backups/db-1.sqlite3", "--confirm=" + name)
            self.assertIn("by its host name", result.stderr, name)
        self.assertEqual(self._log(site), "")
        # Named as `backup` names it, inside the site's folder.
        result = self._run(site, "restore", "backups/db-1.sqlite3", "--confirm=" + SITE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("target:/home/ec2-user/app/db.sqlite3.incoming", self._log(site))

    def test_restore_finds_the_backup_in_the_sites_folder_from_anywhere(self):
        site = self._site(self.GOOD + self.SERVER)
        (site / "backups").mkdir()
        (site / "backups" / "db-1.sqlite3").write_bytes(b"x")
        elsewhere = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, elsewhere, True)
        result = self._run(site, "restore", "backups/db-1.sqlite3", "--confirm=" + SITE,
                           cwd=elsewhere)
        self.assertEqual(result.returncode, 0, result.stderr)

    def _restore_script(self):
        site = self._site(self.GOOD + self.SERVER)
        (site / "db.sqlite3").write_bytes(b"x")
        self._run(site, "restore", "db.sqlite3", "--confirm=" + SITE)
        return (site / "stubs" / "remote-scripts").read_text(encoding="utf-8")

    def test_the_restore_script_on_the_server(self):
        """Run, not read: a migrate that fails is reported as a failure, not
        as success."""
        text = self._restore_script()
        run, log, app = run_remote_script(self, text)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(log[0], "systemctl stop gunicorn")
        self.assertIn("--confirm %s" % SITE, log[1])
        self.assertEqual(log[2:], ["migrate", "systemctl start gunicorn"])
        self.assertFalse((app / "db.sqlite3.incoming").exists())
        # Refused: no migrate, the site serves the database it had.
        run, log, app = run_remote_script(self, text, REPLACE_RC=1)
        self.assertEqual(run.returncode, 3)
        self.assertNotIn("migrate", log)
        self.assertEqual(log[-1], "systemctl start gunicorn")
        self.assertFalse((app / "db.sqlite3.incoming").exists())
        # Replaced, migrate failed: said, not "Done".
        run, log, app = run_remote_script(self, text, MIGRATE_RC=1)
        self.assertEqual(run.returncode, 4)
        self.assertEqual(log[-1], "systemctl start gunicorn")

    def test_the_workbench_switch_reaches_the_server_with_a_warning(self):
        """A site kit server can have it too, said out loud."""
        site = self._site(self.GOOD + "VERIFY_WORKBENCH=" + SITE + "\n")
        result = self._run(site, "validate")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("VERIFY_WORKBENCH is set", result.stderr)
        self.assertIn("VERIFY_WORKBENCH", result.stdout)

    def test_a_deploy_swaps_after_the_code_and_before_migrate(self):
        source = (settings.BASE_DIR / "deploy" / "deploy.sh").read_text(encoding="utf-8")
        remote = source[source.index('echo "--- Running remote setup ---"'):]
        pip = remote.index("pip install -r requirements.txt")
        swap = remote.index("python manage.py replace_database")
        self.assertLess(pip, swap)
        self.assertLess(remote.index("sudo systemctl stop gunicorn"), swap)
        self.assertLess(swap, remote.index("python manage.py migrate --noinput"))
        self.assertIn("the database was NOT replaced", remote)


class DebugWorkbenchTest(TestCase):
    """The debug store still takes two opt-ins, and the second may be the
    workbench's own host instead of DEBUG."""

    def _allowed(self, **values):
        from accounts import debug_store
        base = dict(EVERIFY_DEBUG_CAPTURE=False, DEBUG=False, VERIFY_WORKBENCH="",
                    ALLOWED_HOSTS=["dev.example.org", "10.0.0.9"])
        base.update(values)
        with override_settings(**base):
            return debug_store.debug_allowed()

    def test_capture_alone_or_the_second_switch_alone_opens_nothing(self):
        self.assertFalse(self._allowed(EVERIFY_DEBUG_CAPTURE=True))
        self.assertFalse(self._allowed(DEBUG=True))
        self.assertFalse(self._allowed(VERIFY_WORKBENCH="dev.example.org"))

    def test_capture_with_debug_as_before(self):
        self.assertTrue(self._allowed(EVERIFY_DEBUG_CAPTURE=True, DEBUG=True))

    def test_capture_with_the_sites_own_workbench_host(self):
        self.assertTrue(self._allowed(EVERIFY_DEBUG_CAPTURE=True,
                                      VERIFY_WORKBENCH="dev.example.org"))

    def test_a_workbench_naming_another_host_opens_nothing(self):
        self.assertFalse(self._allowed(EVERIFY_DEBUG_CAPTURE=True,
                                       VERIFY_WORKBENCH="verify.example.org"))
        # A wildcard serves every name, so it vouches for none.
        self.assertFalse(self._allowed(EVERIFY_DEBUG_CAPTURE=True,
                                       VERIFY_WORKBENCH="*", ALLOWED_HOSTS=["*"]))


class PurgeTimerTest(TestCase):
    """The activity log ages out on its own. Every deploy ships
    deploy/install-purge-timer.sh and its two units beside the code and runs
    it; it installs them as gunicorn's own user and turns the timer on. The
    site kit's stand-ins and runner, borrowed as KitHostKeysTest does."""

    STUBS = kit_tests.DeployKitTest.STUBS
    GOOD = kit_tests.DeployKitTest.GOOD
    HOST_KEY = kit_tests.DeployKitTest.HOST_KEY
    _bash = kit_tests.DeployKitTest._bash
    _site = kit_tests.DeployKitTest._site
    _run = kit_tests.DeployKitTest._run

    SYSTEMCTL = ('#!/bin/sh\necho "systemctl $*" >> "$STUB_DIR/log"\n'
                 'case "$*" in\n'
                 '  "show -p User --value gunicorn.service") echo "$GUNICORN_USER" ;;\n'
                 '  "show -p Group --value gunicorn.service") echo "$GUNICORN_GROUP" ;;\n'
                 '  *NextElapseUSecRealtime*) echo "Thu 2026-11-05 00:41:07 UTC" ;;\n'
                 'esac\nexit 0\n')

    def test_every_deploy_ships_the_purge_and_installs_it(self):
        site = self._site(self.GOOD + "SERVER_IP=192.0.2.20\nJUMP_HOST=192.0.2.10\n")
        result = self._run(site, "deploy")
        self.assertEqual(result.returncode, 0, result.stderr)
        log = (site / "stubs" / "log").read_text(encoding="utf-8")
        shipped = [line for line in log.splitlines()
                   if line.endswith("target:/home/ec2-user/app/units/")]
        self.assertEqual(len(shipped), 1, log)
        for name in ("install-purge-timer.sh", "purge-device-logs.service.tftpl",
                     "purge-device-logs.timer.tftpl"):
            self.assertIn("/deploy/" + name, shipped[0])
        remote = (site / "stubs" / "remote-scripts").read_text(encoding="utf-8")
        install = remote.index('sudo bash "$APP_DIR/units/install-purge-timer.sh" '
                               '"$APP_DIR" "$APP_DIR/units"')
        # After the code and its migrations are in, since the unit runs it.
        self.assertLess(remote.index("python manage.py migrate --noinput"), install)

    def _install(self, user="verify-app", group="verify-app"):
        import subprocess

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        stubs, units = tmp / "stubs", tmp / "units"
        stubs.mkdir()
        units.mkdir()
        (stubs / "systemctl").write_text(self.SYSTEMCTL, encoding="utf-8", newline="\n")
        (stubs / "systemctl").chmod(0o755)
        bash, tools = self._bash()
        env = dict(os.environ, STUB_DIR=stubs.as_posix(), SYSTEMD_DIR=units.as_posix(),
                   GUNICORN_USER=user, GUNICORN_GROUP=group,
                   PATH=os.pathsep.join([str(stubs)] + tools + [os.environ.get("PATH", "")]))

        def run():
            result = subprocess.run(
                [bash, (settings.BASE_DIR / "deploy" / "install-purge-timer.sh").as_posix(),
                 "/srv/verify", (settings.BASE_DIR / "deploy").as_posix()],
                env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                timeout=60)
            log = stubs / "log"
            calls = log.read_text(encoding="utf-8") if log.exists() else ""
            log.unlink(missing_ok=True)
            return result, calls
        return units, run

    def test_the_installer_runs_the_purge_daily_as_gunicorn_does(self):
        units, run = self._install()
        result, calls = run()
        self.assertEqual(result.returncode, 0, result.stderr)
        service = (units / "purge-device-logs.service").read_text(encoding="utf-8")
        for line in ("Type=oneshot", "User=verify-app", "Group=verify-app",
                     "WorkingDirectory=/srv/verify/verify",
                     "EnvironmentFile=/srv/verify/.env",
                     "ExecStart=/srv/verify/venv/bin/python manage.py purge_device_logs",
                     # Never while gunicorn is stopped to copy the database.
                     "After=network.target gunicorn.service",
                     "Requisite=gunicorn.service", "PartOf=gunicorn.service"):
            self.assertIn("\n" + line + "\n", service)
        # No --days: the deployment's DEVICE_LOG_RETENTION_DAYS decides.
        self.assertNotIn("--days", service)
        self.assertNotIn("${", service)
        timer = (units / "purge-device-logs.timer").read_text(encoding="utf-8")
        # 02:00 in Manila, and no catching up at a start, when it could meet
        # the boot's own work.
        for line in ("OnCalendar=*-*-* 18:00:00 UTC", "WantedBy=timers.target"):
            self.assertIn("\n" + line + "\n", timer)
        self.assertNotIn("Persistent", timer)
        self.assertNotIn("\r", service + timer)
        self.assertIn("systemctl daemon-reload", calls)
        self.assertIn("systemctl enable --now purge-device-logs.timer", calls)
        self.assertIn("running as verify-app:verify-app", result.stdout)

        # A deploy that changes nothing leaves the units, and systemd, alone.
        result, calls = run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("up to date", result.stdout)
        self.assertNotIn("daemon-reload", calls)
        self.assertIn("systemctl enable --now purge-device-logs.timer", calls)

        # One edited on the server is put back.
        (units / "purge-device-logs.service").write_text(
            service.replace("User=verify-app", "User=root"), encoding="utf-8", newline="\n")
        result, calls = run()
        self.assertIn("installed purge-device-logs.service", result.stdout)
        self.assertIn("daemon-reload", calls)
        self.assertEqual((units / "purge-device-logs.service").read_text(encoding="utf-8"),
                         service)

    def test_a_gunicorn_with_no_group_gives_the_user_s_own(self):
        units, run = self._install(user="verify-app", group="")
        result, _ = run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("\nGroup=verify-app\n",
                      (units / "purge-device-logs.service").read_text(encoding="utf-8"))

    def test_the_installer_will_not_run_the_purge_as_root(self):
        for user in ("", "root", "0"):
            units, run = self._install(user=user, group="")
            result, calls = run()
            self.assertNotEqual(result.returncode, 0, user)
            self.assertIn("would run as root", result.stderr)
            self.assertEqual(list(units.iterdir()), [])
            self.assertNotIn("enable", calls)

    def _remote_setup(self):
        source = (settings.BASE_DIR / "deploy" / "deploy.sh").read_text(encoding="utf-8")
        start = source.index("<<'REMOTE'\n", source.index('echo "--- Running remote setup ---"'))
        start += len("<<'REMOTE'\n")
        return source[start:source.index("\nREMOTE\n", start) + 1]

    def test_the_server_installs_it_once_the_site_serves_again(self):
        run, log, app = run_remote_script(self, self._remote_setup(), SYNC_HOST="")
        self.assertEqual(run.returncode, 0, run.stderr)
        install = [i for i, line in enumerate(log) if line.startswith("install-purge-timer")]
        self.assertEqual(len(install), 1, log)
        self.assertEqual(log[install[0]], "install-purge-timer %s %s/units"
                         % (app.as_posix(), app.as_posix()))
        self.assertLess(log.index("migrate"), install[0])
        self.assertLess(log.index("systemctl restart gunicorn"), install[0])
        # A failed install fails the deploy, said at the end, the site serving.
        run, log, app = run_remote_script(self, self._remote_setup(), SYNC_HOST="",
                                          PURGE_RC=1)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("the activity log's purge was not installed", run.stderr)
        self.assertNotIn("Deploy complete", run.stdout)
        self.assertIn("systemctl restart gunicorn", log)

    def test_the_check_reports_the_purge(self):
        source = (settings.BASE_DIR / "deploy" / "deploy.sh").read_text(encoding="utf-8")
        check = source[source.index('if [ "$COMMAND" = check ]'):source.index("# --- deploy ---")]
        self.assertIn("systemctl is-enabled --quiet purge-device-logs.timer", check)
        self.assertIn("the purge runs as gunicorn does", check)
        self.assertIn("the last purge failed", check)
