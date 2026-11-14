"""manage.py rewrap_keys: every stored private key under a new wrap key, all
or nothing, and the phones notice nothing; the deploy's `rewrap-key`; and
what tells a site its keys do not open.

The command works on the database file, as replace_database does, so these
run it on files made from the test database (`_SwapFixture`)."""

import io
import os
import shutil
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.core import checks
from django.core.management import CommandError, call_command
from django.test import SimpleTestCase, TestCase, override_settings

from accounts import credential_keys, database_swap, device_log
from accounts.management.commands import rewrap_keys
from accounts.models import CredentialEpochKey, DeviceLogKey
from accounts import tests_operations
from accounts.tests_operations import (OTHER_WRAP, SITE, WRAP, _KeysFixture,
                                    _SwapFixture, run_remote_script)
from ovcrypto import keystore


def _wrapper(hex_key):
    return keystore.FileKeyWrapper(credential_keys.parse_wrap_key(hex_key))


class RewrapKeysTest(_SwapFixture):

    def setUp(self):
        super().setUp()
        credential_keys.epoch_key_row(credential_keys.current_epoch() - 1,
                                      credential_keys.TIER_PUBLIC)
        device_log.current_key()
        self.assertEqual(self._sync().status_code, 200)
        # Both tiers of this epoch, last epoch's public key, and log key 7,
        # which current_key() takes as the current one.
        self.live = self._file("rewrap-live.sqlite3")
        self.copy = self._file("rewrap-copy.sqlite3")
        self.count = (CredentialEpochKey.objects.count()
                      + DeviceLogKey.objects.count())
        self.assertEqual(self.count, 4)

    def _key_file(self, value=OTHER_WRAP, private=True, name="new.key", encoding="utf-8"):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding=encoding) as handle:
            handle.write(value + "\n")
        if private:
            keystore.restrict_to_owner(path)
        elif os.name == "nt":
            keystore._set_windows_dacl(path, "D:P(A;;FA;;;%s)(A;;FR;;;BU)"
                                       % keystore._windows_user())
        else:
            os.chmod(path, 0o644)
        return path

    def _run(self, *extra, new=True, confirm=SITE):
        args = list(extra)
        if new:
            args += ["--new-key-file", new if isinstance(new, str) else self._key_file()]
        if confirm:
            args += ["--confirm", confirm]
        out = io.StringIO()
        with patch.object(database_swap, "live_path", return_value=self.live):
            call_command("rewrap_keys", *args, stdout=out, stderr=out)
        return out.getvalue()

    def _rows(self, path):
        db = sqlite3.connect(str(path))
        try:
            return [(table, pk, bytes(public), bytes(wrapped))
                    for table in (database_swap.EPOCH_TABLE, database_swap.LOG_KEY_TABLE)
                    for pk, public, wrapped in db.execute(
                        "SELECT id, public_key, wrapped_private_key FROM %s ORDER BY id"
                        % table)]
        finally:
            db.close()

    def _edit(self, path, sql, *params):
        db = sqlite3.connect(str(path))
        with db:
            db.execute(sql, params)
        db.close()

    def _wrapped_log_key_7(self):
        return next(r[3] for r in self._rows(self.live)
                    if r[0] == database_swap.LOG_KEY_TABLE and r[1] == 7)

    def _open_under(self, path, hex_key):
        wrapper = _wrapper(hex_key)
        return [credential_keys.unwraps_to(public, wrapped, wrapper)
                for _t, _pk, public, wrapped in self._rows(path)]

    def _under(self, key):
        ctx = override_settings(CREDENTIAL_EPOCH_WRAP_KEY=key)
        ctx.enable()
        self.addCleanup(ctx.disable)
        credential_keys.reset_caches()

    # -- a re-wrap ----------------------------------------------------------

    def test_every_key_moves_to_the_new_key_and_phones_notice_nothing(self):
        before = self._rows(self.live)
        self.assertIn("Re-wrapped 4 key(s).", self._run())
        after = self._rows(self.live)
        self.assertEqual([r[2] for r in after], [r[2] for r in before])   # public halves
        self.assertTrue(all(a[3] != b[3] for a, b in zip(after, before)))
        self.assertEqual(self._open_under(self.live, OTHER_WRAP), [True] * 4)
        self.assertEqual(self._open_under(self.live, WRAP), [False] * 4)

        # The site, on the re-wrapped rows and the new key: a phone syncs, and
        # every log key opens.
        for table, pk, _public, wrapped in after:
            model = (CredentialEpochKey if table == database_swap.EPOCH_TABLE
                     else DeviceLogKey)
            model.objects.filter(pk=pk).update(wrapped_private_key=wrapped)
        self._under(OTHER_WRAP)
        self.assertEqual(self._sync().status_code, 200)
        self.assertEqual(len(device_log.private_keys()), DeviceLogKey.objects.count())

    # -- a database from before the rename to CL03 ---------------------------

    def _as_before_cl03(self, path, keep=0):
        """Each row wrapped as it was before the rename, but the first `keep`.
        The label is spelled out, not taken from the command, so a change to
        the command's constant fails here: the rows it must open are fixed."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        wrapper, aes = _wrapper(WRAP), AESGCM(credential_keys.parse_wrap_key(WRAP))
        for table, pk, _public, wrapped in self._rows(path)[keep:]:
            nonce = os.urandom(12)
            self._edit(path, "UPDATE %s SET wrapped_private_key = ? WHERE id = ?" % table,
                       nonce + aes.encrypt(nonce, wrapper.unwrap(wrapped), b"ov-epoch-key"),
                       pk)

    def test_before_cl03_moves_every_key_and_the_wrap_key_stays(self):
        self._as_before_cl03(self.live)
        before = self._rows(self.live)
        self.assertEqual(self._open_under(self.live, WRAP), [False] * 4)

        out = self._run("--before-cl03", new=False)

        self.assertIn("Re-wrapped 4 key(s).", out)
        self.assertIn(".env stays as it is", out)
        after = self._rows(self.live)
        self.assertEqual([r[2] for r in after], [r[2] for r in before])   # public halves
        self.assertEqual(self._open_under(self.live, WRAP), [True] * 4)

        # The site, on the re-wrapped rows: a phone syncs, and every log key opens.
        for table, pk, _public, wrapped in after:
            model = (CredentialEpochKey if table == database_swap.EPOCH_TABLE
                     else DeviceLogKey)
            model.objects.filter(pk=pk).update(wrapped_private_key=wrapped)
        credential_keys.reset_caches()
        self.assertEqual(self._sync().status_code, 200)
        self.assertEqual(len(device_log.private_keys()), DeviceLogKey.objects.count())

    def test_without_the_flag_a_database_from_before_cl03_is_refused(self):
        self._as_before_cl03(self.live)
        before = self._rows(self.live)
        with self.assertRaisesMessage(CommandError, "--before-cl03"):
            self._run()
        self.assertEqual(self._rows(self.live), before)

    def test_before_cl03_finishes_a_mix_and_can_run_again(self):
        self._as_before_cl03(self.live, keep=1)
        self.assertIn("Re-wrapped 3 key(s), 1 already under the new key.",
                      self._run("--before-cl03", new=False))
        self.assertIn("Nothing to re-wrap", self._run("--before-cl03", new=False))
        self.assertEqual(self._open_under(self.live, WRAP), [True] * 4)

    def test_before_cl03_can_change_the_wrap_key_too(self):
        self._as_before_cl03(self.live)
        out = self._run("--before-cl03")
        self.assertIn("put it in .env", out)
        self.assertEqual(self._open_under(self.live, OTHER_WRAP), [True] * 4)
        self.assertEqual(self._open_under(self.live, WRAP), [False] * 4)

    def test_before_cl03_on_a_dry_run_changes_nothing(self):
        self._as_before_cl03(self.live)
        before = self._rows(self.live)
        self.assertIn("Dry run: 4 key(s) would be re-wrapped.",
                      self._run("--before-cl03", "--dry-run", new=False))
        self.assertEqual(self._rows(self.live), before)

    def test_before_cl03_still_needs_this_site_named(self):
        self._as_before_cl03(self.live)
        before = self._rows(self.live)
        with self.assertRaisesMessage(CommandError, "name this site with --confirm"):
            self._run("--before-cl03", new=False, confirm=None)
        self.assertEqual(self._rows(self.live), before)

    def test_before_cl03_on_a_backup_leaves_the_site_alone(self):
        self._as_before_cl03(self.copy)
        live = self._rows(self.live)
        out = self._run("--before-cl03", "--database", str(self.copy), new=False, confirm=None)
        self.assertIn("can be restored where that key is in use", out)
        self.assertEqual(self._open_under(self.copy, WRAP), [True] * 4)
        self.assertEqual(self._rows(self.live), live)

    def test_nothing_is_wrapped_under_the_earlier_label(self):
        opener = rewrap_keys._BeforeCL03Wrapper(credential_keys.parse_wrap_key(WRAP))
        with self.assertRaises(NotImplementedError):
            opener.wrap(b"x" * 32)

    def test_a_dry_run_changes_nothing(self):
        before = self._rows(self.live)
        self.assertIn("Dry run: 4 key(s) would be re-wrapped. Nothing was changed.",
                      self._run("--dry-run"))
        self.assertEqual(self._rows(self.live), before)

    def test_a_failure_part_way_writes_nothing(self):
        before = self._rows(self.live)
        real, calls = rewrap_keys._write, []

        def write(*args):
            calls.append(args)
            if len(calls) == 3:
                raise RuntimeError("the disk filled up")
            return real(*args)

        with patch.object(rewrap_keys, "_write", write), \
                self.assertRaisesMessage(RuntimeError, "the disk filled up"):
            self._run()
        self.assertEqual(len(calls), 3)
        self.assertEqual(self._rows(self.live), before)

    def test_the_write_lock_comes_before_anything_is_read(self):
        """BEGIN IMMEDIATE, because `select_for_update` is nothing on SQLite:
        nothing else writes between the rows read and the rows written. With
        another connection holding the lock, even a dry run waits, and is
        refused."""
        holder = sqlite3.connect(str(self.live), isolation_level=None)
        holder.execute("BEGIN IMMEDIATE")
        try:
            with patch.object(rewrap_keys, "LOCK_TIMEOUT", 0.1), \
                    self.assertRaisesMessage(CommandError, "could not be read or locked"):
                self._run("--dry-run")
        finally:
            holder.execute("ROLLBACK")
            holder.close()

    def test_a_key_that_does_not_open_again_writes_nothing(self):
        before = self._rows(self.live)
        real, calls = keystore.FileKeyWrapper.unwrap, {"new": 0}

        def unwrap(wrapper, blob):
            if wrapper.key == credential_keys.parse_wrap_key(OTHER_WRAP):
                calls["new"] += 1
                if calls["new"] == 3:
                    return b"\x00" * 32
            return real(wrapper, blob)

        with patch.object(keystore.FileKeyWrapper, "unwrap", unwrap), \
                self.assertRaisesMessage(CommandError, "did not open again"):
            self._run()
        self.assertEqual(self._rows(self.live), before)

    # -- rows that do not open ----------------------------------------------

    def test_one_key_that_opens_with_neither_refuses_the_whole_run(self):
        last = credential_keys.current_epoch() - 1
        for table, where, label in (
                (database_swap.EPOCH_TABLE, "epoch = %d" % last, "epoch key %d public" % last),
                (database_swap.LOG_KEY_TABLE, "id = 7", "log key 7")):
            self.live = self._file("neither-%s.sqlite3" % table)
            self._edit(self.live, "UPDATE %s SET wrapped_private_key = ? WHERE %s"
                       % (table, where), b"\x00" * 60)
            before = self._rows(self.live)
            with self.assertRaisesMessage(CommandError, "open with neither the old "
                                          "key nor the new one: " + label):
                self._run()
            self.assertEqual(self._rows(self.live), before)

    def test_unreadable_rows_can_be_left_as_they_are(self):
        self._edit(self.live, "UPDATE device_log_keys SET wrapped_private_key = ? "
                   "WHERE id = 7", b"\x00" * 60)
        out = self._run("--leave-unreadable")
        self.assertIn("Re-wrapped 3 key(s), 1 left as they were, opening with "
                      "neither key (log key 7).", out)
        self.assertEqual(self._open_under(self.live, OTHER_WRAP).count(True), 3)

    def test_a_key_that_is_not_its_rows_private_half_refuses_too(self):
        db = sqlite3.connect(str(self.live))
        first, second = [bytes(r[0]) for r in db.execute(
            "SELECT public_key FROM credential_epoch_keys ORDER BY id LIMIT 2")]
        db.close()
        self._edit(self.live, "UPDATE credential_epoch_keys SET public_key = ? WHERE "
                   "id = (SELECT MIN(id) FROM credential_epoch_keys)", second)
        before = self._rows(self.live)
        with self.assertRaisesMessage(CommandError, "open with neither"):
            self._run()
        self.assertEqual(self._rows(self.live), before)
        self.assertNotEqual(first, second)

    # -- running again --------------------------------------------------------

    def test_running_again_after_a_finished_run_says_so(self):
        """Not "do not open": after a finished run, a rerun says there is
        nothing to re-wrap, not that every key is unreadable."""
        self._run()
        after = self._rows(self.live)
        self.assertIn("Nothing to re-wrap: every key that opens already opens with "
                      "the new key, 4 already under the new key.", self._run())
        self.assertEqual(self._rows(self.live), after)

    def test_running_again_finishes_a_mix(self):
        """A run that stopped, or keys another process made under the old key
        after it: the rerun re-wraps what is still under the old one."""
        old_wrapped = self._wrapped_log_key_7()
        self._run()
        self._edit(self.live, "UPDATE device_log_keys SET wrapped_private_key = ? "
                   "WHERE id = 7", old_wrapped)
        self.assertIn("Re-wrapped 1 key(s), 3 already under the new key.", self._run())
        self.assertEqual(self._open_under(self.live, OTHER_WRAP), [True] * 4)

    def test_the_site_on_the_new_key_finishes_a_mix_from_the_old_one(self):
        """The same mix, found after .env has the new key: the old key from a
        file, the new from the setting."""
        old_wrapped = self._wrapped_log_key_7()
        self._run()
        self._edit(self.live, "UPDATE device_log_keys SET wrapped_private_key = ? "
                   "WHERE id = 7", old_wrapped)
        self._under(OTHER_WRAP)
        old = self._key_file(WRAP, name="old.key")
        self.assertIn("Re-wrapped 1 key(s), 3 already under the new key.",
                      self._run("--old-key-file", old, new=False))
        self.assertEqual(self._open_under(self.live, OTHER_WRAP), [True] * 4)

    # -- a copy, such as a backup ----------------------------------------------

    def test_a_backup_made_before_is_re_wrapped_to_be_restored(self):
        self._run()
        self._under(OTHER_WRAP)
        # Made under the old key: refused as it is...
        with self.assertRaisesMessage(database_swap.SwapRefused, "do not open"):
            database_swap.plan(self.live, self.copy, now=self.now)
        # ...re-wrapped, without the old key ever in .env again, taken.
        old = self._key_file(WRAP, name="old.key")
        out = self._run("--database", str(self.copy), "--old-key-file", old,
                        new=False, confirm="")
        self.assertIn("Re-wrapped 4 key(s). rewrap-copy.sqlite3 now opens with the "
                      "new key", out)
        database_swap.plan(self.live, self.copy, now=self.now)

    def test_restoring_under_the_old_key_beside_re_wrapped_keys_is_refused(self):
        """The old key put back beside a backup missing this epoch's keys
        would build a mix: those keys, carried in from the site, are under
        the new one."""
        self._run()
        self._edit(self.copy, "DELETE FROM credential_epoch_keys WHERE epoch = ?",
                   credential_keys.current_epoch())
        with self.assertRaisesMessage(database_swap.SwapRefused,
                                      "re-wrapped under another key"):
            database_swap.plan(self.live, self.copy, now=self.now,
                               wrapper=_wrapper(WRAP))

    def test_a_copy_is_not_this_sites_database(self):
        for path, said in ((os.path.join(self.dir, "missing.sqlite3"), "No database at"),
                           (str(self.live), "this site's own database")):
            with self.assertRaisesMessage(CommandError, said):
                self._run("--database", path, confirm="")
        empty = os.path.join(self.dir, "empty.sqlite3")
        db = sqlite3.connect(empty)
        db.execute("CREATE TABLE t (x)")
        db.close()
        with self.assertRaisesMessage(CommandError, "holds no stored keys"):
            self._run("--database", empty, confirm="")

    # -- refused before anything is read --------------------------------------

    def test_this_sites_database_only_named_and_with_nothing_else_holding_it(self):
        before = self._rows(self.live)
        for confirm in ("", "another.example.org", "10.0.0.9"):
            with self.assertRaisesMessage(CommandError, "name this site with --confirm"):
                self._run(confirm=confirm)
        with patch.object(database_swap, "in_use", return_value=[4242]), \
                self.assertRaisesMessage(CommandError, "stop gunicorn first"):
            self._run()
        # A gunicorn that started while the rows were read: refused before
        # anything is written.
        with patch.object(database_swap, "in_use", side_effect=[[], [4242]]), \
                self.assertRaisesMessage(CommandError, "stop gunicorn first"):
            self._run()
        self.assertEqual(self._rows(self.live), before)

    def test_what_is_refused_before_anything_is_read(self):
        import base64

        before = self._rows(self.live)
        same_in_base64 = base64.b64encode(bytes.fromhex(WRAP)).decode()
        cases = (
            (dict(new=self._key_file(WRAP, name="same.key")), "are the same"),
            (dict(new=self._key_file(same_in_base64, name="same64.key")), "are the same"),
            (dict(new=self._key_file("not a key", name="bad.key")), "32 bytes"),
            (dict(new=self._key_file(private=False, name="open.key")),
             "accessible|not only to this account|readable"),
            (dict(new=os.path.join(self.dir, "missing.key")), "No file at"),
            (dict(new=self._key_file(OTHER_WRAP, name="utf16.key", encoding="utf-16")),
             "not plain text"),
            (dict(new=False), "Name the new key"),
        )
        for kwargs, message in cases:
            with self.assertRaisesRegex(CommandError, message):
                self._run(**kwargs)
        with override_settings(CREDENTIAL_EPOCH_WRAP_KEY=""), \
                self.assertRaisesMessage(CommandError, "no CREDENTIAL_EPOCH_WRAP_KEY"):
            self._run()
        self.assertEqual(self._rows(self.live), before)


class StoredKeysCheckTest(_KeysFixture):
    """accounts.W004: every deploy's migrate, and `deploy.sh check`, say when
    the wrap key opens none of a site's keys, as after a re-wrap deployed
    with the wrong value."""

    def _w004(self):
        return [m for m in checks.run_checks(tags=[checks.Tags.database],
                                             databases=["default"])
                if m.id == "accounts.W004"]

    def test_said_only_when_a_key_does_not_open(self):
        credential_keys.issuing_keys()
        device_log.current_key()
        self.assertEqual(self._w004(), [])
        self._other_wrap_key()
        found = self._w004()
        self.assertEqual(len(found), 1)
        self.assertIn("3 stored key(s) do not open", found[0].msg)
        self.assertIn("log key", found[0].msg)
        # No wrap key at all is said elsewhere (credential_keys.missing).
        with override_settings(CREDENTIAL_EPOCH_WRAP_KEY=""):
            credential_keys.reset_caches()
            self.assertEqual(self._w004(), [])


class RewrapKeyDeployTest(TestCase):
    """`deploy/deploy.sh rewrap-key FILE --confirm=HOST`: .env loaded,
    gunicorn stopped, and left stopped once the keys are re-wrapped.
    KitHostKeysTest's site and runner, borrowed."""

    # Through the module: imported by name, its own tests would run here too.
    _kit = tests_operations.KitHostKeysTest
    STUBS, SECRET, GOOD = _kit.STUBS, _kit.SECRET, _kit.GOOD
    HOST_KEY, SERVER = _kit.HOST_KEY, _kit.SERVER
    _bash, _site, _run, _log = _kit._bash, _kit._site, _kit._run, _kit._log

    def test_it_names_the_site_and_the_key_file(self):
        site = self._site(self.GOOD + self.SERVER)
        (site / "new-wrap.key").write_text("cd" * 32 + "\n", encoding="utf-8")
        for args, said in ((["rewrap-key"], "needs the file"),
                           (["rewrap-key", "nothing.key"], "no such file"),
                           (["rewrap-key", "new-wrap.key"], "--confirm=HOST"),
                           (["rewrap-key", "new-wrap.key", "--confirm=other.example"],
                            "is not this site"),
                           (["rewrap-key", "new-wrap.key", "--confirm=localhost"],
                            "by its host name")):
            result = self._run(site, *args)
            self.assertNotEqual(result.returncode, 0, args)
            self.assertIn(said, result.stderr, args)
        self.assertEqual(self._log(site), "")
        result = self._run(site, "rewrap-key", "new-wrap.key", "--confirm=" + SITE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("target:/home/ec2-user/app/new-wrap.key", self._log(site))
        self.assertIn("gunicorn is stopped", result.stdout)

    def _script(self):
        site = self._site(self.GOOD + self.SERVER)
        (site / "new-wrap.key").write_text("cd" * 32 + "\n", encoding="utf-8")
        self._run(site, "rewrap-key", "new-wrap.key", "--confirm=" + SITE)
        return (site / "stubs" / "remote-scripts").read_text(encoding="utf-8")

    def test_the_script_on_the_server(self):
        text = self._script()
        run, log, app = run_remote_script(self, text)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(log[0], "systemctl stop gunicorn")
        self.assertIn("rewrap_keys --new-key-file", log[1])
        self.assertIn("--confirm %s" % SITE, log[1])
        # Re-wrapped: gunicorn stays stopped, the .env here has the old key.
        self.assertEqual(len(log), 2)
        self.assertFalse((app / "new-wrap.key").exists())
        # Refused: nothing changed, and the site serves again.
        run, log, app = run_remote_script(self, text, REWRAP_RC=1)
        self.assertEqual(run.returncode, 3)
        self.assertEqual(log[-1], "systemctl start gunicorn")
        self.assertFalse((app / "new-wrap.key").exists())


class InUseTest(SimpleTestCase):
    """`database_swap.in_use` counts a gunicorn serving this code even with
    the file closed: Django closes its connection after every request, so an
    idle one holds nothing, yet opens the file at its next request. A fake
    /proc: each process's `cwd` is a folder of its own, and `here` names the
    one this code runs from."""

    def test_an_idle_gunicorn_here_counts_and_others_do_not(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        database = root / "db.sqlite3"
        database.write_bytes(b"")

        def process(pid, cmdline):
            entry = root / "proc" / str(pid)
            (entry / "fd").mkdir(parents=True)
            (entry / "cwd").mkdir()
            (entry / "cmdline").write_bytes(cmdline)
            return entry / "cwd"

        here = process(101, b"/app/venv/bin/python\0/app/venv/bin/gunicorn\0verify.wsgi")
        process(102, b"/other/venv/bin/gunicorn\0other.wsgi")      # another site's
        process(103, b"/usr/bin/python3\0manage.py\0shell")        # not gunicorn
        (root / "proc" / "self").mkdir()
        self.assertEqual(database_swap.in_use(database, proc=root / "proc", here=here),
                         [101])
        self.assertEqual(database_swap.in_use(database, proc=root / "nothing"), [])
