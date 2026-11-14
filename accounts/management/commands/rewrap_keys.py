"""Re-wrap every stored private key under a new CREDENTIAL_EPOCH_WRAP_KEY.

    python manage.py rewrap_keys --new-key-file NEW --confirm verify.example.org [--dry-run]
    python manage.py rewrap_keys --database COPY --old-key-file OLD [--new-key-file NEW]
    python manage.py rewrap_keys --before-cl03 --confirm verify.example.org [--dry-run]

The epoch keys (`credential_epoch_keys`) and the activity log's keys
(`device_log_keys`) are stored wrapped under the wrap key, so changing it
means wrapping each again under the new one. Phones
notice nothing: they hold the epoch keys wrapped to their own Enclave key,
and no public key changes.

From the old key to the new one. The old is `--old-key-file`, or else this
site's CREDENTIAL_EPOCH_WRAP_KEY; the new is `--new-key-file`, or else the
same setting. One of the two files is needed, and the keys must differ. A
key file holds 64 hex characters or base64 of 32 bytes, as the setting does
(`credential_keys.parse_wrap_key`), and is open to its owner only. A key is
never taken from the command line or the environment, so it is in no
process listing and no shell history.

All or nothing, in one write transaction on the database file (BEGIN
IMMEDIATE; `replace_database` works on the file the same way). A row that
opens with the old key, and is the private half of its own public key, is
wrapped under the new one and opened again with it. A row that already
opens with the new key is left as it is, so running again finishes a run
that stopped, or a mix another process wrote. A row that opens with
neither refuses the run and changes nothing, unless `--leave-unreadable`
says to leave such rows as they are: they open with neither key either way.

This site's database is changed only with `--confirm` naming the site, and
only while no other process holds it open (`database_swap.in_use`): a
gunicorn still running has the old key, and would go on making keys under
it. On a deployed site, `deploy/deploy.sh rewrap-key FILE --confirm=HOST`
runs this with .env loaded and gunicorn stopped, and leaves gunicorn
stopped until a deploy brings the new key. `--database` re-wraps a copy
instead, such as a backup made before the change, so that it can be
restored where the new key is in use.

`--before-cl03` is for a database from before the format was renamed to
CL03. The label in a wrapping's associated data changed
with it (`keystore.WRAP_AAD`), so none of its keys opens on this version, even
under the right wrap key. The flag opens rows under the earlier label and
wraps them under the current one. The wrap key may stay as it is, and then
neither key file is needed. Everything above still holds: all or nothing, safe
to run again, `--confirm`, `--database`, `--dry-run`. It moves stored keys
only: credentials issued before the rename stay unreadable, since their own
format changed too.

A one-off, like BEFORE_CL03_WRAP_AAD below: remove both once no database or
backup from before the rename is wanted.
"""

import os
import sqlite3
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from accounts import credential_keys, database_swap
from accounts.credentials import CredentialError
from ovcrypto import keystore

TABLES = (database_swap.EPOCH_TABLE, database_swap.LOG_KEY_TABLE)

#: Seconds to wait for the write lock, as `database_swap` waits for its file.
LOCK_TIMEOUT = 5

#: The associated data of every wrapping made before the rename to CL03. Here
#: and not in `ovcrypto/`: only `--before-cl03` reads it.
BEFORE_CL03_WRAP_AAD = b"ov-epoch-key"


class _BeforeCL03Wrapper(keystore.FileKeyWrapper):
    """Opens a wrapping made before the rename. Nothing is wrapped this way."""

    def wrap(self, plaintext: bytes) -> bytes:
        raise NotImplementedError("nothing is wrapped under the earlier label")

    def unwrap(self, ciphertext: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        return AESGCM(self.key).decrypt(ciphertext[:12], ciphertext[12:],
                                        BEFORE_CL03_WRAP_AAD)


def _public_half(raw_private: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    return X25519PrivateKey.from_private_bytes(raw_private).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _label(table, row) -> str:
    if table == database_swap.EPOCH_TABLE:
        return "epoch key %d %s" % (row["epoch"], "restricted" if row["tier"] else "public")
    return "log key %d" % row["id"]


def _opens(wrapper, row):
    """The row's raw private key, if it opens under `wrapper` and is the
    private half of the row's own public key; None otherwise."""
    try:
        raw = wrapper.unwrap(bytes(row["wrapped_private_key"]))
        if _public_half(raw) == bytes(row["public_key"]):
            return raw
    except Exception:
        pass
    return None


def _write(conn, table, pk, wrapped):
    """One row's new wrapping: its own function, so a test can fail a run
    part way through and see that nothing was kept."""
    done = conn.execute("UPDATE %s SET wrapped_private_key = ? WHERE id = ?" % table,
                        (wrapped, pk)).rowcount
    if done != 1:
        raise CommandError("%s row %d was not written. Nothing was changed." % (table, pk))


def _read_key_file(path) -> bytes:
    """A wrap key from a file only this account can open."""
    try:
        if os.path.islink(path):
            raise CommandError("%s is a link: name the file itself. Nothing was "
                               "changed." % path)
        keystore._require_private_mode(path)
        if os.name == "posix" and os.stat(path).st_uid != os.getuid():
            raise CommandError("%s belongs to another account. Nothing was "
                               "changed." % path)
        with open(path, encoding="utf-8") as handle:
            return credential_keys.parse_wrap_key(handle.read())
    except FileNotFoundError:
        raise CommandError("No file at %s. Nothing was changed." % path) from None
    except UnicodeDecodeError:
        raise CommandError(
            "%s is not plain text (PowerShell 5 writes UTF-16 with >: use "
            "Set-Content -Encoding ascii). Nothing was changed." % path) from None
    except OSError as exc:
        raise CommandError("%s cannot be read (%s). Nothing was changed."
                           % (path, exc.strerror or exc)) from None
    except (keystore.SigningError, CredentialError) as exc:
        raise CommandError("%s Nothing was changed." % exc) from None


class Command(BaseCommand):
    help = "Re-wrap every stored private key under a new wrap key."

    def add_arguments(self, parser):
        parser.add_argument(
            "--new-key-file", default="",
            help="The key to wrap under, 64 hex characters or base64, in a file "
                 "open to its owner only. Default: this site's "
                 "CREDENTIAL_EPOCH_WRAP_KEY.")
        parser.add_argument(
            "--old-key-file", default="",
            help="The key the rows are wrapped under now, the same way. Default: "
                 "this site's CREDENTIAL_EPOCH_WRAP_KEY.")
        parser.add_argument(
            "--database", default="",
            help="A copy of a database to re-wrap, such as a backup, instead of "
                 "this site's own.")
        parser.add_argument(
            "--confirm", default="",
            help="This site's host name, as in DJANGO_ALLOWED_HOSTS: needed to "
                 "change this site's own database.")
        parser.add_argument(
            "--leave-unreadable", action="store_true",
            help="Leave rows that open with neither key as they are, instead of "
                 "refusing the run.")
        parser.add_argument(
            "--before-cl03", action="store_true",
            help="The database is from before the format was renamed to CL03: open "
                 "its rows under the earlier label. The wrap key may stay the same, "
                 "and then no key file is needed.")
        parser.add_argument(
            "--dry-run", action="store_true",
            help="Check every row and say what would change; change nothing.")

    def handle(self, *args, **options):
        before_cl03 = options["before_cl03"]
        if not (before_cl03 or options["old_key_file"] or options["new_key_file"]):
            raise CommandError(
                "Name the new key with --new-key-file, or the key a copy was "
                "made under with --old-key-file. Nothing was changed.")
        live = database_swap.live_path()
        own = not options["database"]
        if own:
            path = live
            names = database_swap.site_names(settings.ALLOWED_HOSTS)
            if options["confirm"].lower() not in names:
                raise CommandError(
                    "name this site with --confirm: its host name (%s). Nothing "
                    "was changed." % (", ".join(names) or "none"))
            self._refuse_if_in_use(path)
        else:
            path = Path(options["database"])
            if not path.is_file():
                raise CommandError("No database at %s. Nothing was changed." % path)
            if live.exists() and os.path.samefile(path, live):
                raise CommandError(
                    "%s is this site's own database: leave out --database and "
                    "name the site with --confirm. Nothing was changed." % path)

        old = self._key(options["old_key_file"], "old")
        new = self._key(options["new_key_file"], "new")
        same_key = old == new
        if same_key and not before_cl03:
            raise CommandError("The old key and the new key are the same. "
                               "Nothing was changed.")
        opener = _BeforeCL03Wrapper if before_cl03 else keystore.FileKeyWrapper
        rewrapped, already, left = self._rewrap(
            path, opener(old), keystore.FileKeyWrapper(new),
            own=own, dry_run=options["dry_run"],
            leave_unreadable=options["leave_unreadable"])

        also = "".join([
            ", %d already under the new key" % len(already) if already else "",
            ", %d left as they were, opening with neither key (%s)"
            % (len(left), ", ".join(left)) if left else ""])
        if options["dry_run"]:
            self.stdout.write("Dry run: %d key(s) would be re-wrapped%s. Nothing "
                              "was changed." % (len(rewrapped), also))
            return
        if rewrapped:
            credential_keys.logger.warning(
                "rewrap_keys: %d stored key(s) in %s re-wrapped %s",
                len(rewrapped), "this site's database" if own else path.name,
                "from before CL03" if before_cl03 else "under a new wrap key")
        done = ("Re-wrapped %d key(s)%s." % (len(rewrapped), also) if rewrapped
                else "Nothing to re-wrap: every key that opens already opens with "
                     "the new key%s." % also)
        if same_key:
            self.stdout.write(
                done + " The wrap key has not changed, so %s"
                % ("this site's .env stays as it is, and gunicorn can start again."
                   if own else "%s can be restored where that key is in use." % path.name))
        elif own:
            self.stdout.write(
                done + " This site's keys now open with the new key only: put it "
                "in .env as CREDENTIAL_EPOCH_WRAP_KEY, and in the site's "
                "configuration file where deploy.sh writes .env from one, before "
                "gunicorn starts again. Keep the new key's file until the site "
                "runs on it and Setup shows no key in red, and the old key for "
                "the backups made before this.")
        else:
            self.stdout.write(
                done + " %s now opens with the new key, and can be restored where "
                "that key is in use." % path.name)

    def _key(self, path, which) -> bytes:
        if path:
            return _read_key_file(path)
        if not settings.CREDENTIAL_EPOCH_WRAP_KEY:
            raise CommandError(
                "This site has no CREDENTIAL_EPOCH_WRAP_KEY: name the %s key with "
                "--%s-key-file. Nothing was changed." % (which, which))
        try:
            return credential_keys.parse_wrap_key(settings.CREDENTIAL_EPOCH_WRAP_KEY)
        except CredentialError as exc:
            raise CommandError("%s Nothing was changed." % exc) from None

    def _refuse_if_in_use(self, path):
        try:
            database_swap._refuse_if_in_use(path)
        except database_swap.SwapRefused as exc:
            raise CommandError("%s. Nothing was changed." % exc) from None

    def _rewrap(self, path, old, new, *, own, dry_run, leave_unreadable):
        conn = sqlite3.connect(str(path), timeout=LOCK_TIMEOUT, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            # The write lock first, for the whole run: no other connection
            # writes between the rows read and the rows written.
            conn.execute("BEGIN IMMEDIATE")
            try:
                tables = database_swap._tables(conn)
                if database_swap.EPOCH_TABLE not in tables:
                    raise CommandError("%s holds no stored keys: it is not a verify "
                                       "database. Nothing was changed." % path.name)
                todo, already, unreadable = [], [], []
                for table in TABLES:
                    if table not in tables:
                        continue
                    for row in conn.execute("SELECT * FROM %s ORDER BY id" % table):
                        label = _label(table, row)
                        raw = _opens(old, row)
                        if raw is None:
                            (already if _opens(new, row) is not None
                             else unreadable).append(label)
                            continue
                        wrapped = new.wrap(raw)
                        if new.unwrap(wrapped) != raw:
                            raise CommandError("%s did not open again under the new "
                                               "key. Nothing was changed." % label)
                        todo.append((table, row["id"], wrapped, label))
                if unreadable and not leave_unreadable:
                    raise CommandError(
                        "%d stored key(s) open with neither the old key nor the new "
                        "one: %s. Is the old key the one they were made under? Is "
                        "this database from before the rename to CL03 (then "
                        "--before-cl03)? Nothing was changed. If they are known to "
                        "be lost, "
                        "--leave-unreadable re-wraps the rest and leaves them as "
                        "they are." % (len(unreadable), ", ".join(unreadable)))
                if own:
                    # Again, just before writing: a gunicorn started meanwhile
                    # would make its next keys under the old key.
                    self._refuse_if_in_use(path)
                if dry_run:
                    conn.execute("ROLLBACK")
                    return [t[3] for t in todo], already, unreadable
                for table, pk, wrapped, _named in todo:
                    _write(conn, table, pk, wrapped)
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
        except sqlite3.DatabaseError as exc:
            raise CommandError("%s could not be read or locked for writing (%s): "
                               "is another process using it? Nothing was changed."
                               % (path.name, exc)) from None
        finally:
            conn.close()
        return [t[3] for t in todo], already, unreadable
