"""Pre-load the signing and epoch keys from an OfflineVerifier deployment.

Credentials this app mints are opened by phones enrolled with THAT deployment.
Two things therefore cannot be chosen independently here, and this command
exists to copy them across rather than have somebody retype them:

* the ISSUER key, whose public half is already in the trust list those phones
  carry. Sign with a different one and every credential reads as `forged`.
* the EPOCH POLICY, which turns a timestamp into the epoch number a credential
  is permanently bound to. A different genesis silently renumbers everything,
  and a phone then reports `device_stale` for a perfectly good document.

It refuses rather than guesses. A registered public key that does not match
the PEM is the failure with no symptom until a checkpoint rejects a document,
so it is checked here, where it is cheap.

    python manage.py load_credential_keys --from ../OfflineVerifier \\
        --key-path ~/secrets/verify-issuer.pem
"""

import base64
import os
import shutil
import sqlite3
import stat
from datetime import datetime, timedelta, timezone as dt_timezone

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from ovcrypto import keystore

from accounts import credential_keys
from accounts.models import CredentialEpochKey


def _read_env(path):
    """The subset of a .env this command cares about. Not a general parser."""
    values = {}
    if not os.path.exists(path):
        return values
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _as_utc(value):
    """A timestamp out of their SQLite, read as UTC.

    Their rows hold the schedule in UTC, written naive. Stored through Django
    with USE_TZ on, a naive value is interpreted in the LOCAL zone -- which on
    a box set to Asia/Manila moved every imported epoch window eight hours
    earlier than the schedule it is supposed to mirror. The epoch NUMBER is
    computed from the genesis and is unaffected, so nothing reads as forged;
    the damage is that this app would stop shipping an epoch key eight hours
    before it truly expires, which surfaces as a document that stopped opening
    for no reason anybody can see.
    """
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt_timezone.utc)
    return parsed


def _wrap_key_bytes(raw, where):
    """A 32-byte wrapping key from hex or base64."""
    raw = raw.strip()
    if len(raw) == 64:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass
    try:
        decoded = base64.b64decode(raw, validate=True)
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass
    raise CommandError(
        "%s is not a 32-byte key: expected 64 hex characters or base64."
        % where)


class Command(BaseCommand):
    help = "Copy the issuer key and epoch policy from an OfflineVerifier tree."

    def add_arguments(self, parser):
        parser.add_argument("--from", dest="source", required=True,
                            help="Path to the OfflineVerifier project.")
        parser.add_argument("--key-path", dest="key_path", default="",
                            help="Where to write the issuer PEM. Defaults to "
                                 "CREDENTIAL_ISSUER_KEY_PATH.")
        parser.add_argument("--dry-run", action="store_true",
                            help="Report what would happen and change nothing.")
        parser.add_argument("--epochs-only", action="store_true",
                            help="Import the epoch keys and check the policy, "
                                 "but leave the issuer key alone. The only "
                                 "mode allowed once a signer holds it.")

    def handle(self, *args, **options):
        source = os.path.abspath(os.path.expanduser(options["source"]))
        dry = options["dry_run"]
        epochs_only = options["epochs_only"]
        if not os.path.isdir(source):
            raise CommandError("No such directory: %s" % source)
        if credential_keys.signer_mode() and not epochs_only:
            # The signer holds the issuer keys and builds the trust list; a
            # PEM copied in here would be a second key nobody publishes, and an
            # IssuerKey row written here would contradict the signer's mirror.
            raise CommandError(
                "SIGNER_SOCKET or SIGNER_QUEUE_KEY is set: the signer holds "
                "the issuer key. Use --epochs-only to import epoch keys.")

        env = _read_env(os.path.join(source, ".env"))
        if not env:
            raise CommandError(
                "No readable .env in %s -- that file holds the epoch policy "
                "and the wrapping key, and nothing can be aligned without it."
                % source)

        self._check_policy(env)
        if not epochs_only:
            key_id = int(env.get("OV_ISSUER_KEY_ID", "1"))
            pem = self._copy_issuer_key(source, env, options["key_path"],
                                        key_id, dry)
            self._verify_against_registration(source, pem, key_id, dry)
        self._import_epoch_keys(source, env, dry)

        self.stdout.write(self.style.SUCCESS(
            "Aligned with %s." % source if not dry
            else "Dry run: nothing written."))

    # -- policy -----------------------------------------------------------

    def _check_policy(self, env):
        """Refuse on a mismatch. Do not silently adopt: the numbers are in
        this app's settings so they are reviewable, and a command that
        rewrote them would make a deploy able to change them by accident."""
        expected = {
            "OV_GENESIS": settings.CREDENTIAL_GENESIS,
            "OV_EPOCH_SECONDS": settings.CREDENTIAL_EPOCH_SECONDS,
            "OV_OVERLAP_EPOCHS": settings.CREDENTIAL_OVERLAP_EPOCHS,
        }
        wrong = []
        for name, ours in expected.items():
            theirs = env.get(name)
            if theirs is None:
                continue
            if int(theirs) != ours:
                wrong.append("  %-18s theirs %s, ours %s" % (name, theirs, ours))
        if wrong:
            raise CommandError(
                "Epoch policy does not match, so epoch numbers would not "
                "agree and phones would report device_stale for good "
                "documents:\n" + "\n".join(wrong)
                + "\n\nSet these in this app's environment to match, and do "
                  "NOT change them once anything has been issued.")
        self.stdout.write("epoch policy matches (genesis %d, %d-day epochs, "
                          "%d overlap)"
                          % (settings.CREDENTIAL_GENESIS,
                             settings.CREDENTIAL_EPOCH_SECONDS // 86400,
                             settings.CREDENTIAL_OVERLAP_EPOCHS))

    # -- the issuer key ---------------------------------------------------

    def _copy_issuer_key(self, source, env, key_path, key_id, dry):
        their_pem = env.get("OV_DEV_SIGNING_KEY_PEM", "")
        if their_pem:
            their_pem = os.path.join(source, their_pem) \
                if not os.path.isabs(their_pem) else their_pem
        else:
            their_pem = os.path.join(source, "dev-issuer-key.pem")
        if not os.path.exists(their_pem):
            raise CommandError(
                "No issuer PEM at %s. In that project it is created by "
                "`register_issuer_key --create-dev-key`; in production the "
                "private half is on a PKCS#11 token and cannot be copied at "
                "all -- this command is for a shared development key."
                % their_pem)

        target = key_path or settings.CREDENTIAL_ISSUER_KEY_PATH
        if not target:
            raise CommandError(
                "Nowhere to put it: pass --key-path or set "
                "CREDENTIAL_ISSUER_KEY_PATH. Choose a path OUTSIDE this "
                "application directory -- deploy.sh rsyncs it with --delete.")
        target = os.path.abspath(os.path.expanduser(target))

        # commonpath raises across Windows drives, which is exactly the case
        # where the answer is obviously "not inside".
        try:
            inside = os.path.commonpath(
                [target, str(settings.BASE_DIR)]) == str(settings.BASE_DIR)
        except ValueError:
            inside = False
        if inside:
            self.stdout.write(self.style.WARNING(
                "  the key path is inside the application directory; a deploy "
                "will delete it. Move it out before this is anything but a "
                "development setup."))

        if dry:
            self.stdout.write("would copy %s -> %s" % (their_pem, target))
            return their_pem

        os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
        shutil.copyfile(their_pem, target)
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
        self.stdout.write("issuer key  -> %s (key_id %d, mode 0600)"
                          % (target, key_id))
        return target

    def _verify_against_registration(self, source, pem_path, key_id, dry):
        """The PEM must be the key the fleet's trust list already names.

        This is the check worth having: a mismatch has no symptom until a
        credential is rejected at a checkpoint, by which time it is printed.
        """
        from cryptography.hazmat.primitives import serialization

        db = os.path.join(source, "db.sqlite3")
        if not os.path.exists(db):
            self.stdout.write(self.style.WARNING(
                "  no db.sqlite3 there, so the registered public key could "
                "not be checked against the PEM"))
            return
        with open(pem_path, "rb") as handle:
            key = serialization.load_pem_private_key(handle.read(),
                                                     password=None)
        ours = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)

        connection = sqlite3.connect(db)
        try:
            row = connection.execute(
                "select spki_der from keys_issuerkey "
                "where key_id = ? and is_active = 1", (key_id,)).fetchone()
        except sqlite3.Error as exc:
            self.stdout.write(self.style.WARNING(
                "  could not read the issuer registration: %s" % exc))
            return
        finally:
            connection.close()

        if row is None:
            raise CommandError(
                "No active issuer key with key_id=%d is registered there. "
                "Phones would not have this key in their trust list, so every "
                "credential signed with it reads as forged." % key_id)
        if bytes(row[0]) != ours:
            raise CommandError(
                "The registered public key for key_id=%d is NOT this PEM. "
                "Signing with it would produce credentials that fail at a "
                "checkpoint with no earlier symptom." % key_id)
        self.stdout.write("registration matches the PEM (key_id %d)" % key_id)
        if dry:
            # "Dry run: nothing written" has to be true, or the next person
            # to reach for --dry-run on a live box is misled by this one.
            self.stdout.write("would record the trust entry for issuer key "
                              "%d" % key_id)
            return
        self._record_issuer_key(source, key_id, ours)

    def _record_issuer_key(self, source, key_id, spki):
        """Copy the trust-list entry too, with its validity window.

        A device is told which keys to trust and for how long; without this
        row a bundle would carry an empty trust list, and a phone that trusts
        nothing rejects every credential as forged.
        """
        from datetime import datetime, timezone as dt_timezone

        from accounts.models import IssuerKey

        connection = sqlite3.connect(os.path.join(source, "db.sqlite3"))
        try:
            row = connection.execute(
                "select not_before, not_after from keys_issuerkey "
                "where key_id = ? and is_active = 1", (key_id,)).fetchone()
        except sqlite3.Error:
            # An older schema, or a trimmed one. The key itself is what
            # matters; a default window beats abandoning the import.
            row = None
        finally:
            connection.close()

        def _when(value, fallback_days):
            if value:
                try:
                    parsed = datetime.fromisoformat(str(value))
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=dt_timezone.utc)
                    return parsed
                except ValueError:
                    pass
            return datetime.now(dt_timezone.utc) + timedelta(
                days=fallback_days)

        IssuerKey.objects.update_or_create(
            key_id=key_id,
            defaults={"spki_der": spki, "is_active": True,
                      "not_before": _when(row[0] if row else None, -1),
                      "not_after": _when(row[1] if row else None, 730)})
        self.stdout.write("trust entry -> issuer key %d recorded" % key_id)

    # -- epoch keys -------------------------------------------------------

    def _import_epoch_keys(self, source, env, dry):
        db = os.path.join(source, "db.sqlite3")
        if not os.path.exists(db):
            return
        connection = sqlite3.connect(db)
        try:
            rows = connection.execute(
                "select epoch, tier, public_key, wrapped_private_key, "
                "not_before, not_after from keys_epochkey "
                "order by epoch, tier").fetchall()
        except sqlite3.Error:
            rows = []
        finally:
            connection.close()

        if not rows:
            self.stdout.write(
                "no epoch keys there yet -- they are created on demand, and "
                "this app will create them under the same policy, so the "
                "numbering still agrees")
            return

        their_wrap = env.get("OV_EPOCH_WRAP_KEY", "")
        if not their_wrap:
            raise CommandError(
                "%d epoch keys to import, but OV_EPOCH_WRAP_KEY is not in "
                "their .env, so the private halves cannot be unwrapped."
                % len(rows))
        theirs = keystore.FileKeyWrapper(
            _wrap_key_bytes(their_wrap, "their OV_EPOCH_WRAP_KEY"))

        from accounts import credential_keys

        imported = skipped = 0
        for epoch, tier, public, wrapped, not_before, not_after in rows:
            if CredentialEpochKey.objects.filter(epoch=epoch,
                                                 tier=tier).exists():
                skipped += 1
                continue
            raw_private = theirs.unwrap(bytes(wrapped))
            if dry:
                imported += 1
                continue
            CredentialEpochKey.objects.create(
                epoch=epoch, tier=tier, public_key=bytes(public),
                wrapped_private_key=credential_keys._wrapper().wrap(
                    raw_private),
                not_before=_as_utc(not_before), not_after=_as_utc(not_after))
            imported += 1
        self.stdout.write("epoch keys  -> %d imported, %d already present"
                          % (imported, skipped))
