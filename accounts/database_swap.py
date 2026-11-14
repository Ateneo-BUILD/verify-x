"""Putting another copy of the database in the live one's place.

Three ways that happens, all through `replace` (`manage.py
replace_database`): a deploy's `--sync-db`, which brings a workstation's
copy; a restore from a backup; and a rollback to the copy taken before a
deploy. Done any other way -- a file copied over the live one while the
site is still serving -- nothing would be kept of what it replaced, and
nothing said about what went with it.

What goes with it is not only data. The database holds keys:

* the epoch keys every document's sealed sections are encrypted to, wrapped
  under CREDENTIAL_EPOCH_WRAP_KEY. A copy made elsewhere carries its own,
  wrapped under another site's key, and every phone sync would fail after
  it. A copy from before an epoch began lacks that epoch's keys, and the
  next mint would make new ones under the same number, leaving every
  document made with the old ones unreadable for good;
* the device log keys, by the same wrap key: an upload sealed to one this
  site cannot open is refused;
* in file mode, the issuer key phones are told to trust: the site signs
  with its key file, and a copy listing another key under that id would
  have every phone reject every document.

So a copy whose keys this site cannot open is refused outright; this site's
keys that the copy lacks are carried into it; and a copy holding different
keys under the same epoch is refused unless the operator says the copy's
keys win. The rest -- phones paired since, documents and revocations
recorded since -- cannot be carried without merging two databases, so it is
reported before anything changes, and the live database is backed up first.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
from datetime import datetime, timezone as dt_timezone
from pathlib import Path

from accounts import credential_keys
from accounts.credentials import CredentialError

EPOCH_TABLE = "credential_epoch_keys"
LOG_KEY_TABLE = "device_log_keys"


def site_names(hosts) -> list:
    """The entries of DJANGO_ALLOWED_HOSTS that name a site: what
    `--confirm` and `--sync-db` must be. Not an address, localhost, a
    wildcard or a leading-dot pattern: a server commonly lists its own
    address and localhost, so those name no site, and accepting them would
    let a command aimed at the wrong address go through."""
    import ipaddress

    names = []
    for host in hosts:
        host = host.strip().lower()
        if not host or host == "*" or host.startswith(".") or host == "localhost":
            continue
        try:
            ipaddress.ip_address(host.strip("[]"))
            continue
        except ValueError:
            names.append(host)
    return names


def live_path() -> Path:
    """The database this site runs on."""
    from django.conf import settings
    return Path(settings.DATABASES["default"]["NAME"])


class SwapRefused(Exception):
    """The copy would break this site; nothing was changed. `reasons` are
    sentences for the operator."""

    def __init__(self, reasons):
        super().__init__("; ".join(reasons))
        self.reasons = list(reasons)


def _open(path, *, readonly=True, immutable=False):
    """`immutable` for a copy nothing else writes: read as it stands, without
    the -wal and -shm a read-only open of a WAL file leaves beside it."""
    query = "?mode=ro&immutable=1" if immutable else "?mode=ro" if readonly else ""
    conn = sqlite3.connect(Path(path).resolve().as_uri() + query, uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def _site_issuer():
    """(key id, SPKI DER) this site signs with from its key file; None with
    a signer, which keeps verify's issuer rows itself, or with no key."""
    from cryptography.hazmat.primitives import serialization
    from django.conf import settings

    if credential_keys.signer_mode() or not settings.CREDENTIAL_ISSUER_KEY_PATH:
        return None
    try:
        backend = credential_keys.signer()
    except CredentialError:
        return None
    return backend.key_id, backend.private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _tables(conn) -> set:
    return {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}


def _columns(conn, table) -> list:
    return [r[1] for r in conn.execute("PRAGMA table_info(%s)" % table)]


def _all(conn, table, tables) -> list:
    return ([dict(r) for r in conn.execute("SELECT * FROM %s" % table)]
            if table in tables else [])


def _ids(conn, sql, tables, table) -> set:
    return {r[0] for r in conn.execute(sql)} if table in tables else set()


def _when(value) -> int:
    """A stored datetime as unix seconds; Django writes ISO text to SQLite."""
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return 0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt_timezone.utc)
    return int(parsed.timestamp())


def plan(live_path, incoming_path, *, now: int, take_incoming_keys=False,
         wrapper=None, issuer=False) -> dict:
    """What putting `incoming_path` in `live_path`'s place would do, changing
    nothing. Raises SwapRefused with every reason it would be refused.
    `issuer` is `_site_issuer()` unless given."""
    if issuer is False:
        issuer = _site_issuer()
    if wrapper is None:
        try:
            wrapper = credential_keys._wrapper()
        except CredentialError:
            # A site that mints nothing: a copy without keys is fine,
            # one with keys cannot be opened here.
            wrapper = None
    refusals = []
    incoming = _open(incoming_path, immutable=True)
    try:
        try:
            check = incoming.execute("PRAGMA integrity_check").fetchone()[0]
        except sqlite3.DatabaseError as exc:
            raise SwapRefused(["the copy is not a database SQLite can read (%s)"
                               % exc])
        if check != "ok":
            raise SwapRefused(["the copy is damaged (%s)" % check])
        theirs = _tables(incoming)
        if "django_migrations" not in theirs or "Users" not in theirs:
            raise SwapRefused(["the copy is not a verify database"])
        their_epochs = {(r["epoch"], r["tier"]): r
                        for r in _all(incoming, EPOCH_TABLE, theirs)}
        their_logs = {r["id"]: r for r in _all(incoming, LOG_KEY_TABLE, theirs)}
        their_devices = _ids(incoming, "SELECT device_id FROM devices",
                             theirs, "devices")
        their_credentials = _ids(
            incoming, "SELECT credential_id FROM issued_credentials",
            theirs, "issued_credentials")
        their_revoked = _ids(
            incoming, "SELECT credential_id FROM issued_credentials WHERE "
            "revoked_at IS NOT NULL", theirs, "issued_credentials") | _ids(
            incoming, "SELECT credential_id FROM revoked_credential_ids",
            theirs, "revoked_credential_ids")
        their_users = incoming.execute('SELECT COUNT(*) FROM "Users"').fetchone()[0]
        their_issuers = {r["key_id"]: bytes(r["spki_der"]) for r in incoming.execute(
            "SELECT key_id, spki_der FROM issuer_keys WHERE is_active = 1")
        } if "issuer_keys" in theirs else {}
        their_transactions = _ids(incoming, "SELECT transaction_id FROM transactions",
                                  theirs, "transactions")
        their_log_entries = _ids(
            incoming, "SELECT device_uuid || ':' || seq FROM device_log_entries",
            theirs, "device_log_entries")
    finally:
        incoming.close()

    if not Path(live_path).exists():
        # A server rebuilt with no database yet: nothing here to lose.
        live = sqlite3.connect(":memory:")
        live.row_factory = sqlite3.Row
    else:
        live = _open(live_path)
    try:
        ours = _tables(live)
        our_epochs = {(r["epoch"], r["tier"]): r
                      for r in _all(live, EPOCH_TABLE, ours)}
        our_logs = {r["id"]: r for r in _all(live, LOG_KEY_TABLE, ours)}
        our_devices = {r["device_id"]: r["label"] for r in live.execute(
            "SELECT device_id, label FROM devices WHERE revoked_at IS NULL")
        } if "devices" in ours else {}
        our_credentials = _ids(live, "SELECT credential_id FROM issued_credentials",
                               ours, "issued_credentials")
        our_revoked = _ids(
            live, "SELECT credential_id FROM issued_credentials WHERE "
            "revoked_at IS NOT NULL", ours, "issued_credentials") | _ids(
            live, "SELECT credential_id FROM revoked_credential_ids",
            ours, "revoked_credential_ids")
        our_users = (live.execute('SELECT COUNT(*) FROM "Users"').fetchone()[0]
                     if "Users" in ours else 0)
        our_transactions = _ids(live, "SELECT transaction_id FROM transactions",
                                ours, "transactions")
        our_log_entries = _ids(
            live, "SELECT device_uuid || ':' || seq FROM device_log_entries",
            ours, "device_log_entries")
    finally:
        live.close()

    # Keys the copy holds that this site cannot open. Epoch keys while phones
    # are still given them, and the current epoch's whatever its row says,
    # since every mint and sync opens those (`credential_keys.issuing_keys`);
    # every log key, since an upload sealed to a retired one must still open
    # (accounts/device_log.py).
    def opens(r):
        return wrapper is not None and credential_keys.unwraps_to(
            r["public_key"], r["wrapped_private_key"], wrapper)

    current = credential_keys.epoch_at(now)
    unreadable = ["epoch %d %s" % (e, "restricted" if t else "public")
                  for (e, t), r in sorted(their_epochs.items())
                  if (e == current or _when(r["not_after"]) >= now) and not opens(r)]
    unreadable += ["device log key %d" % i for i, r in sorted(their_logs.items())
                   if not opens(r)]
    if unreadable and wrapper is None:
        refusals.append(
            "the copy holds keys (%s), and this site has no "
            "CREDENTIAL_EPOCH_WRAP_KEY to open them" % ", ".join(unreadable))
    elif unreadable:
        refusals.append(
            "the copy's keys do not open with this site's "
            "CREDENTIAL_EPOCH_WRAP_KEY (%s): it was made under another wrap "
            "key, and every phone sync would fail" % ", ".join(unreadable))

    differ = ["epoch %d %s" % (e, "restricted" if t else "public")
              for (e, t) in sorted(set(their_epochs) & set(our_epochs))
              if bytes(their_epochs[(e, t)]["public_key"])
              != bytes(our_epochs[(e, t)]["public_key"])]
    differ += ["device log key %d" % i for i in sorted(set(their_logs) & set(our_logs))
               if bytes(their_logs[i]["public_key"]) != bytes(our_logs[i]["public_key"])]
    if differ and not take_incoming_keys:
        refusals.append(
            "the copy holds other keys than this site's under the same names "
            "(%s): what this site sealed with its own would no longer open. "
            "If that is meant, say so with --take-incoming-keys"
            % ", ".join(differ))

    if issuer is not None:
        key_id, spki = issuer
        if their_issuers.get(key_id) != spki:
            refusals.append(
                "the copy %s issuer key %d as this site signs with: phones "
                "would reject every document. Put this site's key in it first "
                "(manage.py load_credential_keys, on a copy of it), or bring "
                "one that has it" % (
                    "lists another" if key_id in their_issuers else "does not list",
                    key_id))

    carry_epochs = [our_epochs[k] for k in sorted(set(our_epochs) - set(their_epochs))]
    carry_logs = [our_logs[i] for i in sorted(set(our_logs) - set(their_logs))]
    if (carry_epochs and EPOCH_TABLE not in theirs) or (
            carry_logs and LOG_KEY_TABLE not in theirs):
        refusals.append("the copy is too old to carry this site's keys into: "
                        "it has no table for them")
    # The keys carried in from this site must open here too, by the copy's
    # rule: a site whose keys were re-wrapped since the copy was made
    # (rewrap_keys), with the old key put back to restore it, would be put
    # together from rows under two keys.
    carried = ["epoch %d %s" % (r["epoch"], "restricted" if r["tier"] else "public")
               for r in carry_epochs
               if (r["epoch"] == current or _when(r["not_after"]) >= now) and not opens(r)]
    carried += ["device log key %d" % r["id"] for r in carry_logs if not opens(r)]
    if carried and wrapper is not None:
        refusals.append(
            "this site's own keys that the copy lacks, and would be carried into "
            "it, do not open with its CREDENTIAL_EPOCH_WRAP_KEY (%s): they were "
            "re-wrapped under another key. Re-wrap the copy to the key they are "
            "under instead (manage.py rewrap_keys --database), and restore it "
            "with that key in place" % ", ".join(carried))
    if refusals:
        raise SwapRefused(refusals)

    lost_devices = sorted(our_devices[d] or "(no name)"
                          for d in set(our_devices) - their_devices)
    return {
        "carry_epochs": carry_epochs,
        "carry_logs": carry_logs,
        "keys_given_up": differ,
        "lost_devices": lost_devices,
        "lost_credentials": len(our_credentials - their_credentials),
        "lost_revocations": len(our_revoked - their_revoked),
        "lost_transactions": len(our_transactions - their_transactions),
        "lost_log_records": len(our_log_entries - their_log_entries),
        "users": (our_users, their_users),
    }


def describe(p: dict) -> list:
    """The plan as sentences, for the command and the deploy log."""
    lines = []
    carried = (["epoch %d %s" % (r["epoch"], "restricted" if r["tier"] else "public")
                for r in p["carry_epochs"]]
               + ["device log key %d" % r["id"] for r in p["carry_logs"]])
    if carried:
        lines.append("This site's keys the copy lacks are carried into it: %s."
                     % ", ".join(carried))
    if p["keys_given_up"]:
        lines.append("The copy's keys replace this site's (%s): what this site "
                     "sealed with its own no longer opens." % ", ".join(p["keys_given_up"]))
    if p["lost_devices"]:
        lines.append("%d phone%s paired here %s not in the copy: %s. Each must "
                     "reset its keys and pair again." % (
                         len(p["lost_devices"]),
                         "" if len(p["lost_devices"]) == 1 else "s",
                         "is" if len(p["lost_devices"]) == 1 else "are",
                         ", ".join(p["lost_devices"][:10])
                         + (", ..." if len(p["lost_devices"]) > 10 else "")))
    if p["lost_credentials"]:
        lines.append("%d document record%s made here %s not in the copy: those "
                     "documents can no longer be revoked from this site."
                     % (p["lost_credentials"],
                        "" if p["lost_credentials"] == 1 else "s",
                        "is" if p["lost_credentials"] == 1 else "are"))
    if p["lost_revocations"]:
        lines.append("%d revocation%s made here %s not in the copy: revoke "
                     "those documents again, or phones that sync read them "
                     "as valid." % (p["lost_revocations"],
                                    "" if p["lost_revocations"] == 1 else "s",
                                    "is" if p["lost_revocations"] == 1 else "are"))
    if p["lost_transactions"]:
        lines.append("%d verification%s made here %s not in the copy: kept "
                     "only in the backup taken now." % (
                         p["lost_transactions"],
                         "" if p["lost_transactions"] == 1 else "s",
                         "is" if p["lost_transactions"] == 1 else "are"))
    if p["lost_log_records"]:
        lines.append("%d phone activity record%s %s not in the copy: phones "
                     "deleted them once this site had them, so they are kept "
                     "only in the backup taken now." % (
                         p["lost_log_records"],
                         "" if p["lost_log_records"] == 1 else "s",
                         "is" if p["lost_log_records"] == 1 else "are"))
    ours, theirs = p["users"]
    lines.append("People: %d here, %d in the copy." % (ours, theirs))
    return lines


def in_use(path, *, proc=Path("/proc"), here=None) -> list:
    """Process ids, other than this one, with `path` open, or serving this
    code as gunicorn. Linux only (/proc); [] where it cannot tell. gunicorn
    still serving would go on writing to the file this replaces, and every
    write would be lost.

    gunicorn counts whether or not it has the file open: Django closes its
    connection after every request (no CONN_MAX_AGE), so an idle gunicorn
    holds nothing, yet would open the file at its next request. Its units
    run it from the code's own folder (WorkingDirectory, `here`)."""
    from django.conf import settings

    target = os.path.realpath(path)
    here = os.path.realpath(here or settings.BASE_DIR)
    if not proc.is_dir():
        return []
    found = []
    for entry in proc.iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            if (b"gunicorn" in (entry / "cmdline").read_bytes()
                    and os.path.realpath(entry / "cwd") == here):
                found.append(int(entry.name))
                continue
        except OSError:
            pass
        try:
            for fd in (entry / "fd").iterdir():
                if os.path.realpath(fd) == target:
                    found.append(int(entry.name))
                    break
        except OSError:
            continue
    return sorted(found)


def _refuse_if_in_use(path):
    users = in_use(path)
    if users:
        raise SwapRefused(["process%s %s still %s the database open: stop "
                           "gunicorn first" % (
                               "" if len(users) == 1 else "es",
                               ", ".join(map(str, users)),
                               "has" if len(users) == 1 else "have")])


def _settle(path):
    """Bring the live file to rest before anything reads it: one read-write
    open, with no other process holding it, rolls back a transaction a crash
    left half done and folds a WAL into the file, and the file leaves WAL
    mode, which is not the application's. A read-only open of a WAL file
    leaves a -wal beside it that no later step could get rid of. An empty
    rollback journal carries nothing and goes."""
    conn = sqlite3.connect(str(path), timeout=5)
    try:
        conn.execute("PRAGMA journal_mode=DELETE").fetchone()
    finally:
        conn.close()
    journal = Path(str(path) + "-journal")
    if journal.exists() and journal.stat().st_size == 0:
        journal.unlink()
    for suffix in ("-wal", "-journal"):
        if Path(str(path) + suffix).exists():
            raise SwapRefused(["%s%s is still beside the database after SQLite "
                               "opened it: look at it before replacing anything"
                               % (path.name, suffix)])


def _backup(source, dest, *, immutable=False):
    src, dst = _open(source, immutable=immutable), sqlite3.connect(str(dest))
    try:
        with dst:
            src.backup(dst)
    finally:
        dst.close()
        src.close()
    os.chmod(dest, 0o600)


def _insert(conn, table, rows, *, keep_id):
    columns = set(_columns(conn, table))
    for row in rows:
        names = [c for c in row if c in columns and (keep_id or c != "id")]
        conn.execute("INSERT INTO %s (%s) VALUES (%s)" % (
            table, ", ".join(names), ", ".join("?" * len(names))),
            [row[c] for c in names])


def replace(live_path, incoming_path, backup_dir, *, now: int,
            take_incoming_keys=False, wrapper=None) -> dict:
    """Back up the live database, then put a checked copy of `incoming_path`
    in its place with this site's missing keys carried in. The incoming file
    itself is left as it was. Returns the plan plus `backup`."""
    live_path, incoming_path = Path(live_path), Path(incoming_path)
    if live_path.resolve() == incoming_path.resolve():
        raise SwapRefused(["the copy is the live database itself"])
    _refuse_if_in_use(live_path)
    if live_path.exists():
        _settle(live_path)
    p = plan(live_path, incoming_path, now=now,
             take_incoming_keys=take_incoming_keys, wrapper=wrapper)

    stamp = datetime.fromtimestamp(now, dt_timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup = None
    if live_path.exists():
        backup_dir = Path(backup_dir)
        backup_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(backup_dir, 0o700)
        backup = backup_dir / ("db-before-replace-%s.sqlite3" % stamp)
        _backup(live_path, backup)

    work = live_path.with_name(live_path.name + ".incoming-" + stamp)
    try:
        _backup(incoming_path, work, immutable=True)
        conn = _open(work, readonly=False)
        try:
            # The application's journal, whatever the copy's was: a WAL file
            # put in place would wedge every later swap.
            conn.execute("PRAGMA journal_mode=DELETE").fetchone()
            with conn:
                _insert(conn, EPOCH_TABLE, p["carry_epochs"], keep_id=False)
                # A log key's id is the key_id in every record sealed to it.
                _insert(conn, LOG_KEY_TABLE, p["carry_logs"], keep_id=True)
            if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise SwapRefused(["the copy with this site's keys carried in "
                                   "failed its integrity check"])
        finally:
            conn.close()
        if live_path.exists():
            # Whoever could open the live file still can open its successor:
            # its mode and group, which a group-run gunicorn needs.
            st = live_path.stat()
            os.chmod(work, stat.S_IMODE(st.st_mode))
            if hasattr(os, "chown"):
                try:
                    os.chown(work, -1, st.st_gid)
                except PermissionError:
                    pass
        # Again at the last moment: a gunicorn systemd restarted meanwhile
        # would write on into the file this replaces.
        _refuse_if_in_use(live_path)
        for suffix in ("-wal", "-journal"):
            if Path(str(live_path) + suffix).exists():
                raise SwapRefused(["%s%s appeared beside the database while "
                                   "the copy was made: something is writing "
                                   "to it. Stop it and try again"
                                   % (live_path.name, suffix)])
        os.replace(work, live_path)
    finally:
        if work.exists():
            work.unlink()
    p["backup"] = str(backup) if backup else ""
    p["backup_sha256"] = (hashlib.sha256(backup.read_bytes()).hexdigest()
                          if backup else "")
    return p
