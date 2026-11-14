"""Starting the signer, and refusing to, out loud.

Kept out of `__main__` so it can be tested where `pwd` and `grp` do not
exist, as `loop.py` is.

A signer that cannot start takes every mint and every phone sync with it, so
how it refuses matters as much as why:

* `check` loads the policy and seeds it against a copy of the database in
  memory, exactly as a start would, and changes nothing: an operator runs
  it after editing `policy.toml` (`python -m signer check --config ...`),
  before restarting anything.
* A start that is refused -- a configuration that will not load, a ledger
  the bucket is ahead of -- says so once through the alert channel, not once
  per restart: `serve` exits 3 or 2, the unit does not restart on either
  (`RestartPreventExitStatus=`), and a marker beside the database remembers
  what was already said until a start succeeds. Any other failure -- S3 or
  DNS not there yet at boot, a busy disk -- is retried.
* Who may use the admin socket is read on every connection, so taking
  somebody out of `cl03-operators` takes effect at once.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import sys
import tomllib
from pathlib import Path

#: `python -m signer` exit statuses the unit does not restart on.
ROLLBACK = 2
CONFIGURATION = 3

#: Beside the database: the start failure already alerted on.
MARKER = "start-refusal-alerted"


def _configuration_errors():
    from .service import Refused
    # A policy that will not parse or does not say what is needed, a file it
    # names that is not there or not readable, an account or group that does
    # not exist, a held or legacy key that does not match: the operator's to
    # fix, and restarting changes none of it. sqlite3's own errors, and
    # other OSErrors, are not here: those may pass by themselves.
    return (tomllib.TOMLDecodeError, ValueError, KeyError, TypeError,
            FileNotFoundError, PermissionError, Refused)


#: What `serve` treats as a configuration it will not start with (exit 3).
CONFIGURATION_ERRORS = _configuration_errors()


def runtime(path):
    """The `[runtime]` table of the policy file."""
    with open(path, "rb") as handle:
        return tomllib.load(handle).get("runtime", {})


REQUIRED_RUNTIME = ("db", "keys", "admin_socket", "operators_group")
#: What each transport needs besides: the app socket and the one user who
#: may use it, or the site the signer polls (`config.runtime_transport`
#: checks its form). Operators keep the admin socket either way.
REQUIRED_TRANSPORT = {"socket": ("app_socket", "app_user"),
                      "poll": ("site_url",)}
#: What a site with AWS needs besides; one with `ledger_dir` needs none.
REQUIRED_AWS = ("ledger_bucket", "aws_region", "sns_topic")
#: An IAM user's key, as two systemd credentials. A signer beside the app
#: needs both: the app user could reach the instance role through the
#: metadata service. A poll-mode signer, on a host with no app on it, takes
#: both or neither, and with neither boto3's own chain is used -- an EC2
#: instance role (signer/deploy/README.md, "Poll mode").
AWS_CREDENTIALS = ("aws-access-key-id", "aws-secret-access-key")
#: The HMAC key shared with the site, for a poll-mode signer.
POLL_KEY_CREDENTIAL = "poll-key"


def credential_path(name):
    """Where systemd put the credential `name` (LoadCredential=), or None
    when it gave the process no credentials at all."""
    directory = os.environ.get("CREDENTIALS_DIRECTORY")
    return os.path.join(directory, name) if directory else None


def aws_key_files():
    """True when both AWS credentials are given, False when neither is.
    One without the other is a configuration error (ValueError)."""
    present = [name for name in AWS_CREDENTIALS
               if credential_path(name) and os.path.isfile(credential_path(name))]
    if len(present) == 1:
        raise ValueError("the credential %s is given without %s"
                         % (present[0], (set(AWS_CREDENTIALS)
                                         - set(present)).pop()))
    return bool(present)


class _ReadOnlyKeys:
    """The key folder as `check` may touch it: read, never created. A
    folder that is not there yet is an empty one -- the signer makes it at
    its first start -- and a held key named in it is then a missing file,
    as it would be at the start."""

    def __init__(self, directory):
        from .keys import FileKeys
        self._keys = object.__new__(FileKeys)
        self._keys.directory = directory

    def __getattr__(self, name):
        return getattr(self._keys, name)


def check(config_path, *, keys_factory=None, lookup_user=None,
          lookup_group=None):
    """Load the policy and build the service against an in-memory copy of
    the database, as `serve` would. Returns "" when it would start, or why
    it would not. Writes nothing: not the database, not a key."""
    from . import config as cfgmod
    from .clock import Clock
    from .service import SignerService
    from .store import SCHEMA, Store

    try:
        cfg = cfgmod.load(config_path)
        rt = runtime(config_path)
        transport = cfgmod.runtime_transport(rt)
        wanted = (REQUIRED_RUNTIME + REQUIRED_TRANSPORT[transport]
                  + (() if rt.get("ledger_dir") else REQUIRED_AWS))
        missing = [name for name in wanted if not rt.get(name)]
        if missing:
            return "[runtime] does not set %s" % ", ".join(missing)
        if not rt.get("ledger_dir"):
            if transport == cfgmod.POLL:
                aws_key_files()             # both or neither
            elif os.environ.get("CREDENTIALS_DIRECTORY"):
                for name in AWS_CREDENTIALS:
                    if not os.path.isfile(credential_path(name)):
                        return "the credential %s is not there" % name
        if transport == cfgmod.POLL and os.environ.get("CREDENTIALS_DIRECTORY"):
            from . import poll
            poll.read_key(credential_path(POLL_KEY_CREDENTIAL))
        if lookup_user is not None and transport == cfgmod.SOCKET:
            lookup_user(rt["app_user"])
        if lookup_group is not None:
            lookup_group(rt["operators_group"])
            lookup_group(rt.get("app_group", "cl03-signer-app"))
        copy = Store(":memory:")
        if os.path.exists(rt["db"]):
            # Read-only, so not even SQLite's own housekeeping -- a
            # checkpoint, a -wal file left behind -- changes the live one.
            live = sqlite3.connect(Path(rt["db"]).resolve().as_uri() + "?mode=ro",
                                   uri=True, timeout=5)
            try:
                live.backup(copy.db)
            finally:
                live.close()
            # As a start would: this code's tables and columns on the copy.
            copy.db.executescript(SCHEMA)
            copy.upgrade()
        SignerService(copy, (keys_factory or _ReadOnlyKeys)(rt["keys"]), cfg,
                      clock=Clock(), alerts=lambda *_: None)
    except Exception as exc:
        return "%s: %s" % (type(exc).__name__, exc)
    return ""


def state_dir(rt):
    """Where the marker lives: beside the database."""
    return os.path.dirname(os.path.abspath(rt.get("db") or ".")) or "."


def alert_once(rt, message, send):
    """Send `message` as the highest alert unless it is the one already sent
    for this refusal; remember it. `send(severity, message, fields)`."""
    digest = hashlib.sha256(message.encode("utf-8")).hexdigest()
    path = os.path.join(state_dir(rt), MARKER)
    try:
        with open(path, encoding="utf-8") as handle:
            if handle.read().strip() == digest:
                return False
    except OSError:
        pass
    try:
        send("highest", message, {})
    except Exception as exc:              # the journal still has it
        # Not remembered: the next start tries to say it again.
        print("alert not sent: %s" % exc, file=sys.stderr)
        return False
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(digest)
    except OSError:
        pass
    return True


def started(rt):
    """A start got through: the next refusal is news again."""
    try:
        os.remove(os.path.join(state_dir(rt), MARKER))
    except OSError:
        pass


def bare_alerts(rt):
    """An alert channel from the `[runtime]` table alone, for a start that
    fails before the service exists: SNS where the site has it, the journal
    otherwise, and the journal if SNS cannot even be set up."""
    from . import aws
    site = rt.get("site", "verify")
    if rt.get("ledger_dir") or not rt.get("sns_topic"):
        return aws.LogAlerts(site)
    try:
        aws_environment(role_allowed=polls(rt))
        return aws.SnsAlerts(rt["sns_topic"], rt["aws_region"], site)
    except Exception:
        return aws.LogAlerts(site)


def polls(rt) -> bool:
    """Is this a poll-mode signer? False for a `[runtime]` that will not
    load: its start is refused anyway."""
    from . import config as cfgmod
    try:
        return cfgmod.runtime_transport(rt) == cfgmod.POLL
    except Exception:
        return False


def aws_environment(*, role_allowed=False):
    """The IAM user's key from the systemd credentials, into the
    environment boto3 reads first. With neither credential given, a
    poll-mode signer (`role_allowed`) sets nothing and boto3 uses its own
    chain, an EC2 instance role included; a signer beside the app refuses
    (FileNotFoundError). One credential without the other is refused either
    way (ValueError). Both are configuration errors."""
    if not aws_key_files():
        if role_allowed:
            return False
        raise FileNotFoundError("the credential aws-access-key-id is not "
                                "there; a signer beside the app uses an IAM "
                                "user's key, never the instance role")
    for env, name in (("AWS_ACCESS_KEY_ID", "aws-access-key-id"),
                      ("AWS_SECRET_ACCESS_KEY", "aws-secret-access-key")):
        with open(credential_path(name), encoding="utf-8") as handle:
            os.environ[env] = handle.read().strip()
    return True


def operator_check(own_uid, group_name, *, getpwuid=None, getgrnam=None,
                   getgrouplist=None):
    """`is_operator(uid)` for the admin socket: root, the signer itself, or a
    member of `group_name` as the system says NOW, primary group included.
    An account that no longer exists is nobody."""
    if getpwuid is None:
        import grp
        import pwd
        getpwuid, getgrnam, getgrouplist = (pwd.getpwuid, grp.getgrnam,
                                            os.getgrouplist)

    def is_operator(uid):
        if uid in (0, own_uid):
            return True
        try:
            user = getpwuid(uid)
            gid = getgrnam(group_name).gr_gid
        except KeyError:
            return False
        return gid in getgrouplist(user.pw_name, user.pw_gid)

    return is_operator
