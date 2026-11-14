"""`python -m signer serve|reconcile`, as the systemd units run it.

    python -m signer serve --config /etc/cl03-signer/policy.toml
    python -m signer reconcile --config /etc/cl03-signer/policy.toml
    python -m signer check --config /etc/cl03-signer/policy.toml

`check` is what to run after editing the policy, before restarting: it loads
it as a start would and changes nothing (`signer/startup.py`).

    python -m signer adopt --config /etc/cl03-signer/policy.toml

`adopt` makes a rebuilt host's empty database again from its shipped
ledger, with the signer stopped (`signer/adopt.py`).

The runtime section of the policy file names the paths, the sockets and the
AWS resources (`signer/deploy/policy.example.toml`), and how verify reaches
the signer: its app socket on this host (`transport = "socket"`, the
default), or this process dialling out to the site and long-polling it for
jobs (`transport = "poll"`, `signer/poll.py`). The admin socket is opened
either way.
"""

from __future__ import annotations

import argparse
import grp
import json
import os
import pwd
import signal
import sys
import threading
import time

from . import (adopt, aws, config as cfgmod, loop, poll, reconcile, startup,
               watch)
from .clock import Clock
from .keys import FileKeys
from .service import SignerService
from .store import Store
from .transport import Dispatcher, SocketServer


_runtime = startup.runtime

#: Seconds `serve` waits, once stopped, for a poll in flight and the
#: answers in hand, before its last ship. Inside systemd's 90 s.
POLL_STOP_SECONDS = 45


def _secret(name):
    """A systemd credential (LoadCredential=), never the environment."""
    directory = os.environ.get("CREDENTIALS_DIRECTORY", "")
    with open(os.path.join(directory, name), encoding="utf-8") as handle:
        return handle.read().strip()


def _uploader(rt):
    """(uploader, alerts, prefix) for this site."""
    site = rt.get("site", "verify")
    if rt.get("ledger_dir"):
        # A development site with no AWS: the ledger in a folder, alerts in
        # the journal, no heartbeat (signer/deploy/README.md, "A development site").
        return (aws.LocalUploader(rt["ledger_dir"]), aws.LogAlerts(site),
                rt.get("ledger_prefix", site))
    # The IAM user's key; for a poll-mode signer, on a host with no app,
    # boto3's own chain (an instance role) where neither credential is given
    # (README.md, "Poll mode").
    startup.aws_environment(role_allowed=startup.polls(rt))
    return (aws.S3Uploader(rt["ledger_bucket"], rt["aws_region"]),
            aws.SnsAlerts(rt["sns_topic"], rt["aws_region"], site),
            rt.get("ledger_prefix", site))


def _build(args, *, rollback_first=False):
    """Everything a start needs. With `rollback_first`, a ledger behind what
    was shipped is refused (`aws.Rollback`) before anything is written: the
    seeding below writes key events, and on a rebuilt host's empty database
    those would make it unadoptable."""
    cfg = cfgmod.load(args.config)
    rt = _runtime(args.config)
    store = Store(rt["db"])
    clock = Clock()
    uploader, alerts, prefix = _uploader(rt)
    shipper = aws.Shipper(store, uploader, prefix, clock,
                          retain_days=cfgmod.runtime_retain_days(rt))
    if rollback_first:
        shipper.check_rollback()
    service = SignerService(store, FileKeys(rt["keys"]), cfg, clock=clock,
                            alerts=alerts)
    return cfg, rt, store, service, shipper, alerts


def _refuse(rt, message, status):
    """Say why the signer will not start, once (`startup.alert_once`), and
    exit with a status the unit does not restart on."""
    print(message, file=sys.stderr)
    startup.alert_once(rt, message, startup.bare_alerts(rt))
    return status


def serve(args):
    try:
        cfg, rt, store, service, shipper, alerts = _build(
            args, rollback_first=True)
        transport = cfgmod.runtime_transport(rt)
        if transport == cfgmod.POLL:
            # No app socket and no app user on this host: the site is
            # reached over HTTPS with the shared key (signer/poll.py).
            key = poll.read_key(
                startup.credential_path(startup.POLL_KEY_CREDENTIAL))
        else:
            app_uid = pwd.getpwnam(rt["app_user"]).pw_uid
            app_gid = grp.getgrnam(rt.get("app_group", "cl03-signer-app")).gr_gid
        operators_gid = grp.getgrnam(rt["operators_group"]).gr_gid
    except aws.Rollback as exc:
        # One alert, not one every five seconds.
        return _refuse(_runtime(args.config), "refusing to start: %s" % exc,
                       startup.ROLLBACK)
    except startup.CONFIGURATION_ERRORS as exc:
        # A typo in the policy is one alert, and the signer stays down
        # rather than restarting in silence. A fault that is not the
        # configuration's -- a busy or full disk -- raises, and the unit
        # tries again.
        try:
            rt = _runtime(args.config)
        except Exception:
            rt = {}
        return _refuse(rt, "refusing to start: the configuration: %s: %s"
                       % (type(exc).__name__, exc), startup.CONFIGURATION)

    own = os.getuid()
    # Membership as it is at each connection, not as it was at start.
    is_operator = startup.operator_check(own, rt["operators_group"])

    lock = threading.Lock()

    def ship(_op=None):
        with lock:
            shipper.ship()

    # On `systemctl stop` -- before the host is imaged, say -- the loop
    # ships what is left, so an image and the bucket agree on the ledger's
    # head. The handler only sets the event (`loop.py`).
    stop, handler = loop.stopper()
    dispatcher = Dispatcher(service, after_event=ship)
    startup.started(rt)
    servers = []
    if transport == cfgmod.SOCKET:
        app = SocketServer(rt["app_socket"], dispatcher, admin=False,
                           allowed=lambda uid: uid == app_uid)
        # Each socket goes to a group of its own. The signer may only hand a
        # file to a group it is in (`SupplementaryGroups=` in
        # cl03-signer.service), and the app user's own group would also give
        # it the app's files.
        os.chmod(rt["app_socket"], 0o660)
        os.chown(rt["app_socket"], own, app_gid)
        servers.append(app)
    admin = SocketServer(rt["admin_socket"], dispatcher, admin=True,
                         allowed=is_operator)
    os.chmod(rt["admin_socket"], 0o660)
    os.chown(rt["admin_socket"], own, operators_gid)
    servers.append(admin)
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    polling = None
    if transport == cfgmod.POLL:
        # Jobs are answered by the same dispatcher, as the app socket's are;
        # its alerts go to the ledger and out like every other. The site
        # knows this signer by an id kept in its database (`instance_id`).
        site = poll.SiteClient(rt["site_url"], key,
                               instance=poll.instance_id(store))
        poller = poll.Poller(site, dispatcher, alert=service.notice, stop=stop)
        dispatcher.status_extra["poll"] = poller.state
        polling = threading.Thread(target=poller.run, name="cl03-poll",
                                   daemon=True)
        polling.start()

    signal.signal(signal.SIGTERM, handler)

    heartbeat = (aws.NoHeartbeat() if rt.get("ledger_dir") else
                 aws.Heartbeat(rt.get("metric_namespace", "CL03Signer"),
                               rt["aws_region"], rt.get("site", "verify")))
    try:
        import systemd.daemon  # optional
        systemd.daemon.notify("READY=1")
    except Exception:
        pass
    loop.periodic(
        ship, lambda: heartbeat.beat(len(store.all("SELECT 1 FROM pauses")),
                                     failing=dispatcher.failing),
        stop, int(rt.get("ship_every_seconds", 300)))
    if polling is not None:
        # The poll in flight may still hand over jobs, claimed already:
        # answer them, then ship what they wrote.
        polling.join(POLL_STOP_SECONDS)
        try:
            ship()
        except Exception as exc:
            print("final ship failed: %s" % exc, file=sys.stderr)
    return 0


def run_reconcile(args):
    try:
        cfg, rt, store, service, shipper, alerts = _build(
            args, rollback_first=True)
    except aws.Rollback as exc:
        # serve refuses and alerts on this. The timer only keeps out of the
        # database: seeding it would leave a rebuilt host's no longer empty,
        # and `adopt` needs it empty.
        print("not reconciling: %s" % exc, file=sys.stderr)
        return startup.ROLLBACK
    token = _secret("report-token")

    def fetch(since):
        # Inside the run: a policy naming no report is a report unavailable,
        # counted and alerted on, and the warnings below still go out.
        url, host = reconcile.report_target(rt)
        return reconcile.fetch_report(url, host, token, since)

    try:
        reconcile.run(store, fetch, alerts, now=int(time.time()))
    finally:
        # The warnings and the daily summary go out whatever the report
        # did.
        watch.run(store, cfg, alerts, now=int(time.time()))
    return 0


def adopt_ledger(args):
    """`python -m signer adopt`: a rebuilt host's empty database made again
    from the shipped ledger (`signer/adopt.py`)."""
    try:
        cfg = cfgmod.load(args.config)
        rt = _runtime(args.config)
        uploader, _, prefix = _uploader(rt)
        report = adopt.adopt(Store(rt["db"]), cfg, FileKeys(rt["keys"]),
                             uploader, prefix, now=int(time.time()))
    except (adopt.AdoptError,) + startup.CONFIGURATION_ERRORS as exc:
        print("adopt refused: %s" % exc, file=sys.stderr)
        return startup.CONFIGURATION
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def check(args):
    """Exit 0 if the signer would start with this policy, or CONFIGURATION
    with the reason. Changes nothing."""
    why = startup.check(args.config, lookup_user=pwd.getpwnam,
                        lookup_group=grp.getgrnam)
    if why:
        print("cl03-signer would not start: %s" % why, file=sys.stderr)
        return startup.CONFIGURATION
    print("cl03-signer check: the policy loads and the keys match")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m signer")
    parser.add_argument("command", choices=("serve", "reconcile", "check",
                                            "adopt"))
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    return {"serve": serve, "reconcile": run_reconcile, "check": check,
            "adopt": adopt_ledger}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
