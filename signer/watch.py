"""Warnings before anything runs out, and the daily summary.

Run by the reconcile timer after each reconciliation (`python -m signer
reconcile`), through the same alert channel: SNS email, or the journal on a
site with no AWS.

- A key that signs: at 120, 90, 45 and 14 days before its window ends, and
  once it has ended. The deployment key's bundles stop then too.
- The Organization CA: the same days before the last moment it can certify a
  key that leaves `min_signing_days` of signing (`registry.issue_until`).
- The issuing CA in the anchors: two years and one year before it ends, since
  its successor has to ship in an app build first.
- The summary, once a day: the ledger's newest hash -- a witness to the chain
  outside this host -- what was signed, which keys sign until when, pauses,
  and the alerts of the day.

Each warning is sent once per threshold (a `meta` row), the most urgent one
due only, so a timer that was off for months sends one, not four.
"""

from __future__ import annotations

import time
from collections import Counter

from . import registry

DAY = 86400

#: (days before the end, severity, what to do then).
KEY_STEPS = ((120, "medium", "request the next certificates"),
             (90, "medium", "install and publish its successor"),
             (45, "medium", "switch to its successor"),
             (14, "high", "switch to its successor now"))
ANCHOR_STEPS = ((730, "medium", "plan its successor: it ships in an app "
                 "build first"),
                (365, "high", "its successor must ship in an app build now"))
SUMMARY_EVERY = DAY - 900       # the timer runs every 15 minutes


def _day(ts) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(int(ts)))


def _due(steps, end, now):
    """The most urgent step reached before `end`, as (threshold, severity,
    action), the end itself as (0, "high", ...), or None."""
    left = end - now
    if left <= 0:
        return 0, "high", "it has ended"
    reached = [s for s in steps if left <= s[0] * DAY]
    return min(reached, key=lambda s: s[0]) if reached else None


def _warning(store, subject, end, step, message, fields, now):
    """(severity, message, fields, meta name) if this step was not sent."""
    threshold, severity, action = step
    name = "warned:%s:%d:%d" % (subject, end, threshold)
    if store.meta(name) is not None:
        return None
    return (severity, "%s; %s" % (message, action),
            dict(fields, ends=end, days_left=max(0, (end - now) // DAY)), name)


def _key_warnings(store, cfg, now):
    out = []
    for row in store.all("SELECT * FROM keys WHERE state = ? AND legacy = 0 "
                         "ORDER BY key_id", (registry.ACTIVE,)):
        end = row["window_end"]
        step = _due(KEY_STEPS, end, now)
        if step is None:
            continue
        scope = ("the deployment's" if row["organization"] is None
                 else "%s's" % (row["certified_name"] or "an organization"))
        what = ("its documents and every phone's bundles"
                if row["organization"] is None else "its documents")
        successor = store.one(
            "SELECT key_id FROM keys WHERE state = ? AND legacy = 0 AND "
            "organization IS ? ORDER BY key_id LIMIT 1",
            (registry.PUBLISHED, row["organization"]))
        message = ("key %d (%s) stops signing %s on %s"
                   % (row["key_id"], scope, what, _day(end)))
        if successor is not None:
            message += "; key %d is published to take over" % successor["key_id"]
        found = _warning(store, "key-%d" % row["key_id"], end, step, message,
                         {"key_id": row["key_id"],
                          "organization": row["organization"] or ""}, now)
        if found:
            out.append(found)
    return out


def _ca_warnings(store, cfg, now):
    out = []
    for ca in store.all("SELECT * FROM cas WHERE state = ? ORDER BY ca_id",
                        (registry.CERTIFIED,)):
        if not ca["not_after"]:
            continue
        end = registry.issue_until(cfg, ca["not_after"])
        step = _due(KEY_STEPS, end, now)
        if step is None:
            continue
        found = _warning(
            store, "ca-%d" % ca["ca_id"], end,
            (step[0], step[1], "make its successor: cl03signer ca keygen"),
            "Organization CA %d (%s) can certify keys until %s"
            % (ca["ca_id"], ca["name"], _day(end)), {"ca_id": ca["ca_id"]},
            now)
        if found:
            out.append(found)
    return out


def _anchor_warnings(store, cfg, now):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    out = []
    for der in cfg.anchors:
        cert = x509.load_der_x509_certificate(der)
        end = int(cert.not_valid_after_utc.timestamp())
        step = _due(ANCHOR_STEPS, end, now)
        if step is None:
            continue
        name = cert.subject.rfc4514_string()
        found = _warning(
            store, "anchor-%s" % cert.fingerprint(hashes.SHA256()).hex()[:16],
            end, step, "the issuing CA %s ends on %s" % (name, _day(end)),
            {"issuing_ca": name}, now)
        if found:
            out.append(found)
    return out


def summary(store, cfg, now) -> dict:
    """What the daily summary says."""
    seq, head = store.one("SELECT seq, hash FROM ledger ORDER BY seq DESC "
                          "LIMIT 1") or (0, "")
    shipped = store.one("SELECT MAX(seq) AS s FROM ledger WHERE shipped = 1")
    signed = Counter(r["context"] for r in store.all(
        "SELECT context FROM ledger WHERE kind = 'sign' AND at > ?",
        (now - DAY,)))
    alerts = Counter(r["context"] for r in store.all(
        "SELECT context FROM ledger WHERE kind = 'alert' AND at > ?",
        (now - DAY,)))
    keys = {}
    for row in store.all("SELECT * FROM keys WHERE state = ? AND legacy = 0",
                         (registry.ACTIVE,)):
        keys[row["organization"] or "deployment"] = {
            "key_id": row["key_id"], "signs_until": _day(row["window_end"]),
            "suspended": row["suspended_at"] is not None}
    return {"ledger_seq": seq, "ledger_hash": head,
            "shipped_through": (shipped["s"] if shipped else 0) or 0,
            "signed_today": dict(signed), "alerts_today": dict(alerts),
            "signing_keys": keys,
            "paused": [r["context"] for r in store.all("SELECT context FROM "
                                                        "pauses")],
            "revoked": store.one("SELECT COUNT(*) AS n FROM revoked")["n"]}


def run(store, cfg, alerts, *, now: int) -> list:
    """Send what is due. Returns [(severity, message, fields)]."""
    due = (_key_warnings(store, cfg, now) + _ca_warnings(store, cfg, now)
           + _anchor_warnings(store, cfg, now))
    last = store.meta("summary_at")
    if last is None or now - int(last) >= SUMMARY_EVERY:
        due.append(("low", "daily summary", summary(store, cfg, now),
                    "summary_at"))
    sent = []
    for severity, message, fields, name in due:
        try:
            alerts(severity, message, fields)
        except Exception:
            continue            # not marked: tried again at the next run
        with store as db:
            store.set_meta(db, name, now)
        sent.append((severity, message, fields))
    return sent
