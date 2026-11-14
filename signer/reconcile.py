"""Compare what the signer signed with what verify says it issued and saw.

Run by a timer every 15 minutes. verify's report (`GET /api/v1/signer/report`,
token only, over loopback -- or over https from a poll-mode signer's own
host) lists its credential rows and the phone scans it has received since a
time. What it cannot catch, plainly: a compromised app that asks for
signatures and writes matching rows passes the first two checks, and only
the ceilings and the baseline see it; scans arrive only when someone taps
Send log.

Key 1 and every PEM-era key are left out: their credentials have no ledger
rows. The baseline needs only the signer's own ledger, so it runs whether or
not the report came: a report that stops coming is exactly what a compromised
app would arrange. One missing report is not an alarm (a parked app answers
503 with Retry-After); `FAILURES_BEFORE_ALERT` in a row are.
"""

from __future__ import annotations

import json
from collections import Counter

FIRST_SIGNER_KEY = 16
PENDING_GRACE_SECONDS = 600
#: Runs in a row without verify's report before it is an alert: 45 minutes at
#: the timer's 15.
FAILURES_BEFORE_ALERT = 3
GENUINE = {"valid", "genuine"}


class Parked(Exception):
    pass


def findings(store, report: dict, *, now: int, since: int) -> list:
    """[(severity, message, fields)] for one comparison.

    verify's report covers at most its own span (`since` in the report, the
    time it actually started from). Rows signed before that are not in it,
    so they are not compared -- each would read as a false "signed, never
    recorded" -- and are counted in one alert for the span nothing could
    check."""
    out = []
    covered = since
    reported = report.get("since")
    if isinstance(reported, int) and not isinstance(reported, bool) \
            and reported > since:
        covered = reported
        unchecked = sum(
            1 for row in store.all(
                "SELECT summary FROM ledger WHERE kind = 'sign' AND "
                "context = 'credential' AND at >= ? AND at < ?",
                (since, covered))
            if json.loads(row["summary"]).get("key_id", 0) >= FIRST_SIGNER_KEY)
        if unchecked:
            out.append(("medium", "signed while no report came, and older "
                        "than verify's report reaches: not compared",
                        {"from": since, "until": covered,
                         "credentials": unchecked}))
    signed = {}
    for row in store.all("SELECT at, summary FROM ledger WHERE kind = 'sign' "
                         "AND context = 'credential' AND at >= ?", (covered,)):
        summary = json.loads(row["summary"])
        if summary.get("key_id", 0) >= FIRST_SIGNER_KEY:
            signed[summary["credential_id"]] = (row["at"], summary)
    ever = {json.loads(r["summary"]).get("credential_id") for r in store.all(
        "SELECT summary FROM ledger WHERE kind = 'sign' AND "
        "context = 'credential'")}

    rows = {r["credential_id"]: r for r in report.get("credentials", [])}
    for cid, (at, summary) in signed.items():
        row = rows.get(cid)
        if now - at < PENDING_GRACE_SECONDS:
            continue
        if row is None or row.get("state") == "pending":
            out.append(("high", "signed, never recorded",
                        {"credential_id": cid, "key_id": summary["key_id"]}))
    for cid, row in rows.items():
        if (row.get("issuer_key_id", 0) >= FIRST_SIGNER_KEY
                and row.get("state") == "signed" and cid not in ever):
            out.append(("high", "recorded but never signed here",
                        {"credential_id": cid,
                         "key_id": row.get("issuer_key_id")}))
    for scan in report.get("scans", []):
        if (scan.get("verdict") in GENUINE
                and (scan.get("issuer_key") or 0) >= FIRST_SIGNER_KEY
                and scan.get("credential_id") not in ever):
            out.append(("highest", "forged with a trusted key",
                        {"credential_id": scan.get("credential_id"),
                         "key_id": scan.get("issuer_key"),
                         "device": scan.get("device")}))
    out.extend(_baseline(store, now))
    return out


def run(store, fetch, alerts, *, now: int) -> list:
    """One reconciliation: fetch the report, compare, alert. Returns findings.

    `fetch(since)` returns verify's report or raises; `alerts(severity,
    message, fields)` sends one alert.
    """
    since = int(store.meta("reconciled_through", now - 86400))
    try:
        report, reason = fetch(since), ""
    except Parked:
        report, reason = None, "parked (503 with Retry-After)"
    except Exception as exc:
        report, reason = None, "%s: %s" % (type(exc).__name__, exc)
    if report is None:
        failures = int(store.meta("report_failures", 0)) + 1
        with store as db:
            store.set_meta(db, "report_failures", failures)
        found = _baseline(store, now)
        if failures >= FAILURES_BEFORE_ALERT:
            found.append(("high", "verify's report has been unavailable for "
                          "%d runs in a row" % failures,
                          {"reason": reason, "runs": failures}))
    else:
        found = findings(store, report, now=now, since=since)
        with store as db:
            store.set_meta(db, "report_failures", 0)
            store.set_meta(db, "reconciled_through",
                           now - PENDING_GRACE_SECONDS)
    for severity, message, fields in found:
        alerts(severity, message, fields)
    return found


def _baseline(store, now: int) -> list:
    """An organization or operator signing several times its usual rate."""
    day, week = 86400, 7 * 86400
    today, before = Counter(), Counter()
    for row in store.all("SELECT at, summary FROM ledger WHERE kind = 'sign' "
                         "AND context = 'credential' AND at >= ?",
                         (now - week - day,)):
        s = json.loads(row["summary"])
        for who in ("organization:%s" % s.get("organization", ""),
                    "operator:%s" % s.get("operator", "")):
            (today if row["at"] >= now - day else before)[who] += 1
    out = []
    for who, count in today.items():
        usual = before[who] / 7.0
        if count >= 20 and count > 3 * max(usual, 1.0):
            out.append(("medium", "signing well above its baseline",
                        {"principal": who, "today": count,
                         "daily_average": round(usual, 1)}))
    return out


def report_target(rt: dict):
    """(report URL, Host header) from the policy's `[runtime]`.

    On the app's host, loopback with the site's name: `report_url =
    "http://127.0.0.1:8000/api/v1/signer/report/"`, `report_host` the site.
    A poll-mode signer on a host of its own reads it like any client, over
    https: `report_url` defaults to `<site_url>/api/v1/signer/report/`, and
    `report_host` to the URL's own host. The site must let that path through
    its proxy to this host (README.md, "Poll mode")."""
    import urllib.parse

    from .poll import REPORT_PATH

    url = rt.get("report_url")
    if not url and rt.get("site_url"):
        url = rt["site_url"].rstrip("/") + REPORT_PATH
    if not url:
        raise KeyError("report_url")
    return url, rt.get("report_host") or urllib.parse.urlsplit(url).hostname


def fetch_report(url: str, host: str, token: str, since: int) -> dict:
    """The report, over loopback (http) or from another host (https, the
    certificate checked against the URL's host). Raises Parked for a parked
    app."""
    import http.client
    import ssl
    import urllib.parse

    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https":
        conn = http.client.HTTPSConnection(
            parts.hostname, parts.port or 443, timeout=30,
            context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(parts.hostname, parts.port or 80,
                                          timeout=30)
    conn.request("GET", "%s?since=%d" % (parts.path, since),
                 headers={"Host": host or parts.hostname,
                          "Authorization": "Bearer " + token})
    reply = conn.getresponse()
    body = reply.read()
    if reply.status == 503 and reply.getheader("Retry-After"):
        raise Parked()
    if reply.status != 200:
        raise RuntimeError("report: HTTP %d" % reply.status)
    return json.loads(body)
