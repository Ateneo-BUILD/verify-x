"""What verify's pages say about credential signing.

Setup's "Credential signing" card (site admins) and the Credential signing
section of an organization's pages read from here. Read-only: the signer's own
registry and status, through `signer_client`, put into rows a template can
draw. Nothing here changes a key; what verify may do -- pause, suspend, upload
a certificate, and for an organization generate, request, or discard a key,
and publish and start it where the host allows -- are views of their own
(`verify/views/signing.py`), and everything else is a command on the signer
host, which these rows name instead of offering a button. Where the signer's
policy sets `site_controls_all_keys`, the rows offer the rest too -- the
deployment's keys published and started on Setup, and any key unsuspended or
withdrawn -- and name no host command for them.

Without a signer (`SIGNER_SOCKET`, or `SIGNER_QUEUE_KEY` for one that dials
out) the answer is the key file.
"""

from __future__ import annotations

import datetime

from django.conf import settings

from accounts import credential_keys, signer_client
from accounts.models import Organization

DAY = 86400

#: Days before a key stops signing at which Setup starts saying
#: so: a credential never outlives its signer's certificate. The
#: row warns from the first of these.
WARN_DAYS = (120, 90, 45, 14)

_LABELS = {
    "generated": ("Needs certificate", "generated"),
    "certified": ("Certified", "published"),
    "published": ("Published", "published"),
    "active": ("Active", "active"),
    "retired": ("Retired", "retired"),
    "expired": ("Expired", "retired"),
    "withdrawn": ("Withdrawn", "suspended"),
    "legacy": ("Key file", "retired"),
}

#: Order within one scope: what signs now first, history last.
_ORDER = {"active": 0, "published": 1, "certified": 2, "generated": 3,
          "retired": 4, "legacy": 5, "expired": 6, "withdrawn": 7}


def _date(ts):
    if ts is None:
        return None
    return datetime.datetime.fromtimestamp(int(ts), datetime.timezone.utc)


def _row(key, *, orgs, gates, credential_days, now, site_publishes=False,
         site_controls=False, ca_for_site=True):
    state = key["state"]
    suspended = bool(key.get("suspended"))
    label, css = _LABELS.get(state, (state.title(), "retired"))
    if suspended:
        label, css = "Suspended", "suspended"
    window = key.get("window") or [None, None]
    org_id = key.get("organization")
    org = orgs.get(org_id) if org_id else None
    row = {
        "key_id": key["key_id"],
        "state": state,
        "suspended": suspended,
        "label": label,
        "css": css,
        "organization": org,
        "organization_id": org_id,
        "certified_name": key.get("certified_name") or "",
        "legacy": bool(key.get("legacy")),
        # The development key, held by the signer with no certificate; its
        # cert_not_after is the signer's own bookkeeping, not a certificate.
        "raw": bool(key.get("raw")),
        "signs_from": _date(window[0]),
        "signs_until": _date(window[1]),
        "cert_ends": (None if key.get("raw")
                      else _date(key.get("cert_not_after"))),
        "days_left": None,
        "warn": False,
        "gate": None,
        "last_expiry": None,
        "can_suspend": state in ("active", "published") and not suspended,
        # A key the Organization CA certified already has its certificate.
        "can_upload": (state in ("generated", "certified")
                       and not key.get("legacy") and not key.get("ca_id")),
        # From the organization's page only; a published key is withdrawn
        # on the host instead.
        "can_discard": state in ("generated", "certified") and bool(org_id),
        "can_request": state == "generated" and bool(org_id),
        "certified_by": key.get("certified_by") or "",
        "by_organization_ca": bool(key.get("ca_id")),
        # Where the host's policy lets the site publish organization keys,
        # from the organization's Site page (`site_publishes_organization_keys`).
        "can_publish": False,
        "can_activate": False,
        # Where the signer's policy sets `site_controls_all_keys`: lift a
        # suspension, and withdraw a key that was published, from Setup.
        # Never a legacy or held key: those are the policy's.
        "can_unsuspend": (site_controls and suspended
                          and not key.get("legacy") and not key.get("raw")),
        "can_withdraw": (site_controls and not key.get("legacy")
                         and not key.get("raw")
                         and state in ("published", "active", "retired")),
        "gate_open": False,
        "host_command": "",
        "note": "",
        # Certified by an Organization CA that is not for the site phones
        # pair with: they drop it, and the signer refuses to publish or
        # start it (`SignerService._for_this_site`).
        "not_for_site": not ca_for_site,
    }
    # Publish and start from the site: an organization's key on its Site
    # page where either switch is on; the deployment's on Setup itself where
    # `site_controls_all_keys` is.
    by_site = ((site_publishes or site_controls) and bool(org_id)) or (
        site_controls and not org_id and not key.get("legacy")
        and not key.get("raw"))
    where = ("from its organization's Site page" if org_id
             else "on this page")
    if state == "active" and window[1] is not None:
        row["days_left"] = max(0, (window[1] - now) // DAY)
        row["warn"] = row["days_left"] <= WARN_DAYS[0]
    if state in ("retired", "legacy") and window[1] is not None:
        # A credential signed on its last day expires V days later; phones
        # check it up to that day.
        row["last_expiry"] = _date(window[1] + credential_days * DAY)
    if suspended:
        row["note"] = ("Its organization's documents print the plain QR."
                       if org_id else "Documents print the plain QR.")
        if not row["can_unsuspend"]:
            row["host_command"] = "cl03signer unsuspend %d" % key["key_id"]
    elif not ca_for_site and state in ("certified", "published", "active"):
        row["note"] = ("Certified by a CA that is not for this site, so "
                       "phones paired with it drop this key. %s"
                       % ("Discard it and generate a new one."
                          if state == "certified" else
                          "Generate a new key to take over."
                          if state == "active" else
                          "Withdraw it on this page." if site_controls else
                          "Withdraw it on the signer host."))
        if state == "published" and not site_controls:
            row["host_command"] = "cl03signer withdraw %d" % key["key_id"]
    elif state == "published":
        gate = gates.get(str(key["key_id"]))
        if gate and gate.get("needed", True):
            row["gate"] = {"have": gate["have"], "of": gate["of"],
                           "opens_at": _date(gate["opens_at"]),
                           "open": (gate["open"] if "open" in gate
                                    else gate["have"] == gate["of"] or (
                                        gate["opens_at"] is not None
                                        and now >= gate["opens_at"])),
                           # Whether the signer's count can be trusted
                           # yet, and the phones whose app cannot follow
                           # this key.
                           "counted": gate.get("counted", True),
                           "not_capable": gate.get(
                               "not_capable_count",
                               len(gate.get("not_capable") or [])),
                           "phones": _phones(gate.get("not_capable") or [])}
        if by_site:
            row["can_activate"] = True
            # The signer's own answer (registry.activation_gate); it decides
            # again when the button is pressed. A signer from before it
            # sent only the counts.
            if gate is None:
                row["gate_open"] = True
            elif "open" in gate:
                row["gate_open"] = bool(gate["open"])
            else:
                row["gate_open"] = gate["have"] == gate["of"] or (
                    gate["opens_at"] is not None and now >= gate["opens_at"])
            row["note"] = "Start it signing %s." % where
        else:
            row["host_command"] = "cl03signer activate %d" % key["key_id"]
    elif state == "certified":
        if by_site:
            row["can_publish"] = True
            row["note"] = "Publish it %s." % where
        else:
            row["note"] = "A second custodian confirms the publish."
            row["host_command"] = "cl03signer publish %d" % key["key_id"]
    if org_id and org is None and state in ("generated", "certified",
                                            "published", "active"):
        # Its organization was deleted, so no page offers a button for it,
        # and an active one keeps its name from the deployment key: the
        # host command that ends it.
        row["can_publish"] = row["can_activate"] = False
        row["can_unsuspend"] = row["can_withdraw"] = False
        row["note"] = "Its organization is no longer on this site."
        row["host_command"] = (
            "cl03signer discard %d" % key["key_id"]
            if state in ("generated", "certified")
            else "cl03signer retire %d" % key["key_id"]
            + (" (a second operator confirms)" if state == "active" else ""))
    return row


def _phones(device_ids) -> list:
    """The names of the phones a gate waits for, from the signer's hex ids."""
    import uuid

    from accounts.models import Device

    ids = []
    for hex_id in device_ids:
        try:
            ids.append(uuid.UUID(hex=hex_id))
        except (TypeError, ValueError):
            continue
    names = dict(Device.objects.filter(device_id__in=ids)
                 .values_list("device_id", "label"))
    return [names.get(i) or "an unknown phone (%s)" % i.hex[:8] for i in ids]


def _scope_key(row):
    """Deployment keys, then organization keys by organization, then history."""
    if row["legacy"]:
        group = (2, "")
    elif row["organization_id"]:
        org = row["organization"]
        group = (1, (org.name if org else row["certified_name"]).lower())
    else:
        group = (0, "")
    return group + (_ORDER.get(row["state"], 9), row["key_id"])


def overview(now=None, *, force=True) -> dict:
    """Everything Setup's card shows. Never raises for a signer that is down.

    `mode` is "signer", "file" (the key file named by
    CREDENTIAL_ISSUER_KEY_PATH) or "off" (no issuer key at all).
    """
    # Settings minting needs that are not set although an issuer key is: the
    # card says so first, in red, whatever else it shows. Every return
    # carries it.
    missing = credential_keys.missing()
    # Document keys this site cannot open, which phones would be given: a
    # database brought from elsewhere under another wrap key. As red as
    # `missing`, and on every return too.
    unreadable = credential_keys.unreadable_epoch_keys()
    lost = credential_keys.lost_epoch_keys()
    if not credential_keys.signer_mode():
        return {"mode": "file" if settings.CREDENTIAL_ISSUER_KEY_PATH else "off",
                "file_key_id": settings.CREDENTIAL_ISSUER_KEY_ID,
                "missing": missing, "unreadable": unreadable, "lost": lost}
    # How the signer is reached: its socket here, or its poll from a host of
    # its own (`accounts.signer_queue`). Setup words its advice by it.
    transport = signer_client.transport()
    try:
        public = signer_client.public(force=force)
        status = signer_client.status()
    except signer_client.SignerError as exc:
        return {"mode": "signer", "error": str(exc), "missing": missing,
                "unreadable": unreadable, "lost": lost,
                "transport": transport}
    now = int(now if now is not None else status.get("now") or 0)
    keys = public.get("keys", [])
    ids = {k["organization"] for k in keys if k.get("organization")}
    orgs = {str(o.signing_id): o
            for o in Organization.objects.filter(signing_id__in=ids)}
    site_domain = public.get("site_domain") or ""
    ca_for_site = {c["ca_id"]: bool(site_domain)
                   and site_domain in (c.get("domains") or [])
                   for c in public.get("organization_cas") or []}
    site_controls = bool(public.get("site_controls_all_keys"))
    rows = [_row(k, orgs=orgs, gates=status.get("gates") or {},
                 credential_days=public.get("credential_max_days", 365), now=now,
                 site_publishes=bool(
                     public.get("site_publishes_organization_keys")),
                 site_controls=site_controls,
                 ca_for_site=ca_for_site.get(k.get("ca_id"), True)
                 if k.get("ca_id") else True)
            for k in keys]
    rows.sort(key=_scope_key)
    _mark_next_keys(rows)
    ca = _organization_ca(public, now)
    paused = [p["context"] for p in status.get("pauses", [])]
    signed = status.get("signed_today") or {}
    head = status.get("ledger_head") or {}
    return {
        "mode": "signer",
        "transport": transport,
        "error": "",
        "missing": missing,
        "unreadable": unreadable,
        "lost": lost,
        # The signer's own count of internal failures in a row.
        "failing": (status.get("internal_failures") or {}).get("in_a_row", 0),
        "code": _code(status.get("code")),
        "rows": rows,
        "paused": paused,
        "credential_paused": "credential" in paused,
        # The signer's own word that any site admin may do every key action
        # here (`site_controls_all_keys`).
        "site_controls_all_keys": site_controls,
        # The signers that polled this site within minutes: more than one is
        # two signers answering it, each with a ledger the other lacks.
        "pollers": _pollers(transport),
        "credentials_today": signed.get("credential", 0),
        "bundles_today": signed.get("bundle", 0),
        "credential_ceiling": status.get("credential_day_ceiling"),
        "ledger_seq": head.get("seq", 0),
        "ledger_shipped": head.get("shipped_through", 0),
        "ledger_behind": head.get("seq", 0) - head.get("shipped_through", 0),
        "organization_ca": ca,
    }


def _pollers(transport) -> list:
    if transport != "queue":
        return []
    from accounts import signer_queue
    try:
        return signer_queue.pollers()
    except Exception:
        return []


def _code(signer_code) -> dict:
    """Which code the signer runs, against this site's own signer/ and
    ovcrypto/ (`signer.version`). A deploy of verify never updates the
    signer, so Setup shows when the two differ."""
    from signer import version

    site = version.cached_digest(str(settings.BASE_DIR))
    if not signer_code:
        # A signer from before it said: say nothing rather than guess.
        return {"known": False, "differs": False}
    theirs = signer_code.get("digest") or ""
    return {"known": True, "differs": bool(theirs) and theirs != site,
            "signer": theirs[:12], "site": site[:12],
            "commit": (signer_code.get("commit") or "")[:12],
            "wire": signer_code.get("wire")}


def _organization_ca(public, now):
    """The Organization CA as Setup and the organization pages show it.

    `current` issues now; `waiting` is one made on the host and waiting for
    the PKI's certificate; `can_generate` says whether a certificate made
    today would leave enough signing, and `signs_until` how long it would.
    `site_domain` is the site phones pair with, as the signer is told it;
    phones trust what the CA certifies only if it lists that domain.
    """
    cas = public.get("organization_cas") or []
    current = next((c for c in cas if c["state"] == "certified"), None)
    waiting = next((c for c in cas if c["state"] == "generated"), None)
    site_domain = public.get("site_domain") or ""
    out = {"current": None, "waiting": waiting["ca_id"] if waiting else None,
           "withdrawn": [c["ca_id"] for c in cas if c["state"] == "withdrawn"],
           "can_generate": False, "reason": "", "signs_until": None,
           "site_domain": site_domain}
    if current is None:
        out["reason"] = ("This site has no Organization CA, so certificates "
                         "cannot be generated here.")
        return out
    domains = current.get("domains") or []
    out["current"] = {"ca_id": current["ca_id"], "name": current["name"],
                      "ends": _date(current["not_after"]),
                      "issued": current["issued"],
                      "issue_until": _date(current["issue_until"]),
                      "domains": domains,
                      "for_site": bool(site_domain) and site_domain in domains}
    if not out["current"]["for_site"]:
        out["reason"] = ("%s is not for %s, the site phones pair with, so "
                         "phones would not trust what it certifies."
                         % (current["name"], site_domain or "this site"))
        return out
    if current["issue_until"] is None or now > current["issue_until"]:
        out["reason"] = ("%s ends too soon to leave %d days of signing."
                         % (current["name"], public.get("min_signing_days", 90)))
        return out
    leaf_end = min(now + public.get("organization_leaf_days", 730) * DAY,
                   current["not_after"])
    out["can_generate"] = True
    out["signs_until"] = _date(leaf_end
                               - public.get("credential_max_days", 365) * DAY
                               - public.get("margin_seconds", 30 * DAY))
    return out


def _mark_next_keys(rows):
    """Say which keys wait to take over from the one signing in their scope."""
    signing = {r["organization_id"] for r in rows
               if r["state"] == "active" and not r["legacy"]}
    for r in rows:
        if r["legacy"]:
            continue
        if r["state"] in ("published", "certified", "generated") \
                and r["organization_id"] in signing:
            r["next"] = True


def for_organization(org, now=None) -> dict:
    """An organization's own keys, for its pages. Same rules as `overview`."""
    summary = overview(now, force=False)
    if summary["mode"] != "signer" or summary.get("error"):
        return {"mode": summary["mode"], "error": summary.get("error", ""),
                "rows": [], "current": None, "next": None,
                "signing_id": str(org.signing_id), "can_start": False,
                "organization_ca": None, "site_controls_all_keys": False}
    rows = [r for r in summary["rows"]
            if r["organization_id"] == str(org.signing_id)]
    current = next((r for r in rows if r["state"] == "active"), None)
    waiting = next((r for r in rows
                    if r["state"] in ("published", "certified", "generated")),
                   None)
    return {"mode": "signer", "error": "", "rows": rows, "current": current,
            "next": waiting, "signing_id": str(org.signing_id),
            "renamed": bool(current and current["certified_name"]
                            and current["certified_name"] != org.name),
            # One key may wait at a time (the signer refuses a second).
            "can_start": waiting is None,
            "organization_ca": summary["organization_ca"],
            "site_controls_all_keys": summary["site_controls_all_keys"]}
