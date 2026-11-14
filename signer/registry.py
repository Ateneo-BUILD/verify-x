"""Key state: the only record of which keys phones trust, and which signs.

States:

    generated -> certified -> published -> active -> retired -> expired

and, from any of them, withdrawn (final). A key verify asked for that was
never published may instead be discarded (final, never listed).

Organization CAs (the `cas` table) have states of their own:

    generated -> certified -> retired      and withdrawn (final)

One is certified at a time; it certifies organization keys the signer made,
and its withdrawal takes every one of them with it.

A key may also be *suspended* (`suspended_at`): it signs no credentials, and
is listed and -- if it is the deployment key -- still signs bundles, feeds and
statements. Suspension is reversible; withdrawal is not.

Windows. A credential never outlives the certificate of its key, so a key's
credential window ends at the leaf's notAfter - V - M ("signing_until").
The deployment key signs bundles until that window ends too, since a phone
holding a bundle issued after it refuses every later one the key signs
(continuity), and feeds and statements until notAfter - lease - M. A retired
key's window ends when it retired.
"""

from __future__ import annotations

import unicodedata

from ovcrypto import bundle as bundle_mod
from ovcrypto import trust as trust_mod

GENERATED = "generated"
CERTIFIED = "certified"
PUBLISHED = "published"
ACTIVE = "active"
RETIRED = "retired"
WITHDRAWN = "withdrawn"
EXPIRED = "expired"
LEGACY = "legacy"
DISCARDED = "discarded"

#: Keys waiting to take over for their scope.
WAITING = (GENERATED, CERTIFIED, PUBLISHED)

#: Keys whose public half phones are given.
LISTED = (PUBLISHED, ACTIVE, RETIRED, LEGACY)

FIRST_KEY_ID = 16


class RegistryError(ValueError):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__("%s%s" % (reason, ": " + detail if detail else ""))
        self.reason = reason


def get(store, key_id: int):
    return store.one("SELECT * FROM keys WHERE key_id = ?", (key_id,))


def require(store, key_id: int):
    row = get(store, key_id)
    if row is None:
        raise RegistryError("unknown_key", str(key_id))
    return row


def allocate_key_id(db) -> int:
    """Never reused: past every key the table or the ledger has ever named."""
    in_table = db.execute("SELECT MAX(key_id) AS m FROM keys").fetchone()["m"]
    in_cas = db.execute("SELECT MAX(ca_id) AS m FROM cas").fetchone()["m"]
    in_ledger = db.execute(
        "SELECT MAX(CAST(json_extract(summary, '$.key_id') AS INTEGER)) AS m "
        "FROM ledger WHERE kind = 'key'").fetchone()["m"]
    highest = max(FIRST_KEY_ID - 1, in_table or 0, in_cas or 0, in_ledger or 0)
    if highest + 1 >= bundle_mod.CHAINS_DIGEST_ID:
        # The last u32 binds a bundle's chains; it is no key's.
        raise RegistryError("key_ids_exhausted", str(highest))
    return highest + 1


def current_ca(store):
    """The Organization CA that issues now, or None."""
    return store.one("SELECT * FROM cas WHERE state = ?", (CERTIFIED,))


def waiting_key(store, organization):
    """A key made for `organization` and not yet signing, or None."""
    return store.one("SELECT * FROM keys WHERE organization = ? AND state IN "
                     "(?, ?, ?) ORDER BY key_id LIMIT 1",
                     (organization,) + WAITING)


def issue_until(cfg, ca_not_after: int) -> int:
    """The last moment the Organization CA can issue a certificate that
    leaves `min_signing_days` of signing."""
    return (signing_until(cfg, ca_not_after)
            - cfg.min_signing_days * 86400)


def active_key(store, organization):
    """The key that signs for `organization` (None: the deployment key)."""
    if organization is None:
        return store.one("SELECT * FROM keys WHERE state = ? AND legacy = 0 "
                         "AND organization IS NULL", (ACTIVE,))
    return store.one("SELECT * FROM keys WHERE state = ? AND organization = ?",
                     (ACTIVE, organization))


#: Keys whose certified name is spoken for: waiting to take over, or still
#: listed for phones. A withdrawn, expired or discarded key gives it up.
NAME_HELD = WAITING + (ACTIVE, RETIRED)


def name_key(name: str) -> str:
    """How two certified names are compared: NFKC, case-folded, and only the
    letters and digits kept, so "ACME Clinic", "acme  clinic", "ACME
    Clinic." and a fullwidth spelling are one name. verify compares
    organization names the same way (accounts/org_names.py)."""
    folded = unicodedata.normalize("NFKC", name or "").casefold()
    return "".join(ch for ch in folded if ch.isalnum())


#: Scripts whose letters pass for one another: a name may use one of them.
CONFUSABLE_SCRIPTS = frozenset({"LATIN", "CYRILLIC", "GREEK", "ARMENIAN",
                                "CHEROKEE", "COPTIC"})


def mixed_script(name: str) -> bool:
    """Does `name` mix letters of two scripts that look alike -- a Cyrillic or
    Greek capital A in a Latin name? Such a name reads as another one on
    every phone, and no comparison of code points would catch it."""
    seen = set()
    for ch in unicodedata.normalize("NFKC", name or ""):
        if ch.isalpha():
            script = unicodedata.name(ch, "?").split(" ")[0]
            if script in CONFUSABLE_SCRIPTS:
                seen.add(script)
    return len(seen) > 1


def name_held_by_another(store, name: str, organization):
    """The key of an organization other than `organization` that holds `name`,
    or None. Phones show two keys certified under one name identically, so
    a second organization must never get the first one's."""
    wanted = name_key(name)
    if not wanted:
        return None
    for row in store.all(
            "SELECT * FROM keys WHERE organization IS NOT NULL AND "
            "organization != ? AND certified_name IS NOT NULL AND state IN "
            "(%s) ORDER BY key_id" % ", ".join("?" * len(NAME_HELD)),
            (str(organization),) + NAME_HELD):
        if name_key(row["certified_name"]) == wanted:
            return row
    return None


def certified_names(store) -> set:
    """Organizations whose name only their own key may sign."""
    rows = store.all("SELECT certified_name FROM keys WHERE state = ? "
                     "AND organization IS NOT NULL", (ACTIVE,))
    return {r["certified_name"] for r in rows if r["certified_name"]}


def certified_name_keys(store) -> set:
    """`certified_names`, as `name_key` compares them: what the deployment
    key may not sign as an issuer, in any spelling of it."""
    return {name_key(n) for n in certified_names(store)} - {""}


def signing_until(cfg, leaf_not_after: int) -> int:
    return leaf_not_after - cfg.credential_max_seconds - cfg.margin_seconds


def infrastructure_until(cfg, leaf_not_after: int) -> int:
    return leaf_not_after - cfg.lease_seconds - cfg.margin_seconds


def expire(db, cfg, now: int):
    """Move retired keys whose credentials have all expired out of lists."""
    horizon = cfg.credential_max_seconds + cfg.margin_seconds
    db.execute("UPDATE keys SET state = ? WHERE state = ? AND "
               "(retired_at + ? < ? OR leaf_not_after < ?)",
               (EXPIRED, RETIRED, horizon, now, now))
    db.execute("UPDATE keys SET state = ? WHERE state = ? AND "
               "window_end + ? < ?", (EXPIRED, LEGACY, horizon, now))


def trust_list(store, cfg, now: int):
    """(entries, chains): what a bundle lists, and the leaves beside it.

    Listed keys with their windows, sorted by id; withdrawn keys as tombstones
    until their certificate ends, so phones refuse them everywhere; and a
    withdrawn Organization CA as one more, so phones refuse whatever it
    certified. A key the Organization CA certified travels with its
    certificate: (leaf, CA).
    """
    entries, chains = [], {}
    cas = {r["ca_id"]: r for r in store.all("SELECT * FROM cas")}
    rows = store.all("SELECT * FROM keys ORDER BY key_id")
    for row in rows:
        if row["state"] in LISTED:
            entries.append(bundle_mod.TrustEntry(
                row["key_id"], row["window_start"], row["window_end"],
                bytes(row["spki"])))
            if row["leaf"] is not None:
                ca = cas.get(row["ca_id"]) if row["ca_id"] else None
                chains[row["key_id"]] = (
                    (bytes(row["leaf"]), bytes(ca["cert"])) if ca is not None
                    else bytes(row["leaf"]))
        elif row["state"] == WITHDRAWN and (row["leaf_not_after"] or 0) >= now:
            # The key's fingerprint, not just its id: a certificate names no
            # id, so whoever holds a withdrawn key could offer it under
            # another one.
            entries.append(bundle_mod.TrustEntry(
                row["key_id"], now, now,
                trust_mod.fingerprint(bytes(row["spki"]))))
    for ca in cas.values():
        if ca["state"] == WITHDRAWN and (ca["not_after"] or 0) >= now:
            entries.append(bundle_mod.TrustEntry(
                ca["ca_id"], now, now, trust_mod.fingerprint(bytes(ca["spki"]))))
    entries.sort(key=lambda e: e.key_id)
    # 255 entries at most, and one is the chains digest a bundle adds.
    if len(entries) > 254:
        raise RegistryError("trust_list_full", "%d keys" % len(entries))
    return entries, chains


def nothing_signs_bundles(store, cfg, key_row, now: int) -> bool:
    """A deployment key with no deployment key beside it that can still sign a
    bundle: the first one, one after its predecessor was retired or
    withdrawn, or one whose predecessor's window has ended (bundles stop
    then). Nothing can sign a bundle listing it first, so waiting can only
    lengthen the outage; `retire` refuses while a successor waits and
    otherwise takes two operators told so."""
    if key_row["organization"] is not None:
        return False
    current = store.one("SELECT * FROM keys WHERE organization IS NULL AND "
                        "legacy = 0 AND state = ? AND key_id != ?",
                        (ACTIVE, key_row["key_id"]))
    return (current is None or now > current["window_end"]
            or now + cfg.lease_seconds > infrastructure_until(
                cfg, current["leaf_not_after"]))


#: Devices named in a gate that is held for them, at most.
GATE_DEVICES_SHOWN = 20


def activation_gate(store, cfg, key_row, now: int) -> dict:
    """May this published key start signing without stranding a phone?

    `needed` is False for a held raw key, which phones pin, and for a
    deployment key when no deployment key signs (`nothing_signs_bundles`);
    every organization key waits, its first included, since the deployment
    key signed its documents before it.

    Otherwise `of` counts the devices that got a bundle within the last
    lease, `have` those of them that have since got one listing this key, and
    `opens_at` is when one whole lease has passed since it was published.
    Counted from the bundles the signer itself signed, not from what verify
    reports; verify still chooses which devices it asks bundles for, so the
    gate keeps a careful site from stranding its phones, not a compromised
    verify from stranding them. The count is trusted only once the signer has
    signed bundles for a whole lease (`counted`): before that, phones that
    synced through verify's own bundles are in no row, and "nobody" is only
    "unknown".

    A certified deployment key taking over from a raw one (a held key 1) also
    needs every such device's latest bundle to have been asked for by an app
    that follows issuer certificates (`chains` in the bundle's row): an older
    app checks bundles, feeds and statements against key 1 alone, so it is in
    `not_capable` and the gate stays shut for it, whatever the time.
    """
    out = {"needed": True, "open": False, "have": 0, "of": 0,
           "opens_at": None, "counted": False, "not_capable": []}
    if key_row["leaf"] is None or nothing_signs_bundles(store, cfg, key_row,
                                                        now):
        out.update(needed=False, open=True)
        return out
    published = key_row["published_at"]
    if published is None:
        return out
    out["opens_at"] = published + cfg.lease_seconds
    first = store.one("SELECT MIN(at) AS at FROM ledger WHERE kind = 'sign' "
                      "AND context = 'bundle'")["at"]
    out["counted"] = first is not None and first <= now - cfg.lease_seconds
    recent = store.all(
        "SELECT json_extract(summary, '$.device') AS device, at, "
        "json_extract(summary, '$.keys') AS keys, "
        "json_extract(summary, '$.chains') AS chains FROM ledger "
        "WHERE kind = 'sign' AND context = 'bundle' AND at >= ? ORDER BY seq",
        (now - cfg.lease_seconds,))
    seen, capable = {}, {}
    for r in recent:
        listed = "|%d|" % key_row["key_id"] in (r["keys"] or "")
        if r["at"] >= published and listed:
            seen[r["device"]] = True
        else:
            seen.setdefault(r["device"], False)
        capable[r["device"]] = r["chains"] == 1      # the latest row decides
    out["have"], out["of"] = sum(seen.values()), len(seen)
    current = active_key(store, None)
    if (key_row["organization"] is None and current is not None
            and current["leaf"] is None):
        # Only the switch off a raw key strands the old app: once a
        # certified key signs, it is cut off already, and holding the next
        # switch for it would wedge every one after.
        out["not_capable"] = sorted(d for d, ok in capable.items() if not ok)
    out["open"] = not out["not_capable"] and (
        now >= out["opens_at"]
        or (out["counted"] and out["have"] == out["of"]))
    return out


def switch_gate_progress(store, cfg, key_row, now: int):
    """(have, of, opens_at) for a published key (`activation_gate`)."""
    gate = activation_gate(store, cfg, key_row, now)
    return gate["have"], gate["of"], gate["opens_at"]


def switch_gate_open(store, cfg, key_row, now: int) -> bool:
    """`activation_gate`'s answer: may it start signing now?"""
    return activation_gate(store, cfg, key_row, now)["open"]
