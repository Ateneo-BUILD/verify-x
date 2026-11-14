"""A rebuilt signer host carrying on from its shipped ledger.

    sudo -u cl03-signer venv/bin/python -m signer adopt --config /etc/cl03-signer/policy.toml

with the signer stopped, on a database with nothing in it (the README,
"Rebuilding the signer host", says how to give it the AWS key on a site
that ships to S3). It reads every object shipped under the ledger prefix,
checks the chain from its first row, and makes the database again from it:

- the ledger itself, so the chain goes on from the shipped head, the rollback
  check passes, key ids are never reused (`registry.allocate_key_id` reads
  the ledger's key events) and the switch gate has its bundle history;
- the registry's public half -- every key and Organization CA, their states,
  windows and certificates -- replayed from the key events, so a withdrawn
  key is a tombstone again and travels to phones in the next bundle;
- the credential ids already signed, so none is signed twice.

What it cannot bring back is in the report and in the README: private keys
(a key whose file is not in the key folder cannot sign: retire or withdraw
it, or restore the file), pending confirmations, pauses, and the revoked set,
which verify sends again before the next bundle. Rows the old host signed
but had not shipped are gone with it.
"""

from __future__ import annotations

import base64
import json
import uuid

from . import ledger, registry


class AdoptError(ValueError):
    pass


def shipped_rows(uploader, prefix: str) -> list:
    """Every shipped row, in order, the chain checked from the first."""
    rows = []
    for key in uploader.keys(prefix):
        for line in uploader.get(key).decode().splitlines():
            if line.strip():
                rows.append(json.loads(line))
    rows.sort(key=lambda r: r["seq"])
    if not rows:
        raise AdoptError("nothing was shipped under %r: this is a new signer, "
                         "so start it as one" % prefix)
    if rows[0]["seq"] != 1 or rows[0]["prev_hash"] != ledger.GENESIS:
        raise AdoptError("the shipped ledger does not start at its first row")
    for before, after in zip(rows, rows[1:]):
        if after["seq"] != before["seq"] + 1:
            raise AdoptError("shipped rows %d to %d are missing"
                             % (before["seq"] + 1, after["seq"] - 1))
    try:
        ledger.verify_chain(rows)
    except ValueError as exc:
        raise AdoptError("the shipped ledger is broken: %s" % exc)
    return rows


def _bytes(value):
    return base64.b64decode(value) if value else None


def replay(rows, cfg) -> tuple:
    """(keys, cas, credentials, incomplete) from the key and sign events.

    `keys` and `cas` map ids to the columns of their tables; legacy keys
    start from the policy, as a start seeds them. `incomplete` are ids named
    by an event whose key the ledger never described (a `keygen` from before
    the ledger carried public keys, and no `record` after it)."""
    keys, cas, credentials, incomplete = {}, {}, [], set()
    for item in cfg.legacy:
        keys[item.key_id] = {"key_id": item.key_id, "state": registry.LEGACY,
                             "spki": item.spki, "window_start": item.not_before,
                             "window_end": item.not_after, "legacy": 1,
                             "created_at": 0}
    v_m = cfg.credential_max_seconds + cfg.margin_seconds
    for row in rows:
        s, at = json.loads(row["summary"]), row["at"]
        if row["kind"] == "sign" and row["context"] == "credential":
            credentials.append((uuid.UUID(s["credential_id"]).bytes,
                                int(s["key_id"]), at))
            continue
        if row["kind"] != "key":
            continue
        action, kid = row["context"], int(s.get("key_id", 0))
        k, ca = keys.get(kid), cas.get(kid)
        if action == "record":
            keys[kid] = dict({c: s.get(c) for c in (
                "organization", "state", "certified_name", "leaf_not_before",
                "leaf_not_after", "window_start", "window_end",
                "published_at", "activated_at", "retired_at", "withdrawn_at",
                "suspended_at", "created_at", "ca_id", "certified_by")},
                key_id=kid, spki=_bytes(s["spki"]), leaf=_bytes(s.get("leaf")),
                legacy=0)
            incomplete.discard(kid)
        elif action == "keygen":
            if s.get("spki"):
                keys[kid] = {"key_id": kid, "state": registry.GENERATED,
                             "organization": s.get("organization") or None,
                             "spki": _bytes(s["spki"]), "created_at": at,
                             "legacy": 0}
            else:
                incomplete.add(kid)
        elif action == "hold":
            if s.get("spki"):
                keys[kid] = {"key_id": kid, "state": registry.PUBLISHED,
                             "organization": None, "spki": _bytes(s["spki"]),
                             "window_start": s["window_start"],
                             "window_end": s["window_end"],
                             "leaf_not_before": s["window_start"],
                             "leaf_not_after": s["window_end"] + v_m,
                             "published_at": at, "created_at": at, "legacy": 0}
            else:
                incomplete.add(kid)
        elif action == "ca-record":
            cas[kid] = dict({c: s.get(c) for c in (
                "state", "name", "not_before", "not_after", "issued",
                "created_at", "retired_at", "withdrawn_at")},
                ca_id=kid, spki=_bytes(s["spki"]), cert=_bytes(s.get("cert")))
            incomplete.discard(kid)
        elif action == "ca-keygen":
            if s.get("spki"):
                cas[kid] = {"ca_id": kid, "state": registry.GENERATED,
                            "spki": _bytes(s["spki"]), "issued": 0,
                            "created_at": at}
            else:
                incomplete.add(kid)
        elif ca is not None:
            if action == "ca-install" and s.get("cert"):
                ca.update(state=registry.CERTIFIED, cert=_bytes(s["cert"]),
                          name=s.get("name"), not_before=s.get("not_before"),
                          not_after=s.get("not_after"))
            elif action == "ca-retire":
                ca.update(state=registry.RETIRED, retired_at=at)
            elif action == "ca-withdraw":
                ca.update(state=registry.WITHDRAWN, withdrawn_at=at)
        elif k is not None:
            if action in ("install", "issue") and s.get("leaf"):
                k.update(state=registry.CERTIFIED, leaf=_bytes(s["leaf"]),
                         certified_name=s.get("certified_name"),
                         certified_by=s.get("certified_by"),
                         leaf_not_before=s.get("leaf_not_before"),
                         leaf_not_after=s.get("leaf_not_after"),
                         window_start=s.get("leaf_not_before"),
                         window_end=s.get("window_end"),
                         ca_id=s.get("ca_id") if action == "issue" else None)
                if action == "issue" and s.get("ca_id") in cas:
                    cas[s["ca_id"]]["issued"] = cas[s["ca_id"]].get(
                        "issued", 0) + 1
            elif action == "publish":
                k.update(state=registry.PUBLISHED, published_at=at)
            elif action == "activate":
                k.update(state=registry.ACTIVE, activated_at=at)
            elif action == "retire":
                k.update(state=registry.RETIRED, retired_at=at,
                         window_end=min(k.get("window_end") or at, at))
            elif action == "withdraw":
                # A withdrawal from before the ledger said how long its
                # tombstone lives: as `_do_withdraw` reckons it, so a legacy
                # key's is not lost.
                until = s.get("not_after") or k.get("leaf_not_after")
                if until is None and k.get("window_end") is not None:
                    until = k["window_end"] + v_m
                k.update(state=registry.WITHDRAWN, withdrawn_at=at,
                         leaf_not_after=until)
            elif action == "discard":
                k.update(state=registry.DISCARDED)
            elif action == "suspend":
                k.setdefault("suspended_at", None)
                k["suspended_at"] = k["suspended_at"] or at
            elif action == "unsuspend":
                k["suspended_at"] = None
            elif action == "legacy-end" and k.get("legacy"):
                k["window_end"] = min(k["window_end"], at)
        elif action not in ("ca-install", "ca-retire", "ca-withdraw"):
            incomplete.add(kid)
    return keys, cas, credentials, sorted(incomplete)


KEY_COLUMNS = ("key_id", "organization", "state", "spki", "key_ref", "leaf",
               "certified_name", "leaf_not_before", "leaf_not_after",
               "window_start", "window_end", "published_at", "activated_at",
               "retired_at", "withdrawn_at", "suspended_at", "legacy",
               "created_at", "ca_id", "certified_by")
CA_COLUMNS = ("ca_id", "state", "spki", "key_ref", "cert", "name",
              "not_before", "not_after", "issued", "created_at", "retired_at",
              "withdrawn_at")

#: States whose private key the new host must have to go on.
NEEDS_KEY = (registry.GENERATED, registry.CERTIFIED, registry.PUBLISHED,
             registry.ACTIVE)


def _key_file(keys, key_ref, spki) -> str:
    """"present", "missing" or "another key", for a key the registry says
    the host holds."""
    try:
        return "present" if keys.spki(key_ref) == spki else "another key"
    except (OSError, ValueError):
        return "missing"


def adopt(store, cfg, keys, uploader, prefix: str, *, now: int) -> dict:
    """Make an empty database again from the shipped ledger. Returns the
    report it also writes to the ledger."""
    for table in ("ledger", "keys", "cas"):
        if store.one("SELECT COUNT(*) AS n FROM %s" % table)["n"]:
            raise AdoptError("the database is not empty (%s): adopt makes a "
                             "new one from the ledger. Move this one aside "
                             "first" % table)
    rows = shipped_rows(uploader, prefix)
    key_rows, ca_rows, credentials, incomplete = replay(rows, cfg)
    held = {item.key_id: item.key_file for item in cfg.held}
    files = {}
    for kid, k in key_rows.items():
        if k["state"] in NEEDS_KEY and not k.get("legacy"):
            k["key_ref"] = held.get(kid, "key-%d.pem" % kid)
            files[kid] = _key_file(keys, k["key_ref"], k["spki"])
    for cid, c in ca_rows.items():
        if c["state"] in (registry.GENERATED, registry.CERTIFIED):
            c["key_ref"] = "key-%d.pem" % cid
            files["ca-%d" % cid] = _key_file(keys, c["key_ref"], c["spki"])
    report = {
        "through": rows[-1]["seq"], "head": rows[-1]["hash"],
        "keys": {str(kid): k["state"] for kid, k in sorted(key_rows.items())},
        "organization_cas": {str(cid): c["state"]
                             for cid, c in sorted(ca_rows.items())},
        "credentials": len(credentials),
        "key_files": {str(k): v for k, v in sorted(files.items(),
                                                    key=lambda i: str(i[0]))},
        "not_described": incomplete,
    }
    with store as db:
        db.executemany(
            "INSERT INTO ledger (seq, at, kind, context, digest, summary, "
            "prev_hash, hash, shipped) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)",
            [(r["seq"], r["at"], r["kind"], r["context"], r["digest"],
              r["summary"], r["prev_hash"], r["hash"]) for r in rows])
        for k in key_rows.values():
            db.execute("INSERT INTO keys (%s) VALUES (%s)" % (
                ", ".join(KEY_COLUMNS), ", ".join("?" * len(KEY_COLUMNS))),
                [k.get(c, 0 if c == "legacy" else None) for c in KEY_COLUMNS])
        for c in ca_rows.values():
            db.execute("INSERT INTO cas (%s) VALUES (%s)" % (
                ", ".join(CA_COLUMNS), ", ".join("?" * len(CA_COLUMNS))),
                [c.get(col, 0 if col == "issued" else None)
                 for col in CA_COLUMNS])
        db.executemany("INSERT OR IGNORE INTO signed_credentials "
                       "(credential_id, key_id, at) VALUES (?, ?, ?)",
                       credentials)
        store.set_meta(db, "adopted_through", rows[-1]["seq"])
        # Nothing before this start is left to describe (`_record_public_halves`).
        store.set_meta(db, "public_halves_recorded", now)
        ledger.append(db, at=now, kind="admin", context="adopt",
                      summary=dict(report, by="adopt"))
    return report
