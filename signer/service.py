"""The signer's operations.

Two kinds, reached through two sockets (`transport.py`):

* **App operations** -- what verify may ask. Each signs only what its policy
  passes, or reduces trust: pause, suspend, install a certificate (which makes
  a key *certified*, not trusted), add revocations. Nothing here can publish,
  activate, resume, unsuspend or withdraw, except where policy.toml sets
  `site_publishes_organization_keys`: then a site admin may publish an
  organization's key and start it signing. Where it sets
  `site_controls_all_keys`, a site admin may also publish and start the
  deployment's keys, unsuspend a key, resume a paused context and withdraw
  any key, alone.
* **Admin operations** -- an operator on the host. Publishing, withdrawing,
  legacy changes and removing revocations need a second operator's
  confirmation within 24 hours.

A refusal that must leave a trace -- a pause, an alert -- is committed before
it is raised, so the trace outlasts the refusal. Alerts are written to the
ledger inside the transaction and sent only after it commits and the lock is
released, so a slow or unreachable SNS never holds up anybody else's request.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import unicodedata
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ovcrypto import bundle as bundle_mod
from ovcrypto import chain, devicelog, pki, revocation, wire
from ovcrypto import trust as trust_mod

from . import ceilings, config as cfgmod, ledger, messages, registry, version
from .clock import Clock

CONFIRM_SECONDS = 24 * 3600
MAX_EPOCH_KEYS = 32
MAX_WRAPPED = 512
CERTIFIED_NAME_MAX = 96          # what a credential's issuer claim can hold
OPERATOR_MAX = 200               # the site admin named in an alert


def _bad_name(name) -> bool:
    """Not a name a credential may carry as its certified issuer: empty,
    padded, too long, with a control or line-breaking character, or mixing
    look-alike scripts."""
    return (not isinstance(name, str) or not name or name != name.strip()
            or len(name) > CERTIFIED_NAME_MAX or _breaks_lines(name)
            or registry.mixed_script(name))


def _breaks_lines(text: str) -> bool:
    """Controls and format characters (C*), and the line and paragraph
    separators an email or a terminal shows as a new line: none may reach an
    alert or a phone inside a name."""
    return any(unicodedata.category(c).startswith("C")
               or unicodedata.category(c) in ("Zl", "Zp") for c in text)
U32 = 2 ** 32


class Refused(Exception):
    """A request the signer will not carry out. ``reason`` is stable."""

    def __init__(self, reason: str, detail: str = "", **extra):
        super().__init__("%s%s" % (reason, ": " + detail if detail else ""))
        self.reason = reason
        self.detail = detail
        self.extra = extra


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


class _KeySigner:
    """What `Bundle.sign` expects: a key id and a sign()."""

    def __init__(self, keys, row):
        self.keys = keys
        self.key_id = row["key_id"]
        self.key_ref = row["key_ref"]

    def sign(self, message: bytes) -> bytes:
        return self.keys.sign(self.key_ref, message)


class SignerService:
    def __init__(self, store, keys, cfg, clock: Clock = None, alerts=None):
        self.store = store
        self.keys = keys
        self.cfg = cfg
        self.clock = clock or Clock()
        self._alert_hook = alerts or (lambda severity, message, fields: None)
        self._local = threading.local()
        # What this process runs, read once: install.sh replaces the files
        # under a running signer and then restarts it.
        root = version.here()
        self.code = {"digest": version.cached_digest(root),
                     "commit": version.commit(root), "wire": wire.VERSION}
        self._seed_legacy()
        self._seed_held()
        self._record_public_halves()

    #: The columns a `record` event carries: everything a rebuilt registry
    #: needs but the private key.
    RECORDED_KEY = ("organization", "state", "spki", "leaf", "certified_name",
                    "leaf_not_before", "leaf_not_after", "window_start",
                    "window_end", "published_at", "activated_at", "retired_at",
                    "withdrawn_at", "suspended_at", "created_at", "ca_id",
                    "certified_by")
    RECORDED_CA = ("state", "spki", "cert", "name", "not_before", "not_after",
                   "issued", "created_at", "retired_at", "withdrawn_at")

    def _record_public_halves(self):
        """A single `record` key event for every key and Organization CA
        made before the ledger carried public keys and certificates: from
        then on the shipped ledger alone rebuilds the registry, tombstones
        included (`signer.adopt`). Legacy keys come from the policy, so they
        are not recorded."""
        if self.store.meta("public_halves_recorded") is not None:
            return
        now = self.clock.now()

        def blob(value):
            return _b64(bytes(value)) if isinstance(value, (bytes,
                                                            memoryview)) else value

        with self.store as db:
            def ids(contexts, field):
                return {r["k"] for r in db.execute(
                    "SELECT DISTINCT CAST(json_extract(summary, '$.key_id') AS "
                    "INTEGER) AS k FROM ledger WHERE kind = 'key' AND context "
                    "IN (%s) AND json_extract(summary, '$.%s') IS NOT NULL"
                    % (",".join("?" * len(contexts)), field), contexts)}

            have_spki = ids(("keygen", "hold"), "spki")
            have_leaf = ids(("install", "issue"), "leaf")
            for row in db.execute("SELECT * FROM keys WHERE legacy = 0 AND "
                                  "state != ? ORDER BY key_id",
                                  (registry.DISCARDED,)).fetchall():
                if row["key_id"] in have_spki and (
                        row["leaf"] is None or row["key_id"] in have_leaf):
                    continue
                self._key_event(db, now, "record", row["key_id"], "signer",
                                **{c: blob(row[c]) for c in self.RECORDED_KEY})
            ca_spki = ids(("ca-keygen",), "spki")
            ca_cert = ids(("ca-install",), "cert")
            for ca in db.execute("SELECT * FROM cas ORDER BY ca_id").fetchall():
                if ca["ca_id"] in ca_spki and (
                        ca["cert"] is None or ca["ca_id"] in ca_cert):
                    continue
                self._key_event(db, now, "ca-record", ca["ca_id"], "signer",
                                **{c: blob(ca[c]) for c in self.RECORDED_CA})
            self.store.set_meta(db, "public_halves_recorded", now)

    # -- plumbing ---------------------------------------------------------

    def _run(self, fn):
        """Run ``fn(db, now)`` in one transaction. A returned Refused is
        raised only after its writes are committed."""
        now = self.clock.now()
        self._local.alerts = queued = []
        try:
            with self.store as db:
                registry.expire(db, self.cfg, now)
                outcome = fn(db, now)
        finally:
            self._local.alerts = None
        # Committed and unlocked: only now is anything said outside. A
        # rolled-back transaction says nothing, since its rows are gone too.
        for severity, message, fields in queued:
            self._send(severity, message, fields)
        if isinstance(outcome, Refused):
            raise outcome
        return outcome

    def _send(self, severity, message, fields):
        try:
            self._alert_hook(severity, message, fields)
        except Exception:
            pass        # an alert that cannot be sent is still in the ledger

    def _alert(self, db, now, severity, message, **fields):
        ledger.append(db, at=now, kind="alert", context=severity,
                      summary=dict(fields, message=message))
        queued = getattr(self._local, "alerts", None)
        if queued is None:
            self._send(severity, message, fields)
        else:
            queued.append((severity, message, fields))

    def notice(self, severity, message, fields=None):
        """An alert about the signer's surroundings rather than an
        operation -- a poll-mode signer that cannot reach its site: in the
        ledger, so the daily summary counts it, then sent as every alert is.
        The signature `alerts` hooks take."""
        def run(db, now):
            self._alert(db, now, severity, message, **(fields or {}))

        self._run(run)

    def _alert_once(self, db, now, per, severity, message, **fields):
        """At most one alert, and one ledger row, per subject per window.

        A device looping over its cap is refused every time; the ledger and
        the inbox hear about it once a window, not once a request.
        """
        name = "alerted:%s:%s" % (message, per)
        last = self.store.meta(name)
        if last is not None and now - int(last) < per:
            return
        self.store.set_meta(db, name, now)
        self._alert(db, now, severity, message, **fields)

    def _key_event(self, db, now, action, key_id, by, **extra):
        ledger.append(db, at=now, kind="key", context=action,
                      summary=dict(extra, key_id=key_id, by=by, action=action))

    def _policy_window(self, db, key_id, start, end, row):
        """The window policy.toml gives a held or legacy key, against the one
        it was first given. The signer refuses to start until the policy
        says what it first said. The registry may hold a shorter end than
        the policy -- `cl03signer legacy-end`, `retire` -- but never a
        different start."""
        name = "policy_window:%d" % key_id
        said = "%d,%d" % (start, end)
        first = self.store.meta(name)
        if first is None:
            # A database from before this rule: the registry's window is the
            # first one, except an end an operator brought forward.
            ended_early = row is not None and db.execute(
                "SELECT 1 FROM ledger WHERE kind = 'key' AND context IN "
                "('legacy-end', 'retire', 'withdraw') AND CAST(json_extract("
                "summary, '$.key_id') AS INTEGER) = ?", (key_id,)
            ).fetchone() is not None
            if row is not None and (
                    row["window_start"] != start or row["window_end"] > end
                    or (row["window_end"] < end and not ended_early)):
                first = "%d,%d" % (row["window_start"], row["window_end"])
            else:
                self.store.set_meta(db, name, said)
                return
        if first != said:
            def day(ts):
                return time.strftime("%Y-%m-%d %H:%M", time.gmtime(int(ts)))
            was = [int(v) for v in first.split(",")]
            raise Refused("config", "policy.toml gives key %d the window %s "
                          "to %s, but it was first given %s to %s, and a "
                          "key's window is never changed from the policy: put "
                          "it back. To end it early: cl03signer legacy-end %d "
                          "(a legacy key) or retire %d"
                          % (key_id, day(start), day(end), day(was[0]),
                             day(was[1]), key_id, key_id))

    def _seed_legacy(self):
        now = self.clock.now()
        held_ids = {item.key_id for item in self.cfg.held}
        with self.store as db:
            for item in self.cfg.legacy:
                if item.key_id in held_ids:
                    raise Refused("config", "key %d is both held and legacy"
                                  % item.key_id)
                row = registry.get(self.store, item.key_id)
                if row is not None and (not row["legacy"]
                                        or bytes(row["spki"]) != item.spki):
                    raise Refused("config", "key %d is already another key"
                                  % item.key_id)
                self._policy_window(db, item.key_id, item.not_before,
                                    item.not_after, row)
                if row is None:
                    db.execute(
                        "INSERT INTO keys (key_id, state, spki, window_start, "
                        "window_end, legacy, created_at) "
                        "VALUES (?, ?, ?, ?, ?, 1, ?)",
                        (item.key_id, registry.LEGACY, item.spki,
                         item.not_before, item.not_after, now))

    def _seed_held(self):
        """Raw keys from `[[held]]`, seeded once as published, so that
        `cl03signer activate` makes one sign (`config.Held`). The signer does not
        start when a file is not its pinned key, or the key is not P-256, or
        an id is also legacy, or a certified deployment key already signs: a
        raw key never takes over from one, since phones that saw a
        certificate-signed bundle would refuse its bundles."""
        cfg = self.cfg
        legacy_ids = {item.key_id for item in cfg.legacy}
        now = self.clock.now()
        with self.store as db:
            for item in cfg.held:
                if item.key_id in legacy_ids:
                    raise Refused("config", "key %d is both held and legacy"
                                  % item.key_id)
                if item.key_id >= registry.FIRST_KEY_ID:
                    raise Refused("config", "a held key's id is below %d"
                                  % registry.FIRST_KEY_ID)
                row = registry.get(self.store, item.key_id)
                if row is not None:
                    if bytes(row["spki"]) != item.spki or row["legacy"]:
                        raise Refused("config", "key %d is already another "
                                      "key" % item.key_id)
                    self._policy_window(db, item.key_id, item.not_before,
                                        item.signing_until, row)
                    continue
                spki = self.keys.spki(item.key_file)
                if spki != item.spki:
                    raise Refused("config", "%s is not key %d's pinned key"
                                  % (item.key_file, item.key_id))
                public = serialization.load_der_public_key(spki)
                if not (isinstance(public, ec.EllipticCurvePublicKey)
                        and isinstance(public.curve, ec.SECP256R1)):
                    raise Refused("config", "key %d is not P-256" % item.key_id)
                if item.signing_until <= item.not_before:
                    raise Refused("config", "key %d's window is empty"
                                  % item.key_id)
                current = registry.active_key(self.store, None)
                if current is not None and current["leaf"] is not None:
                    raise Refused("config", "key %d is certified and signs; a "
                                  "raw key does not replace it"
                                  % current["key_id"])
                # A made-up certificate end, V + M after the window, so the
                # signing checks treat it as any key: credentials signed on
                # its last day outlive it by no more than a certified key's.
                db.execute(
                    "INSERT INTO keys (key_id, state, spki, key_ref, "
                    "leaf_not_before, leaf_not_after, window_start, "
                    "window_end, published_at, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (item.key_id, registry.PUBLISHED, spki, item.key_file,
                     item.not_before, item.signing_until
                     + cfg.credential_max_seconds + cfg.margin_seconds,
                     item.not_before, item.signing_until, now, now))
                self._policy_window(db, item.key_id, item.not_before,
                                    item.signing_until, None)
                self._key_event(db, now, "hold", item.key_id, "policy",
                                fingerprint=trust_mod.fingerprint(spki).hex(),
                                spki=_b64(spki), window_start=item.not_before,
                                window_end=item.signing_until)
                self._alert(db, now, "medium", "holding raw key %d, with no "
                            "certificate" % item.key_id)

    def _over(self, db, now, context, exc: ceilings.Over, *, pause_on_global):
        if exc.principal == "*:*":
            if pause_on_global:
                ceilings.pause(db, now, context, "signer",
                               "global ceiling: %s" % exc)
                self._alert(db, now, "high", "global ceiling reached; %s paused"
                            % context, context=context, window=exc.window)
                return Refused("paused", str(exc))
            self._alert_once(db, now, exc.window, "medium",
                             "global ceiling reached for %s" % context,
                             context=context, window=exc.window)
            return Refused("over_ceiling", str(exc))
        self._alert_once(db, now, exc.window, "medium",
                         "%s over its %s ceiling" % (exc.principal, context),
                         context=context, principal=exc.principal,
                         window=exc.window)
        return Refused("subject_limit", str(exc))

    # =====================================================================
    # App operations
    # =====================================================================

    def sign_credential(self, message: bytes, *, organization=None,
                        operator: str = "", holder: bool = False,
                        holder_id: str = "") -> dict:
        try:
            msg = messages.parse_credential(message)
        except messages.MessageError as exc:
            raise Refused("policy", str(exc))
        cfg = self.cfg

        def run(db, now):
            if ceilings.paused(self.store, cfgmod.CREDENTIAL):
                return Refused("paused")
            org_key = (registry.active_key(self.store, organization)
                       if organization else None)
            key = org_key or registry.active_key(self.store, None)
            if key is None:
                return Refused("no_key")
            if key["suspended_at"] is not None:
                return Refused("key_suspended", str(key["key_id"]))
            if msg.key_id != key["key_id"]:
                return Refused("key_changed", "sign with key %d" % key["key_id"],
                               key_id=key["key_id"])
            if msg.sig_alg != wire.SIG_ECDSA_P256_SHA256:
                return Refused("policy", "ECDSA P-256 only")
            if org_key is not None:
                if msg.issuer != key["certified_name"]:
                    return Refused("policy", "an organization key signs only "
                                   "its certified name")
            elif (msg.issuer and registry.name_key(msg.issuer)
                    in registry.certified_name_keys(self.store)):
                # Any spelling of it: "alpha registry" or a fullwidth one
                # reads as the certified name on a phone.
                return Refused("policy", "that issuer has its own key")
            skew = cfg.clock_skew_seconds
            if abs(msg.issued_at - now) > skew:
                return Refused("policy", "issued_at is not now")
            if not (key["window_start"] - skew <= msg.issued_at
                    <= key["window_end"] + skew):
                return Refused("key_out_of_window", str(key["key_id"]))
            if msg.expires_at - msg.issued_at > cfg.credential_max_seconds:
                return Refused("policy", "valid longer than %d days"
                               % cfg.credential_max_days)
            if msg.expires_at > key["leaf_not_after"] - cfg.margin_seconds:
                return Refused("key_out_of_window", "outlives the certificate")
            if db.execute("SELECT 1 FROM signed_credentials WHERE "
                          "credential_id = ?", (msg.credential_id,)).fetchone():
                return Refused("policy", "credential id already signed")

            principals = []
            if holder or holder_id:
                # The class, and the one person: one holder cannot spend the
                # whole holder budget.
                principals.append(("holder", "holder"))
                if holder_id:
                    principals.append(("holder_id", str(holder_id)[:64]))
            if organization:
                principals.append(("organization", str(organization)))
            if operator:
                principals.append(("operator", str(operator)))
            try:
                ceilings.check(db, cfg, now, cfgmod.CREDENTIAL, principals)
            except ceilings.Over as exc:
                return self._over(db, now, cfgmod.CREDENTIAL, exc,
                                  pause_on_global=True)

            sig = self.keys.sign(key["key_ref"], message)
            db.execute("INSERT INTO signed_credentials (credential_id, key_id, "
                       "at) VALUES (?, ?, ?)",
                       (msg.credential_id, key["key_id"], now))
            ceilings.record(db, now, cfgmod.CREDENTIAL, principals)
            ledger.append(db, at=now, kind="sign", context="credential",
                          message=message, summary={
                              "credential_id": messages.credential_id_str(
                                  msg.credential_id),
                              "document": msg.document,
                              "organization": str(organization or ""),
                              "issuer": msg.issuer, "location": msg.location,
                              "type": msg.transaction_type,
                              "operator": msg.operator, "holder": holder,
                              "key_id": key["key_id"]})
            return {"sig": _b64(sig), "key_id": key["key_id"]}

        return self._run(run)

    def bundle(self, *, device_id: bytes, device_key_hash: bytes,
               epoch_keys: list, lease_seconds: int, chains=None) -> dict:
        """A bundle for one device. `chains` is whether the app that asked
        follows issuer certificates (verify passes what the phone said in
        this request; None when the phone did not say): the switch gate
        counts a phone ready for a certified deployment key only if it does
        (`registry.activation_gate`)."""
        if not device_id or len(device_id) > 255:
            raise Refused("policy", "device id")
        # Named apart from the trust list's `chains` below, which would
        # otherwise stand in for it.
        follows_chains = None if chains is None else bool(chains)
        if len(epoch_keys) > MAX_EPOCH_KEYS:
            raise Refused("policy", "too many epoch keys")
        wrapped = []
        for k in epoch_keys:
            blob = base64.b64decode(k["wrapped"])
            if k["tier"] not in (0, 1) or len(blob) > MAX_WRAPPED:
                raise Refused("policy", "epoch key")
            wrapped.append(bundle_mod.WrappedEpochKey(
                int(k["epoch"]), int(k["tier"]), int(k["not_before"]),
                int(k["not_after"]), blob))
        cfg = self.cfg

        def run(db, now):
            if ceilings.paused(self.store, cfgmod.BUNDLE):
                return Refused("paused")
            refused = self._revocations_refused()
            if refused:
                return refused
            key = registry.active_key(self.store, None)
            if key is None:
                return Refused("no_key")
            lease = max(0, min(int(lease_seconds), cfg.lease_seconds,
                               bundle_mod.MAX_LEASE_SECONDS))
            if lease < cfgmod.MIN_LEASE_SECONDS:
                # Over on arrival, or nearly: a phone holding it is guarded
                # by continuity for no sync at all.
                return Refused("policy", "a lease of %d s is under %d s"
                               % (lease, cfgmod.MIN_LEASE_SECONDS))
            if now + lease > registry.infrastructure_until(
                    cfg, key["leaf_not_after"]):
                return Refused("key_out_of_window", "bundles")
            if now > key["window_end"]:
                # A phone holding a bundle issued after the signer's window
                # closed refuses every later one it signs, until the lease
                # runs out (continuity, ovcrypto/trust.py): a missed switch
                # stops bundles here, loudly, rather than there.
                self._alert_once(db, now, cfgmod.DAY, "high",
                                 "key %d's window ended; no bundle is signed "
                                 "until another key is activated"
                                 % key["key_id"], key_id=key["key_id"])
                return Refused("key_out_of_window", "bundles: key %d's window "
                               "ended" % key["key_id"])
            principals = [("device", device_id.hex())]
            try:
                ceilings.check(db, cfg, now, cfgmod.BUNDLE, principals)
            except ceilings.Over as exc:
                return self._over(db, now, cfgmod.BUNDLE, exc,
                                  pause_on_global=False)
            try:
                entries, chains = registry.trust_list(self.store, cfg, now)
            except registry.RegistryError as exc:
                self._alert(db, now, "high", str(exc))
                return Refused("trust_list_full")
            if len(entries) >= cfg.trust_list_alert_at:
                self._alert(db, now, "medium", "trust list has %d keys"
                            % len(entries))
            ids = [r["credential_id"] for r in db.execute(
                "SELECT credential_id FROM revoked")]
            # The chains go beside the bundle, relayed by verify; their digest
            # goes inside it, so a phone refuses the bundle whole if one is
            # dropped or changed on the way, rather than losing that key.
            digest = chain.chains_digest(chains)
            b = bundle_mod.Bundle(
                device_id=device_id, issued_at=now, not_before=now,
                not_after=now + lease, epoch_keys=wrapped,
                trust=entries + [bundle_mod.chains_entry(digest)],
                revocation=revocation.build(ids).to_bytes())
            b.sign(_KeySigner(self.keys, key))
            ceilings.record(db, now, cfgmod.BUNDLE, principals)
            listed = "|" + "|".join(str(t.key_id) for t in entries
                                    if not t.is_tombstone) + "|"
            ledger.append(db, at=now, kind="sign", context="bundle",
                          message=b.signed_bytes(), summary={
                              "device": device_id.hex(),
                              "device_key": device_key_hash.hex(),
                              "keys": listed, "not_after": b.not_after,
                              "key_id": key["key_id"],
                              "chains": follows_chains,
                              "chains_digest": digest.hex()})
            return {"bundle": _b64(b.pack()),
                    "issuer_chains": chain.encode_chains(chains),
                    "not_after": b.not_after, "key_id": key["key_id"]}

        return self._run(run)

    def put_revoked(self, credential_ids) -> dict:
        """verify's whole revoked set. The ids not held yet are added, at
        most `revocation_growth_per_call` of them a call, lowest first, and
        `remaining` says how many wait for the next call. Over the cap, and
        over `revocation_alert_per_day` added in a day, is a high alert, so
        growth is never silent."""
        ids = {bytes(c) for c in credential_ids}
        if any(len(c) != 16 for c in ids):
            raise Refused("policy", "a credential id is 16 bytes")
        cfg = self.cfg

        def run(db, now):
            held = {r["credential_id"] for r in
                    db.execute("SELECT credential_id FROM revoked")}
            pending = sorted(ids - held)
            missing = held - ids
            new = pending[:cfg.revocation_growth_per_call]
            # Said once an hour or a day, so the message is the same each
            # time; the counts are in the fields.
            if len(pending) > len(new):
                self._alert_once(db, now, 3600, "high",
                                 "verify sent more new revocations than the "
                                 "signer takes in one call (%d); the rest "
                                 "come with the next calls"
                                 % cfg.revocation_growth_per_call,
                                 pending=len(pending), per_call=len(new))
            db.executemany("INSERT INTO revoked (credential_id, added_at) "
                           "VALUES (?, ?)", [(c, now) for c in new])
            today = db.execute("SELECT COUNT(*) AS n FROM revoked WHERE "
                               "added_at > ?", (now - cfgmod.DAY,)
                               ).fetchone()["n"]
            if new and today > cfg.revocation_alert_per_day:
                self._alert_once(db, now, cfgmod.DAY, "high",
                                 "over %d revocations added in a day"
                                 % cfg.revocation_alert_per_day, day=today)
            if missing:
                # Kept, never dropped: there is no un-revoke, and a restored
                # database must not freeze revocation for good.
                self._alert(db, now, "high", "verify's revoked set is missing "
                            "%d ids the signer holds" % len(missing))
            # How many still wait: no bundle or feed is built while any do,
            # since one from part of the set would have phones forget ids
            # they hold (after a rebuild) or miss new ones
            # (`_revocations_refused`).
            self.store.set_meta(db, "revocations_waiting",
                                len(pending) - len(new))
            self.store.set_meta(db, "revocations_received", now)
            if new:
                ledger.append(db, at=now, kind="admin", context="revocation",
                              summary={"added": len(new),
                                       "total": len(held) + len(new)})
            return {"added": len(new), "remaining": len(pending) - len(new),
                    "missing": len(missing), "total": len(held) + len(new)}

        return self._run(run)

    def _revocations_refused(self):
        """None once verify's whole revoked set is here; a refusal before it
        first arrives, or while part of a set still waits."""
        if self.store.meta("revocations_received") is None:
            return Refused("no_revocations")
        if int(self.store.meta("revocations_waiting", 0) or 0):
            return Refused("revocations_incomplete", "verify is still sending "
                           "the revoked set")
        return None

    def _artifact(self, db, kind, content_key):
        return db.execute("SELECT * FROM artifacts WHERE kind = ? AND "
                          "content_key = ?", (kind, content_key)).fetchone()

    def _latest(self, db, kind):
        return db.execute("SELECT * FROM artifacts WHERE kind = ? ORDER BY "
                          "issued_at DESC LIMIT 1", (kind,)).fetchone()

    def _store_artifact(self, db, kind, content_key, body):
        db.execute("DELETE FROM artifacts WHERE kind = ?", (kind,))
        db.execute("INSERT INTO artifacts (kind, content_key, issued_at, "
                   "not_after, key_id, body) VALUES (?, ?, ?, ?, ?, ?)",
                   (kind, content_key, body["issued_at"], body["not_after"],
                    body.get("key_id", body.get("sig_key_id")),
                    json.dumps(body)))

    def feed(self) -> dict:
        cfg = self.cfg

        def run(db, now):
            if ceilings.paused(self.store, cfgmod.REVOCATION):
                latest = self._latest(db, "feed")
                return (json.loads(latest["body"]) if latest
                        else Refused("paused"))
            refused = self._revocations_refused()
            if refused:
                return refused
            key = registry.active_key(self.store, None)
            if key is None:
                return Refused("no_key")
            ids = sorted(r["credential_id"] for r in
                         db.execute("SELECT credential_id FROM revoked"))
            content = "%s:%d" % (hashlib.sha256(b"".join(ids)).hexdigest(),
                                 key["key_id"])
            held = self._artifact(db, "feed", content)
            if held is not None and now - held["issued_at"] < cfg.feed_resign_seconds:
                return json.loads(held["body"])
            latest = self._latest(db, "feed")
            if (held is None and latest is not None
                    and now - latest["issued_at"] < cfg.feed_min_interval_seconds
                    and latest["key_id"] == key["key_id"]):
                return json.loads(latest["body"])
            try:
                ceilings.check(db, cfg, now, cfgmod.REVOCATION, [])
            except ceilings.Over as exc:
                outcome = self._over(db, now, cfgmod.REVOCATION, exc,
                                     pause_on_global=False)
                return json.loads(latest["body"]) if latest else outcome
            not_after = min(now + cfg.revocation_ttl_seconds,
                            registry.infrastructure_until(
                                cfg, key["leaf_not_after"]))
            blob = revocation.build(ids).to_bytes()
            signed = messages.feed_signed_bytes(now, not_after, key["key_id"],
                                                blob)
            sig = self.keys.sign(key["key_ref"], signed)
            body = {"format": "CL03RL", "version": messages.FEED_VERSION,
                    "issued_at": now, "not_after": not_after,
                    "key_id": key["key_id"], "filter": _b64(blob),
                    "sig": _b64(sig)}
            self._store_artifact(db, "feed", content, body)
            ceilings.record(db, now, cfgmod.REVOCATION, [])
            ledger.append(db, at=now, kind="sign", context="revocation",
                          message=signed, summary={"count": len(ids),
                                                   "key_id": key["key_id"]})
            return body

        return self._run(run)

    def statement(self, *, log_key_id: int, public_key: bytes) -> dict:
        if len(public_key) != 32:
            raise Refused("policy", "a log key is 32 bytes")
        if not isinstance(log_key_id, int) or not 0 <= log_key_id < U32:
            raise Refused("policy", "a log key id is a 32-bit number")
        fingerprint = hashlib.sha256(public_key).hexdigest()
        cfg = self.cfg

        def run(db, now):
            if ceilings.paused(self.store, cfgmod.LOG_KEY):
                latest = self._latest(db, "statement")
                return (json.loads(latest["body"]) if latest
                        else Refused("paused"))
            key = registry.active_key(self.store, None)
            if key is None:
                return Refused("no_key")
            content = "%d:%s:%d" % (log_key_id, public_key.hex(),
                                    key["key_id"])
            held = self._artifact(db, "statement", content)
            if (held is not None
                    and now - held["issued_at"] < cfg.statement_resign_seconds):
                return json.loads(held["body"])
            # Each log key id names one public key, for good: the same id
            # with another key is somebody trying to have phones seal their
            # logs to a key verify never made.
            seen = json.loads(self.store.meta("log_keys_seen", "{}"))
            if isinstance(seen, list):
                seen = {str(i): None for i in seen}
            known = seen.get(str(log_key_id), "")
            if known and known != fingerprint:
                self._alert(db, now, "high", "log key %d offered with another "
                            "public key" % log_key_id, log_key_id=log_key_id,
                            fingerprint=fingerprint)
                return Refused("policy", "log key %d is another key"
                               % log_key_id)
            if known != fingerprint:
                if not known and str(log_key_id) not in seen:
                    self._alert(db, now, "medium", "a new log key, id %d"
                                % log_key_id, log_key_id=log_key_id,
                                fingerprint=fingerprint)
                seen[str(log_key_id)] = fingerprint
                self.store.set_meta(db, "log_keys_seen",
                                    json.dumps(seen, sort_keys=True))
            try:
                ceilings.check(db, cfg, now, cfgmod.LOG_KEY, [])
            except ceilings.Over as exc:
                latest = self._latest(db, "statement")
                outcome = self._over(db, now, cfgmod.LOG_KEY, exc,
                                     pause_on_global=False)
                return json.loads(latest["body"]) if latest else outcome
            not_after = min(now + cfg.statement_days * cfgmod.DAY,
                            key["leaf_not_after"] - cfg.margin_seconds)
            signed = devicelog.key_statement_bytes(log_key_id, public_key, now,
                                                   not_after, key["key_id"])
            sig = self.keys.sign(key["key_ref"], signed)
            body = {"format": devicelog.KEY_MAGIC.decode(),
                    "version": devicelog.KEY_VERSION, "key_id": log_key_id,
                    "public_key": _b64(public_key), "issued_at": now,
                    "not_after": not_after, "sig_key_id": key["key_id"],
                    "sig": _b64(sig)}
            self._store_artifact(db, "statement", content, body)
            ceilings.record(db, now, cfgmod.LOG_KEY, [])
            ledger.append(db, at=now, kind="sign", context="log-key",
                          message=signed, summary={"log_key_id": log_key_id,
                                                   "key_id": key["key_id"]})
            return body

        return self._run(run)

    def log_ack(self, *, device_id: bytes, through_seq: int,
                digest: bytes) -> dict:
        """verify's signed word that it holds a phone's log records up to
        `through_seq` of one upload.

        Signed with the key that signs statements, which the phone's bundle
        lists for exactly this kind of thing; the phone deletes records only
        once one covers them. Nothing here can check verify really stored
        them -- the point is that only verify, through this socket, can say
        so, and not whoever answers for the site's host. Each is a ledger row,
        under a per-device ceiling.
        """
        if len(device_id) != 16:
            raise Refused("policy", "a device id is 16 bytes")
        if len(digest) != 32:
            raise Refused("policy", "an upload digest is 32 bytes")
        if (isinstance(through_seq, bool) or not isinstance(through_seq, int)
                or not 0 <= through_seq < 2 ** 63):
            raise Refused("policy", "through_seq is out of range")
        cfg = self.cfg

        def run(db, now):
            if ceilings.paused(self.store, cfgmod.LOG_ACK):
                return Refused("paused")
            key = registry.active_key(self.store, None)
            if key is None:
                return Refused("no_key")
            principals = [("device", device_id.hex())]
            try:
                ceilings.check(db, cfg, now, cfgmod.LOG_ACK, principals)
            except ceilings.Over as exc:
                return self._over(db, now, cfgmod.LOG_ACK, exc,
                                  pause_on_global=False)
            signed = devicelog.ack_signed_bytes(device_id, through_seq, digest,
                                                now, key["key_id"])
            sig = self.keys.sign(key["key_ref"], signed)
            ceilings.record(db, now, cfgmod.LOG_ACK, principals)
            ledger.append(db, at=now, kind="sign", context="log-ack",
                          message=signed,
                          summary={"device": device_id.hex(),
                                   "through_seq": through_seq,
                                   "key_id": key["key_id"]})
            return {"format": devicelog.ACK_MAGIC.decode(),
                    "version": devicelog.ACK_VERSION, "issued_at": now,
                    "sig_key_id": key["key_id"], "sig": _b64(sig)}

        return self._run(run)

    def sync_time(self, *, device_id: bytes, nonce: bytes) -> dict:
        """This signer's time at a phone's sync, over the nonce the phone made
        for it.

        The one time a phone brings its clock's high-water mark back to. Over
        the phone's own nonce because a bundle, and verify's challenge, can be
        held back from one sync and served at another by whoever answers for
        the site's host. Signed with the key that signs statements, as
        `log_ack` is; the time is this host's. A ledger row each, under a
        per-device ceiling; over it, verify leaves the time out and the phone
        leaves its mark alone.
        """
        if len(device_id) != 16:
            raise Refused("policy", "a device id is 16 bytes")
        if len(nonce) != devicelog.TIME_NONCE_BYTES:
            raise Refused("policy", "a sync nonce is %d bytes"
                          % devicelog.TIME_NONCE_BYTES)
        cfg = self.cfg

        def run(db, now):
            if ceilings.paused(self.store, cfgmod.SYNC_TIME):
                return Refused("paused")
            key = registry.active_key(self.store, None)
            if key is None:
                return Refused("no_key")
            principals = [("device", device_id.hex())]
            try:
                ceilings.check(db, cfg, now, cfgmod.SYNC_TIME, principals)
            except ceilings.Over as exc:
                return self._over(db, now, cfgmod.SYNC_TIME, exc,
                                  pause_on_global=False)
            signed = devicelog.time_signed_bytes(device_id, nonce, now,
                                                 key["key_id"])
            sig = self.keys.sign(key["key_ref"], signed)
            ceilings.record(db, now, cfgmod.SYNC_TIME, principals)
            ledger.append(db, at=now, kind="sign", context="sync-time",
                          message=signed,
                          summary={"device": device_id.hex(),
                                   "key_id": key["key_id"]})
            return {"format": devicelog.TIME_MAGIC.decode(),
                    "version": devicelog.TIME_VERSION, "issued_at": now,
                    "sig_key_id": key["key_id"], "sig": _b64(sig)}

        return self._run(run)

    def pause(self, context: str, *, by: str = "app", reason: str = "") -> dict:
        def run(db, now):
            try:
                ceilings.pause(db, now, context, by, reason)
            except ValueError as exc:
                return Refused("policy", str(exc))
            self._alert(db, now, "high", "%s paused by %s" % (context, by),
                        context=context, reason=reason)
            return {"paused": context}

        return self._run(run)

    def suspend(self, key_id: int, *, by: str = "app",
                operator=None) -> dict:
        """Stop a key's credentials at once. `operator`: the site admin who
        asked from verify's pages, named in the ledger and the alert as the
        other site operations name theirs. A suspension is never refused
        for the name: one that cannot be recorded as it is, is said so."""
        if operator is not None and self._operator_refused(operator):
            operator = "(a site admin whose name could not be recorded)"

        def run(db, now):
            row = registry.get(self.store, key_id)
            if row is None or row["state"] not in (registry.ACTIVE,
                                                   registry.PUBLISHED):
                return Refused("policy", "only a published or active key")
            db.execute("UPDATE keys SET suspended_at = COALESCE(suspended_at, ?) "
                       "WHERE key_id = ?", (now, key_id))
            if operator is None:
                self._key_event(db, now, "suspend", key_id, by)
                self._alert(db, now, "high", "key %d suspended by %s"
                            % (key_id, by))
            else:
                self._key_event(db, now, "suspend", key_id, by,
                                operator=operator)
                self._alert(db, now, "high", "key %d suspended from verify by "
                            "%s" % (key_id, operator),
                            organization=row["organization"] or "")
            return {"suspended": key_id}

        return self._run(run)

    def install_cert(self, key_id: int, leaf_der: bytes, *,
                     by: str = "app") -> dict:
        cfg = self.cfg

        def run(db, now):
            row = registry.get(self.store, key_id)
            if row is None or row["legacy"]:
                return Refused("unknown_key", str(key_id))
            if row["state"] not in (registry.GENERATED, registry.CERTIFIED):
                return Refused("policy", "key %d is %s" % (key_id, row["state"]))
            if self._publish_pending(db, now, key_id):
                return Refused("policy", "key %d has a publish waiting for a "
                               "second operator; its certificate cannot "
                               "change now" % key_id)
            try:
                got = chain.validate(leaf_der, cfg.anchors, now)
            except chain.ChainError as exc:
                return Refused("certificate", exc.reason)
            if got.spki != bytes(row["spki"]):
                return Refused("certificate", "not this key's certificate")
            if row["organization"]:
                if got.classes != {chain.CREDENTIAL}:
                    return Refused("certificate", "an organization key is "
                                   "credential-only")
                if got.organization_id != row["organization"]:
                    return Refused("certificate", "another organization's id")
                if _bad_name(got.organization):
                    # The rule org_generate applies to a name it certifies,
                    # held to a certificate the PKI made.
                    return Refused("certificate", "O is not 1 to %d printable "
                                   "characters, unpadded, in one script"
                                   % CERTIFIED_NAME_MAX)
                refused = self._name_refused(db, now, got.organization,
                                             row["organization"], by)
                if refused:
                    return refused
            elif got.classes != {chain.INFRASTRUCTURE, chain.CREDENTIAL}:
                return Refused("certificate", "the deployment key needs the "
                               "infrastructure and the credential EKU")
            until = registry.signing_until(cfg, got.not_after)
            if until < now + cfg.min_signing_days * cfgmod.DAY:
                return Refused("certificate", "leaves under %d days of signing"
                               % cfg.min_signing_days)
            db.execute("UPDATE keys SET state = ?, leaf = ?, certified_name = ?, "
                       "leaf_not_before = ?, leaf_not_after = ?, "
                       "window_start = ?, window_end = ?, ca_id = NULL, "
                       "certified_by = ? WHERE key_id = ?",
                       (registry.CERTIFIED, leaf_der, got.organization,
                        got.not_before, got.not_after, got.not_before, until,
                        got.ca_name, key_id))
            self._key_event(db, now, "install", key_id, by,
                            fingerprint=hashlib.sha256(leaf_der).hexdigest(),
                            leaf=_b64(leaf_der), certified_name=got.organization,
                            certified_by=got.ca_name,
                            leaf_not_before=got.not_before,
                            leaf_not_after=got.not_after, window_end=until)
            self._alert(db, now, "medium", "certificate installed for key %d"
                        % key_id)
            return {"key_id": key_id, "state": registry.CERTIFIED,
                    "signing_until": until}

        return self._run(run)

    # -- organization keys, from verify's pages ---------------------------
    #
    # A site admin may have the signer make an organization key and either
    # certify it at once with the Organization CA (`org_generate`) or hand
    # back its request for the PKI (`org_keygen`, then `install_cert`). Both
    # make a key that is certified at most: publishing it takes two operators
    # on the host, unless the host lets the site publish (`org_publish`,
    # `org_activate`). One key may wait per organization, and the app may
    # have only so many made a day.

    def _app_may_make_a_key(self, db, now, organization):
        if registry.waiting_key(self.store, organization) is not None:
            return Refused("policy", "a key already waits for this "
                           "organization; publish or discard it first")
        made = db.execute(
            "SELECT COUNT(*) AS n FROM ledger WHERE kind = 'key' AND "
            "context = 'keygen' AND json_extract(summary, '$.by') = 'app' "
            "AND at >= ?", (now - cfgmod.DAY,)).fetchone()["n"]
        if made >= self.cfg.app_keys_per_day:
            self._alert_once(db, now, cfgmod.DAY, "high",
                             "verify asked for over %d keys in a day"
                             % self.cfg.app_keys_per_day)
            return Refused("ceiling", "%d keys a day" % self.cfg.app_keys_per_day)
        return None

    def _new_key(self, db, now, organization, by):
        key_id = registry.allocate_key_id(db)
        key_ref, spki = self.keys.generate(key_id)
        db.execute("INSERT INTO keys (key_id, organization, state, spki, "
                   "key_ref, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                   (key_id, organization, registry.GENERATED, spki, key_ref,
                    now))
        self._key_event(db, now, "keygen", key_id, by,
                        organization=organization or "", spki=_b64(spki))
        return key_id, key_ref, spki

    def org_keygen(self, *, organization, by: str = "app") -> dict:
        """A key for `organization` and its request for the PKI."""
        organization = str(uuid.UUID(str(organization)))

        def run(db, now):
            refused = self._app_may_make_a_key(db, now, organization)
            if refused:
                return refused
            key_id, key_ref, _ = self._new_key(db, now, organization, by)
            csr = self._request_or_destroy(
                key_ref, "OfflineVerifier signing key %d" % key_id)
            self._alert(db, now, "medium", "key %d made for an organization "
                        "by %s, for the PKI" % (key_id, by),
                        organization=organization)
            return {"key_id": key_id, "csr": csr}

        return self._run(run)

    def org_generate(self, *, organization, name, by: str = "app") -> dict:
        """A key for `organization`, certified at once by the Organization CA
        under `name`: the O phones will show, as verify has it now."""
        organization = str(uuid.UUID(str(organization)))
        if _bad_name(name):
            raise Refused("policy", "an organization name of 1 to %d "
                          "printable characters, without spaces at either end"
                          " and in one script" % CERTIFIED_NAME_MAX)
        cfg = self.cfg

        def run(db, now):
            ca = registry.current_ca(self.store)
            if ca is None:
                return Refused("no_organization_ca")
            if not cfg.site_domain:
                return Refused("organization_ca", "site_domain is not set in "
                               "policy.toml, so no phone could trust what it "
                               "issues")
            if now > registry.issue_until(cfg, ca["not_after"]):
                return Refused("organization_ca", "it ends too soon to leave "
                               "%d days of signing; install its successor"
                               % cfg.min_signing_days)
            refused = self._app_may_make_a_key(db, now, organization)
            if refused:
                return refused
            refused = self._name_refused(db, now, name, organization, by)
            if refused:
                return refused
            key_id, key_ref, spki = self._new_key(db, now, organization, by)
            ca_cert = bytes(ca["cert"])
            try:
                leaf = self.keys.certify(
                    ca["key_ref"], ca_cert, spki,
                    not_before=now - cfg.clock_skew_seconds,
                    not_after=min(now + cfg.organization_leaf_days * cfgmod.DAY,
                                  ca["not_after"]),
                    organization=name, organization_id=organization)
                # The phone's own check, before anything is kept: a phone
                # paired with this site, over HTTPS.
                got = chain.validate(leaf, cfg.anchors, now, [ca_cert],
                                     cfg.site_domain)
            except chain.ChainError as exc:
                # Raised, not returned: the key's row must roll back too.
                self.keys.destroy(key_ref)
                if exc.reason == "intermediate_domain":
                    raise Refused("organization_ca", "it is not for %s, the "
                                  "site phones pair with; install a System CA "
                                  "for it" % cfg.site_domain)
                raise Refused("organization_ca", "what it issues fails the "
                              "phone's check: %s" % exc.reason)
            except Exception:
                self.keys.destroy(key_ref)
                raise
            until = registry.signing_until(cfg, got.not_after)
            if until < now + cfg.min_signing_days * cfgmod.DAY:
                # install_cert's rule: raised, so the key's row rolls back.
                self.keys.destroy(key_ref)
                raise Refused("organization_ca", "a certificate of %d days "
                              "leaves under %d days of signing; check "
                              "organization_leaf_days"
                              % (cfg.organization_leaf_days,
                                 cfg.min_signing_days))
            db.execute("UPDATE keys SET state = ?, leaf = ?, certified_name = ?, "
                       "leaf_not_before = ?, leaf_not_after = ?, "
                       "window_start = ?, window_end = ?, ca_id = ?, "
                       "certified_by = ? WHERE key_id = ?",
                       (registry.CERTIFIED, leaf, got.organization,
                        got.not_before, got.not_after, got.not_before, until,
                        ca["ca_id"], got.ca_name, key_id))
            db.execute("UPDATE cas SET issued = issued + 1 WHERE ca_id = ?",
                       (ca["ca_id"],))
            self._key_event(db, now, "issue", key_id, by, ca_id=ca["ca_id"],
                            name=name, organization=organization,
                            fingerprint=hashlib.sha256(leaf).hexdigest(),
                            leaf=_b64(leaf), certified_name=got.organization,
                            certified_by=got.ca_name,
                            leaf_not_before=got.not_before,
                            leaf_not_after=got.not_after, window_end=until)
            self._alert(db, now, "medium", "Organization CA %d certified key "
                        "%d as %r, asked by %s" % (ca["ca_id"], key_id, name, by),
                        organization=organization)
            return {"key_id": key_id, "state": registry.CERTIFIED,
                    "signing_until": until, "certified_by": got.ca_name}

        return self._run(run)

    def csr(self, key_id: int) -> dict:
        """The request for an organization key still waiting for the PKI."""
        row = registry.get(self.store, key_id)
        if (row is None or row["state"] != registry.GENERATED
                or not row["organization"] or not row["key_ref"]):
            raise Refused("policy", "only an organization key waiting for its "
                          "certificate has a request")
        return {"key_id": key_id,
                "csr": self.keys.csr(row["key_ref"], "OfflineVerifier signing "
                                     "key %d" % key_id).decode()}

    def discard(self, key_id: int, *, by: str = "app") -> dict:
        """Destroy an organization key that was never published."""
        def run(db, now):
            row = registry.get(self.store, key_id)
            if row is None or row["legacy"]:
                return Refused("unknown_key", str(key_id))
            if not row["organization"] and by == "app":
                return Refused("policy", "the deployment's own keys are "
                               "discarded on the signer host")
            if row["state"] not in (registry.GENERATED, registry.CERTIFIED):
                return Refused("policy", "only a key that is not yet published "
                               "can be discarded")
            if self._publish_pending(db, now, key_id):
                return Refused("policy", "key %d has a publish waiting for a "
                               "second operator" % key_id)
            db.execute("UPDATE keys SET state = ?, key_ref = NULL "
                       "WHERE key_id = ?", (registry.DISCARDED, key_id))
            if row["key_ref"]:
                self.keys.destroy(row["key_ref"])
            self._key_event(db, now, "discard", key_id, by)
            self._alert(db, now, "low", "key %d discarded by %s" % (key_id, by))
            return {"discarded": key_id}

        return self._run(run)

    # -- publishing an organization key from verify's pages ----------------
    #
    # Only where policy.toml sets `site_publishes_organization_keys`. One
    # site admin then does what two operators do on the host, for an
    # organization's key and nothing else: the deployment's own keys, every
    # withdrawal and the Organization CA stay on the host. Each step names
    # the admin who asked, in the ledger and in a high alert, since what it
    # changes is the name every phone shows.

    @staticmethod
    def _operator_refused(operator):
        """None, or a Refused for a site admin's name that cannot be put in
        the ledger and an alert as it is."""
        if (not isinstance(operator, str) or not operator.strip()
                or len(operator) > OPERATOR_MAX or _breaks_lines(operator)):
            return Refused("policy", "the site admin who asked is named")
        return None

    def _held(self, row) -> bool:
        """A `[[held]]` key: the policy's, as a legacy key is."""
        return row["key_id"] in {held.key_id for held in self.cfg.held}

    def _policy_key_refused(self, row, key_id):
        """None, or a Refused for a key the site may never move: unknown,
        legacy, or held. Those two come from policy.toml and change only
        there, with two operators."""
        if row is None or row["legacy"]:
            return Refused("unknown_key", str(key_id))
        if self._held(row):
            return Refused("policy", "key %d is held under policy.toml; it "
                           "changes only on the signer host" % key_id)
        return None

    def _site_key(self, key_id, operator):
        """The key a site admin may publish or start, or a Refused: an
        organization's, where the policy sets
        `site_publishes_organization_keys`; any but a legacy or held key,
        the deployment's included, where it sets `site_controls_all_keys`."""
        everything = self.cfg.site_controls_all_keys
        if not (self.cfg.site_publishes_organization_keys or everything):
            return Refused("policy", "organization keys are published on the "
                           "signer host here")
        refused = self._operator_refused(operator)
        if refused:
            return refused
        row = registry.get(self.store, key_id)
        if row is None or row["legacy"]:
            return Refused("unknown_key", str(key_id))
        if not row["organization"] and not everything:
            return Refused("policy", "the deployment's own keys are published "
                           "on the signer host")
        return self._policy_key_refused(row, key_id) or row

    def _site_controls(self, operator):
        """None, or a Refused, for what only `site_controls_all_keys` lets
        the site do: withdraw, unsuspend, resume."""
        if not self.cfg.site_controls_all_keys:
            return Refused("policy", "keys are withdrawn and unsuspended, and "
                           "signing resumed, on the signer host here")
        return self._operator_refused(operator)

    def _for_this_site(self, row, now):
        """None, or a Refused for a key whose Organization CA is not for
        `site_domain`: phones paired with this site would drop it, so
        publishing or starting it would only fail its organization's
        documents. Keys the PKI certified directly have no such CA."""
        if not row["ca_id"] or not row["leaf"]:
            return None
        ca = self.store.one("SELECT cert FROM cas WHERE ca_id = ?",
                            (row["ca_id"],))
        if ca is None or not ca["cert"]:
            return Refused("organization_ca", "key %d's Organization CA is "
                           "gone" % row["key_id"])
        try:
            chain.validate(bytes(row["leaf"]), self.cfg.anchors, now,
                           [bytes(ca["cert"])], self.cfg.site_domain)
        except chain.ChainError as exc:
            if exc.reason == "intermediate_domain":
                return Refused("organization_ca", "key %d was certified by a "
                               "CA that is not for %s, the site phones pair "
                               "with, so they would drop it; generate a new "
                               "key" % (row["key_id"], self.cfg.site_domain
                                        or "this site"))
            return Refused("certificate", "key %d's certificate fails the "
                           "phone's check: %s" % (row["key_id"], exc.reason))
        return None

    def _name_refused(self, db, now, name, organization, by):
        """Refuse, and alert, when another organization's key holds `name`:
        phones would show the two identically. Checked where a name is
        certified -- here and on an installed certificate -- and again on the
        site's publish, in case the name was taken since."""
        other = registry.name_held_by_another(self.store, name, organization)
        if other is None:
            return None
        self._alert(db, now, "high", "refused to give organization %s the "
                    "name %r: key %d of organization %s holds it (asked by %s)"
                    % (organization, name, other["key_id"],
                       other["organization"], by),
                    organization=organization)
        return Refused("policy", "another organization's key (%d) already "
                       "carries the name %r; phones could not tell them apart"
                       % (other["key_id"], other["certified_name"]))

    def org_publish(self, key_id: int, *, operator: str,
                    by: str = "app") -> dict:
        """Publish an organization's certified key -- or, where the policy
        sets `site_controls_all_keys`, a deployment key: phones get it at
        their next sync, and nothing is signed with it yet."""
        def run(db, now):
            row = self._site_key(key_id, operator)
            if isinstance(row, Refused):
                return row
            if row["state"] != registry.CERTIFIED:
                return Refused("policy", "only a certified key can be published")
            refused = self._for_this_site(row, now)
            if refused:
                return refused
            if row["organization"]:
                refused = self._name_refused(db, now, row["certified_name"],
                                             row["organization"], by)
                if refused:
                    return refused
            db.execute("UPDATE keys SET state = ?, published_at = ? "
                       "WHERE key_id = ?", (registry.PUBLISHED, now, key_id))
            self._key_event(db, now, "publish", key_id, by, operator=operator,
                            name=row["certified_name"],
                            organization=row["organization"],
                            fingerprint=hashlib.sha256(
                                bytes(row["leaf"])).hexdigest())
            if row["organization"]:
                self._alert(db, now, "high", "key %d published from verify by "
                            "%s; phones will show %r"
                            % (key_id, operator, row["certified_name"]),
                            organization=row["organization"])
            else:
                self._alert(db, now, "high", "deployment key %d published "
                            "from verify by %s; phones list it at their next "
                            "sync" % (key_id, operator))
            return {"published": key_id}

        return self._run(run)

    def org_activate(self, key_id: int, *, operator: str,
                     by: str = "app") -> dict:
        """Start an organization's published key signing -- or, where the
        policy sets `site_controls_all_keys`, a deployment key -- through the
        same gate as the host's `activate`."""
        def run(db, now):
            row = self._site_key(key_id, operator)
            if isinstance(row, Refused):
                return row
            return self._activate(db, now, row, by, operator=operator)

        return self._run(run)

    # -- every key from verify's pages ---------------------------------------
    #
    # Only where policy.toml sets `site_controls_all_keys`: one site admin
    # does at once what is otherwise an operator's on the host, or two
    # operators'. Each names the admin in the ledger and in a high alert. What
    # it costs is said in config.py: the app can stop every phone's sync, and
    # withdraw a key -- which phones then refuse for every credential it ever
    # signed, for good -- though it still cannot make a key. Legacy and held
    # keys stay the policy's.

    def site_withdraw(self, key_id: int, *, operator: str,
                      by: str = "app") -> dict:
        """Withdraw a listed key immediately, with no second operator.
        Final, as `cl03signer withdraw` and its confirmation are."""
        def run(db, now):
            refused = self._site_controls(operator)
            if refused:
                return refused
            row = registry.get(self.store, key_id)
            refused = self._policy_key_refused(row, key_id)
            if refused:
                return refused
            if row["state"] in (registry.GENERATED, registry.CERTIFIED):
                return Refused("policy", "key %d was never published: discard "
                               "it instead" % key_id)
            if row["state"] not in (registry.PUBLISHED, registry.ACTIVE,
                                    registry.RETIRED):
                return Refused("policy", "key %d is %s" % (key_id,
                                                           row["state"]))
            return self._do_withdraw(db, now, key_id, by, operator=operator)

        return self._run(run)

    def site_unsuspend(self, key_id: int, *, operator: str,
                       by: str = "app") -> dict:
        """Lift a suspension, as `cl03signer unsuspend` does, and say so."""
        def run(db, now):
            refused = self._site_controls(operator)
            if refused:
                return refused
            row = registry.get(self.store, key_id)
            refused = self._policy_key_refused(row, key_id)
            if refused:
                return refused
            if row["suspended_at"] is None:
                return Refused("policy", "key %d is not suspended" % key_id)
            db.execute("UPDATE keys SET suspended_at = NULL WHERE key_id = ?",
                       (key_id,))
            self._key_event(db, now, "unsuspend", key_id, by,
                            operator=operator)
            self._alert(db, now, "high", "key %d unsuspended from verify by %s"
                        % (key_id, operator),
                        organization=row["organization"] or "")
            return {"unsuspended": key_id}

        return self._run(run)

    def site_resume(self, context: str, *, operator: str,
                    by: str = "app") -> dict:
        """Lift a pause -- the app's, an operator's, or the global ceiling's
        -- as `cl03signer resume` does, and say so."""
        def run(db, now):
            refused = self._site_controls(operator)
            if refused:
                return refused
            if context != ceilings.ALL and context not in cfgmod.CONTEXTS:
                return Refused("policy", "no such context %r" % (context,))
            if not ceilings.resume(db, context):
                return Refused("policy", "%s is not paused" % context)
            ledger.append(db, at=now, kind="admin", context="resume",
                          summary={"context": context, "by": by,
                                   "operator": operator})
            self._alert(db, now, "high", "%s resumed from verify by %s"
                        % (context, operator), context=context)
            return {"resumed": context}

        return self._run(run)

    def status(self) -> dict:
        now = self.clock.now()
        pauses = [dict(r) for r in self.store.all("SELECT * FROM pauses")]
        counts = {c: self.store.one(
            "SELECT COUNT(*) AS n FROM events WHERE context = ? AND "
            "principal = '*:*' AND at >= ?", (c, now - 86400))["n"]
            for c in cfgmod.CONTEXTS}
        seq, head = ledger.head(self.store)
        shipped = self.store.one("SELECT MAX(seq) AS s FROM ledger "
                                 "WHERE shipped = 1")["s"] or 0
        active = {}
        for row in self.store.all("SELECT * FROM keys WHERE state = ?",
                                  (registry.ACTIVE,)):
            active[row["organization"] or ""] = row["key_id"]
        # How far each published key is from being allowed to switch in, and
        # whether it may: verify shows the signer's own answer, not a copy of
        # its rule (`registry.activation_gate`).
        gates = {}
        for row in self.store.all("SELECT * FROM keys WHERE state = ?",
                                  (registry.PUBLISHED,)):
            gate = registry.activation_gate(self.store, self.cfg, row, now)
            gate["not_capable_count"] = len(gate["not_capable"])
            gate["not_capable"] = gate["not_capable"][:registry.GATE_DEVICES_SHOWN]
            gates[str(row["key_id"])] = gate
        # What waits for an operator, with the name each key would put on
        # phones: the check on a certificate verify had generated is two
        # operators reading this before they publish it.
        waiting = [self._key_summary(row) for row in self.store.all(
            "SELECT * FROM keys WHERE state IN (?, ?, ?) ORDER BY key_id",
            registry.WAITING)]
        pending = []
        for row in self.store.all(
                "SELECT * FROM confirmations WHERE done_at IS NULL AND "
                "requested_at > ? ORDER BY id", (now - CONFIRM_SECONDS,)):
            item = {"confirmation": row["id"], "action": row["action"],
                    "subject": row["subject"], "by": row["requested_by"],
                    "requested_at": row["requested_at"]}
            if row["action"] in ("publish", "withdraw", "retire"):
                key = registry.get(self.store,
                                   int(row["subject"].partition(":")[0]))
                if key is not None:
                    item["key"] = self._key_summary(key)
            pending.append(item)
        return {"now": now, "pauses": pauses, "signed_today": counts,
                "ledger_head": {"seq": seq, "hash": head,
                                "shipped_through": shipped},
                "active": active, "gates": gates,
                "waiting": waiting, "confirmations": pending,
                "code": self.code,
                "credential_day_ceiling": (self.cfg.ceiling(
                    cfgmod.CREDENTIAL, "*") or (None, None, None))[2]}

    def _same_name_as(self, row):
        """The id of another organization's key holding this key's name, or
        None."""
        if not (row["organization"] and row["certified_name"]):
            return None
        other = registry.name_held_by_another(
            self.store, row["certified_name"], row["organization"])
        return other["key_id"] if other is not None else None

    def _key_summary(self, row) -> dict:
        """What two operators read before they publish a key. `same_name_as`
        names another organization's key under the same name, so a clash
        that slipped past is in front of them."""
        return {"key_id": row["key_id"], "state": row["state"],
                "organization": row["organization"],
                "certified_name": row["certified_name"],
                "certified_by": row["certified_by"],
                "organization_ca": row["ca_id"],
                "same_name_as": self._same_name_as(row)}

    def public(self) -> dict:
        keys = []
        for row in self.store.all("SELECT * FROM keys WHERE state != ? "
                                  "ORDER BY key_id", (registry.DISCARDED,)):
            keys.append({
                "key_id": row["key_id"], "organization": row["organization"],
                "state": row["state"], "legacy": bool(row["legacy"]),
                # A held key (`[[held]]`): listed and signing, no certificate.
                "raw": (row["leaf"] is None and not row["legacy"]
                        and row["state"] in registry.LISTED),
                "suspended": row["suspended_at"] is not None,
                "spki": _b64(bytes(row["spki"])),
                "leaf": _b64(bytes(row["leaf"])) if row["leaf"] else None,
                "certified_name": row["certified_name"],
                "certified_by": row["certified_by"],
                # Another organization's key under the same name: shown with
                # the keys, so a clash is visible however it came about.
                "same_name_as": self._same_name_as(row),
                "ca_id": row["ca_id"],
                "window": [row["window_start"], row["window_end"]],
                "cert_not_after": row["leaf_not_after"],
                "published_at": row["published_at"]})
        cfg = self.cfg
        cas = [{"ca_id": r["ca_id"], "state": r["state"], "name": r["name"],
                "not_after": r["not_after"], "issued": r["issued"],
                "issue_until": (registry.issue_until(cfg, r["not_after"])
                                if r["not_after"] else None),
                # What phones match against the site they paired with.
                "domains": list(chain.ca_domains(chain.load(bytes(r["cert"]))))
                           if r["cert"] else []}
               for r in self.store.all("SELECT * FROM cas ORDER BY ca_id")]
        return {"keys": keys,
                "organization_cas": cas,
                "site_domain": cfg.site_domain,
                "organization_leaf_days": cfg.organization_leaf_days,
                "margin_seconds": cfg.margin_seconds,
                "min_signing_days": cfg.min_signing_days,
                "credential_max_days": cfg.credential_max_days,
                "lease_seconds": cfg.lease_seconds,
                "revocation_ttl_seconds": cfg.revocation_ttl_seconds,
                "statement_days": cfg.statement_days,
                "site_publishes_organization_keys":
                    cfg.site_publishes_organization_keys,
                "site_controls_all_keys": cfg.site_controls_all_keys,
                "ca_fingerprints": [hashlib.sha256(a).hexdigest()
                                    for a in cfg.anchors]}

    # =====================================================================
    # Admin operations (an operator on the host)
    # =====================================================================

    def keygen(self, *, organization=None, by: str) -> dict:
        if organization is not None:
            organization = str(uuid.UUID(str(organization)))

        def run(db, now):
            key_id = registry.allocate_key_id(db)
            key_ref, spki = self.keys.generate(key_id)
            db.execute("INSERT INTO keys (key_id, organization, state, spki, "
                       "key_ref, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                       (key_id, organization, registry.GENERATED, spki,
                        key_ref, now))
            self._key_event(db, now, "keygen", key_id, by,
                            organization=organization or "", spki=_b64(spki))
            return {"key_id": key_id,
                    "csr": self._request_or_destroy(
                        key_ref, "OfflineVerifier signing key %d" % key_id)}

        return self._run(run)

    def _request_or_destroy(self, key_ref, common_name, dns_names=()) -> str:
        """The key's certificate request; or, if it cannot be made, the key
        file gone and a refusal raised, so the transaction rolls back and the
        id is not left pointing at a file that blocks the next keygen."""
        try:
            return self.keys.csr(key_ref, common_name, dns_names).decode()
        except Exception as exc:
            self.keys.destroy(key_ref)
            raise Refused("config", "no certificate request for %r: %s"
                          % (common_name, exc))

    # -- the Organization CA ----------------------------------------------

    def ca_keygen(self, *, by: str) -> dict:
        """A key for the next Organization CA, and its request for the PKI:
        this site's System CA, asking for ``site_domain``."""
        cfg = self.cfg
        if not cfg.site_domain:
            raise Refused("config", "set site_domain in policy.toml first: "
                          "the System CA is named after the domain phones "
                          "pair with, and lists it")
        domain = cfg.site_domain
        # Before a key exists, so a name that cannot be leaves nothing behind.
        try:
            name = pki.system_ca_name(domain)
        except ValueError as exc:
            raise Refused("config", "site_domain: %s" % exc)

        def run(db, now):
            waiting = db.execute("SELECT ca_id FROM cas WHERE state = ?",
                                 (registry.GENERATED,)).fetchone()
            if waiting is not None:
                return Refused("policy", "Organization CA %d already waits for "
                               "its certificate" % waiting["ca_id"])
            ca_id = registry.allocate_key_id(db)
            key_ref, spki = self.keys.generate(ca_id)
            db.execute("INSERT INTO cas (ca_id, state, spki, key_ref, "
                       "created_at) VALUES (?, ?, ?, ?, ?)",
                       (ca_id, registry.GENERATED, spki, key_ref, now))
            self._key_event(db, now, "ca-keygen", ca_id, by, domain=domain,
                            spki=_b64(spki))
            self._alert(db, now, "medium", "Organization CA %d made by %s, "
                        "for %s" % (ca_id, by, domain))
            return {"ca_id": ca_id, "domain": domain,
                    "csr": self._request_or_destroy(key_ref, name, (domain,))}

        return self._run(run)

    def ca_install(self, ca_id, cert_der: bytes, *, by: str) -> dict:
        """The PKI's certificate for the waiting Organization CA (`ca_id`
        None: whichever waits). It issues from now on; the one before it
        stops issuing, and the keys it certified keep their certificates.
        It must be for ``site_domain`` and named after it, as phones paired
        with this site require."""
        cfg = self.cfg
        if not cfg.site_domain:
            raise Refused("config", "set site_domain in policy.toml first")
        domain = cfg.site_domain

        def run(db, now):
            row = db.execute("SELECT * FROM cas WHERE state = ? AND "
                             "(? IS NULL OR ca_id = ?)",
                             (registry.GENERATED, ca_id, ca_id)).fetchone()
            if row is None:
                return Refused("policy", "no Organization CA waits for a "
                               "certificate; start one with cl03signer ca keygen")
            ca_id_ = row["ca_id"]
            try:
                got = chain.validate_organization_ca(cert_der, cfg.anchors, now,
                                                     domain=domain)
            except chain.ChainError as exc:
                if exc.reason == "intermediate_domain":
                    listed = chain.ca_domains(chain.load(cert_der))
                    return Refused("certificate", "it is for %s, not %s, the "
                                   "site phones pair with"
                                   % (", ".join(listed) or "no domain", domain))
                return Refused("certificate", exc.reason)
            if trust_mod.canonical_spki(got.spki) != trust_mod.canonical_spki(
                    bytes(row["spki"])):
                return Refused("certificate", "not this CA's certificate")
            if got.name != pki.system_ca_name(domain):
                return Refused("certificate", "it is named %r, not %r"
                               % (got.name, pki.system_ca_name(domain)))
            if now > registry.issue_until(cfg, got.not_after):
                return Refused("certificate", "it ends too soon to issue a "
                               "certificate leaving %d days of signing"
                               % cfg.min_signing_days)
            for old in db.execute("SELECT * FROM cas WHERE state = ?",
                                  (registry.CERTIFIED,)).fetchall():
                db.execute("UPDATE cas SET state = ?, retired_at = ?, "
                           "key_ref = NULL WHERE ca_id = ?",
                           (registry.RETIRED, now, old["ca_id"]))
                if old["key_ref"]:
                    self.keys.destroy(old["key_ref"])
                self._key_event(db, now, "ca-retire", old["ca_id"], by)
            db.execute("UPDATE cas SET state = ?, cert = ?, name = ?, "
                       "not_before = ?, not_after = ? WHERE ca_id = ?",
                       (registry.CERTIFIED, cert_der, got.name, got.not_before,
                        got.not_after, ca_id_))
            self._key_event(db, now, "ca-install", ca_id_, by, domain=domain,
                            fingerprint=hashlib.sha256(cert_der).hexdigest(),
                            cert=_b64(cert_der), name=got.name,
                            not_before=got.not_before, not_after=got.not_after)
            self._alert(db, now, "high", "Organization CA %d (%s) installed by "
                        "%s; it can certify organization keys" % (ca_id_,
                                                                  got.name, by))
            return {"ca_id": ca_id_, "name": got.name,
                    "issue_until": registry.issue_until(cfg, got.not_after)}

        return self._run(run)

    def ca_withdraw(self, ca_id: int, *, by: str) -> dict:
        row = self.store.one("SELECT * FROM cas WHERE ca_id = ?", (ca_id,))
        if row is None or row["state"] == registry.WITHDRAWN:
            raise Refused("policy", "no Organization CA %d to withdraw" % ca_id)
        return self._request("ca-withdraw", ca_id, by)

    def _do_ca_withdraw(self, db, now, ca_id, who):
        row = db.execute("SELECT * FROM cas WHERE ca_id = ?",
                         (ca_id,)).fetchone()
        if row is None or row["state"] == registry.WITHDRAWN:
            return Refused("policy", "nothing to withdraw")
        db.execute("UPDATE cas SET state = ?, withdrawn_at = ?, key_ref = NULL "
                   "WHERE ca_id = ?", (registry.WITHDRAWN, now, ca_id))
        if row["key_ref"]:
            self.keys.destroy(row["key_ref"])
        # Phones refuse everything under it by its fingerprint; here, its
        # keys stop signing and travel as tombstones of their own.
        keys = [r["key_id"] for r in db.execute(
            "SELECT key_id FROM keys WHERE ca_id = ? AND state NOT IN "
            "(?, ?, ?)", (ca_id, registry.WITHDRAWN, registry.EXPIRED,
                          registry.DISCARDED))]
        for key_id in keys:
            self._do_withdraw(db, now, key_id, who)
        self._key_event(db, now, "ca-withdraw", ca_id, who, keys=keys,
                        tombstone=trust_mod.fingerprint(
                            bytes(row["spki"])).hex(),
                        not_after=row["not_after"])
        self._alert(db, now, "high", "Organization CA %d withdrawn by %s, with "
                    "keys %s" % (ca_id, who, keys or "none"))
        return {"withdrawn_ca": ca_id, "keys": keys}

    def _request(self, action, subject, by):
        def run(db, now):
            cur = db.execute("INSERT INTO confirmations (action, subject, "
                             "requested_by, requested_at) VALUES (?, ?, ?, ?)",
                             (action, str(subject), by, now))
            ledger.append(db, at=now, kind="admin", context=action,
                          summary={"subject": str(subject), "by": by,
                                   "confirmation": cur.lastrowid})
            return {"confirmation": cur.lastrowid, "action": action,
                    "needs": "a second operator: cl03signer confirm %d"
                             % cur.lastrowid}

        return self._run(run)

    def publish(self, key_id: int, *, by: str) -> dict:
        row = registry.require(self.store, key_id)
        if row["state"] != registry.CERTIFIED:
            raise Refused("policy", "only a certified key can be published")
        # The second operator confirms THIS certificate: the subject names it,
        # and a different one installed meanwhile voids the request. Both
        # operators are shown the name it puts on phones (`cl03signer status`
        # lists it beside the confirmation).
        result = self._request("publish", "%d:%s" % (
            key_id, hashlib.sha256(bytes(row["leaf"])).hexdigest()), by)
        result["key"] = self._key_summary(row)
        return result

    def _publish_pending(self, db, now, key_id) -> bool:
        return db.execute(
            "SELECT 1 FROM confirmations WHERE action = 'publish' AND "
            "done_at IS NULL AND requested_at > ? AND subject LIKE ?",
            (now - CONFIRM_SECONDS, "%d:%%" % key_id)).fetchone() is not None

    def withdraw(self, key_id: int, *, by: str) -> dict:
        registry.require(self.store, key_id)
        return self._request("withdraw", key_id, by)

    def legacy_end(self, key_id: int, *, by: str) -> dict:
        row = registry.require(self.store, key_id)
        if not row["legacy"]:
            raise Refused("policy", "not a legacy key")
        return self._request("legacy-end", key_id, by)

    def revoked_remove(self, credential_ids, *, by: str) -> dict:
        subject = ",".join(str(uuid.UUID(bytes=bytes(c)))
                           for c in credential_ids)
        return self._request("revoked-remove", subject, by)

    def confirm(self, confirmation_id: int, *, by: str) -> dict:
        def run(db, now):
            row = db.execute("SELECT * FROM confirmations WHERE id = ?",
                             (confirmation_id,)).fetchone()
            if row is None or row["done_at"] is not None:
                return Refused("policy", "no such pending confirmation")
            if row["requested_by"] == by:
                return Refused("policy", "a second, different operator must "
                               "confirm")
            if now - row["requested_at"] > CONFIRM_SECONDS:
                return Refused("policy", "the request is over 24 hours old")
            db.execute("UPDATE confirmations SET done_at = ? WHERE id = ?",
                       (now, confirmation_id))
            action, subject = row["action"], row["subject"]
            who = "%s+%s" % (row["requested_by"], by)
            if action == "publish":
                key_id, _, fingerprint = subject.partition(":")
                return self._do_publish(db, now, int(key_id), who, fingerprint)
            if action == "withdraw":
                return self._do_withdraw(db, now, int(subject), who)
            if action == "retire":
                return self._do_retire(db, now, int(subject), who)
            if action == "ca-withdraw":
                return self._do_ca_withdraw(db, now, int(subject), who)
            if action == "legacy-end":
                db.execute("UPDATE keys SET window_end = MIN(window_end, ?) "
                           "WHERE key_id = ? AND legacy = 1",
                           (now, int(subject)))
                self._key_event(db, now, "legacy-end", int(subject), who)
                return {"legacy_ended": int(subject)}
            if action == "revoked-remove":
                ids = [uuid.UUID(s).bytes for s in subject.split(",") if s]
                db.executemany("DELETE FROM revoked WHERE credential_id = ?",
                               [(c,) for c in ids])
                self._alert(db, now, "high", "%d revocations removed by %s"
                            % (len(ids), who))
                return {"removed": len(ids)}
            return Refused("policy", "unknown action")

        return self._run(run)

    def _do_publish(self, db, now, key_id, who, fingerprint):
        row = registry.get(self.store, key_id)
        if row is None or row["state"] != registry.CERTIFIED:
            return Refused("policy", "only a certified key can be published")
        if hashlib.sha256(bytes(row["leaf"])).hexdigest() != fingerprint:
            return Refused("policy", "key %d's certificate changed after the "
                           "publish was requested; request it again" % key_id)
        refused = self._for_this_site(row, now)
        if refused:
            return refused
        db.execute("UPDATE keys SET state = ?, published_at = ? WHERE key_id = ?",
                   (registry.PUBLISHED, now, key_id))
        self._key_event(db, now, "publish", key_id, who)
        self._alert(db, now, "medium", "key %d published" % key_id)
        return {"published": key_id}

    def _retire(self, db, now, row, who):
        db.execute("UPDATE keys SET state = ?, retired_at = ?, "
                   "window_end = MIN(window_end, ?), key_ref = NULL "
                   "WHERE key_id = ?",
                   (registry.RETIRED, now, now, row["key_id"]))
        if row["key_ref"]:
            self.keys.destroy(row["key_ref"])
        self._key_event(db, now, "retire", row["key_id"], who)

    def _do_withdraw(self, db, now, key_id, who, operator=None):
        """`operator`: the site admin who withdrew it from verify's pages
        (`site_withdraw`), named in the ledger and the alert."""
        row = registry.get(self.store, key_id)
        if row is None or row["state"] == registry.WITHDRAWN:
            return Refused("policy", "nothing to withdraw")
        stops_bundles = (row["state"] == registry.ACTIVE
                         and not row["organization"])
        not_after = row["leaf_not_after"]
        if row["legacy"]:
            not_after = (row["window_end"] + self.cfg.credential_max_seconds
                         + self.cfg.margin_seconds)
        db.execute("UPDATE keys SET state = ?, withdrawn_at = ?, key_ref = NULL, "
                   "leaf_not_after = ? WHERE key_id = ?",
                   (registry.WITHDRAWN, now, not_after, key_id))
        if row["key_ref"]:
            self.keys.destroy(row["key_ref"])
        # The tombstone phones get, and how long, in the ledger itself: a
        # rebuilt signer has only the ledger to carry it on.
        extra = {} if operator is None else {"operator": operator}
        self._key_event(db, now, "withdraw", key_id, who,
                        tombstone=trust_mod.fingerprint(
                            bytes(row["spki"])).hex(),
                        not_after=not_after, **extra)
        if operator is None:
            self._alert(db, now, "high", "key %d withdrawn by %s"
                        % (key_id, who))
        else:
            self._alert(db, now, "high", "key %d withdrawn from verify by %s%s"
                        % (key_id, operator,
                           "; nothing signs bundles, feeds or statements "
                           "until another deployment key is active, so every "
                           "phone's sync is refused meanwhile"
                           if stops_bundles else ""),
                        organization=row["organization"] or "")
        return {"withdrawn": key_id}

    def activate(self, key_id: int, *, by: str) -> dict:
        def run(db, now):
            row = registry.get(self.store, key_id)
            if row is None:
                return Refused("policy", "only a published key can be activated")
            return self._activate(db, now, row, by)

        return self._run(run)

    def _activate(self, db, now, row, by, operator=None):
        key_id = row["key_id"]
        if row["state"] != registry.PUBLISHED:
            return Refused("policy", "only a published key can be activated")
        if row["suspended_at"] is not None:
            return Refused("policy", "unsuspend it first")
        if now >= row["window_end"]:
            return Refused("key_out_of_window", str(key_id))
        refused = self._for_this_site(row, now)
        if refused:
            return refused
        current = registry.active_key(self.store, row["organization"])
        if (row["leaf"] is None and current is not None
                and current["leaf"] is not None):
            # Phones holding a bundle the certified key signed refuse a
            # raw key's for that bundle's lease (continuity).
            return Refused("policy", "a held raw key does not replace "
                           "a certified one")
        # An organization's first key takes over from the deployment key,
        # which had signed its documents: a phone without the new key
        # would refuse them just the same. A deployment key with none active
        # beside it has nothing to wait for (`registry.activation_gate`).
        gate = registry.activation_gate(self.store, self.cfg, row, now)
        if not gate["open"]:
            return Refused("gate", self._gate_reason(gate))
        if current is not None:
            self._retire(db, now, current, by)
        db.execute("UPDATE keys SET state = ?, activated_at = ? "
                   "WHERE key_id = ?", (registry.ACTIVE, now, key_id))
        if operator is None:
            self._key_event(db, now, "activate", key_id, by)
            self._alert(db, now, "medium", "key %d now signs" % key_id)
        else:
            self._key_event(db, now, "activate", key_id, by, operator=operator)
            if row["organization"]:
                self._alert(db, now, "high", "key %d now signs for %r, started "
                            "from verify by %s" % (key_id,
                                                   row["certified_name"],
                                                   operator),
                            organization=row["organization"])
            else:
                self._alert(db, now, "high", "deployment key %d now signs "
                            "bundles, feeds, statements and the documents of "
                            "organizations without a key, started from verify "
                            "by %s" % (key_id, operator))
        return {"active": key_id}

    @staticmethod
    def _gate_reason(gate) -> str:
        if gate["not_capable"]:
            one = len(gate["not_capable"]) == 1
            return ("%d phone%s that synced within a lease run%s an app that "
                    "cannot follow a certified deployment key; update %s, or "
                    "unpair %s and wait out %s last lease (Setup lists them)"
                    % (len(gate["not_capable"]), "" if one else "s",
                       "s" if one else "", "it" if one else "them",
                       "it" if one else "them", "its" if one else "their"))
        if not gate["counted"]:
            return ("the signer has signed bundles for under a lease, so it "
                    "cannot tell which phones have this key; it may switch "
                    "%s" % time.strftime("on %Y-%m-%d %H:%M UTC",
                                         time.gmtime(gate["opens_at"])))
        return ("%d of %d phones that synced within a lease have it; it may "
                "switch once all do, or %s"
                % (gate["have"], gate["of"],
                   time.strftime("on %Y-%m-%d %H:%M UTC",
                                 time.gmtime(gate["opens_at"]))))

    def _successor(self, row):
        """A key waiting to take over from `row` in its scope -- generated,
        certified or published -- or None."""
        return self.store.one(
            "SELECT * FROM keys WHERE state IN (?, ?, ?) AND legacy = 0 AND "
            "organization IS ? AND key_id != ? ORDER BY key_id LIMIT 1",
            registry.WAITING + (row["organization"], row["key_id"]))

    def _retire_refused(self, row):
        """None, or why `row` may not be retired by hand: only an active or
        published key, and never an active one while a successor waits in
        its scope, which `activate` retires through the switch gate.
        Retired first, the successor would start with no gate, and phones
        inside a lease of the old key's refuse it until that lease ends."""
        if row is None or row["state"] not in (registry.ACTIVE,
                                               registry.PUBLISHED):
            return Refused("policy", "only a published or active key")
        if row["state"] == registry.ACTIVE:
            successor = self._successor(row)
            if successor is not None:
                steps = ("cl03signer activate %d" % successor["key_id"]
                         if successor["state"] == registry.PUBLISHED else
                         "publish key %d, then cl03signer activate %d"
                         % (successor["key_id"], successor["key_id"]))
                return Refused("policy", "key %d waits to take over: %s "
                               "retires key %d through the switch gate. "
                               "Retiring first would leave phones refusing "
                               "key %d's bundles and documents"
                               % (successor["key_id"], steps, row["key_id"],
                                  successor["key_id"]))
        return None

    def retire(self, key_id: int, *, by: str) -> dict:
        """A published key retires at once. An active one is irreversible and
        leaves its scope with no key, so it needs a second operator, like a
        withdrawal, and is refused while a successor waits
        (`_retire_refused`)."""
        row = registry.get(self.store, key_id)
        refused = self._retire_refused(row)
        if refused:
            raise refused
        if row["state"] == registry.ACTIVE:
            result = self._request("retire", key_id, by)
            if row["organization"]:
                result["consequence"] = (
                    "%s's documents are signed by the deployment key until "
                    "another of its keys is activated"
                    % (row["certified_name"] or "the organization"))
            else:
                result["consequence"] = (
                    "nothing signs bundles, feeds, statements or the "
                    "deployment's documents until another key is activated: "
                    "every phone's sync is refused meanwhile, and a phone "
                    "inside a lease of this key's refuses the next key until "
                    "that lease ends")
            result["key"] = self._key_summary(row)
            return result

        def run(db, now):
            current = registry.get(self.store, key_id)
            refused = self._retire_refused(current)
            if refused:
                return refused
            self._retire(db, now, current, by)
            return {"retired": key_id}

        return self._run(run)

    def _do_retire(self, db, now, key_id, who):
        row = registry.get(self.store, key_id)
        if row is None or row["state"] != registry.ACTIVE:
            return Refused("policy", "key %d is no longer active" % key_id)
        refused = self._retire_refused(row)
        if refused:
            return refused
        self._retire(db, now, row, who)
        self._alert(db, now, "high", "key %d retired by %s; nothing signs for "
                    "its scope until another key is activated" % (key_id, who))
        return {"retired": key_id}

    def unsuspend(self, key_id: int, *, by: str) -> dict:
        """Lift a suspension. Only of a key that exists and is suspended,
        decided inside the transaction, so a mistyped id writes no key event
        and moves no key id."""
        def run(db, now):
            row = registry.get(self.store, key_id)
            if row is None:
                return Refused("unknown_key", str(key_id))
            if row["suspended_at"] is None:
                return Refused("policy", "key %d is not suspended" % key_id)
            db.execute("UPDATE keys SET suspended_at = NULL WHERE key_id = ?",
                       (key_id,))
            self._key_event(db, now, "unsuspend", key_id, by)
            return {"unsuspended": key_id}

        return self._run(run)

    def resume(self, context: str, *, by: str) -> dict:
        def run(db, now):
            if not ceilings.resume(db, context):
                return Refused("policy", "%s is not paused" % context)
            ledger.append(db, at=now, kind="admin", context="resume",
                          summary={"context": context, "by": by})
            return {"resumed": context}

        return self._run(run)
