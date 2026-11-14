"""The phone's trust rule: which keys a key bundle may make it trust.

The reference for ``Crypto/TrustPolicy.swift``; both read the policy cases in
``vectors/chains.json`` and must reach the same verdict, with the same reason
string, for each.

A build pins raw keys (R) and issuing CAs (C). A key is *vouched for* when its
id is in R with R's key, or when its certificate validates under
``chain.validate`` against C -- and its id is neither in R nor denied. A
bundle is accepted when its signer is vouched for and, if the phone already
holds a chain-signed bundle whose lease is running, is a live entry of that
bundle; a chain-signed bundle must list its own signer too, and a bundle that
binds its chains (``bundle.CHAINS_DIGEST_ID``) must arrive with exactly those.
The accepted bundle's vouched entries are what the phone trusts until its next
sync. A key certified through the site's System CA is vouched for
only when that CA lists ``domain``, the host the phone paired with over HTTPS;
otherwise it is dropped as ``entry_wrong_domain``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization

from . import bundle as bundle_mod
from . import chain, keystore, revocation, verifier

SKEW_SECONDS = 300
MAX_LEASE_SECONDS = bundle_mod.MAX_LEASE_SECONDS

# Refusals of a whole bundle, feed or statement.
MALFORMED = "malformed"
DUPLICATE_KEY_ID = "duplicate_key_id"
WRONG_DEVICE = "wrong_device"
ISSUED_IN_FUTURE = "issued_in_future"
LEASE_TOO_LONG = "lease_too_long"
#: The lease ends when it starts, or before: over on arrival.
LEASE_EMPTY = "lease_empty"
SIGNER_NOT_VOUCHED = "signer_not_vouched"
SIGNER_NOT_INFRASTRUCTURE = "signer_not_infrastructure"
BAD_SIGNATURE = "bad_signature"
CONTINUITY = "continuity"
NO_ENTRIES = "no_entries"
DENIED_KEY = "denied_key"
NOT_LISTED = "not_listed"
#: The certificates beside the bundle are not the ones it binds.
CHAINS_MISMATCH = "chains_mismatch"
#: A chain-signed bundle that does not list its own signer, live: the next
#: one that key signs would fail continuity for the whole lease.
SIGNER_NOT_LISTED = "signer_not_listed"

# Entries dropped from an accepted bundle.
ENTRY_NOT_VOUCHED = "entry_not_vouched"
ENTRY_ID_RESERVED = "entry_id_reserved"
ENTRY_DENIED = "entry_denied"
ENTRY_WINDOW_OUTSIDE_CHAIN = "entry_window_outside_chain"
#: Certified through a System CA that is not for the site the phone paired
#: with, or the phone paired without HTTPS.
ENTRY_WRONG_DOMAIN = "entry_wrong_domain"

_RAW_CLASSES = frozenset({chain.INFRASTRUCTURE, chain.CREDENTIAL})


def canonical_spki(spki: bytes) -> bytes:
    """A P-256 SPKI as cryptography re-encodes it, or the bytes unchanged."""
    try:
        key = serialization.load_der_public_key(spki)
        return key.public_bytes(serialization.Encoding.DER,
                                serialization.PublicFormat.SubjectPublicKeyInfo)
    except Exception:               # not a key cryptography reads
        return spki


def fingerprint(spki: bytes) -> bytes:
    """What a tombstone and the deny-list name a key by: SHA-256 of its SPKI.

    A key id is only a label. A certificate does not say which id it belongs
    to, so a withdrawn key must be refused by what it is.
    """
    return hashlib.sha256(canonical_spki(spki)).digest()


class Refused(Exception):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__("%s%s" % (reason, ": " + detail if detail else ""))
        self.reason = reason


@dataclass(frozen=True)
class Anchors:
    """What a build pins. ``withdrawn`` ships in the app as a deny-list."""
    raw: dict                       # key_id -> DER SPKI
    cas: tuple = ()                 # DER certificates
    withdrawn: frozenset = frozenset()       # key ids
    withdrawn_keys: frozenset = frozenset()  # fingerprints, any key


@dataclass(frozen=True)
class Vouched:
    key_id: int
    spki: bytes
    not_before: int                 # the entry's window
    not_after: int
    raw: bool
    classes: frozenset
    organization: str = None        # an organization key's certified O
    chain_not_after: int = None     # None for a raw key
    ca_name: str = None             # who certified it, as the phone says


@dataclass
class TrustContext:
    """An accepted bundle, as the phone holds it."""
    device_id: bytes
    issued_at: int
    lease_end: int                  # min(not_after, issued_at + 31 days)
    signer: int
    chain_signed: bool
    entries: dict = field(default_factory=dict)     # key_id -> Vouched
    tombstones: frozenset = frozenset()
    dropped: list = field(default_factory=list)     # [(key_id, reason)]
    #: Fingerprints the bundle's tombstones named: kept with the deny-list.
    withdrawn_keys: frozenset = frozenset()

    def listed_signer(self, key_id: int) -> Vouched:
        """A feed or a statement must be signed by a key this bundle lists."""
        entry = self.entries.get(key_id)
        if entry is None:
            raise Refused(NOT_LISTED, "key %d" % key_id)
        if chain.INFRASTRUCTURE not in entry.classes:
            raise Refused(SIGNER_NOT_INFRASTRUCTURE, "key %d" % key_id)
        return entry

    def credential_trust_list(self, now: int) -> verifier.TrustList:
        """What a scan checks a credential against, at the trusted ``now``."""
        keys, windows, certified = {}, {}, {}
        for e in self.entries.values():
            if chain.CREDENTIAL not in e.classes:
                continue
            if e.chain_not_after is not None and now > e.chain_not_after:
                continue
            keys[e.key_id] = e.spki
            windows[e.key_id] = (e.not_before, e.not_after)
            if e.organization is not None:
                certified[e.key_id] = e.organization
        return verifier.TrustList(keys, windows=windows, certified=certified)


def _vouch(key_id: int, spki, chains: dict, anchors: Anchors, denied,
           denied_keys, now, domain):
    """(spki, classes, organization, certified) or a reason string.

    ``certified`` is the ``chain.CertifiedKey``, or None for a raw key.
    ``spki`` None means "whatever the certificate says" (a signer); otherwise
    the certificate must certify exactly that key (an entry). ``denied`` are
    key ids, ``denied_keys`` fingerprints: a withdrawn key is refused under
    any id, and a withdrawn Organization CA takes every key it certified with
    it.
    """
    if key_id in anchors.raw:
        if spki is not None and spki != anchors.raw[key_id]:
            return ENTRY_ID_RESERVED
        if fingerprint(anchors.raw[key_id]) in denied_keys:
            return ENTRY_DENIED
        return anchors.raw[key_id], _RAW_CLASSES, None, None
    if key_id in denied:
        return ENTRY_DENIED
    certs = chains.get(key_id)
    if certs is None:
        return ENTRY_NOT_VOUCHED
    if isinstance(certs, (bytes, bytearray)):
        certs = (bytes(certs),)
    try:
        got = chain.validate(certs[0], anchors.cas, now, certs[1:], domain)
    except chain.ChainError as exc:
        if exc.reason == "intermediate_domain":
            return ENTRY_WRONG_DOMAIN
        return ENTRY_NOT_VOUCHED
    if spki is not None and got.spki != canonical_spki(spki):
        return ENTRY_NOT_VOUCHED
    if fingerprint(got.spki) in denied_keys:
        return ENTRY_DENIED
    if (got.intermediate_spki is not None
            and fingerprint(got.intermediate_spki) in denied_keys):
        return ENTRY_DENIED
    return got.spki, got.classes, got.organization, got


def accept_bundle(raw: bytes, chains: dict, *, anchors: Anchors, denied,
                  device_id: bytes, now: int,
                  previous: TrustContext = None,
                  denied_keys=frozenset(), domain: str = None) -> TrustContext:
    """Accept a key bundle, or raise ``Refused``.

    ``chains`` is ``chain.decode_chains`` of the envelope; ``denied`` and
    ``denied_keys`` are the phone's own deny-list, key ids and fingerprints;
    ``previous`` is the context of the bundle it holds now, if any;
    ``domain`` is the host of the site the phone paired with over HTTPS, or
    None if it paired without it.
    """
    try:
        b = bundle_mod.Bundle.unpack(raw)
    except bundle_mod.BundleError as exc:
        if "listed twice" in str(exc):
            raise Refused(DUPLICATE_KEY_ID, str(exc))
        raise Refused(MALFORMED, str(exc))

    if b.device_id != device_id:
        raise Refused(WRONG_DEVICE)
    if b.issued_at > now + SKEW_SECONDS:
        raise Refused(ISSUED_IN_FUTURE)
    if b.not_after - b.issued_at > MAX_LEASE_SECONDS:
        raise Refused(LEASE_TOO_LONG)
    if b.not_after <= b.issued_at:
        raise Refused(LEASE_EMPTY)
    # A filter the phone cannot read is not "nothing revoked", as on the feed
    # path.
    if b.revocation:
        try:
            revocation.CuckooFilter.from_bytes(b.revocation)
        except ValueError as exc:
            raise Refused(MALFORMED, "revocation filter: %s" % exc)

    tombstones = frozenset(t.key_id for t in b.trust if t.is_tombstone)
    tombstone_keys = frozenset(t.spki for t in b.trust
                               if t.is_tombstone and t.spki)
    deny = set(denied) | set(anchors.withdrawn) | set(tombstones)
    deny_keys = (set(denied_keys) | set(anchors.withdrawn_keys)
                 | set(tombstone_keys))

    # The signer.
    if b.sig_key_id not in anchors.raw and b.sig_key_id in deny:
        raise Refused(DENIED_KEY, "signer %d" % b.sig_key_id)
    signer = _vouch(b.sig_key_id, None, chains, anchors, deny, deny_keys, now,
                    domain)
    if signer == ENTRY_DENIED:
        raise Refused(DENIED_KEY, "signer %d's key" % b.sig_key_id)
    if isinstance(signer, str):
        raise Refused(SIGNER_NOT_VOUCHED, "signer %d" % b.sig_key_id)
    signer_spki, signer_classes, _, _ = signer
    if chain.INFRASTRUCTURE not in signer_classes:
        raise Refused(SIGNER_NOT_INFRASTRUCTURE, "signer %d" % b.sig_key_id)
    if not keystore.verify(signer_spki, b.signed_bytes(), b.sig):
        raise Refused(BAD_SIGNATURE)
    chain_signed = b.sig_key_id not in anchors.raw
    # Judged once the signature verifies, against the chains as decoded: one
    # dropped, altered or added beside the bundle refuses it whole, where it
    # would otherwise cost exactly that key on every phone that synced.
    digest = b.chains_digest
    if digest is not None and chain.chains_digest(chains) != digest:
        raise Refused(CHAINS_MISMATCH)

    # Never older than the bundle held, whoever signed either: an older one
    # brings back retired entries and an older revocation filter.
    if (previous is not None
            and b.issued_at < previous.issued_at - SKEW_SECONDS):
        raise Refused(CONTINUITY, "older than the bundle held")
    # Continuity: inside a running chain-signed lease, only a key that lease
    # already trusted -- and had not retired by then -- may sign the next one.
    if (previous is not None and previous.chain_signed
            and now < previous.lease_end):
        known = previous.entries.get(b.sig_key_id)
        if (known is None or known.spki != signer_spki
                or known.not_after < previous.issued_at):
            raise Refused(CONTINUITY, "signer %d" % b.sig_key_id)

    entries, dropped = {}, []
    for t in b.trust:
        if t.is_tombstone or t.is_chains_digest:
            continue
        got = _vouch(t.key_id, t.spki, chains, anchors, deny, deny_keys, now,
                     domain)
        if isinstance(got, str):
            dropped.append((t.key_id, got))
            continue
        spki, classes, organization, certified = got
        if certified is not None and (t.not_before < certified.not_before
                                      or t.not_after > certified.not_after):
            dropped.append((t.key_id, ENTRY_WINDOW_OUTSIDE_CHAIN))
            continue
        entries[t.key_id] = Vouched(
            t.key_id, spki, t.not_before, t.not_after, certified is None,
            classes, organization,
            certified.not_after if certified is not None else None,
            certified.ca_name if certified is not None else None)
    if not entries:
        raise Refused(NO_ENTRIES)
    # What continuity will ask of the next bundle this key signs, asked now.
    if chain_signed:
        own = entries.get(b.sig_key_id)
        if (own is None or own.spki != signer_spki
                or own.not_after < b.issued_at):
            raise Refused(SIGNER_NOT_LISTED, "signer %d" % b.sig_key_id)

    return TrustContext(
        device_id=b.device_id, issued_at=b.issued_at,
        lease_end=min(b.not_after, b.issued_at + MAX_LEASE_SECONDS),
        signer=b.sig_key_id, chain_signed=chain_signed, entries=entries,
        tombstones=tombstones, dropped=dropped, withdrawn_keys=tombstone_keys)
