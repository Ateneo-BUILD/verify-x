"""Cross-language end-to-end vectors: what the real signer produces.

    python -m signer.tests.make_e2e vectors/signer_e2e.json

The signer here is the real one -- registry, policy, bundle assembly, feed and
statement, and the Organization CA certifying a key a site admin generated --
on a temporary folder, with a test CA and a moved clock. What it
writes is judged twice, by `ovcrypto.trust` (OfflineVerifier's
`tests/test_signer_e2e.py`) and by the app (`SignerE2ETests.swift`), and both
must reach the verdicts recorded beside each case.

The keys are fresh on every run, so the file changes whenever it is
regenerated; the verdicts must not. Copy the file to OfflineVerifier's
`vectors/` as well: the two copies stay identical, like `ovcrypto/`.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import sys
import tempfile
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ovcrypto import bundle as bundle_mod
from ovcrypto import chain, devicelog, issuer, pki, trust, wire

from signer import config as cfgmod, ledger, messages, registry
from signer.clock import FixedClock
from signer.keys import FileKeys
from signer.service import SignerService
from signer.store import Store

from .helpers import LEGACY_KEY, ORG, ORG_NAME, T0, spki_of

DAY = 86400
EPOCH = 42
DEVICE = bytes(range(16))
OTHER_DEVICE = bytes(range(16, 32))
OTHER_ORG_NAME = "Beta Office"
#: The site the phone paired with, which the signer's System CA is for; and
#: one it never paired with.
SITE = "verify.e2e.example"
ELSEWHERE = "verify.elsewhere.example"
SYSTEM_CA = pki.system_ca_name(SITE)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


class _Signer:
    """What `issuer.issue` asks to sign with."""

    def __init__(self, key_id, sign):
        self.key_id = key_id
        self.sig_alg = wire.SIG_ECDSA_P256_SHA256
        self.sign = sign


def build(out_path: str) -> dict:
    folder = tempfile.mkdtemp()
    try:
        return _build(folder, out_path)
    finally:
        shutil.rmtree(folder, True)


def _build(folder: str, out_path: str) -> dict:
    clock = FixedClock(T0)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = pki.make_ca(ca_key, "E2E Issuing CA", T0 - 365 * DAY, T0 + 3650 * DAY,
                     serial=2, path_length=1)
    ca_der = ca.public_bytes(serialization.Encoding.DER)
    cfg = cfgmod.Config(anchors=[ca_der], site_domain=SITE, legacy=[
        cfgmod.Legacy(1, spki_of(LEGACY_KEY), T0 - 200 * DAY, T0 + 100 * DAY)])
    store = Store(os.path.join(folder, "signer.db"))
    keys = FileKeys(os.path.join(folder, "keys"))
    svc = SignerService(store, keys, cfg, clock=clock,
                        alerts=lambda *_args: None)
    # A signer that has signed bundles for over a lease, so its switch gate
    # trusts its own count of phones.
    with store as db:
        ledger.append(db, at=T0 - 31 * DAY, kind="sign", context="bundle",
                      summary={"device": "00" * 16, "keys": "||", "key_id": 0,
                               "chains": True})

    def ready(organization=None, *, activate=True):
        made = svc.keygen(organization=organization, by="alice")
        csr = x509.load_pem_x509_csr(made["csr"].encode())
        profile = pki.ORGANIZATION if organization else pki.DEPLOYMENT
        cert = pki.sign_csr(csr, ca_key, ca, profile, clock.now() - 60,
                            clock.now() + 730 * DAY,
                            serial=x509.random_serial_number(),
                            organization=ORG_NAME if organization else None,
                            organization_id=organization)
        svc.install_cert(made["key_id"], cert.public_bytes(
            serialization.Encoding.DER), by="alice")
        conf = svc.publish(made["key_id"], by="alice")
        svc.confirm(conf["confirmation"], by="bob")
        if activate:
            svc.activate(made["key_id"], by="alice")
        return made["key_id"]

    def key_ref(key_id):
        return registry.require(store, key_id)["key_ref"]

    epoch_sk = X25519PrivateKey.generate()
    epoch_public = issuer.EpochPublicKeys(EPOCH, epoch_sk.public_key(), None)
    revoked_id = uuid.UUID("0b8f2f8e-6a8f-4b39-9f4e-3a3c1f2d7e10").bytes

    def bundle(signer=None):
        clock.advance(100)
        return (signer or svc).bundle(
                          chains=True,  # the chain-aware app
                          device_id=DEVICE, device_key_hash=b"\x11" * 32,
                          epoch_keys=[{
                              "epoch": EPOCH, "tier": 0,
                              "not_before": clock.now() - DAY,
                              "not_after": clock.now() + 120 * DAY,
                              "wrapped": b64(os.urandom(113))}],
                          lease_seconds=30 * DAY), clock.now()

    def credential(key_id, *, issuer_name, issued_at, valid_days=365,
                   sign=None, organization=None, signer=None):
        public = {
            wire.T_CREDENTIAL_ID: uuid.uuid4().bytes,
            wire.T_ISSUED_AT: wire.u32(issued_at),
            wire.T_EXPIRES_AT: wire.u32(issued_at + valid_days * DAY),
            wire.T_DOC_NUMBER: b"E2E-1",
            wire.T_ISSUER_ID: issuer_name.encode(),
        }
        if sign is None:
            def sign(message):
                return base64.b64decode((signer or svc).sign_credential(
                    message, organization=organization)["sig"])
        payload = issuer.issue(public, {}, epoch_keys=epoch_public,
                               signer=_Signer(key_id, sign))
        return issuer.to_qr_string(payload)

    # -- the keys -----------------------------------------------------------
    deployment = ready()                                   # 16
    organization = ready(ORG)                              # 17
    svc.put_revoked([revoked_id])

    b1, at1 = bundle()

    # Credentials, judged against b1.
    clock.advance(10)
    now = clock.now()
    creds = [
        ("deployment_key", credential(deployment, issuer_name=OTHER_ORG_NAME,
                                      issued_at=now),
         "valid", None),
        ("organization_key", credential(organization, issuer_name=ORG_NAME,
                                        issued_at=now, organization=ORG),
         "valid", ORG_NAME),
        ("organization_key_naming_another_issuer",
         credential(organization, issuer_name=OTHER_ORG_NAME, issued_at=now,
                    sign=lambda m: keys.sign(key_ref(organization), m)),
         "forged", None),
        ("legacy_key_inside_its_window",
         credential(1, issuer_name=OTHER_ORG_NAME, issued_at=now - 10 * DAY,
                    sign=lambda m: _raw(LEGACY_KEY, m)),
         "valid", None),
        ("deployment_key_backdated_before_its_window",
         credential(deployment, issuer_name=OTHER_ORG_NAME,
                    issued_at=now - 30 * DAY,
                    sign=lambda m: keys.sign(key_ref(deployment), m)),
         "forged", None),
        ("expired_before_the_key_existed",
         credential(deployment, issuer_name=OTHER_ORG_NAME,
                    issued_at=now - 400 * DAY, valid_days=365,
                    sign=lambda m: keys.sign(key_ref(deployment), m)),
         "expired", None),
    ]
    cred_now = now

    feed1 = svc.feed()
    log_public = X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    statement1 = svc.statement(log_key_id=3, public_key=log_public)
    # A feed signed by the organization key, which may sign credentials only.
    blob = base64.b64decode(feed1["filter"])
    forged_feed = dict(feed1, key_id=organization, sig=b64(keys.sign(
        key_ref(organization), messages.feed_signed_bytes(
            feed1["issued_at"], feed1["not_after"], organization, blob))))

    # -- a rotation: 18 published, reaches the phone, then signs -----------
    clock.advance(100)
    successor = ready(activate=False)                      # 18
    b2, at2 = bundle()
    clock.advance(100)
    svc.activate(successor, by="alice")
    b3, at3 = bundle()
    feed3 = svc.feed()

    # -- 17 withdrawn: the next bundle carries its tombstone ---------------
    clock.advance(100)
    conf = svc.withdraw(organization, by="alice")
    svc.confirm(conf["confirmation"], by="bob")
    b4, at4 = bundle()

    # 17's own key and certificate offered again as key 99, in a bundle the
    # successor signs: what whoever holds a withdrawn key would try.
    org_spki = bytes(registry.require(store, organization)["spki"])
    org_leaf = bytes(registry.require(store, organization)["leaf"])
    relabelled = bundle_mod.Bundle.unpack(base64.b64decode(b4["bundle"]))
    window = registry.require(store, organization)
    relabelled.trust.append(bundle_mod.TrustEntry(
        99, window["window_start"], window["window_end"], org_spki))
    b5 = {"issuer_chains": dict(b4["issuer_chains"],
                                **{"99": [b64(org_leaf)]})}
    _rebind(relabelled, b5["issuer_chains"])
    relabelled.sign(_Signer(successor,
                            lambda m: keys.sign(key_ref(successor), m)))
    b5["bundle"] = b64(relabelled.pack())
    fingerprint17 = b64(trust.fingerprint(org_spki))

    # -- the Organization CA: a key generated from the organization's page --
    clock.advance(100)
    made = svc.ca_keygen(by="alice")
    org_ca_id = made["ca_id"]                              # 19
    org_ca = pki.sign_csr(
        x509.load_pem_x509_csr(made["csr"].encode()), ca_key, ca,
        pki.ORGANIZATION_CA, clock.now() - 60, clock.now() + 5 * 365 * DAY,
        serial=x509.random_serial_number(), domain=SITE)
    org_ca_der = org_ca.public_bytes(serialization.Encoding.DER)
    svc.ca_install(org_ca_id, org_ca_der, by="alice")
    generated = svc.org_generate(organization=ORG,
                                 name=ORG_NAME)["key_id"]  # 20
    conf = svc.publish(generated, by="alice")
    svc.confirm(conf["confirmation"], by="bob")
    # 17 is withdrawn, so the deployment key signs the organization's
    # documents until 20 takes over: the phone must hold 20 first.
    bundle()
    svc.activate(generated, by="alice")
    b6, at6 = bundle()
    clock.advance(10)
    generated_now = clock.now()
    generated_cred = credential(generated, issuer_name=ORG_NAME,
                                issued_at=generated_now, organization=ORG)

    # Whoever broke in kept the CA's key; then it is withdrawn, and its key
    # with it.
    with open(os.path.join(folder, "keys", key_ref_ca(store, org_ca_id)),
              "rb") as handle:
        stolen_ca_key = serialization.load_pem_private_key(handle.read(), None)
    clock.advance(100)
    conf = svc.ca_withdraw(org_ca_id, by="alice")
    svc.confirm(conf["confirmation"], by="bob")
    b7, at7 = bundle()
    ca_spki = bytes(store.one("SELECT spki FROM cas WHERE ca_id = ?",
                              (org_ca_id,))["spki"])
    gen_spki = bytes(registry.require(store, generated)["spki"])
    withdrawn7 = sorted([fingerprint17, b64(trust.fingerprint(ca_spki)),
                         b64(trust.fingerprint(gen_spki))])

    # A key the stolen CA mints afterwards, offered as 77 in a bundle that
    # also drops the CA's tombstone: the phone's own deny-list refuses it.
    minted_key = ec.generate_private_key(ec.SECP256R1())
    minted = pki.issue_leaf(stolen_ca_key, org_ca, minted_key.public_key(),
                            pki.ORGANIZATION, clock.now() - 60,
                            clock.now() + 700 * DAY,
                            serial=x509.random_serial_number(),
                            organization=ORG_NAME, organization_id=ORG)
    forged = bundle_mod.Bundle.unpack(base64.b64decode(b7["bundle"]))
    forged.trust = [t for t in forged.trust
                    if t.key_id not in (org_ca_id, generated)]
    forged.trust.append(bundle_mod.TrustEntry(
        77, clock.now() - 10, clock.now() + 300 * DAY, spki_of(minted_key)))
    b8 = {"issuer_chains": dict(b7["issuer_chains"], **{"77": [
              b64(minted.public_bytes(serialization.Encoding.DER)),
              b64(org_ca_der)]})}
    _rebind(forged, b8["issuer_chains"])
    forged.sign(_Signer(successor, lambda m: keys.sign(key_ref(successor), m)))
    b8["bundle"] = b64(forged.pack())

    # -- a second signer, holding key 1 (`[[held]]`) -------------------------
    # A development site whose phones still pin only the development key:
    # key 1 signs bundles, feeds and statements, and a key the Organization
    # CA certified reaches the phone inside them, with its chain beside.
    held_dir = os.path.join(folder, "held")
    held_keys = FileKeys(os.path.join(held_dir, "keys"))
    with open(os.path.join(held_dir, "keys", "key-1.pem"), "wb") as handle:
        handle.write(LEGACY_KEY.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    held_store = Store(os.path.join(held_dir, "signer.db"))
    held = SignerService(held_store, held_keys, cfgmod.Config(
        anchors=[ca_der], site_domain=SITE, held=[cfgmod.Held(
            1, "key-1.pem", spki_of(LEGACY_KEY), T0 - 200 * DAY,
            T0 + 100 * DAY)]), clock=clock, alerts=lambda *_args: None)
    with held_store as db:  # a lease of bundles, as above
        ledger.append(db, at=clock.now() - 31 * DAY, kind="sign",
                      context="bundle", summary={
                          "device": "00" * 16, "keys": "||", "key_id": 0,
                          "chains": True})
    held.activate(1, by="alice")
    held.put_revoked([revoked_id])
    clock.advance(100)
    made = held.ca_keygen(by="alice")
    held_ca = pki.sign_csr(
        x509.load_pem_x509_csr(made["csr"].encode()), ca_key, ca,
        pki.ORGANIZATION_CA, clock.now() - 60, clock.now() + 5 * 365 * DAY,
        serial=x509.random_serial_number(), domain=SITE)
    held.ca_install(made["ca_id"], held_ca.public_bytes(
        serialization.Encoding.DER), by="alice")
    held_org = held.org_generate(organization=ORG,
                                 name=ORG_NAME)["key_id"]   # 17
    conf = held.publish(held_org, by="alice")
    held.confirm(conf["confirmation"], by="bob")
    held.activate(held_org, by="alice")
    h1, ath = bundle(held)
    clock.advance(10)
    held_now = clock.now()
    held_creds = [
        ("held_key_1_for_an_organization_without_a_key",
         credential(1, issuer_name=OTHER_ORG_NAME, issued_at=held_now,
                    signer=held), "valid", None),
        ("organization_ca_key_beside_the_held_key",
         credential(held_org, issuer_name=ORG_NAME, issued_at=held_now,
                    organization=ORG, signer=held), "valid", ORG_NAME),
    ]
    held_feed = held.feed()
    held_statement = held.statement(log_key_id=3, public_key=log_public)
    held_store.db.close()

    def flip_last(raw_b64):
        raw = bytearray(base64.b64decode(raw_b64))
        raw[-1] ^= 0x01
        return b64(bytes(raw))

    def case(name, b, at, *, expect, previous=None, chains=None,
             device=DEVICE, raw=None, domain=SITE):
        """``domain``: the site the phone paired with over HTTPS."""
        return {"name": name, "bundle": raw or b["bundle"],
                "chains": b["issuer_chains"] if chains is None else chains,
                "device_id": b64(device), "now": at + 10, "previous": previous,
                "domain": domain, "expect": expect}

    ok1 = {"ok": True, "signer": deployment, "chain_signed": True,
           "entries": [1, deployment, organization], "tombstones": [],
           "withdrawn_keys": [],
           "credential_keys": [1, deployment, organization],
           "certified": {str(organization): ORG_NAME}}
    bundles = [
        case("first_bundle", b1, at1, expect=ok1),
        case("signature_altered", b1, at1, raw=flip_last(b1["bundle"]),
             expect={"ok": False, "reason": "bad_signature"}),
        case("chains_missing", b1, at1, chains={},
             expect={"ok": False, "reason": "signer_not_vouched"}),
        case("another_device", b1, at1, device=OTHER_DEVICE,
             expect={"ok": False, "reason": "wrong_device"}),
        case("successor_published", b2, at2, previous="first_bundle", expect={
            "ok": True, "signer": deployment, "chain_signed": True,
            "entries": [1, deployment, organization, successor],
            "tombstones": [], "withdrawn_keys": [],
            "credential_keys": [1, deployment, organization, successor],
            "certified": {str(organization): ORG_NAME}}),
        case("successor_signs", b3, at3, previous="successor_published", expect={
            "ok": True, "signer": successor, "chain_signed": True,
            "entries": [1, deployment, organization, successor],
            "tombstones": [], "withdrawn_keys": [],
            "credential_keys": [1, deployment, organization, successor],
            "certified": {str(organization): ORG_NAME}}),
        case("successor_without_its_announcement", b3, at3,
             previous="first_bundle",
             expect={"ok": False, "reason": "continuity"}),
        case("organization_key_withdrawn", b4, at4, previous="successor_signs",
             expect={"ok": True, "signer": successor, "chain_signed": True,
                     "entries": [1, deployment, successor],
                     "tombstones": [organization],
                     "withdrawn_keys": [fingerprint17],
                     "credential_keys": [1, deployment, successor],
                     "certified": {}}),
        case("withdrawn_key_offered_under_a_new_id", b5, at4,
             previous="organization_key_withdrawn",
             expect={"ok": True, "signer": successor, "chain_signed": True,
                     "entries": [1, deployment, successor],
                     "tombstones": [organization],
                     "withdrawn_keys": [fingerprint17],
                     "credential_keys": [1, deployment, successor],
                     "certified": {}}),
        case("organization_ca_key_listed", b6, at6,
             previous="organization_key_withdrawn",
             expect={"ok": True, "signer": successor, "chain_signed": True,
                     "entries": [1, deployment, successor, generated],
                     "tombstones": [organization],
                     "withdrawn_keys": [fingerprint17],
                     "credential_keys": [1, deployment, successor, generated],
                     "certified": {str(generated): ORG_NAME},
                     "certified_by": {str(deployment): "E2E Issuing CA",
                                      str(successor): "E2E Issuing CA",
                                      str(generated): SYSTEM_CA}}),
        # The same bundle on a phone paired with another site: the System
        # CA is not for it, so its key goes and nothing else does.
        case("organization_ca_key_on_a_phone_paired_elsewhere", b6, at6,
             previous="organization_key_withdrawn", domain=ELSEWHERE,
             expect={"ok": True, "signer": successor, "chain_signed": True,
                     "entries": [1, deployment, successor],
                     "dropped": {str(generated): trust.ENTRY_WRONG_DOMAIN},
                     "tombstones": [organization],
                     "withdrawn_keys": [fingerprint17],
                     "credential_keys": [1, deployment, successor],
                     "certified": {}}),
        case("organization_ca_withdrawn", b7, at7,
             previous="organization_ca_key_listed",
             expect={"ok": True, "signer": successor, "chain_signed": True,
                     "entries": [1, deployment, successor],
                     "tombstones": sorted([organization, org_ca_id, generated]),
                     "withdrawn_keys": withdrawn7,
                     "credential_keys": [1, deployment, successor],
                     "certified": {}}),
        case("key_minted_by_the_withdrawn_ca", b8, at7,
             previous="organization_ca_withdrawn",
             expect={"ok": True, "signer": successor, "chain_signed": True,
                     "entries": [1, deployment, successor],
                     "dropped": {"77": trust.ENTRY_DENIED},
                     "tombstones": [organization],
                     "withdrawn_keys": [fingerprint17],
                     "credential_keys": [1, deployment, successor],
                     "certified": {}}),
    ]
    held_ok = {"ok": True, "signer": 1, "chain_signed": False,
               "entries": [1, held_org], "tombstones": [],
               "withdrawn_keys": [], "credential_keys": [1, held_org],
               "certified": {str(held_org): ORG_NAME},
               "certified_by": {str(held_org): SYSTEM_CA}}
    bundles += [
        case("held_key_1_signs", h1, ath, expect=held_ok),
        # A phone that held a certificate-signed bundle may still take key
        # 1's: that bundle listed key 1, inside its window.
        case("held_key_1_after_a_certified_signer", h1, ath,
             previous="first_bundle", expect=held_ok),
    ]

    data = {
        "description": ("What the credential signer in verify produces, and "
                        "the verdict each must get from ovcrypto.trust and "
                        "from the app. Generated by "
                        "verify/signer/tests/make_e2e.py; test keys only."),
        "anchors": {"raw": {"1": b64(spki_of(LEGACY_KEY))}, "cas": [b64(ca_der)],
                    "withdrawn": []},
        "epoch": {"epoch": EPOCH, "public_tier_sk": b64(epoch_sk.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption()))},
        "domain": SITE,
        "bundles": bundles,
        "credentials": [
            {"name": name, "qr": qr, "context": "first_bundle", "now": cred_now,
             "expect": {"verdict": verdict, "certified_issuer": certified}}
            for name, qr, verdict, certified in creds
        ] + [
            {"name": "organization_key_after_withdrawal", "qr": creds[1][1],
             "context": "organization_key_withdrawn", "now": cred_now,
             "expect": {"verdict": "forged", "certified_issuer": None}},
            {"name": "organization_ca_key", "qr": generated_cred,
             "context": "organization_ca_key_listed", "now": generated_now,
             "expect": {"verdict": "valid", "certified_issuer": ORG_NAME}},
            {"name": "organization_ca_key_after_the_ca_is_withdrawn",
             "qr": generated_cred, "context": "organization_ca_withdrawn",
             "now": generated_now,
             "expect": {"verdict": "forged", "certified_issuer": None}},
            {"name": "organization_ca_key_on_a_phone_paired_elsewhere",
             "qr": generated_cred,
             "context": "organization_ca_key_on_a_phone_paired_elsewhere",
             "now": generated_now,
             "expect": {"verdict": "forged", "certified_issuer": None}},
        ] + [
            {"name": name, "qr": qr, "context": "held_key_1_signs",
             "now": held_now,
             "expect": {"verdict": verdict, "certified_issuer": certified}}
            for name, qr, verdict, certified in held_creds
        ],
        "feeds": [
            {"name": "feed", "feed": feed1, "context": "first_bundle",
             "now": at1 + 10, "expect": {"ok": True}},
            {"name": "feed_by_the_organization_key", "feed": forged_feed,
             "context": "first_bundle", "now": at1 + 10,
             "expect": {"ok": False}},
            {"name": "feed_by_the_successor_before_it_is_listed", "feed": feed3,
             "context": "first_bundle", "now": at1 + 10,
             "expect": {"ok": False}},
            {"name": "feed_by_the_successor", "feed": feed3,
             "context": "successor_signs", "now": at3 + 10,
             "expect": {"ok": True}},
            {"name": "feed_by_the_held_key_1", "feed": held_feed,
             "context": "held_key_1_signs", "now": ath + 10,
             "expect": {"ok": True}},
        ],
        "statements": [
            {"name": "statement", "statement": statement1,
             "context": "first_bundle", "now": at1 + 10,
             "expect": {"ok": True}},
            {"name": "statement_by_the_held_key_1",
             "statement": held_statement, "context": "held_key_1_signs",
             "now": ath + 10, "expect": {"ok": True}},
        ],
        "revoked": [str(uuid.UUID(bytes=revoked_id))],
    }
    with open(out_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(data, handle, indent=1, sort_keys=False)
        handle.write("\n")
    store.db.close()
    return data


def _rebind(b, issuer_chains) -> None:
    """Whoever re-signs a bundle with the signer's key can bind whatever chains
    they send beside it, so these forgeries do: what refuses them is the
    phone's deny-list, as it must be."""
    b.trust = [t for t in b.trust if not t.is_chains_digest]
    b.trust.append(bundle_mod.chains_entry(chain.chains_digest(
        chain.decode_chains(issuer_chains))))


def key_ref_ca(store, ca_id) -> str:
    return store.one("SELECT key_ref FROM cas WHERE ca_id = ?",
                     (ca_id,))["key_ref"]


def _raw(key, message: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from ovcrypto import keystore
    return keystore.der_to_raw_p256(key.sign(message, ec.ECDSA(hashes.SHA256())))


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "vectors/signer_e2e.json")
    print("wrote", sys.argv[1] if len(sys.argv) > 1 else "vectors/signer_e2e.json")
