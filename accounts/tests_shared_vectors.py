"""The shared vectors, judged by this copy of `ovcrypto` (and that copy held
to the verifier app's, when its checkout is beside this one), and the
signing pages' POSTs refused without their CSRF token.
"""

import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from django.conf import settings
from django.test import SimpleTestCase

from accounts.tests_signing_pages import _OrganizationPages
from ovcrypto import chain, feed, revocation, trust, verifier

VECTORS = Path(settings.BASE_DIR) / "vectors"


def _b64(text):
    return base64.b64decode(text)


def _load(name):
    with open(VECTORS / name, encoding="utf-8") as handle:
        return json.load(handle)


class SharedVectorsTest(SimpleTestCase):
    """What OfflineVerifier's tests/test_vectors.py and test_trust.py ask of
    `ovcrypto`, asked of this repository's copy."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.V = _load("vectors.json")
        cls.C = _load("chains.json")
        k = cls.V["keys"]
        cls.device = {k["epoch"]: verifier.EpochPrivateKeys(
            k["epoch"],
            X25519PrivateKey.from_private_bytes(_b64(k["epoch_public_tier_sk"])),
            X25519PrivateKey.from_private_bytes(_b64(k["epoch_restricted_tier_sk"])))}
        cls.trust = verifier.TrustList.bare({
            k["issuer_key_id"]: _b64(k["issuer_spki_der"]),
            k["issuer_ed25519_key_id"]: _b64(k["issuer_ed25519_spki_der"]),
            k["issuer_secp256k1_key_id"]: _b64(k["issuer_secp256k1_spki_der"])})

    def test_credentials_and_negatives(self):
        for case in self.V["credentials"] + [
                dict(c, verify_at=self.V["credentials"][0]["verify_at"])
                for c in self.V["negative"]]:
            with self.subTest(case["name"]):
                got = verifier.verify(case["qr"], epoch_keys=self.device,
                                      trust_list=self.trust, now=case["verify_at"])
                self.assertEqual(got.verdict.value, case["expected_verdict"])

    def test_revocation_and_trust_cases(self):
        filt = revocation.CuckooFilter.from_bytes(_b64(self.V["revocation"]["filter"]))
        for case in self.V["with_revocation"]:
            got = verifier.verify(case["qr"], epoch_keys=self.device,
                                  trust_list=self.trust, now=case["verify_at"],
                                  revocation=filt)
            self.assertEqual(got.verdict.value, case["expected_verdict"], case["name"])
            self.assertEqual(got.needs_online_check,
                             case["expected_needs_online_check"], case["name"])
        key_id = self.V["keys"]["issuer_key_id"]
        for case in self.V["trust_cases"]:
            spec = case["trust"]
            window = tuple(spec.get("window", (0, 2 ** 32 - 1)))
            listed = verifier.TrustList(
                dict(self.trust.keys),
                {k: window if k == key_id else (0, 2 ** 32 - 1)
                 for k in self.trust.keys},
                {key_id: spec["certified"]} if "certified" in spec else {})
            got = verifier.verify(case["qr"], epoch_keys=self.device,
                                  trust_list=listed, now=case["verify_at"])
            self.assertEqual(got.verdict.value, case["expected_verdict"], case["name"])
            self.assertEqual(got.certified_issuer,
                             case.get("expected_certified_issuer"), case["name"])

    def test_feeds(self):
        keys = {self.V["keys"]["issuer_key_id"]: _b64(self.V["keys"]["issuer_spki_der"])}
        for case in self.V["feeds"]:
            try:
                feed.verify_feed(case["feed"], keys=keys, now=case["now"])
                reason = "ok"
            except feed.FeedRefused as exc:
                reason = exc.reason
            self.assertEqual(reason, case["expected"], case["name"])

    def test_certificate_cases(self):
        anchors = {n: _b64(d) for n, d in self.C["anchors"].items()}
        for case in self.C["chains"]:
            with self.subTest(case["name"]):
                args = (_b64(case["leaf"]), [anchors[a] for a in case["anchors"]],
                        case["at"], [_b64(m) for m in case.get("intermediates", [])],
                        case["domain"])
                if case["expect"]["ok"]:
                    got = chain.validate(*args)
                    self.assertEqual(base64.b64encode(got.spki).decode(),
                                     case["expect"]["spki"])
                    self.assertEqual(got.not_after, case["expect"]["not_after"])
                else:
                    with self.assertRaises(chain.ChainError) as err:
                        chain.validate(*args)
                    self.assertEqual(err.exception.reason, case["expect"]["reason"])

    def test_policy_cases(self):
        anchors_by_name = {n: _b64(d) for n, d in self.C["anchors"].items()}

        def accept(case, raw, chains, now, previous=None):
            a = case["anchors"]
            return trust.accept_bundle(
                _b64(raw), chain.decode_chains(chains),
                anchors=trust.Anchors(
                    raw={int(k): _b64(v) for k, v in a["raw"].items()},
                    cas=tuple(anchors_by_name[n] for n in a["cas"]),
                    withdrawn=frozenset(a["withdrawn"])),
                denied=set(case["denied"]), device_id=_b64(case["device_id"]),
                now=now, previous=previous,
                denied_keys={_b64(f) for f in case.get("denied_keys", [])},
                domain=case["domain"])

        for case in self.C["policy"]:
            with self.subTest(case["name"]):
                previous = None
                if case["previous"]:
                    p = case["previous"]
                    previous = accept(case, p["bundle"], p["chains"], p["now"])
                expect = case["expect"]
                if not expect["ok"]:
                    with self.assertRaises(trust.Refused) as err:
                        accept(case, case["bundle"], case["chains"], case["now"],
                               previous)
                    self.assertEqual(err.exception.reason, expect["reason"])
                    continue
                ctx = accept(case, case["bundle"], case["chains"], case["now"],
                             previous)
                # All of it, as OfflineVerifier's test_trust.py asks: this
                # is all that runs where that checkout is not beside this
                # one.
                self.assertEqual(ctx.signer, expect["signer"])
                self.assertEqual(ctx.chain_signed, expect["chain_signed"])
                self.assertEqual(ctx.lease_end, expect["lease_end"])
                self.assertEqual([[k, r] for k, r in ctx.dropped], expect["dropped"])
                self.assertEqual(sorted(ctx.tombstones), expect["tombstones"])
                self.assertEqual(sorted(base64.b64encode(f).decode()
                                        for f in ctx.withdrawn_keys),
                                 expect["withdrawn_keys"])
                self.assertEqual(
                    [{"key_id": v.key_id, "raw": v.raw, "classes": sorted(v.classes),
                      "organization": v.organization,
                      "window": [v.not_before, v.not_after],
                      "chain_not_after": v.chain_not_after}
                     for v in sorted(ctx.entries.values(), key=lambda v: v.key_id)],
                    expect["entries"])
                creds = ctx.credential_trust_list(case["now"])
                self.assertEqual(sorted(creds.keys), expect["credential_keys"])
                self.assertEqual({str(k): o for k, o in (creds.certified or {}).items()},
                                 expect["certified"])
                for key_id, outcome in expect.get("listed", {}).items():
                    if outcome == "ok":
                        ctx.listed_signer(int(key_id))
                        continue
                    with self.assertRaises(trust.Refused) as err:
                        ctx.listed_signer(int(key_id))
                    self.assertEqual(err.exception.reason, outcome)


class OvcryptoIsOfflineVerifiersTest(SimpleTestCase):
    """`ovcrypto/` and `vectors/` are OfflineVerifier's, byte for byte, line
    endings aside. Checked against a checkout of it beside this one
    (`OFFLINEVERIFIER_CHECKOUT`, or ../../OfflineVerifier), and skipped where
    there is none, as on a server."""

    def test_the_copy_is_the_original(self):
        here = Path(settings.BASE_DIR)
        there = Path(os.environ.get("OFFLINEVERIFIER_CHECKOUT")
                     or here.parent.parent / "OfflineVerifier")
        if not (there / "ovcrypto" / "wire.py").is_file():
            self.skipTest("no OfflineVerifier checkout at %s" % there)

        def digests(root):
            out = {}
            for folder in ("ovcrypto", "vectors"):
                for path in sorted((root / folder).glob("*")):
                    if path.is_file() and path.suffix in (".py", ".json"):
                        data = path.read_bytes().replace(b"\r\n", b"\n")
                        out["%s/%s" % (folder, path.name)] = hashlib.sha256(data).hexdigest()
            return out

        self.assertEqual(digests(here), digests(there))


class SigningPostsNeedTheirTokenTest(_OrganizationPages):
    """Every signing POST, without its CSRF token, is refused and changes
    nothing the signer holds. The test client does not check CSRF unless
    asked, so no other test would notice a @csrf_exempt."""

    def test_each_is_refused_without_the_token(self):
        made = self.svc.keygen(by="alice")
        key_id = made["key_id"]
        before = (json.dumps(self.svc.public(), sort_keys=True),
                  self.svc.store.one("SELECT COUNT(*) AS n FROM ledger")["n"])
        self.client = self.client_class(enforce_csrf_checks=True)
        self._sign_in(self.site_admin, self.org)
        posts = ["/app/setup/signing/pause/",
                 "/app/setup/signing/keys/%d/suspend/" % key_id,
                 "/app/setup/signing/keys/%d/certificate/" % key_id,
                 "/app/setup/signing/keys/%d/discard/" % key_id,
                 "/app/setup/signing/keys/%d/publish/" % key_id,
                 "/app/setup/signing/keys/%d/activate/" % key_id,
                 "/app/setup/signing/organizations/%d/generate/" % self.org.id,
                 "/app/setup/signing/organizations/%d/request/" % self.org.id]
        for url in posts:
            with self.subTest(url):
                self.assertEqual(self.client.post(url, {"name": self.org.name}).status_code,
                                 403)
        after = (json.dumps(self.svc.public(), sort_keys=True),
                 self.svc.store.one("SELECT COUNT(*) AS n FROM ledger")["n"])
        self.assertEqual(before, after)
