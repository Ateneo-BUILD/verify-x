"""The end-to-end vector generator still produces what it records.

`make_e2e.py` writes `vectors/signer_e2e.json`, which OfflineVerifier's
Python and Swift tests judge. This runs it afresh against verify's copy of
`ovcrypto`, so a change to the signer that would alter a verdict fails here,
before the file is regenerated and copied.
"""

from __future__ import annotations

import base64
import os
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ovcrypto import chain, trust, verifier

from . import make_e2e


class EndToEndVectorTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        folder = tempfile.mkdtemp()
        cls.data = make_e2e.build(os.path.join(folder, "e2e.json"))

    def _anchors(self):
        a = self.data["anchors"]
        return trust.Anchors(
            raw={int(k): base64.b64decode(v) for k, v in a["raw"].items()},
            cas=tuple(base64.b64decode(c) for c in a["cas"]),
            withdrawn=frozenset(a["withdrawn"]))

    def _contexts(self):
        out = {}
        for case in self.data["bundles"]:
            previous = out.get(case["previous"]) if case["previous"] else None
            try:
                out[case["name"]] = trust.accept_bundle(
                    base64.b64decode(case["bundle"]),
                    chain.decode_chains(case["chains"]), anchors=self._anchors(),
                    denied=previous.tombstones if previous else frozenset(),
                    denied_keys=(previous.withdrawn_keys if previous
                                 else frozenset()),
                    device_id=base64.b64decode(case["device_id"]),
                    now=case["now"], previous=previous, domain=case["domain"])
                verdict = (True, None)
            except trust.Refused as exc:
                verdict = (False, exc.reason)
            with self.subTest(case["name"]):
                self.assertEqual(verdict[0], case["expect"]["ok"])
                self.assertEqual(verdict[1], case["expect"].get("reason"))
                if verdict[0]:
                    ctx = out[case["name"]]
                    self.assertEqual(sorted(ctx.entries), case["expect"]["entries"])
                    self.assertEqual(
                        sorted(base64.b64encode(f).decode()
                               for f in ctx.withdrawn_keys),
                        case["expect"]["withdrawn_keys"])
                    if "certified_by" in case["expect"]:
                        self.assertEqual(
                            {str(k): v.ca_name for k, v in ctx.entries.items()
                             if v.ca_name}, case["expect"]["certified_by"])
                    if "dropped" in case["expect"]:
                        self.assertEqual({str(k): r for k, r in ctx.dropped},
                                         case["expect"]["dropped"])
        return out

    def test_every_bundle_and_credential_gets_its_recorded_verdict(self):
        contexts = self._contexts()
        epoch = self.data["epoch"]
        keys = {epoch["epoch"]: verifier.EpochPrivateKeys(
            epoch["epoch"], X25519PrivateKey.from_private_bytes(
                base64.b64decode(epoch["public_tier_sk"])))}
        for case in self.data["credentials"]:
            ctx = contexts[case["context"]]
            result = verifier.verify(
                case["qr"], epoch_keys=keys,
                trust_list=ctx.credential_trust_list(case["now"]),
                now=case["now"])
            with self.subTest(case["name"]):
                self.assertEqual(result.verdict.value, case["expect"]["verdict"],
                                 result.detail)
                self.assertEqual(result.certified_issuer,
                                 case["expect"]["certified_issuer"])
