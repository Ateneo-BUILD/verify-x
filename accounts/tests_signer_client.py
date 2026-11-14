"""verify with a credential signer: against a real signer, in process.

The signer here is the real `signer` package -- the same policy, registry and
ledger -- reached through its dispatcher instead of a socket. What these pin
is verify's side: every signature comes from the signer, a refusal prints the
plain QR, a lost reply keeps the row, and phones can check what they are sent.
"""

import base64
import hashlib
import os
import shutil
import tempfile
import time
import uuid
from datetime import timedelta
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from django.test import TestCase, override_settings
from django.utils import timezone

from ovcrypto import chain, devicelog, issuer, keystore, pki, trust, verifier

from accounts import (credential_keys, device_log, devices, minting,
                      revocation_feed, signer_client)
from accounts.models import (CredentialEpochKey, Device, IssuedCredential,
                             IssuerKey, Organization, Transaction, User)
from signer import config as cfgmod
from signer.clock import FixedClock
from signer.keys import FileKeys
from signer.service import Refused as ServiceRefused, SignerService
from signer.store import Store
from signer.transport import Dispatcher

WRAP_KEY_HEX = "00112233445566778899aabbccddeeff" * 2
DAY = 86400
ROWS = [{"field": "first_name", "key": "Given Name", "value": "JUAN",
         "show": True}]


#: The site phones pair with, which the signer's System CA is for.
SITE = "verify.example.ph"


@override_settings(CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX,
                   CREDENTIAL_ISSUER_KEY_PATH="", SIGNER_SOCKET="in-process")
class _SignerTest(TestCase):
    """verify against the signer in process, for the site at ``SITE``."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.clock = FixedClock(int(time.time()))
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.ca = pki.make_ca(self.ca_key, "Test Issuing CA",
                              self.clock.now() - 365 * DAY,
                              self.clock.now() + 3650 * DAY, serial=2,
                              path_length=1)
        self.ca_der = self.ca.public_bytes(serialization.Encoding.DER)
        store = Store(os.path.join(self.dir, "signer.db"))
        self.addCleanup(store.db.close)
        self.svc = SignerService(store, FileKeys(os.path.join(self.dir, "k")),
                                 cfgmod.Config(anchors=[self.ca_der],
                                               site_domain=SITE),
                                 clock=self.clock)
        # A signer that has signed bundles for over a lease, so its switch
        # gate trusts its own count of phones.
        from signer import ledger
        with store as db:
            ledger.append(db, at=self.clock.now() - 31 * DAY, kind="sign",
                          context="bundle", summary={
                              "device": "00" * 16, "keys": "||", "key_id": 0,
                              "chains": True})
        dispatcher = Dispatcher(self.svc)

        def transport(op, **args):
            reply = dispatcher.handle({"op": op, "args": args}, admin=False,
                                      by="app")
            if not reply["ok"]:
                raise ServiceRefused(reply["reason"], reply.get("detail", ""),
                                     **(reply.get("extra") or {}))
            return reply["result"]

        signer_client.set_transport(transport)
        self.addCleanup(signer_client.set_transport, None)
        credential_keys.reset_caches()
        revocation_feed.invalidate()
        device_log._statements.clear()
        self.addCleanup(revocation_feed.invalidate)
        self.addCleanup(device_log._statements.clear)
        self.org = Organization.objects.create(name="Alpha Registry")
        self.deployment = self._key()

    def _key(self, organization=None):
        made = self.svc.keygen(organization=organization, by="alice")
        csr = x509.load_pem_x509_csr(made["csr"].encode())
        profile = pki.ORGANIZATION if organization else pki.DEPLOYMENT
        cert = pki.sign_csr(csr, self.ca_key, self.ca, profile,
                            self.clock.now() - 60, self.clock.now() + 730 * DAY,
                            serial=x509.random_serial_number(),
                            organization=self.org.name if organization else None,
                            organization_id=organization)
        key_id = made["key_id"]
        self.svc.install_cert(key_id, cert.public_bytes(
            serialization.Encoding.DER), by="alice")
        conf = self.svc.publish(key_id, by="alice")
        self.svc.confirm(conf["confirmation"], by="bob")
        self.svc.activate(key_id, by="alice")
        signer_client.reset()
        return key_id

    def _spki(self, key_id):
        for k in self.svc.public()["keys"]:
            if k["key_id"] == key_id:
                return base64.b64decode(k["spki"])

    def _mint(self, organization=None):
        txn = Transaction.objects.create(organization=organization or self.org,
                                         authentication_result="success")
        now = timezone.now()
        minted = minting.mint_recorded(
            ROWS, transaction=txn, organization=organization or self.org,
            location_code="Q1", issued_at=now,
            expires_at=now + timedelta(days=365))
        return minted

    def _device_keys(self):
        """What a phone holds for the current epoch."""
        keys = {}
        for row in CredentialEpochKey.objects.all():
            raw = credential_keys.private_key(row)
            keys.setdefault(row.epoch, {})[row.tier] = \
                X25519PrivateKey.from_private_bytes(raw)
        return {epoch: verifier.EpochPrivateKeys(
            epoch, tiers[0], tiers.get(1)) for epoch, tiers in keys.items()}

    def _verify(self, minted, trust_list):
        qr = "CL03:" + minted["qr"].split(":CL03:", 1)[1]
        return verifier.verify(qr, epoch_keys=self._device_keys(),
                               trust_list=trust_list, now=int(time.time()))


class SignerMintTest(_SignerTest):

    def test_a_credential_is_signed_by_the_signer_and_verifies(self):
        minted = self._mint()
        row = IssuedCredential.objects.get(credential_id=minted["credential_id"])
        self.assertEqual(row.state, IssuedCredential.STATE_SIGNED)
        self.assertEqual(row.issuer_key_id, self.deployment)
        result = self._verify(minted, verifier.TrustList.bare(
            {self.deployment: self._spki(self.deployment)}))
        self.assertTrue(result.ok, result.detail)
        self.assertIsNone(result.certified_issuer)

    def test_an_organization_key_signs_its_certified_name(self):
        """One signature proves the organization and, by its chain, the system."""
        org_key = self._key(organization=str(self.org.signing_id))
        minted = self._mint()
        self.assertEqual(IssuedCredential.objects.get(
            credential_id=minted["credential_id"]).issuer_key_id, org_key)
        result = self._verify(minted, verifier.TrustList(
            {org_key: self._spki(org_key)},
            # Any window that holds the credential: this is about its issuer.
            windows={org_key: (0, 2 ** 32 - 1)},
            certified={org_key: "Alpha Registry"}))
        self.assertTrue(result.ok, result.detail)
        self.assertEqual(result.certified_issuer, "Alpha Registry")

    def test_a_switched_key_is_retried_once_with_the_signers_choice(self):
        signer_client.public()                      # caches the old key
        made = self.svc.keygen(by="alice")
        csr = x509.load_pem_x509_csr(made["csr"].encode())
        cert = pki.sign_csr(csr, self.ca_key, self.ca, pki.DEPLOYMENT,
                            self.clock.now() - 60,
                            self.clock.now() + 730 * DAY,
                            serial=x509.random_serial_number())
        self.svc.install_cert(made["key_id"], cert.public_bytes(
            serialization.Encoding.DER), by="alice")
        conf = self.svc.publish(made["key_id"], by="alice")
        self.svc.confirm(conf["confirmation"], by="bob")
        self.svc.activate(made["key_id"], by="alice")    # no devices: open
        minted = self._mint()
        self.assertEqual(IssuedCredential.objects.get(
            credential_id=minted["credential_id"]).issuer_key_id,
            made["key_id"])

    def test_a_paused_signer_leaves_no_row(self):
        self.svc.pause("credential", by="test")
        with self.assertRaises(signer_client.Paused):
            self._mint()
        self.assertEqual(IssuedCredential.objects.count(), 0)

    def test_a_lost_reply_keeps_the_row_as_unknown(self):
        real = signer_client._transport

        def lost(op, **args):
            if op == "sign_credential":
                raise signer_client.Unavailable("timed out", reply_lost=True)
            return real(op, **args)

        signer_client.set_transport(lost)
        with self.assertRaises(signer_client.Unavailable):
            self._mint()
        self.assertEqual(IssuedCredential.objects.get().state,
                         IssuedCredential.STATE_UNKNOWN)

    def test_configured_never_asks_the_signer(self):
        def refuse(op, **args):
            raise AssertionError("asked the signer")

        signer_client.set_transport(refuse)
        self.assertTrue(credential_keys.configured())


class SignerBundleTest(_SignerTest):

    def setUp(self):
        super().setUp()
        self.device_key = ec.generate_private_key(ec.SECP256R1())
        owner = User.objects.create(national_id_card_number="5555666677778888",
                                    digital_national_id="OWN1234",
                                    given_name="Owner", last_name="One")
        self.device = Device.objects.create(
            owner=owner, label="Field 1",
            public_key_der=self.device_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo))
        credential_keys.issuing_keys()

    def _accept(self, blob, chains):
        return trust.accept_bundle(
            blob, chain.decode_chains(chains),
            anchors=trust.Anchors(raw={}, cas=(self.ca_der,)), denied=set(),
            device_id=self.device.device_id.bytes, now=self.clock.now())

    def test_a_phone_accepts_the_signers_bundle(self):
        blob, chains = devices.build_bundle_and_chains(self.device)
        ctx = self._accept(blob, chains)
        self.assertEqual(ctx.signer, self.deployment)
        self.device.refresh_from_db()
        self.assertIsNotNone(self.device.lease_expires_at)

    def test_a_revocation_reaches_the_signer_before_the_bundle(self):
        from ovcrypto import bundle as bundle_mod, revocation

        row = IssuedCredential.objects.create(
            credential_id=uuid.uuid4(), organization=self.org,
            document_uuid=uuid.uuid4(), epoch=1, issuer_key_id=1,
            issued_at=timezone.now(),
            expires_at=timezone.now() + timedelta(days=365))
        revocation_feed.revoke(row, reason="test")
        blob, _ = devices.build_bundle_and_chains(self.device)
        f = revocation.CuckooFilter.from_bytes(
            bundle_mod.Bundle.unpack(blob).revocation)
        self.assertIn(row.credential_id.bytes, f)

    def test_keys_returns_chains_and_records_the_capability(self):
        import json

        from cryptography.hazmat.primitives import hashes

        nonce = json.loads(self.client.post(
            "/api/v1/device/challenge/").content)["challenge"]
        der = self.device_key.sign(base64.b64decode(nonce),
                                   ec.ECDSA(hashes.SHA256()))
        reply = self.client.post("/api/v1/device/keys/", data=json.dumps({
            "device_id": str(self.device.device_id), "challenge": nonce,
            "signature": base64.b64encode(der).decode(),
            "capabilities": ["issuer-chain"]}),
            content_type="application/json")
        self.assertEqual(reply.status_code, 200, reply.content)
        body = reply.json()
        self.assertIn(str(self.deployment), body["issuer_chains"])
        ctx = self._accept(base64.b64decode(body["bundle"]),
                           body["issuer_chains"])
        self.assertEqual(ctx.signer, self.deployment)
        self.device.refresh_from_db()
        self.assertIsNotNone(self.device.issuer_chain_capable_at)

    def test_the_mirror_follows_the_signer(self):
        signer_client.public(force=True)
        mirror = IssuerKey.objects.get(key_id=self.deployment)
        self.assertEqual(mirror.source, IssuerKey.SOURCE_SIGNER)
        self.assertTrue(mirror.is_active)
        self.assertEqual(mirror.state, "active")
        self.assertTrue(mirror.fingerprint_sha256)


class SignerFeedAndStatementTest(_SignerTest):

    def test_the_feed_comes_from_the_signer(self):
        feed = revocation_feed.current_feed()
        self.assertEqual(feed["key_id"], self.deployment)
        blob = base64.b64decode(feed["filter"])
        self.assertTrue(keystore.verify_p256(
            self._spki(self.deployment),
            revocation_feed.signed_bytes(feed["issued_at"], feed["not_after"],
                                         feed["key_id"], blob),
            base64.b64decode(feed["sig"])))

    def test_a_held_feed_is_served_while_the_signer_is_away(self):
        first = revocation_feed.current_feed()
        revocation_feed.invalidate()

        def away(op, **args):
            raise signer_client.Unavailable("down")

        signer_client.set_transport(away)
        self.assertEqual(revocation_feed.current_feed(), first)

    def test_the_statement_comes_from_the_signer(self):
        statement = device_log.key_statement()
        self.assertEqual(statement["sig_key_id"], self.deployment)
        self.assertTrue(keystore.verify_p256(
            self._spki(self.deployment),
            devicelog.key_statement_bytes(
                statement["key_id"], base64.b64decode(statement["public_key"]),
                statement["issued_at"], statement["not_after"],
                statement["sig_key_id"]),
            base64.b64decode(statement["sig"])))


class SignerEdgeCasesTest(_SignerTest):

    def _spy(self, op):
        seen = []
        original = signer_client._transport

        def spy(name, **args):
            if name == op:
                seen.append(args)
            return original(name, **args)

        signer_client.set_transport(spy)
        return seen

    def test_a_revocation_between_the_two_reads_is_sent_next_time(self):
        signer_client.reset()
        puts = self._spy("put_revoked")
        real_ids = revocation_feed.revoked_ids

        def ids_while_somebody_revokes():
            ids = real_ids()
            revocation_feed.bump()
            return ids

        with mock.patch.object(revocation_feed, "revoked_ids",
                               ids_while_somebody_revokes):
            signer_client.ensure_revocations()
        signer_client.ensure_revocations()
        self.assertEqual(len(puts), 2)

    def test_the_set_is_sent_again_after_ten_minutes(self):
        signer_client.reset()
        puts = self._spy("put_revoked")
        signer_client.ensure_revocations()
        signer_client.ensure_revocations()
        self.assertEqual(len(puts), 1)
        later = time.time() + signer_client.REVOKED_RESEND_SECONDS + 1
        with mock.patch.object(signer_client.time, "time", return_value=later):
            signer_client.ensure_revocations()
        self.assertEqual(len(puts), 2)

    def test_a_failure_after_signing_keeps_the_row_as_signed(self):
        from ovcrypto import qrsize

        with mock.patch.object(qrsize, "plan", side_effect=RuntimeError("big")):
            with self.assertRaises(RuntimeError):
                self._mint()
        row = IssuedCredential.objects.order_by("-pk").first()
        self.assertEqual(row.state, IssuedCredential.STATE_SIGNED)

    def test_a_holder_is_named_to_the_signer(self):
        from types import SimpleNamespace

        signs = self._spy("sign_credential")
        txn = Transaction.objects.create(organization=None,
                                         authentication_result="success")
        now = timezone.now()
        minting.mint_recorded(
            ROWS, transaction=txn, organization=None,
            claims_organization=SimpleNamespace(name="Holder Issuer"),
            holder=True, holder_id="abc123", location_code="",
            issued_at=now, expires_at=now + timedelta(days=365))
        self.assertEqual((signs[-1]["holder"], signs[-1]["holder_id"]),
                         (True, "abc123"))


@override_settings(SIGNER_SOCKET="/run/cl03-signer/app.sock")
class SignerSocketTest(TestCase):
    """The socket transport: a request that may have arrived is not "unsent"."""

    class _Socket:
        def __init__(self, fail_at):
            self.fail_at = fail_at

        def settimeout(self, _seconds):
            pass

        def connect(self, _path):
            if self.fail_at == "connect":
                raise ConnectionRefusedError("no signer")

        def sendall(self, _data):
            if self.fail_at == "send":
                raise BrokenPipeError("gone")

        def send(self, data):
            self.sendall(data)
            return len(data)

        def recv(self, _n):
            raise TimeoutError("timed out")

        def recv_into(self, _buffer, _n=0):
            raise TimeoutError("timed out")

        def close(self):
            pass

    def _call(self, fail_at):
        fake = self._Socket(fail_at)
        with mock.patch.object(signer_client.socket, "socket",
                               lambda *_a, **_k: fake), \
                mock.patch.object(signer_client.socket, "AF_UNIX", 1, create=True):
            with self.assertRaises(signer_client.Unavailable) as err:
                signer_client._socket_call("status")
        return err.exception

    def test_no_connection_means_nothing_was_sent(self):
        self.assertFalse(self._call("connect").reply_lost)

    def test_a_failure_after_connecting_may_have_been_signed(self):
        """The row of a credential that may exist is kept as unknown."""
        self.assertTrue(self._call("send").reply_lost)
        self.assertTrue(self._call("recv").reply_lost)


@override_settings(SIGNER_REPORT_TOKEN_SHA256=hashlib.sha256(b"t0ken").hexdigest())
class SignerReportTest(TestCase):

    def test_the_report_needs_the_token(self):
        self.assertEqual(self.client.get("/api/v1/signer/report/").status_code,
                         403)
        self.assertEqual(self.client.get(
            "/api/v1/signer/report/", HTTP_AUTHORIZATION="Bearer wrong"
        ).status_code, 403)

    def test_the_report_lists_credentials(self):
        org = Organization.objects.create(name="Beta")
        row = IssuedCredential.objects.create(
            credential_id=uuid.uuid4(), organization=org,
            document_uuid=uuid.uuid4(), epoch=1, issuer_key_id=16,
            issued_at=timezone.now(),
            expires_at=timezone.now() + timedelta(days=365))
        reply = self.client.get("/api/v1/signer/report/?since=0",
                                HTTP_AUTHORIZATION="Bearer t0ken")
        self.assertEqual(reply.status_code, 200)
        listed = reply.json()["credentials"]
        self.assertEqual(listed[0]["credential_id"], str(row.credential_id))
        self.assertEqual(listed[0]["organization"], str(org.signing_id))

    @override_settings(SIGNER_REPORT_TOKEN_SHA256="")
    def test_without_a_configured_token_there_is_no_report(self):
        self.assertEqual(self.client.get(
            "/api/v1/signer/report/", HTTP_AUTHORIZATION="Bearer t0ken"
        ).status_code, 404)
