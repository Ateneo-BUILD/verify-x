"""App Attest at pairing and at each sync, and the /keys/ signing context.

A real attestation needs a real phone and Apple's servers, so these build
objects shaped like Apple's from a root of their own and stand it in for
Apple's (`ovcrypto.appattest.apple_root`). The checks themselves are pinned
in OfflineVerifier's tests/test_appattest.py; what is pinned here is what
verify does with their answers: records them, and refuses only when
DEVICE_REQUIRE_APP_ATTEST says to.
"""

import base64
import datetime
import hashlib
import json
import os
import shutil
import stat
import struct
import tempfile
import uuid
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from django.test import TestCase, override_settings
from django.utils import timezone

from accounts import credential_keys
from accounts.models import Device, DeviceTicket, IssuerKey, User
from accounts.tests import (ORG_SESSION_KEY, SESSION_KEY, WRAP_KEY_HEX, join,
                            make_org)
from ovcrypto import appattest, devicelog

APP_ID = "ABCDE12345.edu.example.verifier"


# -- a phone's App Attest key, with a chain shaped like Apple's ---------------

def _head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for info, width in ((24, 1), (25, 2), (26, 4)):
        if n < 1 << (8 * width):
            return bytes([major << 5 | info]) + n.to_bytes(width, "big")
    raise ValueError(n)


def _cbor(value):
    if isinstance(value, int):
        return _head(0, value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        return _head(3, len(value.encode())) + value.encode()
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(_cbor(v) for v in value)
    return _head(5, len(value)) + b"".join(_cbor(k) + _cbor(v)
                                           for k, v in value.items())


def _cert(key, issuer_key, subject, issuer, *, ca, extensions=()):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
               .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=30))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    for ext in extensions:
        builder = builder.add_extension(ext, critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


class AttestKey:
    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP384R1())
        self.root = _cert(self.root_key, self.root_key, "Root", "Root", ca=True)
        self.int_key = ec.generate_private_key(ec.SECP384R1())
        self.intermediate = _cert(self.int_key, self.root_key, "Int", "Root", ca=True)
        self.key = ec.generate_private_key(ec.SECP256R1())
        point = self.key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.key_id = hashlib.sha256(point).digest()

    def attestation(self, challenge: bytes, *, app_id=APP_ID) -> str:
        auth = (hashlib.sha256(app_id.encode()).digest() + b"\x41"
                + struct.pack(">I", 0) + appattest.AAGUIDS["development"]
                + struct.pack(">H", 32) + self.key_id)
        nonce = hashlib.sha256(auth + hashlib.sha256(challenge).digest()).digest()
        cred = _cert(self.key, self.int_key, "cred", "Int", ca=False, extensions=[
            x509.UnrecognizedExtension(x509.ObjectIdentifier(appattest.NONCE_OID),
                                       bytes.fromhex("3024a1220420") + nonce)])
        der = [c.public_bytes(serialization.Encoding.DER)
               for c in (cred, self.intermediate)]
        return base64.b64encode(_cbor({"fmt": "apple-appattest",
                                       "attStmt": {"x5c": der},
                                       "authData": auth})).decode()

    def assertion(self, client_data: bytes, counter: int) -> str:
        auth = (hashlib.sha256(APP_ID.encode()).digest() + b"\x40"
                + struct.pack(">I", counter))
        nonce = hashlib.sha256(auth + hashlib.sha256(client_data).digest()).digest()
        return base64.b64encode(_cbor({
            "signature": self.key.sign(nonce, ec.ECDSA(hashes.SHA256())),
            "authenticatorData": auth})).decode()


@override_settings(CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX,
                   DEVICE_PAIRING_TTL_SECONDS=900,
                   DEVICE_LEASE_SECONDS=2592000,
                   DEVICE_CHALLENGE_TTL_SECONDS=120,
                   DEVICE_REQUIRE_APP_ATTEST=False,
                   DEVICE_APP_ATTEST_APP_ID=APP_ID,
                   DEVICE_APP_ATTEST_ENVIRONMENT="development",
                   DEVICE_PAIRING_BASE_URL="https://verify.example.org")
class AppAttestTest(TestCase):

    def setUp(self):
        credential_keys.reset_caches()
        self.addCleanup(credential_keys.reset_caches)
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        pem = os.path.join(self.dir, "issuer.pem")
        issuer = ec.generate_private_key(ec.SECP256R1())
        with open(pem, "wb") as handle:
            handle.write(issuer.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        os.chmod(pem, stat.S_IRUSR | stat.S_IWUSR)
        ctx = override_settings(CREDENTIAL_ISSUER_KEY_PATH=pem,
                                CREDENTIAL_ISSUER_KEY_ID=1)
        ctx.enable()
        self.addCleanup(ctx.disable)
        IssuerKey.objects.create(
            key_id=1, is_active=True,
            spki_der=issuer.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo),
            not_before=timezone.now() - datetime.timedelta(days=1),
            not_after=timezone.now() + datetime.timedelta(days=730))
        self.org = make_org(name="Alpha")
        self.user = User.objects.create(national_id_card_number="1111222233334444",
                                        given_name="Ada")
        join(self.org, self.user)
        self.device_key = ec.generate_private_key(ec.SECP256R1())
        self.device_pub = self.device_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.phone = AttestKey()
        patcher = mock.patch("ovcrypto.appattest.apple_root",
                             return_value=self.phone.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    # -- helpers ------------------------------------------------------------

    def _challenge(self):
        return json.loads(self.client.post("/api/v1/device/challenge/").content)["challenge"]

    def _mint(self, purpose="enrol", device_id=None):
        session = self.client.session
        session[SESSION_KEY] = self.user.id
        session[ORG_SESSION_KEY] = self.org.id
        session.save()
        data = {"purpose": purpose, "label": "Gate 3"}
        if device_id:
            data["device_id"] = device_id
        self.client.post("/app/devices/ticket/", data)
        return DeviceTicket.objects.filter(user=self.user).latest("created_at")

    def _enrol(self, *, attest=True, challenge=None, public_key=None, ticket=None,
               bound=True, attested_key=None, attestation=None, key_id=None):
        """`bound` is a phone whose attestation names the key it pairs, and
        says so. `attested_key` is the key the phone attested for, when a
        relay posts another (`public_key`)."""
        public_key = public_key or self.device_pub
        body = {"enrolment_code": (ticket or self._mint()).code,
                "device_public_key": base64.b64encode(public_key).decode(),
                "label": "Gate 3 iPhone"}
        if attest:
            nonce = challenge or self._challenge()
            raw = base64.b64decode(nonce)
            client_data = (appattest.attest_client_data(raw, attested_key or public_key)
                           if bound else raw)
            body.update(attestation=attestation or self.phone.attestation(client_data),
                        attest_key_id=(key_id if key_id is not None else
                                       base64.b64encode(self.phone.key_id).decode()),
                        challenge=nonce)
            if bound:
                body["capabilities"] = ["attest-device-key"]
        return self.client.post("/api/v1/device/enrol/", data=json.dumps(body),
                                content_type="application/json")

    def _sync(self, device_id, *, counter=1, assertion=True, context=True,
              key=None):
        nonce = self._challenge()
        raw = base64.b64decode(nonce)
        message = devicelog.keys_signed_bytes(raw) if context else raw
        body = {"device_id": device_id, "challenge": nonce,
                "signature": base64.b64encode((key or self.device_key).sign(
                    message, ec.ECDSA(hashes.SHA256()))).decode()}
        if context:
            body["capabilities"] = ["issuer-chain", "keys-context"]
        if assertion:
            body["assertion"] = self.phone.assertion(raw, counter)
        return self.client.post("/api/v1/device/keys/", data=json.dumps(body),
                                content_type="application/json")

    def _device_id(self, response):
        self.assertEqual(response.status_code, 200, response.content)
        return json.loads(response.content)["device_id"]

    # -- pairing ------------------------------------------------------------

    def test_an_attested_pairing_records_the_attested_key(self):
        self._device_id(self._enrol())
        device = Device.objects.get()
        self.assertEqual(device.attest_status, "attested")
        self.assertEqual(bytes(device.attest_public_key_der),
                         self.phone.key.public_key().public_bytes(
                             serialization.Encoding.DER,
                             serialization.PublicFormat.SubjectPublicKeyInfo))

    def test_a_pairing_with_no_attestation_is_recorded_as_such(self):
        self._device_id(self._enrol(attest=False))
        self.assertEqual(Device.objects.get().attest_status, "absent")

    @override_settings(DEVICE_APP_ATTEST_APP_ID="")
    def test_a_site_with_no_app_id_records_that(self):
        self._device_id(self._enrol())
        self.assertEqual(Device.objects.get().attest_status, "unconfigured")

    def test_a_challenge_this_site_never_issued_fails_but_does_not_refuse(self):
        invented = base64.b64encode(os.urandom(24)).decode()
        self._device_id(self._enrol(challenge=invented))
        device = Device.objects.get()
        self.assertEqual(device.attest_status, "failed")
        self.assertIn("challenge", device.attest_detail)

    @override_settings(DEVICE_REQUIRE_APP_ATTEST=True)
    def test_required_a_failed_attestation_refuses_the_pairing(self):
        invented = base64.b64encode(os.urandom(24)).decode()
        self.assertEqual(self._enrol(challenge=invented).status_code, 400)
        self.assertFalse(Device.objects.exists())

    @override_settings(DEVICE_REQUIRE_APP_ATTEST=True)
    def test_required_an_attested_pairing_goes_through(self):
        self._device_id(self._enrol())
        self.assertEqual(Device.objects.get().attest_status, "attested")

    def test_a_relay_cannot_pair_its_own_key_under_a_phones_attestation(self):
        """A genuine attestation for the phone's Enclave key, posted beside a
        key kept in software, names the other key, so it fails -- and with
        the check required, nothing is paired."""
        software = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self._device_id(self._enrol(public_key=software, attested_key=self.device_pub))
        device = Device.objects.get()
        self.assertEqual(device.attest_status, "failed")
        self.assertIn("nonce", device.attest_detail)
        self.assertIsNone(device.attest_public_key_der)
        Device.objects.all().delete()
        with self.settings(DEVICE_REQUIRE_APP_ATTEST=True):
            response = self._enrol(public_key=software, attested_key=self.device_pub)
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Device.objects.exists())

    def test_an_attestation_that_does_not_name_its_key_is_not_counted(self):
        """An older app's: over the bare challenge, and saying nothing. It is
        recorded as not sent, and refused where the check is required."""
        self._device_id(self._enrol(bound=False))
        device = Device.objects.get()
        self.assertEqual(device.attest_status, "absent")
        self.assertIn("older app", device.attest_detail)
        Device.objects.all().delete()
        with self.settings(DEVICE_REQUIRE_APP_ATTEST=True):
            self.assertEqual(self._enrol(bound=False).status_code, 400)

    def test_a_certificate_it_cannot_read_is_a_failure_not_a_500(self):
        """An unknown signature algorithm in the credential certificate is a
        failed check, never an UnsupportedAlgorithm that nothing catches."""
        nonce = self._challenge()
        good = self.phone.attestation(appattest.attest_client_data(
            base64.b64decode(nonce), self.device_pub))
        obj = appattest.cbor_loads(base64.b64decode(good))
        x5c = obj["attStmt"]["x5c"]
        patched = x5c[0].replace(bytes.fromhex("06082a8648ce3d040302"),
                                 bytes.fromhex("06082a8648ce3d040309"))
        self.assertNotEqual(patched, x5c[0])
        bad = base64.b64encode(_cbor({"fmt": "apple-appattest",
                                      "attStmt": {"x5c": [patched, x5c[1]]},
                                      "authData": obj["authData"]})).decode()
        self._device_id(self._enrol(challenge=nonce, attestation=bad))
        self.assertEqual(Device.objects.get().attest_status, "failed")

    def test_an_attest_key_id_that_is_not_text_is_not_a_500(self):
        self._device_id(self._enrol(key_id=5))
        device = Device.objects.get()
        self.assertEqual((device.attest_status, device.attest_key_id), ("failed", ""))

    # -- each sync ------------------------------------------------------------

    def test_an_assertion_advances_the_counter(self):
        device_id = self._device_id(self._enrol())
        self.assertEqual(self._sync(device_id, counter=1).status_code, 200)
        self.assertEqual(self._sync(device_id, counter=2).status_code, 200)
        device = Device.objects.get()
        self.assertEqual((device.attest_counter, device.attest_status), (2, "attested"))

    def test_a_failed_assertion_is_recorded_and_stays_recorded(self):
        """One is what a cloned app looks like, so it stays until the phone
        pairs again; with the check only recorded, the sync still goes on."""
        device_id = self._device_id(self._enrol())
        self._sync(device_id, counter=5)
        self.assertEqual(self._sync(device_id, assertion=False).status_code, 200)
        self._sync(device_id, counter=6)
        device = Device.objects.get()
        self.assertEqual(device.attest_status, "failed")
        self.assertIn("no assertion", device.attest_detail)

    def test_a_counter_that_does_not_advance_refuses_that_sync_only(self):
        """Each challenge is single-use and signed, so a counter that does not
        advance is the phone's own sync overtaken by another -- a double tap.
        That sync alone is refused: recording it as a failure would lock the
        phone out until it paired again."""
        device_id = self._device_id(self._enrol())
        self._sync(device_id, counter=5)
        with self.assertLogs("accounts.devices", "WARNING"):
            self.assertEqual(self._sync(device_id, counter=5).status_code, 200)
        with self.settings(DEVICE_REQUIRE_APP_ATTEST=True):
            with self.assertLogs("accounts.devices", "WARNING"):
                self.assertEqual(self._sync(device_id, counter=4).status_code, 403)
            self.assertEqual(self._sync(device_id, counter=6).status_code, 200)
        device = Device.objects.get()
        self.assertEqual((device.attest_counter, device.attest_status), (6, "attested"))

    @override_settings(DEVICE_REQUIRE_APP_ATTEST=True)
    def test_required_a_failed_assertion_refuses_the_sync(self):
        device_id = self._device_id(self._enrol())
        self.assertEqual(self._sync(device_id, counter=3).status_code, 200)
        self.assertEqual(self._sync(device_id, counter=3).status_code, 403)
        self.assertEqual(self._sync(device_id, assertion=False).status_code, 403)

    @override_settings(DEVICE_REQUIRE_APP_ATTEST=True)
    def test_required_a_failure_refuses_every_later_sync_until_it_pairs_again(self):
        """After a failed assertion a good one is not served either, while the
        Devices page says FAILED: the phone has to pair again."""
        device_id = self._device_id(self._enrol())
        self._sync(device_id, counter=5)
        self.assertEqual(self._sync(device_id, assertion=False).status_code, 403)
        self.assertEqual(self._sync(device_id, counter=6).status_code, 403)
        self.assertEqual(Device.objects.get().attest_counter, 5)

    def test_a_counter_another_sync_moved_past_is_not_stored(self):
        """Two syncs racing: this one's check read the counter before the
        other's update, and passed at 5, below the 6 stored."""
        device_id = self._device_id(self._enrol())
        Device.objects.update(attest_counter=6)
        with mock.patch("ovcrypto.appattest.verify_assertion", return_value=5):
            self.assertEqual(self._sync(device_id, counter=5).status_code, 200)
            with self.settings(DEVICE_REQUIRE_APP_ATTEST=True):
                self.assertEqual(self._sync(device_id, counter=5).status_code, 403)
        device = Device.objects.get()
        self.assertEqual((device.attest_counter, device.attest_status), (6, "attested"))

    @override_settings(DEVICE_REQUIRE_APP_ATTEST=True)
    def test_required_a_holder_phone_still_syncs(self):
        """idmanager's holder phones never attest; they are public-tier only,
        on idmanager's signed word, and requiring App Attest would have cut
        them off."""
        with self.settings(DEVICE_REQUIRE_APP_ATTEST=False):
            device_id = self._device_id(self._enrol(attest=False))
        self.assertEqual(self._sync(device_id, assertion=False).status_code, 403)
        Device.objects.update(public_tier_only=True)
        self.assertEqual(self._sync(device_id, assertion=False).status_code, 200)

    def test_a_phone_paired_before_the_check_syncs_while_it_is_only_recorded(self):
        device_id = self._device_id(self._enrol(attest=False))
        self.assertEqual(self._sync(device_id, assertion=False).status_code, 200)

    def test_required_a_phone_with_no_attested_key_is_refused(self):
        device_id = self._device_id(self._enrol(attest=False))
        with override_settings(DEVICE_REQUIRE_APP_ATTEST=True):
            self.assertEqual(self._sync(device_id, assertion=False).status_code, 403)

    def test_a_rekey_starts_its_attestation_afresh(self):
        device_id = self._device_id(self._enrol())
        self._sync(device_id, counter=4)
        self._sync(device_id, assertion=False)
        self.assertEqual(Device.objects.get().attest_status, "failed")
        hyphenated = str(uuid.UUID(bytes=base64.b64decode(device_id)))
        new_key = ec.generate_private_key(ec.SECP256R1())
        response = self._enrol(
            ticket=self._mint("rekey", hyphenated),
            public_key=new_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo))
        self.assertEqual(response.status_code, 200, response.content)
        device = Device.objects.get()
        self.assertEqual((device.attest_status, device.attest_counter), ("attested", 0))

    def test_the_devices_page_says_what_was_found(self):
        self._device_id(self._enrol())
        page = self.client.get("/app/devices/").content.decode()
        self.assertIn("App Attest: passed", page)

    # -- the /keys/ signing context ------------------------------------

    def test_a_phone_saying_keys_context_is_checked_with_it(self):
        device_id = self._device_id(self._enrol(attest=False))
        self.assertEqual(self._sync(device_id, assertion=False).status_code, 200)

    def test_an_older_phone_still_signs_the_bare_challenge(self):
        device_id = self._device_id(self._enrol(attest=False))
        self.assertEqual(self._sync(device_id, assertion=False,
                                    context=False).status_code, 200)

    def test_a_bare_signature_does_not_pass_as_keys_context(self):
        device_id = self._device_id(self._enrol(attest=False))
        nonce = self._challenge()
        body = {"device_id": device_id, "challenge": nonce,
                "capabilities": ["keys-context"],
                "signature": base64.b64encode(self.device_key.sign(
                    base64.b64decode(nonce), ec.ECDSA(hashes.SHA256()))).decode()}
        response = self.client.post("/api/v1/device/keys/", data=json.dumps(body),
                                    content_type="application/json")
        self.assertEqual(response.status_code, 403)

    @override_settings(DEVICE_REQUIRE_KEYS_CONTEXT=True)
    def test_the_bare_form_can_be_switched_off(self):
        device_id = self._device_id(self._enrol(attest=False))
        response = self._sync(device_id, assertion=False, context=False)
        self.assertEqual(response.status_code, 403)
        self.assertIn("too old", json.loads(response.content)["error"])

    @override_settings(DEVICE_REQUIRE_KEYS_CONTEXT=True)
    def test_too_old_is_said_alike_for_any_id(self):
        """Said before the device is looked up: said after, it would tell a
        live id from an unknown one."""
        live = self._device_id(self._enrol(attest=False))
        answers = []
        for device_id in (live, str(uuid.uuid4())):
            body = {"device_id": device_id, "challenge": self._challenge(),
                    "signature": "c2ln"}
            response = self.client.post("/api/v1/device/keys/",
                                        data=json.dumps(body),
                                        content_type="application/json")
            answers.append((response.status_code, response.content))
        self.assertEqual(answers[0], answers[1])
        self.assertEqual(answers[0][0], 403)
