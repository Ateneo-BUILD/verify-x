"""Holders: a self-verified idmanager user registering their own phone.

What these pin, in the order it matters:

* the restricted tier never reaches a phone registered this way -- not for a
  holder, and not for an operator registering through idmanager either;
* a holder cannot sign in to this site;
* an assertion is accepted only when idmanager signed it, for this
  deployment, recently, a single time, about a liveness-backed check, and
  bound to the very Enclave key the phone proves it holds;
* what is minted is an ordinary credential that opens with the fleet's own
  verifier, names a self-verification, and is recorded so it can be revoked.
"""

import base64
import datetime
import hashlib
import io
import json
import os
import shutil
import stat
import tempfile
import time
import uuid
import zipfile

from django.test import TestCase, override_settings
from django.utils import timezone

from accounts import credential_keys, holders
from accounts.models import (Device, HolderAssertion, IssuedCredential,
                             IssuerKey, Membership, Organization, Transaction,
                             User)
from ovcrypto import devicelog
from verify.views import login_guard
from verify.views.helpers import _find_user


WRAP_KEY_HEX = "00112233445566778899aabbccddeeff" * 2
ISSUER = "https://idmanager.example.org"
AUDIENCE = "https://verify.example.org"


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _p256():
    from cryptography.hazmat.primitives.asymmetric import ec

    return ec.generate_private_key(ec.SECP256R1())


def _spki(key):
    from cryptography.hazmat.primitives import serialization

    return key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)


def _keys_setting(kid, key):
    return "%s:%s" % (kid, base64.b64encode(_spki(key)).decode())


def sign_assertion(key, payload, *, kid="idm-1", alg="ES256",
                   typ=holders.TYP):
    """An ES256 compact JWS, built the way any JOSE library builds one."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature)

    header = _b64url(json.dumps({"alg": alg, "typ": typ, "kid": kid},
                                separators=(",", ":")).encode())
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    r, s = decode_dss_signature(
        key.sign(("%s.%s" % (header, body)).encode(), ECDSA(hashes.SHA256())))
    return "%s.%s.%s" % (header, body,
                         _b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big")))


def a_face(shade=128):
    """A JPEG the portrait renderer can fit -- smooth, so it compresses.

    `shade` makes a different but equally valid face: a test about a face
    nobody vouched for needs one the renderer would happily mint, or it
    proves only that a corrupt image is not rendered.
    """
    import cv2
    import numpy as np

    y, x = np.mgrid[0:240, 0:200]
    image = np.dstack([(x * 255 // 200), (y * 255 // 240),
                       np.full_like(x, shade)]).astype(np.uint8)
    ok, buffer = cv2.imencode(".jpg", image)
    assert ok
    return bytes(buffer)


@override_settings(CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX,
                   DEVICE_LEASE_SECONDS=2592000,
                   DEVICE_CHALLENGE_TTL_SECONDS=120,
                   DEVICE_PAIRING_BASE_URL=AUDIENCE,
                   HOLDER_ASSERTION_ISSUER=ISSUER,
                   HOLDER_ASSERTION_MAX_LIFETIME_SECONDS=600,
                   HOLDER_VERIFICATION_MAX_AGE_SECONDS=900,
                   HOLDER_CREDENTIAL_ISSUER_NAME="Self-verified with idmanager")
class HolderTestBase(TestCase):

    def setUp(self):
        from cryptography.hazmat.primitives import serialization

        credential_keys.reset_caches()
        self.addCleanup(credential_keys.reset_caches)

        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.pem = os.path.join(self.dir, "issuer.pem")
        self.issuer = _p256()
        with open(self.pem, "wb") as handle:
            handle.write(self.issuer.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        os.chmod(self.pem, stat.S_IRUSR | stat.S_IWUSR)
        self.issuer_spki = _spki(self.issuer)
        IssuerKey.objects.create(
            key_id=1, spki_der=self.issuer_spki, is_active=True,
            not_before=timezone.now() - datetime.timedelta(days=1),
            not_after=timezone.now() + datetime.timedelta(days=730))

        # idmanager's vouching key. Only the public half is pinned here.
        self.idm = _p256()
        self.settings_ctx = override_settings(
            CREDENTIAL_ISSUER_KEY_PATH=self.pem, CREDENTIAL_ISSUER_KEY_ID=1,
            HOLDER_ASSERTION_KEYS=_keys_setting("idm-1", self.idm))
        self.settings_ctx.enable()
        self.addCleanup(self.settings_ctx.disable)

        # The phone's Secure Enclave key, which never leaves it.
        self.device_key = _p256()
        self.device_pub = _spki(self.device_key)
        self.face = a_face()

    # -- building an assertion ---------------------------------------------

    def payload(self, **overrides):
        now = int(time.time())
        payload = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": str(uuid.uuid4()),
            "jti": uuid.uuid4().hex,
            "iat": now,
            "exp": now + 300,
            "verified_at": now - 30,
            "amr": ["everify", "liveness"],
            "cnf": {"spki_s256": holders.spki_thumbprint(self.device_pub)},
            "person": {
                "first_name": "JUAN", "middle_name": "SANTOS",
                "last_name": "DELA CRUZ", "reference": "1234-5678-9012-3456",
                "code": "abc1234", "gender": "Male",
                "birth_date": "1990-01-31",
                # Not in CREDENTIAL_FIELDS: must never be minted.
                "full_address": "1 Secret St", "blood_type": "O+",
            },
            "face_sha256": hashlib.sha256(self.face).hexdigest(),
        }
        payload.update(overrides)
        return payload

    def assertion(self, key=None, **overrides):
        return sign_assertion(key or self.idm, self.payload(**overrides))

    # -- the phone ---------------------------------------------------------

    def challenge(self):
        return json.loads(self.client.post(
            "/api/v1/device/challenge/").content)["challenge"]

    # `prefix` goes before the decoded challenge in what the phone signs, and
    # `capabilities`, when given, is what the request says it does.

    def register(self, assertion=None, *, key=None, public_key=None,
                 face=True, label="Juan's iPhone", nonce=None, prefix=b"",
                 capabilities=None):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

        nonce = nonce or self.challenge()
        signer = key or self.device_key
        der = signer.sign(prefix + base64.b64decode(nonce),
                          ECDSA(hashes.SHA256()))
        body = {
            "assertion": assertion if assertion is not None else self.assertion(),
            "device_public_key": base64.b64encode(
                public_key or self.device_pub).decode(),
            "challenge": nonce,
            "signature": base64.b64encode(der).decode(),
            "label": label,
        }
        if face:
            body["face"] = base64.b64encode(
                self.face if face is True else face).decode()
        if capabilities is not None:
            body["capabilities"] = capabilities
        return self.client.post("/api/v1/holder/register/",
                                data=json.dumps(body),
                                content_type="application/json")

    def sync(self, device_id, key=None, *, prefix=b"", capabilities=None):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

        nonce = self.challenge()
        der = (key or self.device_key).sign(prefix + base64.b64decode(nonce),
                                            ECDSA(hashes.SHA256()))
        body = {"device_id": device_id, "challenge": nonce,
                "signature": base64.b64encode(der).decode()}
        if capabilities is not None:
            body["capabilities"] = capabilities
        return self.client.post(
            "/api/v1/device/keys/", data=json.dumps(body),
            content_type="application/json")

    def refused(self, response):
        self.assertEqual(response.status_code, 403, response.content)
        self.assertEqual(json.loads(response.content)["error"],
                         holders.REFUSED)


class HolderPhonesNeverReadOtherPeoplesDetailsTest(HolderTestBase):
    """The restricted tier is everybody's details. A phone registered on
    idmanager's word is never sent it -- the one property this whole path
    could not survive getting wrong."""

    def bundle_tiers(self, response):
        from ovcrypto import bundle as bundle_mod

        device_id = json.loads(response.content)["device_id"]
        synced = self.sync(device_id)
        self.assertEqual(synced.status_code, 200, synced.content)
        parsed = bundle_mod.Bundle.unpack(
            base64.b64decode(json.loads(synced.content)["bundle"]))
        self.assertTrue(parsed.verify({1: self.issuer_spki}))
        return {entry.tier for entry in parsed.epoch_keys}

    def test_a_new_holder_is_created_without_the_restricted_tier(self):
        response = self.register()
        self.assertEqual(response.status_code, 200, response.content)
        user = User.objects.get(national_id_card_number="1234567890123456")
        # The field default is ON, for operators. A holder must not inherit it.
        self.assertFalse(user.device_restricted_tier)
        self.assertEqual(user.registered_via, User.REGISTERED_VIA_IDMANAGER)
        self.assertFalse(json.loads(response.content)["restricted_tier"])

    def test_a_holder_phone_syncs_public_keys_only(self):
        self.assertEqual(self.bundle_tiers(self.register()),
                         {credential_keys.TIER_PUBLIC})

    def test_an_operator_registering_through_idmanager_is_capped_too(self):
        org = Organization.objects.create(name="Alpha")
        operator = User.objects.create(
            national_id_card_number="1234567890123456", given_name="Juan",
            last_name="Dela Cruz", device_restricted_tier=True)
        Membership.objects.create(organization=org, user=operator)

        response = self.register()
        device = Device.objects.get(owner=operator)
        self.assertTrue(device.public_tier_only)
        self.assertFalse(device.restricted_tier)
        self.assertEqual(self.bundle_tiers(response),
                         {credential_keys.TIER_PUBLIC})
        # Their other phones are untouched: the cap is the handset's, the
        # entitlement is still the person's.
        operator.refresh_from_db()
        self.assertTrue(operator.device_restricted_tier)

    def test_the_cap_only_ever_takes_access_away(self):
        owner = User.objects.create(national_id_card_number="5555666677778888",
                                    device_restricted_tier=False)
        capped = Device(owner=owner, public_tier_only=False)
        self.assertFalse(capped.restricted_tier)


class HoldersCannotSignInTest(HolderTestBase):
    """Registering holders must not undo "verify must not auto-provision":
    a holder is a row, not an operator."""

    def setUp(self):
        super().setUp()
        self.assertEqual(self.register().status_code, 200)
        self.holder = User.objects.get(national_id_card_number="1234567890123456")

    def test_find_user_does_not_resolve_a_holder(self):
        self.assertIsNone(_find_user("ABC1234", pcn="1234567890123456"))
        self.assertIsNone(_find_user("ABC1234"))

    def test_the_login_guard_refuses_a_holder_before_eVerify(self):
        self.assertIsNone(login_guard.registered_operator("1234-5678-9012-3456"))
        self.assertIsNone(login_guard.registered_operator("abc1234"))

    def test_an_organization_adding_them_makes_them_an_operator(self):
        org = Organization.objects.create(name="Alpha")
        Membership.objects.create(organization=org, user=self.holder)
        self.assertEqual(_find_user(None, pcn="1234567890123456"), self.holder)
        self.assertEqual(
            login_guard.registered_operator("1234567890123456"), self.holder)

    def test_a_site_admin_is_never_a_holder_only(self):
        self.holder.is_site_admin = True
        self.holder.save()
        self.assertEqual(_find_user(None, pcn="1234567890123456"), self.holder)

    def test_an_ordinary_operator_is_unaffected(self):
        operator = User.objects.create(national_id_card_number="9999888877776666")
        self.assertEqual(_find_user(None, pcn="9999888877776666"), operator)


class HolderAssertionIsAcceptedOnlyWhenEverythingHoldsTest(HolderTestBase):
    """Every way an assertion can be wrong gets the same refusal."""

    def check(self, **kwargs):
        return holders.verify_assertion(
            kwargs.pop("token", None) or self.assertion(**kwargs),
            audience=AUDIENCE, device_public_key=self.device_pub)

    def assertRefused(self, **kwargs):
        with self.assertRaises(holders.HolderError) as caught:
            self.check(**kwargs)
        self.assertEqual(str(caught.exception), holders.REFUSED)

    def test_a_good_assertion_names_the_person(self):
        claims = self.check()
        self.assertEqual(claims["person"]["reference"], "1234567890123456")
        self.assertEqual(claims["person"]["code"], "ABC1234")
        self.assertEqual(claims["kid"], "idm-1")
        # Fields outside the holder set are dropped, not carried.
        self.assertNotIn("full_address", claims["person"])
        self.assertNotIn("blood_type", claims["person"])

    def test_another_key_cannot_sign_one(self):
        self.assertRefused(token=self.assertion(key=_p256()))

    def test_an_unpinned_key_id_is_refused(self):
        self.assertRefused(token=sign_assertion(self.idm, self.payload(),
                                                kid="idm-2"))

    def test_only_es256_and_this_typ(self):
        self.assertRefused(token=sign_assertion(self.idm, self.payload(),
                                                alg="none"))
        self.assertRefused(token=sign_assertion(self.idm, self.payload(),
                                                typ="JWT"))

    def test_another_issuer_is_refused(self):
        self.assertRefused(iss="https://evil.example.org")

    def test_an_assertion_for_another_deployment_is_refused(self):
        self.assertRefused(aud="https://verify-other.example.org")

    def test_an_expired_one_is_refused(self):
        now = int(time.time())
        self.assertRefused(iat=now - 400, exp=now - 1)

    def test_one_issued_in_the_future_is_refused(self):
        now = int(time.time())
        self.assertRefused(iat=now + 3600, exp=now + 3900)

    def test_one_claiming_a_long_life_is_refused(self):
        now = int(time.time())
        self.assertRefused(iat=now, exp=now + 86400)

    def test_a_stale_check_is_refused_however_fresh_the_assertion(self):
        self.assertRefused(verified_at=int(time.time()) - 3600)

    def test_a_check_without_liveness_is_refused(self):
        self.assertRefused(amr=["everify"])
        self.assertRefused(amr="everify liveness")

    def test_it_must_be_bound_to_the_presented_key(self):
        other = _spki(_p256())
        self.assertRefused(cnf={"spki_s256": holders.spki_thumbprint(other)})
        self.assertRefused(cnf={})

    def test_a_card_number_is_required(self):
        person = dict(self.payload()["person"], reference="12345")
        self.assertRefused(person=person)

    def test_a_name_is_required(self):
        person = dict(self.payload()["person"], first_name="")
        self.assertRefused(person=person)

    def test_a_boolean_is_not_a_timestamp(self):
        self.assertRefused(exp=True)

    def test_a_malformed_face_hash_is_refused(self):
        self.assertRefused(face_sha256="not-a-hash")

    def test_tampering_with_the_payload_breaks_the_signature(self):
        header, body, sig = self.assertion().split(".")
        payload = json.loads(base64.urlsafe_b64decode(body + "=="))
        payload["person"]["reference"] = "9999888877776666"
        forged = _b64url(json.dumps(payload).encode())
        self.assertRefused(token="%s.%s.%s" % (header, forged, sig))

    def test_garbage_is_refused_not_raised(self):
        for token in ("", "a.b", "a.b.c.d", "!!!.###.$$$", "x" * 20000):
            with self.subTest(token=token[:10]):
                self.assertRefused(token=token or "x")

    def test_a_bad_entry_in_the_pin_list_does_not_take_the_good_one_down(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        ed = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        setting = ",".join([
            "bad kid!:AAAA", "ed:%s" % base64.b64encode(ed).decode(),
            "junk:notbase64", _keys_setting("idm-1", self.idm)])
        with override_settings(HOLDER_ASSERTION_KEYS=setting):
            self.assertEqual(set(holders.pinned_keys()), {"idm-1"})
            self.check()

    def test_nothing_is_enabled_without_both_halves(self):
        with override_settings(HOLDER_ASSERTION_KEYS=""):
            self.assertFalse(holders.enabled())
            self.assertRefused()
        with override_settings(HOLDER_ASSERTION_ISSUER=""):
            self.assertFalse(holders.enabled())


class HolderRegistrationEndpointTest(HolderTestBase):

    def test_it_does_not_exist_while_unconfigured(self):
        with override_settings(HOLDER_ASSERTION_KEYS=""):
            response = self.register()
        self.assertEqual(response.status_code, 404)
        self.assertFalse(Device.objects.exists())

    def test_a_good_registration_returns_the_device_and_endpoints(self):
        response = self.register()
        self.assertEqual(response.status_code, 200, response.content)
        body = json.loads(response.content)
        device = Device.objects.get()
        self.assertEqual(base64.b64decode(body["device_id"]),
                         device.device_id.bytes)
        self.assertTrue(body["created"])
        self.assertEqual(body["label"], "Juan's iPhone")
        self.assertEqual(body["api_base"], AUDIENCE)
        self.assertEqual(body["endpoints"]["keys"],
                         AUDIENCE + "/api/v1/device/keys/")
        self.assertTrue(device.public_tier_only)
        self.assertEqual(HolderAssertion.objects.get().device, device)

    def test_the_assertion_is_spent_once(self):
        assertion = self.assertion()
        self.assertEqual(self.register(assertion).status_code, 200)
        self.refused(self.register(assertion))
        self.assertEqual(HolderAssertion.objects.count(), 1)

    def test_register_itself_refuses_a_spent_assertion(self):
        """Not only the unique index: `register()` says no in its own words,
        so a caller that forgot to catch IntegrityError still refuses."""
        claims = holders.verify_assertion(
            self.assertion(), audience=AUDIENCE,
            device_public_key=self.device_pub)
        holders.register(claims, self.device_pub)
        with self.assertRaises(holders.HolderError) as caught:
            holders.register(claims, self.device_pub)
        self.assertEqual(str(caught.exception), holders.REFUSED)

    def test_the_phone_must_hold_the_key_it_registers(self):
        response = self.register(key=_p256())
        self.assertEqual(response.status_code, 403)
        self.assertFalse(Device.objects.exists())

    def test_a_failed_signature_still_spends_the_challenge(self):
        nonce = self.challenge()
        self.assertEqual(self.register(key=_p256(), nonce=nonce).status_code, 403)
        response = self.register(nonce=nonce)
        self.assertEqual(response.status_code, 400)
        self.assertFalse(Device.objects.exists())

    def test_an_assertion_for_one_key_registers_nothing_on_another(self):
        other = _p256()
        response = self.register(key=other, public_key=_spki(other))
        self.refused(response)
        self.assertFalse(Device.objects.exists())

    def test_the_same_phone_coming_back_is_re_verified_not_duplicated(self):
        first = json.loads(self.register().content)
        again = json.loads(self.register().content)
        self.assertFalse(again["created"])
        self.assertEqual(first["device_id"], again["device_id"])
        self.assertEqual(Device.objects.count(), 1)
        # A fresh check is a fresh credential.
        self.assertEqual(IssuedCredential.objects.count(), 2)

    def test_a_revoked_phone_is_not_revived(self):
        self.register()
        device = Device.objects.get()
        device.revoked_at = timezone.now()
        device.save()
        response = self.register()
        self.assertEqual(response.status_code, 403)
        self.assertIsNotNone(Device.objects.get().revoked_at)

    def test_a_key_belonging_to_somebody_else_is_refused(self):
        somebody = User.objects.create(national_id_card_number="9999888877776666")
        Device.objects.create(label="theirs", public_key_der=self.device_pub,
                              owner=somebody)
        # The same refusal as any other, not "already paired": whose the key
        # is stays the log's business.
        self.refused(self.register())

    def test_an_operators_record_is_not_rewritten(self):
        org = Organization.objects.create(name="Alpha")
        operator = User.objects.create(
            national_id_card_number="1234567890123456",
            given_name="Juanito", last_name="Cruz")
        Membership.objects.create(organization=org, user=operator)
        self.register()
        operator.refresh_from_db()
        self.assertEqual((operator.given_name, operator.last_name),
                         ("Juanito", "Cruz"))
        self.assertEqual(operator.registered_via, "")

    def test_a_holders_own_record_follows_the_latest_check(self):
        self.register()
        person = dict(self.payload()["person"], last_name="SANTOS")
        self.register(self.assertion(person=person))
        self.assertEqual(
            User.objects.get(national_id_card_number="1234567890123456")
            .last_name, "SANTOS")

    def test_a_malformed_body_is_refused(self):
        response = self.client.post("/api/v1/holder/register/", data="[]",
                                    content_type="application/json")
        self.assertEqual(response.status_code, 400)

    # -- the signature behind its context --------

    def test_a_phone_saying_holder_context_signs_behind_it(self):
        response = self.register(prefix=holders.REGISTER_CONTEXT,
                                 capabilities=["holder-context"])
        self.assertEqual(response.status_code, 200, response.content)

    def test_what_is_signed_must_be_what_the_request_says(self):
        """Said and signed bare, signed and not said, another endpoint's
        context: none of them registers."""
        for prefix, says in ((b"", ["holder-context"]),
                             (holders.REGISTER_CONTEXT, []),
                             (holders.REGISTER_CONTEXT, "holder-context"),
                             (holders.PASSES_CONTEXT, ["holder-context"]),
                             (devicelog.KEYS_CONTEXT, ["holder-context"])):
            response = self.register(prefix=prefix, capabilities=says)
            self.assertEqual(response.status_code, 403, (prefix, says))
        self.assertFalse(Device.objects.exists())

    def test_required_the_bare_form_is_too_old_and_spends_nothing(self):
        nonce = self.challenge()
        with override_settings(HOLDER_REQUIRE_CONTEXT=True):
            response = self.register(nonce=nonce)
            self.assertEqual(response.status_code, 403)
            self.assertEqual(json.loads(response.content)["error"],
                             holders.TOO_OLD)
            self.assertFalse(Device.objects.exists())
            # Refused before the challenge, as `/keys/` refuses "too old".
            response = self.register(nonce=nonce,
                                     prefix=holders.REGISTER_CONTEXT,
                                     capabilities=["holder-context"])
        self.assertEqual(response.status_code, 200, response.content)

    def test_a_holder_signature_buys_nothing_at_keys(self):
        """What the contexts are for: a holder signature that reached another
        host unspent is no `/keys/` signature, whatever the request says."""
        device_id = json.loads(self.register(
            prefix=holders.REGISTER_CONTEXT,
            capabilities=["holder-context"]).content)["device_id"]
        for prefix in (holders.REGISTER_CONTEXT, holders.PASSES_CONTEXT):
            for says in ([], ["keys-context"]):
                response = self.sync(device_id, prefix=prefix,
                                     capabilities=says)
                self.assertEqual(response.status_code, 403, (prefix, says))

    def test_a_phone_with_no_ca_syncs_saying_keys_context_alone(self):
        """idmanager's phones with no issuing CA say "keys-context" and
        nothing else: a good sync, and no claim to read issuer chains."""
        device_id = json.loads(self.register().content)["device_id"]
        response = self.sync(device_id, prefix=devicelog.KEYS_CONTEXT,
                             capabilities=["keys-context"])
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIsNone(Device.objects.get().issuer_chain_capable_at)


class HolderCredentialIsAnOrdinaryCredentialTest(HolderTestBase):
    """What a holder is issued opens with the fleet's own verifier, says it
    is a self-verification, and can be revoked."""

    def open(self, qr):
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey)
        from ovcrypto import verifier

        from accounts.models import CredentialEpochKey

        epoch = credential_keys.current_epoch()
        rows = {row.tier: row
                for row in CredentialEpochKey.objects.filter(epoch=epoch)}
        device = {epoch: verifier.EpochPrivateKeys(
            epoch,
            X25519PrivateKey.from_private_bytes(credential_keys.private_key(
                rows[credential_keys.TIER_PUBLIC])),
            X25519PrivateKey.from_private_bytes(credential_keys.private_key(
                rows[credential_keys.TIER_RESTRICTED])))}
        return verifier.verify(
            "CL03:" + qr.split(":CL03:", 1)[1], epoch_keys=device,
            trust_list=verifier.TrustList.bare({1: self.issuer_spki}),
            now=int(time.time()))

    def test_it_opens_and_names_a_self_verification(self):
        from ovcrypto import verifier, wire

        credential = json.loads(self.register().content)["credential"]
        txn = Transaction.objects.get()
        self.assertTrue(credential["qr"].startswith(
            str(txn.transaction_id).upper() + ":CL03:"))

        opened = self.open(credential["qr"])
        self.assertEqual(opened.verdict, verifier.Verdict.VALID)
        public = opened.public_claims
        self.assertEqual(public[wire.T_ISSUER_ID].decode(),
                         "Self-verified with idmanager")
        self.assertEqual(public[wire.T_TRANSACTION_TYPE].decode(),
                         "Self-verification")
        self.assertEqual(public[wire.T_DOC_NUMBER].decode(),
                         str(txn.transaction_id))
        self.assertNotIn(wire.T_OPERATOR, public)

        fields = dict(wire.decode_fields(
            opened.restricted_claims[wire.T_FIELDS]))
        self.assertEqual(fields["Given Name"], "JUAN")
        self.assertEqual(fields["National ID Card Number"], "1234567890123456")
        self.assertEqual(fields["Date of Birth"], "01/31/1990")
        # Only the holder set: an address never rides a credential shown to
        # strangers.
        self.assertNotIn("1 Secret St", fields.values())
        self.assertNotIn("Permanent Address", fields)

    def test_the_server_opens_only_what_a_phone_would(self):
        """With each key's window and certified issuer, and no key whose
        certificate has ended, as a phone judges."""
        import uuid

        from accounts import holders

        qr = json.loads(self.register().content)["credential"]["qr"]
        self.assertIsNotNone(holders.open_own(qr))
        key = IssuerKey.objects.get(key_id=1)
        opened_window = key.not_before
        key.not_before = timezone.now() + datetime.timedelta(days=1)
        key.save()
        self.assertIsNone(holders.open_own(qr), "issued outside its window")
        key.not_before = opened_window
        key.organization_signing_id = uuid.uuid4()
        key.certified_name = "Another Registry"
        key.save()
        self.assertIsNone(holders.open_own(qr), "another issuer's key")
        key.organization_signing_id = None
        key.certified_name = ""
        key.cert_not_after = timezone.now() - datetime.timedelta(seconds=1)
        key.save()
        self.assertIsNone(holders.open_own(qr), "its certificate has ended")
        key.cert_not_after = None
        key.save()
        self.assertIsNotNone(holders.open_own(qr))

    def test_it_is_recorded_so_it_can_be_revoked(self):
        credential = json.loads(self.register().content)["credential"]
        issued = IssuedCredential.objects.get()
        self.assertEqual(str(issued.credential_id), credential["credential_id"])
        self.assertIsNone(issued.organization)

    def test_the_transaction_belongs_to_no_organization(self):
        self.register()
        txn = Transaction.objects.get()
        self.assertIsNone(txn.organization)
        self.assertIsNone(txn.operator)
        self.assertEqual(txn.transaction_type, "Self-verification")
        self.assertNotIn("full_address", txn.logged_fields)

    def test_the_uuid_in_front_resolves_online(self):
        credential = json.loads(self.register().content)["credential"]
        uuid_text = credential["qr"].split(":CL03:", 1)[0]
        body = json.loads(self.client.get(
            "/api/validate/%s/" % uuid_text).content)
        self.assertEqual(body["status"], "found")
        self.assertEqual(body["transaction"]["transaction_type"],
                         "Self-verification")

    def test_the_vouched_face_rides_its_own_symbol_bound_by_hash(self):
        from ovcrypto import base45, wire

        credential = json.loads(self.register().content)["credential"]
        self.assertIn("portrait_qr", credential)
        magic, cid, image = credential["portrait_qr"].split(":", 2)
        self.assertEqual(magic, "CL03F1")
        self.assertEqual(cid, credential["credential_id"].upper())
        opened = self.open(credential["qr"])
        self.assertEqual(opened.restricted_claims[wire.T_PORTRAIT_HASH],
                         hashlib.sha256(base45.decode(image)).digest())

    def test_a_face_nobody_vouched_for_is_not_minted(self):
        from ovcrypto import wire

        somebody_else = a_face(shade=20)
        self.assertNotEqual(somebody_else, self.face)
        credential = json.loads(
            self.register(face=somebody_else).content)["credential"]
        self.assertNotIn("portrait_qr", credential)
        self.assertNotIn(wire.T_PORTRAIT_HASH,
                         self.open(credential["qr"]).restricted_claims)

    def test_no_keys_means_a_registration_without_a_credential(self):
        with override_settings(CREDENTIAL_ISSUER_KEY_PATH=""):
            response = self.register()
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(json.loads(response.content)["credential"])
        self.assertTrue(Device.objects.exists())


class HolderWalletPassesTest(HolderTestBase):
    """A holder's card as ONE Apple Wallet pass: the credential, their photo.

    The same one pass the card hand-off gives. Nothing
    exists without a Pass Type certificate. Only the registered phone's
    Enclave key, on a phone idmanager vouched for, collects the pass, and
    only for symbols this deployment issued to THAT holder, intact and
    unrevoked -- with a photo only when it is the face the credential binds.
    Everything else the pass says comes from the stored transaction, never
    from the request.
    """

    def setUp(self):
        super().setUp()
        from accounts import tests as account_tests

        cert_pem, key_pem = (
            account_tests.WalletPassTest._throwaway_certificate())
        paths = {}
        for name, blob in (("cert", cert_pem), ("key", key_pem),
                           ("wwdr", cert_pem)):
            paths[name] = os.path.join(self.dir, "wallet-%s.pem" % name)
            with open(paths[name], "wb") as handle:
                handle.write(blob)
        self.wallet_ctx = override_settings(
            WALLET_PASS_TYPE_ID="pass.test.holder", WALLET_TEAM_ID="ABCDE12345",
            WALLET_CERT_PATH=paths["cert"], WALLET_KEY_PATH=paths["key"],
            WALLET_WWDR_PATH=paths["wwdr"])
        self.wallet_ctx.enable()
        self.addCleanup(self.wallet_ctx.disable)

    def registered(self, **kwargs):
        response = self.register(**kwargs)
        self.assertEqual(response.status_code, 200, response.content)
        return json.loads(response.content)

    def passes(self, device_id, credential, portrait=None, *, key=None,
               nonce=None, extra=None, prefix=b""):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA

        nonce = nonce or self.challenge()
        der = (key or self.device_key).sign(prefix + base64.b64decode(nonce),
                                            ECDSA(hashes.SHA256()))
        body = {"device_id": device_id, "challenge": nonce,
                "signature": base64.b64encode(der).decode(),
                "credential": credential}
        if portrait is not None:
            body["portrait_qr"] = portrait
        body.update(extra or {})
        return self.client.post("/api/v1/holder/passes/",
                                data=json.dumps(body),
                                content_type="application/json")

    def unpack(self, response):
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIn("no-store", response["Cache-Control"])
        return {item["kind"]: zipfile.ZipFile(
                    io.BytesIO(base64.b64decode(item["pkpass"])))
                for item in json.loads(response.content)["passes"]}

    def pass_json(self, archive):
        return json.loads(archive.read("pass.json"))

    def not_yours(self, response):
        self.assertEqual(response.status_code, 403, response.content)
        self.assertEqual(json.loads(response.content)["error"],
                         holders.NOT_YOURS)

    def both(self, body):
        credential = body["credential"]
        return (body["device_id"], credential["qr"],
                credential.get("portrait_qr"))

    # -- whether it exists at all -------------------------------------------

    def test_nothing_exists_without_a_pass_certificate(self):
        with override_settings(WALLET_CERT_PATH=""):
            body = self.registered()
            self.assertIsNone(body["wallet_passes"])
            device_id, qr, face = self.both(body)
            self.assertEqual(self.passes(device_id, qr, face).status_code, 404)

    def test_nothing_exists_without_holders_either(self):
        device_id, qr, face = self.both(self.registered())
        with override_settings(HOLDER_ASSERTION_KEYS=""):
            self.assertEqual(self.passes(device_id, qr, face).status_code, 404)

    def test_keys_the_site_cannot_open_are_a_503_not_a_500(self):
        from unittest.mock import patch

        from accounts import devices
        device_id, qr, face = self.both(self.registered())
        with patch("accounts.credential_keys.readable", return_value=False):
            with self.assertLogs("accounts.holders", "ERROR"):
                response = self.passes(device_id, qr, face)
        self.assertEqual(response.status_code, 503, response.content)
        self.assertEqual(json.loads(response.content)["error"], devices.KEYS_UNAVAILABLE)

    def test_a_phone_not_registered_is_told_to_register_again(self):
        """Not the verifier app's words about pairing codes."""
        from verify.views import holder_api
        self.registered()
        response = self.passes(str(uuid.uuid4()), "CL03:X")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(json.loads(response.content)["error"], holder_api.HOLDER_UNKNOWN)
        self.assertNotIn("code", holder_api.HOLDER_UNKNOWN)

    def test_the_registration_says_where_to_collect_them(self):
        self.assertEqual(self.registered()["wallet_passes"],
                         AUDIENCE + "/api/v1/holder/passes/")

    # -- what a holder collects ---------------------------------------------

    def test_one_pass_carries_the_credential_and_the_photo(self):
        from accounts import wallet_pass
        from ovcrypto import base45

        device_id, qr, face = self.both(self.registered())
        response = self.passes(device_id, qr, face)
        self.assertEqual([item["kind"] for item in
                          json.loads(response.content)["passes"]],
                         ["credential"])
        archive = self.unpack(response)["credential"]
        body = self.pass_json(archive)

        # The credential is the one barcode, and the pass names no symbol.
        self.assertEqual(len(body["barcodes"]), 1)
        self.assertEqual(body["barcodes"][0]["message"], qr.upper())
        self.assertNotIn("CL03F1", json.dumps(body))
        self.assertNotIn("headerFields", body["generic"])
        # The photo is the very face the portrait symbol carries -- the one
        # own_symbols() proved -- at 1x, 2x and 3x.
        webp = base45.decode(face.split(":", 2)[2])
        for scale, name in ((1, "thumbnail.png"), (2, "thumbnail@2x.png"),
                            (3, "thumbnail@3x.png")):
            expected = wallet_pass._png_photo(webp, 90 * scale)
            self.assertIsNotNone(expected, name)
            self.assertEqual(archive.read(name), expected, name)

        issued = IssuedCredential.objects.get()
        self.assertEqual(body["serialNumber"],
                         str(issued.transaction.transaction_id))
        self.assertEqual(body["expirationDate"], issued.expires_at.isoformat())
        self.assertIn("icon.png", archive.namelist())

    def test_an_avif_portrait_still_gives_the_pass_its_photo(self):
        """With PORTRAIT_FORMAT=avif the symbol carries the compact form,
        which no image library opens as it stands. The photo has to come
        through the decoder that rebuilds the container, or every AVIF
        holder's pass loses its picture without a word -- a face that will
        not decode costs only the photo, by design, so nothing would say."""
        import cv2
        import numpy as np

        from accounts import credentials, portrait_avif, wallet_pass
        from ovcrypto import base45

        if not portrait_avif.available():
            self.skipTest("Pillow without AVIF support")
        with override_settings(PORTRAIT_FORMAT="avif"):
            device_id, qr, face = self.both(self.registered())
            self.assertTrue(face.startswith("CL03F2:"))
            archive = self.unpack(self.passes(device_id, qr, face))["credential"]
        compact = base45.decode(face.split(":", 2)[2])
        expected = wallet_pass._png_photo(compact, 180)
        self.assertIsNotNone(expected)
        self.assertEqual(archive.read("thumbnail@2x.png"), expected)
        photo = cv2.imdecode(np.frombuffer(expected, np.uint8),
                             cv2.IMREAD_GRAYSCALE)
        self.assertEqual(max(photo.shape), 180)
        face_px = credentials.decode_portrait(compact)
        self.assertAlmostEqual(float(photo.mean()), float(face_px.mean()),
                               delta=3)

    def test_the_photo_keeps_the_portraits_shape(self):
        import cv2
        import numpy as np

        from accounts import wallet_pass

        ok, tall = cv2.imencode(".webp", np.full((160, 120), 128, np.uint8))
        self.assertTrue(ok)
        photo = cv2.imdecode(np.frombuffer(
            wallet_pass._png_photo(bytes(tall), 180), np.uint8),
            cv2.IMREAD_COLOR)
        self.assertEqual(photo.shape[:2], (180, 135))

    def test_what_the_pass_says_comes_from_the_record(self):
        device_id, qr, face = self.both(self.registered())
        archives = self.unpack(self.passes(
            device_id, qr, face,
            extra={"holder": "MALLORY", "card_number": "9999",
                   "organization": "Somebody Else"}))
        body = self.pass_json(archives["credential"])
        text = json.dumps(body)
        for planted in ("MALLORY", "9999", "Somebody Else"):
            self.assertNotIn(planted, text)
        generic = body["generic"]
        self.assertEqual(generic["primaryFields"][0]["value"],
                         "JUAN SANTOS DELA CRUZ")
        secondary = {f["key"]: f["value"] for f in generic["secondaryFields"]}
        logged = Transaction.objects.get().logged_fields
        self.assertEqual(secondary, {"card": logged["reference"],
                                     "digital": logged["code"]})
        self.assertEqual(body["organizationName"], "Self-verified with idmanager")
        self.assertEqual(body["passTypeIdentifier"], "pass.test.holder")

    def test_the_registration_carries_the_card_the_phone_draws(self):
        from verify.views import handoff

        card = self.registered()["credential"]["card"]
        txn = Transaction.objects.get()
        # As logged -- normalised the way the credential carries them.
        self.assertEqual(txn.logged_fields["reference"], "1234567890123456")
        self.assertEqual(card, {
            "organization": "Self-verified with idmanager",
            "holder": "JUAN SANTOS DELA CRUZ",
            "card_number": "1234567890123456",
            "digital_id": "ABC1234",
            "transaction_type": "Self-verification",
            "location": "",
            "verified_at": handoff.verified_at_text(txn.verification_timestamp),
            "expires_on": handoff.expires_on_text(
                IssuedCredential.objects.get(transaction=txn).expires_at),
            "transaction_id": str(txn.transaction_id),
        })

    def test_without_a_portrait_the_pass_has_no_photo(self):
        device_id, qr, face = self.both(self.registered(face=False))
        self.assertIsNone(face)
        archives = self.unpack(self.passes(device_id, qr))
        self.assertEqual(set(archives), {"credential"})
        archive = archives["credential"]
        self.assertEqual(self.pass_json(archive)["barcodes"][0]["message"],
                         qr.upper())
        self.assertFalse([name for name in archive.namelist()
                          if name.startswith("thumbnail")])

    def test_a_face_that_will_not_decode_costs_only_the_photo(self):
        from accounts import wallet_pass

        self.assertIsNone(wallet_pass._png_photo(b"not an image", 180))
        blob = wallet_pass.for_holder(
            {"transaction_id": "t-1", "holder": "JUAN"},
            message="T-1:CL03:ABC", face=b"not an image")
        self.assertIsNotNone(blob)
        names = zipfile.ZipFile(io.BytesIO(blob)).namelist()
        self.assertIn("pass.json", names)
        self.assertFalse([n for n in names if n.startswith("thumbnail")])

    # -- who may collect them -----------------------------------------------

    def test_only_the_registered_phones_key_collects(self):
        device_id, qr, face = self.both(self.registered())
        nonce = self.challenge()
        response = self.passes(device_id, qr, face, key=_p256(), nonce=nonce)
        self.assertEqual(response.status_code, 403)
        # The challenge was spent by the failure, as `/keys/` spends it.
        self.assertEqual(
            self.passes(device_id, qr, face, nonce=nonce).status_code, 400)

    def test_a_phone_saying_holder_context_collects_behind_it(self):
        device_id, qr, face = self.both(self.registered())
        says = {"capabilities": ["holder-context"]}
        self.unpack(self.passes(device_id, qr, face,
                                prefix=holders.PASSES_CONTEXT, extra=says))
        # Said and signed bare, signed and not said, another endpoint's
        # context: none collects.
        for prefix, extra in ((b"", says),
                              (holders.PASSES_CONTEXT, {"capabilities": []}),
                              (holders.REGISTER_CONTEXT, says),
                              (devicelog.KEYS_CONTEXT, says)):
            response = self.passes(device_id, qr, face, prefix=prefix,
                                   extra=extra)
            self.assertEqual(response.status_code, 403, (prefix, extra))

    def test_required_the_bare_form_is_too_old_for_any_id(self):
        """Said before the device is looked up, so the same for a live id
        and an unknown one."""
        device_id, qr, face = self.both(self.registered())
        with override_settings(HOLDER_REQUIRE_CONTEXT=True):
            for who in (device_id, str(uuid.uuid4())):
                response = self.passes(who, qr, face)
                self.assertEqual(response.status_code, 403)
                self.assertEqual(json.loads(response.content)["error"],
                                 holders.TOO_OLD)
            self.unpack(self.passes(
                device_id, qr, face, prefix=holders.PASSES_CONTEXT,
                extra={"capabilities": ["holder-context"]}))

    def test_a_revoked_phone_collects_nothing(self):
        device_id, qr, face = self.both(self.registered())
        Device.objects.update(revoked_at=timezone.now())
        self.assertEqual(self.passes(device_id, qr, face).status_code, 403)

    def test_a_phone_idmanager_did_not_vouch_for_holds_nobodys_card(self):
        device_id, qr, face = self.both(self.registered())
        HolderAssertion.objects.all().delete()
        self.not_yours(self.passes(device_id, qr, face))

    def test_somebody_elses_credential_is_refused(self):
        mine = self.registered()
        other_key = _p256()
        other_pub = _spki(other_key)
        person = dict(self.payload()["person"], first_name="MARIA",
                      reference="9999-8888-7777-6666", code="xyz9876")
        theirs = self.registered(
            assertion=self.assertion(
                cnf={"spki_s256": holders.spki_thumbprint(other_pub)},
                person=person),
            key=other_key, public_key=other_pub)
        _, their_qr, their_face = self.both(theirs)
        self.not_yours(self.passes(mine["device_id"], their_qr, their_face))
        # ...and a genuine pair is still served to its own phone.
        self.assertEqual(
            self.passes(theirs["device_id"], their_qr, their_face,
                        key=other_key).status_code, 200)

    def test_only_a_self_verification_goes_in_a_holders_wallet(self):
        """The same person verified at a counter holds that organization's
        document credential -- not one for this endpoint to sign into a
        pass as the holder's own."""
        device_id, qr, face = self.both(self.registered())
        Transaction.objects.update(transaction_type="Civil registry request")
        self.not_yours(self.passes(device_id, qr, face))
        Transaction.objects.update(
            transaction_type="Self-verification",
            organization=Organization.objects.create(name="Alpha"))
        self.not_yours(self.passes(device_id, qr, face))

    # -- what may be put in one ---------------------------------------------

    def test_a_tampered_credential_is_refused(self):
        device_id, qr, face = self.both(self.registered())
        front, body = qr.split(":CL03:", 1)
        flipped = body[:40] + ("A" if body[40] != "A" else "B") + body[41:]
        self.not_yours(self.passes(device_id, front + ":CL03:" + flipped))
        self.not_yours(self.passes(device_id, "not a credential"))

    def test_the_reserved_marker_does_not_go_in_a_wallet(self):
        """The reserved designators are read by nothing."""
        from ovcrypto import wire
        device_id, qr, face = self.both(self.registered())
        front, body = qr.split(":CL03:", 1)
        self.not_yours(self.passes(
            device_id, front + ":" + wire.LEGACY_QR_PREFIX + body, face))

    def test_the_uuid_in_front_must_be_the_credentials_own(self):
        device_id, qr, face = self.both(self.registered())
        body = qr.split(":CL03:", 1)[1]
        self.not_yours(self.passes(
            device_id, str(uuid.uuid4()).upper() + ":CL03:" + body))

    def test_a_revoked_credential_is_refused(self):
        device_id, qr, face = self.both(self.registered())
        IssuedCredential.objects.update(revoked_at=timezone.now())
        self.not_yours(self.passes(device_id, qr, face))

    def test_an_expired_credential_is_refused(self):
        from unittest import mock

        device_id, qr, face = self.both(self.registered())
        with mock.patch("accounts.holders.time") as clock:
            clock.time.return_value = time.time() + 20 * 365 * 86400
            self.not_yours(self.passes(device_id, qr, face))

    def test_a_face_the_credential_does_not_bind_is_refused(self):
        from ovcrypto import base45

        device_id, qr, face = self.both(self.registered())
        magic, cid, _image = face.split(":", 2)
        swapped = "%s:%s:%s" % (magic, cid, base45.encode(b"somebody else"))
        self.not_yours(self.passes(device_id, qr, swapped))
        elsewhere = face.replace(cid, str(uuid.uuid4()).upper())
        self.not_yours(self.passes(device_id, qr, elsewhere))
        self.not_yours(self.passes(device_id, qr, "CL03F1:garbage"))
