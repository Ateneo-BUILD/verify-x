"""The document, the log, the credential and the card are made of eVerify's
answer and nothing else (accounts/verified_answer.py).

Every lookup here goes through the real `POST /everify/` with only the
upstream faked, because the property being pinned is that the answer the
server KEPT is what is used -- not whatever a test, or a browser, hands the
log afterwards. The bodies posted to the log deliberately carry somebody
else: a helper that stored and posted the same rows could not tell reading
the session from reading the request.
"""

import json
import os
import shutil
import stat
import tempfile
import time
from unittest.mock import MagicMock, patch

import requests
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext

from accounts import credential_keys, user_records, verified_answer
from accounts.models import (CardHandoff, IssuedCredential, SiteSettings,
                             Transaction, TransactionType, User)
from accounts.tests import (SESSION_KEY, TEST_EVERIFY_HOSTS, WRAP_KEY_HEX, join,
                            keep_answer, make_org)
from accounts.tests_capacity import _session_writes
from verify.views.helpers import ORG_SESSION_KEY

PERSON = {
    "reference": "1111222233334444", "code": "ABC1234",
    "first_name": "JUAN", "middle_name": "SANTOS", "last_name": "DELA CRUZ",
    "birth_date": "1990-01-15", "gender": "Male",
}

#: Somebody else entirely, as a page that had been tampered with would post.
FORGED = [
    {"field": "first_name", "key": "Given Name", "value": "FORGED", "show": True},
    {"field": "last_name", "key": "Last Name", "value": "IMPOSTOR", "show": True},
    {"field": "reference", "key": "National ID Card Number",
     "value": "9999888877776666", "show": True},
]


def _response(status, body):
    response = MagicMock(status_code=status)
    response.json.return_value = body
    response.text = json.dumps(body)
    return response


@override_settings(EVERIFY_ALLOWED_HOSTS=TEST_EVERIFY_HOSTS)
class VerifiedAnswerTest(TestCase):

    def setUp(self):
        credential_keys.reset_caches()
        self.addCleanup(credential_keys.reset_caches)

        site = SiteSettings.load()
        site.everify_base_url = "https://site.example/api"
        site.everify_client_id = "site-id"
        site.everify_client_secret = "site-secret"
        site.save()

        self.org = make_org("Alpha", locations=("Main Office", "Back Office"))
        self.desk = self.org.locations.get(name="Main Office")
        self.operator = User.objects.create(
            national_id_card_number="5555666677778888", given_name="Ada",
            last_name="Lovelace")
        join(self.org, self.operator)
        self.type = TransactionType.objects.create(
            organization=self.org, name="Visitor Access")
        self._sign_in()

    def _sign_in(self, org=None):
        session = self.client.session
        session[SESSION_KEY] = self.operator.id
        session[ORG_SESSION_KEY] = (org or self.org).id
        session["operator_location"] = str(self.desk.id)
        session.save()

    def _query(self, data=None, *, status=200, body=None, fail=None):
        """POST /everify/ with eVerify answering `data` (or `body`, at
        `status`), or raising `fail` on the query."""
        def post(url, json=None, headers=None, timeout=None, **kwargs):
            if url.endswith("/auth"):
                return _response(200, {"data": {"access_token": "tok"}})
            if fail is not None:
                raise fail
            return _response(status, body if body is not None
                             else {"data": dict(data)})
        with patch("verify.views.everify.requests.post", side_effect=post):
            return self.client.post(
                "/everify/",
                data=json.dumps({"value": PERSON["reference"],
                                 "face_liveness_session_id": "sess"}),
                content_type="application/json")

    def _log(self, **body):
        body.setdefault("transaction_type", str(self.type.id))
        return self.client.post("/everify/log-transaction/",
                                data=json.dumps(body),
                                content_type="application/json")

    def _credentials(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        pem = os.path.join(directory, "issuer.pem")
        with open(pem, "wb") as handle:
            handle.write(ec.generate_private_key(ec.SECP256R1()).private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        os.chmod(pem, stat.S_IRUSR | stat.S_IWUSR)
        return override_settings(CREDENTIAL_ISSUER_KEY_PATH=pem,
                                 CREDENTIAL_ISSUER_KEY_ID=1,
                                 CREDENTIAL_EPOCH_WRAP_KEY=WRAP_KEY_HEX)

    def _credential_fields(self, qr):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from ovcrypto import verifier, wire

        keys = credential_keys.issuing_keys()
        rows = {tier: credential_keys.epoch_key_row(keys.epoch, tier)
                for tier in (credential_keys.TIER_PUBLIC,
                             credential_keys.TIER_RESTRICTED)}
        device = {keys.epoch: verifier.EpochPrivateKeys(
            keys.epoch,
            X25519PrivateKey.from_private_bytes(
                credential_keys.private_key(rows[credential_keys.TIER_PUBLIC])),
            X25519PrivateKey.from_private_bytes(
                credential_keys.private_key(rows[credential_keys.TIER_RESTRICTED])))}
        opened = verifier.verify(
            "CL03:" + qr.split(":CL03:", 1)[1], epoch_keys=device,
            trust_list=verifier.TrustList.bare(
                {1: credential_keys.signer().public_key_der()}),
            now=int(time.time()))
        self.assertEqual(opened.verdict, verifier.Verdict.VALID)
        claims = {**opened.public_claims, **opened.restricted_claims}
        return dict(wire.decode_fields(claims[wire.T_FIELDS])), claims

    def _nothing_written(self):
        self.assertFalse(Transaction.objects.filter(
            authentication_result="success").exists())
        self.assertFalse(IssuedCredential.objects.exists())
        self.assertFalse(CardHandoff.objects.exists())

    # -- what a verified lookup keeps, and what is made of it --------------

    def test_a_verified_lookup_keeps_the_answer_it_was_given(self):
        self.assertEqual(self._query(PERSON).status_code, 200)
        rows = verified_answer.rows(self.client.session, self.org)
        values = {row["field"]: row["value"] for row in rows}
        self.assertEqual(values["first_name"], "JUAN")
        self.assertEqual(verified_answer.subject(self.client.session, self.org),
                         user_records.subject_key(PERSON["reference"]))

    def test_rows_posted_to_the_log_change_nothing(self):
        """The rule: a page posting somebody else, as a success, gets
        eVerify's person logged, signed and handed off -- never its own."""
        self._query(PERSON)
        with self._credentials():
            response = self._log(verification_data=FORGED, result="success",
                                 operator_location=str(self.desk.id))
            body = json.loads(response.content)
            self.assertEqual(body["status"], "ok")
            fields, claims = self._credential_fields(body["qr"])

        txn = Transaction.objects.get()
        self.assertEqual(txn.given_name, "JUAN")
        self.assertEqual(txn.last_name, "DELA CRUZ")
        self.assertEqual(txn.national_id_card_number, PERSON["reference"])
        self.assertEqual(txn.subject_key,
                         user_records.subject_key(PERSON["reference"]))
        self.assertNotIn("FORGED", json.dumps(txn.logged_fields))

        self.assertEqual(fields["Given Name"], "JUAN")
        self.assertNotIn(b"FORGED", b"".join(
            v for v in claims.values() if isinstance(v, bytes)))

        card = CardHandoff.objects.get(token=body["handoff_token"]).payload
        self.assertIn("JUAN", card["holder"])
        self.assertNotIn("FORGED", json.dumps(card))

    def test_the_mock_keeps_its_answer_only_where_it_may_run(self):
        """Its 'answer' is the caller's own body -- which is why it needs two
        opt-ins -- and it is kept exactly as a real one is."""
        with override_settings(DEBUG=True, EVERIFY_ALLOW_MOCK_LOGIN=True):
            self.client.post(
                "/everify/",
                data=json.dumps({"value": PERSON["reference"],
                                 "first_name": "MOCK", "last_name": "PERSON"}),
                content_type="application/json")
        self.assertIsNotNone(verified_answer.rows(self.client.session, self.org))

    # -- nothing on file means nothing logged -------------------------------

    def test_with_no_answer_on_file_nothing_is_logged(self):
        with self._credentials():
            response = self._log(verification_data=FORGED, result="success")
        self.assertEqual(response.status_code, 409)
        self._nothing_written()

    def test_rows_kept_where_the_browser_used_to_put_them_are_not_an_answer(self):
        session = self.client.session
        session["verification_data"] = FORGED
        session.save()
        with self._credentials():
            response = self._log()
        self.assertEqual(response.status_code, 409)
        self._nothing_written()
        self.assertRedirects(self.client.get("/app/document/"), "/app/",
                             fetch_redirect_response=False)

    def test_an_answer_for_another_organization_is_not_this_ones(self):
        other = make_org("Beta")
        join(other, self.operator)
        keep_answer(self.client, other, FORGED)
        with self._credentials():
            response = self._log()
        self.assertEqual(response.status_code, 409)
        self._nothing_written()
        self.assertRedirects(self.client.get("/app/document/"), "/app/",
                             fetch_redirect_response=False)

    def test_a_failed_lookup_leaves_no_answer_behind(self):
        """Whichever way the next lookup fails -- including the 5xx answers,
        on which Django does not save the session by itself."""
        def no_client():
            self.org.everify_client_id = ""
            self.org.save(update_fields=["everify_client_id"])

        failures = {
            "verified false": lambda: self._query(dict(PERSON, verified=False)),
            "named nobody": lambda: self._query({"token": "t"}),
            "refused": lambda: self._query(
                status=400, body={"error": "bad", "message": "Bad request."}),
            "no answer": lambda: self._query(
                fail=requests.ConnectionError("down")),
            "no client": lambda: (no_client(), self._query(PERSON))[1],
        }
        for name, fail in failures.items():
            with self.subTest(name):
                self.org.everify_client_id = "org-id"
                self.org.save(update_fields=["everify_client_id"])
                self._query(PERSON)
                self.assertIn(verified_answer.KEY, self.client.session)
                fail()
                self.assertNotIn(verified_answer.KEY, self.client.session)
                self.assertEqual(self._log().status_code, 409)
        self.assertFalse(Transaction.objects.filter(
            authentication_result="success").exists())

    def test_signing_in_keeps_no_answer(self):
        self.client.logout()
        User.objects.create(national_id_card_number=PERSON["reference"],
                            given_name="Juan")
        response = self._query(PERSON)
        self.assertEqual(response.status_code, 200)
        self.assertIn(SESSION_KEY, self.client.session)
        self.assertNotIn(verified_answer.KEY, self.client.session)

    # -- the browser hands nothing back -------------------------------------

    def test_there_is_no_endpoint_to_store_rows_through(self):
        self._query(PERSON)
        response = self.client.post(
            "/app/store-verification/",
            data=json.dumps({"verification_data": FORGED}),
            content_type="application/json")
        self.assertEqual(response.status_code, 404)
        page = self.client.get("/app/document/").content.decode()
        self.assertIn("JUAN", page)
        self.assertNotIn("FORGED", page)

    def test_the_document_carries_no_copy_of_the_answer_to_post_back(self):
        self._query(PERSON)
        response = self.client.get("/app/document/")
        page = response.content.decode()
        self.assertNotIn("data_json", response.context)
        self.assertNotIn("verification-data-json", page)
        self.assertNotIn("verification_data", page)
        self.assertNotIn("result: 'success'", page)
        self.assertIn("body: JSON.stringify({ transaction_type: transactionType })",
                      page)

    def test_the_verify_page_goes_straight_to_the_document(self):
        page = self.client.get("/app/").content.decode()
        self.assertNotIn("store-verification", page)
        self.assertIn("window.location.href = '/app/document/';", page)

    def test_the_outcome_is_never_the_bodys_or_a_rows(self):
        keep_answer(self.client, self.org, [
            {"key": "Given Name", "value": "Juan"},
            {"key": "Verified", "value": False}])
        self._log(result="failure")
        self.assertEqual(Transaction.objects.get().authentication_result, "success")

    # -- the type and the location are the organization's own ----------------

    def test_a_type_must_be_one_of_this_organizations_active_types(self):
        other = make_org("Beta")
        theirs = TransactionType.objects.create(organization=other, name="Theirs")
        retired = TransactionType.objects.create(
            organization=self.org, name="Retired", is_active=False)
        self._query(PERSON)
        for value in ("Anything I like", str(theirs.id), str(retired.id)):
            with self.subTest(value):
                self.assertEqual(self._log(transaction_type=value).status_code, 400)
        self._nothing_written()

    def test_the_location_is_the_sessions_and_never_raw_text(self):
        back = self.org.locations.get(name="Back Office")
        self._query(PERSON)
        self._log(operator_location=str(back.id))
        txn = Transaction.objects.get()
        self.assertEqual(txn.location_ref, self.desk)
        self.assertEqual(txn.operator_location, "Main Office")

        session = self.client.session
        session["operator_location"] = "A desk I typed"
        session.save()
        self._log()
        latest = Transaction.objects.latest("verification_timestamp")
        self.assertIsNone(latest.location_ref)
        self.assertEqual(latest.operator_location, "")

    # -- how long the answer lasts ------------------------------------------

    def test_one_answer_may_be_logged_more_than_once(self):
        """A second log of a genuinely verified person is not a forgery, and
        a lost response must be retryable."""
        self._query(PERSON)
        self.assertEqual(self._log().status_code, 200)
        self.assertEqual(self._log().status_code, 200)
        self.assertEqual(Transaction.objects.count(), 2)
        self.assertIn(verified_answer.KEY, self.client.session)

    def test_the_verify_page_and_switching_forget_the_answer(self):
        self._query(PERSON)
        self.client.get("/app/")
        self.assertNotIn(verified_answer.KEY, self.client.session)

        self._query(PERSON)
        self.client.post("/choose/switch/")
        self.assertNotIn(verified_answer.KEY, self.client.session)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_debug_sample_keeps_nobodys_records(self):
        self.operator.is_site_admin = True
        self.operator.save(update_fields=["is_site_admin"])
        self._query(PERSON)
        self.client.get("/debug-sample/")
        self.assertIsNotNone(verified_answer.rows(self.client.session, self.org))
        self.assertEqual(verified_answer.subject(self.client.session, self.org), "")

    def test_the_lookup_writes_the_session_once_and_nothing_after_it_does(self):
        self.client.get("/app/")            # forgets, and stamps the refresh
        with CaptureQueriesContext(connection) as q:
            self._query(PERSON)
        self.assertEqual(len(_session_writes(q.captured_queries)), 1)
        for name, request in (("document", lambda: self.client.get("/app/document/")),
                              ("log", lambda: self._log())):
            with CaptureQueriesContext(connection) as q:
                self.assertEqual(request().status_code, 200, name)
            self.assertEqual(_session_writes(q.captured_queries), [], name)
