"""What the sign-in page can reach without a session gives nothing away and
writes nothing it should not -- and what reaches the log, PostgreSQL can store.
"""

import json
from types import SimpleNamespace
from unittest import mock

import requests
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import RequestFactory, TestCase, override_settings

from accounts.models import LoginAttempt, Membership, Transaction, TransactionType, User
from accounts.tests import SESSION_KEY, TEST_EVERIFY_HOSTS, join, keep_answer, make_org
from verify.views import login_guard
from verify.views.everify import _fit_to_columns, _log_failure_transaction
from verify.views.helpers import ORG_SESSION_KEY


@override_settings(EVERIFY_ALLOWED_HOSTS=TEST_EVERIFY_HOSTS)
class PublicEndpointTest(TestCase):

    def _operator(self, org_name=None):
        user = User.objects.create(
            national_id_card_number="1111222233334444", given_name="Ada")
        session = self.client.session
        session[SESSION_KEY] = user.id
        self.org = None
        if org_name is not None:
            self.org = make_org(org_name)
            join(self.org, user, Membership.ROLE_OPERATOR)
            session[ORG_SESSION_KEY] = self.org.id
        session.save()
        return user

    def _log(self, body=None):
        """Log as the page does, with a verified answer on file when there is
        an organization to have asked for it."""
        if body is None:
            type_id = ""
            if getattr(self, "org", None) is not None:
                type_id = str(TransactionType.objects.create(
                    organization=self.org, name="New Enrollment").id)
                keep_answer(self.client, self.org,
                            [{"key": "Given Name", "value": "Juan"}])
            body = json.dumps({"transaction_type": type_id or "New Enrollment"})
        return self.client.post("/everify/log-transaction/",
                                content_type="application/json", data=body)

    def test_nobody_signed_out_can_log_a_verification(self):
        self.assertEqual(self._log().status_code, 403)
        self.assertFalse(Transaction.objects.exists())

    def test_nor_an_operator_with_no_organization_chosen(self):
        self._operator()
        self.assertEqual(self._log().status_code, 409)
        self.assertFalse(Transaction.objects.exists())

    def test_an_operator_acting_for_an_organization_still_logs(self):
        user = self._operator("Alpha")
        self.assertEqual(self._log().status_code, 200)
        self.assertEqual(Transaction.objects.get().operator, user)

    def test_a_malformed_log_body_is_refused_not_a_server_error(self):
        self._operator("Alpha")
        for body in (b"\xff", b"not json", b"[]", b'"text"',
                     b'{"transaction_type": 5}', b'{"transaction_type": ["a"]}'):
            with self.subTest(body=body):
                self.assertEqual(self._log(body).status_code, 400)
        self.assertFalse(Transaction.objects.exists())

    def test_a_qr_decoder_failure_says_nothing_about_the_server(self):
        image = SimpleUploadedFile("id.png", b"\x89PNG\r\n\x1a\n",
                                   content_type="image/png")
        with mock.patch("verify.views.qr._decode_qr_from_bytes",
                        side_effect=RuntimeError("/srv/app/secret-detail")), \
                self.assertLogs("verify.views.qr", "ERROR") as logs:
            response = self.client.post("/decode-qr/", {"qr_image": image})
        self.assertEqual(response.status_code, 500)
        self.assertNotIn(b"secret-detail", response.content)
        self.assertIn("secret-detail", "\n".join(logs.output))

    def test_a_sign_in_server_error_says_nothing_about_the_server(self):
        with mock.patch("verify.views.everify.login_guard.registered_operator",
                        side_effect=RuntimeError('relation "secret_detail" does not exist')), \
                self.assertLogs("verify.views.everify", "ERROR"):
            response = self.client.post(
                "/everify/", content_type="application/json",
                data=json.dumps({"value": "1111222233334444"}))
        self.assertEqual(response.status_code, 500)
        self.assertNotIn(b"secret_detail", response.content)

    def test_a_refused_sign_in_keeps_the_id_number_out_of_the_log(self):
        request = RequestFactory().post("/everify/")
        request.user = AnonymousUser()
        with self.assertLogs("verify.views.login_guard", "WARNING") as logs:
            login_guard.record_refused_attempt(request, "9999-8888-7777-6666")
        attempt = LoginAttempt.objects.get()
        self.assertEqual(attempt.submitted_id, "9999888877776666")
        output = "\n".join(logs.output)
        self.assertNotIn("9999888877776666", output)
        self.assertNotIn("6666", output)
        self.assertIn("attempt=%d" % attempt.pk, output)

    def test_a_malformed_body_is_refused_not_a_server_error(self):
        for url in ("/everify/", "/everify/log-liveness-failure/"):
            for body in (b"\xff", b"not json", b"[]", b'"text"', b'{"value": 5}',
                         b'{"first_name": ["a"]}', b'{"value": "1111\\u0000"}'):
                with self.subTest(url=url, body=body):
                    response = self.client.post(
                        url, content_type="application/json", data=body)
                    self.assertEqual(response.status_code, 400)
        self.assertFalse(Transaction.objects.exists())

    def test_no_answer_from_everify_names_no_address(self):
        site_client = SimpleNamespace(
            configured=True, base_url="https://everify.example/secret-path",
            refusal=lambda owner: None)
        with mock.patch("verify.views.everify.login_guard.registered_operator",
                        return_value=object()), \
                mock.patch("verify.views.everify._site_everify",
                           return_value=site_client), \
                mock.patch("verify.views.everify.get_everify_access_token",
                           return_value="token"), \
                mock.patch("verify.views.everify.requests.post",
                           side_effect=requests.ConnectionError(
                               "https://everify.example/secret-path")), \
                self.assertLogs("verify.views.everify", "ERROR"):
            response = self.client.post(
                "/everify/", content_type="application/json",
                data=json.dumps({"value": "1111222233334444"}))
        self.assertEqual(response.status_code, 500)
        self.assertIn(b"did not answer after 3 attempts", response.content)
        self.assertNotIn(b"secret-path", response.content)

    def test_a_logging_server_error_says_nothing_about_the_server(self):
        self._operator("Alpha")
        with mock.patch("verify.views.everify._log_context",
                        side_effect=RuntimeError('column "secret_detail" does not exist')), \
                self.assertLogs("verify.views.everify", "ERROR") as logs:
            response = self._log()
        self.assertEqual(response.status_code, 500)
        self.assertNotIn(b"secret_detail", response.content)
        self.assertIn("secret_detail", "\n".join(logs.output))


class OverlengthWriteTest(TestCase):
    """PostgreSQL refuses a string longer than its column, or one holding a
    NUL, where SQLite kept it."""

    def test_values_are_cut_to_their_column(self):
        fitted = _fit_to_columns(Transaction, {
            "sex": "x" * 50, "given_name": "ANA", "logged_fields": {"a": "b"},
            "operator": None})
        self.assertEqual(len(fitted["sex"]),
                         Transaction._meta.get_field("sex").max_length)
        self.assertEqual(fitted["given_name"], "ANA")
        self.assertEqual(fitted["logged_fields"], {"a": "b"})
        self.assertIsNone(fitted["operator"])

    def test_a_nul_is_dropped(self):
        self.assertEqual(
            _fit_to_columns(Transaction, {"given_name": "A\x00NA"})["given_name"],
            "ANA")

    def test_a_failure_with_an_overlong_scan_is_still_logged(self):
        request = RequestFactory().post("/everify/")
        SessionMiddleware(lambda r: None).process_request(request)
        request.user = AnonymousUser()
        scanned = "https://example.org/" + "q" * 200   # a QR that is not a National ID
        _log_failure_transaction(
            request, {"value": scanned, "first_name": "A" * 400}, "not an ID")
        row = Transaction.objects.get()
        self.assertEqual(row.authentication_result, "failure")
        # Not in either ID shape, so in neither ID column; the row is
        # logged all the same.
        self.assertEqual(row.digital_national_id_number, "")
        self.assertEqual(row.national_id_card_number, "")
        self.assertEqual(len(row.given_name),
                         Transaction._meta.get_field("given_name").max_length)
