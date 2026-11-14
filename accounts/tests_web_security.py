"""The tenant boundary and web hygiene: fetching the portrait an answer points
at, the CSRF token on /everify/, what a failure row keeps, an
organization's last admin, signing out by POST, Demo Mode's default mask,
User Records reads, HSTS, the absolute session lifetime and the deploy's
DEBUG check.
"""

import base64
import datetime
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import requests

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from accounts import admin_roles, everify_face, user_records, verified_answer
from accounts.models import (Device, DeviceLogEntry, LoginAttempt, Membership,
                             Organization, OrganizationFieldSetting, Transaction,
                             TransactionType, User, UserRecordsRead)
from accounts.tests import join, make_org
from verify.sessions import SIGNED_IN_AT
from verify.views.helpers import (DEMO_MASK_CHAR, ORG_SESSION_KEY,
                                  apply_demo_mask)

SESSION_KEY = "verify_user_id"
REPO = Path(settings.BASE_DIR)

JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 64
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
WEBP = b"RIFF\x00\x00\x00\x00WEBPVP8 " + b"\x00" * 64


def sign_in(client, user, org=None):
    session = client.session
    session[SESSION_KEY] = user.id
    if org is not None:
        session[ORG_SESSION_KEY] = org.id
    session.save()


def post_json(client, path, body):
    data = body if isinstance(body, (str, bytes)) else json.dumps(body)
    return client.post(path, data=data, content_type="application/json")


class FakeRaw:
    """urllib3's response as `_read` uses it: read1(), and no socket."""

    connection = None

    def __init__(self, body):
        self._body = body

    def read1(self, amt, decode_content=None):
        chunk, self._body = self._body[:amt], self._body[amt:]
        return chunk


class FakeResponse:
    """What `requests.get(..., stream=True)` hands back, as far as the
    portrait fetch reads it."""

    def __init__(self, status=200, body=b"", headers=None, location=None):
        self.status_code = status
        self.headers = dict(headers or {})
        if location is not None:
            self.headers["Location"] = location
        self.is_redirect = location is not None and status in (301, 302, 303, 307, 308)
        self.raw = FakeRaw(body)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def resolving(table):
    """Patch name resolution: `table` maps a host to its addresses."""
    return patch.object(everify_face, "_addresses",
                        side_effect=lambda host: set(table.get(host, ())) or None)


PUBLIC = {"faces.example.ph": {"203.0.113.10"}, "cdn.example.ph": {"203.0.113.11"}}


@patch.object(everify_face, "_public",
              side_effect=lambda a: not a.startswith(("10.", "127.", "169.254.",
                                                      "192.168.", "::1", "fd")))
class FaceAddressTest(TestCase):
    """What may be fetched at all. 203.0.113.0/24 is a documentation range,
    which `ipaddress` counts as not global, so the public test hosts stand in
    through a patched `_public`; PublicAddressTest checks the real one."""

    def refusal(self, url, table=PUBLIC):
        with resolving(table):
            return everify_face.refusal(url)

    def test_a_public_https_host_is_fetched(self, _):
        self.assertIsNone(self.refusal("https://faces.example.ph/p/1.jpg?sig=x"))

    def test_plain_http_is_refused(self, _):
        self.assertEqual(self.refusal("http://faces.example.ph/p/1.jpg"), "not https")

    def test_other_schemes_are_refused(self, _):
        for url in ("file:///etc/passwd", "ftp://faces.example.ph/x", "/static/mock-face.png",
                    "data:image/png;base64,AAAA", ""):
            self.assertIsNotNone(self.refusal(url), url)

    def test_an_address_is_refused_whatever_it_is(self, _):
        """Even a public one, which resolves to itself as a name would."""
        table = dict(PUBLIC, **{"203.0.113.10": {"203.0.113.10"}})
        self.assertIsNone(self.refusal("https://faces.example.ph/", table))
        for url in ("https://169.254.169.254/latest/meta-data/",
                    "https://127.0.0.1/", "https://[::1]/", "https://203.0.113.10/"):
            self.assertEqual(self.refusal(url, table), "an address, not a host name", url)

    def test_a_name_for_the_metadata_service_or_the_private_network_is_refused(self, _):
        table = {"metadata.evil.example": {"169.254.169.254"},
                 "intranet.evil.example": {"10.1.2.3"},
                 "loopback.evil.example": {"127.0.0.1"},
                 "split.evil.example": {"203.0.113.12", "192.168.1.1"}}
        for host in table:
            self.assertEqual(self.refusal("https://%s/x.jpg" % host, table),
                             "a host that resolves to a non-public address", host)

    def test_a_name_that_does_not_resolve_is_refused(self, _):
        self.assertEqual(self.refusal("https://nowhere.example.ph/x.jpg"),
                         "a host that does not resolve")

    def test_another_port_is_refused(self, _):
        self.assertEqual(self.refusal("https://faces.example.ph:8443/x.jpg"),
                         "not the default port")
        self.assertIsNone(self.refusal("https://faces.example.ph:443/x.jpg"))

    def test_urls_the_two_parsers_read_differently_are_refused(self, _):
        for url in ("https://evil.example\\@faces.example.ph/x.jpg",
                    "https://user@faces.example.ph/x.jpg",
                    "https://faces.example.ph/x .jpg"):
            self.assertIsNotNone(self.refusal(url), url)

    @override_settings(EVERIFY_FACE_HOSTS=["cdn.example.ph"])
    def test_face_hosts_narrows_it(self, _):
        self.assertEqual(self.refusal("https://faces.example.ph/x.jpg"),
                         "a host EVERIFY_FACE_HOSTS does not list")
        self.assertIsNone(self.refusal("https://cdn.example.ph/x.jpg"))


class FaceDripTest(TestCase):
    """A body sent a byte at a time, or not at all, is cut off at the
    deadline, not after a whole chunk or a whole read timeout: 20 bytes 0.3 s
    apart must not take 6 s against a 1 s limit. A real socket, because a
    fake cannot block."""

    def _read_from(self, gap, count=40):
        """`_read` with a 1 s deadline against a server that sends the
        headers, then one body byte every `gap` seconds."""
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        stop = threading.Event()

        def serve():
            conn, _ = server.accept()
            conn.recv(4096)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
                         b"Content-Type: image/jpeg\r\n\r\n" % count)
            for _ in range(count):
                if stop.wait(gap):
                    break
                try:
                    conn.sendall(b"\xff")
                except OSError:
                    break
            conn.close()

        threading.Thread(target=serve, daemon=True).start()
        started = time.monotonic()
        try:
            with requests.get("http://127.0.0.1:%d/" % server.getsockname()[1],
                              timeout=5, stream=True) as response:
                body = everify_face._read(response, time.monotonic() + 1.0)
        finally:
            stop.set()
            server.close()
        return body, time.monotonic() - started

    def test_a_drip_is_cut_off_at_the_deadline(self):
        body, took = self._read_from(gap=0.2)
        self.assertIsNone(body)
        self.assertLess(took, 2.5)

    def test_a_stall_is_cut_off_at_the_deadline_not_the_read_timeout(self):
        body, took = self._read_from(gap=4.0, count=1)
        self.assertIsNone(body)
        self.assertLess(took, 2.5)

    def test_a_prompt_body_is_read_whole(self):
        body, _took = self._read_from(gap=0.0, count=40)
        self.assertEqual(body, b"\xff" * 40)


class PublicAddressTest(TestCase):

    def test_the_ranges_refused(self):
        for address in ("127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.1",
                        "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1",
                        "240.0.0.1", "::1", "fe80::1", "fd00::1", "::ffff:169.254.169.254",
                        "not an address"):
            self.assertFalse(everify_face._public(address), address)

    def test_a_public_address_passes(self):
        for address in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
            self.assertTrue(everify_face._public(address), address)


@patch.object(everify_face, "_public", side_effect=lambda a: a.startswith("203."))
class FaceFetchTest(TestCase):

    URL = "https://faces.example.ph/p/1?sig=abc"

    def fetch(self, *responses, table=PUBLIC):
        with resolving(table), \
                patch.object(everify_face.requests, "get",
                             side_effect=list(responses)) as get:
            return everify_face.data_uri(self.URL), get

    def test_a_jpeg_comes_back_as_a_data_uri(self, _):
        uri, get = self.fetch(FakeResponse(body=JPEG, headers={"Content-Type": "image/jpeg"}))
        self.assertEqual(uri, "data:image/jpeg;base64," + base64.b64encode(JPEG).decode())
        kwargs = get.call_args.kwargs
        self.assertFalse(kwargs["allow_redirects"])
        self.assertTrue(kwargs["stream"])

    def test_the_type_is_the_bytes_not_the_header(self, _):
        uri, _get = self.fetch(FakeResponse(body=PNG, headers={"Content-Type": "text/html"}))
        self.assertTrue(uri.startswith("data:image/png;base64,"))
        uri, _get = self.fetch(FakeResponse(body=WEBP, headers={"Content-Type": "image/jpeg"}))
        self.assertTrue(uri.startswith("data:image/webp;base64,"))

    def test_a_body_that_is_not_an_image_is_never_the_face(self, _):
        for body in (b'{"AccessKeyId": "ASIA", "SecretAccessKey": "x"}',
                     b"<html><script>alert(1)</script></html>", b"GIF89a....", b""):
            uri, _get = self.fetch(FakeResponse(body=body,
                                                headers={"Content-Type": "image/jpeg"}))
            self.assertIsNone(uri, body)

    def test_a_redirect_is_judged_before_it_is_followed(self, _):
        uri, get = self.fetch(
            FakeResponse(302, location="https://metadata.evil.example/latest/"),
            table=dict(PUBLIC, **{"metadata.evil.example": {"169.254.169.254"}}))
        self.assertIsNone(uri)
        self.assertEqual(get.call_count, 1)

    def test_a_redirect_to_a_public_host_is_followed(self, _):
        uri, get = self.fetch(FakeResponse(302, location="https://cdn.example.ph/p.jpg"),
                              FakeResponse(body=JPEG))
        self.assertTrue(uri.startswith("data:image/jpeg"))
        self.assertEqual(get.call_args_list[1].args[0], "https://cdn.example.ph/p.jpg")

    def test_a_relative_redirect_stays_on_the_host(self, _):
        uri, get = self.fetch(FakeResponse(301, location="/p/2.jpg"), FakeResponse(body=JPEG))
        self.assertEqual(get.call_args_list[1].args[0], "https://faces.example.ph/p/2.jpg")
        self.assertIsNotNone(uri)

    def test_too_many_redirects(self, _):
        hops = [FakeResponse(302, location="https://cdn.example.ph/%d" % i)
                for i in range(everify_face.MAX_REDIRECTS + 1)]
        uri, get = self.fetch(*hops)
        self.assertIsNone(uri)
        self.assertEqual(get.call_count, everify_face.MAX_REDIRECTS + 1)

    def test_a_large_body_is_refused(self, _):
        declared = FakeResponse(body=JPEG, headers={
            "Content-Length": str(everify_face.MAX_BYTES + 1)})
        self.assertIsNone(self.fetch(declared)[0])
        undeclared = FakeResponse(body=JPEG + b"\x00" * everify_face.MAX_BYTES)
        self.assertIsNone(self.fetch(undeclared)[0])
        exactly = FakeResponse(body=JPEG + b"\x00" * (everify_face.MAX_BYTES - len(JPEG)))
        self.assertIsNotNone(self.fetch(exactly)[0])

    def test_a_slow_body_is_refused(self, _):
        # The deadline is set, the request starts inside it, and it has
        # passed by the first read.
        with patch.object(everify_face.time, "monotonic",
                          side_effect=[0, 0, everify_face.DEADLINE + 1]):
            self.assertIsNone(self.fetch(FakeResponse(body=JPEG))[0])

    def test_without_a_socket_the_deadline_still_holds(self, _):
        """When urllib3 does not expose the socket, no read gets a timeout
        of its own, and the deadline is checked between reads instead."""
        self.assertIsNone(everify_face._read(FakeResponse(body=JPEG), time.monotonic() - 1))
        self.assertEqual(everify_face._read(FakeResponse(body=JPEG), time.monotonic() + 60),
                         JPEG)

    def test_no_request_starts_after_the_deadline(self, _):
        with patch.object(everify_face.time, "monotonic",
                          side_effect=[0, 0, everify_face.DEADLINE + 1]):
            uri, get = self.fetch(FakeResponse(302, location="https://cdn.example.ph/p.jpg"),
                                  FakeResponse(body=JPEG))
        self.assertIsNone(uri)
        self.assertEqual(get.call_count, 1)

    def test_an_error_status_is_no_face(self, _):
        self.assertIsNone(self.fetch(FakeResponse(403, body=JPEG))[0])

    def test_nothing_is_sent_to_a_refused_address(self, _):
        with patch.object(everify_face.requests, "get") as get:
            self.assertIsNone(everify_face.data_uri("https://169.254.169.254/latest/"))
        get.assert_not_called()

    def test_it_never_raises(self, _):
        with resolving(PUBLIC), patch.object(everify_face.requests, "get",
                                             side_effect=RuntimeError("boom")), \
                self.assertLogs("accounts.everify_face", "ERROR"):
            self.assertIsNone(everify_face.data_uri(self.URL))

    def test_the_url_is_never_logged(self, _):
        with self.assertLogs("accounts.everify_face", "WARNING") as logs:
            self.fetch(FakeResponse(body=b"not an image"))
        self.assertNotIn("sig=abc", "\n".join(logs.output))
        self.assertIn("faces.example.ph", "\n".join(logs.output))

    def test_the_verification_rows_use_it(self, _):
        from verify.views.everify import _prepare_data_for_frontend
        with resolving({"169.254.169.254": set()}), \
                patch.object(everify_face.requests, "get") as get:
            rows = _prepare_data_for_frontend(
                {"face_url": "http://169.254.169.254/latest/meta-data/iam/",
                 "first_name": "JUAN", "last_name": "DELA CRUZ"})
        get.assert_not_called()
        self.assertNotIn("face_url", [r["field"] for r in rows])


class EverifyCsrfTest(TestCase):

    def setUp(self):
        self.org = make_org("Mine")
        self.operator = User.objects.create(national_id_card_number="1111222233334444")
        join(self.org, self.operator)
        self.client = Client(enforce_csrf_checks=True)
        sign_in(self.client, self.operator, self.org)

    def test_a_signed_in_post_without_the_token_is_refused(self):
        with patch("verify.views.everify.requests.post") as upstream:
            response = post_json(self.client, "/everify/", {"value": "1234567890123456"})
        self.assertEqual(response.status_code, 403)
        upstream.assert_not_called()

    def test_with_the_token_it_gets_past_the_check(self):
        self.client.get("/app/")
        token = self.client.cookies[settings.CSRF_COOKIE_NAME].value
        # A body the view refuses itself: a 400 from the view, not the 403
        # the CSRF check gives, with nothing sent upstream.
        response = self.client.post("/everify/", data="not json",
                                    content_type="application/json",
                                    HTTP_X_CSRFTOKEN=token)
        self.assertEqual(response.status_code, 400)

    def test_both_pages_send_it(self):
        for name, call in (("login.html", "fetch('/everify/', {"),
                           ("app.html", "fetch(QUERY_URL, {")):
            source = (REPO / "templates" / name).read_text(encoding="utf-8")
            start = source.index(call)
            self.assertIn("'X-CSRFToken': csrfToken", source[start:start + 200], name)


class FailureRowLogSettingsTest(TestCase):

    def setUp(self):
        self.org = make_org("Mine")
        self.operator = User.objects.create(national_id_card_number="1111222233334444")
        join(self.org, self.operator)

    def _switch_off(self, *keys):
        for key in keys:
            OrganizationFieldSetting.objects.create(
                organization=self.org, key=key, include_in_log=False,
                show_on_document=True, position=0)

    def _fail(self, value="1234-5678-9012-3456", signed_in=True):
        if signed_in:
            sign_in(self.client, self.operator, self.org)
        response = post_json(self.client, "/everify/log-liveness-failure/", {
            "value": value, "first_name": "JUAN", "middle_name": "SANTOS",
            "last_name": "DELA CRUZ", "birth_date": "1990-03-12",
            "failure_detail": "cancelled"})
        self.assertEqual(response.status_code, 200)
        return Transaction.objects.latest("id")

    def test_what_the_organization_logs_is_kept(self):
        row = self._fail()
        self.assertEqual((row.given_name, row.last_name, row.date_of_birth,
                          row.national_id_card_number),
                         ("JUAN", "DELA CRUZ", "1990-03-12", "1234567890123456"))

    def test_a_field_with_log_off_is_not_written(self):
        self._switch_off("first_name", "middle_name", "birth_date", "reference")
        row = self._fail()
        self.assertEqual((row.given_name, row.middle_name, row.date_of_birth,
                          row.national_id_card_number), ("", "", "", ""))
        self.assertEqual(row.last_name, "DELA CRUZ")

    def test_the_digital_id_follows_its_own_switch(self):
        self._switch_off("code")
        self.assertEqual(self._fail("CWD0842").digital_national_id_number, "")

    def test_signed_out_the_defaults_apply(self):
        self._switch_off("first_name")
        row = self._fail(signed_in=False)
        self.assertIsNone(row.organization)
        self.assertEqual(row.given_name, "JUAN")


class InvalidJsonTest(TestCase):

    def setUp(self):
        self.org = make_org("Mine")
        self.root = User.objects.create(national_id_card_number="9999000011112222")
        admin_roles.designate(self.root, "site_admin", None, "test")
        join(self.org, self.root, Membership.ROLE_ADMIN)
        sign_in(self.client, self.root, self.org)

    def test_a_400_everywhere_never_a_500(self):
        paths = ["/app/admin/profile/", "/app/admin/everify/",
                 "/app/admin/verification/",
                 "/app/site/organizations/%d/copy-credentials/" % self.org.pk,
                 "/app/site/organizations/%d/fields/" % self.org.pk,
                 "/app/site/organizations/%d/toggle/" % self.org.pk,
                 "/app/site/organizations/%d/members/remove/" % self.org.pk,
                 "/app/site/organizations/%d/members/" % self.org.pk,
                 "/app/admin/add-user/", "/app/admin/update-role/",
                 "/app/admin/remove-user/", "/app/admin/add-location/",
                 "/app/admin/update-location/", "/app/admin/remove-location/",
                 "/app/admin/add-transaction-type/",
                 "/app/admin/update-transaction-type/",
                 "/app/admin/remove-transaction-type/"]
        for path in paths:
            for body in ("not json", "[1, 2]", b"\xff\xfe"):
                response = post_json(self.client, path, body)
                self.assertEqual(response.status_code, 400, (path, body))
                self.assertEqual(json.loads(response.content)["message"], "Invalid JSON.")
        self.org.refresh_from_db()
        self.assertTrue(self.org.is_active)


class LastAdminLockTest(TestCase):
    """The check and the change are one step, under a lock on the
    organization's admin rows: two admins removing each other at once
    cannot both pass."""

    def setUp(self):
        self.org = make_org("Mine")
        self.site = User.objects.create(national_id_card_number="9999000011112222")
        admin_roles.designate(self.site, "site_admin", None, "test")
        self.a = User.objects.create(national_id_card_number="1111222233334444")
        self.b = User.objects.create(national_id_card_number="2222333344445555")
        join(self.org, self.a, Membership.ROLE_ADMIN)
        join(self.org, self.b, Membership.ROLE_ADMIN)
        sign_in(self.client, self.site, self.org)

    def test_every_path_locks_first(self):
        calls = [
            ("/app/admin/update-role/", {"user_id": None, "role": Membership.ROLE_OPERATOR}),
            ("/app/admin/remove-user/", {"user_id": None}),
            ("/app/site/organizations/%d/members/" % self.org.pk,
             {"national_id_card_number": None, "role": Membership.ROLE_OPERATOR}),
            ("/app/site/organizations/%d/members/remove/" % self.org.pk, {"user_id": None}),
        ]
        for path, body in calls:
            target = self.a if Membership.objects.filter(user=self.a).exists() else self.b
            body = {k: (v if v is not None else
                        (target.national_id_card_number if k == "national_id_card_number"
                         else target.pk)) for k, v in body.items()}
            with patch("verify.views.orgs._lock_admins") as lock:
                post_json(self.client, path, body)
            lock.assert_called_once_with(self.org.pk)


class LastAdminTest(TestCase):

    def setUp(self):
        self.org = make_org("Mine")
        self.site = User.objects.create(national_id_card_number="9999000011112222")
        admin_roles.designate(self.site, "site_admin", None, "test")
        self.admin = User.objects.create(national_id_card_number="1111222233334444")
        self.membership = join(self.org, self.admin, Membership.ROLE_ADMIN)

    def _site_remove(self):
        sign_in(self.client, self.site, self.org)
        return post_json(self.client, "/app/site/organizations/%d/members/remove/" % self.org.pk,
                         {"user_id": self.admin.pk})

    def test_the_site_page_keeps_the_last_admin(self):
        response = self._site_remove()
        self.assertEqual(response.status_code, 400)
        self.assertIn("only admin", json.loads(response.content)["message"])
        self.assertTrue(Membership.objects.filter(pk=self.membership.pk).exists())

    def test_with_a_second_admin_it_goes(self):
        join(self.org, User.objects.create(national_id_card_number="2222333344445555"),
             Membership.ROLE_ADMIN)
        self.assertEqual(self._site_remove().status_code, 200)
        self.assertFalse(Membership.objects.filter(pk=self.membership.pk).exists())

    def test_an_operator_still_goes(self):
        self.membership.role = Membership.ROLE_OPERATOR
        self.membership.save()
        self.assertEqual(self._site_remove().status_code, 200)

    def test_the_site_page_does_not_demote_the_last_admin(self):
        sign_in(self.client, self.site, self.org)
        response = post_json(self.client,
                             "/app/site/organizations/%d/members/" % self.org.pk,
                             {"national_id_card_number": "1111222233334444",
                              "role": Membership.ROLE_OPERATOR})
        self.assertEqual(response.status_code, 400)
        self.membership.refresh_from_db()
        self.assertEqual(self.membership.role, Membership.ROLE_ADMIN)

    def test_the_organization_page_neither(self):
        """A site admin reaches every organization's page without being a
        member, so "you cannot remove yourself" alone does not cover it."""
        sign_in(self.client, self.site, self.org)
        demote = post_json(self.client, "/app/admin/update-role/",
                           {"user_id": self.admin.pk, "role": Membership.ROLE_OPERATOR})
        remove = post_json(self.client, "/app/admin/remove-user/",
                           {"user_id": self.admin.pk})
        self.assertEqual((demote.status_code, remove.status_code), (400, 400))
        self.membership.refresh_from_db()
        self.assertEqual(self.membership.role, Membership.ROLE_ADMIN)


class DeleteWithPhoneLogTest(TestCase):

    def setUp(self):
        self.org = make_org("Mine")
        self.site = User.objects.create(national_id_card_number="9999000011112222")
        admin_roles.designate(self.site, "site_admin", None, "test")
        sign_in(self.client, self.site, self.org)

    def _log_entry(self):
        owner = User.objects.create(national_id_card_number="1111222233334444")
        device = Device.objects.create(device_id=uuid.uuid4(), label="Desk",
                                       owner=owner, public_key_der=b"k")
        DeviceLogEntry.objects.create(
            device=device, device_uuid=device.device_id, device_label="Desk",
            owner=owner, owner_name="", owner_national_id_number="", seq=1,
            key_id=1, event="scan", outcome="success", detail={}, app_build="1",
            received_at=timezone.now(), record_hash=bytes(32), chain_ok=True,
            readable=True, organization=self.org, organization_name=self.org.name)

    def test_refused_while_a_phone_log_record_is_filed_under_it(self):
        self._log_entry()
        response = post_json(self.client,
                             "/app/site/organizations/%d/delete/" % self.org.pk, {})
        self.assertEqual(response.status_code, 400)
        self.assertIn("1 phone log record", json.loads(response.content)["message"])
        self.assertTrue(Organization.objects.filter(pk=self.org.pk).exists())

    def test_the_page_offers_no_delete_button_for_it(self):
        self._log_entry()
        page = self.client.get("/app/site/").content.decode()
        self.assertNotIn('class="btn-delete-org"', page)
        self.assertIn("1 phone log record on record", page)

    def test_without_history_it_still_goes(self):
        response = post_json(self.client,
                             "/app/site/organizations/%d/delete/" % self.org.pk, {})
        self.assertEqual(response.status_code, 200)

    def test_the_enabled_switch_asks_before_disabling(self):
        page = self.client.get("/app/site/").content.decode()
        self.assertIn('data-name="Mine"', page)
        self.assertRegex(page, r"if \(!wanted && !confirm\('Disable '")


class SessionEndedOnTheVerifyPageTest(TestCase):
    """A Verify page left open when its session ended must not sign its
    browser in as the person it then verifies."""

    def test_a_verification_without_a_session_is_refused(self):
        with patch("verify.views.everify.requests.post") as upstream:
            response = post_json(self.client, "/everify/",
                                 {"value": "3916098324035936", "purpose": "verify"})
        self.assertEqual(response.status_code, 401)
        self.assertTrue(json.loads(response.content)["signed_out"])
        upstream.assert_not_called()
        self.assertFalse(Transaction.objects.exists())
        self.assertFalse(LoginAttempt.objects.exists())
        self.assertIsNone(self.client.session.get(SESSION_KEY))

    def test_the_verify_page_says_what_it_asks_and_goes_home_when_told(self):
        source = (REPO / "templates" / "app.html").read_text(encoding="utf-8")
        start = source.index("function sendVerifyQuery(payload)")
        body = source[start:start + 1500]
        self.assertIn("payload.purpose = 'verify';", body)
        self.assertRegex(body, r"if \(result\.signed_out\) \{\s*releaseLiveness\(\);\s*"
                               r"window\.location\.href = '/';")

    def test_the_sign_in_page_does_not(self):
        source = (REPO / "templates" / "login.html").read_text(encoding="utf-8")
        self.assertNotIn("purpose = 'verify'", source)
        self.assertNotIn("purpose: 'verify'", source)


class SignOutAndSwitchTest(TestCase):

    def setUp(self):
        self.a = make_org("Alpha")
        self.b = make_org("Beta")
        self.operator = User.objects.create(national_id_card_number="1111222233334444")
        join(self.a, self.operator)
        join(self.b, self.operator)
        sign_in(self.client, self.operator, self.a)

    def test_a_get_of_logout_asks_and_signs_nobody_out(self):
        response = self.client.get("/logout/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Sign out?")
        self.assertEqual(self.client.session.get(SESSION_KEY), self.operator.pk)

    def test_a_post_signs_out(self):
        response = self.client.post("/logout/")
        self.assertRedirects(response, "/", fetch_redirect_response=False)
        self.assertIsNone(self.client.session.get(SESSION_KEY))

    def test_without_the_token_it_is_refused(self):
        client = Client(enforce_csrf_checks=True)
        sign_in(client, self.operator, self.a)
        self.assertEqual(client.post("/logout/").status_code, 403)
        self.assertEqual(client.session.get(SESSION_KEY), self.operator.pk)

    def test_signed_out_a_get_goes_home(self):
        self.client.post("/logout/")
        self.assertRedirects(self.client.get("/logout/"), "/",
                             fetch_redirect_response=False)

    def test_a_get_of_switch_drops_nothing(self):
        session = self.client.session
        verified_answer.keep(session, self.a,
                             [{"field": "first_name", "key": "Given Name", "value": "JUAN"}],
                             "")
        session.save()
        self.assertRedirects(self.client.get("/choose/switch/"), "/choose/",
                             fetch_redirect_response=False)
        self.assertEqual(self.client.session.get(ORG_SESSION_KEY), self.a.pk)
        self.assertTrue(verified_answer.rows(self.client.session, self.a))

    def test_a_post_of_switch_drops_the_context(self):
        session = self.client.session
        verified_answer.keep(session, self.a,
                             [{"field": "first_name", "key": "Given Name", "value": "JUAN"}],
                             "")
        session.save()
        self.client.post("/choose/switch/")
        self.assertIsNone(self.client.session.get(ORG_SESSION_KEY))
        self.assertFalse(verified_answer.rows(self.client.session, self.a))

    def test_the_pages_post_them(self):
        page = self.client.get("/app/").content.decode()
        self.assertRegex(page, r'<form method="post" action="/logout/" class="inline-form">\s*'
                               r'<input type="hidden" name="csrfmiddlewaretoken"')
        self.assertRegex(page, r'<form method="post" action="/choose/switch/" class="inline-form">')
        self.assertNotIn('data-href="/logout/"', page)


class DemoMaskDefaultDenyTest(TestCase):

    VALUES = {
        "first_name": "JUAN MIGUEL", "middle_name": "SANTOS", "last_name": "DELA CRUZ",
        "full_name": "JUAN MIGUEL SANTOS DELA CRUZ", "suffix": "JR",
        "email": "juan@example.ph", "mobile_number": "+639170000000",
        "gender": "Male", "residency_status": "Filipino Citizen",
        "address_line_1": "123 Katipunan Ave", "barangay": "Loyola Heights",
        "pob_municipality": "Quezon City", "reference": "3916098324035936",
        "code": "CWD0842", "age": 36, "a_key_added_next_year": "SECRET",
        "face_url": "data:image/jpeg;base64,AAAA",
    }

    def masked(self):
        rows = [{"field": key, "key": key, "value": value}
                for key, value in self.VALUES.items()]
        return {row["field"]: row["value"] for row in apply_demo_mask(rows)}

    def test_nothing_new_reaches_an_audience(self):
        masked = self.masked()
        for key in ("middle_name", "suffix", "email", "mobile_number", "gender",
                    "residency_status", "address_line_1", "barangay",
                    "pob_municipality", "a_key_added_next_year"):
            self.assertIn(DEMO_MASK_CHAR, masked[key], key)
            self.assertNotIn(str(self.VALUES[key]).split()[-1], masked[key], key)

    def test_full_name_no_longer_undoes_the_given_name(self):
        masked = self.masked()["full_name"]
        self.assertTrue(masked.startswith("JUAN "))
        for word in ("MIGUEL", "SANTOS", "DELA", "CRUZ"):
            self.assertNotIn(word, masked)

    def test_a_number_is_masked_too(self):
        self.assertIn(DEMO_MASK_CHAR, self.masked()["age"])

    def test_what_was_decided_stays(self):
        masked = self.masked()
        self.assertEqual(masked["last_name"], "DELA CRUZ")
        self.assertEqual(masked["face_url"], self.VALUES["face_url"])
        self.assertTrue(masked["first_name"].startswith("JUAN "))
        self.assertTrue(masked["reference"].endswith("6"))
        self.assertNotIn("3916", masked["reference"])


PERSON = "3916098324035936"


class UserRecordsReadLogTest(TestCase):

    def setUp(self):
        self.here = make_org("Here")
        self.clinic = make_org("Clinic")
        self.operator = User.objects.create(national_id_card_number="1111222233334444")
        join(self.here, self.operator)
        self.nurse = User.objects.create(national_id_card_number="2222333344445555")
        join(self.clinic, self.nurse)
        self.private = TransactionType.objects.create(
            organization=self.clinic, name="HIV Test", shared_in_user_records=False)
        self.public = TransactionType.objects.create(
            organization=self.clinic, name="Medical Consultation")
        self.mine = TransactionType.objects.create(
            organization=self.here, name="Private Matter", shared_in_user_records=False)
        key = user_records.subject_key(PERSON)
        for org, operator, kind in ((self.clinic, self.nurse, self.private),
                                    (self.clinic, self.nurse, self.public),
                                    (self.here, self.operator, self.mine)):
            Transaction.objects.create(
                organization=org, operator=operator, authentication_result="success",
                transaction_type=kind.name, transaction_type_ref=kind, subject_key=key)
        sign_in(self.client, self.operator, self.here)

    def _verified(self, card=PERSON):
        session = self.client.session
        verified_answer.keep(session, self.here,
                             [{"field": "reference", "key": "Card", "value": card}],
                             user_records.subject_key(card) if card else "")
        session.save()

    def _types(self):
        data = json.loads(self.client.get("/app/user-records/").content)
        return sorted((r["organization"], r["transaction_type"]) for r in data["records"])

    def test_every_read_is_recorded(self):
        self._verified()
        self.client.get("/app/user-records/")
        read = UserRecordsRead.objects.get()
        self.assertEqual((read.operator, read.organization, read.records),
                         (self.operator, self.here, 3))
        self.assertEqual(read.subject_key, user_records.subject_key(PERSON))
        self.assertNotIn(PERSON, read.subject_key)

    def test_no_person_no_record(self):
        self._verified(card="")
        self.client.get("/app/user-records/")
        self.assertFalse(UserRecordsRead.objects.exists())

    def test_another_organizations_private_type_is_not_named(self):
        self._verified()
        self.assertEqual(self._types(), [("Clinic", "Medical Consultation"),
                                         ("Clinic", user_records.TYPE_NOT_SHARED),
                                         ("Here", "Private Matter")])

    def test_deleting_a_private_type_does_not_name_it(self):
        """The link goes when the type is deleted, and "no link" must not
        read as shared, handing the name back to everybody."""
        self.private.delete()
        self._verified()
        self.assertIn(("Clinic", user_records.TYPE_NOT_SHARED), self._types())
        self.assertNotIn(("Clinic", "HIV Test"), self._types())

    def test_a_self_verification_keeps_its_type(self):
        Transaction.objects.create(
            organization=None, operator=None, authentication_result="success",
            transaction_type="Self-verification",
            subject_key=user_records.subject_key(PERSON))
        self._verified()
        self.assertIn("Self-verification", [t for _o, t in self._types()])

    def test_the_audit_trail_is_read_only_in_django_admin(self):
        from django.contrib import admin as django_admin
        model_admin = django_admin.site._registry[UserRecordsRead]
        self.assertFalse(model_admin.has_add_permission(None))
        self.assertFalse(model_admin.has_change_permission(None))
        self.assertFalse(model_admin.has_delete_permission(None))


class UserRecordsSwitchIsSiteAdminsTest(TestCase):

    def setUp(self):
        self.org = make_org("Mine")
        self.admin = User.objects.create(national_id_card_number="1111222233334444")
        join(self.org, self.admin, Membership.ROLE_ADMIN)
        self.site = User.objects.create(national_id_card_number="9999000011112222")
        admin_roles.designate(self.site, "site_admin", None, "test")

    def _save(self, user, **body):
        sign_in(self.client, user, self.org)
        return post_json(self.client, "/app/admin/verification/", body)

    def test_an_organization_admin_cannot_turn_it_on_or_off(self):
        response = self._save(self.admin, check_user_records=False)
        self.assertEqual(response.status_code, 403)
        self.org.refresh_from_db()
        self.assertTrue(self.org.check_user_records)

    def test_but_still_sets_the_repeat_alert(self):
        response = self._save(self.admin, check_user_records=True,
                              repeat_alert=False, repeat_alert_days=30)
        self.assertEqual(response.status_code, 200)
        self.org.refresh_from_db()
        self.assertEqual((self.org.repeat_alert, self.org.repeat_alert_days), (False, 30))

    def test_a_site_admin_can(self):
        self.assertEqual(self._save(self.site, check_user_records=False).status_code, 200)
        self.org.refresh_from_db()
        self.assertFalse(self.org.check_user_records)

    def test_the_page_greys_it_out_for_an_organization_admin(self):
        sign_in(self.client, self.admin, self.org)
        page = self.client.get("/app/admin/").content.decode()
        self.assertRegex(page, r'id="check-user-records"\s+disabled')
        self.assertIn("A site administrator turns it on or off.", page)


class TypeSharingTest(TestCase):

    def setUp(self):
        self.org = make_org("Mine")
        self.admin = User.objects.create(national_id_card_number="1111222233334444")
        join(self.org, self.admin, Membership.ROLE_ADMIN)
        self.kind = TransactionType.objects.create(organization=self.org, name="Visit")
        sign_in(self.client, self.admin, self.org)

    def _share(self, value):
        return post_json(self.client, "/app/admin/update-transaction-type/",
                         {"id": self.kind.pk, "shared_in_user_records": value})

    def test_an_organization_admin_keeps_a_type_to_itself(self):
        self.assertEqual(self._share(False).status_code, 200)
        self.kind.refresh_from_db()
        self.assertFalse(self.kind.shared_in_user_records)

    def test_only_a_real_boolean(self):
        self.assertEqual(self._share("false").status_code, 400)
        self.kind.refresh_from_db()
        self.assertTrue(self.kind.shared_in_user_records)

    def test_the_page_offers_it(self):
        page = self.client.get("/app/admin/").content.decode()
        self.assertRegex(page, r'data-shared-tt="%d"\s+checked' % self.kind.pk)


class HstsTest(TestCase):

    def test_an_https_answer_carries_it(self):
        response = self.client.get("/", secure=True)
        self.assertEqual(response["Strict-Transport-Security"], "max-age=31536000")

    def test_this_host_only_by_default(self):
        self.assertFalse(settings.SECURE_HSTS_INCLUDE_SUBDOMAINS)


class AbsoluteSessionLifetimeTest(TestCase):

    def setUp(self):
        self.org = make_org("Mine")
        self.operator = User.objects.create(national_id_card_number="1111222233334444")
        join(self.org, self.operator)

    def _signed_in_ago(self, seconds):
        sign_in(self.client, self.operator, self.org)
        session = self.client.session
        session[SIGNED_IN_AT] = int(time.time()) - seconds
        session.save()

    def test_a_session_older_than_the_limit_ends(self):
        self._signed_in_ago(settings.SESSION_ABSOLUTE_SECONDS + 60)
        self.assertRedirects(self.client.get("/validate/"), "/",
                             fetch_redirect_response=False)
        self.assertIsNone(self.client.session.get(SESSION_KEY))

    def test_a_younger_one_goes_on(self):
        self._signed_in_ago(settings.SESSION_ABSOLUTE_SECONDS - 60)
        self.assertEqual(self.client.get("/validate/").status_code, 200)

    def test_one_opened_before_the_rule_is_stamped_not_ended(self):
        sign_in(self.client, self.operator, self.org)
        self.assertEqual(self.client.get("/validate/").status_code, 200)
        self.assertAlmostEqual(self.client.session[SIGNED_IN_AT], time.time(), delta=60)

    def test_signing_in_starts_the_clock(self):
        self._signed_in_ago(settings.SESSION_ABSOLUTE_SECONDS + 60)
        from verify.views.helpers import _login_session
        request = type("R", (), {"session": self.client.session})()
        _login_session(request, self.operator)
        self.assertAlmostEqual(request.session[SIGNED_IN_AT], time.time(), delta=60)

    def test_a_django_admin_login_starts_it_too(self):
        get_user_model().objects.create_superuser("root", "r@example.org", "pw")
        self.client.login(username="root", password="pw")
        self.assertAlmostEqual(self.client.session[SIGNED_IN_AT], time.time(), delta=60)

    def test_the_setting(self):
        self.assertEqual(settings.SESSION_ABSOLUTE_SECONDS, 12 * 3600)


# ---------------------------------------------------------------------------
# A bash that can run the deploy scripts.
# ---------------------------------------------------------------------------

BASH = shutil.which("bash")


#: Whether a deploy script can be run here.
CAN_RUN_DEPLOY = bool(BASH and "system32" not in BASH.lower())
