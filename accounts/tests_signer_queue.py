"""verify with a signer that dials out: the job queue and its endpoints.

`SIGNER_QUEUE_KEY` set and `SIGNER_SOCKET` empty: every request for the
signer is a job in the database, collected by the signer's long poll and
answered through `POST /api/v1/signer/answers/` (accounts/signer_queue.py,
signer/poll.py). These pin verify's half: the endpoints take nothing without
the signer's MAC for this site's host, its time and an unused nonce, refuse
anything malformed without an error, and sign what they say back; no job is
handed out twice, each within a size and with its time left by the
database's clock; a request given up on says whether the signer may have
acted; no process lets all its threads wait, nor waits inside a transaction;
and through all of it, a caller reads exactly what the socket would have
said. The end-to-end cases run the real signer and its real poll client
against this site's real views, in one thread: the signer's poll runs inside
the app's wait, where a sleep would have been.
"""

import json
import threading
import time
import urllib.parse
from datetime import timedelta
from unittest import mock

from django.core import checks
from django.db import OperationalError, connection, transaction
from django.template.loader import render_to_string
from django.test import TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from accounts import (checks as account_checks, credential_keys, devices,
                      signer_client, signer_queue)
from accounts.models import IssuedCredential, SignerJob, SignerNonce
from accounts import tests_signer_client as against_the_signer
from signer import poll
from signer.transport import Dispatcher

KEY = bytes(range(1, 33))
KEY_HEX = KEY.hex()
JOBS = "/api/v1/signer/jobs/"
ANSWERS = "/api/v1/signer/answers/"
#: The test client's host: the site's own, in every MAC.
HOST = "testserver"


def _send_through(client):
    """`poll.SiteClient`'s send, through Django's test client: the real
    views, URL routing and middleware, no network."""
    def send(method, url, headers, body, timeout):
        parts = urllib.parse.urlsplit(url)
        path = parts.path + ("?" + parts.query if parts.query else "")
        headers = {k: v for k, v in headers.items() if k != "Content-Type"}
        if method == "GET":
            reply = client.get(path, headers=headers)
        else:
            reply = client.post(path, data=body,
                                content_type="application/json",
                                headers=headers)
        return reply.status_code, reply.headers.get, reply.content
    return send


class _Synchronous:
    """The poller's executor, in this thread: the test database's
    transaction is this thread's only."""

    def submit(self, fn, *args):
        fn(*args)

    def shutdown(self, wait=True):
        pass


@override_settings(SIGNER_QUEUE_KEY=KEY_HEX, SIGNER_SOCKET="")
class EndpointTest(TestCase):
    """The two endpoints, as anybody but the signer meets them."""

    def get(self, path=JOBS + "?wait=0&max=5", key=KEY, host=HOST, **kw):
        return self.client.get(path, headers=poll.sign(key, "GET", path,
                                                       host=host, **kw))

    def post(self, body=b'{"answers": []}', key=KEY, **kw):
        return self.client.post(ANSWERS, data=body,
                                content_type="application/json",
                                headers=poll.sign(key, "POST", ANSWERS, body,
                                                  host=HOST, **kw))

    @override_settings(SIGNER_QUEUE_KEY="")
    def test_both_are_not_found_without_the_key(self):
        self.assertEqual(self.get().status_code, 404)
        self.assertEqual(self.post().status_code, 404)

    def test_nothing_without_the_signers_mac(self):
        self.assertEqual(self.client.get(JOBS).status_code, 403)
        self.assertEqual(self.client.post(ANSWERS, data=b"{}",
                                          content_type="application/json"
                                          ).status_code, 403)
        for reply in (self.get(key=bytes(32)), self.post(key=bytes(32))):
            self.assertEqual(reply.status_code, 403)
            self.assertEqual(reply.json(), {"error": "unauthenticated"})
            self.assertNotIn(poll.HEADER_MAC, reply.headers)
        self.assertEqual(SignerNonce.objects.count(), 0)

    def test_a_request_signed_for_another_site_is_refused(self):
        """Two sites sharing a key cannot replay into each other."""
        reply = self.get(host="other.example.ph")
        self.assertEqual((reply.status_code, reply.json()),
                         (403, {"error": "unauthenticated"}))

    def test_malformed_headers_are_a_bare_403_never_a_500(self):
        """Superscript digits for the time, which `isdigit` takes and `int`
        refuses, and a non-ASCII MAC, which makes `compare_digest` raise."""
        path = JOBS + "?wait=0"
        good = poll.sign(KEY, "GET", path, host=HOST)
        for name, value in ((poll.HEADER_TIME, "¹²³"),
                            (poll.HEADER_MAC, "é" * 64),
                            (poll.HEADER_NONCE, "é" * 20)):
            with self.subTest(name=name):
                headers = dict(good, **{name: value})
                reply = self.client.get(path, headers=headers)
                self.assertEqual((reply.status_code, reply.json()),
                                 (403, {"error": "unauthenticated"}))
                self.assertNotIn(poll.HEADER_MAC, reply.headers)

    def test_a_changed_query_or_body_is_refused(self):
        headers = poll.sign(KEY, "GET", JOBS + "?wait=0&max=5", host=HOST)
        self.assertEqual(self.client.get(JOBS + "?wait=0&max=50",
                                         headers=headers).status_code, 403)
        headers = poll.sign(KEY, "POST", ANSWERS, b'{"answers": []}',
                            host=HOST)
        self.assertEqual(self.client.post(
            ANSWERS, data=b'{"answers": [] }', content_type="application/json",
            headers=headers).status_code, 403)

    def test_a_clock_out_by_more_than_a_minute_is_named(self):
        reply = self.get(now=time.time() - 61)
        self.assertEqual((reply.status_code, reply.json()),
                         (403, {"error": "clock"}))

    def test_a_replayed_request_is_refused_on_any_server(self):
        headers = poll.sign(KEY, "GET", JOBS + "?wait=0", host=HOST)
        self.assertEqual(self.client.get(JOBS + "?wait=0",
                                         headers=headers).status_code, 200)
        reply = self.client.get(JOBS + "?wait=0", headers=headers)
        self.assertEqual((reply.status_code, reply.json()),
                         (403, {"error": "replayed"}))

    def test_what_the_site_says_back_is_signed_for_that_request(self):
        path = JOBS + "?wait=0&max=5"
        headers = poll.sign(KEY, "GET", path, host=HOST)
        reply = self.client.get(path, headers=headers)
        self.assertEqual(reply.json(), {"jobs": []})
        poll.check(KEY, reply.headers.get, poll.RESPONSE, path, reply.content,
                   host=HOST, request_nonce=headers[poll.HEADER_NONCE])
        with self.assertRaises(poll.AuthError):
            poll.check(KEY, reply.headers.get, poll.RESPONSE, path,
                       reply.content, host=HOST, request_nonce="x" * 32)

    def test_each_job_says_how_long_it_has_by_the_databases_clock(self):
        SignerJob.objects.create(request='{"op": "feed", "args": {}}',
                                 created_at=timezone.now(),
                                 expires_at=timezone.now() + timedelta(
                                     seconds=10))
        [job] = self.get(JOBS + "?wait=0&max=5").json()["jobs"]
        self.assertEqual(job["request"], '{"op": "feed", "args": {}}')
        # The job's time is the database's and this test's is Python's: they
        # can differ by a fraction of a millisecond either way.
        self.assertTrue(9 < job["expires_in"] <= 10.05, job)
        self.assertAlmostEqual(job["expires_at"], time.time() + 10, delta=2)

    def test_the_poll_names_its_signer(self):
        self.get(JOBS + "?wait=0&signer=0a1b2c.host-one")
        self.get(JOBS + "?wait=0&signer=not%20an%20id")
        self.assertEqual(sorted(SignerNonce.objects.values_list(
            "signer", flat=True)), ["", "0a1b2c.host-one"])

    def test_no_csrf_token_is_asked_of_the_signer(self):
        self.client = self.client_class(enforce_csrf_checks=True)
        self.assertEqual(self.post().status_code, 200)

    def test_a_bad_query_or_body_is_a_signed_400(self):
        reply = self.get(JOBS + "?wait=soon")
        self.assertEqual(reply.status_code, 400)
        self.assertIn(poll.HEADER_MAC, reply.headers)
        for body in (b"[]", b"not json", b'{"answers": [{"id": "1", '
                     b'"reply": "{}"}]}', b'{"answers": [{"id": 1, '
                     b'"reply": "[]"}]}', b'{"answers": {}}'):
            with self.subTest(body=body):
                self.assertEqual(self.post(body).status_code, 400)

    def test_an_answer_over_djangos_limit_is_a_413(self):
        with override_settings(DATA_UPLOAD_MAX_MEMORY_SIZE=100):
            self.assertEqual(self.post(b'{"answers": []}' + b" " * 200)
                             .status_code, 413)

    @override_settings(SIGNER_QUEUE_KEY="not a key")
    def test_a_site_with_a_broken_key_refuses_everything(self):
        self.assertEqual(self.get().status_code, 503)

    def test_the_long_poll_waits_at_most_25_seconds_without_a_transaction(self):
        """A short look every tenth of a second, and nothing held between."""
        waited, now = [], [0.0]

        def pause(seconds):
            self.assertFalse(signer_queue._in_foreign_transaction())
            waited.append(seconds)
            now[0] += seconds

        with mock.patch.object(signer_queue, "_pause", pause), \
                mock.patch.object(signer_queue, "_clock", lambda: now[0]):
            reply = self.get(JOBS + "?wait=99&max=5")
        self.assertEqual(reply.json(), {"jobs": []})
        self.assertAlmostEqual(now[0], poll.MAX_WAIT_SECONDS)
        self.assertEqual(max(waited), signer_queue.JOB_LOOK_SECONDS)

    def test_the_long_poll_answers_as_soon_as_it_has_a_job(self):
        now = [0.0]

        def pause(seconds):
            now[0] += seconds
            if now[0] >= 1 and not SignerJob.objects.exists():
                SignerJob.objects.create(
                    request="{}", created_at=timezone.now(),
                    expires_at=timezone.now() + timedelta(seconds=10))

        with mock.patch.object(signer_queue, "_pause", pause), \
                mock.patch.object(signer_queue, "_clock", lambda: now[0]):
            reply = self.get(JOBS + "?wait=20&max=5")
        self.assertEqual(len(reply.json()["jobs"]), 1)
        self.assertLess(now[0], 1.2)


@override_settings(SIGNER_QUEUE_KEY=KEY_HEX, SIGNER_SOCKET="")
class QueueTest(TestCase):
    """The queue itself, without HTTP."""

    def job(self, request="{}", *, seconds=10, **fields):
        now = timezone.now()
        return SignerJob.objects.create(
            request=request, created_at=now,
            expires_at=now + timedelta(seconds=seconds), **fields)

    def heard(self, signer=""):
        SignerNonce.objects.create(nonce=signer_queue.secrets.token_hex(16),
                                   seen_at=timezone.now(), signer=signer)

    def test_a_job_is_handed_to_one_poll_only(self):
        jobs = [self.job('{"n": %d}' % i) for i in range(5)]
        first = signer_queue.claim(3)
        second = signer_queue.claim(3)
        self.assertEqual([j[0] for j in first], [j.pk for j in jobs[:3]])
        self.assertEqual([j[0] for j in second], [j.pk for j in jobs[3:]])
        self.assertEqual(signer_queue.claim(3), [])
        self.assertEqual(first[0][1], '{"n": 0}')

    def test_a_claim_stops_at_its_size_and_a_big_job_goes_alone(self):
        small = [self.job('{"x": "%s"}' % ("a" * 30)) for _ in range(3)]
        big = self.job('{"x": "%s"}' % ("b" * 300))
        after = self.job()
        with mock.patch.object(signer_queue, "MAX_CLAIM_BYTES", 100):
            self.assertEqual([j[0] for j in signer_queue.claim(10)],
                             [small[0].pk, small[1].pk])
            self.assertEqual([j[0] for j in signer_queue.claim(10)],
                             [small[2].pk])
            self.assertEqual([j[0] for j in signer_queue.claim(10)], [big.pk])
            self.assertEqual([j[0] for j in signer_queue.claim(10)],
                             [after.pk])

    def test_an_expired_or_withdrawn_job_is_not_handed_out(self):
        self.job(seconds=-1)
        self.job(claimed_at=timezone.now(), claim=signer_queue.WITHDRAWN)
        self.assertEqual(signer_queue.claim(10), [])

    def test_an_answer_is_kept_once_for_a_job_handed_out(self):
        waiting = self.job()
        handed = self.job()
        withdrawn = self.job(claimed_at=timezone.now(),
                             claim=signer_queue.WITHDRAWN)
        signer_queue.claim(1)                    # the first
        got = signer_queue.accept([(waiting.pk, '{"ok": true}'),
                                   (handed.pk, '{"ok": true}'),
                                   (withdrawn.pk, '{"ok": true}'),
                                   (999999, '{"ok": true}')])
        self.assertEqual(got["accepted"], [waiting.pk])
        self.assertEqual(sorted(got["unknown"]),
                         sorted([handed.pk, withdrawn.pk, 999999]))
        again = signer_queue.accept([(waiting.pk, '{"ok": false}')])
        self.assertEqual(again["unknown"], [waiting.pk])
        self.assertEqual(SignerJob.objects.get(pk=waiting.pk).answer,
                         '{"ok": true}')

    def test_nothing_is_queued_while_no_signer_polls(self):
        """Else every document would wait out the timeout first."""
        with self.assertRaises(signer_queue.NotCollected):
            signer_queue.ask("{}")
        self.assertEqual(SignerJob.objects.count(), 0)
        SignerNonce.objects.create(
            nonce="o" * 32, seen_at=timezone.now() - timedelta(
                seconds=signer_queue.ALIVE_SECONDS + 1))
        self.assertFalse(signer_queue.alive())

    def _waiting(self, during, timeout=2):
        """ask(), with `during(job)` run at the first pause."""
        now = [0.0]

        def pause(seconds):
            job = SignerJob.objects.order_by("-pk").first()
            if job is not None and not getattr(pause, "done", False):
                pause.done = True
                during(job)
            now[0] += seconds

        with mock.patch.object(signer_queue, "_pause", pause), \
                mock.patch.object(signer_queue, "_clock", lambda: now[0]):
            return signer_queue.ask('{"op": "status", "args": {}}',
                                    timeout=timeout)

    def test_a_job_is_created_and_expires_by_the_databases_clock(self):
        """Not this server's: app servers' clocks may disagree."""
        self.heard()
        seen = {}

        def look(job):
            seen["created"], seen["expires"] = (job.created_at, job.expires_at)

        signer_queue.purge(force=True)            # due now, not inside
        with mock.patch("django.utils.timezone.now",
                        side_effect=AssertionError("a server's clock")), \
                self.assertRaises(signer_queue.NotCollected):
            self._waiting(look, timeout=5)
        self.assertFalse(hasattr(signer_queue, "timezone"))
        self.assertAlmostEqual((seen["expires"] - seen["created"])
                               .total_seconds(), 5, delta=0.01)
        self.assertLess(abs((seen["created"] - timezone.now())
                            .total_seconds()), 5)

    def test_a_job_nobody_collected_is_withdrawn_and_nothing_happened(self):
        self.heard()
        with self.assertRaises(signer_queue.NotCollected):
            self._waiting(lambda job: None)
        self.assertEqual(SignerJob.objects.count(), 0)

    def test_a_job_collected_and_not_answered_may_have_been_done(self):
        self.heard()
        with self.assertRaises(signer_queue.Lost):
            self._waiting(lambda job: signer_queue.claim(10))
        self.assertEqual(SignerJob.objects.count(), 0)

    def test_the_answer_is_returned_as_it_came_and_the_job_deleted(self):
        self.heard()
        text = '{"ok": true, "result": {"x": "\\u00e9"}}'

        def answer(job):
            signer_queue.claim(10)
            signer_queue.accept([(job.pk, text)])

        self.assertEqual(self._waiting(answer), text)
        self.assertEqual(SignerJob.objects.count(), 0)

    @override_settings(SIGNER_QUEUE_MAX_WAITING=1)
    def test_no_more_threads_wait_than_the_process_allows(self):
        """The answer and the poll are requests too: a worker whose every
        thread waits could take neither."""
        self.heard()
        refused = []

        def second(job):
            with self.assertRaises(signer_queue.Busy):
                signer_queue.ask("{}")
            refused.append(SignerJob.objects.count())

        with self.assertRaises(signer_queue.NotCollected):
            self._waiting(second)
        self.assertEqual(refused, [1])            # the second never queued
        self.assertEqual(signer_queue._waiting, 0)
        self.assertTrue(issubclass(signer_queue.Busy,
                                   signer_queue.NotCollected))

    @override_settings(SIGNER_QUEUE_MAX_WAITING=1)
    def test_one_more_waits_a_moment_for_a_place_before_it_is_refused(self):
        held = signer_queue._Slot()
        held.__enter__()
        released = threading.Timer(0.1, held.__exit__, args=(None, None, None))
        released.start()
        started = time.monotonic()
        with signer_queue._Slot(wait=2.0):
            self.assertLess(time.monotonic() - started, 1.5)
        released.join()
        held = signer_queue._Slot()
        held.__enter__()
        try:
            started = time.monotonic()
            with self.assertRaises(signer_queue.Busy):
                signer_queue._Slot(wait=0.05).__enter__()
            self.assertGreaterEqual(time.monotonic() - started, 0.04)
        finally:
            held.__exit__(None, None, None)
        self.assertEqual(signer_queue._waiting, 0)

    def test_the_kits_gunicorn_reads_the_same_threads(self):
        """One GUNICORN_THREADS in .env sets gunicorn's threads and the
        app's cap alike; unset, gunicorn keeps the 2 it always had."""
        import os
        import runpy
        from django.conf import settings as live
        path = os.path.join(live.BASE_DIR, "deploy", "gunicorn.conf.py")
        for value, threads in (("", 2), ("4", 4)):
            with self.subTest(value=value), \
                    mock.patch.dict(os.environ, {"GUNICORN_THREADS": value}):
                self.assertEqual(runpy.run_path(path)["threads"], threads)

    def test_the_cap_is_below_gunicorns_threads_by_default(self):
        from verify import settings as site
        self.assertGreaterEqual(site.SIGNER_QUEUE_MAX_WAITING, 1)
        if site.GUNICORN_THREADS:
            self.assertLess(site.SIGNER_QUEUE_MAX_WAITING,
                            site.GUNICORN_THREADS)

    def test_it_refuses_to_wait_inside_a_transaction(self):
        """The job would be invisible to the poll, and on SQLite the wait
        would hold the one write lock. A test case's own blocks are not
        the caller's."""
        self.heard()
        with transaction.atomic():
            with self.assertRaises(signer_queue.InTransaction):
                signer_queue.ask("{}")
            with self.assertRaises(signer_client.Unavailable) as err:
                with mock.patch.object(signer_client, "_transport", None):
                    signer_client.call("public")
            self.assertFalse(err.exception.reply_lost)
        self.assertEqual(SignerJob.objects.count(), 0)
        self.assertFalse(signer_queue._in_foreign_transaction())

    def test_expired_jobs_and_old_nonces_are_purged(self):
        old = timezone.now() - timedelta(hours=1)
        SignerJob.objects.create(request="{}", created_at=old,
                                 expires_at=old + timedelta(seconds=10))
        live = self.job()
        SignerNonce.objects.create(nonce="a" * 32, seen_at=old)
        self.heard()
        signer_queue.purge(force=True)
        self.assertEqual(list(SignerJob.objects.values_list("pk", flat=True)),
                         [live.pk])
        self.assertEqual(SignerNonce.objects.count(), 1)

    def test_two_signers_polling_are_seen(self):
        self.heard("0a1b2c.host-one")
        self.assertEqual(signer_queue.pollers(), ["0a1b2c.host-one"])
        self.heard("0a1b2c.host-one")
        self.heard("9f8e7d.host-two")
        self.heard("")
        self.assertEqual(signer_queue.pollers(),
                         ["0a1b2c.host-one", "9f8e7d.host-two"])
        page = render_to_string("includes/signing_setup.html", {"signing": {
            "mode": "signer", "pollers": signer_queue.pollers(), "rows": []}})
        self.assertIn("2 different signers have polled this site", page)
        self.assertIn("<code>9f8e7d.host-two</code>", page)

    def test_signer_mode_with_only_the_queue_key(self):
        self.assertTrue(credential_keys.signer_mode())
        self.assertTrue(signer_client.enabled())
        self.assertIs(signer_client._wire(), signer_client._queue_call)
        with override_settings(SIGNER_SOCKET="/run/cl03-signer/app.sock"):
            self.assertIs(signer_client._wire(), signer_client._socket_call)
        with override_settings(SIGNER_QUEUE_KEY=""):
            self.assertFalse(credential_keys.signer_mode())
            self.assertFalse(signer_client.enabled())


@override_settings(SIGNER_QUEUE_KEY=KEY_HEX, SIGNER_SOCKET="")
class ConcurrentClaimTest(TransactionTestCase):
    """Two polls claiming together, each on its own connection, as two app
    servers would: every job goes to one of them, none to both. On SQLite
    the conditional write decides; PostgreSQL adds SKIP LOCKED."""

    def test_two_connections_never_share_a_job(self):
        now = timezone.now()
        SignerJob.objects.bulk_create([SignerJob(
            request='{"n": %d}' % i, created_at=now,
            expires_at=now + timedelta(minutes=5)) for i in range(60)])
        start = threading.Barrier(2)
        got = {0: [], 1: []}
        errors = []

        def poll_until_empty(n):
            try:
                start.wait()
                empty = 0
                while empty < 3:
                    try:
                        claimed = signer_queue.claim(4)
                    except OperationalError:      # the one writer's lock
                        time.sleep(0.001)
                        continue
                    got[n].extend(j[0] for j in claimed)
                    empty = 0 if claimed else empty + 1
            except Exception as exc:              # pragma: no cover
                errors.append(exc)
            finally:
                connection.close()

        threads = [threading.Thread(target=poll_until_empty, args=(n,))
                   for n in (0, 1)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        self.assertEqual(errors, [])
        self.assertEqual(set(got[0]) & set(got[1]), set())
        self.assertEqual(sorted(got[0] + got[1]),
                         sorted(SignerJob.objects.values_list("pk", flat=True)))
        self.assertEqual(SignerJob.objects.filter(
            claimed_at__isnull=True).count(), 0)


class SettingsCheckTest(TestCase):

    def run_check(self):
        return {m.id for m in account_checks.signer_queue_settings()}

    def test_a_good_key_or_none_is_quiet(self):
        with override_settings(SIGNER_QUEUE_KEY=""):
            self.assertEqual(self.run_check(), set())
        with override_settings(SIGNER_QUEUE_KEY=KEY_HEX, SIGNER_SOCKET=""):
            self.assertEqual(self.run_check(), set())

    def test_what_a_deploy_is_told(self):
        with override_settings(SIGNER_QUEUE_KEY="abc"):
            self.assertIn("accounts.E004", self.run_check())
        with override_settings(SIGNER_QUEUE_KEY=KEY_HEX,
                               SIGNER_SOCKET="/run/cl03-signer/app.sock"):
            self.assertIn("accounts.W005", self.run_check())
        for seconds in (0, 26):
            with override_settings(SIGNER_QUEUE_TIMEOUT_SECONDS=seconds):
                self.assertIn("accounts.E005", self.run_check())
        for waiting, threads in ((4, 4), (0, 0), (5, 2)):
            with override_settings(SIGNER_QUEUE_MAX_WAITING=waiting,
                                   GUNICORN_THREADS=threads):
                self.assertIn("accounts.W006", self.run_check())
        with override_settings(SIGNER_QUEUE_MAX_WAITING=3, GUNICORN_THREADS=4):
            self.assertNotIn("accounts.W006", self.run_check())

    def test_it_runs_with_every_deploys_checks(self):
        self.assertIn(account_checks.signer_queue_settings,
                      checks.registry.registry.registered_checks)


class _ThroughTheQueue:
    """Mixed into a test against the in-process signer: the same signer,
    reached through the queue and this site's own endpoints."""

    def setUp(self):
        super().setUp()
        signer_client.set_transport(None)       # the queue, not a shortcut
        self.dispatcher = Dispatcher(self.svc)
        self.site = poll.SiteClient("https://testserver", KEY,
                                    send=_send_through(self.client))
        self.alerts = []
        self.poller = poll.Poller(
            self.site, self.dispatcher, wait=0,
            alert=lambda *args: self.alerts.append(args))
        self.poller.executor.shutdown()
        self.poller.executor = _Synchronous()
        self.poller.cycle()                     # the signer is listening
        self.answers = []
        real_ask = signer_queue.ask

        def spy(text, **kw):
            answer = real_ask(text, **kw)
            self.answers.append((json.loads(text), answer))
            return answer

        for patcher in (mock.patch.object(signer_queue, "_pause",
                                          lambda s: self.poller.cycle()),
                        mock.patch.object(signer_queue, "ask", spy)):
            patcher.start()
            self.addCleanup(patcher.stop)


@override_settings(SIGNER_SOCKET="", SIGNER_QUEUE_KEY=KEY_HEX)
class QueueSignerTest(_ThroughTheQueue, against_the_signer._SignerTest):

    def test_an_answer_is_byte_for_byte_the_sockets(self):
        signer_client.public(force=True)
        request, answer = self.answers[-1]
        self.assertEqual(request, {"op": "public", "args": {}})
        self.assertEqual(answer, json.dumps(self.dispatcher.handle(
            request, admin=False, by="verify-app")))

    def test_a_credential_is_signed_through_the_queue_and_verifies(self):
        from ovcrypto import verifier
        minted = self._mint()
        row = IssuedCredential.objects.get(credential_id=minted["credential_id"])
        self.assertEqual(row.state, IssuedCredential.STATE_SIGNED)
        self.assertEqual(row.issuer_key_id, self.deployment)
        result = self._verify(minted, verifier.TrustList.bare(
            {self.deployment: self._spki(self.deployment)}))
        self.assertTrue(result.ok, result.detail)
        self.assertIn("sign_credential", [r["op"] for r, _ in self.answers])
        self.assertEqual(SignerJob.objects.count(), 0)

    def test_a_refusal_reads_as_it_does_on_the_socket(self):
        self.svc.pause("credential", by="test")
        with self.assertRaises(signer_client.Paused):
            self._mint()
        self.assertEqual(IssuedCredential.objects.count(), 0)

    def test_no_operators_command_goes_through_the_queue(self):
        """The queue is the app's role, as the app socket is."""
        for op, args in (("withdraw", {"key_id": self.deployment}),
                         ("resume", {"context": "credential"}),
                         ("keygen", {})):
            with self.subTest(op=op):
                with self.assertRaises(signer_client.Refused) as err:
                    signer_client.call(op, **args)
                self.assertEqual(err.exception.reason, "forbidden")

    def test_a_signer_that_took_the_job_and_went_quiet_keeps_the_row(self):
        """It may have signed: the row is `unknown`, never deleted."""
        signer_client.public(force=True)          # the key, before it went

        def collects_but_never_answers(seconds):
            signer_queue.claim(10)

        with mock.patch.object(signer_queue, "_pause",
                               collects_but_never_answers), \
                override_settings(SIGNER_QUEUE_TIMEOUT_SECONDS=1):
            with self.assertRaises(signer_client.Unavailable) as err:
                self._mint()
        self.assertTrue(err.exception.reply_lost)
        self.assertEqual(IssuedCredential.objects.get().state,
                         IssuedCredential.STATE_UNKNOWN)

    def test_a_job_that_ran_out_is_refused_and_leaves_no_row(self):
        """The signer acted on nothing, and says so: not a lost reply."""
        signer_client.public(force=True)
        with mock.patch.object(signer_queue, "claim", side_effect=lambda n: [
                (pk, text, at, 0.0) for pk, text, at, _ in
                type(self).real_claim(n)]):
            with self.assertRaises(signer_client.Refused) as err:
                self._mint()
        self.assertEqual(err.exception.reason, "expired")
        self.assertEqual(IssuedCredential.objects.count(), 0)
        self.assertEqual(self.svc.status()["signed_today"]["credential"], 0)

    real_claim = staticmethod(signer_queue.claim)

    def test_setup_reads_the_signer_through_the_queue_and_says_so(self):
        from accounts import signing_status
        summary = signing_status.overview()
        self.assertEqual((summary["mode"], summary["transport"],
                          summary["error"]), ("signer", "queue", ""))
        self.assertIn(self.deployment, [r["key_id"] for r in summary["rows"]])
        self.assertEqual(summary["pollers"], [])     # no id from this client

    def test_a_signer_that_never_came_did_nothing(self):
        SignerNonce.objects.all().delete()
        with self.assertRaises(signer_client.Unavailable) as err:
            self._mint()
        self.assertFalse(err.exception.reply_lost)
        self.assertEqual(IssuedCredential.objects.count(), 0)


@override_settings(SIGNER_SOCKET="", SIGNER_QUEUE_KEY=KEY_HEX)
class QueueBundleTest(_ThroughTheQueue,
                      against_the_signer.SignerBundleTest):
    """A phone's sync through the queue: the revoked set, then the bundle,
    which the phone accepts as the signer's."""

    def test_the_sync_needs_the_signer_listening(self):
        SignerNonce.objects.all().delete()
        with self.assertRaises(devices.PairingError):
            devices.build_bundle_and_chains(self.device)
