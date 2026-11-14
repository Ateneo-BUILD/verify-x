"""A signer that dials out: the poll transport, its HMAC, its backoff.

What these pin is the signer's half (`signer/poll.py`): a job is answered
exactly as the app socket answers it, nothing an operator does is reachable
through the queue, both directions carry the key's MAC for the site's host,
nothing malformed is more than a refusal, a poll takes only what idle
workers can answer and refuses a job that ran out, and a site that does not
answer -- or does not take the answers -- is alerted on a single time, in
its own words, not once per attempt. verify's half -- the queue, its
endpoints and the client -- is `accounts/tests_signer_queue.py`.
"""

import base64
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.parse
from types import SimpleNamespace
from unittest import mock

from signer import aws, config as cfgmod, poll, reconcile, startup
from signer.store import Store
from signer.transport import Dispatcher

from . import test_operations
from .helpers import SignerTest

KEY = bytes(range(32))
SITE_URL = "https://verify.example.ph"
HOST = "verify.example.ph"


class FakeSite:
    """The site's two endpoints as verify answers them, in memory: it
    checks the signer's MAC (for its own host) and nonce, and signs what it
    says back."""

    def __init__(self, key=KEY, *, sign_with=None, host=HOST):
        self.key = key
        self.sign_with = sign_with or key
        self.host = host
        self.pending = []           # [(id, request text, seconds left)]
        self.answers = {}
        self.posts = 0
        self.seen = set()
        self.next_id = 1
        self.down = None            # an exception to raise instead
        self.down_posts = None      # one for answers only
        self.status = None          # an HTTP status to answer instead
        self.answer_status = []     # statuses for the next answers
        self.asked = []             # each poll's query

    def queue(self, op, expires_in=10, **args):
        job_id = self.next_id
        self.next_id += 1
        self.pending.append((job_id, json.dumps({"op": op, "args": args}),
                             expires_in))
        return job_id

    def __call__(self, method, url, headers, body, timeout):
        if self.down is not None:
            raise self.down
        if method == "POST" and self.down_posts is not None:
            raise self.down_posts
        parts = urllib.parse.urlsplit(url)
        path = parts.path + ("?" + parts.query if parts.query else "")
        refuse = self.status
        if method == "POST":
            self.posts += 1
            if self.answer_status:
                refuse = self.answer_status.pop(0)
        if refuse is not None:
            return refuse, (lambda name: None), json.dumps(
                {"error": "Not authorised."}).encode()
        nonce = poll.check(self.key, headers.get, method, path, body,
                           host=self.host)
        assert nonce not in self.seen, "a nonce used twice"
        self.seen.add(nonce)
        if parts.path == poll.JOBS_PATH:
            query = urllib.parse.parse_qs(parts.query)
            self.asked.append(query)
            n = int(query["max"][0])
            handed, self.pending = self.pending[:n], self.pending[n:]
            reply = {"jobs": [{"id": i, "request": r, "expires_at": 0,
                               "expires_in": left} for i, r, left in handed]}
        else:
            accepted, unknown = [], []
            for item in json.loads(body)["answers"]:
                (unknown if item["id"] in self.answers else accepted).append(
                    item["id"])
                self.answers.setdefault(item["id"], item["reply"])
            reply = {"accepted": accepted, "unknown": unknown}
        data = json.dumps(reply).encode()
        signed = poll.sign(self.sign_with, poll.RESPONSE, path, data,
                           host=self.host, request_nonce=nonce)
        return 200, (lambda name: {k.lower(): v for k, v in signed.items()}
                     .get(name.lower())), data


class _Synchronous:
    """A poller's executor that answers in the caller's thread."""

    def submit(self, fn, *args):
        fn(*args)

    def shutdown(self, wait=True):
        pass


class MacTest(unittest.TestCase):

    def headers(self, **kw):
        return poll.sign(KEY, "POST", poll.ANSWERS_PATH, b"{}", host=HOST, **kw)

    def check(self, headers, **kw):
        return poll.check(KEY, headers.get, kw.pop("method", "POST"),
                          kw.pop("path", poll.ANSWERS_PATH),
                          kw.pop("body", b"{}"), host=kw.pop("host", HOST), **kw)

    def test_a_signed_request_checks_and_names_its_nonce(self):
        h = self.headers()
        self.assertEqual(self.check(h), h[poll.HEADER_NONCE])

    def test_every_part_is_bound_the_sites_host_too(self):
        """Two sites sharing a key cannot replay into each other."""
        h = self.headers()
        for change in ({"method": "GET"}, {"path": poll.JOBS_PATH},
                       {"body": b"{ }"}, {"host": "other.example.ph"}):
            with self.subTest(change=change):
                with self.assertRaises(poll.AuthError) as err:
                    self.check(h, **change)
                self.assertEqual(err.exception.reason, "mac")
        with self.assertRaises(poll.AuthError):
            poll.check(bytes(32), h.get, "POST", poll.ANSWERS_PATH, b"{}",
                       host=HOST)

    def test_the_host_is_written_one_way(self):
        """`site_url`'s host and Django's reading of the request's agree."""
        self.assertEqual(poll.site_host("https://Verify.Example.PH:443/"), HOST)
        self.assertEqual(poll.normal_host("VERIFY.example.ph."), HOST)
        self.assertEqual(poll.normal_host("[::1]"), poll.site_host(
            "http://[::1]:8000"))
        self.check(poll.sign(KEY, "POST", poll.ANSWERS_PATH, b"{}",
                             host="Verify.Example.PH"))

    def test_the_query_string_is_part_of_the_path(self):
        """`wait` and `max` cannot be changed on the way."""
        h = poll.sign(KEY, "GET", poll.JOBS_PATH + "?wait=20&max=10",
                      host=HOST)
        with self.assertRaises(poll.AuthError):
            poll.check(KEY, h.get, "GET", poll.JOBS_PATH + "?wait=20&max=99",
                       host=HOST)

    def test_a_clock_more_than_a_minute_away_is_refused(self):
        h = self.headers(now=1_800_000_000)
        self.check(h, now=1_800_000_060)
        for now in (1_800_000_061, 1_799_999_939):
            with self.subTest(now=now):
                with self.assertRaises(poll.AuthError) as err:
                    self.check(h, now=now)
                self.assertEqual(err.exception.reason, "skew")

    def test_missing_headers(self):
        good = self.headers()
        for name in (poll.HEADER_MAC, poll.HEADER_NONCE, poll.HEADER_TIME):
            with self.subTest(name=name):
                h = dict(good)
                h[name] = None
                with self.assertRaises(poll.AuthError) as err:
                    self.check(h)
                self.assertEqual(err.exception.reason, "missing")

    def test_malformed_headers_are_a_refusal_never_an_error(self):
        good = self.headers()
        for name, value in ((poll.HEADER_TIME, "¹²³"),
                            (poll.HEADER_TIME, "١٢٣"),
                            (poll.HEADER_TIME, "-5"),
                            (poll.HEADER_TIME, "1e9"),
                            (poll.HEADER_TIME, "1" * 13),
                            (poll.HEADER_MAC, "é" * 64),
                            (poll.HEADER_MAC, good[poll.HEADER_MAC].upper()),
                            (poll.HEADER_MAC, good[poll.HEADER_MAC][:63]),
                            (poll.HEADER_MAC, " " + good[poll.HEADER_MAC]),
                            (poll.HEADER_NONCE, "short"),
                            (poll.HEADER_NONCE, "a" * 20 + "\n"),
                            (poll.HEADER_NONCE, "é" * 20),
                            (poll.HEADER_NONCE, "a" * 65)):
            with self.subTest(name=name, value=value):
                h = dict(good)
                h[name] = value
                with self.assertRaises(poll.AuthError) as err:
                    self.check(h)
                self.assertEqual(err.exception.reason, "malformed")

        def broken(name):
            raise UnicodeDecodeError("latin-1", b"\xff", 0, 1, "bad")

        with self.assertRaises(poll.AuthError):
            poll.check(KEY, broken, "POST", poll.ANSWERS_PATH, b"{}", host=HOST)

    def test_a_response_is_bound_to_its_request(self):
        """Neither replayed as a request nor as another request's answer."""
        signed = poll.sign(KEY, poll.RESPONSE, poll.JOBS_PATH, b"{}",
                           host=HOST, request_nonce="n" * 32)
        poll.check(KEY, signed.get, poll.RESPONSE, poll.JOBS_PATH, b"{}",
                   host=HOST, request_nonce="n" * 32)
        with self.assertRaises(poll.AuthError):
            poll.check(KEY, signed.get, poll.RESPONSE, poll.JOBS_PATH, b"{}",
                       host=HOST, request_nonce="m" * 32)
        with self.assertRaises(poll.AuthError):
            poll.check(KEY, signed.get, "GET", poll.JOBS_PATH, b"{}",
                       host=HOST)

    def test_the_key_is_32_bytes_in_hex_or_base64(self):
        self.assertEqual(poll.parse_key(KEY.hex()), KEY)
        self.assertEqual(poll.parse_key(" %s\n" % KEY.hex()), KEY)
        self.assertEqual(poll.parse_key(base64.b64encode(KEY).decode()), KEY)
        for raw in ("", "00" * 31, "zz" * 32, base64.b64encode(KEY[:16]).decode(),
                    "not a key"):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    poll.parse_key(raw)


class TransportPolicyTest(unittest.TestCase):

    def test_socket_is_the_default_and_poll_needs_an_https_origin(self):
        self.assertEqual(cfgmod.runtime_transport({}), "socket")
        self.assertEqual(cfgmod.runtime_transport(
            {"transport": "poll", "site_url": SITE_URL}), "poll")
        self.assertEqual(cfgmod.runtime_transport(
            {"transport": "poll", "site_url": "http://127.0.0.1:8000"}), "poll")
        for rt in ({"transport": "tcp"},
                   {"transport": "poll"},
                   {"transport": "poll", "site_url": ""},
                   {"transport": "poll", "site_url": "http://verify.example.ph"},
                   {"transport": "poll", "site_url": SITE_URL + "/app/"},
                   {"transport": "poll", "site_url": SITE_URL + "?x=1"},
                   {"transport": "poll", "site_url": "https://user@verify.example.ph"},
                   {"transport": "poll", "site_url": "verify.example.ph"}):
            with self.subTest(rt=rt):
                with self.assertRaises(ValueError):
                    cfgmod.runtime_transport(rt)


class RetentionTest(SignerTest):
    """How long each shipped ledger object is locked: the policy's."""

    def test_400_days_unless_the_policy_says_otherwise(self):
        self.assertEqual(cfgmod.runtime_retain_days({}), 400)
        self.assertEqual(cfgmod.runtime_retain_days(
            {"ledger_retain_days": 7}), 7)
        for value in (0, -1, "30", True, 1.5):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    cfgmod.runtime_retain_days({"ledger_retain_days": value})

    def test_a_bad_value_stops_the_signer(self):
        path = os.path.join(self.dir, "policy.toml")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write('[runtime]\nsite = "x"\nledger_retain_days = 0\n')
        with self.assertRaises(ValueError):
            cfgmod.load(path)

    def test_each_object_is_written_with_it(self):
        import datetime
        kept = []

        class Recorder(aws.FakeUploader):
            def put(self, key, body, retain_until):
                kept.append(retain_until)
                super().put(key, body, retain_until)

        self.ready()
        for days in (400, 3):
            with self.subTest(days=days):
                with self.store as db:
                    from signer import ledger
                    ledger.append(db, at=self.clock.now(), kind="admin",
                                  context="test", summary={})
                aws.Shipper(self.store, Recorder(), "verify", self.clock,
                            retain_days=days).ship()
                now = datetime.datetime.fromtimestamp(self.clock.now(),
                                                      datetime.timezone.utc)
                self.assertEqual(kept[-1] - now, datetime.timedelta(days=days))


class PollCheckTest(SignerTest):
    """`python -m signer check` for a poll-mode policy."""

    #: The policy CheckTest writes, without inheriting CheckTest's tests.
    _policy = test_operations.CheckTest._policy

    def _poll_policy(self, extra_runtime='transport = "poll"\n'
                                         'site_url = "%s"\n' % SITE_URL,
                     aws=False):
        path, db = self._policy()
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        text = (text.replace('app_socket = "a.sock"\n', "")
                .replace('app_user = "verify-app"\n', "") + extra_runtime)
        if aws:
            text = text.replace('ledger_dir = "ledger"\n',
                                'aws_region = "r"\nledger_bucket = "b"\n'
                                'sns_topic = "arn:t"\n')
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path

    def credentials(self, **files):
        folder = tempfile.mkdtemp(dir=self.dir)
        for name, value in files.items():
            with open(os.path.join(folder, name.replace("_", "-")), "w",
                      encoding="utf-8") as handle:
                handle.write(value)
        return mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": folder})

    def test_no_app_socket_or_app_user_is_needed(self):
        path = self._poll_policy()
        with self.credentials(poll_key=KEY.hex()):
            self.assertEqual(startup.check(
                path, lookup_user=lambda name: self.fail("looked up %s" % name),
                lookup_group=lambda name: None), "")

    def test_the_site_is_named_and_its_form_checked(self):
        self.assertIn("site_url", startup.check(
            self._poll_policy('transport = "poll"\n')))
        self.assertIn("https", startup.check(self._poll_policy(
            'transport = "poll"\nsite_url = "http://verify.example.ph"\n')))

    def test_the_poll_key_must_be_there_and_be_one(self):
        path = self._poll_policy()
        with self.credentials():
            self.assertIn("poll-key", startup.check(path))
        with self.credentials(poll_key="not a key"):
            self.assertIn("32 bytes", startup.check(path))

    def test_aws_keys_are_both_or_neither_in_poll_mode(self):
        path = self._poll_policy(aws=True)
        with self.credentials(poll_key=KEY.hex()):
            self.assertEqual(startup.check(path), "")
        with self.credentials(poll_key=KEY.hex(), aws_access_key_id="k"):
            self.assertIn("without", startup.check(path))

    def test_a_socket_policy_still_needs_both_aws_credentials(self):
        """The instance role is for a host with no app on it only."""
        path, _db = self._policy()
        with open(path, encoding="utf-8") as handle:
            text = handle.read().replace(
                'ledger_dir = "ledger"\n',
                'aws_region = "r"\nledger_bucket = "b"\nsns_topic = "arn:t"\n')
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        with self.credentials():
            self.assertIn("the credential aws-access-key-id is not there",
                          startup.check(path))

    def test_a_socket_policy_still_needs_its_app_user(self):
        path, _db = self._policy()
        with open(path, encoding="utf-8") as handle:
            text = handle.read().replace('app_user = "verify-app"\n', "")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        self.assertIn("app_user", startup.check(path))


class AwsCredentialsTest(unittest.TestCase):
    """An IAM user's key; or, for a poll-mode signer only, none and boto3's
    own chain (an instance role)."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.dir, True)
        patcher = mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY":
                                               self.dir})
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
            os.environ.pop(name, None)

    def write(self, *names):
        for name in names:
            with open(os.path.join(self.dir, name), "w") as handle:
                handle.write(" %s\n" % name.upper())

    def test_a_signer_beside_the_app_refuses_without_its_keys(self):
        with self.assertRaises(FileNotFoundError):
            startup.aws_environment()
        self.assertTrue(issubclass(FileNotFoundError,
                                   startup.CONFIGURATION_ERRORS))

    def test_a_poll_mode_signer_leaves_the_environment_to_boto3(self):
        self.assertFalse(startup.aws_key_files())
        self.assertFalse(startup.aws_environment(role_allowed=True))
        self.assertNotIn("AWS_ACCESS_KEY_ID", os.environ)

    def test_both_are_put_where_boto3_reads_first(self):
        self.write(*startup.AWS_CREDENTIALS)
        self.assertTrue(startup.aws_environment())
        self.assertEqual(os.environ["AWS_ACCESS_KEY_ID"], "AWS-ACCESS-KEY-ID")
        self.assertEqual(os.environ["AWS_SECRET_ACCESS_KEY"],
                         "AWS-SECRET-ACCESS-KEY")

    def test_one_without_the_other_is_a_configuration_error(self):
        self.write("aws-access-key-id")
        for allowed in (False, True):
            with self.subTest(role_allowed=allowed):
                with self.assertRaises(ValueError):
                    startup.aws_environment(role_allowed=allowed)
        self.assertTrue(issubclass(ValueError, startup.CONFIGURATION_ERRORS))

    def test_the_start_alert_channel_uses_the_role_in_poll_mode_only(self):
        made = []

        class Sns:
            def __init__(self, *args):
                made.append(args)

        rt = {"sns_topic": "arn:t", "aws_region": "r"}
        with mock.patch.object(aws, "SnsAlerts", Sns):
            self.assertIsInstance(startup.bare_alerts(rt), aws.LogAlerts)
            self.assertIsInstance(startup.bare_alerts(dict(
                rt, transport="poll", site_url=SITE_URL)), Sns)
        self.assertEqual(len(made), 1)


class PollerTest(SignerTest):

    def setUp(self):
        super().setUp()
        self.deployment = self.ready()
        self.site = FakeSite()
        self.now = [0.0]
        self.client = poll.SiteClient(SITE_URL, KEY, send=self.site,
                                      monotonic=lambda: self.now[0])
        self.dispatcher = Dispatcher(self.svc)
        self.sent = []
        self.slept = []
        self.poller = poll.Poller(
            self.client, self.dispatcher,
            alert=lambda severity, message, fields: self.sent.append(
                (severity, message)),
            clock=lambda: self.now[0], wall=lambda: 1_800_000_000 + self.now[0],
            sleep=self.slept.append, jitter=lambda: 1.0, workers=1)
        self.poller.executor.shutdown()
        self.poller.executor = _Synchronous()
        # The journal's lines, kept out of the test output.
        patcher = mock.patch.object(poll, "logger")
        self.logged = patcher.start()
        self.addCleanup(patcher.stop)

    def reply(self, job_id):
        return json.loads(self.site.answers[job_id])

    def signed_rows(self):
        return self.store.one("SELECT COUNT(*) AS n FROM ledger WHERE "
                              "kind = 'sign' AND context = 'credential'")["n"]

    # -- answered as the app socket answers --------------------------------

    def test_a_job_is_answered_byte_for_byte_as_the_socket_would(self):
        job = self.site.queue("public")
        self.assertEqual(self.poller.cycle(), 0.0)
        socket_frame = json.dumps(self.dispatcher.handle(
            {"op": "public", "args": {}}, admin=False, by="verify-app"))
        self.assertEqual(self.site.answers[job], socket_frame)

    def test_a_credential_is_signed_through_the_queue(self):
        message = self.credential(self.deployment)
        job = self.site.queue("sign_credential",
                              message=base64.b64encode(message).decode(),
                              operator="OPERATOR")
        self.poller.cycle()
        reply = self.reply(job)
        self.assertTrue(reply["ok"], reply)
        self.assertEqual(reply["result"]["key_id"], self.deployment)

    def test_a_refusal_comes_back_as_the_socket_says_it(self):
        self.svc.pause("credential", reason="test")
        message = self.credential(self.deployment)
        job = self.site.queue("sign_credential",
                              message=base64.b64encode(message).decode())
        self.poller.cycle()
        self.assertEqual(self.reply(job), {"ok": False, "reason": "paused",
                                           "detail": "", "extra": {}})

    def test_no_operators_command_is_reachable_through_the_queue(self):
        """The HMAC stands in for the app user's uid, not for an operator."""
        self.poller.workers = poll.MAX_JOBS
        jobs = [self.site.queue(op, key_id=self.deployment)
                for op in ("withdraw", "unsuspend", "activate", "retire",
                           "publish", "legacy_end")]
        jobs.append(self.site.queue("resume", context="credential"))
        jobs.append(self.site.queue("keygen"))
        jobs.append(self.site.queue("ca_withdraw", ca_id=1))
        self.poller.cycle()
        for job in jobs:
            with self.subTest(job=job):
                self.assertEqual(self.reply(job)["reason"], "forbidden")

    def test_a_job_that_is_not_an_object_is_a_bad_request(self):
        self.poller.workers = 2
        self.site.pending.append((99, "[1, 2]", 10))
        self.site.pending.append((98, "not json", 10))
        self.poller.cycle()
        for job in (98, 99):
            self.assertEqual(self.reply(job)["reason"], "bad_request")

    def test_status_says_how_the_poll_and_its_answers_are_going(self):
        self.dispatcher.status_extra["poll"] = self.poller.state
        self.site.queue("feed")
        self.poller.cycle()
        got = self.dispatcher.handle({"op": "status"}, admin=True, by="alice")
        state = got["result"]["poll"]
        self.assertEqual(state["site"], SITE_URL)
        self.assertEqual((state["failures_in_a_row"], state["answered"],
                          state["answers_failing_in_a_row"],
                          state["answers_lost"]), (0, 1, 0, 0))

    # -- only what it can answer, only while it is wanted --------------------

    def test_it_asks_for_no_more_jobs_than_it_has_idle_workers(self):
        self.poller.workers = 3
        self.poller.busy = 1
        self.poller.cycle()
        self.assertEqual(self.site.asked[-1]["max"], ["2"])
        self.poller.busy = 3
        with mock.patch.object(self.poller._idle, "wait") as waited:
            self.assertEqual(self.poller.cycle(), 0.0)
        waited.assert_called_once()
        self.assertEqual(len(self.site.asked), 1)       # not asked at all

    def test_a_job_that_ran_out_is_refused_without_acting(self):
        """verify has given up on it: signing it would only spend a
        credential id and a ceiling on nobody."""
        message = self.credential(self.deployment)
        late = self.site.queue("sign_credential", expires_in=0,
                               message=base64.b64encode(message).decode())
        self.poller.cycle()
        self.assertEqual(self.reply(late)["reason"], "expired")
        self.assertEqual(self.signed_rows(), 0)
        self.assertEqual(self.poller.state()["expired_unanswered"], 1)
        in_time = self.site.queue("sign_credential", expires_in=5,
                                  message=base64.b64encode(message).decode())
        self.poller.cycle()
        self.assertTrue(self.reply(in_time)["ok"])

    def test_the_time_left_is_counted_on_this_hosts_clock(self):
        """Not by comparing the two clocks, which may be a minute apart."""
        job = self.site.queue("public", expires_in=3)
        [got] = self.client.jobs(0, 1)
        self.now[0] += 2.9
        self.poller._answer(got)
        self.assertTrue(self.reply(job)["ok"])
        job = self.site.queue("public", expires_in=3)
        [got] = self.client.jobs(0, 1)
        self.now[0] += 3
        self.poller._answer(got)
        self.assertEqual(self.reply(job)["reason"], "expired")

    def test_the_site_is_told_which_signer_polls(self):
        client = poll.SiteClient(SITE_URL, KEY, send=self.site,
                                 instance="0a1b2c.signer-host")
        client.jobs(0, 1)
        self.assertEqual(self.site.asked[-1]["signer"], ["0a1b2c.signer-host"])
        poll.SiteClient(SITE_URL, KEY, send=self.site,
                        instance="bad id!").jobs(0, 1)
        self.assertNotIn("signer", self.site.asked[-1])

    # -- answers, and when they do not get through ----------------------------

    def test_an_answer_that_did_not_arrive_is_sent_again(self):
        real = self.site
        tries = []

        def flaky(method, url, headers, body, timeout):
            if method == "POST" and not tries:
                tries.append(1)
                raise ConnectionResetError("reset")
            return real(method, url, headers, body, timeout)

        self.client.send = flaky
        job = self.site.queue("feed")
        self.poller.cycle()
        self.assertIn(job, self.site.answers)
        self.assertEqual(self.slept, [poll.BACKOFF_FIRST])
        self.assertEqual(self.poller.state()["answers_lost"], 0)

    def test_answers_lost_in_a_row_are_counted_and_alerted_once(self):
        self.site.down_posts = ConnectionResetError("reset")
        for n in range(1, poll.ANSWER_ALERT_AFTER + 3):
            self.site.queue("feed")
            self.poller.cycle()
            state = self.poller.state()
            self.assertEqual((state["answers_failing_in_a_row"],
                              state["answers_lost"]), (n, n))
            self.assertIn("reset", state["last_answer_error"])
        high = [m for s, m in self.sent if s == "high"]
        self.assertEqual(len(high), 1, self.sent)
        self.assertIn("%d answers in a row did not reach"
                      % poll.ANSWER_ALERT_AFTER, high[0])
        self.site.down_posts = None
        self.site.queue("feed")
        self.poller.cycle()
        self.assertEqual(self.sent[-1][0], "medium")
        self.assertIn("answers reach", self.sent[-1][1])
        self.assertEqual(self.poller.state()["answers_failing_in_a_row"], 0)

    def test_an_answer_too_large_to_post_says_so_and_verify_still_hears(self):
        """Not the key, the clock or the proxy: the size. verify learns the
        request may have been done, at once rather than at its timeout."""
        job = self.site.queue("public")
        with mock.patch.object(poll, "MAX_ANSWER_BYTES", 400):
            self.poller.cycle()
        self.assertEqual(self.reply(job), poll.TOO_LARGE_REPLY)
        [(severity, message)] = self.sent
        self.assertEqual(severity, "high")
        self.assertIn("too large", message)
        self.assertNotIn("refuses", message)
        self.assertEqual(self.poller.state()["too_large"], 1)

    def test_a_413_from_the_site_is_said_as_what_it_is(self):
        job = self.site.queue("feed")
        self.site.answer_status = [413]
        self.poller.cycle()
        self.assertEqual(self.reply(job), poll.TOO_LARGE_REPLY)
        [(severity, message)] = self.sent
        self.assertIn("HTTP 413", message)
        self.assertNotIn("poll key", message)
        self.assertEqual(self.site.posts, 2)        # one 413, one answer

    def test_it_stops_when_told_and_answers_what_it_holds(self):
        stop = threading.Event()
        self.poller.stop = stop
        job = self.site.queue("public")
        real = self.site

        def then_stop(method, url, headers, body, timeout):
            got = real(method, url, headers, body, timeout)
            if method == "GET":
                stop.set()
            return got

        self.client.send = then_stop
        self.poller.run()
        self.assertIn(job, self.site.answers)

    # -- the site not answering ----------------------------------------------

    def test_an_unreachable_site_backs_off_and_alerts_once(self):
        self.site.down = ConnectionRefusedError("refused")
        delays = []
        for _ in range(12):
            delays.append(self.poller.cycle())
            self.now[0] += delays[-1]
        self.assertEqual(delays[:7], [1, 2, 4, 8, 16, 32, 60])
        self.assertEqual(max(delays), poll.BACKOFF_MAX)
        high = [m for s, m in self.sent if s == "high"]
        self.assertEqual(len(high), 1, self.sent)
        self.assertIn("has not reached %s for" % SITE_URL, high[0])
        self.assertGreaterEqual(self.now[0], poll.ALERT_AFTER_SECONDS)

    def test_nothing_is_said_about_a_blip(self):
        self.site.down = ConnectionResetError("reset")
        for _ in range(3):
            self.now[0] += self.poller.cycle()
        self.site.down = None
        self.poller.cycle()
        self.assertEqual(self.sent, [])

    def test_a_long_outage_is_said_again_only_every_few_hours(self):
        self.site.down = TimeoutError("timed out")
        while self.now[0] < poll.REALERT_SECONDS * 2 + 600:
            self.now[0] += self.poller.cycle()
        self.assertEqual(len([s for s, _ in self.sent if s == "high"]), 3)

    def test_a_refusal_is_said_at_once_and_its_end_too(self):
        """A wrong key or clock does not mend itself by waiting."""
        self.site.status = 403
        for _ in range(5):
            self.now[0] += self.poller.cycle()
        [(severity, message)] = self.sent
        self.assertEqual(severity, "high")
        self.assertIn("refuses the signer's poll", message)
        self.assertIn("HTTP 403 (Not authorised.)", message)
        self.site.status = None
        self.poller.cycle()
        self.assertEqual(self.sent[-1][0], "medium")
        self.assertIn("again", self.sent[-1][1])
        self.assertEqual(self.poller.state()["failures_in_a_row"], 0)

    def test_a_poll_answered_with_too_much_is_said_as_what_it_is(self):
        self.site.status = 413
        self.poller.cycle()
        [(severity, message)] = self.sent
        self.assertIn("more than it may", message)
        self.assertNotIn("poll key", message)

    def test_a_signer_pointed_at_another_host_is_refused(self):
        """The site checks the MAC against its own host."""
        self.client.host = "other.example.ph"
        self.site.queue("public")
        with self.assertRaises(poll.AuthError):
            self.client.jobs(0, 1)

    def test_an_answer_not_signed_with_the_key_is_not_the_sites(self):
        """Whoever answered does not hold the key: hand it nothing."""
        self.site.sign_with = bytes(32)
        job = self.site.queue("public")
        self.poller.cycle()
        self.assertNotIn(job, self.site.answers)
        [(severity, message)] = self.sent
        self.assertIn("not the site's", message)

    def test_what_counts_as_the_site_saying_no(self):
        """No key there, a proxy that keeps /api/v1/signer/ to itself, a MAC
        or clock refused, a body too large: waiting mends none of them. A
        server error or a gateway's might pass."""
        for status, kind in ((403, poll.REFUSED), (404, poll.REFUSED),
                             (400, poll.REFUSED), (413, poll.TOO_LARGE),
                             (500, poll.UNREACHABLE), (502, poll.UNREACHABLE),
                             (503, poll.UNREACHABLE)):
            with self.subTest(status=status):
                self.site.status = status
                with self.assertRaises(poll.SiteError) as err:
                    self.client.jobs()
                self.assertEqual(err.exception.kind, kind)
                self.assertIs(err.exception.refused, kind != poll.UNREACHABLE)


class InstanceIdTest(SignerTest):

    def test_stable_across_restarts_and_names_the_host(self):
        first = poll.instance_id(self.store, hostname="signer-1.example")
        self.assertEqual(poll.instance_id(self.store,
                                          hostname="signer-1.example"), first)
        self.assertTrue(first.endswith(".signer-1.example"))
        self.assertTrue(poll.INSTANCE_PATTERN.fullmatch(first))
        other = Store(os.path.join(self.dir, "other.db"))
        self.addCleanup(other.db.close)
        self.assertNotEqual(poll.instance_id(other,
                                             hostname="signer-1.example"),
                            first)
        self.assertTrue(poll.INSTANCE_PATTERN.fullmatch(
            poll.instance_id(self.store, hostname="höst name!")))


class ServiceNoticeTest(SignerTest):

    def test_a_notice_is_in_the_ledger_and_sent(self):
        self.svc.notice("high", "the signer has not reached the site",
                        {"failures": 3})
        row = self.store.one("SELECT * FROM ledger WHERE kind = 'alert' "
                             "ORDER BY seq DESC LIMIT 1")
        self.assertEqual(row["context"], "high")
        self.assertEqual(json.loads(row["summary"])["failures"], 3)
        self.assertIn(("high", "the signer has not reached the site"),
                      self.alerts)


class ReportTargetTest(unittest.TestCase):
    """The reconciler reads the report over loopback beside the app, or
    over https from a poll-mode signer's own host."""

    def test_loopback_with_the_sites_name(self):
        self.assertEqual(reconcile.report_target({
            "report_url": "http://127.0.0.1:8000/api/v1/signer/report/",
            "report_host": "verify.example.ph"}),
            ("http://127.0.0.1:8000/api/v1/signer/report/",
             "verify.example.ph"))

    def test_poll_mode_defaults_to_the_sites_own_https_address(self):
        self.assertEqual(reconcile.report_target({"site_url": SITE_URL + "/"}),
                         (SITE_URL + "/api/v1/signer/report/",
                          "verify.example.ph"))
        with self.assertRaises(KeyError):
            reconcile.report_target({})

    def test_https_is_https_with_the_certificate_checked(self):
        made = []

        class Conn:
            def __init__(self, host, port, timeout, context=None):
                made.append((host, port, context))

            def request(self, method, path, headers):
                made.append((method, path, headers))

            def getresponse(self):
                return mock.Mock(status=200, read=lambda: b'{"since": 1}',
                                 getheader=lambda name: None)

        import http.client
        import ssl
        with mock.patch.object(http.client, "HTTPSConnection", Conn):
            got = reconcile.fetch_report(SITE_URL + "/api/v1/signer/report/",
                                         "verify.example.ph", "t0ken", 5)
        self.assertEqual(got, {"since": 1})
        host, port, context = made[0]
        self.assertEqual((host, port), ("verify.example.ph", 443))
        self.assertIsInstance(context, ssl.SSLContext)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertEqual(made[1][1], "/api/v1/signer/report/?since=5")
        self.assertEqual(made[1][2]["Authorization"], "Bearer t0ken")


class ReconcileWithoutAReportTest(SignerTest):
    """A policy naming no report is a report unavailable: counted, alerted
    after three runs, and the warnings and daily summary still go out."""

    def setUp(self):
        super().setUp()
        from signer import transport
        with mock.patch.dict(sys.modules, {"grp": SimpleNamespace(),
                                           "pwd": SimpleNamespace()}), \
                mock.patch.object(transport, "SocketServer", object,
                                  create=True):
            sys.modules.pop("signer.__main__", None)
            from signer import __main__ as main
        self.main = main
        self.addCleanup(sys.modules.pop, "signer.__main__", None)
        self.db = os.path.join(self.dir, "reconcile.db")
        self.path = os.path.join(self.dir, "policy.toml")
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(
                '[runtime]\nsite = "verify"\ndb = "%s"\nkeys = "%s"\n'
                'app_socket = "a"\nadmin_socket = "b"\napp_user = "verify-app"\n'
                'operators_group = "cl03-operators"\nledger_dir = "%s"\n'
                % (self.db.replace("\\", "/"),
                   os.path.join(self.dir, "k").replace("\\", "/"),
                   os.path.join(self.dir, "ledger").replace("\\", "/")))
        with open(os.path.join(self.dir, "report-token"), "w") as handle:
            handle.write("t0ken")

    def test_the_run_counts_it_and_the_warnings_still_go_out(self):
        with mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": self.dir}), \
                mock.patch("sys.stderr"):
            status = self.main.run_reconcile(SimpleNamespace(config=self.path))
        self.assertEqual(status, 0)
        store = Store(self.db)
        self.addCleanup(store.db.close)
        self.assertEqual(int(store.meta("report_failures")), 1)
        self.assertIsNotNone(store.meta("summary_at"))   # watch.run ran


class DeployFilesTest(unittest.TestCase):

    def read(self, name):
        here = os.path.join(os.path.dirname(__file__), "..", "deploy")
        with open(os.path.join(here, name), encoding="utf-8") as handle:
            return handle.read()

    def test_the_poll_drop_in_loads_the_key_after_any_drop_in_that_clears(self):
        """systemd reads drop-ins by name; an empty LoadCredential= in one
        read later would throw the poll key away."""
        self.assertIn("LoadCredential=poll-key:/etc/cl03-signer/credstore/"
                      "poll-key", self.read("poll.conf"))
        self.assertLess("instance-role.conf", "poll.conf")
        self.assertLess("local-ledger.conf", "poll.conf")
        role = self.read("instance-role.conf")
        self.assertRegex(role, r"(?m)^LoadCredential=$")
        self.assertNotIn("aws-", role.split("[Service]")[1])

    def test_install_has_a_poll_mode_without_an_app_user(self):
        script = self.read("install.sh")
        self.assertIn('if [ "$APP_USER" = "--poll" ]; then', script)
        self.assertIn("/etc/systemd/system/cl03-signer.service.d/poll.conf",
                      script)
