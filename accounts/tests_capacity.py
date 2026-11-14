"""What keeps one verification cheap for the site.

What these pin, one rule each:

  * the hand-off purge reads an index, not the whole table;
  * a bridged site admin's placeholder ID fits its column, and the rows
    already written too long are shortened;
  * a signed-in request does not rewrite the session unless something
    changed or the refresh is due, and an anonymous one never creates one;
  * expired sessions -- which can hold a verified person's face -- are
    cleared at sign-in;
  * the static cache-buster is the same for every process serving the same
    files, and changes when a file does;
  * nginx compresses what it sends;
  * the seal image is big enough to print and small enough to send.
"""

import importlib
import os
import shutil
import tempfile
import time
from datetime import timedelta
from importlib import import_module
from pathlib import Path
from unittest.mock import patch

from django.apps import apps
from django.conf import settings
from django.contrib.auth.models import User as DjangoUser
from django.contrib.sessions.models import Session
from django.db import connection
from django.test import RequestFactory, SimpleTestCase, TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from accounts import verified_answer
from accounts.models import CardHandoff, Membership, Transaction, User
from accounts.tests import SESSION_KEY, join, make_org
from verify import sessions as verify_sessions
from verify.static_version import static_version
from verify.views import handoff
from verify.views.helpers import ORG_SESSION_KEY, _get_session_user, _login_session

BASE = Path(settings.BASE_DIR)


def _session_writes(queries):
    return [q["sql"] for q in queries
            if "django_session" in q["sql"]
            and q["sql"].lstrip().upper().startswith(("INSERT", "UPDATE"))]


class HandoffPurgeIndexTest(TestCase):
    """`purge_expired()` runs on every hand-off it opens. Unindexed, each run
    would read the whole table: every hand-off of the last five minutes, half
    a million rows at 100,000 verifications a minute."""

    def test_the_purge_reads_an_index(self):
        plan = CardHandoff.objects.filter(expires_at__lte=timezone.now()).explain()
        self.assertRegex(plan, r"SEARCH card_handoffs USING (COVERING )?INDEX \S*expires_at", plan)
        self.assertNotRegex(plan, r"\bSCAN card_handoffs\b", plan)

    def test_the_purge_still_takes_only_what_has_expired(self):
        now = timezone.now()
        gone = CardHandoff.objects.create(payload={}, expires_at=now - timedelta(seconds=1))
        kept = CardHandoff.objects.create(payload={}, expires_at=now + timedelta(minutes=5))
        handoff.purge_expired()
        self.assertFalse(CardHandoff.objects.filter(pk=gone.pk).exists())
        self.assertTrue(CardHandoff.objects.filter(pk=kept.pk).exists())


class BridgedAdminIdTest(TestCase):
    """A Django superuser opening /app/ gets a verify User with a placeholder
    card number, and it has to fit the sixteen-character column: SQLite
    stores a longer one, PostgreSQL refuses it."""

    def test_a_bridged_admin_fits_the_column(self):
        django_user = DjangoUser.objects.create_superuser("root", "r@example.org", "x")
        request = RequestFactory().get("/app/")
        request.user = django_user
        request.session = import_module(settings.SESSION_ENGINE).SessionStore()
        user = _get_session_user(request)
        limit = User._meta.get_field("national_id_card_number").max_length
        self.assertTrue(user.national_id_card_number.startswith("ADMIN"))
        self.assertLessEqual(len(user.national_id_card_number), limit)
        self.assertEqual(user.national_id_card_number, "ADMIN%011d" % django_user.id)

    def test_the_migration_shortens_the_rows_already_written(self):
        migration = importlib.import_module("accounts.migrations.0042_bridged_admin_ids")
        long_row = User.objects.create(national_id_card_number="ADMIN000000000007",
                                       digital_national_id="root7")
        person = User.objects.create(national_id_card_number="1111222233334444")
        logged = Transaction.objects.create(operator_national_id_number="ADMIN000000000007")
        other = Transaction.objects.create(operator_national_id_number="1111222233334444")
        migration.shorten(apps, None)
        long_row.refresh_from_db()
        person.refresh_from_db()
        logged.refresh_from_db()
        other.refresh_from_db()
        self.assertEqual(long_row.national_id_card_number, "ADMIN00000000007")
        self.assertEqual(person.national_id_card_number, "1111222233334444")
        # The transactions that admin logged still name the same operator.
        self.assertEqual(logged.operator_national_id_number, "ADMIN00000000007")
        self.assertEqual(other.operator_national_id_number, "1111222233334444")

    def test_the_migration_never_takes_a_value_already_in_use(self):
        migration = importlib.import_module("accounts.migrations.0042_bridged_admin_ids")
        User.objects.create(national_id_card_number="ADMIN00000000009",
                            digital_national_id="root9-new")
        long_row = User.objects.create(national_id_card_number="ADMIN000000000009",
                                       digital_national_id="root9-old")
        migration.shorten(apps, None)
        long_row.refresh_from_db()
        self.assertEqual(long_row.national_id_card_number, "ADMIN000000000009")


class SessionRefreshTest(TestCase):
    """While a verification is open the session carries the person's rows
    and face, so it is not rewritten on every request: it is saved when it
    changes, or when the refresh falls due -- which keeps a used session
    alive."""

    def setUp(self):
        self.org = make_org()
        self.user = User.objects.create(national_id_card_number="1111222233334444",
                                        given_name="Ada")
        join(self.org, self.user, Membership.ROLE_ADMIN)
        session = self.client.session
        session[SESSION_KEY] = self.user.id
        session[ORG_SESSION_KEY] = self.org.id
        session["operator_location"] = str(self.org.locations.first().id)
        session.save()

    def _get(self, path="/app/user-records/"):
        with CaptureQueriesContext(connection) as q:
            response = self.client.get(path)
        return response, _session_writes(q.captured_queries)

    def test_settings_no_longer_save_on_every_request(self):
        self.assertFalse(settings.SESSION_SAVE_EVERY_REQUEST)
        self.assertIn("verify.sessions.RefreshSessionMiddleware", settings.MIDDLEWARE)
        self.assertGreater(settings.MIDDLEWARE.index("verify.sessions.RefreshSessionMiddleware"),
                           settings.MIDDLEWARE.index(
                               "django.contrib.sessions.middleware.SessionMiddleware"))

    def test_a_request_that_changes_nothing_writes_nothing(self):
        self._get()                       # stamps the refresh time once
        response, writes = self._get()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(writes, [])

    def test_the_session_carrying_a_face_is_not_rewritten_on_every_read(self):
        session = self.client.session
        verified_answer.keep(session, self.org, [
            {"field": "face_url", "key": "Face Photo",
             "value": "data:image/jpeg;base64," + "A" * 9000, "show": True},
            {"field": "first_name", "key": "Given Name", "value": "Juan",
             "show": True}])
        session.save()
        self._get()
        for path in ("/app/user-records/", "/app/document/", "/app/user-records/"):
            response, writes = self._get(path)
            # The document, not a redirect away from it: a page that is never
            # rendered proves nothing about what reading it writes.
            self.assertEqual(response.status_code, 200, path)
            self.assertEqual(writes, [], path)

    def test_a_used_session_is_refreshed_when_due(self):
        self._get()
        later = time.time() + settings.SESSION_REFRESH_SECONDS + 1
        with patch("verify.sessions.time.time", return_value=later):
            response, writes = self._get()
        self.assertEqual(len(writes), 1)
        self.assertIn(settings.SESSION_COOKIE_NAME, response.cookies)
        row = Session.objects.get(session_key=self.client.session.session_key)
        self.assertGreater(row.expire_date,
                           timezone.now() + timedelta(seconds=settings.SESSION_COOKIE_AGE
                                                      - settings.SESSION_REFRESH_SECONDS - 60))

    def test_an_idle_session_still_ends_no_later_than_before(self):
        self._get()
        row = Session.objects.get(session_key=self.client.session.session_key)
        self.assertLessEqual(row.expire_date,
                             timezone.now() + timedelta(seconds=settings.SESSION_COOKIE_AGE + 5))

    def test_a_stranger_never_gets_a_session_row(self):
        self.client.cookies.clear()
        before = Session.objects.count()
        self.client.get("/")
        self.assertEqual(Session.objects.count(), before)


class ClearExpiredAtSignInTest(TestCase):
    """Expired sessions are cleared at sign-in: a session abandoned
    mid-verification holds the person's rows and face, and nothing else
    runs `clearsessions`."""

    def _session(self, expire):
        store = import_module(settings.SESSION_ENGINE).SessionStore()
        store[verified_answer.KEY] = {
            "organization": 1, "subject": "",
            "rows": [{"field": "face_url", "value": "data:..."}]}
        store.create()
        Session.objects.filter(session_key=store.session_key).update(expire_date=expire)
        return store.session_key

    def test_signing_in_clears_expired_sessions_and_only_those(self):
        expired = self._session(timezone.now() - timedelta(minutes=1))
        live = self._session(timezone.now() + timedelta(hours=1))
        user = User.objects.create(national_id_card_number="1111222233334444")
        request = RequestFactory().post("/everify/")
        request.session = import_module(settings.SESSION_ENGINE).SessionStore()
        _login_session(request, user)
        self.assertFalse(Session.objects.filter(session_key=expired).exists())
        self.assertTrue(Session.objects.filter(session_key=live).exists())

    def test_a_failure_to_tidy_up_never_costs_the_sign_in(self):
        user = User.objects.create(national_id_card_number="1111222233334444")
        request = RequestFactory().post("/everify/")
        request.session = import_module(settings.SESSION_ENGINE).SessionStore()
        store = import_module(settings.SESSION_ENGINE).SessionStore
        with patch.object(store, "clear_expired", side_effect=RuntimeError("down")):
            _login_session(request, user)
        self.assertEqual(request.session[SESSION_KEY], user.id)


class StaticVersionTest(SimpleTestCase):
    """The cache-buster is a digest of the static files, so every worker and
    server stamps the same URLs, and browsers fetch a script again only when
    it changes."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        Path(self.dir, "a.js").write_text("one")
        os.makedirs(os.path.join(self.dir, "sub"))
        Path(self.dir, "sub", "b.css").write_text("two")

    def test_it_is_the_same_for_the_same_files_whenever_it_is_worked_out(self):
        first = static_version([self.dir])
        with patch("time.time", return_value=time.time() + 3600):
            self.assertEqual(static_version([self.dir]), first)

    def test_it_changes_when_any_file_does(self):
        before = static_version([self.dir])
        Path(self.dir, "sub", "b.css").write_text("three")
        self.assertNotEqual(static_version([self.dir]), before)

    def test_it_reads_the_prefixed_form_of_staticfiles_dirs(self):
        self.assertEqual(static_version([("branding", self.dir)]), static_version([self.dir]))

    def test_the_site_stamps_the_digest(self):
        self.assertEqual(settings.APP_VERSION, static_version(settings.STATICFILES_DIRS))


class NginxCompressionTest(SimpleTestCase):
    """One verification's responses are 214 KB as sent and 66 KB compressed;
    on a busy site, data out is the largest line on the bill."""

    def test_the_site_kit_compresses_what_it_sends(self):
        conf = (BASE / "deploy" / "nginx.conf.tftpl").read_text(encoding="utf-8")
        server = conf[conf.index("server {"):]
        code = "\n".join(line for line in server.splitlines()
                         if not line.lstrip().startswith("#"))
        self.assertRegex(code, r"\n\s*gzip on;")
        self.assertRegex(code, r"\n\s*gzip_proxied any;")
        types = next(line for line in code.splitlines() if "gzip_types" in line)
        for kind in ("application/javascript", "application/json", "text/css"):
            self.assertIn(kind, types)


class SealImageTest(SimpleTestCase):
    """The seal prints at 23.5 mm and the phone card draws it at 132 px: big
    enough to print, small enough to send."""

    def test_big_enough_to_print_small_enough_to_send(self):
        import cv2
        path = BASE / "static" / "PSAAuthenticationStamp.png"
        image = cv2.imread(str(path), cv2.IMREAD_UNCHANGED)
        height, width = image.shape[:2]
        self.assertEqual(height, width)
        self.assertGreaterEqual(width, round(23.5 / 25.4 * 600))   # 600 dpi at 23.5 mm
        self.assertLess(path.stat().st_size, 400 * 1024)
