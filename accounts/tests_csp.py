"""The Content-Security-Policy, and the templates that have to live with it.

verify/csp.py lets a page run only this site's scripts, the two pinned
external files, and inline <script> blocks carrying the request's nonce. A
template that breaks the rule does not fail loudly: the browser just refuses
the script and a button stops working. So these check both ends:

  * the source -- no on* attribute or javascript: URL in any template, every
    inline <script> nonced, every external one pinned;
  * the output -- every page a signed-in site admin can open, and Django
    admin's, rendered and read back against the header it was sent with.
"""

import re
from datetime import timedelta
from html.parser import HTMLParser
from pathlib import Path

from django.conf import settings
from django.contrib.auth.models import User as DjangoUser
from django.test import TestCase, override_settings
from django.utils import timezone

from accounts import tests as base_tests
from accounts import verified_answer
from accounts.models import CardHandoff, Membership, SiteSettings, User
from accounts.tests import TEST_SSO_ISSUERS, join, make_org
from verify import csp
from verify.views.helpers import ORG_SESSION_KEY

TEMPLATES = Path(settings.BASE_DIR) / "templates"


class Scripts(HTMLParser):
    """Every <script>, every on* attribute and every javascript: URL."""

    def __init__(self):
        super().__init__()
        self.scripts, self.handlers, self.js_urls = [], [], []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        for name, value in attrs.items():
            if name.startswith("on"):
                self.handlers.append((tag, name, value))
            if name in ("href", "src", "action", "formaction") and value \
                    and value.strip().lower().startswith("javascript:"):
                self.js_urls.append((tag, name, value))
        if tag == "script":
            self.scripts.append(attrs)


def parse(html):
    parser = Scripts()
    parser.feed(html)
    return parser


class PolicyTest(TestCase):

    def test_every_html_page_carries_the_policy_with_a_fresh_nonce(self):
        first = self.client.get("/")
        second = self.client.get("/")
        nonces = []
        for response in (first, second):
            header = response[csp.HEADER]
            nonce = re.search(r"'nonce-([^']+)'", header).group(1)
            self.assertGreaterEqual(len(nonce), 22)
            self.assertEqual(header, csp.policy(nonce))
            nonces.append(nonce)
        self.assertNotEqual(*nonces)

    def test_the_policy_says_what_it_should(self):
        header = csp.policy("abc")
        self.assertIn("script-src 'self' 'nonce-abc' "
                      "https://liveness.everify.gov.ph/js/everify-liveness-sdk.min.js "
                      "https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js",
                      header)
        for directive in ("object-src 'none'", "base-uri 'self'", "frame-ancestors 'none'"):
            self.assertIn(directive, header)
        for absent in ("unsafe-inline", "unsafe-eval", "strict-dynamic", "*"):
            self.assertNotIn(absent, header)

    def test_json_responses_carry_none(self):
        response = self.client.get("/health/")
        self.assertNotIn(csp.HEADER, response)


class TemplateSourceTest(TestCase):
    """What the browser would refuse, found before it gets there."""

    #: An on* attribute however it is quoted or separated (`onerror=x`,
    #: `<svg/onload=...>`), a javascript: URL, and a URL attribute spelled
    #: with numeric character references (`java&#115;cript:`).
    FORBIDDEN = re.compile(
        r"""[\s/"']on[a-z]+\s*=|\bjavascript\s*:"""
        r"""|\b(?:href|src|action|formaction)\s*=\s*["']?[^"'\s>]*&#""", re.I)

    def test_no_template_has_an_inline_handler_or_javascript_url(self):
        offenders = []
        for path in TEMPLATES.rglob("*.html"):
            text = path.read_text(encoding="utf-8")
            # Only markup: what a <script> or <style> holds is not attributes.
            markup = re.sub(r"<(script|style)\b[^>]*>.*?</\1>", "", text, flags=re.S | re.I)
            for match in self.FORBIDDEN.finditer(markup):
                offenders.append(f"{path.relative_to(TEMPLATES)}: {match.group(0)!r}")
        self.assertEqual(offenders, [])

    def test_the_pattern_finds_what_it_must(self):
        for bad in ('<img src=x onerror=alert(1)>', '<svg/onload="x">', "<a href='javascript:x'>",
                    '<a href="java&#115;cript:x">', '<b ONCLICK="x">', '<i\tonmouseover=x>'):
            self.assertTrue(self.FORBIDDEN.search(bad), bad)
        for fine in ('<button data-confirm="Sure?">', '<a href="/a/?x=1&amp;y=2">',
                     '<input name="once">', '<div class="online">'):
            self.assertFalse(self.FORBIDDEN.search(fine), fine)

    def test_autosubmit_is_wired_for_every_kind_of_field_that_uses_it(self):
        """The Setup switch is a checkbox; a select-only listener left it dead."""
        kinds = set()
        for path in TEMPLATES.rglob("*.html"):
            kinds |= {tag.lower() for tag in re.findall(
                r"<(\w+)\b[^>]*\sdata-autosubmit\b", path.read_text(encoding="utf-8"))}
        self.assertTrue(kinds <= {"input", "select"}, kinds)
        self.assertIn("field.matches('[data-autosubmit]')",
                      (TEMPLATES / "base.html").read_text(encoding="utf-8"))

    def test_every_script_tag_is_nonced_or_pinned(self):
        offenders = []
        for path in TEMPLATES.rglob("*.html"):
            text = path.read_text(encoding="utf-8")
            for tag in re.findall(r"<script\b[^>]*>", text):
                src = re.search(r'\ssrc="([^"]*)"', tag)
                if src:
                    url = src.group(1)
                    if not (url.startswith("{% static ") or url in csp.EXTERNAL_SCRIPTS):
                        offenders.append(f"{path.relative_to(TEMPLATES)}: {tag}")
                elif 'nonce="{{ csp_nonce }}"' not in tag:
                    offenders.append(f"{path.relative_to(TEMPLATES)}: {tag}")
        self.assertEqual(offenders, [])


@override_settings(SSO_ALLOWED_ISSUERS=TEST_SSO_ISSUERS)
class RenderedPageTest(TestCase):
    """Every page read back against the header it was sent with."""

    def setUp(self):
        self.org = make_org(name="Alpha", issuer_code="ALP")
        self.admin = User.objects.create(national_id_card_number="1111222233334444",
                                         digital_national_id="ADM1234", given_name="Ada",
                                         is_site_admin=True)
        join(self.org, self.admin, Membership.ROLE_ADMIN)
        join(self.org, User.objects.create(national_id_card_number="5555666677778888"))
        session = self.client.session
        session["verify_user_id"] = self.admin.id
        session[ORG_SESSION_KEY] = self.org.id
        session.save()

    def _check(self, response, url):
        self.assertEqual(response.status_code, 200, url)
        html = response.content.decode()
        nonce = re.search(r"'nonce-([^']+)'", response[csp.HEADER]).group(1)
        found = parse(html)
        self.assertEqual(found.handlers, [], url)
        self.assertEqual(found.js_urls, [], url)
        inline = 0
        for attrs in found.scripts:
            src = attrs.get("src")
            if src:
                same_origin = src.startswith("/") and not src.startswith("//")
                self.assertTrue(same_origin or src in csp.EXTERNAL_SCRIPTS, (url, src))
            elif attrs.get("type") == "application/json":
                continue  # json_script data: never executed
            else:
                inline += 1
                self.assertEqual(attrs.get("nonce"), nonce, url)
        return inline

    def test_every_page_a_site_admin_opens(self):
        session = self.client.session
        verified_answer.keep(session, self.org, base_tests.DemoModeTest.ROWS)
        session.save()
        # The document first: opening /app/ forgets the answer it is made of.
        pages = ["/app/document/", "/app/", "/app/admin/", "/app/site/",
                 f"/app/site/organizations/{self.org.id}/", "/app/site/organizations/new/",
                 "/app/setup/", "/app/devices/", "/choose/", "/validate/"]
        inline = sum(self._check(self.client.get(url), url) for url in pages)
        self.assertGreater(inline, len(pages))  # base.html's own block on every page

    def test_the_signed_out_page(self):
        self.client.session.flush()
        self._check(self.client.get("/"), "/")

    def test_the_sso_sign_in_page(self):
        site = SiteSettings.load()
        site.login_mode = SiteSettings.LOGIN_SSO
        site.sso_issuer, site.sso_client_id, site.sso_client_secret = (
            "https://sso.example/o", "id", "secret")
        site.save()
        self.client.session.flush()
        response = self.client.get("/")
        self.assertIn("login_sso.html", [t.name for t in response.templates])
        self._check(response, "/ (SSO)")

    def test_the_card_hand_off_page(self):
        handoff = CardHandoff.objects.create(
            payload=dict(base_tests.WalletHandoffTest.PAYLOAD),
            expires_at=timezone.now() + timedelta(seconds=300))
        url = f"/card/{handoff.token}/"
        response = self.client.get(url)
        self.assertIn("card.html", [t.name for t in response.templates])
        self._check(response, url)

    @override_settings(DEBUG=True, EVERIFY_DEBUG_CAPTURE=True)
    def test_the_debug_store_pages(self):
        for url in ("/app/setup/", "/debug-cleanup/"):
            response = self.client.get(url)
            self._check(response, url)
        self.assertIn("data-autosubmit", self.client.get("/app/setup/").content.decode())

    def test_django_admins_own_pages(self):
        root = DjangoUser.objects.create_superuser("root", password="x")
        self.client.force_login(root)
        for url in ("/admin/", "/admin/accounts/organization/",
                    f"/admin/accounts/organization/{self.org.id}/change/",
                    f"/admin/accounts/user/{self.admin.id}/change/"):
            self._check(self.client.get(url), url)
