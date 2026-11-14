"""The page layout: signed-in pages take the window, one-task pages do not.

What these pin:

  * a working page is held to no width at all;
  * the pages that are one short task (sign-in, single sign-on, Choose,
    Validate, an operator's Setup, the Verify outcome) keep the centred
    800 px column;
  * the working pages put their cards in a main and a side column, on a wide
    SCREEN only -- never on paper, never on a narrow window, which still
    reads in the order it always did;
  * the document's sheet sits beside its controls without the print path
    noticing, and the records table turns into stacked rows by the width of
    its card, not of the window.

These read the markup and the stylesheet: a source assertion cannot tell how
wide a column came out, only which rule decides it.
"""

import re
from html.parser import HTMLParser

from django.test import TestCase, override_settings

from accounts import sample_data, verified_answer
from accounts.models import (Device, DeviceTicket, Location, Membership,
                             SiteSettings, TransactionType, User)
from accounts.tests import SESSION_KEY, TEST_SSO_ISSUERS, join, make_org
from verify.views.helpers import ORG_SESSION_KEY

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "param", "source", "track", "wbr"}


class _Tree(HTMLParser):
    """Every element's id, classes, ancestors and place in the document.

    Templates close a <p> or an <li> implicitly now and then, so an end tag
    pops back to the element it names rather than trusting the stack."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.elements = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        el = {
            "tag": tag,
            "id": attrs.get("id"),
            "classes": set((attrs.get("class") or "").split()),
            "attrs": attrs,
            "ancestors": list(self.stack),
            "index": len(self.elements),
        }
        self.elements.append(el)
        if tag not in VOID:
            self.stack.append(el)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID and self.stack:
            self.stack.pop()

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i]["tag"] == tag:
                del self.stack[i:]
                return


def _tree(html):
    tree = _Tree()
    tree.feed(html)
    return tree


def _by_id(tree, element_id):
    found = [el for el in tree.elements if el["id"] == element_id]
    assert len(found) == 1, "%d elements with id %r" % (len(found), element_id)
    return found[0]


def _by_class(tree, cls):
    return [el for el in tree.elements if cls in el["classes"]]


def _one(tree, cls):
    found = _by_class(tree, cls)
    assert len(found) == 1, "%d elements with class %r" % (len(found), cls)
    return found[0]


def _inside(el, cls):
    return any(cls in a["classes"] for a in el["ancestors"])


def _outer_container(tree):
    """The page's own .container -- the first, outermost one."""
    for el in tree.elements:
        if "container" in el["classes"]:
            return el
    raise AssertionError("no .container on the page")


def _css(html):
    """Every stylesheet on the page, comments removed.

    A selector named in a comment is not a rule, and prose must never
    satisfy an assertion about the CSS."""
    sheets = re.findall(r"<style[^>]*>(.*?)</style>", html, flags=re.S | re.I)
    return re.sub(r"/\*.*?\*/", " ", "\n".join(sheets), flags=re.S)


def _rules(css, context=()):
    """(context, selector, declarations) for every rule, at-rules as context.

    The context is the chain of @media / @container preludes the rule sits
    in, whitespace normalised -- so "is this rule screen-only" is a question
    about where the rule IS, not about which words appear near it."""
    out = []
    i, n = 0, len(css)
    while i < n:
        j = css.find("{", i)
        if j < 0:
            break
        prelude = " ".join(css[i:j].split())
        depth, k = 1, j + 1
        while k < n and depth:
            if css[k] == "{":
                depth += 1
            elif css[k] == "}":
                depth -= 1
            k += 1
        body = css[j + 1:k - 1]
        if prelude.startswith(("@media", "@container", "@supports")):
            out.extend(_rules(body, context + (prelude,)))
        elif not prelude.startswith("@"):
            decls = {}
            for part in body.split(";"):
                if ":" in part:
                    prop, value = part.split(":", 1)
                    decls[prop.strip()] = " ".join(value.split())
            for selector in prelude.split(","):
                out.append((context, " ".join(selector.split()), decls))
        i = k
    return out


def _decls(css, selector, context=()):
    """The declarations of `selector` in exactly `context`, merged."""
    merged = {}
    for ctx, sel, decls in _rules(css):
        if sel == selector and ctx == context:
            merged.update(decls)
    return merged


def _contexts(css, selector):
    return {ctx for ctx, sel, _ in _rules(css) if sel == selector}


WIDE = "@media screen and (min-width: 1100px)"
DOC_WIDE = "@media screen and (min-width: 1280px)"


class LayoutTestBase(TestCase):
    def setUp(self):
        self.org = make_org("Org One", locations=("Main Office",))
        self.other = make_org("Org Two", locations=("Clinic",))
        TransactionType.objects.create(organization=self.org, name="Medical")
        self.admin = User.objects.create(
            national_id_card_number="1234567890123456",
            digital_national_id="ADM0001", given_name="ADA",
            last_name="ADMIN", is_site_admin=True)
        join(self.org, self.admin, Membership.ROLE_ADMIN)
        self.operator = User.objects.create(
            national_id_card_number="1111222233334444",
            digital_national_id="OPR0001", given_name="OTTO",
            last_name="OPERATOR")
        join(self.org, self.operator)

    def sign_in(self, user):
        session = self.client.session
        session[SESSION_KEY] = user.id
        session[ORG_SESSION_KEY] = self.org.id
        session["operator_location"] = str(
            Location.objects.filter(organization=self.org).first().id)
        session.save()

    def page(self, url):
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, url)
        return response.content.decode()

    def document_page(self):
        self.sign_in(self.admin)
        session = self.client.session
        verified_answer.keep(session, self.org, sample_data.sample_rows(self.org))
        session.save()
        return self.page("/app/document/")


@override_settings(SSO_ALLOWED_ISSUERS=TEST_SSO_ISSUERS)
class PageWidthTest(LayoutTestBase):
    """No limit for the working pages; 800 px for the one-task ones."""

    def test_no_signed_in_page_is_held_to_a_width(self):
        self.sign_in(self.admin)
        css = _css(self.page("/app/"))
        for selector in (".container", "main", ".site-header", ".branding-footer"):
            self.assertNotIn("max-width", _decls(css, selector), selector)
        # Nor anywhere else at the top level of the shared sheet.
        capped = [sel for ctx, sel, d in _rules(css)
                  if not ctx and "max-width" in d
                  and sel in (".container", "main", ".site-header",
                              ".branding-footer", "body")]
        self.assertEqual(capped, [])

    def test_the_narrow_column_is_the_one_it_always_was(self):
        self.sign_in(self.admin)
        css = _css(self.page("/app/"))
        self.assertEqual(
            _decls(css, ".container.container--narrow").get("max-width"), "800px")

    def assertNarrow(self, html, name):
        self.assertIn("container--narrow", _outer_container(_tree(html))["classes"],
                      "%s should keep the centred column" % name)

    def assertWide(self, html, name):
        self.assertNotIn("container--narrow", _outer_container(_tree(html))["classes"],
                         "%s should take the window" % name)

    def test_the_one_task_pages_keep_the_centred_column(self):
        self.assertNarrow(self.page("/"), "sign-in")
        self.sign_in(self.admin)
        self.assertNarrow(self.page("/validate/"), "Validate")
        self.assertNarrow(self.page("/choose/"), "Choose")

    def test_single_sign_on_keeps_the_centred_column(self):
        site = SiteSettings.load()
        site.login_mode = SiteSettings.LOGIN_SSO
        site.sso_issuer = "https://sso.example.test/o"
        site.sso_client_id = "verify"
        site.sso_client_secret = "s3cret"
        site.save()
        html = self.page("/")
        self.assertIn("sso-card", html)
        self.assertNarrow(html, "single sign-on")

    def test_the_working_pages_take_the_window(self):
        self.sign_in(self.admin)
        for url in ("/app/", "/app/admin/", "/app/site/",
                    "/app/site/organizations/%d/" % self.org.id,
                    "/app/site/organizations/new/", "/app/devices/",
                    "/app/setup/"):
            self.assertWide(self.page(url), url)
        self.assertWide(self.document_page(), "/app/document/")

    def test_an_operators_setup_is_a_one_task_page(self):
        """Demo Mode and the fingerprint reader: two short sections, one task,
        the centred column. Not the site admin's version with nothing in its
        second column."""
        self.sign_in(self.operator)
        html = self.page("/app/setup/")
        tree = _tree(html)
        self.assertNarrow(html, "an operator's Setup")
        card = _one(tree, "setup-card")
        self.assertNotIn("setup-card--wide", card["classes"])
        self.assertEqual(_by_class(tree, "page-cols"), [])
        self.assertEqual(_by_class(tree, "page-side"), [])

    def test_the_verify_outcome_is_centred_like_a_one_task_page(self):
        self.sign_in(self.admin)
        css = _css(self.page("/app/"))
        outcome = _decls(css, "#verify-outcome")
        self.assertEqual(outcome.get("max-width"), "800px")
        self.assertEqual(outcome.get("margin-left"), "auto")
        self.assertEqual(outcome.get("margin-right"), "auto")


class TwoColumnTest(LayoutTestBase):
    """Two columns on a wide screen, and nowhere else."""

    def test_the_columns_exist_only_on_a_wide_screen(self):
        self.sign_in(self.admin)
        css = _css(self.page("/app/admin/"))
        # Grid only inside the wide-screen query: a narrow window stacks,
        # and paper never gets a second column.
        self.assertEqual(_contexts(css, ".page-cols"), {(WIDE,)})
        self.assertEqual(_decls(css, ".page-cols", (WIDE,)).get("display"), "grid")
        # Placed by name, so a page can keep its narrow-window order.
        main = _decls(css, ".page-cols > .page-main", (WIDE,))
        side = _decls(css, ".page-cols > .page-side", (WIDE,))
        self.assertEqual((main.get("grid-column"), main.get("grid-row")), ("1", "1"))
        self.assertEqual((side.get("grid-column"), side.get("grid-row")), ("2", "1"))
        # The main column is the wider one.
        cols = _decls(css, ".page-cols", (WIDE,))["grid-template-columns"]
        self.assertEqual(cols, "minmax(0, 1.6fr) minmax(0, 1fr)")

    def test_the_organization_page_keeps_its_narrow_order(self):
        """Settings first in the markup, as a narrow window has always shown
        them; the lists people change daily are the main column."""
        self.sign_in(self.admin)
        tree = _tree(self.page("/app/admin/"))
        side, main = _one(tree, "page-side"), _one(tree, "page-main")
        self.assertLess(side["index"], main["index"])
        for body in ("export-body", "device-log-body", "profile-body",
                     "everify-body", "verification-body"):
            el = _by_id(tree, body)
            self.assertTrue(_inside(el, "page-side"), body)
            self.assertFalse(_inside(el, "page-main"), body)
        for body in ("users-card", "locations-body", "tt-body"):
            el = _by_id(tree, body)
            self.assertTrue(_inside(el, "page-main"), body)
            self.assertFalse(_inside(el, "page-side"), body)
        # Statistics spans the top, in neither column.
        stats = _by_id(tree, "stats-body")
        self.assertFalse(_inside(stats, "page-cols"))

    def test_the_site_page_puts_organizations_beside_the_phones_log(self):
        self.sign_in(self.admin)
        tree = _tree(self.page("/app/site/"))
        self.assertTrue(_inside(_by_id(tree, "device-logs"), "page-side"))
        tables = _by_class(tree, "org-table")
        self.assertTrue(tables)
        self.assertTrue(all(_inside(t, "page-main") for t in tables))

    def test_the_verify_steps_sit_side_by_side(self):
        self.sign_in(self.admin)
        html = self.page("/app/")
        tree = _tree(html)
        steps = _by_id(tree, "verify-steps")
        self.assertIn("page-cols", steps["classes"])
        children = [el for el in tree.elements
                    if el["ancestors"] and el["ancestors"][-1] is steps]
        self.assertEqual(len([c for c in children if "card" in c["classes"]]), 2)
        self.assertIn("minmax(0, 1.25fr) minmax(0, 1fr)",
                      _decls(_css(html), "#verify-steps.page-cols", (WIDE,))
                      .get("grid-template-columns", ""))

    def test_a_site_admins_setup_splits_their_settings_from_the_sites(self):
        self.sign_in(self.admin)
        html = self.page("/app/setup/")
        tree = _tree(html)
        self.assertIn("setup-card--wide", _one(tree, "setup-card")["classes"])
        cols = _one(tree, "page-cols")
        self.assertIn("page-cols--even", cols["classes"])
        css = _css(html)
        self.assertEqual(_decls(css, ".setup-card.setup-card--wide").get("max-width"), "none")
        # Their own settings left, the site's right -- found by heading.
        main, side = _one(tree, "page-main"), _one(tree, "page-side")
        self.assertLess(main["index"], side["index"])
        self.assertTrue(_inside(main, "page-cols") and _inside(side, "page-cols"))
        text = html[html.index('class="page-side"'):]
        self.assertIn("Site Administration", text)
        self.assertIn("Sign-in eVerify client", text)
        self.assertNotIn("User Settings", text)


class DeviceColumnsTest(LayoutTestBase):
    def test_pairing_is_a_card_of_its_own_beside_the_list(self):
        self.sign_in(self.admin)
        self.client.post("/app/devices/ticket/", {"purpose": "enrol",
                                                  "label": "Desk iPad"})
        html = self.page("/app/devices/")
        tree = _tree(html)
        panel = _one(tree, "pair-panel")
        listing = _one(tree, "device-list")
        pairing = _one(tree, "pair-card")
        # The order a narrow window has always shown: the code, the list,
        # then the form.
        self.assertLess(panel["index"], listing["index"])
        self.assertLess(listing["index"], pairing["index"])
        # The form is the pairing form, in a card of its own.
        button = _one(tree, "btn-pair")
        self.assertTrue(_inside(button, "pair-card"))
        self.assertFalse(_inside(button, "device-list"))
        enrol = [el for el in tree.elements if el["tag"] == "input"
                 and el["attrs"].get("value") == "enrol"]
        self.assertTrue(enrol and all(_inside(el, "pair-card") for el in enrol))
        # Placed by name: the list down the left, the code and the form
        # stacked on the right, with the form taking the flexible row.
        css = _css(html)
        self.assertEqual(_decls(css, ".device-cols", (WIDE,)).get("grid-template-rows"),
                         "auto 1fr")
        self.assertEqual(_decls(css, ".device-cols > .device-list", (WIDE,)).get("grid-row"),
                         "1 / span 2")
        self.assertEqual(_decls(css, ".device-cols > .pair-panel", (WIDE,)).get("grid-column"), "2")
        self.assertEqual(_decls(css, ".device-cols > .pair-card", (WIDE,)).get("grid-row"), "2")
        self.assertEqual(_contexts(css, ".device-cols"), {(WIDE,)})


class SiteOrganizationColumnsTest(LayoutTestBase):
    def test_the_cards_keep_their_order_and_are_placed_by_name(self):
        self.sign_in(self.admin)
        html = self.page("/app/site/organizations/%d/" % self.org.id)
        tree = _tree(html)
        order = [_one(tree, cls)["index"] for cls in
                 ("org-cols-form", "org-cols-people", "org-cols-fields",
                  "org-cols-lists")]
        self.assertEqual(order, sorted(order))
        for cls in ("org-cols-form", "org-cols-people", "org-cols-fields",
                    "org-cols-lists"):
            self.assertTrue(_inside(_one(tree, cls), "org-cols"), cls)
        css = _css(html)
        self.assertEqual(_contexts(css, ".org-cols"), {(WIDE,)})
        self.assertEqual(_decls(css, ".org-cols", (WIDE,)).get("grid-template-rows"),
                         "auto 1fr auto")
        place = lambda cls: _decls(css, ".org-cols > ." + cls, (WIDE,))
        self.assertEqual(place("org-cols-form").get("grid-row"), "1 / span 2")
        self.assertEqual((place("org-cols-people").get("grid-column"),
                          place("org-cols-people").get("grid-row")), ("2", "1"))
        # Lists directly under People, in the flexible row the form's extra
        # height goes into.
        self.assertEqual((place("org-cols-lists").get("grid-column"),
                          place("org-cols-lists").get("grid-row")), ("2", "2"))
        # The field editor across the whole width below both.
        self.assertEqual(place("org-cols-fields").get("grid-column"), "1 / -1")
        self.assertEqual(place("org-cols-fields").get("grid-row"), "3")

    def test_a_new_organizations_form_lands_where_it_will_be(self):
        self.sign_in(self.admin)
        tree = _tree(self.page("/app/site/organizations/new/"))
        self.assertTrue(_inside(_one(tree, "org-cols-form"), "org-cols"))
        self.assertEqual(_by_class(tree, "org-cols-people"), [])


class DocumentColumnsTest(LayoutTestBase):
    """The sheet beside its controls, without the print path noticing."""

    def test_the_controls_come_first_and_sit_beside_the_sheet(self):
        html = self.document_page()
        tree = _tree(html)
        side, stage = _one(tree, "doc-side"), _one(tree, "doc-stage")
        # First in the markup: a narrow window reads them above the sheet.
        self.assertLess(side["index"], stage["index"])
        self.assertTrue(_inside(side, "doc-layout") and _inside(stage, "doc-layout"))
        for element_id in ("pre-log-controls", "post-log-controls",
                           "doc-status", "user-records"):
            self.assertTrue(_inside(_by_id(tree, element_id), "doc-side"), element_id)
        # And nothing of the sheet is in the side column.
        page = _by_id(tree, "doc-page")
        self.assertTrue(_inside(page, "doc-stage"))
        self.assertFalse(_inside(page, "doc-side"))

    def test_the_columns_are_screen_only(self):
        css = _css(self.document_page())
        self.assertEqual(_contexts(css, ".doc-layout"), {(DOC_WIDE,)})
        layout = _decls(css, ".doc-layout", (DOC_WIDE,))
        self.assertEqual(layout.get("display"), "grid")
        # The sheet's column is exactly as wide as the paper.
        self.assertEqual(layout.get("grid-template-columns"),
                         "max-content minmax(0, 1fr)")
        side = _decls(css, ".doc-layout > .doc-side", (DOC_WIDE,))
        self.assertEqual((side.get("grid-column"), side.get("grid-row")), ("2", "1"))
        self.assertEqual(side.get("position"), "sticky")
        stage = _decls(css, ".doc-layout > .doc-stage", (DOC_WIDE,))
        self.assertEqual((stage.get("grid-column"), stage.get("grid-row")), ("1", "1"))
        # Nothing about the layout reaches paper: the print block is the one
        # place a rule could change what the fitter measured.
        for ctx, sel, _ in _rules(css):
            if any("print" in c for c in ctx):
                self.assertNotIn("doc-layout", sel)
                self.assertNotIn("doc-side", sel)

    def test_the_records_table_follows_the_width_of_its_card(self):
        """Beside the sheet the window is wide and the card is not; a
        four-column table there would run its last column out of the card."""
        css = _css(self.document_page())
        self.assertEqual(_decls(css, ".user-records").get("container"), "ur / inline-size")
        query = "@container ur (max-width: 560px)"
        self.assertEqual(_decls(css, ".ur-table thead", (query,)).get("display"), "none")
        self.assertEqual(_decls(css, ".ur-stats", (query,)).get("grid-template-columns"),
                         "repeat(2, minmax(0, 1fr))")
        # Not the window: no viewport query decides the stacked rows.
        self.assertEqual(_contexts(css, ".ur-table thead"), {(query,)})
