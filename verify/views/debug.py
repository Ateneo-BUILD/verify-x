"""The dev store's own pages: what is kept, the button that empties it, and
a synthetic document to look at.

Both exist ONLY where `debug_store.debug_allowed()` is true. Everywhere else
this is a 404, not a "forbidden": a page that refuses politely still tells
anyone who asks that a store of identity records is a thing this deployment
has. Production has neither opt-in, so the URLs simply are not there.

The store is also listed, switched and emptied from `/app/setup/`, which
posts here -- so there is one implementation of each of those however you
arrived at it.

The page is also where the sizing question gets answered -- for each captured
face and demographic record it reports what the two symbols on the card come
out at, which is the whole reason the store exists. Measuring is why the data
is kept; emptying it afterwards is why this page has a button.
"""

from django.http import Http404
from django.shortcuts import redirect, render
from django.views.decorators.http import require_http_methods

from accounts import credentials, debug_store, sample_data, verified_answer
from accounts.models import DebugCapture, SiteSettings

from . import core
from .helpers import _require_context, _require_login


def _gate(request):
    """Dev store open, and a site admin asking. Returns the user, or 404s.

    Two checks, and neither replaces the other: the gate decides whether this
    deployment has such a store at all, the session decides whether this
    person may look at real people's faces. A development instance is
    still a site with real records on it.

    **Every refusal is the same 404, including "you are not signed in".** The
    ordinary bounce to the login page would answer "does this deployment keep
    identity records?" for anyone who asked, which is the question the 404
    exists to leave unanswered -- and it would answer it on the one deployment
    where the answer is yes. A site admin signs in first and comes back.
    """
    if not debug_store.debug_allowed():
        raise Http404
    user, redir = _require_login(request)
    if redir or user is None or not user.is_site_admin:
        raise Http404
    return user


def _requested_capture(request):
    """The stored response `?capture=` names, or None.

    One resolver, because the sample document and the sample validation page
    ask the same question and two rules have to hold identically on both:

    **Successes only.** A failure row holds an upstream error body, not a
    person; filling either page from one would render a validated record with
    nobody in it.

    **Parsed before it is queried.** `pk` is an integer column, so filtering
    it by junk raises rather than matching nothing -- the lesson
    `POST /api/v1/device/keys/` learned by answering a 500. Junk, a failure,
    and a row that does not exist all resolve to the same None.

    **Demo Mode does NOT substitute.** Falling back to the synthetic person
    here, on the reasoning that a real name on a projector is the same
    question as the faces the store's own table hides, would be wrong twice.
    Demo Mode's rule everywhere else in this app is that it **masks what is
    rendered** -- it never changes WHICH record is rendered, and a page that
    quietly answers about a different person than the row you clicked is not
    redacted, it is wrong. And it would not even be consistent with the page
    it fills: `/validate/` renders a real scanned transaction in the clear
    whether or not Demo Mode is on.

    So the capture is always retrieved. The document then masks it exactly as
    it masks a real verification -- same `apply_demo_mask()`, same blurred
    face -- and the validation page renders it as it renders any other
    transaction. Turning Demo Mode off is what shows it in the clear, which is
    what that switch is for.
    """
    wanted = (request.GET.get("capture") or "").strip()
    if not wanted.isdigit():
        return None
    return DebugCapture.objects.filter(
        pk=int(wanted), outcome=DebugCapture.OUTCOME_SUCCESS).first()


@require_http_methods(["GET", "POST"])
def debug_cleanup(request):
    """See what the store holds; POST to empty it, or to pause it.

    Both buttons on the Setup page post here as well, so there is one
    implementation of emptying the store and one of pausing it however you
    arrived. `next` is a fixed choice of two pages rather than a URL, because
    a redirect target taken from a POST body is a redirect to anywhere.
    """
    _gate(request)

    purged = None
    if request.method == "POST":
        back = ("setup" if request.POST.get("next") == "setup"
                else "debug_cleanup")
        if request.POST.get("scope") == "one":
            # One row rather than the lot. The store is a scratch pad and a
            # study usually wants a handful of what it has; the alternative
            # to dropping one is dropping all of them and running the
            # lookups again. `purge_one()` parses the id before it queries,
            # so a hand-made POST carrying junk deletes nothing and 500s on
            # nothing.
            purged = debug_store.purge_one(request.POST.get("capture"))
            request.session["debug_purged"] = purged
            return redirect(back)
        if request.POST.get("scope") == "switch":
            # An unchecked checkbox is absent from the POST, so absence is
            # off -- the same reading Setup gives Demo Mode.
            site = SiteSettings.load()
            site.debug_capture_enabled = bool(request.POST.get("enabled"))
            site.save()
            return redirect(back)
        # "photos" is the softer option, exactly as purge_login_attempts has:
        # keep what the fields were, drop the faces.
        purged = debug_store.purge(
            photos_only=request.POST.get("scope") == "photos")
        request.session["debug_purged"] = purged
        return redirect(back)

    purged = request.session.pop("debug_purged", None)

    rows = []
    # The sizing table is about what a document costs, so it is the
    # successes. The counts above still say how many failures there were,
    # and the Setup page lists them with what the upstream said.
    for capture in DebugCapture.objects.filter(
            outcome=DebugCapture.OUTCOME_SUCCESS)[:200]:
        portrait = debug_store.measure_portrait(capture.photo_data)
        rows.append({
            "capture": capture,
            "portrait": portrait,
            "credential": debug_store.measure_credential(
                capture.payload, organization=capture.organization),
        })

    context = {
        "rows": rows,
        "purged": purged,
        "stamp_mm": credentials.STAMP_MM,
        "portrait_stamp_mm": credentials.PORTRAIT_STAMP_MM,
        "portrait_px": credentials.PORTRAIT_PX,
    }
    context.update(debug_store.store_summary())
    # demo_mode and session_display_name arrive from the context
    # processor, so nothing here has to remember them.
    return render(request, "debug_cleanup.html", context)


def debug_sample(request):
    """Put the synthetic person in the session and open their document.

    The point is to look at a finished document -- the two symbols, the
    density tier, a field just switched on, the demo redaction -- without a
    real person having been verified to produce one. `sample_data` builds the
    rows through THIS organization's field configuration, so what appears is
    what this organization would print.

    **Nothing about the identity comes from the request**, and there is
    nothing here a caller could put there: the values are constants and the
    face is drawn. That is the difference between this and
    `_mock_everify_data()`, which echoes the caller's own POST body back as a
    verified identity and needs two opt-ins for exactly that reason.

    `?capture=<id>` renders a stored response instead of the synthetic person
    -- the document half of what `?capture=` already did for the validation
    page, and the whole reason the store keeps whole responses rather than the
    prepared rows. It is the same rule one level along: the values come from
    the store and all the request chose was which stored row to open. The face
    comes back out of `photo_data`, where `capture()` put it, and goes back
    under `face_url`, where a real payload carries it.

    The rows are still built through THIS organization's field list rather
    than the capturing organization's, so what a stored response shows is what
    this deployment would print of it -- which is the question a document view
    is being opened to answer.

    Opening it logs nothing and mints nothing. **Pressing Log Transaction on
    it does both**, exactly as it would for a real verification -- which is
    deliberate, because the two QR symbols only exist after a mint and they
    are most of what a sample is worth looking at. The cost is a transaction
    row for somebody who does not exist, in that organization's log and its
    export. That is bounded by the gate above: this page cannot exist on a
    deployment without both debug opt-ins, so the row can only ever land in a
    development database.

    It is also the ONE place that keeps an answer eVerify did not give
    (accounts/verified_answer.py): the log signs whatever is kept, so a
    sample document can be logged only where that gate is open. It keeps no
    User Records subject -- the sample person has no history, and must not
    inherit the last real person's.
    """
    _gate(request)
    _user, org, redir = _require_context(request)
    if redir:
        return redir

    capture = _requested_capture(request)
    values = None
    if capture is not None:
        values = dict(capture.payload or {})
        # `capture()` drops `face_url` -- it is a signed URL that expires --
        # and keeps the bytes it pointed at in a column of its own. Putting
        # them back under that key is what makes a stored response the same
        # shape as a live one, so the row builder needs no branch for it.
        if capture.photo_data:
            values["face_url"] = capture.photo_data
    # `?face=drawn` swaps the chosen portrait for the drawn stand-in,
    # which is the one that compresses like skin. Looking at a document
    # wants the portrait; measuring one wants the stand-in. A stored
    # response brings its own face and neither stand-in applies.
    verified_answer.keep(
        request.session, org,
        sample_data.sample_rows(
            org, drawn_face=request.GET.get("face") == "drawn", values=values),
        subject="")
    return redirect("document")


def debug_sample_validate(request):
    """The Validate page, filled, without a transaction having been logged.

    The Validate page renders whatever `/api/validate/<uuid>/` returns, so
    seeing it full normally means verifying somebody and logging them first.
    This fills it in the browser instead.

    **The API is not taught to vouch for it, and that is the point.** An
    endpoint whose entire job is "this record exists" must not have a mode
    where it says so about a record that does not -- it is unauthenticated,
    it is what a printed QR resolves to, and a third party checking a document
    is exactly who would be misled. So the sample id is a real UUID that
    resolves to **nothing**, the page says on its face that it is a sample,
    and only this page is filled.

    The rows are built by handing an UNSAVED `Transaction` to the same
    `transaction_payload()` the real endpoint uses, so this is a sample of the
    page that exists rather than of one spelled slightly differently.

    `?capture=<id>` fills it from a stored response instead of the synthetic
    person -- the whole reason the store keeps whole responses is to have real
    values to look at. **Demo Mode does not change which record that is**; see
    `_requested_capture()`. This page renders a real scanned transaction in
    the clear whether Demo Mode is on or off, and a stored response is now
    treated the same way, rather than being swapped for somebody else.
    """
    user = _gate(request)
    _user, org, redir = _require_context(request)
    if redir:
        return redir

    capture = _requested_capture(request)

    txn = sample_data.sample_transaction(
        capture.payload if capture else None,
        organization=org, operator=user,
        when=capture.created_at if capture else None,
        source="capture:%d" % capture.pk if capture else "sample")

    return render(request, "validate.html", {
        "user": user,
        "prefill": {"transaction": core.transaction_payload(txn),
                    "transaction_id": str(txn.transaction_id)},
        # What the page says it is showing. A filled Validate page that did
        # not say would be indistinguishable from a real check.
        "prefill_source": ("capture #%d, kept on this instance" % capture.pk
                           if capture else "a synthetic person"),
    })
