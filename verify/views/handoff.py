"""The card hand-off: a finished verification, on the holder's own phone.

The document page draws a QR beside Print Document. The holder scans it with
an ordinary camera, and `/card/<token>/` draws the portrait card and offers to
save it to Photos. Nothing is typed, nothing is signed in, and the link stops
working when the operator leaves the document.

**Read `accounts.models.CardHandoff` before changing anything here.** The
token is the whole authorisation -- the phone has no account and cannot get
one -- so the controls are its unguessability, its five minutes, and the
release on the way out. This is the only endpoint in the app that serves an
identity without a session.

Three rules it inherits rather than invents:

**The organization comes from the session.** It is resolved when the hand-off
is opened, by the view that already has a session, and stored. The phone is
never asked which organization it is fetching for -- the same shape as every
organization-scoped view, one level further out.

**Demo Mode is decided from the operator, on the server.** `open_handoff()`
is handed rows that are already masked and a face that is already resampled,
by the same call that mints the credential. There is no flag in the request
that could switch it off, because the browser composing that request is the
one being masked.

**Nothing about the card comes from the caller.** The phone POSTs nothing and
GETs one row by its token. `release()` is the single exception and it can only
destroy.
"""

from __future__ import annotations

import logging

from django.conf import settings
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from accounts import everify_fields, wallet_pass
from accounts.models import CardHandoff, IssuedCredential

logger = logging.getLogger(__name__)


#: What the card prints beside the two symbols, matched on eVerify's OWN keys.
#: Never the label: the label is editable per organization and a rename must
#: not silently blank the card -- the same rule `_card_holder()` follows.
NAME_FIELDS = ("first_name", "middle_name", "last_name")
CARD_NUMBER_FIELD = "reference"
DIGITAL_ID_FIELD = "code"


def _values(rows):
    """eVerify key -> value, for the rows the organization DISPLAYS."""
    values = {}
    for row in rows or ():
        field = everify_fields.field_of(row)
        if field:
            values[field] = row.get("value")
    return values


def holder_from_rows(rows):
    """Who the rows describe: one name, and the two ID numbers.

    Lives here, beside the keys it matches on, because it now has TWO
    consumers -- the card the holder saves to their phone, and the
    certificate the document prints. A person holding the paper beside the
    card on their phone is exactly who would notice the two disagreeing, so
    they are not allowed to: there is one answer to "who is this" and both
    read it from here.

    The name is joined as ONE string on purpose. Demo Mode's `mask_name`
    keeps the first word, so masking given, middle and last separately would
    keep all three whole and redact nothing.

    `label` is the organization's own display text and is what gets PRINTED;
    the selection above is by eVerify's own key, which is the rule the whole
    field configuration rests on -- renaming a field must not blank the card.
    """
    values = _values(rows)
    labels = {}
    for row in rows or ():
        field = everify_fields.field_of(row)
        if field:
            labels[field] = row.get("key") or field

    name = " ".join(
        str(values.get(part) or "").strip() for part in NAME_FIELDS)
    numbers = []
    for field in (CARD_NUMBER_FIELD, DIGITAL_ID_FIELD):
        value = str(values.get(field) or "").strip()
        if value:
            numbers.append({"label": labels.get(field, field), "value": value})
    return {
        "name": " ".join(name.split()),
        "card_number": str(values.get(CARD_NUMBER_FIELD) or ""),
        "digital_id": str(values.get(DIGITAL_ID_FIELD) or ""),
        "numbers": numbers,
    }


#: Everything `holder_from_rows()` speaks for. The document lifts exactly
#: these out of its field list so they are not printed twice -- once in the
#: certificate and again as rows underneath it.
HOLDER_FIELDS = NAME_FIELDS + (CARD_NUMBER_FIELD, DIGITAL_ID_FIELD)

#: The portrait. Not part of the holder block above because its value is an
#: image rather than text, but lifted out of the field list for the same
#: reason: the certificate prints it, so the rows must not.
FACE_FIELD = "face_url"


def payload_from_rows(rows, *, organization, transaction_type, location_name,
                      verified_at, transaction_id, qr, portrait_qr,
                      face_data_uri, expires_on=""):
    """Everything the card draws, and nothing else.

    Deliberately flat and already-decided: the phone page composes no business
    logic, it draws what it is given. Which fields, whose organization and
    whether to mask were all settled by the caller, which had a session to
    settle them with.

    `rows` are the DISPLAY rows -- already narrowed to what this organization
    shows, and already demo-masked when the operator is presenting.
    """
    holder = holder_from_rows(rows)
    return {
        "organization": organization,
        "holder": holder["name"],
        "card_number": holder["card_number"],
        "digital_id": holder["digital_id"],
        "transaction_type": transaction_type,
        "location": location_name,
        "verified_at": verified_at,
        # `expires_on_text()` of the date signed into the credential. Empty on a
        # card stored before cards printed one, and the renderer then draws the
        # header without it.
        "expires_on": expires_on,
        "transaction_id": transaction_id,
        "qr": qr,
        "portrait_qr": portrait_qr or "",
        "face": face_data_uri or "",
    }


def holder_card(txn):
    """A holder's card: `payload_from_rows()` for a self-verification.

    Composed from the STORED transaction and never from the phone. The rows
    are what was logged, which is exactly what the credential carries
    (`accounts.holders.credential_rows`). The organization line is the
    issuer the credential names, recorded on the transaction when it was
    minted; there is no location, because a self-verification happened
    nowhere in particular, and the card draws its usual dash.

    No symbols and no face. The phone already holds both symbols, and draws
    the face from the portrait symbol -- the image the document's card draws
    too, which is `portrait_data_uri` there. Used twice: in the registration
    response, for the picture the phone draws, and for the Wallet passes.
    """
    rows = [{"field": field,
             "key": everify_fields.DEFAULT_NAMES.get(field) or field,
             "value": value}
            for field, value in (txn.logged_fields or {}).items()]
    expires = (IssuedCredential.objects.filter(transaction=txn)
               .order_by("-issued_at").values_list("expires_at", flat=True).first())
    card = payload_from_rows(
        rows,
        organization=txn.operator_location or "",
        transaction_type=txn.transaction_type or "",
        location_name="",
        verified_at=verified_at_text(txn.verification_timestamp),
        expires_on=expires_on_text(expires) if expires else "",
        transaction_id=str(txn.transaction_id),
        qr="", portrait_qr="", face_data_uri="")
    for symbol in ("qr", "portrait_qr", "face"):
        del card[symbol]
    return card


def verified_at_text(when):
    """How a card spells the moment of verification, in this site's zone.

    One spelling, because there are now two cards: the document's, and the
    one a holder's phone draws from what `accounts.holders.card_for()`
    sends it. Side by side they must read alike.
    """
    return when.astimezone(timezone.get_current_timezone()).strftime(
        "%b %d %Y %I:%M %p")


def expires_on_text(when):
    """How a card spells the day its credential expires: the date of
    `verified_at_text()`, so the two read alike side by side. The date and not
    the moment, because a holder plans by the day."""
    return when.astimezone(timezone.get_current_timezone()).strftime("%b %d %Y")


def open_handoff(payload):
    """Store one card and return its row, or None.

    NEVER raises, the rule `_mint_credential()` follows and for the same
    reason: a verification that was performed and logged must not be lost
    because the convenience hanging off it could not be written.
    """
    try:
        purge_expired()
        return CardHandoff.objects.create(
            payload=payload,
            expires_at=timezone.now() + timezone.timedelta(
                seconds=settings.CARD_HANDOFF_TTL_SECONDS))
    except Exception:
        logger.exception("could not open a card hand-off")
        return None


def purge_expired():
    """Drop hand-offs nobody collected.

    On every open rather than on a timer. This table is a hand-off, not a
    record -- `login_attempts` is the audit trail and is deliberately aged out
    by hand, because how long to keep it is a policy call. How long to keep an
    uncollected card is not: past its expiry it can never be served again, so
    holding the identity in it buys nothing at all.
    """
    CardHandoff.objects.filter(expires_at__lte=timezone.now()).delete()


def resolve(token):
    """The live hand-off for this token, or None.

    Expired, released and never-existed are one answer, exactly as
    `devices.TICKET_REFUSED` is one answer: telling them apart tells somebody
    feeding in guesses which ones were real.
    """
    row = CardHandoff.objects.filter(token=token).first()
    if row is None:
        return None
    if row.expires_at <= timezone.now():
        row.delete()
        return None
    return row


# ---------------------------------------------------------------------------
# The two endpoints
# ---------------------------------------------------------------------------


@require_http_methods(["GET"])
def card_handoff(request, token):
    """The portrait card, for the phone that scanned the QR.

    404 for anything that is not a live hand-off -- and 404 rather than a
    redirect to the login page, because this caller has no account to sign in
    to and never will.
    """
    row = resolve(token)
    if row is None:
        raise Http404

    # Whether to draw the Add to Apple Wallet button is decided HERE, not by
    # the page: an unconfigured deployment shows no button rather than one
    # that fails when pressed. The platform half of the decision is the
    # page's, because only the browser knows what it is.
    response = render(request, "card.html", {
        "card": row.payload,
        "wallet_url": (reverse("card_handoff_pass", args=[token])
                       if wallet_pass.configured() and row.payload.get("qr")
                       else ""),
    })
    # It is an identity, on a link that is about to stop working. Nothing in
    # between should keep a copy, and nothing should index it.
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response["Pragma"] = "no-cache"
    response["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    response["Referrer-Policy"] = "no-referrer"
    return response


@require_http_methods(["GET"])
def card_handoff_pass(request, token):
    """The same card as ONE Apple Wallet pass: the credential, and the face.

    Nothing here is a second decision about the verification: the pass is
    built from the hand-off's **stored** payload, so which fields it shows,
    whose organization it names and whether it is masked were all settled by
    the request that had a session. See `wallet_pass.from_handoff()`.

    Same token, same five minutes, same single refusal for expired, released
    and never-existed. **What the TTL protects is the fetch** -- a pass, once
    added, sits in the holder's wallet indefinitely, which is the one way
    this differs from the photo the card page offers.

    404 rather than a 503 when a pass cannot be built. The card page has
    already decided whether to offer one, so a request arriving here for an
    unconfigured deployment is not a caller to explain anything to.
    """
    row = resolve(token)
    if row is None:
        raise Http404

    built = wallet_pass.from_handoff(row.payload)
    if built is None:
        raise Http404

    # One `.pkpass`, the pass a holder's idmanager adds -- see
    # `wallet_pass.card_pass()`.
    blob, content_type, filename = built
    response = HttpResponse(blob, content_type=content_type)
    response["Content-Disposition"] = 'attachment; filename="%s"' % filename
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    response["Referrer-Policy"] = "no-referrer"
    return response


@csrf_exempt
@require_http_methods(["POST"])
def card_handoff_release(request, token):
    """Drop the hand-off. Called by `pagehide` on the document page.

    **`csrf_exempt`, and that is not a shortcut.** `navigator.sendBeacon()`
    cannot set a CSRF header -- it is what still fires when a tab is closing,
    which is exactly the moment this has to work. What the exemption exposes
    is a cross-site caller DESTROYING a hand-off it already knows the token
    of; the token is the only thing that identifies the row, and anyone
    holding it could simply fetch the card instead. The dangerous direction
    is opening one, and that needs a session and a logged transaction.

    Always 200. A token that is already gone is the outcome asked for.
    """
    CardHandoff.objects.filter(token=token).delete()
    return JsonResponse({"status": "ok"})
