"""What verify may do to credential signing, from its pages.

Pause credential signing, suspend one key, and upload a certificate for a key
the signer generated. For an organization, also: have the signer make its
key and either certify it at once with the Organization CA or hand back its
request for the PKI, and discard such a key before it is published. Each
makes things safer or makes something a person on the signer host must still
publish; resuming, publishing, activating and withdrawing happen on the host.
The one exception is an organization's key where the host's policy sets
`site_publishes_organization_keys`: a site admin publishes it and starts it
signing here, and the signer names that admin in a high alert. Withdrawing
stays on the host.

Where the host's policy sets `site_controls_all_keys` -- an option for a
site whose app servers are replaced at every release -- any site admin, a
designated one included, also publishes and starts the deployment's keys,
unsuspends a key, resumes signing and withdraws any key, here, alone
(`_switcher`, `_controller`). Off, nothing of that is offered or sent, and
only a superuser's own login publishes or starts a key.

Site admins only. Every form posts here and comes back to the page it was on;
`next` is a fixed choice, Setup or one organization's page, never a URL taken
from the POST body.
"""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.utils import dateformat, timezone
from django.views.decorators.http import require_http_methods

from accounts import signer_client
from accounts.models import Organization

from .helpers import _require_login

NOTICE_KEY = "signing_notice"

#: A leaf is about a kilobyte. Anything far past that is not one.
MAX_CERTIFICATE_BYTES = 16 * 1024


def _back(request):
    raw = request.POST.get("next") or ""
    if raw.startswith("org:") and raw[4:].isdigit():
        return redirect("site_organization", org_id=int(raw[4:]))
    return redirect("setup")


def _notice(request, ok, text):
    request.session[NOTICE_KEY] = {"ok": ok, "text": text}


def take_notice(request):
    """The last action's outcome, once, for the page it returned to."""
    return request.session.pop(NOTICE_KEY, None)


def _explain(exc):
    if isinstance(exc, signer_client.Unavailable):
        if exc.reply_lost:
            return ("The signer's answer was lost, so it may have done it. "
                    "Reload this page to see the key as the signer has it.")
        return "The signer did not answer, so nothing changed. Check that cl03-signer is running."
    if exc.reason == "certificate":
        return "The signer refused this certificate: %s." % (exc.detail or "it is not valid")
    if exc.reason == "no_organization_ca":
        return ("This site has no Organization CA, so nothing was generated. "
                "Request a certificate from the PKI instead.")
    if exc.reason == "organization_ca":
        return ("The Organization CA cannot issue now: %s. Request a "
                "certificate from the PKI instead." % (exc.detail or "it is not valid"))
    if exc.reason == "ceiling":
        return ("The signer has made as many keys today as verify may ask for "
                "(%s), so nothing was made. Try again tomorrow." % exc.detail)
    if exc.reason == "gate":
        return ("Some phones that synced this month do not have this key yet, "
                "so it does not sign yet. It can start once they sync, or a "
                "month after it was published.")
    return "The signer refused: %s." % (exc.detail or exc.reason)


def _site_admin(request):
    user, redir = _require_login(request)
    if redir:
        return None, redir
    if not user.is_site_admin:
        return None, redirect("app")
    return user, None


@require_http_methods(["POST"])
def signing_pause(request):
    user, redir = _site_admin(request)
    if redir:
        return redir
    try:
        signer_client.pause("credential", reason="Setup, by %s" % user.display_name)
    except signer_client.SignerError as exc:
        _notice(request, False, _explain(exc))
    else:
        _notice(request, True,
                "Credential signing is paused. Documents print the plain QR "
                "until a site admin resumes it on this page."
                if signer_client.site_controls_all_keys() else
                "Credential signing is paused. Documents print the plain QR "
                "until someone on the signer host runs `cl03signer resume credential`.")
    return _back(request)


@require_http_methods(["POST"])
def signing_suspend(request, key_id):
    user, redir = _site_admin(request)
    if redir:
        return redir
    try:
        signer_client.suspend(key_id, _operator(user))
    except signer_client.SignerError as exc:
        _notice(request, False, _explain(exc))
    else:
        _notice(request, True,
                "Key %d is suspended and signs no more credentials. A site "
                "admin resumes it on this page." % key_id
                if signer_client.site_controls_all_keys() else
                "Key %d is suspended and signs no more credentials. Someone on "
                "the signer host resumes it with `cl03signer unsuspend %d`."
                % (key_id, key_id))
    return _back(request)


def _leaf_der(upload):
    """The one certificate in a PEM or DER file, as DER, or None."""
    raw = upload.read(MAX_CERTIFICATE_BYTES + 1)
    if not raw or len(raw) > MAX_CERTIFICATE_BYTES:
        return None
    try:
        if b"-----BEGIN" in raw:
            certs = x509.load_pem_x509_certificates(raw)
            if len(certs) != 1:
                return None
            return certs[0].public_bytes(serialization.Encoding.DER)
        return x509.load_der_x509_certificate(raw).public_bytes(
            serialization.Encoding.DER)
    except ValueError:
        return None


@require_http_methods(["POST"])
def signing_certificate(request, key_id):
    _, redir = _site_admin(request)
    if redir:
        return redir
    upload = request.FILES.get("certificate")
    leaf = _leaf_der(upload) if upload else None
    if leaf is None:
        _notice(request, False,
                "Choose one certificate file (.pem, .crt or .der) for key %d. "
                "A file holding a whole chain is refused: only the key's own "
                "certificate goes here." % key_id)
        return _back(request)
    try:
        result = signer_client.install_cert(key_id, leaf)
    except signer_client.SignerError as exc:
        _notice(request, False, _explain(exc))
    else:
        _notice(request, True,
                "Key %d is certified and can sign until %s. %s"
                % (key_id, _day(result.get("signing_until")),
                   _publish_step(key_id)))
    return _back(request)


def _publish_step(key_id):
    """What publishing this key takes on this deployment, as one sentence."""
    try:
        public = signer_client.public()
    except signer_client.SignerError:
        public = {}
    key = next((k for k in public.get("keys", []) if k["key_id"] == key_id),
               {})
    if public.get("site_controls_all_keys") or (
            key.get("organization")
            and public.get("site_publishes_organization_keys")):
        return "Publish it on this page when you are ready."
    return ("Someone on the signer host publishes it with `cl03signer publish "
            "%d`, and a second custodian confirms." % key_id)


# -- an organization's own key, from its Site page -------------------------

def _org_page(org):
    return redirect("site_organization", org_id=org.id)


@require_http_methods(["POST"])
def signing_generate(request, org_id):
    _, redir = _site_admin(request)
    if redir:
        return redir
    org = get_object_or_404(Organization, pk=org_id)
    # The name the page showed: a rename since then is not certified unseen.
    if request.POST.get("name") != org.name:
        _notice(request, False,
                "The organization's name changed after this page was shown, "
                "so nothing was made. Check the name and generate again.")
        return _org_page(org)
    try:
        result = signer_client.org_generate(org.signing_id, org.name)
    except signer_client.SignerError as exc:
        _notice(request, False, _explain(exc))
    else:
        _notice(request, True,
                "Key %d is certified by %s as \u201c%s\u201d and can sign until "
                "%s. %s"
                % (result["key_id"], result.get("certified_by") or "the Organization CA",
                   org.name, _day(result.get("signing_until")),
                   _publish_step(result["key_id"])))
    return _org_page(org)


@require_http_methods(["POST"])
def signing_request(request, org_id):
    _, redir = _site_admin(request)
    if redir:
        return redir
    org = get_object_or_404(Organization, pk=org_id)
    try:
        result = signer_client.org_keygen(org.signing_id)
    except signer_client.SignerError as exc:
        _notice(request, False, _explain(exc))
    else:
        _notice(request, True,
                "Key %d is made. Download its request and send it to the PKI "
                "with signing ID %s, then upload the certificate here when it "
                "returns." % (result["key_id"], org.signing_id))
    return _org_page(org)


@require_http_methods(["GET"])
def signing_csr(request, key_id):
    """The request file itself, for the PKI."""
    _, redir = _site_admin(request)
    if redir:
        return redir
    try:
        pem = signer_client.csr(key_id)
    except signer_client.SignerError as exc:
        _notice(request, False, _explain(exc))
        return redirect("setup")
    response = HttpResponse(pem, content_type="application/pkcs10")
    response["Content-Disposition"] = 'attachment; filename="key-%d.csr"' % key_id
    return response


@require_http_methods(["POST"])
def signing_discard(request, key_id):
    _, redir = _site_admin(request)
    if redir:
        return redir
    try:
        signer_client.discard(key_id)
    except signer_client.SignerError as exc:
        _notice(request, False, _explain(exc))
    else:
        _notice(request, True,
                "Key %d is discarded and its private key destroyed." % key_id)
    return _back(request)


def _operator(user):
    """Who the signer's ledger and alert name: a name, and the account."""
    return "%s (user %d)" % (user.display_name, user.pk)


def _switcher(request):
    """(user, refusal) for publishing or starting a key: a site admin through a
    Django superuser's own login. A designated site admin may do everything
    else here, but not put a new certified name on every phone
    (User.switches_signing_keys) -- unless the signer's own policy sets
    `site_controls_all_keys`, which lets any site admin
    (User.may_switch_signing_keys)."""
    user, redir = _site_admin(request)
    if redir:
        return None, redir
    if not (user.switches_signing_keys or user.may_switch_signing_keys(
            signer_client.site_controls_all_keys())):
        _notice(request, False,
                "Publishing or starting a key takes a Django superuser's own "
                "login: sign in at Django admin and come back to this page.")
        return None, _back(request)
    return user, None


def _controller(request):
    """(user, refusal) for withdrawing, unsuspending and resuming from the
    site: only where the signer's policy sets `site_controls_all_keys`, and
    then by any site admin. Otherwise nothing is sent: these are the host's."""
    user, redir = _site_admin(request)
    if redir:
        return None, redir
    # The switch, not who asks: off, a superuser's own login sends nothing
    # either, since these are the host's (two operators for a withdrawal).
    if not (signer_client.site_controls_all_keys()
            and user.may_switch_signing_keys(True)):
        _notice(request, False,
                "This is done on the signer host here: `cl03signer withdraw`, "
                "`unsuspend` or `resume`, with a second operator where it "
                "asks for one.")
        return None, _back(request)
    return user, None


def _key(key_id):
    """The signer's word on one key, from its cached public view, or {}."""
    if not signer_client.enabled():
        return {}
    try:
        keys = signer_client.public().get("keys", [])
    except signer_client.SignerError:
        return {}
    return next((k for k in keys if k["key_id"] == key_id), {})


@require_http_methods(["POST"])
def signing_publish(request, key_id):
    user, redir = _switcher(request)
    if redir:
        return redir
    try:
        signer_client.org_publish(key_id, _operator(user))
    except signer_client.SignerError as exc:
        _notice(request, False, _explain(exc))
    else:
        _notice(request, True,
                "Key %d is published. Phones get it at their next sync; start "
                "it signing once they have it." % key_id)
    return _back(request)


@require_http_methods(["POST"])
def signing_activate(request, key_id):
    user, redir = _switcher(request)
    if redir:
        return redir
    try:
        signer_client.org_activate(key_id, _operator(user))
    except signer_client.SignerError as exc:
        _notice(request, False, _explain(exc))
    else:
        _notice(request, True,
                "Key %d now signs this organization's new documents, and "
                "phones show them as certified." % key_id
                if _key(key_id).get("organization") else
                "Key %d now signs bundles, feeds and statements, and the "
                "documents of organizations without a key of their own. The "
                "key it replaces is retired." % key_id)
    return _back(request)


#: What a site admin may resume, where the policy lets the site.
CONTEXTS = ("credential", "bundle", "revocation", "log-key", "log-ack",
            "sync-time", "all")


@require_http_methods(["POST"])
def signing_withdraw(request, key_id):
    """Withdraw a key, at once and for good, where the signer's policy sets
    `site_controls_all_keys`. The page asks first, naming what stops."""
    user, redir = _controller(request)
    if redir:
        return redir
    deployment = not _key(key_id).get("organization")
    try:
        signer_client.site_withdraw(key_id, _operator(user))
    except signer_client.SignerError as exc:
        _notice(request, False, _explain(exc))
    else:
        _notice(request, True,
                "Key %d is withdrawn. Phones drop it at their next sync and "
                "refuse what it signed. %s"
                % (key_id, "Nothing signs bundles, feeds or statements until "
                   "another deployment key is active, so every phone's sync is "
                   "refused meanwhile." if deployment else
                   "Its organization's documents are signed with the "
                   "deployment key until another of its keys is active."))
    return _back(request)


@require_http_methods(["POST"])
def signing_unsuspend(request, key_id):
    user, redir = _controller(request)
    if redir:
        return redir
    try:
        signer_client.site_unsuspend(key_id, _operator(user))
    except signer_client.SignerError as exc:
        _notice(request, False, _explain(exc))
    else:
        _notice(request, True, "Key %d is resumed and signs again." % key_id)
    return _back(request)


@require_http_methods(["POST"])
def signing_resume(request):
    user, redir = _controller(request)
    if redir:
        return redir
    context = request.POST.get("context") or "credential"
    if context not in CONTEXTS:
        _notice(request, False, "There is no such kind of signing to resume.")
        return _back(request)
    try:
        signer_client.site_resume(context, _operator(user))
    except signer_client.SignerError as exc:
        _notice(request, False, _explain(exc))
    else:
        _notice(request, True,
                "Credential signing is resumed." if context == "credential"
                else "Signing (%s) is resumed." % context)
    return _back(request)


def _day(ts):
    if not ts:
        return "its certificate allows"
    # In the site's time zone, as the page beneath the notice shows dates.
    return dateformat.format(timezone.localtime(datetime.datetime.fromtimestamp(
        int(ts), datetime.timezone.utc)), "j M Y")
