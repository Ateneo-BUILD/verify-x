"""Single sign-on -- an OpenID Connect client and the SSO login route.

The provider a site administrator names runs the eVerify National ID +
liveness check on its side and returns `pcn` (16-digit National ID card
number) and `digital_id` claims. This module never talks to eVerify directly.

Ported from wallet/wallet/oidc.py, which was itself ported from tasktracker:
standard library only (urllib / secrets / hashlib / base64 / json), so SSO
adds no dependency to requirements.txt. Two things differ from wallet:

  * credentials come from the SiteSettings row, not from Django settings,
    because they are administered from the Setup page;
  * a verified identity that matches no registered operator gets NO session
    and NO account. wallet auto-provisions; verify must not.
"""

import base64
import hashlib
import json
import logging
import secrets
import urllib.error
import urllib.parse
import urllib.request

from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods

from accounts import sso_issuer
from accounts.models import SiteSettings
from .core import _sso_page_context
from .helpers import _find_user, _login_session

logger = logging.getLogger(__name__)

SCOPES = "openid profile email pcn digital_id"

STATE_KEY = "sso_state"
VERIFIER_KEY = "sso_verifier"

_DISCOVERY_CACHE = {}


class SsoAuthError(Exception):
    """The OIDC exchange failed or returned something untrustworthy."""


# --------------------------------------------------------------- primitives
# Thin network wrappers, kept separate so tests can patch them.

def _read_json(req):  # pragma: no cover - network primitive
    # urlopen raises HTTPError on 4xx/5xx and the body carries the OAuth
    # error_description, so surface that rather than a bare status code.
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"HTTP {exc.code} from {req.full_url}: {detail}")


def _post_form(url, data):  # pragma: no cover - network primitive
    body = urllib.parse.urlencode(data).encode()
    return _read_json(urllib.request.Request(url, data=body, method="POST"))


def _get_bearer(url, token):  # pragma: no cover - network primitive
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", "Bearer " + token)
    return _read_json(req)


def _fetch_discovery(url):  # pragma: no cover - network primitive
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


# --------------------------------------------------------------- OIDC flow

def discovery(issuer):
    """The provider's discovery document, fetched once per issuer."""
    issuer = (issuer or "").rstrip("/")
    if issuer not in _DISCOVERY_CACHE:
        _DISCOVERY_CACHE[issuer] = _fetch_discovery(
            issuer + "/.well-known/openid-configuration/")
    return _DISCOVERY_CACHE[issuer]


def pkce_pair():
    """A PKCE (verifier, S256 challenge) pair -- the provider mandates PKCE."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _allowed_issuer(site):
    """The site's issuer, only if this server allows it. The routes already
    see SSO as not configured otherwise; this is the second check, where
    the network is."""
    if not sso_issuer.allowed(site.sso_issuer):
        raise SsoAuthError("The SSO issuer is not one this server allows.")
    return site.sso_issuer


def auth_url(site, redirect_uri, state, code_challenge):
    issuer = _allowed_issuer(site)
    params = {
        "client_id": site.sso_client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": SCOPES,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    endpoint = discovery(issuer)["authorization_endpoint"]
    return endpoint + "?" + urllib.parse.urlencode(params)


def exchange(site, code, redirect_uri, code_verifier):
    """Trade an authorization code for the verified National ID profile.

    Returns the claims the provider vouched for. Raises SsoAuthError on any
    failure. The caller must take the identity only from this return value.
    """
    disco = discovery(_allowed_issuer(site))
    try:
        token_resp = _post_form(disco["token_endpoint"], {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
            "client_id": site.sso_client_id,
            "client_secret": site.sso_client_secret,
        })
        access_token = token_resp.get("access_token")
        if not access_token:
            raise SsoAuthError("No access token returned.")
        info = _get_bearer(disco["userinfo_endpoint"], access_token)
        if not (info.get("sub") or ""):
            raise SsoAuthError("Provider did not return a subject id.")
    except SsoAuthError as exc:
        logger.warning("SSO sign-in rejected: %s", exc)
        raise
    except Exception as exc:  # network / parse failure
        logger.warning("SSO exchange failed: %s", exc)
        raise SsoAuthError(f"SSO exchange failed: {exc}") from exc

    return {
        "sub": (info.get("sub") or "").strip(),
        "national_id": (info.get("pcn") or "").strip(),
        "digital_id": (info.get("digital_id") or "").strip(),
        "first_name": (info.get("given_name") or "").strip(),
        "middle_name": (info.get("middle_name") or "").strip(),
        "last_name": (info.get("family_name") or "").strip(),
    }


# --------------------------------------------------------------- login views

def _render_login(request, site, error):
    return render(request, "login_sso.html", _sso_page_context(site, error))


def _login_operator_from_sso(request, profile):
    """Resolve the provider's claims to a registered operator and sign in.

    Mirrors _login_user_from_everify: the identifiers come only from what the
    provider returned, an unmatched identity creates nothing, and empty name
    fields are backfilled. Returns the User, or None if nobody matched.
    """
    digital_id = profile.get("digital_id", "")
    card_number = profile.get("national_id", "")
    if not digital_id and not card_number:
        return None

    user = _find_user(digital_id, pcn=card_number)
    if user is None:
        return None

    updated = False
    for field, value in (("national_id_card_number", card_number),
                         ("digital_national_id", digital_id),
                         ("given_name", profile.get("first_name", "")),
                         ("middle_name", profile.get("middle_name", "")),
                         ("last_name", profile.get("last_name", ""))):
        if value and not getattr(user, field):
            setattr(user, field, value)
            updated = True
    if updated:
        user.save()

    _login_session(request, user, via="sso",
                   issuer=SiteSettings.load().sso_issuer, sub=profile.get("sub", ""))
    return user


@require_http_methods(["POST"])
def sso_login(request):
    """Start the SSO round trip: PKCE + state, then off to the provider.

    POST only: it is submitted from the login form, which carries the CSRF
    token. A GET would let any page start the flow.
    """
    site = SiteSettings.load()
    if not site.sso_login_active:
        return redirect("home")

    state = secrets.token_urlsafe(24)
    verifier, challenge = pkce_pair()
    request.session[STATE_KEY] = state
    request.session[VERIFIER_KEY] = verifier

    redirect_uri = request.build_absolute_uri(reverse("sso_callback"))
    try:
        return redirect(auth_url(site, redirect_uri, state, challenge))
    except Exception as exc:
        logger.warning("SSO discovery failed: %s", exc)
        return _render_login(request, site,
                             "The sign-in service is unavailable. "
                             "Please try again.")


def sso_callback(request):
    """Handle the provider redirect: check state, exchange, sign in."""
    site = SiteSettings.load()
    if not site.sso_login_active:
        return redirect("home")

    # Pop both halves before anything else, so a failed attempt cannot be
    # replayed against the same state.
    state = request.session.pop(STATE_KEY, None)
    verifier = request.session.pop(VERIFIER_KEY, None)

    def fail(message):
        return _render_login(request, site, message)

    if request.GET.get("error"):
        return fail("Sign-in was cancelled.")
    if not state or not verifier or state != request.GET.get("state"):
        return fail("Sign-in session expired or was invalid. Please try again.")
    code = request.GET.get("code")
    if not code:
        return fail("No authorization code returned. Please try again.")

    redirect_uri = request.build_absolute_uri(reverse("sso_callback"))
    try:
        profile = exchange(site, code, redirect_uri, verifier)
    except SsoAuthError:
        return fail("Could not verify your National ID. Please try again.")

    user = _login_operator_from_sso(request, profile)
    if user is None:
        # Verified by the provider, but not an operator on this site. No
        # account is created -- same rule as the eVerify path.
        logger.info("SSO sign-in refused: sub=%s is not a registered operator",
                    profile.get("sub"))
        return fail("This National ID is not registered as an operator on "
                    "this site.")

    # The chooser decides whether anything still needs asking: a
    # single-organization, single-location operator is sent straight on.
    return redirect("choose")
