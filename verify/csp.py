"""Content-Security-Policy: which scripts a page may run.

Every HTML response says that script may come only from this site, from the
two external files a page loads (PSA's liveness loader and the QR library,
each pinned to its exact path), or from an inline <script> carrying this
request's nonce. Nothing else runs: not an injected <script>, not an onclick
attribute, not a javascript: link. A stored "card number" that a template
bug let run as script on a page would still be refused by the browser.

What that asks of templates, and what accounts/tests_csp.py pins:

  * every inline <script> carries nonce="{{ csp_nonce }}";
  * no element carries an on* event attribute and no link a javascript: URL.
    The few things those did are declared as data attributes instead and
    wired up once, in base.html: data-confirm on a form, data-href (a path
    on this site) on a button, data-autosubmit on an input or select.

Only script-src, object-src, base-uri and frame-ancestors are set. Styles,
images, fetches and frames are left alone on purpose: the pages use inline
styles and data: images throughout, and PSA's liveness check runs in an
iframe on its own origin under its own policy.
"""

import secrets

#: The only scripts loaded from another host, by exact file. A host alone
#: would let anyone who can inject a <script src> pull any package off the CDN.
EXTERNAL_SCRIPTS = (
    "https://liveness.everify.gov.ph/js/everify-liveness-sdk.min.js",
    "https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js",
)

HEADER = "Content-Security-Policy"


def policy(nonce):
    return "; ".join((
        " ".join(("script-src", "'self'", f"'nonce-{nonce}'") + EXTERNAL_SCRIPTS),
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'none'",
    ))


class ContentSecurityPolicyMiddleware:
    """A fresh nonce per request, and the policy on every HTML response."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.csp_nonce = secrets.token_urlsafe(18)
        response = self.get_response(request)
        if (response.get("Content-Type", "").startswith("text/html")
                and HEADER not in response):
            response[HEADER] = policy(request.csp_nonce)
        return response


def nonce(request):
    """Template context: `csp_nonce` for inline <script> tags."""
    return {"csp_nonce": getattr(request, "csp_nonce", "")}
