"""Which single sign-on provider a site administrator may point sign-in at.

With SSO selected, whoever answers at the issuer decides who signs in: the
callback takes the National ID it returns and opens a session for that
operator. A site administrator who could name any issuer could stand up a
provider of their own and sign in as anybody, other site administrators
included. So the issuer is the server's to allow, as the eVerify address is
(everify_address.py):

  * `SSO_ALLOWED_ISSUERS` in the environment lists the issuers, exactly;
    it is empty by default, so a site that wants SSO says which provider;
  * Setup saves no other issuer, and logs every change with who made it;
  * an issuer stored before the rule, or since dropped from the list, counts
    as SSO not configured: the login page offers eVerify instead, and the
    SSO routes do nothing.
"""

import logging
import re
from urllib.parse import urlparse

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator

logger = logging.getLogger(__name__)

#: Never part of an issuer this server allows: a backslash or "@" is how a
#: URL names one host to one parser and another to the next.
_UNSAFE = re.compile(r"[\\@\s\x00-\x1f\x7f]")


def _normal(url):
    return (url or "").strip().rstrip("/")


def allowed_issuers():
    """The issuers this server allows, as listed, without a trailing slash."""
    return [issuer for issuer in
            (_normal(value) for value in getattr(settings, "SSO_ALLOWED_ISSUERS", []))
            if issuer]


def allowed(issuer):
    """True only for an https issuer on the list, compared exactly."""
    issuer = _normal(issuer)
    if not issuer or _UNSAFE.search(issuer):
        return False
    parsed = urlparse(issuer)
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    return issuer in allowed_issuers()


def clean(value):
    """(issuer, error). A blank issuer is allowed: it means no SSO."""
    issuer = _normal(value)
    if not issuer:
        return "", ""
    if len(issuer) > 255:
        return "", "SSO issuer is too long."
    try:
        URLValidator(schemes=["https"])(issuer)
    except ValidationError:
        return "", "SSO issuer must be an https:// URL."
    if not allowed(issuer):
        listed = allowed_issuers()
        if not listed:
            return "", ("This server allows no single sign-on provider. Its "
                        "operator lists the ones it may use in "
                        "SSO_ALLOWED_ISSUERS.")
        return "", ("SSO issuer must be one this server allows: %s "
                    "(SSO_ALLOWED_ISSUERS)." % ", ".join(listed))
    return issuer, ""


def log_change(actor_id, old, new):
    """Every change of the issuer, with who made it."""
    if _normal(old) != _normal(new):
        logger.warning("SSO issuer changed by user %s: %r -> %r",
                       actor_id, old, new)
