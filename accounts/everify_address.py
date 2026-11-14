"""Where a verification's identity answer comes from, and who may say so.

Whatever answers at an eVerify base URL is the identity authority for every
verification run against it: its "verified" answer is kept, logged as a
success and signed into a credential that every phone reads as genuine, and
the client secret is sent to it. So the address is a SITE ADMINISTRATOR's
decision -- the Site page, Setup and Django admin -- and never an
organization's own admins'. It must be https, because the secret and the
answer both cross the wire. And its host must be one the server's operator
listed in EVERIFY_ALLOWED_HOSTS, so even a site administrator's typo or a
hijacked site-admin session cannot point verifications anywhere else.
"""

import logging
import re
from urllib.parse import urlparse

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from urllib3.exceptions import LocationParseError
from urllib3.util import parse_url

logger = logging.getLogger(__name__)

#: The column's width; SQLite would not enforce it.
MAX_LENGTH = 255

#: Characters no eVerify address needs and URL parsers disagree about. A
#: backslash ends the authority for urllib3 -- which `requests` connects with
#: -- but not for urlparse, so "https://evil.example\@ws.everify.gov.ph/api"
#: reads as PSA's host here and goes to evil.example. Userinfo (@) is
#: refused for the same reason, and whitespace and controls with it.
_UNSAFE = re.compile(r"[\\@\s\x00-\x1f\x7f]")


def allowed_hosts():
    return [host.lower() for host in getattr(settings, "EVERIFY_ALLOWED_HOSTS", [])]


def allowed(url):
    """May a request be sent to `url`? https, a host on the list, and the two
    parsers that matter -- ours and the one `requests` connects with -- agree
    on which host that is."""
    url = url or ""
    if _UNSAFE.search(url):
        return False
    try:
        ours, theirs = urlparse(url), parse_url(url)
    except (ValueError, LocationParseError):
        return False
    host = (ours.hostname or "").lower()
    return (ours.scheme == "https" and theirs.scheme == "https"
            and (theirs.host or "").lower() == host
            and host in allowed_hosts())


def clean(value):
    """(url, error) for an address a site administrator typed.

    Blank is allowed: it leaves the client unconfigured.
    """
    url = (value or "").strip()
    if not url:
        return "", ""
    if len(url) > MAX_LENGTH:
        return "", "The eVerify base URL is too long."
    try:
        URLValidator(schemes=["https"])(url)
    except ValidationError:
        return "", "The eVerify base URL must be an https:// address."
    if not allowed(url):
        hosts = ", ".join(allowed_hosts()) or "none"
        return "", ("The eVerify base URL must be on a host this server allows "
                    f"({hosts}). The server's EVERIFY_ALLOWED_HOSTS setting lists them.")
    return url, ""


def log_change(actor, scope, old, new):
    """One line per change of an address, naming who made it.

    `actor` is a User, a user id, or a label such as "django:3"."""
    if (old or "") != (new or ""):
        logger.warning("eVerify address for %s changed by user %s: %r -> %r",
                       scope, getattr(actor, "pk", actor), old or "", new or "")
