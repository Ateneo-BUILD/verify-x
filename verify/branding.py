"""A deployment's own name and footer logos.

Nothing in this repository names the organization running a site. Pages are
titled SITE_TITLE ("Verify" when unset), and the footer draws whatever logos
SITE_FOOTER_LOGOS lists from BRANDING_DIR -- or no footer at all.

SITE_FOOTER_LOGOS is operator-written text that ends up on every page, so it
is parsed strictly. An entry naming anything but a plain image file in the
branding folder, or linking anywhere but an http(s) address, is dropped and
logged rather than drawn: a typo in a footer must not take a page down, and
must not become markup either.

SVG is refused, as it is for organization logos: an SVG can carry script,
and these files are served from the site's own origin.
"""
import logging
import re

from django.conf import settings

logger = logging.getLogger(__name__)

IMAGE_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.(png|jpe?g|gif|webp)$", re.I)
WEB_LINK = re.compile(r"^https?://[^\s\"'<>]+$", re.I)


def footer_logos(raw=None):
    """[{src, href, alt}] from a "file|link|alt;file|link|alt" string."""
    raw = settings.SITE_FOOTER_LOGOS if raw is None else raw
    logos = []
    for entry in raw.split(";"):
        entry = entry.strip()
        if not entry:
            continue
        parts = [part.strip() for part in entry.split("|")]
        name = parts[0]
        link = parts[1] if len(parts) > 1 else ""
        alt = parts[2] if len(parts) > 2 else name.rsplit(".", 1)[0]
        if len(parts) > 3 or not IMAGE_FILE.match(name) or (link and not WEB_LINK.match(link)):
            logger.warning("SITE_FOOTER_LOGOS: ignoring the entry %r", entry)
            continue
        logos.append({"src": "branding/" + name, "href": link, "alt": alt})
    return logos
