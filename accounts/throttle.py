"""Per-address limits on what anybody can reach without signing in.

Without a limit, a signed-out `POST /everify/` for an unknown ID holds a
worker for the matched 2-5 s delay and stores a face,
`log-liveness-failure` writes a row per call, `/decode-qr/` runs six OpenCV
passes over a 10 MB image, a phone's `/challenge/` inserts a row, and
`/admin/login/` takes passwords with no lockout at all: a handful of
concurrent requests could fill every worker.

Each is counted per client address over a window, and a request over the
limit is answered 429 without doing the work -- and without writing
anything, so the limit cannot itself fill the table. nginx limits
Django admin's login in front of the application (deploy/nginx.conf.tftpl);
this is the half that ships with the code.

**The limit is the same for every caller.** The sign-in limit is counted
before anything looks at the ID, so a registered and an unregistered ID are
refused alike: it tells an enumerator nothing (login_guard.py's rule).
"""

import ipaddress
import logging
import random
import time
from datetime import timedelta
from urllib.parse import urlparse

from django.conf import settings
from django.http import HttpResponse, JsonResponse
from django.utils import timezone

logger = logging.getLogger(__name__)

#: scope -> (requests allowed, window in seconds), per client address.
#: An office signs its operators in from one public address, so the sign-in
#: paths allow a morning's worth; what they stop is a flood.
LIMITS = {
    # POST /everify/ signed out: one sign-in is one request.
    "sign-in": (30, 600),
    # POST /everify/log-liveness-failure/ signed out.
    "liveness-failure": (30, 600),
    # POST /decode-qr/ signed out: a login page scanning a card, retried.
    "decode-qr": (60, 600),
    # POST /api/v1/device/challenge/: one per sync, and an organization's
    # phones may share one address.
    "device-challenge": (120, 600),
    # POST /admin/login/: passwords.
    "admin-login": (10, 900),
}

#: One refusal per scope and address is logged per window, not one per
#: request: the log is not to be the next thing a flood fills.
_last_logged = {}


def limits():
    merged = dict(LIMITS)
    merged.update(getattr(settings, "RATE_LIMITS", {}))
    return merged


def client_address(request):
    """The client's address as the nearest trusted proxy saw it.

    Every deployment runs a load balancer in front of nginx: the balancer
    appends the client's address to X-Forwarded-For and nginx appends the
    balancer's. Anything before those two was written by the client and
    proves nothing, so the client is the entry `VERIFY_PROXY_HOPS` (default
    2) from the end -- never the first, which is the client's own to choose.
    Fewer entries than that means the request did not come through the whole
    chain, and the earliest one a proxy wrote is used.
    """
    hops = int(getattr(settings, "VERIFY_PROXY_HOPS", 2))
    entries = [entry.strip() for entry in
               request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")
               if entry.strip()]
    if hops > 0 and entries:
        candidate = entries[-min(hops, len(entries))]
    else:
        candidate = request.META.get("REMOTE_ADDR") or ""
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return "unknown"


def allow(request, scope):
    """True if this request is within its address's limit, and counts it.

    A request over the limit is not counted: it writes no row.
    """
    from .models import RateLimitHit

    allowed, seconds = limits()[scope]
    if allowed <= 0:
        return True
    now = timezone.now()
    key = client_address(request)
    recent = RateLimitHit.objects.filter(
        scope=scope, key=key, at__gte=now - timedelta(seconds=seconds)).count()
    if recent >= allowed:
        _log_refusal(scope, key, allowed, seconds)
        return False
    RateLimitHit.objects.create(scope=scope, key=key, at=now)
    if random.random() < 0.02:
        longest = max(window for _, window in limits().values())
        RateLimitHit.objects.filter(at__lt=now - timedelta(seconds=longest)).delete()
    return True


def _log_refusal(scope, key, allowed, seconds):
    mark = (scope, key)
    if time.monotonic() - _last_logged.get(mark, -seconds) >= seconds:
        _last_logged[mark] = time.monotonic()
        logger.warning("Rate limit: %s from %s refused (more than %d in %d s)",
                       scope, key, allowed, seconds)


def cross_site(request):
    """A browser request that another site's page sent.

    `/everify/`, `/decode-qr/` and the device challenge take no CSRF token,
    so any page open in a browser could post to them -- and every such post
    would count against the limit of that browser's address, so a page
    somebody in an office opens could lock the whole office out. A browser
    says where a request came from: `Sec-Fetch-Site`, and `Origin` on every
    POST. A request that names another site is refused before it is counted.
    Phones and other non-browser callers send neither.
    """
    if request.META.get("HTTP_SEC_FETCH_SITE") == "cross-site":
        return True
    origin = request.META.get("HTTP_ORIGIN")
    if origin is None:
        return False
    if origin in getattr(settings, "CSRF_TRUSTED_ORIGINS", []):
        return False
    try:
        host = request.get_host()
    except Exception:
        return True
    return urlparse(origin).netloc != host


def refuse_cross_site(request):
    """A 403 for a cross-site browser request, or None."""
    if cross_site(request):
        return JsonResponse({"status": "error", "ok": False,
                             "message": "Requests from other sites are refused."},
                            status=403)
    return None


MESSAGE = "Too many attempts from this network. Wait a few minutes and try again."


def refused_json(**extra):
    response = JsonResponse({"status": "error", "message": MESSAGE, **extra},
                            status=429)
    response["Retry-After"] = "60"
    return response


def admin_login(view):
    """Django admin's login view, with POSTs limited per address."""
    def limited(request, *args, **kwargs):
        if request.method == "POST" and not allow(request, "admin-login"):
            response = HttpResponse(MESSAGE, status=429,
                                    content_type="text/plain; charset=utf-8")
            response["Retry-After"] = "60"
            return response
        return view(request, *args, **kwargs)
    return limited
