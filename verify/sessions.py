"""Keeping a signed-in session alive without rewriting it on every request.

`SESSION_SAVE_EVERY_REQUEST` is off. On, every request would rewrite the
whole session row -- and while a verification is open, that row carries the
verified person's rows and face, about 10 KB. Four of the six requests of
one verification would rewrite it: 42 of the 47 KB a verification writes to
the database.

What the switch would buy is a session that stays alive while it is used
and ends four hours after the last request. `RefreshSessionMiddleware` keeps
that, at most once every `SESSION_REFRESH_SECONDS`: an idle session ends
between four hours less that interval and four hours after its last
request, so never later than four hours. A request that changes the session
saves it anyway, and the stamp rides along.

`clear_expired()` is the other half. Nothing else runs `clearsessions`, so
a session abandoned mid-verification would keep its rows, face included, in
the database and in every backup indefinitely. It goes at the next sign-in
after it expires.

The refresh means a session in use never ends by itself, so
`AbsoluteSessionLifetimeMiddleware` ends every one
`SESSION_ABSOLUTE_SECONDS` after it signed in, however busy it has been.
"""
import logging
import time
from importlib import import_module

from django.conf import settings

logger = logging.getLogger(__name__)

#: When the session was last saved, in seconds since the epoch.
REFRESHED_AT = "_refreshed_at"

#: When the session signed in, in seconds since the epoch.
SIGNED_IN_AT = "_signed_in_at"


def mark_signed_in(session):
    """Start a session's absolute lifetime: at every sign-in, eVerify, SSO
    and Django admin alike."""
    session[SIGNED_IN_AT] = int(time.time())


class AbsoluteSessionLifetimeMiddleware:
    """End a session SESSION_ABSOLUTE_SECONDS after it signed in, however
    busy it has been. The idle limit alone let one sign-in last for as
    long as somebody kept using it.

    Listed after SessionMiddleware and before AuthenticationMiddleware: a
    Django admin login shares the session, so ending it ends that too, and
    the bridge's own row with it. A session already open when this arrived
    carries no stamp and is given one now, so a deploy signs nobody out."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        session = getattr(request, "session", None)
        if session is not None and not session.is_empty():
            now = int(time.time())
            started = session.get(SIGNED_IN_AT)
            if not isinstance(started, int):
                session[SIGNED_IN_AT] = now
            elif now - started > settings.SESSION_ABSOLUTE_SECONDS:
                logger.info("Ended a session signed in %d minutes ago",
                            (now - started) // 60)
                session.flush()
        return self.get_response(request)


class RefreshSessionMiddleware:
    """Mark a live session modified when it is due a refresh, so Django's
    SessionMiddleware saves it and re-sends the cookie with a fresh expiry.

    Listed AFTER SessionMiddleware, so its response half runs first."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        session = getattr(request, "session", None)
        if session is None or session.is_empty():
            # Nobody signed in, or signed out: never create a session to
            # stamp it, or every visit to the login page would write a row.
            return response
        now = int(time.time())
        last = session.get(REFRESHED_AT)
        due = (not isinstance(last, int)
               or now - last >= settings.SESSION_REFRESH_SECONDS)
        if session.modified or due:
            session[REFRESHED_AT] = now
        return response


def clear_expired():
    """Delete expired sessions, as `manage.py clearsessions` does. Never
    raises: tidying up must not cost anybody their sign-in."""
    try:
        import_module(settings.SESSION_ENGINE).SessionStore.clear_expired()
    except Exception:
        logger.exception("could not clear expired sessions")
