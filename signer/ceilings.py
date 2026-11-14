"""Rate ceilings, per principal first, and pauses.

A principal over its cap is refused and nobody else notices. Every per-
principal cap is at most a quarter of the global one (`config.py`), so only
four principals at their caps together, or a compromised app -- which could
pause signing anyway -- reach a global ceiling. Only the global credential
ceiling pauses anything. Bundle, feed and statement ceilings refuse the excess
and alert; they never pause, so no caller can stop the fleet syncing. A
principal over its cap is alerted on once a window, not once a request.
"""

from __future__ import annotations

from . import config as cfgmod

WINDOWS = (60, 3600, 86400)
ALL = "all"


class Over(Exception):
    def __init__(self, context, principal, window):
        super().__init__("%s over its %d-second ceiling for %s"
                         % (principal, window, context))
        self.context = context
        self.principal = principal
        self.window = window


def _count(db, context, principal, since):
    return db.execute("SELECT COUNT(*) AS n FROM events WHERE context = ? "
                      "AND principal = ? AND at >= ?",
                      (context, principal, since)).fetchone()["n"]


def check(db, cfg, now: int, context: str, principals) -> None:
    """Raise `Over` for the first cap this request would break.

    `principals` is [(kind, value)], e.g. [("organization", "<id>")]. The
    global count is checked last, so a principal at its own cap is refused as
    itself, never as the whole context.
    """
    for kind, value in list(principals) + [("*", "*")]:
        limits = cfg.ceiling(context, kind)
        if not limits:
            continue
        key = value if kind != "*" else "*"
        for window, limit in zip(WINDOWS, limits):
            if limit is None:
                continue
            if _count(db, context, "%s:%s" % (kind, key), now - window) >= limit:
                raise Over(context, "%s:%s" % (kind, key), window)


def record(db, now: int, context: str, principals) -> None:
    for kind, value in list(principals) + [("*", "*")]:
        db.execute("INSERT INTO events (context, principal, at) VALUES (?, ?, ?)",
                   (context, "%s:%s" % (kind, value if kind != "*" else "*"),
                    now))
    db.execute("DELETE FROM events WHERE at < ?", (now - WINDOWS[-1],))


def paused(store, context: str):
    """The pause that stops `context`, if any: its own, or everything."""
    return store.one("SELECT * FROM pauses WHERE context IN (?, ?)",
                     (context, ALL))


def pause(db, now: int, context: str, by: str, reason: str) -> None:
    if context != ALL and context not in cfgmod.CONTEXTS:
        raise ValueError("no such context %r" % context)
    db.execute("INSERT INTO pauses (context, paused_at, by, reason) "
               "VALUES (?, ?, ?, ?) ON CONFLICT(context) DO NOTHING",
               (context, now, by, reason[:200]))


def resume(db, context: str) -> int:
    return db.execute("DELETE FROM pauses WHERE context = ?",
                      (context,)).rowcount
