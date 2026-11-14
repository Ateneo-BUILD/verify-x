"""The signer's main loop: ship the ledger and beat, until told to stop.

Kept out of `__main__` so it can be tested where `pwd` and `grp` do not
exist. A stop request (`systemctl stop`, before the host is imaged, say)
only sets an event. The handler never ships: it runs in the main thread,
possibly in the middle of a ship that holds the shipper's lock, and taking
that lock again there would deadlock and lose the final ship.
"""

from __future__ import annotations

import sys
import threading


def stopper():
    """(event, a signal handler that only sets it)."""
    stop = threading.Event()

    def handler(_signum=None, _frame=None):
        stop.set()

    return stop, handler


def periodic(ship, beat, stop: threading.Event, every: float) -> None:
    """Ship and beat every `every` seconds; once stopped, ship one last time."""
    while not stop.is_set():
        try:
            ship()
            beat()
        except Exception as exc:          # keep serving; the alarm notices
            print("periodic task failed: %s" % exc, file=sys.stderr)
        stop.wait(every)
    try:
        ship()
    except Exception as exc:
        print("final ship failed: %s" % exc, file=sys.stderr)
