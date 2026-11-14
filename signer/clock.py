"""The signer's idea of now, injectable so tests can move it."""

import time


class Clock:
    def now(self) -> int:
        return int(time.time())


class FixedClock(Clock):
    def __init__(self, at: int):
        self.at = at

    def now(self) -> int:
        return self.at

    def advance(self, seconds: int):
        self.at += seconds
