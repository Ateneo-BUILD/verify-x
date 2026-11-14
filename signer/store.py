"""The signer's database: one SQLite file, one writer.

Everything the signer must remember lives here, beside the ledger, so a
restore brings it all back together and the rollback check (`aws.py`) can
refuse a copy older than what was shipped. verify holds a mirror of the key
table at most; it never writes here.
"""

from __future__ import annotations

import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS keys (
    key_id            INTEGER PRIMARY KEY,
    organization      TEXT,          -- signing_id, NULL for the deployment key
    state             TEXT NOT NULL,
    spki              BLOB NOT NULL,
    key_ref           TEXT,          -- where the private key is, if held
    leaf              BLOB,          -- DER certificate, once certified
    certified_name    TEXT,
    leaf_not_before   INTEGER,
    leaf_not_after    INTEGER,
    window_start      INTEGER,
    window_end        INTEGER,       -- signing_until, or the retirement time
    published_at      INTEGER,
    activated_at      INTEGER,
    retired_at        INTEGER,
    withdrawn_at      INTEGER,
    suspended_at      INTEGER,
    legacy            INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL,
    ca_id             INTEGER,       -- the Organization CA that certified it
    certified_by      TEXT           -- the CA name phones show for it
);
CREATE TABLE IF NOT EXISTS cas (    -- Organization CAs (docs: "generated on verify")
    ca_id         INTEGER PRIMARY KEY,   -- from the key ids, never reused
    state         TEXT NOT NULL,         -- generated | certified | retired | withdrawn
    spki          BLOB NOT NULL,
    key_ref       TEXT,
    cert          BLOB,                  -- DER, from the PKI
    name          TEXT,
    not_before    INTEGER,
    not_after     INTEGER,
    issued        INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    retired_at    INTEGER,
    withdrawn_at  INTEGER
);
CREATE TABLE IF NOT EXISTS confirmations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    action        TEXT NOT NULL,
    subject       TEXT NOT NULL,
    requested_by  TEXT NOT NULL,
    requested_at  INTEGER NOT NULL,
    done_at       INTEGER
);
CREATE TABLE IF NOT EXISTS ledger (
    seq        INTEGER PRIMARY KEY,
    at         INTEGER NOT NULL,
    kind       TEXT NOT NULL,        -- sign | key | alert | admin
    context    TEXT NOT NULL,
    digest     TEXT NOT NULL,        -- SHA-256 of what was signed, or ""
    summary    TEXT NOT NULL,        -- canonical JSON
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL,
    shipped    INTEGER NOT NULL DEFAULT 0
);
-- The switch gate's and the reconciler's reads by kind and time, so Setup
-- does not scan a year of signatures for each published key.
CREATE INDEX IF NOT EXISTS ledger_by_kind ON ledger (kind, context, at);
CREATE TABLE IF NOT EXISTS artifacts (
    kind         TEXT NOT NULL,      -- feed | statement
    content_key  TEXT NOT NULL,
    issued_at    INTEGER NOT NULL,
    not_after    INTEGER NOT NULL,
    key_id       INTEGER NOT NULL,
    body         TEXT NOT NULL,      -- JSON, as verify serves it
    PRIMARY KEY (kind, content_key)
);
CREATE TABLE IF NOT EXISTS revoked (
    credential_id BLOB PRIMARY KEY,
    added_at      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS signed_credentials (
    credential_id BLOB PRIMARY KEY,
    key_id        INTEGER NOT NULL,
    at            INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    context    TEXT NOT NULL,
    principal  TEXT NOT NULL,        -- "*" for the global count
    at         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS events_by_principal ON events (context, principal, at);
CREATE TABLE IF NOT EXISTS pauses (
    context    TEXT PRIMARY KEY,     -- a context, or "all"
    paused_at  INTEGER NOT NULL,
    by         TEXT NOT NULL,
    reason     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    name   TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
"""


#: Seconds a write waits for another process's write lock -- the
#: reconciler's -- before it is refused. sqlite3's own default, said here.
BUSY_TIMEOUT = 5.0


class Store:
    """A connection and a lock: the service is single-writer by design."""

    def __init__(self, path: str, busy_timeout: float = BUSY_TIMEOUT):
        self.path = path
        self.db = sqlite3.connect(path, check_same_thread=False,
                                  isolation_level=None, timeout=busy_timeout)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(SCHEMA)
        self.upgrade()
        self.lock = threading.RLock()

    def upgrade(self):
        """Bring an older store's tables up to this code's. Also run by
        `startup.check` on the copy it makes of the live database."""
        # A store made before the Organization CA lacks its two key columns.
        have = {r["name"] for r in self.db.execute("PRAGMA table_info(keys)")}
        for name, decl in (("ca_id", "INTEGER"), ("certified_by", "TEXT")):
            if name not in have:
                self.db.execute("ALTER TABLE keys ADD COLUMN %s %s" % (name, decl))

    def __enter__(self):
        """Lock, then begin. A BEGIN that fails -- another process holding the
        write lock past the timeout, a read-only file after a restore --
        gives the lock back before it raises: `__exit__` never runs for a
        `with` whose `__enter__` raised, and a lock kept here would wedge
        every later request and the ledger's shipping until a restart."""
        self.lock.acquire()
        try:
            self.db.execute("BEGIN IMMEDIATE")
        except BaseException:
            self.lock.release()
            raise
        return self.db

    def __exit__(self, exc_type, exc, tb):
        """Commit, or roll back; a COMMIT that fails is rolled back too, so
        the connection is never left inside a transaction."""
        try:
            if exc_type is None:
                try:
                    self.db.execute("COMMIT")
                except BaseException:
                    self._rollback()
                    raise
            else:
                self._rollback()
        finally:
            self.lock.release()

    def _rollback(self):
        try:
            self.db.execute("ROLLBACK")
        except sqlite3.Error:
            pass        # nothing left to roll back: SQLite already ended it

    def one(self, sql, args=()):
        return self.db.execute(sql, args).fetchone()

    def all(self, sql, args=()):
        return self.db.execute(sql, args).fetchall()

    def meta(self, name, default=None):
        row = self.one("SELECT value FROM meta WHERE name = ?", (name,))
        return row["value"] if row else default

    def set_meta(self, db, name, value):
        db.execute("INSERT INTO meta (name, value) VALUES (?, ?) "
                   "ON CONFLICT(name) DO UPDATE SET value = excluded.value",
                   (name, str(value)))
