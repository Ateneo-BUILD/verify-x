"""The hash-chained record of every signature and every key event.

Each row names the hash of the row before it, so a row changed or removed
after the fact breaks every hash that follows. Rows go to write-once storage
(`aws.py`): key events immediately, the rest every few minutes. The daily
summary carries the newest hash, a witness outside this host.

Holds no holder data: the restricted section is encrypted before it is
signed. It does hold operator names and document numbers, as the parsed
summary of each credential.
"""

from __future__ import annotations

import hashlib
import json

GENESIS = "0" * 64


def _canonical(fields: dict) -> str:
    return json.dumps(fields, sort_keys=True, separators=(",", ":"))


def row_hash(prev_hash: str, seq: int, at: int, kind: str, context: str,
             digest: str, summary: str) -> str:
    material = _canonical({"prev": prev_hash, "seq": seq, "at": at,
                           "kind": kind, "context": context,
                           "digest": digest, "summary": summary})
    return hashlib.sha256(material.encode()).hexdigest()


def append(db, *, at: int, kind: str, context: str, summary: dict,
           message: bytes = b"") -> dict:
    """Append one row inside the caller's transaction. Returns it."""
    last = db.execute("SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1"
                      ).fetchone()
    seq = (last["seq"] + 1) if last else 1
    prev = last["hash"] if last else GENESIS
    digest = hashlib.sha256(message).hexdigest() if message else ""
    text = _canonical(summary)
    h = row_hash(prev, seq, at, kind, context, digest, text)
    db.execute("INSERT INTO ledger (seq, at, kind, context, digest, summary, "
               "prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
               (seq, at, kind, context, digest, text, prev, h))
    return {"seq": seq, "at": at, "kind": kind, "context": context,
            "digest": digest, "summary": text, "prev_hash": prev, "hash": h}


def head(store):
    row = store.one("SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1")
    return (row["seq"], row["hash"]) if row else (0, GENESIS)


def verify_chain(rows) -> int:
    """Check a run of rows in order. Returns how many; raises on a break."""
    prev = None
    count = 0
    for row in rows:
        if prev is not None and row["prev_hash"] != prev:
            raise ValueError("ledger broken before row %d" % row["seq"])
        expected = row_hash(row["prev_hash"], row["seq"], row["at"],
                            row["kind"], row["context"], row["digest"],
                            row["summary"])
        if expected != row["hash"]:
            raise ValueError("ledger row %d was changed" % row["seq"])
        prev = row["hash"]
        count += 1
    return count


def rows_since(store, seq: int):
    return store.all("SELECT * FROM ledger WHERE seq > ? ORDER BY seq", (seq,))
