"""Append-only, hash-chained audit log.

Every event is hashed together with the hash of the event before it, so any
edit, deletion or reordering of past rows breaks the chain from that point on.
verify() walks the chain and reports the first row that fails.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL    NOT NULL,
    session_id TEXT    NOT NULL,
    direction  TEXT    NOT NULL,
    kind       TEXT    NOT NULL,
    method     TEXT,
    msg_id     TEXT,
    payload    TEXT    NOT NULL,
    verdict    TEXT,
    rule_id    TEXT,
    latency_ms REAL,
    prev_hash  TEXT    NOT NULL,
    hash       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_method  ON events(method);
"""

# Fields that are covered by the hash. Anything not in here can be altered
# without breaking the chain, so keep this list equal to the whole record.
HASHED_FIELDS = (
    "seq",
    "ts",
    "session_id",
    "direction",
    "kind",
    "method",
    "msg_id",
    "payload",
    "verdict",
    "rule_id",
    "latency_ms",
)


def canonical(obj: Any) -> bytes:
    """Stable serialisation, so the same record always hashes the same way."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def chain_hash(prev_hash: str, record: dict) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))
    h.update(canonical({k: record.get(k) for k in HASHED_FIELDS}))
    return h.hexdigest()


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    checked: int
    broken_at: int | None = None
    detail: str | None = None


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._lock = threading.Lock()
        # isolation_level=None: we drive transactions explicitly, because the
        # chain tip must be read inside the same write lock as the insert.
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.executescript(SCHEMA)

    def append(
        self,
        *,
        session_id: str,
        direction: str,
        kind: str,
        payload: Any,
        method: str | None = None,
        msg_id: str | None = None,
        verdict: str | None = None,
        rule_id: str | None = None,
        latency_ms: float | None = None,
    ) -> int:
        """Append one event. Returns its sequence number.

        A session usually involves several gateway processes, one per MCP
        server, all appending to the same log. Each must see the true tip of
        the chain, so the read and the insert happen inside one BEGIN
        IMMEDIATE. Caching the tip in memory produces a log that looks fine and
        fails verification - the integrity claim has to hold under concurrency
        or it is not a claim.
        """
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute(
                    "SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                seq = (row["seq"] + 1) if row else 1
                prev_hash = row["hash"] if row else GENESIS
                record = {
                    "seq": seq,
                    "ts": time.time(),
                    "session_id": session_id,
                    "direction": direction,
                    "kind": kind,
                    "method": method,
                    "msg_id": msg_id,
                    "payload": canonical(payload).decode("utf-8"),
                    "verdict": verdict,
                    "rule_id": rule_id,
                    "latency_ms": latency_ms,
                }
                record["prev_hash"] = prev_hash
                record["hash"] = chain_hash(prev_hash, record)
                self._db.execute(
                    "INSERT INTO events (seq, ts, session_id, direction, kind, method,"
                    " msg_id, payload, verdict, rule_id, latency_ms, prev_hash, hash)"
                    " VALUES (:seq, :ts, :session_id, :direction, :kind, :method,"
                    " :msg_id, :payload, :verdict, :rule_id, :latency_ms, :prev_hash, :hash)",
                    record,
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
            return seq

    def verify(self) -> VerifyResult:
        """Recompute the chain from genesis. Detects edits, deletions, reorders."""
        prev = GENESIS
        checked = 0
        expected_seq = 1
        for row in self._db.execute("SELECT * FROM events ORDER BY seq ASC"):
            record = dict(row)
            if record["seq"] != expected_seq:
                return VerifyResult(
                    False, checked, record["seq"], f"gap: expected seq {expected_seq}"
                )
            if record["prev_hash"] != prev:
                return VerifyResult(False, checked, record["seq"], "prev_hash mismatch")
            if chain_hash(prev, record) != record["hash"]:
                return VerifyResult(False, checked, record["seq"], "content altered")
            prev = record["hash"]
            checked += 1
            expected_seq += 1
        return VerifyResult(True, checked)

    def events(self, session_id: str | None = None) -> Iterator[dict]:
        sql = "SELECT * FROM events"
        args: tuple = ()
        if session_id:
            sql += " WHERE session_id = ?"
            args = (session_id,)
        sql += " ORDER BY seq ASC"
        for row in self._db.execute(sql, args):
            yield dict(row)

    def close(self) -> None:
        with self._lock:
            self._db.close()
