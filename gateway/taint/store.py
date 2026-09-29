"""Session-scoped taint labels, shared across gateway processes.

A session runs one gateway per MCP server. The gateway in front of `web` sees
the fetched page; the gateway in front of `mail` sees the send. Taint has to
survive that process boundary, so it lives in the same SQLite file as the audit
log and every gateway in the session reads and writes it. The harness gives all
of them the same --session id, which is what ties the records together.

Two labels, because they answer different questions:

  sensitive  - came out of a private_read tool. Asking: is private data
               leaving through this call?
  untrusted  - came out of an untrusted_inbound tool. Asking: was this call
               shaped by content an attacker controls?

s04 needs the first one. The injected send carries the credentials note
verbatim, and no keyword, score or recipient check is involved in noticing it.
"""

from __future__ import annotations

import os
import re
import sqlite3
import threading
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

SENSITIVE = "sensitive"
UNTRUSTED = "untrusted"

# Length, in normalised characters, of the shortest overlap treated as a match.
# Lower catches paraphrase-resistant fragments but raises false positives on
# ordinary shared phrasing; higher is safer and misses short secrets. 24 is
# tuned against the benign controls, and the sensitivity of this number is
# itself a result worth reporting.
MIN_OVERLAP = 24


def current_threshold() -> int:
    """Read at call time, from the environment, so a harness can vary it.

    The matching runs inside gateway subprocesses. A threshold patched in the
    harness process never reaches them - an earlier version of the sweep did
    exactly that and reported every threshold as 24. The environment is the
    one channel the children inherit.
    """
    raw = os.environ.get("MCPGW_MIN_OVERLAP")
    return int(raw) if raw else MIN_OVERLAP

SCHEMA = """
CREATE TABLE IF NOT EXISTS taint (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    server     TEXT,
    tool       TEXT,
    label      TEXT NOT NULL,
    content    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_taint_session ON taint(session_id, label);
"""

_WORD = re.compile(r"[^a-z0-9]+")


def normalise(text: str) -> str:
    """Strip the cheap evasions: case, whitespace, punctuation, percent
    encoding. An attacker who must defeat both the normaliser and the matcher
    has a harder job than one who only has to add a space."""
    if not text:
        return ""
    try:
        text = urllib.parse.unquote(text)
    except Exception:
        pass
    return _WORD.sub("", text.lower())


def overlaps(tainted: str, candidate: str, min_len: int | None = None) -> bool:
    if min_len is None:
        min_len = current_threshold()
    a, b = normalise(tainted), normalise(candidate)
    if len(a) < min_len or len(b) < min_len:
        return False
    # k-gram containment: cheap, and order-insensitive enough to survive
    # reordering of a copied block.
    grams = {a[i : i + min_len] for i in range(len(a) - min_len + 1)}
    return any(g in b for g in grams)


def flatten(value) -> str:
    if isinstance(value, dict):
        return " ".join(flatten(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return " ".join(flatten(v) for v in value)
    return str(value) if value is not None else ""


@dataclass
class TaintStore:
    path: str

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.executescript(SCHEMA)

    def record(self, session_id: str, server: str, tool: str, label: str, content: str) -> None:
        if not content:
            return
        with self._lock:
            self._db.execute(
                "INSERT INTO taint (session_id, server, tool, label, content)"
                " VALUES (?, ?, ?, ?, ?)",
                (session_id, server, tool, label, content),
            )

    def has_label(self, session_id: str, label: str) -> bool:
        row = self._db.execute(
            "SELECT 1 FROM taint WHERE session_id = ? AND label = ? LIMIT 1",
            (session_id, label),
        ).fetchone()
        return row is not None

    def labels_in(self, session_id: str, args, mode: str = "fine") -> set[str]:
        """Which taint labels this call's arguments carry.

        fine   - the arguments actually contain content that came from a
                 labelled source. Precise, cheap in utility, and evadable: an
                 agent that paraphrases the secret defeats it.
        coarse - the session has touched a labelled source at all, so every
                 later call inherits the label. Unevadable, and it blocks
                 legitimate work. Both ship, both are benchmarked, and the gap
                 between them is the interesting number.
        """
        if mode == "off":
            return set()
        if mode == "coarse":
            return {
                label
                for label in (SENSITIVE, UNTRUSTED)
                if self.has_label(session_id, label)
            }

        text = flatten(args)
        if not text:
            return set()
        found: set[str] = set()
        for row in self._db.execute(
            "SELECT label, content FROM taint WHERE session_id = ?", (session_id,)
        ):
            if row["label"] in found:
                continue
            if overlaps(row["content"], text):
                found.add(row["label"])
        return found

    def close(self) -> None:
        with self._lock:
            self._db.close()
