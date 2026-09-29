"""The chain must hold when several gateway processes share one log.

A session spans one gateway per MCP server. If each caches the chain tip in
memory they interleave and every verification fails. This test is the
regression guard for that.
"""

from __future__ import annotations

import multiprocessing as mp
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _writer(db_path: str, tag: str, n: int) -> None:
    sys.path.insert(0, str(ROOT))
    from gateway.audit.log import AuditLog

    log = AuditLog(db_path)
    for i in range(n):
        log.append(
            session_id=tag,
            direction="client_to_server",
            kind="request",
            method="tools/call",
            payload={"writer": tag, "i": i},
        )
    log.close()


def main() -> int:
    from gateway.audit.log import AuditLog

    db = str(Path(tempfile.mkdtemp()) / "audit.db")
    AuditLog(db).close()  # create schema before the race

    procs = [mp.Process(target=_writer, args=(db, f"w{i}", 40)) for i in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join()

    log = AuditLog(db)
    result = log.verify()
    events = list(log.events())
    log.close()

    if not result.ok:
        print(f"[FAIL] chain broken at seq {result.broken_at}: {result.detail}")
        return 1
    if len(events) != 160:
        print(f"[FAIL] expected 160 events, got {len(events)}")
        return 1
    print(f"[pass] 4 processes x 40 appends: {result.checked} events, chain intact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
