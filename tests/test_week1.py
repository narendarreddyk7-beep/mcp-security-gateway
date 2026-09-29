"""Week 1 milestone tests.

Proves three things:
  1. The proxy is transparent  - a session through it is byte-identical to a
     session against the server directly.
  2. Every frame lands in the audit log, attributed to its method.
  3. The chain verifies, and detects an edit to a past row.
"""

from __future__ import annotations

import json
import os
import subprocess
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER = [sys.executable, str(ROOT / "servers" / "echo" / "server.py")]

SESSION = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        # Non-ASCII and an astral-plane codepoint: the transport must not
        # mangle either. (Lone surrogates are an obfuscation vector in their
        # own right - they get a deliberate scenario in week 5, not a fixture.)
        "params": {"name": "echo", "arguments": {"text": "hello \u00e9\u00fc \U0001F512"}},
    },
]


def _feed(cmd: list[str]) -> list[dict]:
    payload = "".join(json.dumps(m) + "\n" for m in SESSION).encode()
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    proc = subprocess.run(
        cmd, input=payload, capture_output=True, timeout=30, cwd=ROOT, env=env
    )
    if proc.returncode not in (0, None):
        print(proc.stderr.decode(), file=sys.stderr)
    return [json.loads(l) for l in proc.stdout.decode().splitlines() if l.strip()]


def test_transport_is_transparent(tmp_db: str) -> None:
    direct = _feed(SERVER)
    through = _feed([sys.executable, "-m", "gateway", "--db", tmp_db, "--"] + SERVER)
    assert direct == through, "proxy altered the stream"
    assert len(direct) == 3, f"expected 3 responses, got {len(direct)}"
    assert direct[2]["result"]["content"][0]["text"] == "hello \u00e9\u00fc \U0001F512", "unicode mangled"


def test_audit_captures_session(tmp_db: str) -> None:
    sys.path.insert(0, str(ROOT))
    from gateway.audit.log import AuditLog

    log = AuditLog(tmp_db)
    events = list(log.events())
    kinds = [e["kind"] for e in events]
    assert kinds[0] == "session_start" and kinds[-1] == "session_end"

    methods = [e["method"] for e in events if e["method"]]
    assert methods.count("tools/call") == 2, "request and its response both attributed"
    assert "notifications/initialized" in methods

    call = next(e for e in events if e["method"] == "tools/call")
    assert json.loads(call["payload"])["params"]["name"] == "echo"
    # Transparent mode forwards every protocol frame. Gateway-generated
    # records (manifest findings) carry their own verdicts and are not frames.
    frames = [e for e in events if e["direction"] != "gateway"]
    assert all(e["verdict"] == "allow" for e in frames), "transparent mode must allow every frame"
    log.close()


def test_chain_verifies_and_detects_tampering(tmp_db: str) -> None:
    sys.path.insert(0, str(ROOT))
    from gateway.audit.log import AuditLog

    log = AuditLog(tmp_db)
    result = log.verify()
    assert result.ok, f"chain broken at {result.broken_at}: {result.detail}"
    assert result.checked > 5
    log.close()

    # Edit a past row the way an attacker covering their tracks would.
    db = sqlite3.connect(tmp_db)
    target = db.execute(
        "SELECT seq FROM events WHERE method = 'tools/call' ORDER BY seq LIMIT 1"
    ).fetchone()[0]
    db.execute(
        "UPDATE events SET payload = ? WHERE seq = ?",
        (json.dumps({"params": {"name": "innocent"}}), target),
    )
    db.commit()
    db.close()

    log = AuditLog(tmp_db)
    result = log.verify()
    assert not result.ok, "tampering went undetected"
    assert result.broken_at == target
    log.close()
    print(f"    tamper detected at seq {target}: {result.detail}")


def main() -> int:
    import tempfile

    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "audit.db")
    failures = 0
    for fn in (
        test_transport_is_transparent,
        test_audit_captures_session,
        test_chain_verifies_and_detects_tampering,
    ):
        try:
            fn(db)
            print(f"[pass] {fn.__name__}")
        except AssertionError as exc:
            failures += 1
            print(f"[FAIL] {fn.__name__}: {exc}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
