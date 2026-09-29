"""CLI entry point.

    # transparent: record everything, deny nothing
    python -m gateway --db audit.db -- python3 servers/notes/server.py

    # enforcing
    python -m gateway --db audit.db --policy policy/default.yaml \
        --task-class research -- python3 servers/web/server.py

Everything after `--` is the real MCP server command. The agent is configured
to launch this instead of the server itself.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from gateway.audit.log import AuditLog
from gateway.interceptor import ApprovalBroker, PolicyInterceptor
from gateway.policy.engine import Policy, PolicyEngine
from gateway.proxy.stdio import StdioProxy
from gateway.taint.store import TaintStore


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--" not in argv:
        print("usage: python -m gateway [options] -- SERVER_CMD ...", file=sys.stderr)
        return 2
    split = argv.index("--")
    own, server_cmd = argv[:split], argv[split + 1 :]
    if not server_cmd:
        print("error: no server command after --", file=sys.stderr)
        return 2

    ap = argparse.ArgumentParser(prog="gateway", add_help=False)
    ap.add_argument("--db", default="audit.db")
    ap.add_argument("--session", default=None)
    ap.add_argument("--policy", default=None,
                    help="policy file; omit for transparent mode")
    ap.add_argument("--task-class", default=None,
                    help="task class the session is scoped to")
    ap.add_argument("--server-name", default=None,
                    help="override; normally learned from the initialize reply")
    ap.add_argument("--approval", default="auto-deny",
                    choices=["auto-deny", "auto-approve", "prompt"])
    ap.add_argument("--taint", default="off", choices=["off", "fine", "coarse"],
                    help="dataflow tracking; requires a shared --session "
                         "across every gateway in the session")
    ap.add_argument("-h", "--help", action="help")
    args = ap.parse_args(own)

    engine = None
    if args.policy:
        if not args.task_class:
            print("error: --policy requires --task-class", file=sys.stderr)
            return 2
        engine = PolicyEngine(Policy.load(args.policy), args.task_class)

    if args.taint != "off" and not args.session:
        # Taint is shared state keyed by session. Without a shared id each
        # gateway would label into its own island and the tracker would
        # silently do nothing - worse than being switched off.
        print("error: --taint requires --session shared across all gateways",
              file=sys.stderr)
        return 2

    audit = AuditLog(args.db)
    taint = TaintStore(args.db) if args.taint != "off" else None
    proxy = StdioProxy(server_cmd, audit, session_id=args.session or None)
    proxy.interceptor = PolicyInterceptor(
        audit=audit,
        session_id=proxy.session_id,
        engine=engine,
        approvals=ApprovalBroker(args.approval, timeout_s=60),
        server_name=args.server_name,
        taint=taint,
        taint_mode=args.taint,
    )
    try:
        return asyncio.run(proxy.run())
    finally:
        audit.close()
        if taint:
            taint.close()


if __name__ == "__main__":
    raise SystemExit(main())
