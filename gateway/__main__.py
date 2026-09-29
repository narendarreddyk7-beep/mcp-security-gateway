"""CLI entry point.

    python -m gateway --db audit.db -- python servers/echo/server.py

Everything after `--` is the real MCP server command. The agent is configured
to launch this instead of the server itself.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from gateway.audit.log import AuditLog
from gateway.proxy.stdio import StdioProxy


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--" not in argv:
        print("usage: python -m gateway [--db PATH] -- SERVER_CMD ...", file=sys.stderr)
        return 2
    split = argv.index("--")
    own, server_cmd = argv[:split], argv[split + 1 :]
    if not server_cmd:
        print("error: no server command after --", file=sys.stderr)
        return 2

    ap = argparse.ArgumentParser(prog="gateway", add_help=False)
    ap.add_argument("--db", default="audit.db")
    ap.add_argument("--session", default=None)
    ap.add_argument("-h", "--help", action="help")
    args = ap.parse_args(own)

    audit = AuditLog(args.db)
    proxy = StdioProxy(server_cmd, audit, session_id=args.session)
    try:
        return asyncio.run(proxy.run())
    finally:
        audit.close()


if __name__ == "__main__":
    raise SystemExit(main())
