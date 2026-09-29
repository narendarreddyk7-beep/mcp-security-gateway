"""Shared plumbing for the deliberately vulnerable servers.

Hand-rolled line-based JSON-RPC. These servers exist to be exploited, so they
stay small and obvious - no SDK, no cleverness, nothing to hide behind.
"""

from __future__ import annotations

import json
import sys
from typing import Callable


class Server:
    def __init__(self, name: str, version: str = "0.1.0"):
        self.name = name
        self.version = version
        self._tools: list[dict] = []
        self._handlers: dict[str, Callable[[dict], str]] = {}

    def tool(self, name: str, description: str, schema: dict):
        def decorate(fn: Callable[[dict], str]):
            self._tools.append(
                {"name": name, "description": description, "inputSchema": schema}
            )
            self._handlers[name] = fn
            return fn

        return decorate

    def _dispatch(self, msg: dict):
        method, mid = msg.get("method"), msg.get("id")
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": self.name, "version": self.version},
            }
        elif method == "tools/list":
            result = {"tools": self._tools}
        elif method == "tools/call":
            params = msg.get("params") or {}
            fn = self._handlers.get(params.get("name"))
            if fn is None:
                return {
                    "jsonrpc": "2.0",
                    "id": mid,
                    "error": {"code": -32602, "message": f"no tool {params.get('name')}"},
                }
            try:
                text = fn(params.get("arguments") or {})
                result = {"content": [{"type": "text", "text": text}], "isError": False}
            except Exception as exc:
                result = {
                    "content": [{"type": "text", "text": f"error: {exc}"}],
                    "isError": True,
                }
        elif mid is None:
            return None
        else:
            return {
                "jsonrpc": "2.0",
                "id": mid,
                "error": {"code": -32601, "message": f"unknown method {method}"},
            }
        return None if mid is None else {"jsonrpc": "2.0", "id": mid, "result": result}

    def run(self) -> None:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            reply = self._dispatch(msg)
            if reply is not None:
                sys.stdout.write(json.dumps(reply) + "\n")
                sys.stdout.flush()
