"""Minimal MCP client over stdio.

Enough of the protocol to drive scenarios: initialize, tools/list, tools/call.
Deliberately hand-rolled so the harness has no SDK version coupling, and so a
failure here is obviously ours.

The client does not know whether it is talking to a server directly or through
the gateway. That is the whole point: the same scenario runs in both
configurations, and the only difference is the command it spawns.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from typing import Any


class McpError(RuntimeError):
    """A JSON-RPC error response, including a gateway denial."""

    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.data = data


@dataclass
class ToolResult:
    content: str
    is_error: bool = False
    raw: dict = field(default_factory=dict)


class McpClient:
    def __init__(self, name: str, cmd: list[str], cwd: str | None = None):
        self.name = name
        self.cmd = cmd
        self._next_id = 0
        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            text=True,
            bufsize=1,
        )
        self._stderr: list[str] = []
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        self.tools: list[dict] = []

    def _drain_stderr(self) -> None:
        assert self._proc.stderr
        for line in self._proc.stderr:
            self._stderr.append(line.rstrip())

    def _call(self, method: str, params: dict | None = None) -> Any:
        assert self._proc.stdin and self._proc.stdout
        self._next_id += 1
        mid = self._next_id
        msg = {"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}}
        self._proc.stdin.write(json.dumps(msg) + "\n")
        self._proc.stdin.flush()

        while True:
            line = self._proc.stdout.readline()
            if not line:
                stderr = "\n".join(self._stderr[-10:])
                raise McpError(-1, f"{self.name}: server closed the connection\n{stderr}")
            try:
                reply = json.loads(line)
            except json.JSONDecodeError:
                continue
            if reply.get("id") != mid:
                continue  # notification or a reply we are not waiting on
            if "error" in reply:
                err = reply["error"]
                raise McpError(err.get("code", -1), err.get("message", ""), err.get("data"))
            return reply.get("result")

    def initialize(self) -> dict:
        result = self._call("initialize", {"protocolVersion": "2025-06-18"})
        assert self._proc.stdin
        self._proc.stdin.write(
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
        )
        self._proc.stdin.flush()
        return result

    def list_tools(self) -> list[dict]:
        self.tools = (self._call("tools/list") or {}).get("tools", [])
        return self.tools

    def call_tool(self, name: str, arguments: dict) -> ToolResult:
        result = self._call("tools/call", {"name": name, "arguments": arguments})
        blocks = (result or {}).get("content", [])
        text = "\n".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        return ToolResult(content=text, is_error=bool((result or {}).get("isError")), raw=result or {})

    def close(self) -> None:
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
            self._proc.wait(timeout=5)
        except Exception:
            self._proc.kill()
