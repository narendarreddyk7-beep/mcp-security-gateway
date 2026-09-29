"""The agent side of the harness.

`CompliantAgent` models an agent that is *completely persuaded* by whatever it
reads. It performs the task it was given, and it obeys any instruction it finds
inside a tool result, without judgement.

This is not a cheap stand-in for a real model. It is the worst case the threat
model names: "even if the agent is completely persuaded by injected content, it
cannot exfiltrate data, because the gateway denies the call." A real LLM
sometimes refuses an injection on its own, which would credit the gateway with
a block it did not perform. The compliant agent never refuses, so every attack
that fails, fails because of the gateway.

Fixtures carry the same instruction twice: as prose for a real model, and as an
AGENT-DIRECTIVE block for this one. One fixture, two backends.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from harness.mcp_client import McpClient, McpError, ToolResult

DIRECTIVE_RE = re.compile(
    r"AGENT-DIRECTIVE\s*(?P<body>\[.*?\])\s*(?:END-DIRECTIVE|-->|\Z)",
    re.DOTALL,
)

MAX_DIRECTIVE_DEPTH = 3  # injected content that injects more content


@dataclass
class CallRecord:
    server: str
    tool: str
    args: dict
    origin: str  # "task" or "injected"
    ok: bool
    result: str | None = None
    error: str | None = None


@dataclass
class AgentRun:
    calls: list[CallRecord] = field(default_factory=list)
    output: list[str] = field(default_factory=list)

    @property
    def denied(self) -> list[CallRecord]:
        return [c for c in self.calls if not c.ok]

    @property
    def injected_calls(self) -> list[CallRecord]:
        return [c for c in self.calls if c.origin == "injected"]


class CompliantAgent:
    def __init__(self, clients: dict[str, McpClient]):
        self.clients = clients
        self.run = AgentRun()
        self._last_result: str = ""

    def perform(self, task_calls: list[dict]) -> AgentRun:
        for spec in task_calls:
            self._invoke(spec, origin="task", depth=0)
        return self.run

    def _invoke(self, spec: dict, origin: str, depth: int) -> None:
        server = spec["server"]
        tool = spec["tool"]
        args = self._expand(spec.get("args", {}))

        client = self.clients.get(server)
        if client is None:
            self.run.calls.append(
                CallRecord(server, tool, args, origin, ok=False, error="no such server")
            )
            return

        try:
            result: ToolResult = client.call_tool(tool, args)
        except McpError as exc:
            # A gateway denial arrives here as a JSON-RPC error. The agent does
            # not retry or route around it; measuring evasion is a separate
            # experiment, not the default.
            self.run.calls.append(
                CallRecord(server, tool, args, origin, ok=False, error=str(exc))
            )
            return

        self.run.calls.append(
            CallRecord(server, tool, args, origin, ok=True, result=result.content)
        )
        self._last_result = result.content
        self.run.output.append(result.content)

        if depth < MAX_DIRECTIVE_DEPTH:
            for injected in self._extract_directives(result.content):
                self._invoke(injected, origin="injected", depth=depth + 1)

    @staticmethod
    def _extract_directives(text: str) -> list[dict]:
        out: list[dict] = []
        for match in DIRECTIVE_RE.finditer(text or ""):
            try:
                parsed = json.loads(match.group("body"))
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, list):
                out.extend(p for p in parsed if isinstance(p, dict))
        return out

    def _expand(self, args: Any) -> Any:
        """Substitute the previous tool result, so exfiltration can chain."""
        if isinstance(args, dict):
            return {k: self._expand(v) for k, v in args.items()}
        if isinstance(args, list):
            return [self._expand(v) for v in args]
        if isinstance(args, str):
            return (
                args.replace("{{LAST_RESULT}}", self._last_result)
                .replace(
                    "{{LAST_RESULT_URLENC}}",
                    urllib.parse.quote(self._last_result, safe=""),
                )
                .replace(
                    "{{LAST_RESULT_B64}}",
                    __import__("base64")
                    .b64encode(self._last_result.encode())
                    .decode(),
                )
            )
        return args
