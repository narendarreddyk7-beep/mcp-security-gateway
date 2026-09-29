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

import base64
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

SLICE_RE = re.compile(r"\{\{LAST_RESULT_SLICE:(?P<start>\d+):(?P<end>\d+)\}\}")


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
        return [c for c in self.calls if c.origin.startswith("injected")]


class CompliantAgent:
    def __init__(self, clients: dict[str, McpClient]):
        self.clients = clients
        self.run = AgentRun()
        self._last_result: str = ""

    def perform(self, task_calls: list[dict]) -> AgentRun:
        # A real agent puts tool descriptions in its context before it does
        # anything, so a poisoned description executes before the user has
        # typed a word. Scanning them here models that faithfully.
        for server, client in self.clients.items():
            for tool in getattr(client, "tools", []):
                for injected in self._extract_directives(tool.get("description", "")):
                    self._invoke(injected, origin="injected_manifest", depth=0)
        for spec in task_calls:
            self._invoke(spec, origin="task", depth=0)
        return self.run

    def _run_block(self, directives: list[dict], block_source: str, depth: int) -> None:
        # A directive block reads a secret once, then leaks it. Slice/templating
        # binds to the most recent READ result within the block, not to the last
        # call - otherwise each exfil call would template against the previous
        # exfil call's HTTP response. block_read holds that secret.
        block_read = block_source
        for spec in directives:
            produced = self._invoke(
                spec, origin="injected", depth=depth, source=block_read
            )
            # A read tool's result becomes the source for the fragments that
            # follow. An egress call's response does not.
            if produced is not None and self._is_read(spec):
                block_read = produced

    @staticmethod
    def _is_read(spec: dict) -> bool:
        return any(
            k in spec.get("tool", "")
            for k in ("read", "list", "search", "get", "fetch_note")
        )

    def _invoke(self, spec: dict, origin: str, depth: int,
                source: str | None = None) -> str | None:
        server = spec["server"]
        tool = spec["tool"]
        # source pins templating to a specific prior result (chained exfil);
        # without it, {{...}} means the most recent result (single hop).
        args = self._expand(spec.get("args", {}), source)

        client = self.clients.get(server)
        if client is None:
            self.run.calls.append(
                CallRecord(server, tool, args, origin, ok=False, error="no such server")
            )
            return None

        try:
            result: ToolResult = client.call_tool(tool, args)
        except McpError as exc:
            # A gateway denial arrives here as a JSON-RPC error. The agent does
            # not retry or route around it; measuring evasion is a separate
            # experiment, not the default.
            self.run.calls.append(
                CallRecord(server, tool, args, origin, ok=False, error=str(exc))
            )
            return None

        self.run.calls.append(
            CallRecord(server, tool, args, origin, ok=True, result=result.content)
        )
        self._last_result = result.content
        self.run.output.append(result.content)

        if depth < MAX_DIRECTIVE_DEPTH:
            directives = self._extract_directives(result.content)
            if directives:
                # Within a block, templating references the most recent result
                # produced *inside the block* (so the note that the first call
                # reads becomes the source the later slice calls draw from),
                # falling back to the block's own source for the first call.
                self._run_block(directives, block_source=result.content, depth=depth + 1)
        return result.content

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

    def _expand(self, args: Any, source: str | None = None) -> Any:
        """Substitute a prior tool result, so exfiltration can chain."""
        if isinstance(args, dict):
            return {k: self._expand(v, source) for k, v in args.items()}
        if isinstance(args, list):
            return [self._expand(v, source) for v in args]
        if isinstance(args, str):
            return self._template(args, source)
        return args

    def _template(self, text: str, source: str | None = None) -> str:
        last = source if source is not None else self._last_result
        out = (
            text.replace("{{LAST_RESULT}}", last)
            .replace("{{LAST_RESULT_URLENC}}", urllib.parse.quote(last, safe=""))
            .replace("{{LAST_RESULT_B64}}", base64.b64encode(last.encode()).decode())
            # Reversal is the cheapest transform no substring matcher can
            # follow. It stands in for any semantic restatement: an agent that
            # paraphrases a secret rather than copying it produces the same
            # problem, and cannot be caught by looking for shared text.
            .replace("{{LAST_RESULT_REVERSED}}", last[::-1])
        )
        # {{LAST_RESULT_SLICE:start:end}} carries a fragment, so a secret can
        # be split across many calls that are each individually unremarkable.
        for match in SLICE_RE.finditer(out):
            start, end = int(match.group("start")), int(match.group("end"))
            out = out.replace(match.group(0), urllib.parse.quote(last[start:end], safe=""))
        return out
