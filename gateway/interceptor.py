"""The seam where security plugs into the transport.

The proxy knows nothing about policy; it hands every frame here and does what
the returned Decision says. That separation is the claim the project makes -
the security layer cannot corrupt the protocol, because it never touches the
bytes it forwards.
"""

from __future__ import annotations

import sys
from typing import Callable

from gateway import decision as D
from gateway.audit.log import AuditLog
from gateway.manifest.classify import dangerous_combinations, profile_tools
from gateway.policy.engine import ALLOW, APPROVE, DENY, REDACT, PolicyEngine
from gateway.proxy.jsonrpc import CLIENT_TO_SERVER, SERVER_TO_CLIENT, Message
from gateway.taint.store import SENSITIVE, UNTRUSTED, TaintStore

PRIVATE_READ = "private_read"
UNTRUSTED_INBOUND = "untrusted_inbound"
EGRESS = "egress"


class ApprovalBroker:
    """Human gate. Fails closed: a timeout or an unreadable terminal denies.

    Modes exist so the benchmark stays deterministic. `prompt` is for demos;
    `auto-deny` is the default because an approval step that silently approves
    is not a control.
    """

    def __init__(self, mode: str = "auto-deny", timeout_s: int = 60):
        self.mode = mode
        self.timeout_s = timeout_s

    def ask(self, tool: str, args: dict, reason: str) -> bool:
        if self.mode == "auto-approve":
            return True
        if self.mode != "prompt":
            return False
        if not sys.stderr.isatty():
            return False
        print(
            f"\n[gateway] approval required\n  tool: {tool}\n  reason: {reason}"
            f"\n  args: {args}\n  approve? [y/N] ",
            file=sys.stderr,
            end="",
            flush=True,
        )
        try:
            with open("/dev/tty") as tty:
                return tty.readline().strip().lower() in ("y", "yes")
        except OSError:
            return False


class PolicyInterceptor:
    def __init__(
        self,
        audit: AuditLog,
        session_id: str,
        engine: PolicyEngine | None,
        approvals: ApprovalBroker | None = None,
        server_name: str | None = None,
        taint: TaintStore | None = None,
        taint_mode: str = "off",
    ):
        self.audit = audit
        self.session_id = session_id
        self.engine = engine
        self.approvals = approvals or ApprovalBroker()
        self.server_name = server_name
        self.taint = taint
        self.taint_mode = taint_mode
        self._pending_list_ids: set[str] = set()
        # msg_id -> tool name, so a result can be attributed to the tool that
        # produced it. Without this the gateway cannot tell whether content
        # coming back is private, untrusted, or neither.
        self._pending_calls: dict[str, str] = {}

    async def __call__(self, direction: str, message: Message) -> D.Decision:
        if direction == SERVER_TO_CLIENT:
            self._observe_server(message)
            self._label_result(message)
            return D.allow(message.raw)

        if message.method == "tools/list" and message.msg_id:
            self._pending_list_ids.add(message.msg_id)
        if not message.is_tool_call:
            return D.allow(message.raw)

        tool = f"{self.server_name or '?'}.{message.tool_name}"
        args = message.tool_args or {}
        if message.msg_id:
            self._pending_calls[message.msg_id] = tool

        if self.engine is None:
            return D.allow(message.raw)  # transparent mode

        verdict = self.engine.evaluate(tool, args, self._signals(tool, args))

        if verdict.action == APPROVE:
            approved = self.approvals.ask(tool, args, verdict.reason)
            self.audit.append(
                session_id=self.session_id,
                direction="gateway",
                kind="approval",
                method="tools/call",
                payload={"tool": tool, "approved": approved, "reason": verdict.reason},
                verdict="approved" if approved else "denied",
                rule_id=verdict.rule_id,
            )
            if not approved:
                return D.deny(message.msg_id, f"{verdict.reason} (not approved)",
                              verdict.rule_id, tool)
            return D.allow(message.raw, verdict.rule_id)

        if verdict.action in (DENY, REDACT):
            # REDACT is accepted by the schema but not yet implemented; denying
            # is the safe reading of an unimplemented action, and the audit
            # record says which rule asked for what.
            return D.deny(message.msg_id, verdict.reason, verdict.rule_id, tool)

        return D.allow(message.raw, verdict.rule_id)

    def _signals(self, tool: str, args: dict) -> dict:
        """Evidence for the policy engine. Signals never decide anything."""
        if self.taint is None or self.taint_mode == "off":
            return {}
        caps = self.engine.policy.caps_for(tool) if self.engine else []
        if EGRESS not in caps:
            # Taint only matters at a sink. Checking every call would cost
            # latency for no decision.
            return {}
        labels = self.taint.labels_in(self.session_id, args, self.taint_mode)
        return {"args_taint": labels}

    def _label_result(self, message: Message) -> None:
        """Label content on its way back, by the capabilities of the tool that
        produced it. This is the source end of the dataflow."""
        if self.taint is None or self.taint_mode == "off" or self.engine is None:
            return
        tool = self._pending_calls.pop(message.msg_id, None) if message.msg_id else None
        if tool is None:
            return
        result = (message.parsed or {}).get("result") if isinstance(message.parsed, dict) else None
        if not isinstance(result, dict):
            return
        text = "\n".join(
            b.get("text", "") for b in result.get("content", []) if isinstance(b, dict)
        )
        if not text:
            return

        caps = self.engine.policy.caps_for(tool)
        for cap, label in ((PRIVATE_READ, SENSITIVE), (UNTRUSTED_INBOUND, UNTRUSTED)):
            if cap in caps:
                self.taint.record(
                    self.session_id, self.server_name or "?", tool, label, text
                )
                self.audit.append(
                    session_id=self.session_id,
                    direction="gateway",
                    kind="taint",
                    method="tools/call",
                    payload={"tool": tool, "label": label, "bytes": len(text)},
                    verdict="labelled",
                )

    def _observe_server(self, message: Message) -> None:
        """Learn the server's name, and audit its tool manifest on arrival."""
        result = (message.parsed or {}).get("result") if isinstance(message.parsed, dict) else None
        if not isinstance(result, dict):
            return

        info = result.get("serverInfo")
        if isinstance(info, dict) and info.get("name") and not self.server_name:
            self.server_name = info["name"]

        if message.msg_id in self._pending_list_ids:
            self._pending_list_ids.discard(message.msg_id)
            tools = result.get("tools") or []
            known = self.engine.policy.capabilities if self.engine else {}
            profiles = profile_tools(self.server_name or "?", tools, known)
            findings = [
                {"tool": f.tool, "kind": f.kind, "detail": f.detail}
                for p in profiles for f in p.findings
            ]
            self.audit.append(
                session_id=self.session_id,
                direction="gateway",
                kind="manifest",
                method="tools/list",
                payload={
                    "server": self.server_name,
                    "tools": [
                        {"name": p.name, "capabilities": p.capabilities} for p in profiles
                    ],
                    "findings": findings,
                    "combinations": dangerous_combinations(profiles),
                },
                verdict="flagged" if findings else "clean",
            )


async def transparent(direction: str, message: Message) -> D.Decision:
    return D.allow(message.raw)
