"""What the gateway decides to do with one frame.

A denial cannot simply drop the frame: the agent is blocking on a JSON-RPC
response and would hang. Every deny must synthesise an error back to the
caller, which is why a decision carries both a forward path and a return path.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

ALLOW = "allow"
DENY = "deny"
REDACT = "redact"
APPROVE = "require_approval"

# -32001 is in the implementation-defined server error range. Agents surface it
# as a tool error, which is what we want: the model learns the call failed
# without learning how to get around the gateway.
DENY_CODE = -32001


@dataclass
class Decision:
    action: str
    forward: bytes | None = None
    respond: bytes | None = None
    rule_id: str | None = None
    reason: str | None = None

    @property
    def blocked(self) -> bool:
        return self.forward is None


def allow(raw: bytes, rule_id: str | None = None) -> Decision:
    return Decision(action=ALLOW, forward=raw, rule_id=rule_id)


def deny(msg_id: str | None, reason: str, rule_id: str, tool: str | None = None) -> Decision:
    body = {
        "jsonrpc": "2.0",
        "id": _coerce_id(msg_id),
        "error": {
            "code": DENY_CODE,
            "message": f"blocked by gateway policy: {reason}",
            "data": {"rule": rule_id, "tool": tool},
        },
    }
    return Decision(
        action=DENY,
        forward=None,
        respond=json.dumps(body).encode() + b"\n",
        rule_id=rule_id,
        reason=reason,
    )


def _coerce_id(msg_id: str | None):
    if msg_id is None:
        return None
    try:
        return int(msg_id)
    except (TypeError, ValueError):
        return msg_id
