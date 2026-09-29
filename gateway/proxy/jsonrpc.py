"""Minimal JSON-RPC 2.0 classification.

The proxy parses messages only to describe them for the audit log and, later,
for policy. Forwarding always uses the original bytes, never a re-serialisation
of this parse, so a quirk in our parser can never corrupt the stream.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

CLIENT_TO_SERVER = "client_to_server"
SERVER_TO_CLIENT = "server_to_client"


@dataclass
class Message:
    raw: bytes
    parsed: Any | None
    kind: str  # request | response | error | notification | batch | unparsable
    method: str | None = None
    msg_id: str | None = None

    @property
    def is_tool_call(self) -> bool:
        return self.method == "tools/call"

    @property
    def tool_name(self) -> str | None:
        if not self.is_tool_call or not isinstance(self.parsed, dict):
            return None
        params = self.parsed.get("params")
        return params.get("name") if isinstance(params, dict) else None

    @property
    def tool_args(self) -> dict | None:
        if not self.is_tool_call or not isinstance(self.parsed, dict):
            return None
        params = self.parsed.get("params")
        if not isinstance(params, dict):
            return None
        args = params.get("arguments")
        return args if isinstance(args, dict) else None

    def audit_payload(self) -> Any:
        """What goes in the log. Unparsable frames are recorded as text so a
        malformed message is still evidence rather than a silent gap."""
        if self.parsed is not None:
            return self.parsed
        return {"unparsable": self.raw.decode("utf-8", errors="replace")}


def _as_id(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def parse(raw: bytes) -> Message:
    text = raw.strip()
    if not text:
        return Message(raw=raw, parsed=None, kind="unparsable")
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return Message(raw=raw, parsed=None, kind="unparsable")

    if isinstance(obj, list):
        methods = [m.get("method") for m in obj if isinstance(m, dict)]
        return Message(
            raw=raw,
            parsed=obj,
            kind="batch",
            method=",".join(m for m in methods if m) or None,
        )

    if not isinstance(obj, dict):
        return Message(raw=raw, parsed=obj, kind="unparsable")

    method = obj.get("method")
    has_id = "id" in obj and obj["id"] is not None

    if method is not None:
        kind = "request" if has_id else "notification"
        return Message(
            raw=raw, parsed=obj, kind=kind, method=method, msg_id=_as_id(obj.get("id"))
        )

    if "error" in obj:
        return Message(raw=raw, parsed=obj, kind="error", msg_id=_as_id(obj.get("id")))

    if "result" in obj:
        return Message(raw=raw, parsed=obj, kind="response", msg_id=_as_id(obj.get("id")))

    return Message(raw=raw, parsed=obj, kind="unparsable", msg_id=_as_id(obj.get("id")))
