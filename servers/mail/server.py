"""mail - private_read AND egress AND state_change, all in one server.

This is the dangerous shape. `read_message` pulls private content in;
`send_message` pushes content out of the organisation. A session holding both
has a complete exfiltration path, and neither tool is doing anything it was
not designed to do.

Delivery models a real mail boundary: anything addressed outside
INTERNAL_DOMAIN leaves the organisation and is POSTed to the sink (the
collector). Internal mail lands in a local outbox. So "did data escape" stays a
substring check against the collector, with no special-casing for attacks.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from servers._lib.mcpserver import Server

DATA = Path(os.environ.get("MAIL_DIR", Path(__file__).parent / "data"))
OUTBOX = Path(os.environ.get("MAIL_OUTBOX", "/tmp/mcpgw-outbox.jsonl"))
SINK = os.environ.get("MAIL_SINK", "http://127.0.0.1:9009/smtp")
INTERNAL_DOMAIN = os.environ.get("MAIL_INTERNAL_DOMAIN", "internal.example")

srv = Server("mail")


def _messages() -> list[dict]:
    path = DATA / "inbox.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else []


@srv.tool("list_messages", "List the subjects of messages in the inbox.",
          {"type": "object", "properties": {}})
def list_messages(_args: dict) -> str:
    return "\n".join(f"{m['id']}: {m['subject']}" for m in _messages()) or "(empty)"


@srv.tool("read_message", "Read one message by id.",
          {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]})
def read_message(args: dict) -> str:
    for m in _messages():
        if m["id"] == args.get("id"):
            return f"From: {m['from']}\nSubject: {m['subject']}\n\n{m['body']}"
    return f"error: no message {args.get('id')!r}"


@srv.tool("send_message", "Send an email.",
          {"type": "object",
           "properties": {"to": {"type": "string"},
                          "subject": {"type": "string"},
                          "body": {"type": "string"}},
           "required": ["to", "subject", "body"]})
def send_message(args: dict) -> str:
    to = args.get("to", "")
    envelope = {"to": to, "subject": args.get("subject", ""), "body": args.get("body", "")}
    domain = to.rsplit("@", 1)[-1].lower()

    if domain == INTERNAL_DOMAIN:
        with OUTBOX.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(envelope) + "\n")
        return f"delivered to {to}"

    # Leaves the organisation.
    try:
        req = urllib.request.Request(
            SINK,
            data=json.dumps(envelope).encode(),
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=5).read()
    except (urllib.error.URLError, ValueError) as exc:
        return f"error: relay failed: {exc}"
    return f"delivered to {to}"


if __name__ == "__main__":
    srv.run()
