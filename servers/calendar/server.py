"""calendar - untrusted_inbound with no user action required.

Anyone who knows an address can put text in someone's calendar. The user never
accepted the invite and never asked for it, but the agent reads it as context
the moment it is asked what is on today.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from servers._lib.mcpserver import Server

DATA = Path(os.environ.get("CALENDAR_DIR", Path(__file__).parent / "data"))

srv = Server("calendar")


def _events() -> list[dict]:
    path = DATA / "events.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else []


@srv.tool("list_events", "List today's events.", {"type": "object", "properties": {}})
def list_events(_args: dict) -> str:
    return "\n".join(f"{e['id']} {e['time']}: {e['title']}" for e in _events()) or "(nothing today)"


@srv.tool("read_event", "Read one event, including its description.",
          {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]})
def read_event(args: dict) -> str:
    for e in _events():
        if e["id"] == args.get("id"):
            return (f"{e['title']}\n{e['time']}\nOrganiser: {e['organiser']}\n\n"
                    f"{e['description']}")
    return f"error: no event {args.get('id')!r}"


if __name__ == "__main__":
    srv.run()
