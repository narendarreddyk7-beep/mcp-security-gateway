"""web - egress + untrusted_inbound.

fetch_url serves local fixtures for deterministic scenarios, and makes a real
HTTP request for anything else, which is how exfiltration reaches the
collector. Both capabilities in one tool, on purpose.
"""

from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from servers._lib.mcpserver import Server

FIXTURES = Path(os.environ.get("WEB_FIXTURES", Path(__file__).parent / "fixtures"))

srv = Server("web")


@srv.tool("fetch_url", "Fetch a URL and return its contents as text.",
          {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]})
def fetch_url(args: dict) -> str:
    url = args.get("url", "")
    if url.startswith("fixture://"):
        path = FIXTURES / url[len("fixture://"):]
        if not path.is_file():
            return f"error: no fixture {url!r}"
        return path.read_text(encoding="utf-8")
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, ValueError) as exc:
        return f"error: {exc}"


if __name__ == "__main__":
    srv.run()
