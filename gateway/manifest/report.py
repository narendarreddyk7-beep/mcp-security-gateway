"""Manifest report: what the connected servers can actually do.

    python -m gateway.manifest.report audit.db

Cross-server analysis lives here rather than in the proxy, because each gateway
process fronts one server and sees only its own tools. The audit log is the
shared surface, so the session-wide view is a report over the log rather than
something the proxy can compute inline.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict

from gateway.audit.log import AuditLog
from gateway.manifest.classify import ToolProfile, dangerous_combinations


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m gateway.manifest.report AUDIT_DB", file=sys.stderr)
        return 2

    log = AuditLog(sys.argv[1])
    manifests = [json.loads(e["payload"]) for e in log.events() if e["kind"] == "manifest"]
    if not manifests:
        print("no manifest events in this log")
        return 0

    profiles: list[ToolProfile] = []
    findings: list[dict] = []
    by_short: dict[str, list[str]] = defaultdict(list)

    for m in manifests:
        for tool in m["tools"]:
            profiles.append(ToolProfile(tool["name"], tool["capabilities"]))
            by_short[tool["name"].split(".", 1)[-1]].append(tool["name"])
        findings.extend(m.get("findings", []))

    print("tools and capabilities")
    for p in sorted(profiles, key=lambda p: p.name):
        print(f"  {p.name:<26} {', '.join(p.capabilities) or '-'}")

    combos = dangerous_combinations(profiles)
    print("\ndangerous capability combinations in this session")
    if combos:
        for c in combos:
            print(f"  {c}")
    else:
        print("  none")

    shadowed = {k: sorted(set(v)) for k, v in by_short.items() if len(set(v)) > 1}
    if shadowed:
        print("\nname collisions across servers")
        for short, full in shadowed.items():
            print(f"  {short}: {', '.join(full)}")

    if findings:
        print("\ntool definition findings")
        for f in findings:
            print(f"  [{f['kind']:<22}] {f['tool']}: {f['detail']}")

    log.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
