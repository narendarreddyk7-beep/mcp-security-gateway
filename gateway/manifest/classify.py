"""Static analysis of the tool definitions a server advertises.

Two jobs. Classify each tool's capabilities, so policy can reason about what a
session can do rather than about tool names. And flag tools whose *description*
contains instructions aimed at the agent - an attack that happens at
tools/list time, before the user has typed anything, and which no amount of
prompt inspection will ever see.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

PRIVATE_READ = "private_read"
EGRESS = "egress"
STATE_CHANGE = "state_change"
EXECUTE = "execute"
SPEND = "spend"

# Heuristics for tools the policy file does not name explicitly. The policy map
# is authoritative; this is what the auditor uses to describe unknown tools and
# to warn when a server adds something nobody has classified.
HEURISTICS: list[tuple[str, str]] = [
    (r"\b(read|list|search|get|fetch|open)\b.*\b(note|file|message|mail|doc|event|record)", PRIVATE_READ),
    (r"\b(send|post|publish|upload|share|email|fetch_url|request|webhook)\b", EGRESS),
    (r"\b(write|create|update|delete|remove|move|set|schedule)\b", STATE_CHANGE),
    (r"\b(exec|run|shell|command|eval|script)\b", EXECUTE),
    (r"\b(pay|charge|purchase|order|transfer|invoice)\b", SPEND),
]

# Instruction-shaped language has no business in a tool description. A
# description explains what a tool does; it does not address the assistant.
DESCRIPTION_INJECTION = [
    (r"\b(ignore|disregard|override)\b.{0,40}\b(previous|prior|above|earlier|instruction)", "override_directive"),
    (r"\b(you must|you should|always|before (you|using|calling))\b", "imperative_to_agent"),
    (r"\b(do not (tell|mention|inform|reveal)|without (telling|informing)|silently)\b", "secrecy_directive"),
    (r"\b(assistant|agent|ai|model|system)\s*[:,]", "role_address"),
    (r"<\s*(system|important|instructions?)\s*>", "pseudo_tag"),
]

# Zero-width and direction-control characters hide text from a human reviewer
# while leaving it fully visible to the model.
INVISIBLE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")


@dataclass
class ToolFinding:
    tool: str
    kind: str
    detail: str


@dataclass
class ToolProfile:
    name: str
    capabilities: list[str] = field(default_factory=list)
    findings: list[ToolFinding] = field(default_factory=list)


def classify(name: str, description: str = "", schema: dict | None = None) -> list[str]:
    text = f"{name} {description}".lower()
    caps = {cap for pattern, cap in HEURISTICS if re.search(pattern, text)}
    return sorted(caps)


def inspect_description(name: str, description: str) -> list[ToolFinding]:
    out: list[ToolFinding] = []
    for pattern, kind in DESCRIPTION_INJECTION:
        if re.search(pattern, description or "", re.IGNORECASE):
            out.append(ToolFinding(name, "description_injection", kind))
    if INVISIBLE.search(description or ""):
        out.append(ToolFinding(name, "description_injection", "invisible_characters"))
    return out


def profile_tools(server: str, tools: list[dict], known: dict[str, list[str]]) -> list[ToolProfile]:
    profiles: list[ToolProfile] = []
    for tool in tools:
        name = tool.get("name", "")
        full = f"{server}.{name}"
        caps = known.get(full)
        findings = inspect_description(full, tool.get("description", ""))
        if caps is None:
            caps = classify(name, tool.get("description", ""), tool.get("inputSchema"))
            findings.append(
                ToolFinding(full, "unclassified", f"inferred {caps or ['none']}")
            )
        profiles.append(ToolProfile(name=full, capabilities=caps, findings=findings))
    return profiles


def dangerous_combinations(profiles: list[ToolProfile]) -> list[str]:
    """Capability pairs that together form a complete path, regardless of which
    tools hold them or whether they live on the same server."""
    caps = {c for p in profiles for c in p.capabilities}
    out = []
    if PRIVATE_READ in caps and EGRESS in caps:
        out.append("private_read + egress: complete exfiltration path")
    if PRIVATE_READ in caps and SPEND in caps:
        out.append("private_read + spend: data-informed financial action")
    if EXECUTE in caps and EGRESS in caps:
        out.append("execute + egress: remote code with a return channel")
    return out
