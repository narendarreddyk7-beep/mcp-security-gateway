"""Declarative policy: the authoritative decision-maker.

Only four actions exist - allow, deny, redact, require_approval - and that
list is deliberately short. Every task class ends in a default deny, so a tool
nobody thought about is refused rather than permitted.

Inspectors (week 5) will feed scores in here as signals. They never decide.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ALLOW, DENY, REDACT, APPROVE = "allow", "deny", "redact", "require_approval"
VALID_ACTIONS = {ALLOW, DENY, REDACT, APPROVE}


@dataclass
class Rule:
    id: str
    when: dict
    action: str
    reason: str = ""


@dataclass
class TaskClass:
    name: str
    tools: list[str] = field(default_factory=list)
    default: str = DENY


@dataclass
class Verdict:
    action: str
    rule_id: str
    reason: str

    @property
    def allowed(self) -> bool:
        return self.action == ALLOW


@dataclass
class Policy:
    capabilities: dict[str, list[str]] = field(default_factory=dict)
    task_classes: dict[str, TaskClass] = field(default_factory=dict)
    rules: list[Rule] = field(default_factory=list)
    limits: dict = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        classes = {
            name: TaskClass(name=name, tools=spec.get("tools", []),
                            default=spec.get("default", DENY))
            for name, spec in (raw.get("task_classes") or {}).items()
        }
        rules = []
        for spec in raw.get("rules") or []:
            action = spec.get("action")
            if action not in VALID_ACTIONS:
                raise ValueError(f"rule {spec.get('id')}: unknown action {action!r}")
            rules.append(Rule(id=spec["id"], when=spec.get("when") or {},
                              action=action, reason=spec.get("reason", "")))
        return cls(
            capabilities=raw.get("capabilities") or {},
            task_classes=classes,
            rules=rules,
            limits=raw.get("limits") or {},
        )

    def caps_for(self, tool: str) -> list[str]:
        return self.capabilities.get(tool, [])


class PolicyEngine:
    def __init__(self, policy: Policy, task_class: str):
        self.policy = policy
        self.task_class = task_class
        self.calls = 0

    def evaluate(self, tool: str, args: dict, signals: dict[str, Any] | None = None) -> Verdict:
        signals = signals or {}
        caps = self.policy.caps_for(tool)

        # 1. Scope. A task class names the tools its work needs; anything else
        #    is refused before any rule runs. This is the control that does not
        #    depend on recognising an attack.
        cls = self.policy.task_classes.get(self.task_class)
        if cls is None:
            return Verdict(DENY, "unknown_task_class",
                           f"no task class {self.task_class!r} in policy")
        if tool not in cls.tools:
            return Verdict(cls.default, "out_of_scope",
                           f"{tool} is not in task class {self.task_class!r}")

        # 2. Session limits.
        self.calls += 1
        max_calls = (self.policy.limits.get("session") or {}).get("max_calls")
        if max_calls and self.calls > max_calls:
            return Verdict(DENY, "session_call_limit", f"exceeded {max_calls} calls")

        # 3. Rules, in order, first match wins.
        for rule in self.policy.rules:
            if self._matches(rule.when, tool, caps, args, signals):
                return Verdict(rule.action, rule.id, rule.reason or rule.id)

        return Verdict(ALLOW, "in_scope", f"{tool} permitted for {self.task_class}")

    def _matches(self, when: dict, tool: str, caps: list[str],
                 args: dict, signals: dict) -> bool:
        if not when:
            return False
        for key, expected in when.items():
            if key == "tool" and tool != expected:
                return False
            elif key == "capability" and expected not in caps:
                return False
            elif key == "args_taint":
                # Signals carry a set of labels; a rule names one of them.
                if expected not in (signals.get("args_taint") or set()):
                    return False
            elif key == "signal":
                score = signals.get(expected)
                gte = when.get("gte")
                if score is None or (gte is not None and score < gte):
                    return False
            elif key == "gte":
                continue  # consumed by "signal"
            elif key not in ("tool", "capability", "args_taint", "signal"):
                return False  # unknown condition never matches, by design
        return True
