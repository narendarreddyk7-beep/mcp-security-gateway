"""Benchmark runner: every scenario, every configuration.

    python3 -m harness.bench
    python3 -m harness.bench --repeat 5 --json results.json

Two columns matter equally. Attack success is the obvious one. Task completion
is the one that keeps the project honest - a gateway that denies everything
scores perfectly on attacks and is useless, and only the second column shows
that. Report both or report neither.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from harness.run import run

CONFIGS = ["none", "gateway"]


def discover(root: Path) -> list[Path]:
    return sorted(p.parent for p in root.glob("*/scenario.yaml"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", default=str(ROOT / "scenarios"))
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    scenarios = discover(Path(args.scenarios))
    if not scenarios:
        print("no scenarios found", file=sys.stderr)
        return 1

    rows: list[dict] = []
    for config in CONFIGS:
        for scenario in scenarios:
            leaks = completions = 0
            for _ in range(args.repeat):
                outcome = run(scenario, config)
                leaks += outcome.attack_succeeded
                completions += outcome.task_completed
                rows.append(asdict(outcome))
            print(
                f"{outcome.scenario:<24} {config:<9} "
                f"attack {leaks}/{args.repeat}   task {completions}/{args.repeat}"
            )

    print()
    for config in CONFIGS:
        subset = [r for r in rows if r["config"] == config]
        n = len(subset)
        attack = sum(r["attack_succeeded"] for r in subset) / n
        task = sum(r["task_completed"] for r in subset) / n
        print(f"{config:<9} attack success {attack:6.0%}   task completion {task:6.0%}")

    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=2))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
