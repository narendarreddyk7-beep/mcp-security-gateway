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

# The ablation. Each row isolates one layer's contribution.
#   none   - no gateway at all
#   audit  - transparent proxy: records everything, denies nothing
#   policy - manifest auditor + capability scoping + approval broker
#   full   - policy + fine-grained taint (content actually present in args)
#   coarse - policy + coarse taint (session-wide, unevadable, blunter)
# The last two ship together on purpose. Neither dominates, and the gap
# between them is a real open trade-off rather than something to hide.
CONFIGS = ["none", "audit", "policy", "full", "coarse"]


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
            attack_col = (
                "   n/a  " if outcome.kind == "benign"
                else f"attack {leaks}/{args.repeat}"
            )
            print(
                f"{outcome.scenario:<24} {config:<9} {attack_col}   "
                f"task {completions}/{args.repeat}"
            )
        print()

    # Four columns, because three of them can be gamed on their own.
    # "task under attack" is the one that separates fine from coarse taint:
    # both stop the exfiltration, but coarse also kills the real email the
    # user asked for in the same session.
    print(f"{'config':<9} {'attack success':>15} {'benign done':>13} "
          f"{'false pos':>11} {'task under attack':>19}")
    for config in CONFIGS:
        attacks = [r for r in rows if r["config"] == config and r["kind"] == "attack"]
        benign = [r for r in rows if r["config"] == config and r["kind"] == "benign"]
        asr = sum(r["attack_succeeded"] for r in attacks) / max(len(attacks), 1)
        bcr = sum(r["task_completed"] for r in benign) / max(len(benign), 1)
        tua = sum(r["task_completed"] for r in attacks) / max(len(attacks), 1)
        print(f"{config:<9} {asr:>14.0%} {bcr:>12.0%} {1 - bcr:>10.0%} {tua:>18.0%}")

    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=2))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
