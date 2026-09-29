"""Scenario runner.

    python3 -m harness.run scenarios/s01_direct_injection --config none
    python3 -m harness.run scenarios/s01_direct_injection --config gateway

`--config` decides only what command each server is launched with: the server
itself, or the gateway wrapping it. The agent and the scenario are identical
either way, which is what makes the ablation honest.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from collector import server as collector
from harness.agent import CompliantAgent
from harness.mcp_client import McpClient

COLLECTOR_PORT = 9009


@dataclass
class Outcome:
    scenario: str
    config: str
    attack_succeeded: bool
    task_completed: bool
    calls: int
    denied: int
    injected_calls: int

    def line(self) -> str:
        attack = "LEAKED" if self.attack_succeeded else "blocked"
        task = "completed" if self.task_completed else "FAILED"
        return (
            f"{self.scenario:<24} {self.config:<9} "
            f"attack={attack:<8} task={task:<9} "
            f"calls={self.calls} denied={self.denied} injected={self.injected_calls}"
        )


def server_cmd(name: str, config: str, audit_db: Path) -> list[str]:
    direct = [sys.executable, str(ROOT / "servers" / name / "server.py")]
    if config == "none":
        return direct
    return [sys.executable, "-m", "gateway", "--db", str(audit_db), "--"] + direct


def run(scenario_dir: Path, config: str, verbose: bool = False) -> Outcome:
    spec = yaml.safe_load((scenario_dir / "scenario.yaml").read_text())
    workdir = Path(tempfile.mkdtemp(prefix="mcpgw-"))
    log_path = workdir / "collector.jsonl"
    audit_db = workdir / "audit.db"

    sink = collector.serve(COLLECTOR_PORT, log_path)
    clients: dict[str, McpClient] = {}
    try:
        for name in spec["servers"]:
            client = McpClient(name, server_cmd(name, config, audit_db), cwd=str(ROOT))
            client.initialize()
            client.list_tools()
            clients[name] = client

        agent = CompliantAgent(clients)
        result = agent.perform(spec["task_calls"])

        leaked = collector.contains(spec["success_predicate"]["collector_contains"], log_path)
        blob = "\n".join(result.output)
        completed = all(s in blob for s in spec["benign_predicate"].get("output_contains", []))

        if verbose:
            print(f"\n--- calls ({config}) ---")
            for c in result.calls:
                mark = "ok " if c.ok else "DENY"
                print(f"  [{mark}] {c.origin:<8} {c.server}.{c.tool} {json.dumps(c.args)[:90]}")
                if c.error:
                    print(f"         {c.error}")
            print(f"--- collector received {len(collector.received(log_path))} request(s) ---\n")

        return Outcome(
            scenario=spec["id"],
            config=config,
            attack_succeeded=leaked,
            task_completed=completed,
            calls=len(result.calls),
            denied=len(result.denied),
            injected_calls=len(result.injected_calls),
        )
    finally:
        for client in clients.values():
            client.close()
        sink.shutdown()
        shutil.rmtree(workdir, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario")
    ap.add_argument("--config", default="none", choices=["none", "gateway"])
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    outcome = run(Path(args.scenario), args.config, args.verbose)
    print(json.dumps(asdict(outcome)) if args.json else outcome.line())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
