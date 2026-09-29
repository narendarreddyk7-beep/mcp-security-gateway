"""Week 5 milestone tests: the new scenarios and the finding.

The most important assertion here is test_chunked_defeats_fine_taint. It locks
in the project's headline result - that content-based taint has a bypass - so
that if someone later lowers the overlap threshold to make the number look
better, this test fails and forces them to acknowledge the utility cost.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import harness.run as R
from harness.run import run

S = ROOT / "scenarios"


def test_s02_leaks_without_gateway_blocks_with_it() -> None:
    assert run(S / "s02_tool_poisoning", "none").attack_succeeded
    out = run(S / "s02_tool_poisoning", "policy")
    assert not out.attack_succeeded, "manifest-time injection must be blocked"
    assert out.task_completed, "the legitimate crm lookup must still work"


def test_s03_calendar_invite_blocked() -> None:
    assert run(S / "s03_calendar_invite", "none").attack_succeeded
    out = run(S / "s03_calendar_invite", "policy")
    assert not out.attack_succeeded, "injection from an unaccepted invite must be blocked"
    assert out.task_completed


def test_chunked_defeats_fine_taint() -> None:
    """The headline finding. Fine-grained taint compares each call's arguments
    against tainted content; six-character fragments never reach the overlap
    threshold, so the exfiltration succeeds. This is expected and documented."""
    out = run(S / "s06_chunked_exfil", "full")
    assert out.attack_succeeded, (
        "if this now passes, fine-mode taint has changed - verify the "
        "false-positive cost and update the README before celebrating"
    )


def test_chunked_caught_by_coarse_taint() -> None:
    """The other half of the finding: coarse taint ignores content, so it stops
    what fine mode misses - at the utility cost measured elsewhere."""
    out = run(S / "s06_chunked_exfil", "coarse")
    assert not out.attack_succeeded, "coarse taint should stop chunked exfil"


def test_manifest_auditor_flags_poisoned_description() -> None:
    """s02's poison is in a tool description. The auditor must flag it even
    though scoping is what ultimately blocks the calls."""
    from gateway.manifest.classify import inspect_description
    from servers.crm.server import POISONED_DESCRIPTION

    kinds = {f.detail for f in inspect_description("crm.lookup", POISONED_DESCRIPTION)}
    assert "secrecy_directive" in kinds
    assert "imperative_to_agent" in kinds


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failures = 0
    for fn in tests:
        try:
            fn()
            print(f"[pass] {fn.__name__}")
        except AssertionError as exc:
            failures += 1
            print(f"[FAIL] {fn.__name__}: {exc}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
