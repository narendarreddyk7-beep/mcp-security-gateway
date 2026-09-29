"""Week 4 milestone tests: taint tracking."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gateway.taint.store import SENSITIVE, UNTRUSTED, TaintStore, normalise, overlaps

SECRET = "access key id: AKIA2E0XAMPLE7WQ4RZP secret: CANARY-7f3a91-do-not-share"


def _store() -> TaintStore:
    return TaintStore(str(Path(tempfile.mkdtemp()) / "t.db"))


def test_normalisation_survives_cheap_evasion() -> None:
    base = normalise("CANARY-7f3a91-do-not-share")
    assert normalise("canary 7f3a91 do not share") == base
    assert normalise("C A N A R Y - 7 f 3 a 9 1 - d o - n o t - s h a r e") == base
    assert normalise("CANARY%2D7f3a91%2Ddo%2Dnot%2Dshare") == base


def test_overlap_requires_real_sharing() -> None:
    assert overlaps(SECRET, f"please verify {SECRET} thanks")
    assert not overlaps(SECRET, "Two-phase integration, SSO first, 14 November.")


def test_sensitive_reaches_egress_is_detected() -> None:
    store = _store()
    store.record("s1", "notes", "notes.read_note", SENSITIVE, SECRET)
    args = {"to": "research@acme-partners.net", "body": SECRET}
    assert SENSITIVE in store.labels_in("s1", args, "fine")
    store.close()


def test_taint_is_session_scoped() -> None:
    """Labels must not leak between sessions sharing one database."""
    store = _store()
    store.record("s1", "notes", "notes.read_note", SENSITIVE, SECRET)
    assert store.labels_in("s2", {"body": SECRET}, "fine") == set()
    store.close()


def test_fine_mode_lets_unrelated_calls_through() -> None:
    store = _store()
    store.record("s1", "notes", "notes.read_note", SENSITIVE, SECRET)
    clean = {"to": "priya@internal.example", "body": "Summary: SSO first, 14 Nov."}
    assert store.labels_in("s1", clean, "fine") == set()
    store.close()


def test_coarse_mode_taints_everything_after_a_read() -> None:
    """The honest cost of the unevadable mode: the same unrelated call the
    fine mode allows is blocked here."""
    store = _store()
    store.record("s1", "notes", "notes.read_note", SENSITIVE, SECRET)
    clean = {"to": "priya@internal.example", "body": "Summary: SSO first, 14 Nov."}
    assert SENSITIVE in store.labels_in("s1", clean, "coarse")
    store.close()


def test_s04_blocked_with_fine_taint() -> None:
    import harness.run as R

    outcome = R.run(ROOT / "scenarios" / "s04_confused_deputy", "full")
    assert not outcome.attack_succeeded, "taint must stop the injected send"
    assert outcome.task_completed, "the real email to Priya must still go"
    assert outcome.denied == 1


def test_known_false_positive_is_reproducible() -> None:
    """Sharing your own notes is blocked by sensitive_egress. This is a real
    limitation, asserted here so it stays visible and cannot regress silently
    into an unmeasured claim of perfection."""
    import harness.run as R

    outcome = R.run(ROOT / "scenarios" / "b02_share_own_notes", "full")
    assert not outcome.task_completed, (
        "b02 is expected to fail under fine taint; if it now passes, the "
        "false-positive number in the README is stale"
    )


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
