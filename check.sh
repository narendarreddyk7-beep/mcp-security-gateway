#!/usr/bin/env bash
# One-command health check. Run from the repo root: ./check.sh
set -u
cd "$(dirname "$0")"
export PYTHONPATH=.
PY="${PYTHON:-python3}"

echo "python: $($PY --version)"
echo

fail=0
run() {
  echo "== $1"
  shift
  if "$@"; then echo; else echo "   ^ FAILED"; echo; fail=1; fi
}

run "transport + audit log"        $PY tests/test_week1.py
run "audit chain under concurrency" $PY tests/test_audit_concurrency.py
run "policy engine + manifest auditor" $PY tests/test_week3.py
run "taint tracking"               $PY tests/test_week4.py
run "new scenarios + the finding"  $PY tests/test_week5.py
run "threshold sweep"              $PY -m harness.sweep
run "dashboard imports"            $PY -c "import dashboard.app; print('[pass] dashboard API imports')"
run "scenario benchmark"           $PY -m harness.bench

if [ "$fail" -eq 0 ]; then
  echo "all checks passed"
  echo
  echo "Read the table as an argument, not a scoreboard:"
  echo "  audit   observation alone buys no security"
  echo "  policy  scoping stops s01; s04 uses only permitted tools"
  echo "  full    taint stops both, and costs 33% false positives"
  echo "  coarse  unevadable, and kills the real email in s04 too"
  echo
  echo "b02 failing under full/coarse is a measured limitation, not a bug."
  echo "Sharing your own notes is the commonest legitimate reason private"
  echo "data reaches an egress tool, and the gateway cannot tell it apart"
  echo "from exfiltration."
else
  echo "some checks failed - paste the output above"
fi
exit "$fail"
