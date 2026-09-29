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
run "s01 without the gateway"      $PY -m harness.run scenarios/s01_direct_injection --config none
run "s01 through the gateway"      $PY -m harness.run scenarios/s01_direct_injection --config gateway

if [ "$fail" -eq 0 ]; then
  echo "all checks passed"
  echo
  echo "Both s01 runs should say attack=LEAKED. That is correct right now:"
  echo "the gateway is still transparent. Week 3 is what makes it say blocked."
else
  echo "some checks failed - paste the output above"
fi
exit "$fail"
