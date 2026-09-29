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
run "scenario benchmark"           $PY -m harness.bench

if [ "$fail" -eq 0 ]; then
  echo "all checks passed"
  echo
  echo "Attack success should be 100% in both configurations right now."
  echo "That is correct: the gateway is still transparent. Week 3 and week 4"
  echo "are what pull the gateway row down."
else
  echo "some checks failed - paste the output above"
fi
exit "$fail"
