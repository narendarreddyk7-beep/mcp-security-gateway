"""Chain verification CLI: python -m gateway.audit.verify audit.db"""

import sys

from gateway.audit.log import AuditLog


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m gateway.audit.verify AUDIT_DB", file=sys.stderr)
        return 2
    log = AuditLog(sys.argv[1])
    result = log.verify()
    if result.ok:
        print(f"chain intact: {result.checked} events verified")
        return 0
    print(f"CHAIN BROKEN at seq {result.broken_at}: {result.detail}", file=sys.stderr)
    print(f"{result.checked} events verified before the break", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
