# Dashboard

A small FastAPI app that reads the artifacts the gateway already writes - the
audit log, taint records, manifest findings - and serves them as a live view.
It contains no security logic. It is a viewer, and the gateway blocks calls
whether or not the dashboard is running.

## Run it

```bash
pip install fastapi uvicorn      # in your .venv
python3 -m dashboard.app --demo  # runs s01 + s04, then serves
```

Open http://127.0.0.1:8000. The `--demo` flag runs the two flagship attacks
through the full gateway first, so there is something real to look at
immediately. To view an existing audit db instead:

```bash
python3 -m dashboard.app --db audit.db
```

## What it shows

- **Session list** with call counts, denials, taint labels, manifest flags.
- **Per-call timeline**: each tool call with its verdict (allow / deny /
  require_approval), the policy rule that fired, and latency.
- **Manifest audit**: dangerous capability combinations flagged at connect
  time, and any tool-description injection findings.
- **Taint labels**: which results were marked sensitive or untrusted.
- **Chain-verify banner**: recomputes the audit hash chain and reports whether
  the log has been tampered with.

## Security note

Every string the dashboard renders - tool names, arguments, injected text - is
attacker-influenced. It is inserted as inert text, never as markup. A gateway
whose own dashboard could be XSSed by a captured payload would undercut the
point of the project, so the escaping is deliberate and worth checking in
`static/index.html`.
