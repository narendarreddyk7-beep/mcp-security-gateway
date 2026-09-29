# MCP Security Gateway

A transparent proxy that sits between an AI agent and the MCP servers it uses,
brokering every tool call against a declarative policy, tracking where data
came from, and recording everything in a tamper-evident audit log.

Shipped alongside it: a suite of agentic attack scenarios and a benchmark that
measures how well the gateway works, including where it fails.

## Threat model

**The attacker controls** content returned by tools (web pages, email bodies,
file contents, calendar invites) and the tool definitions advertised by
third-party MCP servers.

**The attacker does not control** the gateway process, the policy file, the
agent runtime, or the user's original instruction.

**Out of scope:** a malicious operator, supply-chain compromise of the gateway
itself, attacks on the model weights.

**Security goal:** even if the agent is completely persuaded by injected
content, it cannot exfiltrate private data or take a consequential action,
because the gateway denies the call regardless of the agent's intent.

That last point is the thesis. The defence does not depend on detecting the
injection.

## Status

| Component | State |
|---|---|
| stdio proxy | working, transparent, tested |
| hash-chained audit log | working, tamper + concurrency tested |
| vulnerable servers (notes, web, mail, calendar) | working |
| collector oracle | working |
| scenario runner + benchmark | working |
| s01 direct injection | lands (as intended) |
| s04 confused deputy | lands (as intended) |
| http transport | not started |
| manifest auditor | not started |
| policy engine | not started |
| taint tracker | not started |
| inspectors | not started |
| scenario suite + benchmark | not started |
| dashboard | not started |

## Quickstart

```bash
python3 tests/test_week1.py              # transport + audit
python3 tests/test_audit_concurrency.py  # chain under concurrent writers
python3 -m harness.bench                 # every scenario, every config
python3 -m gateway --db audit.db -- python3 servers/echo/server.py
python3 -m gateway.audit.verify audit.db
```

Point an agent at the gateway instead of the server and the session is
unchanged, except that every frame is now on the record.

## Current results

```
none      attack success   100%   task completion   100%
gateway   attack success   100%   task completion   100%
```

Both rows are supposed to look like this. The gateway is a transparent proxy
so far - it records everything and denies nothing. Weeks 3 and 4 pull the
second row down while keeping task completion up, and the gap between those
two rows is the whole result.

## Design rules

1. **Forwarding uses the original bytes.** Parsing happens on a copy, for the
   audit log and policy. A bug in the parser can never corrupt the stream.
2. **Detection is advisory, policy is authoritative.** Inspectors emit scores
   and reasons; only the policy engine decides.
3. **Fail closed.** Inspector errors and approval timeouts deny, never allow.
4. **Scenarios are data, not code.** Attacks are YAML plus fixtures, so the
   suite can grow past ten.

## Protocol target

MCP revision `2025-06-18`. Stated explicitly because the protocol is still
moving and a project that silently targets a stale revision ages badly.
