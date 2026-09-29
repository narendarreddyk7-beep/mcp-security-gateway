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
| manifest auditor | working, cross-server report |
| policy engine | working, 4 actions, default deny |
| approval broker | working, fails closed |
| taint tracker | working, fine + coarse, both benchmarked |
| inspectors | not started |
| scenario suite | 2 attacks, 3 benign controls |
| dashboard | not started |

## Quickstart

```bash
python3 tests/test_week1.py              # transport + audit
python3 tests/test_audit_concurrency.py  # chain under concurrent writers
python3 tests/test_week3.py              # policy + manifest auditor
python3 tests/test_week4.py              # taint tracking
python3 -m harness.bench                 # every scenario, every config
python3 -m gateway.manifest.report audit.db
python3 -m gateway --db audit.db -- python3 servers/echo/server.py
python3 -m gateway.audit.verify audit.db
```

Point an agent at the gateway instead of the server and the session is
unchanged, except that every frame is now on the record.

## Current results

```
config     attack success   benign done   false pos   task under attack
none                100%         100%          0%               100%
audit               100%         100%          0%               100%
policy               50%         100%          0%               100%
full                  0%          67%         33%               100%
coarse                0%          67%         33%                50%
```

Five configurations, each isolating one layer. `none` is no gateway. `audit`
is the transparent proxy - it records everything and denies nothing, and it is
in the table to show that observation alone buys no security. `policy` adds
capability scoping. `full` adds fine-grained taint tracking. `coarse` swaps in
session-wide taint.

**Why s01 falls to scoping but s04 does not.** Summarising a web page needs no
access to notes, so the injected read is out of scope and refused. s04 is
harder: the user legitimately asked for a brief to be read, notes to be
checked, and an email sent, so every tool the injection uses is one the task
class already permits. The injection adds no capability. It changes the
recipient and the body.

**What closes s04.** The `sensitive_egress` rule denies a call to an egress
tool whose arguments contain content that came out of a private_read tool. It
references no keyword, no score, no recipient and no domain - only where the
arguments came from. The injected send carries the credentials note verbatim;
the real send to Priya carries a summary nobody read from a private source.

**The 33% false positives are the honest cost.** Control b02 asks the agent to
email the user's own standup notes to a colleague. Nothing malicious happens,
but private content legitimately reaches an egress tool, which is exactly the
pattern the rule denies. Sharing your own data is the commonest legitimate
reason for that flow, and this gateway cannot currently tell it apart from
exfiltration. There is a test asserting b02 still fails, so the number in this
table cannot go stale without someone noticing.

**Fine versus coarse.** Fine-grained taint checks whether the arguments
actually contain labelled content. It is precise and evadable - an agent that
paraphrases the secret rather than copying it defeats it. Coarse-grained taint
labels every call after the session touches a private source, which cannot be
evaded and blocks the legitimate email in s04 as well, hence 50% in the last
column. Neither dominates. Both ship, both are measured, and the gap between
them is a real open trade-off rather than something to hide.

An obvious objection: why not just block email to external recipients? Because
it does not generalise. The same exfiltration works through any egress tool, a
recipient allowlist breaks every legitimate external email, and the attacker
picks a different channel. Taint addresses the property that is actually wrong
with the call.

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
