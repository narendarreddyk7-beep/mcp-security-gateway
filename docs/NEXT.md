# Next steps, in dependency order

## Week 2 — attacks before defences
Build the exploit before the fix, so there is always a demo and an oracle.

- [x] `servers/notes` — list/read, seeded with a `CANARY-` credential
- [ ] `servers/mail` — list/read/**send** (the dangerous private_read+egress pair)
- [x] `servers/web` — fetch_url, fixtures + real egress
- [ ] `servers/calendar` — list/read events
- [x] `collector/` — HTTP sink; matches raw, percent-encoded and base64
- [x] `scenarios/s01_direct_injection` — LEAKED, as intended
- [ ] `scenarios/s04_confused_deputy` — needs the mail server
- [x] `harness/run.py` — runs a scenario, checks both predicates
- [x] `harness/agent.py` — compliant agent (worst-case, deterministic)
- **Milestone:** s01 and s04 both succeed against a bare agent; the canary
  appears in the collector log.

## Week 3 — manifest auditor + policy engine
- [ ] capability classifier, dangerous-combination flagging
- [ ] tool-description injection detection, name-shadowing detection
- [ ] policy schema (pydantic), evaluator, four actions only
- [ ] approval broker, fail-closed timeout
- **Milestone:** s01 fails, s04 still succeeds.

## Week 4 — taint tracker
- [ ] source labelling at the proxy boundary
- [ ] fine-grained (normalised substring) and coarse-grained (session-wide)
      propagation, both shipped, both benchmarked
- [ ] sink enforcement on `egress`, declassification via approval only
- **Milestone:** s04 fails. This is the week the project becomes distinctive.

## Week 5 — inspectors + full suite
- [ ] three layers, shared signal contract with a `version` field
- [ ] s02 (tool-description poisoning), s03 (calendar invite),
      s05 (rug pull), s06 (chunked exfiltration)
- [ ] ~12 benign controls, including ones that *look* suspicious
- [ ] lone-surrogate / homoglyph / zero-width obfuscation scenario
- **Milestone:** four-row ablation table, five repetitions per scenario.

## Week 6 — dashboard, README, demo
- [ ] live session view, benchmark report (these two carry the interview)
- [ ] server audit, approval queue, audit log explorer with "verify chain"
- [ ] split-screen demo clip
- [ ] limitations section, written before anyone asks

If time runs short, cut dashboard pages 3-5. Never cut the benchmark.
