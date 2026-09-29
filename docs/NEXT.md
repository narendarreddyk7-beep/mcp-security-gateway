# Next steps, in dependency order

## Week 2 — attacks before defences
Build the exploit before the fix, so there is always a demo and an oracle.

- [x] `servers/notes` — list/read, seeded with a `CANARY-` credential
- [x] `servers/mail` — list/read/**send**; external recipients relay to the sink
- [x] `servers/web` — fetch_url, fixtures + real egress
- [x] `servers/calendar` — list/read events
- [x] `collector/` — HTTP sink; matches raw, percent-encoded and base64
- [x] `scenarios/s01_direct_injection` — LEAKED, as intended
- [x] `scenarios/s04_confused_deputy` — LEAKED, as intended
- [x] `harness/bench.py` — all scenarios x all configs
- [x] `harness/run.py` — runs a scenario, checks both predicates
- [x] `harness/agent.py` — compliant agent (worst-case, deterministic)
- **Milestone: DONE.** s01 and s04 both succeed; the canary reaches the
  collector by two different routes (fetch_url, and a legitimate send_message).

## Week 3 — manifest auditor + policy engine
- [x] capability classifier, dangerous-combination flagging
- [x] tool-description injection detection (imperatives, secrecy, invisible chars)
- [x] policy schema + evaluator, four actions, default deny
- [x] approval broker, fails closed (auto-deny / auto-approve / prompt)
- [x] cross-server manifest report over the audit log
- [ ] name-shadowing detection wired into a scenario (needs s02)
- **Milestone: DONE.** s01 blocked, s04 still leaks, task completion 100%.

## Week 4 — taint tracker
- [x] source labelling at the proxy boundary (sensitive + untrusted)
- [x] cross-process taint store, session-scoped, shared via the audit db
- [x] fine and coarse propagation, both shipped, both benchmarked
- [x] sink enforcement on `egress`
- [x] benign controls b01-b03, so false positives are measured
- [ ] declassification via approval (currently a taint label is permanent)
- **Milestone: DONE.** s04 blocked, task completion held at 100% under fine
  taint, 33% false positives measured and documented.

### Known gaps to close
- [ ] paraphrase evasion: an agent that rewrites the secret defeats fine mode.
      Needs a scenario that does this deliberately, and an honest number.
- [ ] b02-style sharing: approval is the obvious answer (require_approval
      rather than deny on sensitive_egress). Cheap to try, measure both.
- [ ] chunked exfiltration (s06) will likely defeat the 24-character overlap
      threshold. Vary MIN_OVERLAP and report the sensitivity curve.

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
