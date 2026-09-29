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

## Week 5 — scenarios + the finding
- [x] s02 tool-description poisoning (blocked by scoping; flagged by auditor)
- [x] s03 calendar invite (injection from unaccepted event)
- [x] s06 chunked exfiltration - DEFEATS fine-grained taint, caught by coarse
- [x] benign controls b04 (security article), b05 (calendar read)
- [x] per-scenario attack-success breakdown in the benchmark
- [x] agent models manifest-time directives and chunked/transformed carriage
- [ ] s05 rug pull (server changes its manifest after approval)
- [ ] run with --repeat 5 once a real model backend exists; harness is ready
- **Milestone: DONE.** The layered argument is now visible per-scenario, and
  the chunked-exfil bypass of our own taint layer is a documented, tested
  result rather than an unmeasured claim.

### The finding, stated plainly for the README/demo
Content-based taint tracking is defeated by fragmentation. s06 splits the
secret into 6-char pieces; the 24-char overlap threshold never matches. Coarse
taint catches it but blocks legitimate data sharing. This is the real,
unsolved tension in the field - not a gap to apologise for.

### Threshold sensitivity (worth a figure in the README)
- [ ] sweep MIN_OVERLAP from 4 to 48, plot attack success vs false positives
      for s06 and b02 together. The crossover point is the money chart.

## Week 6 — dashboard, README, demo
- [x] FastAPI backend serving the audit log, taint, manifest, benchmark
- [x] live session view: verdict per call, rule fired, taint labels,
      manifest findings, chain-verify banner
- [x] attacker-controlled strings escaped (no self-XSS)
- [x] --demo flag: runs s01+s04 through the full gateway, then serves
- [x] benchmark.json + sweep.json exported for the dashboard
- [ ] benchmark report *page* in the dashboard (data is already served)
- [ ] split-screen demo clip (record: none vs full on s04)
- [ ] limitations section in the README

### Demo recording script (30s)
1. `python3 -m dashboard.app --demo`, open the browser
2. Point at the s04 session: fetch allowed, note read (taint: sensitive),
   injected send DENIED by sensitive_egress, real send to Priya allowed
3. Point at the manifest flag: private_read + egress exfiltration path
4. Point at the chain-verify banner
5. Cut to terminal: `python3 -m harness.bench` per-scenario table
