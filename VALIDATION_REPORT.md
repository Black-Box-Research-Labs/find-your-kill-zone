# VALIDATION_REPORT — frozen-oracle gate (AIV-grade)

*This report is itself the evidence, not a claim about it: every figure is
independently re-derivable from the commands below — you do not have to trust us.*

## Verdict: ✅ PASS — the extracted engine is analysis-output-identical to the stage engine (publication comments sanitized)

**Method.** The extracted breadth engine and the monorepo (stage) engine were run
on the same target, same pinned SHA, same churn window, in the same session — then
their §7.2 kill-zone summaries were compared field-by-field by an independent
adversarial validator (the producer never judged its own output).

| Stamp | Value |
|---|---|
| Target | `aliasrobotics/cai` @ `7ec0b4ccf2c5757d53824ae263578cee036c5725` (13 commits in window) |
| Window | `--since "180 days ago"` (identical for both engines, same session) |
| Image | `find-your-kill-zone` (45-tool air-gapped clean room, `--network none`) |
| Oracle | monorepo engine `interrogate` output, fresh same-day (semgrep non-degraded: 232) |

### §7.2 contract — every field identical

| Field | Stage engine | Extracted | Match |
|---|---|---|---|
| `status` | SECURITY_ESCALATION | SECURITY_ESCALATION | ✅ |
| `highComplexityFileCount` | 53 | 53 | ✅ |
| `banditTotalFindings` | 2217 | 2217 | ✅ |
| `banditHighHigh` | 5 | 5 | ✅ |
| `semgrepTotalFindings` | 232 | 232 | ✅ |
| `securityEscalationCount` | 5 | 5 | ✅ |
| `highChurnFileCount` | 2 | 2 | ✅ |
| `complexityChurnKillZone` | 0 | 0 | ✅ |
| `intersectionP0Count` / `…ProdCount` | 0 / 0 | 0 / 0 | ✅ |
| `intersections.{p0,p0Prod,fragilityDensity,fragilityDensityProd}` | all `[]` | all `[]` | ✅ |
| `vectors.density` | 25-file set | identical set | ✅ |
| `vectors.fragility` | 2-file set | identical set | ✅ |
| `vectors.vulnerability.severityCounts` | ERROR 93 · HIGH 6 · INFO 6 · LOW 2189 · MEDIUM 22 · WARNING 133 | identical | ✅ |
| `thresholds` | churn 15 · complexity 15 · semgrepMinSeverity ERROR | identical | ✅ |

Only difference: the `metricCitations.*.jsonPath` provenance strings embed each
run's analysis filename (different timestamps) — a pointer, not a kill-zone signal.

### What this does NOT establish (threats to validity)

This report applies the same known-limitations discipline we ask of everyone else
to itself. It proves a narrow thing well; here is what it explicitly does not prove.

- **Fidelity, not correctness.** This is a *sameness* proof: the extracted engine
  produces the identical §7.2 kill zone as the stage engine. It says **nothing about
  whether any nominated file contains a real bug.** The kill zone is a nomination
  for human review, not a verdict — confirming a finding is depth work that is
  deliberately not in this repo (see README, "What it proves — and what it does not").
- **Determinism against a frozen oracle, not independent ground truth.** The
  comparison baseline is a same-day snapshot of the stage engine's own output, frozen
  to defeat the degraded-capture failure that halted Run 2. So this validates that the
  two engines **agree with each other** on a pinned input; it is not an external
  oracle. A systematic error shared by both engines would pass this gate. The defense
  against that is the per-field provenance (every number re-derivable from the JSON
  path that produced it), not this report.
- **Only window-independent fields are bit-stable.** Complexity, bandit, and semgrep
  counts are deterministic for a fixed `@SHA`. The **churn-derived fields are
  environment-sensitive** — they depend on clone depth and the `--since` window, which
  is why both engines were pinned to the same SHA, same `"180 days ago"`, same session.
  Re-run with a shallow clone or a different window and the churn-dependent fields
  (`highChurnFileCount`, the fragility vector, any churn∩complexity overlap) can move.
  That is a property of the metric, not a regression.
- **One target, one window.** This gate was run on `aliasrobotics/cai` at one SHA. It
  establishes the extraction is faithful *there*; it is not a claim that every repo,
  language mix, or window reproduces identically.

The full honest-limits list for the tool's *output* (churn-window sensitivity,
shallow-clone distortion, tool-class false positives, heavy build) lives in
[`FIND-YOUR-KILL-ZONE.md` §7](./FIND-YOUR-KILL-ZONE.md). This section covers the
limits of *the validation itself*.

### Reproduce
```
# extracted engine on cai:
BB_PARALLEL_ANALYZERS=1 BB_SEMGREP_JOBS=4 ./run.sh <path-to-cai>@7ec0b4c --since "180 days ago"
# diff the §7.2 fields against any fresh stage-engine interrogate of the same SHA+window.
```

### History (honest provenance)
- **Run 1** halted: extraction byte-perfect but the engine could not boot (missing
  own deps) and a financial-translation moat surface shipped. → FIX-1..4.
- **Run 2** the gate ran; logic-loss refuted, but the published May-16 `cai`
  oracle was a **degraded semgrep capture (0 findings)** and churn fields drifted on
  a relative window. → re-froze the oracle same-day, pinned the window.
- **Run 3 (this report):** exact reproduction on every §7.2 field. The extraction
  never altered an analyzer, threshold, or severity gate.
