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
