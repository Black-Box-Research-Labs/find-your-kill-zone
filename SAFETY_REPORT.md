# SAFETY_REPORT — adversarial panel

> ## ✅ All 5 claims HELD — no open air-gap / moat / verifier break

Each claim was attacked by an independent fresh refuter trying to BREAK it (default
to "broke" unless it genuinely could not). Final state after the run-3 remediations:

| # | Claim | Verdict | Notes |
|---|---|---|---|
| 1 | Un-air-gap escape | ✅ HELD | `--network none` hardcoded in compose; no `run.sh` override path |
| 2 | Phone-home at runtime | ✅ HELD | all advisory/rule data vendored at build; nothing fetches live |
| 3 | Secret / vault / DB leak | ✅ HELD | no `DATABASE_URL`/Neon/RLS/secret in tree or image |
| 4 | WORM ledger honesty | ✅ HELD *(was BROKE)* | real `--verify` shipped; see below |
| 5 | Role-3 moat leak | ✅ HELD *(was BROKE)* | financial surface + run artifacts removed; see below |

## Claim 4 — WORM honesty (remediated)
Run 2 found `--ledger` was append-only with **no verifier** while the docs claimed
"tamper → the chain breaks." Remediation: ported `_verify_ledger` into `run.sh` +
a `--verify <ledger>` subcommand + verify-before-append. Fresh adversarial drill:
valid chain → `✓` exit 0; any tampered line → `❌ HASH MISMATCH` exit 1; chain-link
break → detected; append refuses a tampered ledger. A fully re-chained forgery does
pass (keyless SHA-256 ceiling) — and the marketing is honestly scoped to that:
"keyless / plain shasum / tamper-evident on any edit," never "unforgeable/signed."

## Claim 5 — Role-3 moat leak (remediated)
Run 2 found two surfaces: (a) `engine/vendored/analyze-emit.ts` shipped as dead code
naming the withheld buyer-valuation pipeline + pointing at withheld docs; (b) real
`cai` security findings staged as sample output. Remediation: **dropped
`analyze-emit.ts`** (its consumer was already severed), **sanitized** the moat-naming
comments in `analyze.ts` (zero §7.2 effect), and **removed the run artifacts**
(`output/`, `.validation/`) — they are `.gitignore`'d and regenerated per run. Fresh
sweep confirms: no `analyze-emit`/`computeFinancials`/`PR-5` in shipped source, no
staged findings/dumps, no withheld-doc pointers. README/front-door only *name* the
withheld moat as "deliberately not here" — the sanctioned Role-1 teaser.
