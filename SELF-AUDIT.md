# SELF-AUDIT — we ran this tool on this tool

The whole pitch of Black Box is honest, verifiable self-scrutiny. So before
publishing, we pointed `find-your-kill-zone` at its own code — and, because a
fresh repo has no edit history, at the **real authoring history** of these files
in the codebase they were extracted from. Here is exactly what it found.
*Measured 2026-06-09; every number is reproducible (commands below).*

## The result

```
status: COMPLETE_NO_P0
kill zone  (complexity ∩ churn ∩ security):   0 files
  intersections.fragilityDensity / …Prod  =  []   (the complexity ∩ churn kill zone)
  intersections.p0 / p0Prod                =  []   (the triple intersection)
high-complexity vector (density):   7 files  ← includes engine/commands/analyze.ts
high-churn vector (fragility, ≥15 edits/180d):   0 files
security (bandit / semgrep):   0 / 0
thresholds:  churn 15 · complexity 15 · semgrep ERROR
```

**The empty kill zone is not a fresh-repo accident — it holds against real history.**

## The honest part: yes, our own synthesis core is our most complex file

`engine/commands/analyze.ts` — the file that *computes* the kill zone — is our
most complex file. CodeScene scores it **6.61 (Yellow)**, and our own engine puts
it in the high-complexity `density` vector. We are not hiding that.

It is **not** in the kill zone. Here is precisely why, with the real numbers:

| `analyze.ts` | gate | value | clears? |
|---|---|---|---|
| complexity | ≥ 15 cyclomatic | yes (density vector) | ✅ |
| churn | ≥ 15 edits / 180d | **9 edits** (real authoring history) | ❌ |
| security | any ERROR-severity finding | 0 | ❌ |

The kill zone is a deliberate **triple intersection** — complexity **and** churn
**and** a real security signal. `analyze.ts` clears exactly one of the three. A
lone complex file is "where you might look," not "where you've been hit." That
distinction is the entire reason the tool is an intersection and not a complexity
blocklist you could game by deleting comments.

For scale: the actual highest-churn files in the source codebase over the same
window are documentation and talk decks (24, 22, 17 edits), not the engine. The
breadth engine is stable; our churniest file isn't even code.

## Why we did NOT refactor `analyze.ts` to chase a green score

It is the **literal stage engine** — byte-for-byte the synthesis that runs in our
paid audits. `VALIDATION_REPORT.md` proves the extracted engine reproduces the
stage engine *exactly*, field-by-field, against a frozen oracle. Refactoring
`analyze.ts` for a prettier number would **break that proof** and force re-passing
the validation gate — trading a verifiable "this is the real engine" guarantee for
a vanity score on a file that doesn't enter the kill zone anyway. We chose fidelity.

## Reproduce (you don't have to trust us)

```bash
# 1. Complexity is a property of the code — reproducible anywhere, today:
git init && git add -A
git -c commit.gpgsign=false -c core.hooksPath=/dev/null commit -q --no-verify -m baseline
BB_PARALLEL_ANALYZERS=1 BB_SEMGREP_JOBS=4 ./run.sh . --since "180 days ago"
# when done: rm -rf .git output .validation   # don't leave the tool repo git-init'd
jq '{status, density:.vectors.density, killzone:.intersections.fragilityDensity}' \
   output/analysis/find-your-kill-zone.interrogate.json
#   → analyze.ts in density; kill zone []

# 2. The churn figure (9 edits/180d) is the file's real authoring history; the
#    engine's churn method is just:  git log --since --name-only, counted per file.
#    A freshly-published repo's churn restarts at publish, so this number grows
#    only as the public repo accumulates real edits.
```

## Honest footnotes
- **Stamped, "as of 2026-06-09."** `analyze.ts` is a young file (9 commits all-time).
  As it accumulates edits it *could* cross the churn threshold later and enter the
  kill zone — at which point we'd trace it by hand, like any other kill-zone file.
- **Complexity ≠ defect.** Density (and CodeScene's 6.61) flag maintainability cost,
  not a bug. The tool's job is to *rank where humans should look*, not to convict.
