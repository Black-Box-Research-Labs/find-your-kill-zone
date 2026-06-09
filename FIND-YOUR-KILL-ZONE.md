# FIND YOUR KILL ZONE

*The breadth engine, by Black Box Research Labs. Sibling to "Who Reviews the Reviewers?" (WRR).*

> **You are an LLM coding agent.** A human pointed you at their repository and handed you
> this file. **This file is your complete instruction set.** You need exactly two things:
> **Docker** (daemon running) and **this `find-your-kill-zone` repo**. Nothing else — no API
> key, no account, no network access to a service we run, no data leaves the human's machine.
>
> Your job: build a real air-gapped analysis engine, run it on the human's repo with its
> network physically severed, and print them their **kill zone** — the small set of files
> that are simultaneously high-churn, high-complexity, and security-flagged. That is *where a
> reviewer should look by hand.* It is the machine's nomination, **not** a verdict.
>
> This is the literal engine that runs on stage — the same analyzers, the same
> fragility ∩ density ∩ vulnerability synthesis. It is not a reimplementation and not a toy.

---

## 1. Hard rules — anti-fabrication (read these before you run anything)

These are inherited from WRR. Violating one invalidates the whole run. You are an LLM; you
are *capable* of inventing a plausible number. **Do not.** Every number you print must trace
to a command you actually ran and a JSON field you actually read.

1. **READ-ONLY on the human's repo.** You analyze a `cp -R` copy in `/tmp`; the engine never
   mutates the human's working tree. Do not `git commit`, `git checkout`, edit, or delete
   anything in their repo. The only writes you make are inside *this* `find-your-kill-zone` repo
   (the `output/` dir) and `/tmp`.
2. **SHOW YOUR WORK.** Every figure in the scorecard is read from the engine's JSON. Print the
   `jsonPath` next to each number so the human (or a third party) can re-derive it. A number
   with no path is a fabrication.
3. **STAMP EVERY NUMBER.** Format: `<value>, <OWNER/REPO>@<sha>, as of <YYYY-MM-DD>`. The value,
   the exact commit it was computed at, and the date you computed it. An unstamped number is
   not a result.
4. **DETERMINISTIC.** Same repo + same `@SHA` + same `--since` window ⇒ same kill zone. The
   only sanctioned non-determinism is semgrep *timing* (the engine intersects counts, so the
   counts must still match). If you get two different scorecards for the same inputs, something
   is wrong — say so, do not pick the prettier one.
5. **DON'T GUESS.** If the engine could not compute a field (tool degraded, JSON missing the
   key), print `could not compute` for that row and say which tool degraded. **"Could not
   compute" is an honest output. A fabricated count is a lie that looks like work.**
6. **NEVER fabricate the kill zone itself.** If `run.sh` exits non-zero or produces no
   `*.interrogate.json`, you have NO kill zone to report. Stop and surface the engine's error
   verbatim. Do not synthesize a scorecard from the progress log, from memory, or from the
   extended dump — only `*.interrogate.json` is the source of truth.

---

## 2. Preflight

Resolve these before building. Do not proceed if any check fails.

**2.1 — Docker present and the daemon is up; `jq` available.** (Docker runs the engine; `jq`
parses the scorecard in §5. `git` is needed only if your target is a local path whose churn you
want measured.)
```bash
docker version >/dev/null 2>&1 || { echo "FATAL: Docker not installed or daemon down. Start Docker and retry."; exit 1; }
docker info  >/dev/null 2>&1 || { echo "FATAL: Docker daemon not responding."; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "FATAL: jq not found (needed to read the scorecard JSON). Install jq and retry."; exit 1; }
```

**2.2 — Resolve the target identity: `OWNER/REPO@SHA` + `TODAY`.** You need these to *stamp*
every number (rule 3).

> **Prerequisite:** the target must be a **git checkout with history** — the historian/churn
> analyzers read `git log`, and the stamp needs a real `@SHA`. A plain (non-git) directory will
> still analyze for complexity/security, but churn is meaningless and the stamp is malformed, so
> the kill zone (which requires churn) is structurally empty. Guard for it first:

```bash
git -C <path-to-user-repo> rev-parse --git-dir >/dev/null 2>&1 \
  || { echo "FATAL: target is not a git repository — churn cannot be measured. Point at a git checkout."; exit 1; }
TARGET_REPO="$(git -C <path-to-user-repo> config --get remote.origin.url | sed -E 's#(git@|https://)([^/:]+)[/:]##; s#\.git$##')"   # -> OWNER/REPO
TARGET_SHA="$(git -C <path-to-user-repo> rev-parse --short HEAD)"
TODAY="$(date -u +%Y-%m-%d)"
echo "Target: ${TARGET_REPO}@${TARGET_SHA}  | As of: ${TODAY}"
```
If the repo has no remote (local-only), use the directory name as `OWNER/REPO` and still
record `@${TARGET_SHA}`. The stamp must always carry a real commit SHA.

**2.3 — The engine image either builds (§3) or already exists.**
```bash
docker image inspect find-your-kill-zone >/dev/null 2>&1 \
  && echo "image present — you may skip §3" \
  || echo "image absent — build it in §3 (one-time, multi-GB, several minutes)"
```

---

## 3. Build the engine (one-time)

```bash
docker build -f infrastructure/Dockerfile -t find-your-kill-zone .
```

⚠ **Expect this to be heavy:** a multi-GB image (~5 GB resident; keep **≥8 GB free** — the image
plus a `/tmp` copy of your repo plus the analysis dump can eat the margin), several
minutes the first time (cached rebuilds are seconds). It bakes **45 analysis tools** (radon,
bandit, semgrep + the custom rule pack, gocyclo, eslint, the historian, the advisory DBs) into
one clean room. **This is the only step that uses the network** — it pulls tool packages *at
build time*. After this, the runtime is air-gapped.
The build hard-fails if a required tool (e.g. `commander`) didn't land — there is no silent
half-built image.

Capture the clean-room fingerprint now (you'll print it in §6) — the SHA-256 of the toolchain
Dockerfile, which is the **stable** provenance anchor. (Don't use the docker image id: BuildKit
re-exports it on every rebuild, so it changes even when nothing did.)
```bash
CLEANROOM="$(shasum -a 256 infrastructure/Dockerfile | awk '{print $1}')"
```

---

## 4. Run — air-gapped

```bash
./run.sh <path-to-user-repo> --since "90 days ago" --ledger
```

What happens, and why it matters:

- The runner `cp -R`s the repo into a `/tmp` workspace (read-only invariant — the human's
  clone is never touched) and best-effort unshallows the **copy** so the historian sees real
  churn depth.
- It runs the engine in a container with **`network_mode: none`** — hardcoded in
  `infrastructure/docker-compose.yml`, with **no `--network` passthrough and no env escape**
  in `run.sh`. **The human's code cannot leave the box.** Say this to the human plainly: the
  container is physically severed from the network; nothing phones home; all advisory data
  was vendored at build time.
- It runs **`analyze`** (→ the extended analysis dump) and then **`interrogate`** (→ the
  **kill-zone summary** — `output/analysis/<repo>.interrogate.json`). The kill zone is emitted
  by `interrogate`, not `analyze`.
- `--ledger` appends one self-contained SHA-256 WORM line so the run is independently
  re-verifiable (§6).
- `run.sh` prints the live heartbeat **and**, as its last line, the path to the summary JSON.
  **If it exits non-zero or prints no path, STOP** (rule 6) — a missing summary is a hard error,
  never a pass. Surface the engine's error to the human verbatim.
- The engine may **expand** your `--since` window if it yields too few commits (e.g. `90 days
  ago` → `365 days ago`); the scorecard stamps the **effective** window (`sinceEffective`), so
  churn-derived numbers reflect that, not necessarily what you typed.
- **Timing:** the parallel sweep runs in **~1.5–2 min** on a medium repo (semgrep is the long
  pole). `run.sh` defaults `BB_SEMGREP_JOBS=4` for that speed. On a **very large** target
  (thousands of files) where semgrep memory is a concern, lower it: `BB_SEMGREP_JOBS=1 ./run.sh …`.

```bash
# Pipe through `tee` so the live heartbeat + scorecard print to YOUR screen AND
# get captured. Do NOT wrap the call in $(...): that swallows the on-screen
# scorecard into a variable and you'd see nothing.
./run.sh <path-to-user-repo> --since "90 days ago" --ledger | tee /tmp/fykz-run.log
# NB: run.sh's [verify]/[ledger] lines go to STDERR, so on-screen they appear AFTER the
# summary path — but `tee` only captures STDOUT, so the log's last line is genuinely the
# .interrogate.json path. tail -n1 is correct; don't "fix" it.
SUMMARY="$(tail -n1 /tmp/fykz-run.log)"
test -s "$SUMMARY" || { echo "FATAL: no kill-zone summary produced — see engine error above."; exit 1; }
```

---

## 5. Parse + print the kill-zone scorecard

The summary file (`$SUMMARY`, the `*.interrogate.json`) **is** the `summary` object: its
top-level keys include `status`, `nextActions`, `metricCitations`, `intersections`, `vectors`,
`thresholds`, `churn`, `securityEscalations`, and `analysisFile`. Read each field below directly
— **do not recompute anything**; the engine already did the intersection math, and rule 5
forbids you inventing it.

> ⚠️ **zsh users (the macOS default shell):** `$status` is a **read-only reserved variable** in
> zsh — assigning `status=$(…)` aborts with `read-only variable: status` and you get no
> scorecard. This block uses `kzstatus` to avoid that. (If you adapt it, never name a variable
> `status`, `path`, or `argv` in zsh.)

```bash
J="$SUMMARY"
kzstatus=$(jq -r '.status' "$J")
hicx=$(jq -r '.metricCitations.highComplexityFileCount.value' "$J")
hich=$(jq -r '.metricCitations.highChurnFileCount.value' "$J")
bhh=$(jq -r '.metricCitations.banditHighHigh.value' "$J")
semg=$(jq -r '.metricCitations.semgrepTotalFindings.value' "$J")
kz=$(jq -r '.intersections.fragilityDensityProd | length' "$J")           # churn ∩ complexity (prod)
p0=$(jq -r '.intersections.p0Prod | length' "$J")                         # churn ∩ complexity ∩ vuln (prod)
churn_thr=$(jq -r '.thresholds.churn' "$J")
cx_thr=$(jq -r '.thresholds.complexity' "$J")
next=$(jq -r '.nextActions[0] // "none"' "$J")
window=$(jq -r '.churn.sinceEffective // .churn.sinceRequested // "90 days ago"' "$J")
```

If any `jq` returns `null` or empty, that tool degraded — print `could not compute` for that
row and name the degraded tool (rule 5). Every row below cites the `jsonPath` it came from so
the human can reproduce it.

**Print exactly this shape** (substitute the stamped values; the `JSON path` column is the
reproduce instruction):

```
YOUR KILL ZONE — <OWNER/REPO>@<sha>
Window: churn since <window>  |  As of: <YYYY-MM-DD>  |  air-gapped: --network none

Signal                          | Value (stamped)                  | JSON path (reproduce)
--------------------------------+----------------------------------+-------------------------------------------------
High-complexity files (cc≥<cx_thr>) | <hicx>                       | .metricCitations.highComplexityFileCount.value
High-churn files (≥<churn_thr> chg) | <hich>                       | .metricCitations.highChurnFileCount.value
Bandit HIGH/HIGH (escalation)   | <bhh>                            | .metricCitations.banditHighHigh.value
Semgrep findings                | <semg>                           | .metricCitations.semgrepTotalFindings.value
KILL ZONE (churn ∩ complexity)  | <kz> files                       | .intersections.fragilityDensityProd[]
P0 (churn ∩ complexity ∩ vuln)  | <p0> files                       | .intersections.p0Prod[]
--------------------------------+----------------------------------+-------------------------------------------------
STATUS: <kzstatus>   (COMPLETE_NO_P0 | FD_ACTION_REQUIRED | P0_ACTION_REQUIRED | SECURITY_ESCALATION)
NEXT:   <nextActions[0]>
```

> **Count vs vector:** `highComplexityFileCount` is the raw count of *all* files at cc ≥ threshold
> (can be large). It is distinct from `.vectors.density`, the candidate set the engine carries into
> the intersection, which is **capped at `.thresholds.maxCandidates` (25)**. So a count of 53 with a
> density vector of 25 is correct and consistent — not a discrepancy.

Every numeric cell is stamped `<value>, <OWNER/REPO>@<sha>, as of <TODAY>` per rule 3. Read
the status meanings to the human:
- **`COMPLETE_NO_P0`** — no file is in all three vectors; no production P0. Clean breadth pass.
- **`FD_ACTION_REQUIRED`** — there *is* a churn ∩ complexity kill zone (list it); look there by hand.
- **`P0_ACTION_REQUIRED`** — files sit in churn ∩ complexity ∩ vulnerability. Highest-priority hand review.
- **`SECURITY_ESCALATION`** — bandit HIGH/HIGH in production paths. Escalate.

Then print the human-readable kill-zone file list so they know *which files* to open:
```bash
echo "Kill-zone files (open these by hand):"; jq -r '.intersections.fragilityDensityProd[]' "$J"
echo "P0 files (highest priority):";          jq -r '.intersections.p0Prod[]'          "$J"
```

---

## 6. Verifiability footer — the AIV teaser (print this; it is the point)

**Do not skip this.** The result is only half the message; the *provenance* is the other half,
and it is the single most on-brand moment in the demo. The message to the human is: **"Don't
trust me — re-run it yourself and check the chain."** Print all three:

```bash
# 1) WORM ledger head hash (only present if you ran with --ledger)
LEDGER_HEAD="$(sed -E -n 's/.* sha=([0-9a-fA-F]{64}).*/\1/p' output/analysis_ledger.log | tail -n1)"
# 2) clean-room fingerprint: SHA-256 of the Dockerfile that pins the exact 45-tool
#    toolchain. THIS is the determinism anchor — stable and reproducible by anyone.
#    (The local docker image id is NOT stable across cached rebuilds: BuildKit
#    re-exports the manifest on every `docker build`, so do not anchor on it.)
CLEANROOM="$(shasum -a 256 infrastructure/Dockerfile 2>/dev/null | awk '{print $1}')"
# 3) the exact, copy-pasteable re-run command
```

Print:
```
VERIFY: ledger <LEDGER_HEAD:0:12>  |  clean-room <CLEANROOM:0:12>  |  re-run: ./run.sh <OWNER/REPO|path> --since "<window>" --ledger
```

Explain, briefly, what each token *proves*:
- **ledger `<...>`** — the head of a self-contained SHA-256 WORM chain over this run's outputs.
  It chains to the prior entry (`prev=` field). Tamper with any past line and the chain breaks —
  prove it yourself: `./run.sh --verify output/analysis_ledger.log` re-derives every entry's hash
  and chain-links them, exiting non-zero with `HASH MISMATCH` on any edit. No service of ours is
  involved; it's plain `shasum -a 256` under the hood.
- **clean-room `<...>`** — SHA-256 of the Dockerfile that pins the exact 45-tool toolchain. Same
  clean-room fingerprint + same `@SHA` + same window ⇒ same kill zone (rule 4). Reproducible by
  anyone: `shasum -a 256 infrastructure/Dockerfile`. (Don't anchor on the local docker image id —
  BuildKit re-exports it on every rebuild, even when nothing changed.)
- **re-run** — the one command that reproduces everything above, air-gapped, from scratch.

This is the AIV (verifiable-evidence) protocol shown as a *teaser*: the ledger is a trivially
non-secret provenance primitive. It proves the run **happened and is reproducible**. It is a
gift; the buyer-verification pipeline behind it is not in this repo (§7).

---

## 7. Honest limits — say these out loud, do not bury them

State these to the human verbatim. Overselling the kill zone torches the credibility the
air-gap buys.

- **This proves breadth *ran* and is *verifiable* — it does NOT prove a finding is real.**
  The kill zone is *where to look by hand*, the machine's nomination, **not** an adjudicated
  bug. Turning a kill-zone file into a confirmed finding is human depth work (Black Box's
  "Set-A") that is **deliberately not in this tool.** That gap is the product, not an omission.
- **Churn-window sensitivity.** The kill zone moves with `--since`. A 90-day window and a
  1-year window can nominate different files. The window is stamped in the scorecard (`Window:`);
  changing it is a legitimate different question, not a bug.
- **Shallow-clone distortion.** The historian needs commit depth. `run.sh` best-effort
  unshallows the `/tmp` *copy*, but a CI shallow clone with no history can still understate
  churn. If `.churn.commitCount` looks implausibly low, say so.
- **Tool-class false positives.** semgrep/bandit findings are *candidates*, not verdicts —
  keyword-class rules over-fire. The engine's value is *intersecting* them with churn and
  complexity to rank, not adjudicating any single finding. A lone semgrep hit on a low-churn,
  low-complexity file is not your kill zone.
- **Build is heavy.** Multi-GB image, minutes to build (45 vendored tools). That is the honest
  cost of an air-gapped breadth engine; the front-door front-loads the expectation.
- **"Could not compute" beats a guess.** If a tool degraded, the affected row says so. That is
  the design, not a failure (rule 5).

---

*FIND-YOUR-KILL-ZONE — the breadth half, shipped honestly and in full, including the kill-zone
overlap. The breadth is the gift; the verifiable-findings + buyer pipeline is the moat, and it
stays withheld. Re-run it. Check the chain.*
