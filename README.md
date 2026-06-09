# find-your-kill-zone

*An air-gapped breadth engine, by Black Box Research Labs. Sibling to "Who Reviews the
Reviewers?" (WRR).*

This is the **literal stage engine** from a Black Box live demo, extracted standalone: the
exact analyzers and the exact `fragility ∩ density ∩ vulnerability` kill-zone synthesis that
runs on stage. It is **not** a reimplementation. It finds your **kill zone** — the small set
of files that are simultaneously high-churn, high-complexity, and security-flagged. That is
*where a reviewer should look by hand.* It is a nomination, not a verdict.

It runs in a clean room with **its network physically severed** (`--network none`). **Your code
never leaves the box.**

---

## Two depths — pick one

### Depth 1 — start here: hand it to your agent (core)

You don't run commands; **your LLM coding agent does.** Open
**[`FIND-YOUR-KILL-ZONE.md`](./FIND-YOUR-KILL-ZONE.md)** and hand it to your agent (Claude
Code, Cursor, Copilot, etc.) pointed at your repo. That file is its complete instruction set.
It will:

1. check Docker, resolve your `OWNER/REPO@SHA`;
2. build the engine image (one-time, multi-GB, a few minutes);
3. run it **air-gapped** on a `/tmp` copy of your repo (your working tree is never touched);
4. print your **kill-zone scorecard** — every number stamped and tied to the exact JSON path
   that produced it;
5. print a **verifiability footer** (WORM ledger head hash + image digest + the one re-run
   command) so you can re-derive every number yourself.

The agent is the UX. The engine underneath is the real thing. You need only **Docker** and
**this repo** — no account, no API key, no data sent to any service we run.

### Depth 2 — want it air-gapped + reproducible? build the engine yourself (deep)

No agent. Same tool, run by hand:

```bash
# 1. build the clean room (one-time; multi-GB; only step that touches the network)
docker build -f infrastructure/Dockerfile -t find-your-kill-zone .

# 2. run it on your repo, air-gapped, with the verifiability ledger
./run.sh /path/to/your/repo --since "90 days ago" --ledger
#   -> output/analysis/<repo>.interrogate.json   <- THE kill zone (the §7.2 summary)
#   -> output/analysis/<repo>.local.analysis.extended.<ts>.json   <- the full dump
#   -> output/analysis_ledger.log                <- the SHA-256 WORM chain

# 3. read the kill zone
jq '.status, .intersections.fragilityDensityProd, .intersections.p0Prod' \
  output/analysis/<repo>.interrogate.json
```

`run.sh` accepts a local path **or** a clone URL (it clones to `/tmp` *before* the air gap;
the analysis container still runs with no network). Flags: `--since "<window>"`
(default `"90 days ago"`), `--ledger` (opt-in WORM provenance line). The container's
`--network none` is hardcoded in `infrastructure/docker-compose.yml` with no override path.

---

## What it proves — and what it does not

**Proves:** the breadth sweep **ran** and is **reproducible** — same repo + same `@SHA` + same
window ⇒ same kill zone, and the `--ledger` chain lets a third party re-verify it without
trusting us: run `./run.sh --verify output/analysis_ledger.log` — it re-derives every entry's
hash and checks the chain, failing loudly (`HASH MISMATCH`, exit 1) on any tampered line.

**Does not prove:** that any nominated file contains a real bug. The kill zone is *where to
look by hand* — the machine's nomination. Turning a kill-zone file into a confirmed finding is
human depth work that is **deliberately not in this repo.**

> **The line, stated once:** machine breadth is the commodity — that is this gift, shipped in
> full, including the kill-zone overlap. The human depth that confirms a finding, and the
> buyer-verifiable provenance pipeline behind it, are the moat. They are not here.

See [`FIND-YOUR-KILL-ZONE.md` §7](./FIND-YOUR-KILL-ZONE.md) for the full honest-limits list
(churn-window sensitivity, shallow-clone distortion, tool-class false positives, heavy build).

We also ran this tool on **itself** — see [`SELF-AUDIT.md`](./SELF-AUDIT.md). Our own
kill-zone synthesis file is our most complex file, and it's *not* in the kill zone. We show
you exactly why.

---

## After you run it

The kill zone tells you *where to look by hand* — the highest-leverage files to put human eyes
on. It does **not** tell you a finding is real; that's the human Set-A trace work, deliberately
not in this tool.

- **Useful? Missed something?** → there's **one pinned issue**. A 👍, or a one-line "my stack is
  X / it choked on Y", tells us whether to keep maintaining this. No account-linking, no
  telemetry — this repo phones home to nobody (grep it).
- **Want humans to actually trace your kill zone** — verified findings with buyer-checkable
  provenance (the AIV protocol), not just "here's where to look"? → that's what we do:
  **hello@blackboxresearchlabs.com**

*The breadth is the gift. The human depth is the work. Run the breadth on Monday; talk to us
when the breadth scares you.*

---

## Layout

```
find-your-kill-zone/
  FIND-YOUR-KILL-ZONE.md   front door — hand this to your LLM agent
  engine/                  the literal stage engine (analyzers + kill-zone synthesis)
  infrastructure/          the 45-tool air-gapped clean room (Dockerfile + compose + semgrep rules)
  run.sh                   thin air-gapped single-repo runner (+ `--verify` for the WORM ledger)
  SELF-AUDIT.md            what this tool says about its own code
  VALIDATION_REPORT.md     proof the engine == our stage engine (frozen-oracle gate)
  SAFETY_REPORT.md         the adversarial safety panel that gated this repo
  LICENSE · NOTICE · THIRD-PARTY-NOTICES.md
  README.md                this file
```

---

*`find-your-kill-zone`, by [Black Box Research Labs](https://github.com/Black-Box-Research-Labs).
Sibling: [`who-reviews-the-reviewers`](https://github.com/Black-Box-Research-Labs/who-reviews-the-reviewers)
(governance self-audit). The [AIV verification protocol](https://github.com/Black-Box-Research-Labs/aiv-protocol)
is the moat; the breadth is the gift.*
