#!/usr/bin/env bash
# find-your-kill-zone — thin, air-gapped, single-repo runner.
#
# Replaces the 1011-line fleet machinery of the monorepo's
# scripts/analyze_host.sh. KEEPS: cp→/tmp workspace, air-gapped
# `docker compose run`, the BB_ANALYZE_PROGRESS `_present` curated heartbeat,
# the analyze→interrogate chain, a single JSON deliverable, and an opt-in
# self-contained SHA-256 WORM ledger. DROPS: per-job UUID vault nests,
# dual-mirror, retention janitor, teardown-watchdog fleet, telemetry/avt_log,
# and ~15 BB_* flags.
#
# Usage:
#   ./run.sh <repo_path_or_url> [--since "<window>"] [--ledger]
#   ./run.sh --verify <ledger-file>     # re-derive + chain-check a WORM ledger
#
# Output:
#   ./output/analysis/<target>.local.analysis.extended.<ts>.json   (extended dump)
#   ./output/analysis/<target>.interrogate.json                    (THE kill zone)
#
# FIX-2: the §7.2 kill-zone summary is emitted by `interrogate`, not `analyze`.
#        run.sh runs analyze (→ extended JSON) THEN interrogate (→ summary JSON).
# FIX-3: a boot/init failure must NOT be masked by the progress filter. The
#        engine's non-zero exit propagates; no summary JSON ⇒ hard error, never
#        exit 0.
set -u
set -o pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$REPO_ROOT/infrastructure/docker-compose.yml"

# ── arg parse (Test Layer A) ───────────────────────────────────────────────
TARGET_ARG=""
SINCE="90 days ago"
LEDGER="false"
VERIFY_FILE=""
USAGE="Usage: $0 <repo_path_or_url> [--since \"<window>\"] [--ledger]  |  $0 --verify <ledger-file>"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --since) SINCE="${2:-}"; shift 2 ;;
    --since=*) SINCE="${1#*=}"; shift ;;
    --ledger) LEDGER="true"; shift ;;
    --verify) VERIFY_FILE="${2:-}"; shift 2 ;;
    --verify=*) VERIFY_FILE="${1#*=}"; shift ;;
    -h|--help)
      echo "$USAGE" >&2
      exit 0 ;;
    -*)
      echo "[error] unknown flag: $1" >&2
      exit 2 ;;
    *)
      if [ -z "$TARGET_ARG" ]; then TARGET_ARG="$1"; else
        echo "[error] unexpected extra argument: $1" >&2; exit 2
      fi
      shift ;;
  esac
done

# ── SHA-256 helpers + WORM ledger verifier (top-level so --verify can run
#    before any analysis, and so the append path can verify-before-append).
_sha_str() {
  if command -v shasum >/dev/null 2>&1; then printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then printf '%s' "$1" | sha256sum | awk '{print $1}'
  else echo ""; fi
}
_sha_file() {
  [ -f "$1" ] || { echo ""; return; }
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else echo ""; fi
}
# Re-derives each entry's hash from prev|ts|event|os|details and checks the
# prev← chain linkage. Detects ANY edit to a past line. Returns non-zero on the
# first break. This is the verifier the --ledger marketing promises; without it
# the chain is append-only theater.
_verify_ledger() {
  local file="$1" expected_prev="0" n=0 line sha prev ts event details os recomputed
  if [ ! -f "$file" ]; then echo "[verify] no ledger at $file — nothing to verify." >&2; return 0; fi
  while IFS= read -r line; do
    n=$((n + 1)); [ -z "$line" ] && continue
    sha="$(printf '%s' "$line"     | sed -E -n 's/.* sha=([0-9a-fA-F]{64}).*/\1/p')"
    prev="$(printf '%s' "$line"    | sed -E -n 's/.* prev=([0-9a-fA-F]{64}|0).*/\1/p')"
    ts="$(printf '%s' "$line"      | sed -E -n 's/^\[([^]]+)\].*/\1/p')"
    event="$(printf '%s' "$line"   | sed -E -n 's/^\[[^]]+\] ([A-Z0-9_]*):.*/\1/p')"
    details="$(printf '%s' "$line" | sed -E -n 's/^\[[^]]+\] [A-Z0-9_]*: (.*) os=.*/\1/p')"
    os="$(printf '%s' "$line"      | sed -E -n 's/.* os=([^ ]*).*/\1/p')"
    if [ -z "$sha" ] || [ -z "$prev" ] || [ -z "$ts" ] || [ -z "$event" ] || [ -z "$details" ] || [ -z "$os" ]; then
      echo "[verify] ❌ line $n malformed — cannot verify chain. FAIL." >&2; return 1
    fi
    if [ "$prev" != "$expected_prev" ]; then
      echo "[verify] ❌ line $n chain break: expected prev=$expected_prev, got prev=$prev. FAIL." >&2; return 1
    fi
    recomputed="$(_sha_str "$prev|$ts|$event|$os|$details")"
    if [ -z "$recomputed" ] || [ "$recomputed" != "$sha" ]; then
      echo "[verify] ❌ line $n HASH MISMATCH — entry was tampered. FAIL." >&2; return 1
    fi
    expected_prev="$sha"
  done < "$file"
  echo "[verify] ✓ WORM ledger intact: $n entries chain-verified ($file)" >&2
  return 0
}

# --verify mode: check a ledger and exit (no analysis, no target needed).
if [ -n "$VERIFY_FILE" ]; then
  _verify_ledger "$VERIFY_FILE"; exit $?
fi

if [ -z "$TARGET_ARG" ]; then
  echo "$USAGE" >&2
  exit 2
fi

# ── resolve target: URL → clone to /tmp; else local path ───────────────────
CLONE_TMP=""
# Clean up on EXIT: the URL clone (if any) AND the /tmp workspace copy. WORKSPACE is
# guarded with ${WORKSPACE:-} because it isn't assigned until later and this script
# runs under `set -u`. Leaving the workspace behind between runs is untidy (a cp -R of
# the target lingers in /tmp); this reaps it whether the run succeeds, errors, or aborts.
cleanup() {
  [ -n "${CLONE_TMP:-}" ] && rm -rf "$CLONE_TMP" 2>/dev/null
  [ -n "${WORKSPACE:-}" ] && rm -rf "$WORKSPACE" 2>/dev/null
  return 0
}
trap cleanup EXIT

case "$TARGET_ARG" in
  http://*|https://*|git@*|ssh://*)
    CLONE_TMP="$(mktemp -d "/tmp/find-your-kill-zone-clone.XXXXXX")"
    echo "[clone] $TARGET_ARG → $CLONE_TMP (network used HERE, before the air gap)" >&2
    if ! git clone --no-single-branch "$TARGET_ARG" "$CLONE_TMP/repo"; then
      echo "[error] git clone failed: $TARGET_ARG" >&2
      exit 1
    fi
    SRC_REPO="$CLONE_TMP/repo"
    ;;
  *)
    if [ ! -d "$TARGET_ARG" ]; then
      echo "[error] not a directory and not a URL: $TARGET_ARG" >&2
      exit 1
    fi
    SRC_REPO="$(cd "$TARGET_ARG" && pwd)"
    git -C "$SRC_REPO" rev-parse --git-dir >/dev/null 2>&1 || { echo "[error] target is not a git repository (or has no commits) — churn cannot be measured. Point at a git checkout with history." >&2; exit 1; }
    ;;
esac

TARGET_NAME="$(basename "$SRC_REPO")"

# ── stage into a /tmp workspace (NOT a vault) ──────────────────────────────
# The container mounts this dir at /workspace. cp -R so the user's clone is
# never mutated (best-effort unshallow happens on the COPY only).
WORKSPACE="/tmp/find-your-kill-zone-workspace"
rm -rf "$WORKSPACE" 2>/dev/null || true
mkdir -p "$WORKSPACE/$TARGET_NAME"
cp -R "$SRC_REPO/." "$WORKSPACE/$TARGET_NAME/"
# Best-effort unshallow the COPY (historian needs depth); never the user's repo.
if [ -f "$WORKSPACE/$TARGET_NAME/.git/shallow" ]; then
  ( cd "$WORKSPACE/$TARGET_NAME" && git fetch --unshallow ) 2>/dev/null || true
fi

OUT_DIR="$REPO_ROOT/output/analysis"
mkdir -p "$OUT_DIR"
TS="$(date -u +"%Y%m%dT%H%M%SZ")"
ANALYSIS_HOST="$OUT_DIR/${TARGET_NAME}.local.analysis.extended.${TS}.json"
ANALYSIS_CONT="/workspace/output/${TARGET_NAME}.local.analysis.extended.${TS}.json"
SUMMARY_HOST="$OUT_DIR/${TARGET_NAME}.interrogate.json"
SUMMARY_CONT="/workspace/output/${TARGET_NAME}.interrogate.json"

mkdir -p "$WORKSPACE/output"

# ── BB_ANALYZE_PROGRESS curated heartbeat (KEEP, §2) ───────────────────────
# Crostini note: default mawk block-buffers stdin; `-W interactive` line-buffers
# it. macOS BSD awk line-buffers to a pipe and rejects -W, so probe once.
_BB_AWK_I=(awk)
if awk -W interactive 'BEGIN{exit 0}' </dev/null >/dev/null 2>&1; then
  _BB_AWK_I=(awk -W interactive)
fi
_present() {
  if [ "${BB_ANALYZE_PROGRESS:-}" != "1" ]; then cat; return; fi
  "${_BB_AWK_I[@]}" '
    /^\[skip\]/        { next }
    /^outfile \(/      { next }
    /^since window:/   { next }
    /^\[done\]/        { next }
    / -> /             { next }
    /^\/workspace\//   { next }
    /parallel worker_threads/ { t=""; if (match($0,/\[\+[0-9]+s\]/)) t=substr($0,RSTART,RLENGTH); print "  ▸ " t " sweeping: python · javascript · go · historian  (parallel)"; fflush(); next }
    /pysub:bandit:/        { t=""; if (match($0,/\[\+[0-9]+s\]/)) t=substr($0,RSTART,RLENGTH); n=$0; sub(/.*pysub:bandit:/,"",n); print "         python › " t " bandit ✓ · " n " high-severity"; fflush(); next }
    /pysub:semgrep-start:/ { t=""; if (match($0,/\[\+[0-9]+s\]/)) t=substr($0,RSTART,RLENGTH); n=$0; sub(/.*pysub:semgrep-start:/,"",n); print "         python › " t " semgrep — deep security scan, " n " files…"; fflush(); next }
    /pysub:semgrep:/       { t=""; if (match($0,/\[\+[0-9]+s\]/)) t=substr($0,RSTART,RLENGTH); n=$0; sub(/.*pysub:semgrep:/,"",n); print "         python › " t " semgrep ✓ · " n " findings"; fflush(); next }
    /done:[a-z]/       { t=""; if (match($0,/\[\+[0-9]+s\]/)) t=substr($0,RSTART,RLENGTH); tool=$0; sub(/.*done:/,"",tool); print "       ✓ " t " " tool; fflush(); next }
    /degraded:[a-z]/   { t=""; if (match($0,/\[\+[0-9]+s\]/)) t=substr($0,RSTART,RLENGTH); tool=$0; sub(/.*degraded:/,"",tool); print "       ⚠ " t " " tool " (degraded)"; fflush(); next }
    /analyzers done/   { t=""; if (match($0,/\[\+[0-9]+s\]/)) t=substr($0,RSTART,RLENGTH); print "  ▸ " t " ✓ analyzers complete"; fflush(); next }
    # FIX-3: everything else — including [fail]/[abort]/stderr/tool errors and
    # ts-node init traces — PASSES THROUGH so a boot failure is never hidden.
    { print; fflush() }
  '
}

# ── reduced env set (§2: ~5 flags) ─────────────────────────────────────────
# KEEP: BB_PARALLEL_ANALYZERS, BB_SEMGREP_JOBS, BB_ANALYZE_PROGRESS,
#       BB_ANALYZE_T0, --since. Everything else dropped.
BB_PARALLEL_ANALYZERS="${BB_PARALLEL_ANALYZERS:-1}"
# semgrep is the long pole. jobs=4 matches the demo timing (cai: ~72s sweep / ~94s
# total vs ~3min single-threaded). Default to 4 for the snappy out-of-box experience;
# semgrep degrades gracefully under memory pressure, but on a VERY large target
# (thousands of files) you can lower it — `BB_SEMGREP_JOBS=1 ./run.sh …` — to cap RAM.
BB_SEMGREP_JOBS="${BB_SEMGREP_JOBS:-4}"
BB_ANALYZE_PROGRESS="${BB_ANALYZE_PROGRESS:-1}"
BB_ANALYZE_T0="${BB_ANALYZE_T0:-$(date +%s)}"

# In-container env. NODE_PATH lets the engine resolve `commander` from the
# image-baked /opt/node_modules (FIX-1); the ts-node loader resolves from the
# global /usr/local/lib/node_modules. TS_NODE_TRANSPILE_ONLY skips type-check.
CONTAINER_ENV="NODE_NO_WARNINGS=1 \
NODE_PATH=/usr/local/lib/node_modules:/opt/node_modules \
TS_NODE_PROJECT=/opt/tsconfig.json \
TS_NODE_TRANSPILE_ONLY=1 \
BB_PARALLEL_ANALYZERS=$BB_PARALLEL_ANALYZERS \
BB_SEMGREP_JOBS=$BB_SEMGREP_JOBS \
BB_ANALYZE_PROGRESS=$BB_ANALYZE_PROGRESS \
BB_ANALYZE_T0=$BB_ANALYZE_T0"

LOADER="/usr/local/lib/node_modules/ts-node/esm.mjs"

# compose run: --rm (ephemeral), -T (no TTY), explicit per-run workspace mount.
# --network none is enforced by docker-compose.yml (network_mode: none); there
# is NO --network passthrough here (rule 4 / D3).
DC=(docker compose -f "$COMPOSE_FILE")
RUN_BASE=(run --rm -T -v "$WORKSPACE:/workspace" audit-env)

# FIX-2 step 1 of 2 — analyze → extended analysis JSON.
ANALYZE_PAYLOAD="mkdir -p /tmp/.config /tmp/.cache /tmp/.semgrep /workspace/output; \
export $CONTAINER_ENV; \
node --loader $LOADER /opt/engine/cli.ts analyze --since \"$SINCE\" --out '$ANALYSIS_CONT' '/workspace/$TARGET_NAME'"

echo "[start] $(date -u) analyze container run — clean room · air-gapped (--network none)" >&2
"${DC[@]}" "${RUN_BASE[@]}" bash -lc "$ANALYZE_PAYLOAD" 2>&1 | _present
RC_ANALYZE=${PIPESTATUS[0]}

# FIX-3: propagate the engine's non-zero exit; the extended artifact must exist.
if [ "$RC_ANALYZE" -ne 0 ]; then
  echo "[abort] analyze exited non-zero (rc=$RC_ANALYZE) — air-gapped engine failed to boot/run. NOT exiting 0." >&2
  exit "$RC_ANALYZE"
fi
if [ ! -f "$WORKSPACE/output/${TARGET_NAME}.local.analysis.extended.${TS}.json" ]; then
  echo "[abort] analyze produced no extended-analysis JSON — hard error (FIX-3), not a silent pass." >&2
  exit 1
fi
# Surface the host-side extended artifact.
cp "$WORKSPACE/output/${TARGET_NAME}.local.analysis.extended.${TS}.json" "$ANALYSIS_HOST"

# FIX-2 step 2 of 2 — interrogate → the §7.2 kill-zone summary JSON (THE deliverable).
INTERROGATE_PAYLOAD="export $CONTAINER_ENV; \
node --loader $LOADER /opt/engine/cli.ts interrogate '$ANALYSIS_CONT' --out '$SUMMARY_CONT'"

echo "[start] $(date -u) interrogate — computing kill zone" >&2
"${DC[@]}" "${RUN_BASE[@]}" bash -lc "$INTERROGATE_PAYLOAD" 2>&1 | _present
RC_INTERROGATE=${PIPESTATUS[0]}

if [ "$RC_INTERROGATE" -ne 0 ]; then
  echo "[abort] interrogate exited non-zero (rc=$RC_INTERROGATE). NOT exiting 0." >&2
  exit "$RC_INTERROGATE"
fi
if [ ! -f "$WORKSPACE/output/${TARGET_NAME}.interrogate.json" ]; then
  echo "[abort] interrogate produced NO kill-zone summary JSON — hard error (FIX-3)." >&2
  exit 1
fi
cp "$WORKSPACE/output/${TARGET_NAME}.interrogate.json" "$SUMMARY_HOST"

echo "$SUMMARY_HOST"

# ── opt-in WORM ledger (KEEP, simplified — §2) ─────────────────────────────
# Self-contained SHA-256 chain, no DB. Appends one verifiable line per run.
if [ "$LEDGER" = "true" ]; then
  LEDGER_FILE="$REPO_ROOT/output/analysis_ledger.log"
  ( umask 077; mkdir -p "$(dirname "$LEDGER_FILE")"; touch "$LEDGER_FILE" )
  chmod 600 "$LEDGER_FILE" 2>/dev/null || true

  # Verify-before-append: refuse to extend a chain that has been tampered with
  # (matches the monorepo's analyze_host.sh discipline). Without this, a forged
  # ledger would silently grow a fresh valid-looking tail on top of a broken chain.
  if ! _verify_ledger "$LEDGER_FILE"; then
    echo "[ledger] ❌ refusing to append to a tampered/corrupt ledger. Aborting." >&2
    exit 1
  fi

  TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  EVENT="ANALYSIS_COMPLETED"
  OS="$(uname -s)"
  SUMMARY_SHA="$(_sha_file "$SUMMARY_HOST")"; [ -z "$SUMMARY_SHA" ] && SUMMARY_SHA="unavailable"
  ANALYSIS_SHA="$(_sha_file "$ANALYSIS_HOST")"; [ -z "$ANALYSIS_SHA" ] && ANALYSIS_SHA="unavailable"
  DETAILS="target=$TARGET_NAME since=$SINCE summary=$(basename "$SUMMARY_HOST") summary_sha=$SUMMARY_SHA analysis_sha=$ANALYSIS_SHA"

  PREV_HASH="$(tail -n 1 "$LEDGER_FILE" 2>/dev/null | sed -E -n 's/.* sha=([0-9a-fA-F]{64}).*/\1/p')"
  [ -z "$PREV_HASH" ] && PREV_HASH="0"
  CHAIN_INPUT="$PREV_HASH|$TIMESTAMP|$EVENT|$OS|$DETAILS"
  NEW_HASH="$(_sha_str "$CHAIN_INPUT")"
  if [ -z "$NEW_HASH" ]; then
    echo "[error] no SHA-256 tool available — cannot append WORM ledger entry." >&2
    exit 1
  fi
  echo "[$TIMESTAMP] $EVENT: $DETAILS os=$OS prev=$PREV_HASH sha=$NEW_HASH" >> "$LEDGER_FILE"
  echo "[ledger] appended: $LEDGER_FILE (head sha=${NEW_HASH:0:12})" >&2
fi
