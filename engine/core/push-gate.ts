/**
 * push-gate adapter — SEVERED no-op stub for the standalone breadth engine.
 *
 * ── Provenance ─────────────────────────────────────────────────────────────
 * Upstream, this module delegated to an internal DB/tracker layer, severed
 * here. That layer (database / RLS session / tracker) is not part of the
 * standalone breadth engine and is therefore absent from this public release.
 *
 * ── Why a stub and not a deletion ──────────────────────────────────────────
 * `engine/commands/analyze.ts` calls `pushGate(...)` after writing its artifact.
 * The upstream implementation is ALREADY an env-gated no-op: it returns
 * immediately unless an internal DB env var (unused in the standalone engine)
 * is set. In the air-gapped standalone that env var is never set, so the
 * original code path is a pure no-op. This stub reproduces that exact runtime
 * behavior (return early, never throw, never reach a DB) WITHOUT carrying the
 * internal import graph.
 *
 * The `analyze.ts` call site is copied verbatim — only the import this file
 * satisfies changed. No analysis logic, threshold, or metric is touched.
 */

/**
 * Gate-state record shape. Inlined here (upstream this type came from the
 * internal tracker layer, severed in this release). Kept structurally
 * identical so the verbatim `analyze.ts` call site type-checks unchanged.
 */
export type GateRecord = {
  gate: string;
  status: string;
  updatedAt: string;
  details?: string;
  evidencePaths?: string[];
};

/**
 * No-op in the standalone breadth engine. The upstream behavior was an
 * env-gated no-op (no internal DB env var ⇒ early return); air-gapped, that env
 * is never present, so the observable behavior is identical: the artifact write
 * already succeeded, and there is no tracker/DB to push to.
 */
export async function pushGate(
  _targetId: string,
  _gateId: string,
  _record: GateRecord,
): Promise<void> {
  return;
}
