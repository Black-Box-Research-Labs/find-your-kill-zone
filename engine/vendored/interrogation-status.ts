/**
 * Canonical EXEC3_5 interrogation status enum + type guard.
 *
 * Extracted from `engine/commands/analyze.ts:1229` where the union was
 * inlined. Shared module exists so dispatcher (Stream G —
 * `watch-dispatchers-interrogate.ts`) + DAL persistence
 * (`interrogation_artifacts` table) + verify-stage evaluators agree on the
 * value space without each redeclaring it.
 *
 * Per EXEC3_5 §2.2-2.4 + §7.3 (Mandatory Outcome Declaration):
 *   - `COMPLETE_NO_P0`: triple-intersection empty AND (if churn.selectionMode
 *     ∈ {expanded,fallback}) `fragilityDensityProd` computed + recorded.
 *   - `P0_ACTION_REQUIRED`: `intersections.p0Prod[]` non-empty.
 *   - `FD_ACTION_REQUIRED`: `p0Prod` empty BUT `fragilityDensityProd[]`
 *     non-empty under expanded/fallback churn.
 *   - `SECURITY_ESCALATION`: Bandit HIGH+HIGH bypass per EXEC3_5 §2.2; tag
 *     dominates other classifications (set before P0 check).
 *
 * Trace gate (EXEC3_6) auto-chains when status `!== "COMPLETE_NO_P0"`.
 *
 * @see artifacts/shared/protocols/EXEC3_5.md §2, §7.3
 * @see artifacts/shared/protocols/EXEC3_6.md §2 (trigger conditions)
 * @see engine/commands/analyze.ts:1229 (legacy inline declaration site)
 */

/**
 * The four legal terminal status values emitted by `bb-audit interrogate`.
 * Watcher dispatchers, DAL persistence, and downstream trace auto-enqueue
 * decisions all key off this string-typed value.
 */
export type InterrogationStatus =
  | "COMPLETE_NO_P0"
  | "P0_ACTION_REQUIRED"
  | "FD_ACTION_REQUIRED"
  | "SECURITY_ESCALATION";

/**
 * Runtime tuple of all valid `InterrogationStatus` values. Exported so
 * spec assertions + DAL CHECK-constraint generation can iterate over them
 * without redeclaring the union.
 *
 * Order is not semantic — for an "outcome severity" ordering see
 * `STATUS_SEVERITY_RANK` below.
 */
export const INTERROGATION_STATUSES: readonly InterrogationStatus[] = [
  "COMPLETE_NO_P0",
  "P0_ACTION_REQUIRED",
  "FD_ACTION_REQUIRED",
  "SECURITY_ESCALATION",
] as const;

/**
 * Severity ranking for outcome-comparison logic. Higher = more urgent.
 * SECURITY_ESCALATION sits highest because Bandit HIGH+HIGH bypasses the
 * triple-intersection model per EXEC3_5 §2.2. FD_ACTION_REQUIRED ranks below
 * P0_ACTION_REQUIRED because P0 has all three vectors confirmed (Fragility
 * ∩ Density ∩ Vulnerability) while FD has only Fragility ∩ Density.
 */
export const STATUS_SEVERITY_RANK: Record<InterrogationStatus, number> = {
  COMPLETE_NO_P0: 0,
  FD_ACTION_REQUIRED: 1,
  P0_ACTION_REQUIRED: 2,
  SECURITY_ESCALATION: 3,
};

/**
 * Runtime type guard. Use this when parsing LLM stdout or DB row JSONB:
 * `if (!isInterrogationStatus(raw.status)) throw new ValidationError(...)`.
 */
export function isInterrogationStatus(
  value: unknown,
): value is InterrogationStatus {
  return (
    typeof value === "string" &&
    (INTERROGATION_STATUSES as readonly string[]).includes(value)
  );
}

/**
 * Predicate: does this status indicate trace dispatch should auto-chain?
 * Per EXEC3_6 §2.2: chain when status !== `"COMPLETE_NO_P0"`.
 *
 * Used by the watcher's interrogate→trace handoff logic
 * (`watch-dispatchers-interrogate.ts` in Stream G).
 */
export function shouldAutoChainTrace(status: InterrogationStatus): boolean {
  return status !== "COMPLETE_NO_P0";
}
