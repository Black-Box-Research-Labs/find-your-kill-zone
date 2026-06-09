/**
 * find-your-kill-zone — stripped CLI entrypoint.
 *
 * ── What this is ───────────────────────────────────────────────────────────
 * A minimal Commander program that registers EXACTLY two verbs, both exported
 * verbatim from `./commands/analyze.ts`:
 *
 *   • `analyze`     — runs the air-gapped analyzer sweep (python · javascript ·
 *                     go · historian via worker_threads) and writes the
 *                     extended analysis JSON.
 *   • `interrogate` — reads that analysis JSON and emits the §7.2 kill-zone
 *                     `summary` (status / metricCitations / intersections /
 *                     vectors / thresholds). THIS is the deliverable.
 *
 * (FIX-2 / run-1 DEVIATION-1: the kill-zone summary is produced by
 * `interrogate`, not `analyze`; `run.sh` chains analyze → interrogate.)
 *
 * ── What this deliberately omits ───────────────────────────────────────────
 * Upstream, this entrypoint eagerly wired ~40 sibling commands plus `dotenv`,
 * telemetry hooks, a metadata registry, and help-grouping — all delegated to an
 * internal DB/tracker layer, severed here. NONE of that is imported in this
 * release. Direct (non-lazy) import of the two commands is safe precisely
 * because `analyze.ts`'s entire graph is engine-internal + vendored after
 * extraction.
 *
 * No DB, no tracker, no telemetry, no watch, no dotenv.
 */

import { Command } from "commander";
import { fileURLToPath } from "node:url";

import { analyzeCommand, interrogateCommand } from "./commands/analyze.js";

/**
 * Build the two-verb breadth-engine program.
 */
export function buildProgram(): Command {
  const program = new Command();

  program
    .name("find-your-kill-zone")
    .description("Air-gapped breadth engine — analyze + interrogate (kill zone)")
    .showHelpAfterError(true)
    .showSuggestionAfterError(true);

  program.addCommand(analyzeCommand);
  program.addCommand(interrogateCommand);

  return program;
}

export async function main(argv: string[] = process.argv): Promise<void> {
  const program = buildProgram();
  await program.parseAsync(argv);
}

// Run when invoked directly (e.g. `node --loader ts-node/esm engine/cli.ts ...`).
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  });
}
