import { parentPort, workerData } from "node:worker_threads";
import { runPythonAnalysis } from "./python.js";
import { runJavaScriptAnalysis } from "./javascript.js";
import { runGoAnalysis } from "./go.js";
import { runHistorianAnalysis } from "./historian.js";

// Structured-clone-safe slice of AnalysisContext (strings / number / string[]).
// Each runXAnalysis below is the EXISTING sync (or async, for historian) fn;
// the spawnSync inside each blocks only THIS worker's OS thread, so four
// workers run their semgrep/bandit/gosec/hercules subprocesses concurrently.
// BB_SEMGREP_JOBS is read via process.env inside python.ts, inherited here
// through the Worker's { env: process.env } option in analyze.ts.
type Ctx = {
  absolutePath: string;
  trackedFiles: string[];
  hasGoFiles: boolean;
  tsconfigs: string[];
  repoFileCount: number;
  churnRaw: string;
  churnSince: string;
};

async function main(): Promise<void> {
  const { tool, context } = workerData as { tool: string; context: Ctx };
  try {
    let res: unknown;
    if (tool === "python") {
      res = await runPythonAnalysis(
        context.absolutePath,
        context.trackedFiles,
        (msg) => parentPort?.postMessage({ progress: msg }),
      );
    } else if (tool === "javascript") {
      res = runJavaScriptAnalysis(
        context.absolutePath,
        context.trackedFiles,
        context.tsconfigs,
        context.repoFileCount,
      );
    } else if (tool === "go") {
      res = runGoAnalysis(context.absolutePath, context.hasGoFiles);
    } else if (tool === "historian") {
      res = await runHistorianAnalysis(
        context.absolutePath,
        context.churnRaw,
        context.churnSince,
      );
    } else {
      throw new Error(`unknown tool: ${tool}`);
    }
    parentPort?.postMessage({ ok: true, tool, res });
  } catch (e) {
    parentPort?.postMessage({
      ok: false,
      tool,
      error: e instanceof Error ? e.message : String(e),
    });
  }
}

void main();
