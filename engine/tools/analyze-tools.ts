import { createToolRegistry, type ForensicTool } from "./registry.js";

import { runGoAnalysis } from "../analyzers/go.js";
import { runHistorianAnalysis } from "../analyzers/historian.js";
import { runJavaScriptAnalysis } from "../analyzers/javascript.js";
import { runPythonAnalysis } from "../analyzers/python.js";

export type AnalysisContext = {
  absolutePath: string;
  trackedFiles: string[];
  hasGoFiles: boolean;
  tsconfigs: string[];
  repoFileCount: number;
  churnRaw: string;
  churnSince: string;
};

/**
 * Create a tool registry populated with the default forensic analysis tools.
 *
 * The registry is pre-registered with tools for Python, JavaScript/TypeScript, Go, and repository history analysis.
 *
 * @returns A tool registry configured for AnalysisContext containing the default forensic tools
 */
export function createDefaultAnalyzeToolRegistry() {
  const registry = createToolRegistry<AnalysisContext>();

  const pythonTool: ForensicTool<AnalysisContext> = {
    name: "python",
    languages: ["python"],
    execute(context) {
      return runPythonAnalysis(context.absolutePath, context.trackedFiles);
    },
  };

  const javascriptTool: ForensicTool<AnalysisContext> = {
    name: "javascript",
    languages: ["javascript", "typescript"],
    execute(context) {
      return runJavaScriptAnalysis(
        context.absolutePath,
        context.trackedFiles,
        context.tsconfigs,
        context.repoFileCount,
      );
    },
  };

  const goTool: ForensicTool<AnalysisContext> = {
    name: "go",
    languages: ["go"],
    execute(context) {
      return runGoAnalysis(context.absolutePath, context.hasGoFiles);
    },
  };

  const historianTool: ForensicTool<AnalysisContext> = {
    name: "historian",
    languages: ["git"],
    execute(context) {
      return runHistorianAnalysis(
        context.absolutePath,
        context.churnRaw,
        context.churnSince,
      );
    },
  };

  registry.register(pythonTool);
  registry.register(javascriptTool);
  registry.register(goTool);
  registry.register(historianTool);

  return registry;
}