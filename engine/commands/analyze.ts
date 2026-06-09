import { Command } from "commander";
import { Worker } from "node:worker_threads";
import { existsSync } from "node:fs";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { pushGate } from "../core/push-gate.js";

import {
  isEnvTrue,
  run,
  parseRadonHighComplexityCount,
  parseEslintHighComplexityCount,
  parseBanditHighCount,
  computeHotspotsByChurn,
  summarizeChurnRaw,
  classifyBugFixCommits,
} from "../analyzers/utils.js";
import type { GoAnalysisResult } from "../analyzers/go.js";
import type { HistorianResult } from "../analyzers/historian.js";
import type { JavaScriptAnalysisResult } from "../analyzers/javascript.js";
import type { PythonAnalysisResult } from "../analyzers/python.js";
import {
  createDefaultAnalyzeToolRegistry,
  type AnalysisContext,
} from "../tools/analyze-tools.js";
// A churn-log helper import was removed here — its only consumers were a
// downstream emit block that is out of scope for the standalone breadth tool
// (stripped below). The helper file is not shipped.
import type { InterrogationStatus } from "../vendored/interrogation-status.js";

type AnalyzeOptions = {
  out: string | undefined;
  since: string | undefined;
};

export const analyzeCommand = new Command("analyze")
  .description(
    "Deep forensic analysis (local) for paid audits. Requires a secure container.",
  )
  .argument("<path>", "Path to local repository or codebase")
  .option("--out <path>", "Write analysis JSON to a file (optional)")
  .option(
    "--since <since>",
    "Git churn window (passed to `git log --since=...`)",
    "180 days ago",
  )
  .action(async (targetPath: string, options: AnalyzeOptions) => {
    if (process.env.IN_CONTAINER !== "true") {
      throw new Error(
        "CRITICAL: IN_CONTAINER must be true. Analysis must be performed inside the Forensic Factory. Run: scripts/workspace_init.sh",
      );
    }

    if (!isEnvTrue(process.env.DOCKER_MANDATE)) {
      throw new Error(
        "CRITICAL: DOCKER_MANDATE must be true. Analysis must be performed within a Secure Container.",
      );
    }

    const absolutePath = path.resolve(process.cwd(), targetPath);
    const stat = await fs.stat(absolutePath);
    if (!stat.isDirectory()) {
      throw new Error(`Invalid path: ${absolutePath}`);
    }

    let complexityRaw = "";
    let securityRaw = "";

    const churnSinceRequested = options.since ?? "180 days ago";

    const getChurnRaw = (since: string) =>
      run(
        "git",
        [
          "-C",
          absolutePath,
          "log",
          `--since=${since}`,
          "--name-only",
          "--pretty=format:",
        ],
        absolutePath,
      );

    const getCommitCount = (since: string): number => {
      try {
        const raw = run(
          "git",
          ["-C", absolutePath, "rev-list", "--count", `--since=${since}`, "HEAD"],
          absolutePath,
        ).trim();
        const n = Number.parseInt(raw, 10);
        return Number.isFinite(n) && n >= 0 ? n : 0;
      } catch {
        return 0;
      }
    };

    const churnMinCount = 10;
    const churnMaxCandidates = 25;

    const churnCandidates = [
      churnSinceRequested,
      "180 days ago",
      "365 days ago",
      "730 days ago",
    ].filter((v, idx, arr) => arr.indexOf(v) === idx);

    let churnSinceEffective = churnSinceRequested;
    let churnRaw = getChurnRaw(churnSinceEffective);
    let churnSelectionMode: "strict" | "expanded" | "fallback" = "strict";
    let churnHotspots = computeHotspotsByChurn(churnRaw, {
      minCount: churnMinCount,
      ensureNonEmpty: false,
    });

    let bestSince = churnSinceEffective;
    let bestRaw = churnRaw;
    let bestSummary = summarizeChurnRaw(churnRaw);
    let bestScore = bestSummary.fileTouchLines * 1000 + bestSummary.maxCount;

    if (churnHotspots.length === 0) {
      for (const candidate of churnCandidates.slice(1)) {
        const candidateRaw = getChurnRaw(candidate);
        const candidateSummary = summarizeChurnRaw(candidateRaw);
        const candidateScore =
          candidateSummary.fileTouchLines * 1000 + candidateSummary.maxCount;
        if (candidateScore > bestScore) {
          bestScore = candidateScore;
          bestSince = candidate;
          bestRaw = candidateRaw;
          bestSummary = candidateSummary;
        }
        const candidateHotspots = computeHotspotsByChurn(candidateRaw, {
          minCount: churnMinCount,
          ensureNonEmpty: false,
        });
        if (candidateHotspots.length > 0) {
          churnSelectionMode = "expanded";
          churnSinceEffective = candidate;
          churnRaw = candidateRaw;
          churnHotspots = candidateHotspots;
          break;
        }
      }
    }

    if (churnHotspots.length === 0) {
      churnSelectionMode = "fallback";
      churnSinceEffective = bestSince;
      churnRaw = bestRaw;
      churnHotspots = computeHotspotsByChurn(churnRaw, {
        minCount: churnMinCount,
        ensureNonEmpty: true,
        maxCandidates: churnMaxCandidates,
      });
    }

    const churnSummary = summarizeChurnRaw(churnRaw);
    const churnCommitCount = getCommitCount(churnSinceEffective);

    const churnHotspotsWithBugFix = churnHotspots.map((h) => {
      try {
        const logRaw = run(
          "git",
          ["-C", absolutePath, "log", "--oneline", "--all", "--follow", `--since=${churnSinceEffective}`, "--", h.file],
          absolutePath,
        );
        return { ...h, bugFixCommitCount: classifyBugFixCommits(logRaw) };
      } catch {
        return { ...h, bugFixCommitCount: 0 };
      }
    });

    // Enumerate tracked files to drive conditional tool execution and avoid heavy/no-op scans
    let trackedFiles: string[] = [];
    try {
      trackedFiles = run("git", ["-C", absolutePath, "ls-files"], absolutePath)
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);
    } catch {
      trackedFiles = [];
    }
    const hasGoFiles = trackedFiles.some((f) => f.endsWith(".go"));
    const tsconfigs = trackedFiles.filter((f) => f.endsWith("tsconfig.json"));
    const repoFileCount = trackedFiles.length;

    // Optional JS/TS tools (safe to skip on error)
    let jscpdRaw = "";
    let depcheckRaw = "";
    let retireRaw = "";
    let madgeRaw = "";
    let semgrepRaw = "";
    let semgrepPyRaw = "";
    let semgrepGoRaw = "";
    let complexityJsRaw = "";
    let knipRaw = "";
    let tsPruneRaw = "";
    let licenseCheckerRaw = "";
    let depCruiserRaw = "";
    let typeCoverageRaw = "";
    let detectSecretsRaw = "";
    let vultureRaw = "";
    let safetyRaw = "";
    let gosecRaw = "";
    let gocycloRaw = "";
    // Historian summaries (computed locally; offline)
    let historianRevertsByAuthor: { author: string; count: number }[] = [];
    let historianChurnByFolder: { folder: string; count: number }[] = [];
    let historianStaleCriticalPaths: {
      path: string;
      lastTouchedAt: string | null;
    }[] = [];
    let historianBusFactor: {
      byAuthor: { author: string; email: string | null; commits: number }[];
      totalCommits: number;
      top1Share: number;
      top2Share: number;
      top3Share: number;
      scope: "since" | "lifetime";
      hercules?: {
        ownershipByAuthor: { author: string; score: number; share: number }[];
      };
    } | null = null;
    let gitShortlogRaw = "";
    let gitShortlogLifetimeRaw = "";
    // Historian (SQL via gitqlite)
    let historianSQLReverts: { author: string; count: number }[] = [];
    let gitqliteRevertsRaw = "";
    // Historian Phase 2 (Hercules burndown/ownership; optional)
    let herculesRaw = "";
    let coverageSummary: {
      files: string[];
      covered: number;
      total: number;
      percent: number;
    } | null = null;
    const toolErrors: Record<string, string | null> = {
      jscpd: null,
      depcheck: null,
      retire: null,
      madge: null,
      semgrep: null,
      semgrepPy: null,
      semgrepGo: null,
      complexityJs: null,
      knip: null,
      tsPrune: null,
      licenseChecker: null,
      dependencyCruiser: null,
      typeCoverage: null,
      detectSecrets: null,
      vulture: null,
      safety: null,
      gosec: null,
      gocyclo: null,
      historianReverts: null,
      historianChurn: null,
      historianStale: null,
      historianBusFactor: null,
      historianSQL: null,
      historianHercules: null,
      coverageParse: null,
    };
    const depcheckByPackage: Record<
      string,
      { raw: string; error: string | null }
    > = {};
    const retireByPackage: Record<
      string,
      { raw: string; error: string | null }
    > = {};

    const toolRegistry = createDefaultAnalyzeToolRegistry();
    const analysisContext: AnalysisContext = {
      absolutePath,
      trackedFiles,
      hasGoFiles,
      tsconfigs,
      repoFileCount,
      churnRaw,
      churnSince: churnSinceEffective,
    };

    // Optional per-tool heartbeat to stderr. The analyze pipeline runs its
    // language tools sequentially and otherwise emits nothing until the final
    // output path (~4 min of dead air on a real repo). Gate behind
    // BB_ANALYZE_PROGRESS=1 so default/CI behavior and stdout (the artifact
    // path consumed by downstream tooling) are byte-identical; only stderr
    // gains `▸ <tool>` markers when explicitly requested. Each line is stamped
    // with elapsed seconds so a live audience can see motion.
    const progressOn = process.env.BB_ANALYZE_PROGRESS === "1";
    // Wall-clock zero. Prefer BB_ANALYZE_T0 (host epoch seconds, stamped by
    // analyze_host.sh at the top of the run) so `▸ [+Ns]` counts from when the
    // operator pressed Enter — including docker spin-up + ts-node boot — and the
    // stamps match a stopwatch. Falls back to "now" (this point, ~22s in) when
    // the var is absent (e.g. a bare `node cli.ts analyze` outside the harness).
    const t0Env = Number(process.env.BB_ANALYZE_T0);
    const beatBaseMs =
      Number.isFinite(t0Env) && t0Env > 0 ? t0Env * 1000 : Date.now();
    const beat = (msg: string): void => {
      if (!progressOn) return;
      const secs = Math.round((Date.now() - beatBaseMs) / 1000);
      process.stderr.write(`▸ [+${secs}s] ${msg}\n`);
    };

    // BB_PARALLEL_ANALYZERS=1 runs python/javascript/go/historian in four
    // worker_threads. Each runXAnalysis is sync-spawnSync-bound (or async for
    // historian); separate OS threads let their subprocesses run concurrently.
    // Default OFF → large-tree audits stay byte-identical to today.
    const parallelOn = process.env.BB_PARALLEL_ANALYZERS === "1";
    // Resolve the ts-node ESM loader the worker must use to import the .ts
    // analyzers. Probe BB_TSNODE_LOADER override, then the in-image path
    // (analyze_host.sh's loader), then a repo-relative fallback for bare runs.
    const TS_NODE_LOADER =
      process.env.BB_TSNODE_LOADER && existsSync(process.env.BB_TSNODE_LOADER)
        ? process.env.BB_TSNODE_LOADER
        : existsSync("/usr/local/lib/node_modules/ts-node/esm.mjs")
          ? "/usr/local/lib/node_modules/ts-node/esm.mjs"
          : new URL("../../node_modules/ts-node/esm.mjs", import.meta.url)
              .pathname;
    function runInWorker<T>(tool: string, context: AnalysisContext): Promise<T> {
      return new Promise<T>((resolve, reject) => {
        const w = new Worker(
          new URL("../analyzers/analyzer-worker.ts", import.meta.url),
          {
            workerData: { tool, context },
            execArgv: ["--loader", TS_NODE_LOADER],
            env: process.env,
          },
        );
        let settled = false;
        w.on(
          "message",
          (m: {
            ok?: boolean;
            res?: T;
            error?: string;
            progress?: string;
          }) => {
            // Progress events are emitted from THIS (main) thread so they stay
            // ordered against the top-level heartbeat; a worker's own stderr
            // arrives out of order. Not a settling message — keep listening.
            if (m && typeof m.progress === "string") {
              beat(m.progress);
              return;
            }
            settled = true;
            if (m && m.ok) resolve(m.res as T);
            else reject(new Error(`[${tool}] ${m?.error || "worker failed"}`));
            void w.terminate();
          },
        );
        w.once("error", (e) => {
          if (!settled) {
            settled = true;
            reject(e);
          }
        });
        w.once("exit", (code) => {
          if (!settled && code !== 0)
            reject(new Error(`[${tool}] worker exited ${code}`));
        });
      });
    }

    if (parallelOn) {
      beat("python|javascript|go|historian — parallel worker_threads");
      // Emit a completion beat as EACH worker finishes (they settle at staggered
      // times — historian/go/js typically before python's semgrep). This keeps
      // the live terminal moving during the parallel sweep and shows all four
      // analyzers actually running, instead of one static line then a long gap.
      const trackTool = <T>(tool: string, p: Promise<T>): Promise<T> =>
        p.then(
          (r) => {
            beat(`done:${tool}`);
            return r;
          },
          (e) => {
            beat(`degraded:${tool}`);
            throw e;
          },
        );
      const [pyS, jsS, goS, histS] = await Promise.allSettled([
        trackTool(
          "python",
          runInWorker<PythonAnalysisResult>("python", analysisContext),
        ),
        trackTool(
          "javascript",
          runInWorker<JavaScriptAnalysisResult>("javascript", analysisContext),
        ),
        trackTool("go", runInWorker<GoAnalysisResult>("go", analysisContext)),
        trackTool(
          "historian",
          runInWorker<HistorianResult>("historian", analysisContext),
        ),
      ]);
      if (pyS.status === "fulfilled") {
        const pyResult = pyS.value;
        complexityRaw = pyResult.complexityRaw;
        securityRaw = pyResult.securityRaw;
        semgrepPyRaw = pyResult.semgrepPyRaw;
        vultureRaw = pyResult.vultureRaw;
        safetyRaw = pyResult.safetyRaw;
        toolErrors.semgrepPy = pyResult.errors.semgrepPy;
        toolErrors.vulture = pyResult.errors.vulture;
        toolErrors.safety = pyResult.errors.safety;
      } else {
        toolErrors.semgrepPy =
          pyS.reason instanceof Error
            ? pyS.reason.message
            : String(pyS.reason);
      }
      if (jsS.status === "fulfilled") {
        const jsResult = jsS.value;
        jscpdRaw = jsResult.jscpdRaw;
        depcheckRaw = jsResult.depcheckRaw;
        retireRaw = jsResult.retireRaw;
        madgeRaw = jsResult.madgeRaw;
        semgrepRaw = jsResult.semgrepRaw;
        complexityJsRaw = jsResult.complexityJsRaw;
        knipRaw = jsResult.knipRaw;
        tsPruneRaw = jsResult.tsPruneRaw;
        licenseCheckerRaw = jsResult.licenseCheckerRaw;
        depCruiserRaw = jsResult.depCruiserRaw;
        typeCoverageRaw = jsResult.typeCoverageRaw;
        Object.assign(depcheckByPackage, jsResult.depcheckByPackage);
        Object.assign(retireByPackage, jsResult.retireByPackage);
        toolErrors.jscpd = jsResult.errors.jscpd;
        toolErrors.depcheck = jsResult.errors.depcheck;
        toolErrors.retire = jsResult.errors.retire;
        toolErrors.madge = jsResult.errors.madge;
        toolErrors.semgrep = jsResult.errors.semgrep;
        toolErrors.complexityJs = jsResult.errors.complexityJs;
        toolErrors.knip = jsResult.errors.knip;
        toolErrors.tsPrune = jsResult.errors.tsPrune;
        toolErrors.licenseChecker = jsResult.errors.licenseChecker;
        toolErrors.dependencyCruiser = jsResult.errors.dependencyCruiser;
        toolErrors.typeCoverage = jsResult.errors.typeCoverage;
      } else {
        toolErrors.semgrep =
          jsS.reason instanceof Error
            ? jsS.reason.message
            : String(jsS.reason);
      }
      if (goS.status === "fulfilled") {
        const goResult = goS.value;
        semgrepGoRaw = goResult.semgrepGoRaw;
        gosecRaw = goResult.gosecRaw;
        gocycloRaw = goResult.gocycloRaw;
        toolErrors.semgrepGo = goResult.errors.semgrepGo;
        toolErrors.gosec = goResult.errors.gosec;
        toolErrors.gocyclo = goResult.errors.gocyclo;
      } else {
        toolErrors.semgrepGo =
          goS.reason instanceof Error
            ? goS.reason.message
            : String(goS.reason);
      }
      if (histS.status === "fulfilled") {
        const historianResult = histS.value;
        historianRevertsByAuthor = historianResult.revertsByAuthor;
        historianChurnByFolder = historianResult.churnByFolder;
        historianStaleCriticalPaths = historianResult.staleCriticalPaths;
        historianBusFactor = historianResult.busFactor;
        historianSQLReverts = historianResult.sqlReverts;
        gitShortlogRaw = historianResult.gitShortlogRaw;
        gitShortlogLifetimeRaw = historianResult.gitShortlogLifetimeRaw;
        gitqliteRevertsRaw = historianResult.gitqliteRevertsRaw;
        herculesRaw = historianResult.herculesRaw;
        toolErrors.historianReverts = historianResult.errors.historianReverts;
        toolErrors.historianChurn = historianResult.errors.historianChurn;
        toolErrors.historianStale = historianResult.errors.historianStale;
        toolErrors.historianBusFactor =
          historianResult.errors.historianBusFactor;
        toolErrors.historianSQL = historianResult.errors.historianSQL;
        toolErrors.historianHercules =
          historianResult.errors.historianHercules;
      } else {
        toolErrors.historianBusFactor =
          histS.reason instanceof Error
            ? histS.reason.message
            : String(histS.reason);
      }
      beat("analyzers done — assembling + writing artifact");
    } else {
      beat("python — bandit/complexity/semgrep/vulture/safety");
    const pythonTool = toolRegistry.list().find((t) => t.name === "python");
    if (!pythonTool) {
      throw new Error("Missing registered tool: python");
    }
    const pyResult = (await pythonTool.execute(
      analysisContext,
    )) as PythonAnalysisResult;
    complexityRaw = pyResult.complexityRaw;
    securityRaw = pyResult.securityRaw;
    semgrepPyRaw = pyResult.semgrepPyRaw;
    vultureRaw = pyResult.vultureRaw;
    safetyRaw = pyResult.safetyRaw;
    toolErrors.semgrepPy = pyResult.errors.semgrepPy;
    toolErrors.vulture = pyResult.errors.vulture;
    toolErrors.safety = pyResult.errors.safety;

    beat("javascript — jscpd/depcheck/retire/madge/semgrep/knip");
    const javascriptTool = toolRegistry
      .list()
      .find((t) => t.name === "javascript");
    if (!javascriptTool) {
      throw new Error("Missing registered tool: javascript");
    }
    const jsResult = (await javascriptTool.execute(
      analysisContext,
    )) as JavaScriptAnalysisResult;
    jscpdRaw = jsResult.jscpdRaw;
    depcheckRaw = jsResult.depcheckRaw;
    retireRaw = jsResult.retireRaw;
    madgeRaw = jsResult.madgeRaw;
    semgrepRaw = jsResult.semgrepRaw;
    complexityJsRaw = jsResult.complexityJsRaw;
    knipRaw = jsResult.knipRaw;
    tsPruneRaw = jsResult.tsPruneRaw;
    licenseCheckerRaw = jsResult.licenseCheckerRaw;
    depCruiserRaw = jsResult.depCruiserRaw;
    typeCoverageRaw = jsResult.typeCoverageRaw;
    Object.assign(depcheckByPackage, jsResult.depcheckByPackage);
    Object.assign(retireByPackage, jsResult.retireByPackage);
    toolErrors.jscpd = jsResult.errors.jscpd;
    toolErrors.depcheck = jsResult.errors.depcheck;
    toolErrors.retire = jsResult.errors.retire;
    toolErrors.madge = jsResult.errors.madge;
    toolErrors.semgrep = jsResult.errors.semgrep;
    toolErrors.complexityJs = jsResult.errors.complexityJs;
    toolErrors.knip = jsResult.errors.knip;
    toolErrors.tsPrune = jsResult.errors.tsPrune;
    toolErrors.licenseChecker = jsResult.errors.licenseChecker;
    toolErrors.dependencyCruiser = jsResult.errors.dependencyCruiser;
    toolErrors.typeCoverage = jsResult.errors.typeCoverage;

    beat("go — semgrep/gosec/gocyclo");
    const goTool = toolRegistry.list().find((t) => t.name === "go");
    if (!goTool) {
      throw new Error("Missing registered tool: go");
    }
    const goResult = (await goTool.execute(
      analysisContext,
    )) as GoAnalysisResult;
    semgrepGoRaw = goResult.semgrepGoRaw;
    gosecRaw = goResult.gosecRaw;
    gocycloRaw = goResult.gocycloRaw;
    toolErrors.semgrepGo = goResult.errors.semgrepGo;
    toolErrors.gosec = goResult.errors.gosec;
    toolErrors.gocyclo = goResult.errors.gocyclo;
    } // end sequential analyzers (else branch of parallelOn)

    // Secrets scanning (repo-wide).
    // NOTE: `--json` is NOT a valid flag for `detect-secrets scan` (it is only
    // accepted by the `audit` subcommand / pre-commit hook). Passing it makes
    // argparse error to stderr and exit non-zero, producing empty stdout. The
    // former `|| true` then masked that failure, so the scanner silently
    // contributed nothing across every audit. `scan --all-files` already emits
    // JSON (`{version, plugins_used, results, ...}`) to stdout on success and
    // exits 0 even when zero secrets are found. Dropping `|| true` lets a real
    // failure (missing binary, bad flag) surface via the catch below into
    // toolErrors.detectSecrets instead of being swallowed.
    try {
      detectSecretsRaw = run(
        "bash",
        ["-lc", "detect-secrets scan --all-files"],
        absolutePath,
      );
    } catch (e) {
      toolErrors.detectSecrets = e instanceof Error ? e.message : String(e);
    }

    // Go security scan (best-effort)
    try {
      gosecRaw = run(
        "bash",
        [
          "-lc",
          "if command -v gosec >/dev/null 2>&1; then gosec -fmt=json -quiet ./... || true; else true; fi",
        ],
        absolutePath,
      );
    } catch (e) {
      toolErrors.gosec = e instanceof Error ? e.message : String(e);
    }

    // Go cyclomatic complexity (best-effort)
    try {
      if (hasGoFiles) {
        // Tolerate non-zero exit codes and still capture stdout, if any
        gocycloRaw = run(
          "bash",
          ["-lc", "gocyclo -over 10 . || true"],
          absolutePath,
        );
      }
    } catch (e) {
      toolErrors.gocyclo = e instanceof Error ? e.message : String(e);
    }

    // Normalize retire empty output to explicit JSON for stable downstream parsing
    if (!retireRaw || retireRaw.trim() === "") {
      retireRaw = "{}";
    }

    // Coverage: parse lcov.info if present (best-effort)
    try {
      const lcovList = run(
        "bash",
        [
          "-lc",
          "find . -type f -name lcov.info -not -path '*/node_modules/*' | head -n 50",
        ],
        absolutePath,
      )
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);
      if (lcovList.length > 0) {
        let total = 0;
        let covered = 0;
        for (const rel of lcovList) {
          try {
            const p = path.resolve(absolutePath, rel);
            const content = await fs.readFile(p, "utf8");
            for (const line of content.split("\n")) {
              if (line.startsWith("DA:")) {
                const parts = line.substring(3).split(",");
                if (parts.length === 2) {
                  const hits = parseInt(parts[1] ?? "0", 10);
                  if (!Number.isNaN(hits)) {
                    total += 1;
                    if (hits > 0) covered += 1;
                  }
                }
              }
            }
          } catch {
            // ignore file read errors
          }
        }
        if (total > 0) {
          coverageSummary = {
            files: lcovList,
            covered,
            total,
            percent: Math.round((covered / total) * 10000) / 100,
          };
        }
      }
      // If no lcov, attempt to parse Python coverage.xml (Cobertura-style)
      if (!coverageSummary) {
        const covXmlList = run(
          "bash",
          [
            "-lc",
            "find . -type f -name coverage.xml -not -path '*/node_modules/*' -not -path '*/.venv/*' | head -n 50",
          ],
          absolutePath,
        )
          .split("\n")
          .map((s) => s.trim())
          .filter(Boolean);
        if (covXmlList.length > 0) {
          // Aggregate by summing lines-covered/lines-valid if available; otherwise use line-rate
          let total = 0;
          let covered = 0;
          for (const rel of covXmlList) {
            try {
              const p = path.resolve(absolutePath, rel);
              const xml = await fs.readFile(p, "utf8");
              const mLines = xml.match(
                /lines-valid="(\d+)"[\s\S]*?lines-covered="(\d+)"/,
              );
              if (mLines) {
                const tv = parseInt(mLines[1] ?? "0", 10);
                const cv = parseInt(mLines[2] ?? "0", 10);
                if (!Number.isNaN(tv) && !Number.isNaN(cv)) {
                  total += tv;
                  covered += cv;
                }
              } else {
                const mRate = xml.match(/line-rate="([0-9]*\.?[0-9]+)"/);
                if (mRate) {
                  const rate = parseFloat(mRate[1] ?? "0");
                  if (!Number.isNaN(rate)) {
                    // Use a pseudo-total of 100 for rate-only files
                    total += 100;
                    covered += Math.round(rate * 100);
                  }
                }
              }
            } catch {
              // ignore xml read/parse errors
            }
          }
          if (total > 0) {
            coverageSummary = {
              files: covXmlList,
              covered,
              total,
              percent: Math.round((covered / total) * 10000) / 100,
            };
          }
        }
      }
      // If still no coverage, attempt Go coverage via go tool cover -func (best-effort)
      if (!coverageSummary) {
        try {
          const covGoList = run(
            "bash",
            [
              "-lc",
              "find . -type f -name 'coverage.out' -not -path '*/node_modules/*' -not -path '*/.venv/*' | head -n 50",
            ],
            absolutePath,
          )
            .split("\n")
            .map((s) => s.trim())
            .filter(Boolean);
          if (covGoList.length > 0) {
            let total = 0;
            let covered = 0;
            for (const rel of covGoList) {
              try {
                const raw = run(
                  "go",
                  ["tool", "cover", "-func", rel],
                  absolutePath,
                );
                const lines = raw
                  .split("\n")
                  .map((s) => s.trim())
                  .filter(Boolean);
                const last = lines[lines.length - 1] || "";
                const m = last.match(/\s([0-9]+(?:\.[0-9]+)?)%\s*$/);
                const percentStr = m ? m[1] : "";
                const pct = parseFloat(percentStr);
                if (!Number.isNaN(pct)) {
                  total += 100;
                  covered += Math.round(pct);
                }
              } catch {
                // ignore per-file errors
              }
            }
            if (total > 0) {
              coverageSummary = {
                files: covGoList,
                covered,
                total,
                percent: Math.round((covered / total) * 10000) / 100,
              };
            }
          }
        } catch {
          // ignore go coverage enumeration errors
        }
      }
    } catch (e) {
      toolErrors.coverageParse = e instanceof Error ? e.message : String(e);
    }

    // Historian Phase 1 (offline): Reverts by author, churn by folder, stale critical paths
    // Historian Phase 2 (heuristic bus factor): shortlog within window
    // Historian Phase 1B (gitqlite): curated SQL queries with tight bounds
    // Historian Phase 2 (optional): Hercules burndown, guarded with timeout and presence checks
    if (!parallelOn) {
    beat("historian — reverts/churn/bus-factor/gitqlite/hercules (long pole)");
    try {
      const historianTool = toolRegistry
        .list()
        .find((t) => t.name === "historian");
      if (!historianTool) {
        throw new Error("Missing registered tool: historian");
      }
      const historianResult = (await historianTool.execute(
        analysisContext,
      )) as HistorianResult;
      historianRevertsByAuthor = historianResult.revertsByAuthor;
      historianChurnByFolder = historianResult.churnByFolder;
      historianStaleCriticalPaths = historianResult.staleCriticalPaths;
      historianBusFactor = historianResult.busFactor;
      historianSQLReverts = historianResult.sqlReverts;
      gitShortlogRaw = historianResult.gitShortlogRaw;
      gitShortlogLifetimeRaw = historianResult.gitShortlogLifetimeRaw;
      gitqliteRevertsRaw = historianResult.gitqliteRevertsRaw;
      herculesRaw = historianResult.herculesRaw;
      toolErrors.historianReverts = historianResult.errors.historianReverts;
      toolErrors.historianChurn = historianResult.errors.historianChurn;
      toolErrors.historianStale = historianResult.errors.historianStale;
      toolErrors.historianBusFactor = historianResult.errors.historianBusFactor;
      toolErrors.historianSQL = historianResult.errors.historianSQL;
      toolErrors.historianHercules = historianResult.errors.historianHercules;
    } catch (e) {
      toolErrors.historianBusFactor =
        e instanceof Error ? e.message : String(e);
    }
    beat("analyzers done — assembling + writing artifact");
    } // end historian (else branch of parallelOn)

    // An out-of-scope emit block was removed here. It captured per-commit /
    // file-count inputs for a downstream layer that is NOT part of this
    // standalone breadth tool. The removed fields are NOT in the §7.2 kill-zone
    // contract, so the interrogate `summary` is unaffected (independently verified).

    const analysis = {
      path: absolutePath,
      complexity: {
        highComplexityFileCount: parseRadonHighComplexityCount(complexityRaw) + parseEslintHighComplexityCount(complexityJsRaw),
      },
      security: {
        highFindingCount: parseBanditHighCount(securityRaw),
      },
      js: {
        duplication: {
          raw: jscpdRaw,
        },
        deps: {
          raw: depcheckRaw,
          byPackage: depcheckByPackage,
        },
        security: {
          raw: retireRaw,
          retireByPackage: retireByPackage,
        },
        modules: {
          raw: madgeRaw,
        },
        semgrep: {
          raw: semgrepRaw,
        },
        complexity: {
          raw: complexityJsRaw,
        },
        knip: {
          raw: knipRaw,
        },
        tsPrune: {
          raw: tsPruneRaw,
        },
        licenses: {
          raw: licenseCheckerRaw,
        },
        dependencyCruiser: {
          raw: depCruiserRaw,
        },
        typeCoverage: {
          raw: typeCoverageRaw,
        },
      },
      py: {
        semgrep: {
          raw: semgrepPyRaw,
        },
        vulture: {
          raw: vultureRaw,
        },
        safety: {
          raw: safetyRaw,
        },
        complexity: {
          raw: complexityRaw,
        },
        security: {
          raw: securityRaw,
        },
      },
      go: {
        semgrep: {
          raw: semgrepGoRaw,
        },
        security: {
          raw: gosecRaw,
        },
        complexity: {
          raw: gocycloRaw,
        },
      },
      coverage: coverageSummary,
      secrets: {
        detectSecrets: {
          raw: detectSecretsRaw,
        },
      },
      hotspots: {
        highChurnFiles: churnHotspotsWithBugFix,
        churn: {
          sinceRequested: churnSinceRequested,
          sinceEffective: churnSinceEffective,
          selectionMode: churnSelectionMode,
          minCount: churnMinCount,
          maxCandidates: churnMaxCandidates,
          commitCount: churnCommitCount,
          fileTouchLines: churnSummary.fileTouchLines,
          uniqueFiles: churnSummary.uniqueFiles,
          maxCount: churnSummary.maxCount,
        },
      },
      historian: {
        revertsByAuthor: historianRevertsByAuthor,
        churnByFolder: historianChurnByFolder,
        staleCriticalPaths: historianStaleCriticalPaths,
        busFactor: historianBusFactor,
        sql: {
          revertsByAuthor: historianSQLReverts,
        },
      },
      churn: {
        since: churnSinceEffective,
        sinceRequested: churnSinceRequested,
      },
      // MOAT-STRIP: an out-of-scope emit block was removed here (see the matching
      // strip above). Not in the §7.2 kill-zone contract.
      raw: {
        radon: complexityRaw,
        bandit: securityRaw,
        gitChurn: churnRaw,
        jscpd: jscpdRaw,
        depcheck: depcheckRaw,
        retire: retireRaw,
        madge: madgeRaw,
        semgrep: semgrepRaw,
        semgrepPy: semgrepPyRaw,
        semgrepGo: semgrepGoRaw,
        complexityJs: complexityJsRaw,
        knip: knipRaw,
        tsPrune: tsPruneRaw,
        licenseChecker: licenseCheckerRaw,
        dependencyCruiser: depCruiserRaw,
        typeCoverage: typeCoverageRaw,
        detectSecrets: detectSecretsRaw,
        vulture: vultureRaw,
        safety: safetyRaw,
        gosec: gosecRaw,
        gocyclo: gocycloRaw,
        gitShortlog: gitShortlogRaw,
        gitShortlogLifetime: gitShortlogLifetimeRaw,
        gitqliteReverts: gitqliteRevertsRaw,
        hercules: herculesRaw,
      },
      errors: toolErrors,
    };

    // Compact JSON (no 2-space pretty-print). The artifact embeds every analyzer's
    // raw output (multi-MB), and pretty-printing + writing it is a slow post-sweep
    // step on a weak CPU. The artifact is machine-consumed (jq in c2/c3, downstream
    // commands) so formatting is irrelevant. Set BB_ANALYZE_PRETTY=1 to restore the
    // 2-space form for human diffing. Compact saves real wall-time on slow hosts.
    const output =
      process.env.BB_ANALYZE_PRETTY === "1"
        ? JSON.stringify(analysis, null, 2)
        : JSON.stringify(analysis);

    if (options.out) {
      const outPath = path.resolve(process.cwd(), options.out);
      await fs.mkdir(path.dirname(outPath), { recursive: true });
      await fs.writeFile(outPath, output + "\n", "utf8");
      process.stdout.write(`${outPath}\n`);

      // BB_ANALYZE_FAST_EXIT=1: the artifact is written + its path printed, so the
      // one-shot analyze is functionally done. On a slow host node otherwise hangs
      // ~10s here waiting for the analyzer worker threads (and their spawned child
      // processes) to drain before the event loop empties. Force-exit to reclaim
      // that time. Safe for a one-shot run: the only thing after this is pushGate,
      // which is an env-gated no-op unless an internal DB env var (unused in the
      // standalone engine) is set.
      // Default off = unchanged behavior (Mac/CI / programmatic callers).
      if (process.env.BB_ANALYZE_FAST_EXIT === "1") {
        await new Promise((r) => setTimeout(r, 50)); // let stdout flush first
        process.exit(0);
      }

      // Push gate state after artifact write. Target id derived from
      // analysis-file basename (e.g. `output/analysis/myorg-repo.json` →
      // `myorg-repo`). Env-gated no-op when the internal DB env var (unused in
      // the standalone engine) is unset; log-and-swallow on failure.
      const targetId = path.basename(outPath, ".json").replace(/\.local\.analysis\..*$/, "");
      await pushGate(targetId, "ANALYZE", {
        gate: "ANALYZE",
        status: "OPEN",
        updatedAt: new Date().toISOString(),
        details: `Analysis written: ${outPath}`,
        evidencePaths: [outPath],
      });
      return;
    }

    process.stdout.write(output + "\n");
  });

type InterrogateOptions = {
  out?: string;
  complexityThreshold?: string;
  churnThreshold?: string;
  maxCandidates?: string;
  semgrepMinSeverity?: string;
  includeNonSecuritySemgrep?: boolean;
  includeNonProd?: boolean;
  failOnActionRequired?: boolean;
};

export const interrogateCommand = new Command("interrogate")
  .description(
    "Phase 3.5 signal interrogation: summarize churn metadata and compute lethality shortlist from an analysis artifact",
  )
  .argument("<analysis-json>", "Path to analysis JSON (e.g., output/analysis/<targetId>.local.analysis.extended.<TS>.json)")
  .option("--out <path>", "Write the interrogation summary JSON to a file (optional)")
  .option("--complexity-threshold <n>", "Complexity threshold for Density (default 15)")
  .option("--churn-threshold <n>", "Churn count threshold for Fragility (default 15)")
  .option("--max-candidates <n>", "Max candidates to output per vector (default 25)")
  .option(
    "--semgrep-min-severity <level>",
    "Minimum Semgrep severity to count as Vulnerability (default ERROR)",
    "ERROR",
  )
  .option(
    "--include-non-security-semgrep",
    "Include non-security Semgrep rules in the Vulnerability vector (default false)",
    false,
  )
  .option(
    "--include-non-prod",
    "Include non-production paths (tests/examples/docs) in production-filtered intersections (default false)",
    false,
  )
  .option(
    "--fail-on-action-required",
    "Exit non-zero when Phase 3.5 status indicates manual work remains (default false)",
    false,
  )
  .action(async (analysisJsonPathRaw: string, options: InterrogateOptions) => {
    const analysisPath = path.resolve(process.cwd(), analysisJsonPathRaw);

    const readInt = (raw: string | undefined, fallback: number): number => {
      if (typeof raw !== "string") return fallback;
      const n = Number.parseInt(raw, 10);
      return Number.isFinite(n) ? n : fallback;
    };

    const maxCandidates = readInt(options.maxCandidates, 25);
    const complexityThreshold = readInt(options.complexityThreshold, 15);
    const churnThreshold = readInt(options.churnThreshold, 15);

    const asRecord = (v: unknown): Record<string, unknown> | null => {
      if (!v || typeof v !== "object" || Array.isArray(v)) return null;
      return v as Record<string, unknown>;
    };

    const readString = (v: unknown): string | null =>
      typeof v === "string" ? v : null;

    const readFiniteNumber = (v: unknown): number | null =>
      typeof v === "number" && Number.isFinite(v) ? v : null;

    const normalizePath = (p: string, prefix: string | null): string => {
      const s = p.trim();
      if (!s) return s;
      const ws = "/workspace/";
      const idx = s.indexOf(ws);
      if (idx >= 0) {
        const sub = s.slice(idx + ws.length);
        const parts = sub.split("/");
        if (parts.length >= 2) return parts.slice(1).join("/");
      }
      if (prefix && s.startsWith(prefix)) {
        const out = s.slice(prefix.length);
        return out.startsWith("/") ? out.slice(1) : out;
      }
      return s;
    };

    const extractJsonSubstring = (raw: string): string => {
      const trimmed = raw.trim();
      const idxObj = trimmed.indexOf("{");
      const idxArr = trimmed.indexOf("[");
      const idx =
        idxObj === -1
          ? idxArr
          : idxArr === -1
            ? idxObj
            : Math.min(idxObj, idxArr);
      return idx > 0 ? trimmed.slice(idx) : trimmed;
    };

    const parseEmbeddedJson = (raw: string): unknown | null => {
      const candidate = extractJsonSubstring(raw);
      try {
        return JSON.parse(candidate) as unknown;
      } catch {
        return null;
      }
    };

    const parseRadonComplexity = (raw: string, basePrefix: string | null) => {
      const parsed = parseEmbeddedJson(raw);
      const r = parsed ? asRecord(parsed) : null;
      if (!r) return [] as Array<{ file: string; score: number }>;

      const out: Array<{ file: string; score: number }> = [];
      for (const [fileRaw, entries] of Object.entries(r)) {
        if (!Array.isArray(entries)) continue;
        let max = 0;
        for (const item of entries) {
          const rec = asRecord(item);
          const v = rec ? readFiniteNumber(rec.complexity) : null;
          if (typeof v === "number" && v > max) max = v;
        }
        if (max > 0) {
          out.push({ file: normalizePath(fileRaw, basePrefix), score: max });
        }
      }
      return out;
    };

    const parseGoCyclo = (raw: string, basePrefix: string | null) => {
      const maxByFile = new Map<string, number>();
      for (const lineRaw of raw.split("\n")) {
        const line = lineRaw.trim();
        if (!line) continue;
        const m = line.match(/^\s*(\d+)\s+([^\s]+)\s+/);
        if (!m) continue;
        const score = Number.parseInt(m[1] ?? "0", 10);
        const file = normalizePath(m[2] ?? "", basePrefix);
        if (!file) continue;
        const prev = maxByFile.get(file) ?? 0;
        if (score > prev) maxByFile.set(file, score);
      }
      return Array.from(maxByFile.entries()).map(([file, score]) => ({ file, score }));
    };

    const parseEslintComplexity = (raw: string, basePrefix: string | null) => {
      const parsed = parseEmbeddedJson(raw);
      if (!Array.isArray(parsed)) return [] as Array<{ file: string; score: number }>;
      const maxByFile = new Map<string, number>();
      for (const entry of parsed) {
        const rec = asRecord(entry);
        if (!rec) continue;
        const filePath = typeof rec.filePath === "string" ? rec.filePath : "";
        const messages = Array.isArray(rec.messages) ? rec.messages : [];
        for (const msg of messages) {
          const m = asRecord(msg);
          if (!m) continue;
          if (m.ruleId !== "complexity") continue;
          const text = typeof m.message === "string" ? m.message : "";
          const match = text.match(/complexity of (\d+)/);
          if (!match) continue;
          const score = Number.parseInt(match[1] ?? "0", 10);
          const prev = maxByFile.get(filePath) ?? 0;
          if (score > prev) maxByFile.set(filePath, score);
        }
      }
      const out: Array<{ file: string; score: number }> = [];
      for (const [fileRaw, score] of maxByFile) {
        const file = normalizePath(fileRaw, basePrefix);
        if (file && score > 0) out.push({ file, score });
      }
      return out;
    };

    const parseSemgrepFiles = (raw: string, basePrefix: string | null) => {
      const parsed = parseEmbeddedJson(raw);
      const r = parsed ? asRecord(parsed) : null;
      const results = r ? (r.results as unknown) : null;
      const out = new Set<string>();
      const counts: Record<string, number> = {};
      const selectedCounts: Record<string, number> = {};

      if (!Array.isArray(results)) {
        return { files: out, severityCounts: counts, selectedSeverityCounts: selectedCounts };
      }

      const severityRank = (s: string): number => {
        const sev = s.toUpperCase();
        if (sev === "ERROR") return 2;
        if (sev === "WARNING") return 1;
        if (sev === "INFO") return 0;
        return -1;
      };

      const minSeverityRaw = (options.semgrepMinSeverity || "WARNING").toUpperCase();
      const minSeverity = severityRank(minSeverityRaw);
      const includeNonSecurity = Boolean(options.includeNonSecuritySemgrep);
      const warnedUnknownSeverities = new Set<string>();

      const isSecuritySemgrep = (
        checkId: string | null,
        extra: Record<string, unknown> | null,
      ): boolean => {
        if (checkId && checkId.includes(".security.")) return true;
        const meta = extra ? asRecord(extra["metadata"]) : null;
        if (!meta) return false;
        if (meta["cwe"] || meta["owasp"]) return true;
        const category = readString(meta["category"]);
        if (category && category.toLowerCase().includes("security")) return true;
        return false;
      };

      for (const item of results) {
        const rec = asRecord(item);
        if (!rec) continue;

        const pathRaw = readString(rec["path"]);
        const checkId = readString(rec["check_id"]);
        const extra = asRecord(rec["extra"]);
        const severityRaw = extra ? readString(extra["severity"]) : null;
        const severity = (severityRaw || "UNKNOWN").toUpperCase();
        counts[severity] = (counts[severity] ?? 0) + 1;

        const sec = isSecuritySemgrep(checkId, extra);
        if (!sec && !includeNonSecurity) continue;
        const rank = severityRank(severity);
        if (rank < 0) {
          if (!warnedUnknownSeverities.has(severity)) {
            warnedUnknownSeverities.add(severity);
            process.stderr.write(
              `analyze: unknown semgrep severity "${severity}" silently filtered (S2A-Hardening-severity-warn). Known: ERROR/WARNING/INFO.\n`,
            );
          }
          continue;
        }
        if (rank < minSeverity) continue;

        selectedCounts[severity] = (selectedCounts[severity] ?? 0) + 1;
        if (pathRaw) out.add(normalizePath(pathRaw, basePrefix));
      }

      return { files: out, severityCounts: counts, selectedSeverityCounts: selectedCounts };
    };

    const parseBanditFiles = (raw: string, basePrefix: string | null) => {
      const parsed = parseEmbeddedJson(raw);
      const r = parsed ? asRecord(parsed) : null;
      const results = r ? (r.results as unknown) : null;
      const out = new Set<string>();
      const counts: Record<string, number> = {};
      const selectedCounts: Record<string, number> = {};
      const criticalEscalations: Array<{
        file: string;
        line: number;
        testId: string;
        severity: string;
        confidence: string;
        text: string;
        cwe: { id: number; link: string } | null;
      }> = [];

      if (!Array.isArray(results)) {
        return { files: out, severityCounts: counts, selectedSeverityCounts: selectedCounts, criticalEscalations };
      }

      for (const item of results) {
        const rec = asRecord(item);
        if (!rec) continue;

        const filenameRaw = readString(rec["filename"]);
        const severityRaw = readString(rec["issue_severity"]);
        const confidenceRaw = readString(rec["issue_confidence"]);
        const severity = (severityRaw || "UNKNOWN").toUpperCase();
        const confidence = (confidenceRaw || "UNKNOWN").toUpperCase();
        counts[severity] = (counts[severity] ?? 0) + 1;

        if (severity === "MEDIUM" || severity === "HIGH") {
          selectedCounts[severity] = (selectedCounts[severity] ?? 0) + 1;
          if (filenameRaw) out.add(normalizePath(filenameRaw, basePrefix));
        }

        if (severity === "HIGH" && confidence === "HIGH" && filenameRaw) {
          const cweRaw = asRecord(rec["issue_cwe"]);
          criticalEscalations.push({
            file: normalizePath(filenameRaw, basePrefix),
            line: typeof rec["line_number"] === "number" ? (rec["line_number"] as number) : 0,
            testId: readString(rec["test_id"]) || "unknown",
            severity,
            confidence,
            text: readString(rec["issue_text"]) || "",
            cwe: cweRaw
              ? { id: typeof cweRaw["id"] === "number" ? (cweRaw["id"] as number) : 0, link: readString(cweRaw["link"]) || "" }
              : null,
          });
        }
      }

      return { files: out, severityCounts: counts, selectedSeverityCounts: selectedCounts, criticalEscalations };
    };

    let rawAnalysis: string;
    try {
      rawAnalysis = await fs.readFile(analysisPath, "utf8");
    } catch {
      process.stderr.write(`File not found: ${analysisPath}\n`);
      process.exitCode = 1;
      return;
    }

    let analysisUnknown: unknown;
    try {
      analysisUnknown = JSON.parse(rawAnalysis) as unknown;
    } catch {
      process.stderr.write(`Invalid JSON: ${analysisPath}\n`);
      process.exitCode = 1;
      return;
    }

    const analysis = asRecord(analysisUnknown);
    if (!analysis) {
      process.stderr.write(`Invalid analysis object: ${analysisPath}\n`);
      process.exitCode = 1;
      return;
    }

    const basePathRaw = readString(analysis.path);
    const basePrefix = basePathRaw ? basePathRaw.replace(/\/+$/, "") : null;

    const hotspots = asRecord(analysis.hotspots);
    const highChurnFiles = Array.isArray(hotspots?.highChurnFiles)
      ? (hotspots?.highChurnFiles as unknown[])
      : [];

    const fragility = new Set<string>();
    for (const item of highChurnFiles) {
      const rec = asRecord(item);
      const fileRaw = rec ? readString(rec.file) : null;
      const count = rec ? readFiniteNumber(rec.count) : null;
      if (!fileRaw || typeof count !== "number") continue;
      if (count >= churnThreshold) fragility.add(normalizePath(fileRaw, basePrefix));
    }

    const churnMeta = hotspots ? asRecord(hotspots.churn) : null;

    const rawTools = asRecord(analysis.raw);
    const py = asRecord(analysis.py);
    const pyComplexity = py ? asRecord(py.complexity) : null;
    const pyComplexityRaw = pyComplexity ? readString(pyComplexity.raw) : null;
    const go = asRecord(analysis.go);
    const goComplexity = go ? asRecord(go.complexity) : null;
    const goComplexityRaw = goComplexity ? readString(goComplexity.raw) : null;

    const js = asRecord(analysis.js);

    const radonRaw = pyComplexityRaw || (rawTools ? readString(rawTools.radon) : null) || "";
    const radonScores = radonRaw ? parseRadonComplexity(radonRaw, basePrefix) : [];
    const gocycloScores = goComplexityRaw ? parseGoCyclo(goComplexityRaw, basePrefix) : [];

    const jsComplexity = js ? asRecord(js.complexity) : null;
    const jsComplexityRaw = jsComplexity ? readString(jsComplexity.raw) : null;
    const eslintScores = jsComplexityRaw ? parseEslintComplexity(jsComplexityRaw, basePrefix) : [];

    const densityScores = [...radonScores, ...gocycloScores, ...eslintScores];
    densityScores.sort((a, b) => b.score - a.score);
    const density = new Set<string>();
    for (const item of densityScores) {
      if (density.size >= maxCandidates) break;
      if (item.score >= complexityThreshold) density.add(item.file);
    }
    const jsSemgrep = js ? asRecord(js.semgrep) : null;
    const jsSemgrepRaw = jsSemgrep ? readString(jsSemgrep.raw) : null;
    const pySemgrep = py ? asRecord(py.semgrep) : null;
    const pySemgrepRaw = pySemgrep ? readString(pySemgrep.raw) : null;
    const pySecurity = py ? asRecord(py.security) : null;
    const pySecurityRaw = pySecurity ? readString(pySecurity.raw) : null;
    const goSemgrep = go ? asRecord(go.semgrep) : null;
    const goSemgrepRaw = goSemgrep ? readString(goSemgrep.raw) : null;

    const vulnFiles = new Set<string>();
    const severityCounts: Record<string, number> = {};
    const semgrepSources = [jsSemgrepRaw, pySemgrepRaw, goSemgrepRaw];
    const semgrepSeverityCounts: Record<string, number> = {};
    const semgrepSelectedSeverityCounts: Record<string, number> = {};
    for (const raw of semgrepSources) {
      if (!raw) continue;
      const parsed = parseSemgrepFiles(raw, basePrefix);
      for (const f of parsed.files) vulnFiles.add(f);
      for (const [k, v] of Object.entries(parsed.severityCounts)) {
        semgrepSeverityCounts[k] = (semgrepSeverityCounts[k] ?? 0) + v;
      }
      for (const [k, v] of Object.entries(parsed.selectedSeverityCounts)) {
        semgrepSelectedSeverityCounts[k] = (semgrepSelectedSeverityCounts[k] ?? 0) + v;
      }
    }

    const banditSeverityCounts: Record<string, number> = {};
    const banditSelectedSeverityCounts: Record<string, number> = {};
    let banditCriticalEscalations: ReturnType<typeof parseBanditFiles>["criticalEscalations"] = [];
    if (pySecurityRaw) {
      const parsed = parseBanditFiles(pySecurityRaw, basePrefix);
      for (const f of parsed.files) vulnFiles.add(f);
      for (const [k, v] of Object.entries(parsed.severityCounts)) {
        banditSeverityCounts[k] = (banditSeverityCounts[k] ?? 0) + v;
      }
      for (const [k, v] of Object.entries(parsed.selectedSeverityCounts)) {
        banditSelectedSeverityCounts[k] = (banditSelectedSeverityCounts[k] ?? 0) + v;
      }
      banditCriticalEscalations = parsed.criticalEscalations;
    }

    for (const [k, v] of Object.entries(semgrepSeverityCounts)) {
      severityCounts[k] = (severityCounts[k] ?? 0) + v;
    }
    for (const [k, v] of Object.entries(banditSeverityCounts)) {
      severityCounts[k] = (severityCounts[k] ?? 0) + v;
    }

    const severityCountsSelected: Record<string, number> = {};
    for (const [k, v] of Object.entries(semgrepSelectedSeverityCounts)) {
      severityCountsSelected[k] = (severityCountsSelected[k] ?? 0) + v;
    }
    for (const [k, v] of Object.entries(banditSelectedSeverityCounts)) {
      severityCountsSelected[k] = (severityCountsSelected[k] ?? 0) + v;
    }

    const isNonProdPath = (file: string): boolean => {
      if (options.includeNonProd) return false;
      return (
        /(^|\/)tests?(\/|$)/.test(file) ||
        /(^|\/)examples(\/|$)/.test(file) ||
        /(^|\/)benchmarks(\/|$)/.test(file) ||
        /(^|\/)docs(\/|$)/.test(file) ||
        /(^|\/)standard-tests(\/|$)/.test(file)
      );
    };

    const p0: string[] = [];
    for (const f of fragility) {
      if (density.has(f) && vulnFiles.has(f)) p0.push(f);
    }
    p0.sort();

    const p0Prod = p0.filter((f) => !isNonProdPath(f));

    const fd: string[] = [];
    for (const f of fragility) {
      if (density.has(f)) fd.push(f);
    }
    fd.sort();

    const fdProd = fd.filter((f) => !isNonProdPath(f));

    const criticalEscalationsProd = banditCriticalEscalations.filter(
      (e) => !isNonProdPath(e.file),
    );

    let status: InterrogationStatus = "COMPLETE_NO_P0";
    const nextActions: string[] = [];

    if (criticalEscalationsProd.length > 0) {
      status = "SECURITY_ESCALATION";
      nextActions.push(
        `STANDALONE SECURITY BYPASS: ${criticalEscalationsProd.length} HIGH-severity/HIGH-confidence finding(s) detected. These bypass the triple-intersection requirement and must be traced immediately.`,
      );
      for (const e of criticalEscalationsProd) {
        nextActions.push(
          `  → ${e.file}:${e.line} [${e.testId}] ${e.cwe ? `CWE-${e.cwe.id}` : ""}: ${e.text}`,
        );
      }
    }

    if (p0Prod.length > 0) {
      if (status !== "SECURITY_ESCALATION") status = "P0_ACTION_REQUIRED";
      nextActions.push(
        "For each file in intersections.p0Prod: extract sink (file+line+rule+severity) from tool raw output and perform source→sink→sanitizer semantic trace.",
      );
      nextActions.push(
        "Apply reachability gate: downgrade non-prod paths and dead code per vulture/knip.",
      );
    }

    if (fdProd.length > 0) {
      if (status === "COMPLETE_NO_P0") status = "FD_ACTION_REQUIRED";
      nextActions.push(
        `Complexity×Churn kill zone: ${fdProd.length} file(s) are both high-complexity and high-churn. Record intersections.fragilityDensityProd and perform manual trace selectively.`,
      );
    }

    const analysisBasename = path.basename(analysisPath);

    const metricCitations = {
      _note: "Each citation maps a metric to its JSON path in the analysis artifact. Use these as evidence pointers.",
      highComplexityFileCount: {
        value: densityScores.filter((d) => d.score >= complexityThreshold).length,
        jsonPath: [
          pyComplexityRaw ? `${analysisBasename} → .py.complexity.raw (radon JSON)` : null,
          goComplexityRaw ? `${analysisBasename} → .go.complexity.raw (gocyclo text)` : null,
          jsComplexityRaw ? `${analysisBasename} → .js.complexity.raw (eslint JSON)` : null,
        ].filter(Boolean),
        derivation: `Files with max cyclomatic complexity >= ${complexityThreshold}`,
      },
      highChurnFileCount: {
        value: fragility.size,
        jsonPath: `${analysisBasename} → .hotspots.highChurnFiles[] (count >= ${churnThreshold})`,
      },
      banditTotalFindings: {
        value: Object.values(banditSeverityCounts).reduce((a, b) => a + b, 0),
        jsonPath: `${analysisBasename} → .py.security.raw (bandit JSON .results[])`,
        severityBreakdown: banditSeverityCounts,
      },
      banditHighHigh: {
        value: banditCriticalEscalations.length,
        jsonPath: `${analysisBasename} → .py.security.raw (bandit JSON .results[] where issue_severity=HIGH AND issue_confidence=HIGH)`,
      },
      semgrepTotalFindings: {
        value: Object.values(semgrepSeverityCounts).reduce((a, b) => a + b, 0),
        jsonPath: pySemgrepRaw
          ? `${analysisBasename} → .py.semgrep.raw (semgrep JSON .results[])`
          : jsSemgrepRaw
            ? `${analysisBasename} → .js.semgrep.raw (semgrep JSON .results[])`
            : goSemgrepRaw
              ? `${analysisBasename} → .go.semgrep.raw (semgrep JSON .results[])`
              : null,
        severityBreakdown: semgrepSeverityCounts,
      },
      intersectionP0Count: {
        value: p0.length,
        derivation: "fragility ∩ density ∩ vulnerability (all vectors)",
      },
      intersectionP0ProdCount: {
        value: p0Prod.length,
        derivation: "fragility ∩ density ∩ vulnerability (production paths only)",
      },
      complexityChurnKillZone: {
        value: fd.length,
        derivation: "fragility ∩ density (churn × complexity intersection)",
      },
      securityEscalationCount: {
        value: criticalEscalationsProd.length,
        derivation: "bandit HIGH/HIGH findings in production paths (standalone bypass)",
      },
    };

    const summary = {
      analysisFile: analysisBasename,
      status,
      nextActions,
      metricCitations,
      churn: {
        sinceRequested: churnMeta ? readString(churnMeta.sinceRequested) : null,
        sinceEffective: churnMeta ? readString(churnMeta.sinceEffective) : null,
        selectionMode: churnMeta ? readString(churnMeta.selectionMode) : null,
        minCount: churnMeta ? readFiniteNumber(churnMeta.minCount) : null,
        maxCandidates: churnMeta ? readFiniteNumber(churnMeta.maxCandidates) : null,
        commitCount: churnMeta ? readFiniteNumber(churnMeta.commitCount) : null,
        fileTouchLines: churnMeta ? readFiniteNumber(churnMeta.fileTouchLines) : null,
        uniqueFiles: churnMeta ? readFiniteNumber(churnMeta.uniqueFiles) : null,
        maxCount: churnMeta ? readFiniteNumber(churnMeta.maxCount) : null,
        observedHighChurnFiles: highChurnFiles.length,
      },
      thresholds: {
        churn: churnThreshold,
        complexity: complexityThreshold,
        maxCandidates,
        semgrepMinSeverity: (options.semgrepMinSeverity || "WARNING").toUpperCase(),
        includeNonSecuritySemgrep: Boolean(options.includeNonSecuritySemgrep),
        includeNonProd: Boolean(options.includeNonProd),
      },
      vectors: {
        fragility: Array.from(fragility).sort().slice(0, maxCandidates),
        density: Array.from(density).sort().slice(0, maxCandidates),
        vulnerability: {
          severityCounts,
          severityCountsSelected,
          sources: {
            semgrep: {
              severityCounts: semgrepSeverityCounts,
              selectedSeverityCounts: semgrepSelectedSeverityCounts,
            },
            bandit: {
              severityCounts: banditSeverityCounts,
              selectedSeverityCounts: banditSelectedSeverityCounts,
            },
          },
          files: Array.from(vulnFiles).sort().slice(0, maxCandidates),
        },
      },
      intersections: {
        p0: p0.slice(0, maxCandidates),
        p0Prod: p0Prod.slice(0, maxCandidates),
        fragilityDensity: fd.slice(0, maxCandidates),
        fragilityDensityProd: fdProd.slice(0, maxCandidates),
      },
      securityEscalations: {
        total: banditCriticalEscalations.length,
        totalProd: criticalEscalationsProd.length,
        findings: criticalEscalationsProd.map((e) => ({
          file: e.file,
          line: e.line,
          testId: e.testId,
          severity: e.severity,
          confidence: e.confidence,
          text: e.text,
          cwe: e.cwe,
        })),
      },
    };

    const output = JSON.stringify(summary, null, 2);

    if (Boolean(options.failOnActionRequired) && status !== "COMPLETE_NO_P0") {
      process.exitCode = 2;
    }

    if (typeof options.out === "string" && options.out.trim() !== "") {
      const outPath = path.resolve(process.cwd(), options.out.trim());
      await fs.mkdir(path.dirname(outPath), { recursive: true });
      await fs.writeFile(outPath, output + "\n", "utf8");
      process.stdout.write(`${outPath}\n`);
      return;
    }

    process.stdout.write(output + "\n");
  });
