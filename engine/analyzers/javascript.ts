import * as path from "node:path";
import { run } from "./utils.js";

export interface JavaScriptAnalysisResult {
  jscpdRaw: string;
  depcheckRaw: string;
  retireRaw: string;
  madgeRaw: string;
  semgrepRaw: string;
  complexityJsRaw: string;
  knipRaw: string;
  tsPruneRaw: string;
  licenseCheckerRaw: string;
  depCruiserRaw: string;
  typeCoverageRaw: string;
  depcheckByPackage: Record<string, { raw: string; error: string | null }>;
  retireByPackage: Record<string, { raw: string; error: string | null }>;
  errors: {
    jscpd: string | null;
    depcheck: string | null;
    retire: string | null;
    madge: string | null;
    semgrep: string | null;
    complexityJs: string | null;
    knip: string | null;
    tsPrune: string | null;
    licenseChecker: string | null;
    dependencyCruiser: string | null;
    typeCoverage: string | null;
  };
}

/**
 * Orchestrates multiple JavaScript/TypeScript analysis tools and aggregates their outputs.
 *
 * @param absolutePath - Absolute path to the repository root where analyses will be executed
 * @param trackedFiles - List of repository file paths used to select file patterns and subsets for analyses
 * @param tsconfigs - Relative paths to tsconfig files; used to run type-coverage per tsconfig (up to 25)
 * @param repoFileCount - Total number of files in the repository; used to skip expensive checks for very large repos
 * @returns A JavaScriptAnalysisResult containing raw outputs from each tool, per-package depcheck/retire results, and an errors map for each tool
 */
export function runJavaScriptAnalysis(
  absolutePath: string,
  trackedFiles: string[],
  tsconfigs: string[],
  repoFileCount: number,
): JavaScriptAnalysisResult {
  const errors: JavaScriptAnalysisResult["errors"] = {
    jscpd: null,
    depcheck: null,
    retire: null,
    madge: null,
    semgrep: null,
    complexityJs: null,
    knip: null,
    tsPrune: null,
    licenseChecker: null,
    dependencyCruiser: null,
    typeCoverage: null,
  };

  const depcheckByPackage: Record<
    string,
    { raw: string; error: string | null }
  > = {};
  const retireByPackage: Record<string, { raw: string; error: string | null }> =
    {};

  // jscpd - copy/paste detection
  let jscpdRaw = "";
  try {
    if (repoFileCount > 5000) {
      errors.jscpd = "skipped: repository too large for default jscpd run";
    } else {
      const jscpdArgs: string[] = ["--reporters", "json", "--silent"];
      const addPattern = (p: string) => {
        jscpdArgs.push("--pattern", p);
      };
      const addIgnore = (e: string) => {
        jscpdArgs.push("--ignore", e);
      };
      // Patterns based on repo content
      if (trackedFiles.some((f) => f.endsWith(".ts"))) addPattern("**/*.ts");
      if (trackedFiles.some((f) => f.endsWith(".tsx"))) addPattern("**/*.tsx");
      if (trackedFiles.some((f) => f.endsWith(".js"))) addPattern("**/*.js");
      if (trackedFiles.some((f) => f.endsWith(".jsx"))) addPattern("**/*.jsx");
      if (trackedFiles.some((f) => f.endsWith(".py"))) addPattern("**/*.py");
      // Common heavyweight ignores
      addIgnore("**/node_modules/**");
      addIgnore("**/.next/**");
      addIgnore("**/dist/**");
      addIgnore("**/build/**");
      addIgnore("**/coverage/**");
      // Root path last
      jscpdArgs.push(absolutePath);
      jscpdRaw = run("jscpd", jscpdArgs, absolutePath);
    }
  } catch (e) {
    errors.jscpd = e instanceof Error ? e.message : String(e);
  }

  // depcheck - unused dependencies
  let depcheckRaw = "";
  try {
    depcheckRaw = run("bash", ["-lc", "depcheck --json || true"], absolutePath);
  } catch (e) {
    errors.depcheck = e instanceof Error ? e.message : String(e);
  }

  // Per-package depcheck/retire for monorepos (best-effort)
  try {
    const listRaw = run(
      "bash",
      [
        "-lc",
        "find . -maxdepth 4 -name package.json -not -path '*/node_modules/*'",
      ],
      absolutePath,
    );
    const pkgs = listRaw
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);

    for (const pkg of pkgs) {
      const relDir = path.dirname(pkg);
      const pkgDir = path.resolve(absolutePath, relDir);
      // depcheck per package
      try {
        const raw = run("bash", ["-lc", "depcheck --json || true"], pkgDir);
        depcheckByPackage[relDir] = { raw, error: null };
      } catch (e) {
        depcheckByPackage[relDir] = {
          raw: "",
          error: e instanceof Error ? e.message : String(e),
        };
      }
      // retire per package
      try {
        const raw = run(
          "bash",
          [
            "-lc",
            "retire --path . --outputformat json --noupdate --exitwith 0 || true",
          ],
          pkgDir,
        );
        retireByPackage[relDir] = { raw, error: null };
      } catch (e) {
        retireByPackage[relDir] = {
          raw: "",
          error: e instanceof Error ? e.message : String(e),
        };
      }
    }
  } catch {
    // ignore enumeration failures
  }

  // retire - vulnerability scanning
  let retireRaw = "";
  try {
    retireRaw = run(
      "bash",
      [
        "-lc",
        "retire --path . --outputformat json --noupdate --exitwith 0 || true",
      ],
      absolutePath,
    );
  } catch (e) {
    errors.retire = e instanceof Error ? e.message : String(e);
  }

  // madge - circular dependency detection
  let madgeRaw = "";
  try {
    madgeRaw = run("madge", ["--json", "--circular", "."], absolutePath);
  } catch (e) {
    errors.madge = e instanceof Error ? e.message : String(e);
  }

  // semgrep JS/TS
  let semgrepRaw = "";
  try {
    semgrepRaw = run(
      "bash",
      [
        "-lc",
        "semgrep --config /opt/engine/semgrep/semgrep-rules-js.yml --include '**/*.ts' --include '**/*.tsx' --include '**/*.js' --include '**/*.jsx' --exclude '**/node_modules/**' --exclude '**/.next/**' --exclude '**/dist/**' --exclude '**/build/**' --exclude '**/coverage/**' --json --metrics=off --timeout 0 || true",
      ],
      absolutePath,
    );
  } catch (e) {
    errors.semgrep = e instanceof Error ? e.message : String(e);
  }

  // JS/TS complexity via ESLint + @typescript-eslint/parser (best-effort)
  // Replaces legacy `cr` which only handled .js and crashed on modern syntax.
  // ESLint exits 1 on warnings so we wrap with `|| true` (same pattern as knip).
  let complexityJsRaw = "";
  try {
    const jsTsTrackedAll = trackedFiles.filter(
      (f) => f.endsWith(".ts") || f.endsWith(".tsx") || f.endsWith(".js") || f.endsWith(".jsx"),
    );
    if (jsTsTrackedAll.length > 0) {
      complexityJsRaw = run(
        "bash",
        [
          "-lc",
          "NODE_PATH=/usr/local/lib/node_modules eslint --no-eslintrc" +
            " --parser @typescript-eslint/parser" +
            " --parser-options ecmaVersion:2022,sourceType:module" +
            " --rule 'complexity: [warn, 10]'" +
            " --ext .ts,.tsx,.js,.jsx" +
            " --ignore-pattern '**/vendor/**'" +
            " --ignore-pattern '**/node_modules/**'" +
            " --ignore-pattern '**/*.d.ts'" +
            " --ignore-pattern '**/dist/**'" +
            " --ignore-pattern '**/build/**'" +
            " --ignore-pattern '**/coverage/**'" +
            " --ignore-pattern '**/__mocks__/**'" +
            " --ignore-pattern '**/.next/**'" +
            " --no-error-on-unmatched-pattern" +
            " -f json . || true",
        ],
        absolutePath,
      );
    }
  } catch (e) {
    errors.complexityJs = e instanceof Error ? e.message : String(e);
  }

  // knip - unused exports.
  // NOTE: `--json` is NOT a knip 5.x flag (the JSON reporter is selected via
  // `--reporter json`); the old `knip --json` printed help text and exited,
  // so knip emitted a ~4.4 KB usage blob instead of findings on EVERY target
  // (Python and TS alike). Guard on package.json (mirrors the ts-prune
  // tsconfig guard) so non-JS targets short-circuit to empty cleanly instead
  // of emitting help, and use the correct reporter flag.
  let knipRaw = "";
  try {
    knipRaw = run(
      "bash",
      ["-lc", "[ -f package.json ] && knip --reporter json || true"],
      absolutePath,
    );
  } catch (e) {
    errors.knip = e instanceof Error ? e.message : String(e);
  }

  // ts-prune - unused TypeScript exports
  let tsPruneRaw = "";
  try {
    tsPruneRaw = run(
      "bash",
      ["-lc", "[ -f tsconfig.json ] && ts-prune -p tsconfig.json || true"],
      absolutePath,
    );
  } catch (e) {
    errors.tsPrune = e instanceof Error ? e.message : String(e);
  }

  // license-checker
  let licenseCheckerRaw = "";
  try {
    licenseCheckerRaw = run(
      "bash",
      ["-lc", "license-checker --json || true"],
      absolutePath,
    );
  } catch (e) {
    errors.licenseChecker = e instanceof Error ? e.message : String(e);
  }

  // dependency-cruiser.
  // NOTE: bare `depcruise .` builds the module graph but reports
  // ZERO violations without a ruleset — confirmed empty even on valid TS
  // targets (continue + humanlayer). Supply a minimal default ruleset
  // (no-circular = warn, no-orphans = info) via a runtime temp config so the
  // cruiser actually emits `summary.violations[]` for Rule 12 to consume. The
  // JSON is single-quoted in bash (double-quotes literal) and written with
  // printf to avoid heredoc-in-string fragility; `pathNot` uses `[.]` char
  // classes instead of `\.` to dodge JS/bash backslash escaping. Validation is
  // Docker-gated (needs a fresh TS re-analyze; existing JSONs are pre-fix).
  let depCruiserRaw = "";
  try {
    depCruiserRaw = run(
      "bash",
      [
        "-lc",
        `CFG=$(mktemp); printf '%s' '{"forbidden":[{"name":"no-circular","severity":"warn","from":{},"to":{"circular":true}},{"name":"no-orphans","severity":"info","from":{"orphan":true,"pathNot":["[.](json|d[.]ts)$"]},"to":{}}]}' > "$CFG"; depcruise --config "$CFG" -x 'node_modules|dist|build|coverage' --output-type json . || true; rm -f "$CFG"`,
      ],
      absolutePath,
    );
  } catch (e) {
    errors.dependencyCruiser = e instanceof Error ? e.message : String(e);
  }

  // type-coverage
  let typeCoverageRaw = "";
  try {
    if (tsconfigs.length > 0) {
      const parts: string[] = [];
      let anyTypeCoverageOk = false;
      const typeCoverageErrors: string[] = [];
      for (const rel of tsconfigs.slice(0, 25)) {
        try {
          const abs = path.resolve(absolutePath, rel);
          const pkgDir = path.dirname(abs);
          const out = run(
            "type-coverage",
            ["-p", abs, "--detail", "--ignore-catch", "false"],
            pkgDir,
          );
          parts.push(`# ${rel}\n${out}`);
          anyTypeCoverageOk = true;
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          typeCoverageErrors.push(`# ${rel} ERROR\n${msg}`);
        }
      }
      if (parts.length > 0) {
        typeCoverageRaw = parts.join("\n");
      }
      if (!anyTypeCoverageOk && typeCoverageErrors.length > 0) {
        errors.typeCoverage = typeCoverageErrors[0];
      }
    }
  } catch (e) {
    errors.typeCoverage = e instanceof Error ? e.message : String(e);
  }

  // Normalize retire empty output
  if (!retireRaw || retireRaw.trim() === "") {
    retireRaw = "{}";
  }

  return {
    jscpdRaw,
    depcheckRaw,
    retireRaw,
    madgeRaw,
    semgrepRaw,
    complexityJsRaw,
    knipRaw,
    tsPruneRaw,
    licenseCheckerRaw,
    depCruiserRaw,
    typeCoverageRaw,
    depcheckByPackage,
    retireByPackage,
    errors,
  };
}