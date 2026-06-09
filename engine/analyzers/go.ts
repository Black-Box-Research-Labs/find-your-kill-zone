import { execFileSync } from "node:child_process";

export interface GoAnalysisResult {
  semgrepGoRaw: string;
  gosecRaw: string;
  gocycloRaw: string;
  errors: {
    semgrepGo: string | null;
    gosec: string | null;
    gocyclo: string | null;
  };
}

/**
 * Run Go static analysis tools against a repository path and collect each tool's raw output and any observed errors.
 *
 * @param absolutePath - Filesystem path used as the working directory for each analysis command
 * @param hasGoFiles - Whether the target contains Go files; controls whether gocyclo is executed
 * @returns An object with raw tool outputs (`semgrepGoRaw`, `gosecRaw`, `gocycloRaw`) and an `errors` map containing per-tool error messages or `null` when no error was observed
 */
export function runGoAnalysis(
  absolutePath: string,
  hasGoFiles: boolean,
): GoAnalysisResult {
  const runBash = (
    cmd: string,
  ): { stdout: string; stderr: string; status: number } => {
    try {
      const stdout = execFileSync("bash", ["-lc", cmd], {
        cwd: absolutePath,
        timeout: 300_000,
        maxBuffer: 10 * 1024 * 1024,
        stdio: ["ignore", "pipe", "pipe"],
      });
      return { stdout: stdout.toString(), stderr: "", status: 0 };
    } catch (e: unknown) {
      const err = e as {
        status?: number | null;
        stdout?: Buffer;
        stderr?: Buffer;
        message?: string;
      };
      const status = typeof err.status === "number" ? err.status : 1;
      const stdout = err.stdout ? err.stdout.toString() : "";
      const stderr = err.stderr ? err.stderr.toString() : (err.message ?? "");
      return { stdout, stderr, status };
    }
  };

  const errors: GoAnalysisResult["errors"] = {
    semgrepGo: null,
    gosec: null,
    gocyclo: null,
  };

  // Go Semgrep (offline rules from vendored pack). Best-effort and non-fatal.
  let semgrepGoRaw = "";
  try {
    const res = runBash(
      "semgrep --config /opt/semgrep-rules/go --include '**/*.go' --exclude '**/vendor/**' --exclude '**/node_modules/**' --exclude '**/dist/**' --exclude '**/build/**' --exclude '**/coverage/**' --json --metrics=off --timeout 0",
    );
    semgrepGoRaw = res.stdout;
    if (res.status !== 0) {
      errors.semgrepGo = `semgrep failed (exit ${res.status})${res.stderr ? `: ${res.stderr}` : ""}`;
    } else {
      try {
        const trimmed = semgrepGoRaw.trim();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
          const parsed = JSON.parse(trimmed) as { errors?: unknown };
          const semgrepErrors = (parsed as { errors?: unknown[] }).errors;
          if (Array.isArray(semgrepErrors) && semgrepErrors.length > 0) {
            errors.semgrepGo = `semgrep reported ${semgrepErrors.length} error(s)`;
          }
        }
      } catch (e) {
        errors.semgrepGo =
          e instanceof Error ? e.message : "Failed to parse semgrep JSON";
      }
    }
  } catch (e) {
    errors.semgrepGo = e instanceof Error ? e.message : String(e);
  }

  // Go security scan (best-effort)
  let gosecRaw = "";
  try {
    const res = runBash("gosec -fmt=json -quiet ./...");
    gosecRaw = res.stdout;
    if (res.status === 127) {
      errors.gosec = "gosec not installed";
    } else if (res.status !== 0 && res.status !== 1) {
      errors.gosec = `gosec failed (exit ${res.status})${res.stderr ? `: ${res.stderr}` : ""}`;
    }
  } catch (e) {
    errors.gosec = e instanceof Error ? e.message : String(e);
  }

  // Go cyclomatic complexity (best-effort)
  let gocycloRaw = "";
  try {
    if (hasGoFiles) {
      const res = runBash("gocyclo -over 10 .");
      gocycloRaw = res.stdout;
      if (res.status === 127) {
        errors.gocyclo = "gocyclo not installed";
      } else if (res.status !== 0 && res.status !== 1) {
        errors.gocyclo = `gocyclo failed (exit ${res.status})${res.stderr ? `: ${res.stderr}` : ""}`;
      }
    }
  } catch (e) {
    errors.gocyclo = e instanceof Error ? e.message : String(e);
  }

  return {
    semgrepGoRaw,
    gosecRaw,
    gocycloRaw,
    errors,
  };
}