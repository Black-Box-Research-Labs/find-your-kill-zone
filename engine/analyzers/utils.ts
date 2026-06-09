import { spawnSync } from "node:child_process";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

/**
 * Determine whether an environment-style string represents an affirmative value.
 *
 * @param value - The environment variable value to evaluate; may be `undefined`.
 * @returns `true` if `value` (case-insensitive) equals `true`, `1`, `yes`, or `on`, `false` otherwise.
 */
export function isEnvTrue(value: string | undefined): boolean {
  if (!value) return false;
  const normalized = value.trim().toLowerCase();
  return (
    normalized === "true" ||
    normalized === "1" ||
    normalized === "yes" ||
    normalized === "on"
  );
}

/**
 * Execute a command in the specified working directory and return its standard output.
 *
 * @param cmd - Executable name or path to run (e.g., "radon", "bandit", "git")
 * @param args - Arguments to pass to the command
 * @param cwd - Working directory for the command
 * @returns The command's stdout as a string
 * @throws Error - If the process fails to start, is terminated by a signal, or exits with a non-zero status. For `radon` or `bandit` failures the error message suggests installing the corresponding tool.
 */
export function run(cmd: string, args: string[], cwd: string): string {
  const timeoutMs = 300_000;
  const preserveTmp = isEnvTrue(process.env.BB_RUN_PRESERVE_TMP);

  const tmpRootEnv =
    typeof process.env.BB_RUN_TMPDIR === "string" &&
    process.env.BB_RUN_TMPDIR.trim().length > 0
      ? process.env.BB_RUN_TMPDIR.trim()
      : null;
  const tmpRoot = tmpRootEnv ? tmpRootEnv : os.tmpdir();
  if (tmpRootEnv) {
    try {
      if (fs.existsSync(tmpRoot)) {
        if (!fs.statSync(tmpRoot).isDirectory()) {
          throw new Error(`BB_RUN_TMPDIR is not a directory: ${tmpRoot}`);
        }
      } else {
        fs.mkdirSync(tmpRoot, { recursive: true });
      }
    } catch (e) {
      throw new Error(
        `Invalid BB_RUN_TMPDIR: ${tmpRoot}\n${captureError(e)}`,
      );
    }
  }

  const safeCmd = cmd.replace(/[^a-zA-Z0-9_-]/g, "_");
  const nonce = crypto.randomBytes(8).toString("hex");
  const stdoutPath = path.join(tmpRoot, `bb-run-${safeCmd}-${nonce}.stdout`);
  const stderrPath = path.join(tmpRoot, `bb-run-${safeCmd}-${nonce}.stderr`);

  let outFd: number | null = null;
  let errFd: number | null = null;

  try {
    outFd = fs.openSync(stdoutPath, "w");
    errFd = fs.openSync(stderrPath, "w");

    const res = spawnSync(cmd, args, {
      cwd,
      timeout: timeoutMs,
      stdio: ["ignore", outFd, errFd],
    });

    if (outFd !== null) fs.closeSync(outFd);
    if (errFd !== null) fs.closeSync(errFd);
    outFd = null;
    errFd = null;

    const stdout = fs.readFileSync(stdoutPath, "utf8");
    const stderr = fs.readFileSync(stderrPath, "utf8");

    if (!preserveTmp) {
      try {
        fs.unlinkSync(stdoutPath);
      } catch {
        true;
      }
      try {
        fs.unlinkSync(stderrPath);
      } catch {
        true;
      }
    }

    const errorMsg = res.error instanceof Error ? res.error.message : "";
    const status = typeof res.status === "number" ? res.status : null;
    const signal = typeof res.signal === "string" ? res.signal : null;

    if (res.error) {
      const message = errorMsg || "Failed to spawn process";

      if (cmd === "radon") {
        throw new Error(
          `Missing 'radon' binary or command failed. Fix: python3 -m pip install radon\n${message}`,
        );
      }

      if (cmd === "bandit") {
        throw new Error(
          `Missing 'bandit' binary or command failed. Fix: python3 -m pip install bandit\n${message}`,
        );
      }

      throw new Error(`Command failed: ${cmd} ${args.join(" ")}\n${message}`);
    }

    if (signal) {
      const message = stderr.trim() || stdout.trim() || `killed by signal: ${signal}`;
      throw new Error(`Command failed: ${cmd} ${args.join(" ")}\n${message}`);
    }

    if (status !== null && status !== 0) {
      const message = stderr.trim() || stdout.trim() || `exit=${status}`;

      if (cmd === "radon") {
        throw new Error(
          `Missing 'radon' binary or command failed. Fix: python3 -m pip install radon\n${message}`,
        );
      }

      if (cmd === "bandit") {
        throw new Error(
          `Missing 'bandit' binary or command failed. Fix: python3 -m pip install bandit\n${message}`,
        );
      }

      throw new Error(`Command failed: ${cmd} ${args.join(" ")}\n${message}`);
    }

    return stdout;
  } finally {
    if (outFd !== null) {
      try {
        fs.closeSync(outFd);
      } catch {
        true;
      }
    }
    if (errFd !== null) {
      try {
        fs.closeSync(errFd);
      } catch {
        true;
      }
    }
    if (!preserveTmp) {
      try {
        fs.unlinkSync(stdoutPath);
      } catch {
        true;
      }
      try {
        fs.unlinkSync(stderrPath);
      } catch {
        true;
      }
    }
  }
}

/**
 * Tool error tracking record type.
 */
export type ToolErrors = Record<string, string | null>;

/**
 * Creates a ToolErrors map with every known tool key initialized to `null`.
 *
 * @returns A ToolErrors object mapping each known tool name to `null`
 */
export function createToolErrors(): ToolErrors {
  return {
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
}

/**
 * Convert an unknown value to a usable error message string.
 *
 * @param e - The unknown error value to extract a message from.
 * @returns The error's message if `e` is an Error, otherwise the string representation of `e`.
 */
export function captureError(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * Strip leading non-JSON text (for example progress bars or log lines) from tool output.
 *
 * Finds the first `{` or `[` in the trimmed input and returns the substring starting at that delimiter; if neither delimiter is found, returns the trimmed original string.
 *
 * @param raw - Tool output that may contain leading non-JSON text
 * @returns The substring beginning at the first JSON delimiter (`{` or `[`), or the trimmed original input if no delimiter is present
 */
function extractJsonSubstring(raw: string): string {
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
}

/**
 * Counts files reported by radon whose `complexity` value is greater than 10.
 *
 * @param raw - The raw JSON output produced by `radon cc -j`
 * @returns The number of files with any entry whose numeric `complexity` is greater than 10; returns 0 if the input cannot be parsed
 */
export function parseRadonHighComplexityCount(raw: string): number {
  const threshold = 10;

  try {
    const parsed = JSON.parse(extractJsonSubstring(raw)) as Record<string, unknown>;
    let count = 0;

    for (const value of Object.values(parsed)) {
      if (!Array.isArray(value)) continue;

      let fileHasHigh = false;

      for (const entry of value) {
        if (!entry || typeof entry !== "object") continue;
        const record = entry as Record<string, unknown>;
        const complexity = record["complexity"];
        if (typeof complexity === "number" && complexity > threshold) {
          fileHasHigh = true;
          break;
        }
      }

      if (fileHasHigh) count += 1;
    }

    return count;
  } catch {
    return 0;
  }
}

/**
 * Counts unique files from ESLint JSON output where at least one `complexity`
 * rule message reports a cyclomatic complexity greater than 10.
 *
 * @param raw - The raw JSON output produced by `eslint -f json`
 * @returns The number of unique files with any complexity warning above 10; returns 0 if the input cannot be parsed
 */
export function parseEslintHighComplexityCount(raw: string): number {
  const threshold = 10;

  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return 0;

    let count = 0;
    for (const entry of parsed) {
      if (!entry || typeof entry !== "object") continue;
      const messages = (entry as Record<string, unknown>)["messages"];
      if (!Array.isArray(messages)) continue;

      let fileHasHigh = false;
      for (const msg of messages) {
        if (!msg || typeof msg !== "object") continue;
        const rec = msg as Record<string, unknown>;
        if (rec["ruleId"] !== "complexity") continue;
        const text = typeof rec["message"] === "string" ? rec["message"] : "";
        const m = text.match(/complexity of (\d+)/);
        if (m) {
          const cc = Number.parseInt(m[1] ?? "0", 10);
          if (cc > threshold) {
            fileHasHigh = true;
            break;
          }
        }
      }
      if (fileHasHigh) count += 1;
    }

    return count;
  } catch {
    return 0;
  }
}

/**
 * Count HIGH-severity findings from Bandit JSON output.
 *
 * @param raw - The Bandit output as a JSON string (expected to contain a `results` array)
 * @returns The number of items in `results` whose `issue_severity` equals `HIGH`; returns `0` if parsing fails or `results` is missing
 */
export function parseBanditHighCount(raw: string): number {
  try {
    const parsed = JSON.parse(extractJsonSubstring(raw)) as Record<string, unknown>;
    const results = parsed["results"];
    if (!Array.isArray(results)) return 0;

    let count = 0;
    for (const item of results) {
      if (!item || typeof item !== "object") continue;
      const record = item as Record<string, unknown>;
      const severity = record["issue_severity"];
      if (severity === "HIGH") count += 1;
    }

    return count;
  } catch {
    return 0;
  }
}

/**
 * Derives high-churn file hotspots from raw git churn output.
 *
 * @param churnRaw - Raw output from `git log --name-only` (one file path per line; blank lines and `.git/` entries are ignored)
 * @returns An array of `{ file, commits }` objects for files with more than 10 commits, sorted by `commits` descending
 */
export function computeHotspotsByChurn(
  churnRaw: string,
): Array<{ file: string; commits: number }>;
export function computeHotspotsByChurn(
  churnRaw: string,
  options?: {
    minCount?: number;
    maxCandidates?: number;
    ensureNonEmpty?: boolean;
  },
): Array<{ file: string; count: number; commits: number }>;
/**
 * Determine file hotspots from raw churn data by counting touches per file and returning the most-churned files.
 *
 * @param churnRaw - Newline-separated list of file paths (empty lines ignored). Lines beginning with `.git/` are ignored.
 * @param options - Optional behavior modifiers:
 *   - `minCount` — minimum touches required for a file to be considered a hotspot (default: 10).
 *   - `maxCandidates` — maximum number of entries to return when falling back to top candidates (default: 25).
 *   - `ensureNonEmpty` — when true and no file meets `minCount`, return the top `maxCandidates` instead of an empty array (default: false).
 * @returns An array of hotspot objects sorted by descending churn. Each object contains:
 *   - `file` — the file path,
 *   - `count` — the number of touches for that file,
 *   - `commits` — same value as `count` (provided for compatibility with older callers).
 */
export function computeHotspotsByChurn(
  churnRaw: string,
  options?: {
    minCount?: number;
    maxCandidates?: number;
    ensureNonEmpty?: boolean;
  },
): Array<{ file: string; count: number; commits: number }> {
  const counts: Record<string, number> = {};

  for (const line of churnRaw.split("\n")) {
    const file = line.trim();
    if (!file) continue;
    if (file.startsWith(".git/")) continue;

    counts[file] = (counts[file] ?? 0) + 1;
  }

  const minCount =
    typeof options?.minCount === "number" && Number.isFinite(options.minCount)
      ? Math.max(1, Math.floor(options.minCount))
      : 10;
  const maxCandidates =
    typeof options?.maxCandidates === "number" &&
    Number.isFinite(options.maxCandidates)
      ? Math.max(1, Math.floor(options.maxCandidates))
      : 25;
  const ensureNonEmpty = options?.ensureNonEmpty === true;

  const sorted = Object.entries(counts)
    .map(([file, count]) => ({ file, count, commits: count }))
    .sort((a, b) => b.count - a.count);

  const strict = sorted.filter((item) => item.count >= minCount);
  if (strict.length > 0) return strict.slice(0, maxCandidates);
  if (!ensureNonEmpty) return [];
  return sorted.slice(0, maxCandidates);
}

/**
 * Summarizes raw churn data to report total touches, number of distinct files, and the maximum touches for any single file.
 *
 * @param churnRaw - Newline-separated raw churn input where each non-empty line is a file path (lines beginning with `.git/` are ignored)
 * @returns An object with:
 *  - `fileTouchLines`: the total count of non-empty, non-`.git/` lines
 *  - `uniqueFiles`: the number of distinct file paths encountered
 *  - `maxCount`: the largest number of touches recorded for any single file
 */
export function summarizeChurnRaw(churnRaw: string): {
  fileTouchLines: number;
  uniqueFiles: number;
  maxCount: number;
} {
  let fileTouchLines = 0;
  const counts: Record<string, number> = {};

  for (const line of churnRaw.split("\n")) {
    const file = line.trim();
    if (!file) continue;
    if (file.startsWith(".git/")) continue;
    fileTouchLines += 1;
    counts[file] = (counts[file] ?? 0) + 1;
  }

  let maxCount = 0;
  for (const v of Object.values(counts)) {
    if (v > maxCount) maxCount = v;
  }

  return {
    fileTouchLines,
    uniqueFiles: Object.keys(counts).length,
    maxCount,
  };
}

/**
 * Extracts best-effort per-author ownership scores from Hercules (labours-format) JSON.
 *
 * Parses the provided JSON string, searches the structure for an `authors`-style array,
 * and aggregates numeric vectors aligned to those authors to produce per-author scores
 * and normalized shares. Returns `null` when the input is not parseable or yields no valid data.
 *
 * @param raw - Raw JSON text produced by Hercules / labours (expected labours-format output)
 * @returns An object with `ownershipByAuthor`, an array of up to 20 entries `{ author, score, share }`,
 *          or `null` if parsing fails or no valid ownership data is found
 */
export function parseHerculesOwnershipMinimal(raw: string): {
  ownershipByAuthor: { author: string; score: number; share: number }[];
} | null {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return null;
  }

  const totals = new Map<string, number>();

  /**
   * Add numeric entries from a numeric vector to the running totals map for corresponding authors.
   *
   * Updates a shared `totals` Map by adding each finite numeric element in `vec` to the matching author by index.
   *
   * @param authors - Ordered list of author identifiers. Each numeric element in `vec` will be added to the corresponding author at the same index.
   * @param vec - Expected to be an array of numbers aligned with `authors`. If not an array, has a different length than `authors`, or contains non-finite values, no totals are updated.
   * @returns `true` if at least one numeric value was added, `false` if `authors` and `vec` are both empty (nothing to add), or `undefined` when `vec` is invalid, mismatched, or contains non-finite entries.
   */
  function addVector(authors: string[], vec: unknown) {
    if (!Array.isArray(vec)) return;
    if (vec.length !== authors.length) return;
    let any = false;
    for (let i = 0; i < vec.length; i++) {
      const v = vec[i];
      if (typeof v === "number" && Number.isFinite(v)) {
        totals.set(authors[i], (totals.get(authors[i]) ?? 0) + v);
        any = true;
      } else {
        return;
      }
    }
    return any;
  }

  /**
   * Traverse a parsed JSON structure to discover author lists and accumulate numeric vectors aligned to those authors.
   *
   * Recursively scans objects and arrays; when an author list (keys like `authors`, `Authors`, or `people`) is found,
   * numeric arrays whose length matches the authors (or 2D arrays with rows that match) are aggregated into the module's
   * ownership totals.
   *
   * @param node - A parsed JSON node (object, array, primitive) to traverse
   * @param currentAuthors - The current author list context, or `null` if none has been found in the ancestors
   */
  function traverse(node: unknown, currentAuthors: string[] | null) {
    if (node && typeof node === "object") {
      if (Array.isArray(node)) {
        for (const item of node) traverse(item, currentAuthors);
        return;
      }
      const rec = node as Record<string, unknown>;
      let authorsHere: string[] | null = currentAuthors;
      const poss = rec["authors"] ?? rec["Authors"] ?? rec["people"];
      if (Array.isArray(poss) && poss.every((x) => typeof x === "string")) {
        authorsHere = poss as string[];
      }

      if (authorsHere) {
        for (const val of Object.values(rec)) {
          if (Array.isArray(val)) {
            if (addVector(authorsHere, val)) continue;
            if (
              val.length > 0 &&
              Array.isArray(val[0]) &&
              (val[0] as unknown[]).length === authorsHere.length
            ) {
              for (const row of val) addVector(authorsHere, row);
            }
          }
        }
      }

      for (const v of Object.values(rec)) traverse(v, authorsHere);
    }
  }

  traverse(data, null);

  const entries = Array.from(totals.entries())
    .map(([author, score]) => ({ author, score }))
    .sort((a, b) => b.score - a.score);
  const total = entries.reduce((s, e) => s + e.score, 0);
  if (!Number.isFinite(total) || total <= 0 || entries.length === 0)
    return null;

  const ownershipByAuthor = entries.slice(0, 20).map((e) => ({
    author: e.author,
    score: Math.round(e.score * 1000) / 1000,
    share: Math.round((e.score / total) * 10000) / 10000,
  }));
  return { ownershipByAuthor };
}

const BUG_FIX_RE = /\b(fix|bug|revert|regression|patch|hotfix|bugfix)\b/i;
const FALSE_POSITIVE_RE = /\b(fixture|debug.?log|bugbear)\b/i;

/**
 * Count commits whose messages indicate bug-fix activity.
 *
 * Parses newline-separated `git log --oneline` output and returns the count
 * of lines whose commit message matches bug-fix keywords while excluding
 * known false-positive patterns (e.g. "fixture", "bugbear").
 *
 * @param gitLogOneline - Raw output from `git log --oneline --follow -- <file>`
 * @returns The number of commit messages classified as bug-fix related
 */
export function classifyBugFixCommits(gitLogOneline: string): number {
  let count = 0;
  for (const line of gitLogOneline.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const message = trimmed.replace(/^[0-9a-f]+\s+/, "");
    if (!BUG_FIX_RE.test(message)) continue;
    if (FALSE_POSITIVE_RE.test(message)) continue;
    count++;
  }
  return count;
}