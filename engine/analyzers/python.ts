import * as path from "node:path";
import { spawnSync } from "node:child_process";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import { run } from "./utils.js";

export interface PythonAnalysisResult {
  complexityRaw: string;
  securityRaw: string;
  semgrepPyRaw: string;
  vultureRaw: string;
  safetyRaw: string;
  errors: {
    semgrepPy: string | null;
    vulture: string | null;
    safety: string | null;
  };
}

/**
 * Run multiple Python static-analysis and dependency-scan tools against a project directory.
 *
 * @param absolutePath - Filesystem path of the project root to analyze.
 * @param trackedFiles - List of project-tracked file paths; used to locate `requirements*.txt` files for dependency scanning.
 * @returns An object containing raw outputs for radon (complexity), bandit (security), semgrep (Python rules), vulture (dead-code detection), safety (dependency checks), and an `errors` map with tool-specific error messages for `semgrepPy`, `vulture`, and `safety`.
 */
export async function runPythonAnalysis(
  absolutePath: string,
  trackedFiles: string[],
  onProgress?: (msg: string) => void,
): Promise<PythonAnalysisResult> {
  // Yield the worker's event loop so a queued onProgress postMessage actually
  // transmits to the main thread DURING the run (a sync spawnSync chain would
  // otherwise flush everything only at the end — out of order). No-op cost.
  const _flush = (): Promise<void> =>
    onProgress
      ? new Promise<void>((r) => setImmediate(r))
      : Promise.resolve();
  const makeTmpPath = (prefix: string, ext: string): string => {
    const nonce = crypto.randomBytes(8).toString("hex");
    return path.join(os.tmpdir(), `${prefix}-${nonce}.${ext}`);
  };

  const requirementsFromUvLock = (content: string): {
    requirements: string;
    packageCount: number;
  } => {
    const lines = content.split("\n");
    const requirements: string[] = [];

    let inPackage = false;
    let pkgName: string | null = null;
    let pkgVersion: string | null = null;

    const flush = (): void => {
      if (pkgName && pkgVersion) {
        requirements.push(`${pkgName}==${pkgVersion}`);
      }
      pkgName = null;
      pkgVersion = null;
    };

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (line === "[[package]]") {
        if (inPackage) flush();
        inPackage = true;
        continue;
      }
      if (!inPackage) continue;

      if (!pkgName) {
        const mName = line.match(/^name\s*=\s*"([^"]+)"\s*$/);
        if (mName) {
          pkgName = mName[1] ?? null;
          continue;
        }
      }

      if (!pkgVersion) {
        const mVer = line.match(/^version\s*=\s*"([^"]+)"\s*$/);
        if (mVer) {
          pkgVersion = mVer[1] ?? null;
          continue;
        }
      }

      if (pkgName && pkgVersion) {
        flush();
      }
    }

    if (inPackage) flush();

    const unique = Array.from(new Set(requirements)).sort((a, b) =>
      a.localeCompare(b),
    );
    return { requirements: unique.join("\n") + "\n", packageCount: unique.length };
  };

  const runBash = (
    cmd: string,
  ): { stdout: string; stderr: string; status: number } => {
    const timeoutMs = 300_000;
    const tmpRoot = os.tmpdir();
    const nonce = crypto.randomBytes(8).toString("hex");
    const stdoutPath = path.join(tmpRoot, `bb-py-runbash-${nonce}.stdout`);
    const stderrPath = path.join(tmpRoot, `bb-py-runbash-${nonce}.stderr`);

    let outFd: number | null = null;
    let errFd: number | null = null;

    try {
      outFd = fs.openSync(stdoutPath, "w");
      errFd = fs.openSync(stderrPath, "w");

      const res = spawnSync("bash", ["-lc", cmd], {
        cwd: absolutePath,
        timeout: timeoutMs,
        stdio: ["ignore", outFd, errFd],
      });

      if (outFd !== null) fs.closeSync(outFd);
      if (errFd !== null) fs.closeSync(errFd);
      outFd = null;
      errFd = null;

      const stdout = fs.readFileSync(stdoutPath, "utf8");
      const stderr = fs.readFileSync(stderrPath, "utf8");

      const status =
        typeof res.status === "number"
          ? res.status
          : res.signal
            ? 1
            : res.error
              ? 1
              : 0;
      const errMsg =
        res.error instanceof Error ? res.error.message : "";
      const finalStderr = stderr || errMsg;

      return {
        stdout,
        stderr: finalStderr,
        status,
      };
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
  };

  const runOfflineAdvisoryDbAudit = (
    reqPath: string,
  ): { raw: string; error: string | null } => {
    const dbRoot = process.env.PYTHON_ADVISORY_DB || "/opt/advisory-db";
    const vulnsDir = path.join(dbRoot, "vulns");
    if (!fs.existsSync(vulnsDir)) {
      return {
        raw: `# OFFLINE_DB_MISSING: ${vulnsDir}`,
        error: `OFFLINE_DB_MISSING: advisory DB not found at ${vulnsDir}`,
      };
    }

    const cmd =
      `REQ=${JSON.stringify(reqPath)} DB=${JSON.stringify(dbRoot)} python3 - <<'PY'\n` +
      `import json\n` +
      `import os\n` +
      `import re\n` +
      `from pathlib import Path\n` +
      `\n` +
      `import yaml\n` +
      `from packaging.version import Version\n` +
      `\n` +
      `req_path = os.environ.get('REQ')\n` +
      `db_root = os.environ.get('DB', '/opt/advisory-db')\n` +
      `vulns_dir = Path(db_root) / 'vulns'\n` +
      `\n` +
      `def canonicalize(name: str) -> str:\n` +
      `  return re.sub(r'[-_.]+', '-', (name or '').strip().lower())\n` +
      `\n` +
      `def parse_requirements(p: str):\n` +
      `  deps = []\n` +
      `  try:\n` +
      `    for raw in Path(p).read_text(encoding='utf-8', errors='ignore').splitlines():\n` +
      `      line = raw.strip()\n` +
      `      if not line or line.startswith('#'):\n` +
      `        continue\n` +
      `      m = re.match(r'^([A-Za-z0-9_.-]+)==([^\\s]+)$', line)\n` +
      `      if not m:\n` +
      `        continue\n` +
      `      deps.append((m.group(1), m.group(2)))\n` +
      `  except Exception:\n` +
      `    return []\n` +
      `  return deps\n` +
      `\n` +
      `def is_affected(version: Version, osv: dict):\n` +
      `  affected = osv.get('affected') or []\n` +
      `  for entry in affected:\n` +
      `    ranges = (entry or {}).get('ranges') or []\n` +
      `    for r in ranges:\n` +
      `      if (r or {}).get('type') != 'ECOSYSTEM':\n` +
      `        continue\n` +
      `      events = (r or {}).get('events') or []\n` +
      `      current_intro = None\n` +
      `      for ev in events:\n` +
      `        if not isinstance(ev, dict):\n` +
      `          continue\n` +
      `        if 'introduced' in ev:\n` +
      `          try:\n` +
      `            current_intro = Version(str(ev.get('introduced')))\n` +
      `          except Exception:\n` +
      `            current_intro = None\n` +
      `        if 'fixed' in ev and current_intro is not None:\n` +
      `          try:\n` +
      `            fixed = Version(str(ev.get('fixed')))\n` +
      `            if version >= current_intro and version < fixed:\n` +
      `              return True\n` +
      `          except Exception:\n` +
      `            pass\n` +
      `          current_intro = None\n` +
      `        if 'last_affected' in ev and current_intro is not None:\n` +
      `          try:\n` +
      `            last = Version(str(ev.get('last_affected')))\n` +
      `            if version >= current_intro and version <= last:\n` +
      `              return True\n` +
      `          except Exception:\n` +
      `            pass\n` +
      `          current_intro = None\n` +
      `      if current_intro is not None:\n` +
      `        if version >= current_intro:\n` +
      `          return True\n` +
      `  return False\n` +
      `\n` +
      `if not vulns_dir.exists():\n` +
      `  print(json.dumps({'error': 'OFFLINE_DB_MISSING', 'vulnsDir': str(vulns_dir)}))\n` +
      `  raise SystemExit(3)\n` +
      `\n` +
      `deps = parse_requirements(req_path)\n` +
      `results = []\n` +
      `total_vulns = 0\n` +
      `for name, ver in deps:\n` +
      `  canon = canonicalize(name)\n` +
      `  pkg_dir = vulns_dir / canon\n` +
      `  if not pkg_dir.exists():\n` +
      `    continue\n` +
      `  try:\n` +
      `    v = Version(str(ver))\n` +
      `  except Exception:\n` +
      `    continue\n` +
      `  vulns = []\n` +
      `  for p in pkg_dir.glob('*.y*ml'):\n` +
      `    try:\n` +
      `      osv = yaml.safe_load(p.read_text(encoding='utf-8', errors='ignore'))\n` +
      `      if not isinstance(osv, dict):\n` +
      `        continue\n` +
      `      if not is_affected(v, osv):\n` +
      `        continue\n` +
      `      vulns.append({\n` +
      `        'id': osv.get('id'),\n` +
      `        'aliases': osv.get('aliases') or [],\n` +
      `        'details': (osv.get('details') or ''),\n` +
      `        'published': osv.get('published'),\n` +
      `      })\n` +
      `    except Exception:\n` +
      `      continue\n` +
      `  if vulns:\n` +
      `    total_vulns += len(vulns)\n` +
      `    results.append({'name': name, 'version': ver, 'vulnerabilities': vulns})\n` +
      `\n` +
      `print(json.dumps({\n` +
      `  'db': str(vulns_dir),\n` +
      `  'dependencyCount': len(deps),\n` +
      `  'vulnerabilityCount': total_vulns,\n` +
      `  'results': results,\n` +
      `}, ensure_ascii=False))\n` +
      `PY`;

    const res = runBash(cmd);
    const combined = [res.stdout.trim(), res.stderr.trim()]
      .filter(Boolean)
      .join("\n");
    if (res.status === 127) {
      return { raw: combined, error: "python3 not installed" };
    }
    if (res.status !== 0) {
      if (combined.includes("OFFLINE_DB_MISSING")) {
        return { raw: combined, error: `OFFLINE_DB_MISSING: ${vulnsDir}` };
      }
      return {
        raw: combined,
        error: res.stderr
          ? `offline advisory audit failed (exit ${res.status}): ${res.stderr}`
          : `offline advisory audit failed (exit ${res.status})`,
      };
    }
    return { raw: combined, error: null };
  };

  const errors: PythonAnalysisResult["errors"] = {
    semgrepPy: null,
    vulture: null,
    safety: null,
  };

  // Real sub-tool signal for the live demo. python is the long pole (semgrep),
  // so it reports `pysub:` events at real boundaries with REAL counts — NOT a
  // filler pulse. Reported via onProgress (the parallel worker forwards these to
  // the main thread by postMessage so they stay ordered; a worker's stderr would
  // arrive out of order). High-severity for bandit (the scary number, not the
  // raw total). No-op when onProgress is absent / progress disabled.
  const _countSemgrep = (raw: string): number => {
    try {
      const j = JSON.parse(raw.replace(/^[^{[]*/, "")) as {
        results?: unknown[];
      };
      return Array.isArray(j.results) ? j.results.length : 0;
    } catch {
      return 0;
    }
  };
  const _countBanditHigh = (raw: string): number => {
    try {
      const j = JSON.parse(raw.replace(/^[^{[]*/, "")) as {
        results?: { issue_severity?: string }[];
      };
      return Array.isArray(j.results)
        ? j.results.filter(
            (r) => (r.issue_severity || "").toUpperCase() === "HIGH",
          ).length
        : 0;
    } catch {
      return 0;
    }
  };

  // Optional sub-directory scope for the python tools (BB_PY_SCAN_SUBDIR, e.g.
  // "src"). On a slow host this cuts the python worker substantially (radon +
  // bandit + semgrep all scan the subtree) while keeping the demo's findings —
  // the c2 B-codes all live under src/. Falls back to the full tree if the subdir
  // is absent. Default = whole tree (Mac/CI unchanged). filenames still contain
  // "src/" so c2's filter + sub("/workspace/cai/";"") are unaffected.
  const _pyScanSub = (process.env.BB_PY_SCAN_SUBDIR || "").trim();
  const scanRoot =
    _pyScanSub && fs.existsSync(path.join(absolutePath, _pyScanSub))
      ? path.join(absolutePath, _pyScanSub)
      : absolutePath;

  // Radon complexity (always runs - required)
  const complexityRaw = run("radon", ["cc", scanRoot, "-j"], absolutePath);

  // Bandit security (always runs - required)
  const securityRaw = run(
    "bandit",
    ["-r", scanRoot, "-f", "json", "--exit-zero"],
    absolutePath,
  );
  onProgress?.(`pysub:bandit:${_countBanditHigh(securityRaw)}`);
  await _flush();

  // Python Semgrep (offline rules from vendored pack). Best-effort and non-fatal.
  let semgrepPyRaw = "";
  try {
    const semgrepOutPath = makeTmpPath("bb-semgrep-py", "json");
    // BB_SEMGREP_JOBS override: default "1" preserves the large-tree OOM guard
    // (agno = 3830 py files). Demo target cai (351 files, 3.8GB container) opts
    // into "4" for ~3x speedup with identical findings. Strict /^\d+$/ guards
    // against shell injection since the value is interpolated into runBash.
    const jobsVal = /^\d+$/.test(process.env.BB_SEMGREP_JOBS || "")
      ? (process.env.BB_SEMGREP_JOBS as string)
      : "1";
    // Scale-stability fix: on large Python targets (agno = 2,373
    // py files × 380 rules) semgrep 1.40.0 aborted with exit 1 and no output
    // file. Three changes: (1) drop the redundant `--include '**/*.py'` — the
    // python rule packs already scope to Python and the include overlapped the
    // excludes (semgrep's "paths match both --include and --exclude" warning,
    // a signature of an unhealthy invocation); (2) add an explicit `.` target
    // instead of relying on bare cwd; (3) cap memory + single-thread
    // (`--max-memory 2000 --jobs 1`) so the scan plan doesn't OOM/abort on a
    // large tree. Validation is Docker-gated (semgrep is image-only); see
    // packet — end-to-end confirmation runs during the agno re-analyze cycle.
    onProgress?.(`pysub:semgrep-start:${trackedFiles.length}`);
    await _flush();
    const res = runBash(
      `OUT=${JSON.stringify(semgrepOutPath)}; ` +
        // Two optional speed knobs for slow hosts (semgrep-py is the longest
        // analyzer, ~95s on a 2-core box). Both default to off = Mac/CI unchanged.
        // Shell ${} are escaped (\${) so the CONTAINER evaluates them, not JS.
        //  • BB_SEMGREP_PY_TIMEOUT (per-rule seconds, replaces semgrep's default
        //    --timeout 0=unbounded): semgrep still COMPLETES and writes real
        //    findings, just skips pathologically-slow rule×file combos. Measured:
        //    timeout=2 → 69s/231 findings vs 95s/231 (keeps all findings). This is
        //    the findings-preserving lever (use this for the live demo).
        //  • BB_SEMGREP_PY_CAP_S (wall-clock seconds): hard SIGTERM backstop. If it
        //    fires, semgrep is killed before writing $OUT → 0 findings. Safety net
        //    only; leave unset for the demo so findings are preserved.
        `TO=; command -v timeout >/dev/null 2>&1 && [ "\${BB_SEMGREP_PY_CAP_S:-0}" -gt 0 ] 2>/dev/null && TO="timeout -k 5 -s TERM \${BB_SEMGREP_PY_CAP_S}s"; ` +
        // Config pack + scan scope are env-overridable for slow hosts. semgrep has
        // a ~30s fixed rule-load floor here; BB_SEMGREP_PY_CONFIG=.../python/lang/security
        // (security rules only — cai's framework rules don't apply) + the shared
        // BB_PY_SCAN_SUBDIR=src cut it to ~36s with ~76 real security findings.
        // Defaults = full pack, whole tree (Mac/CI unchanged).
        `$TO semgrep --config \${BB_SEMGREP_PY_CONFIG:-/opt/semgrep-rules/python} --config /opt/semgrep-rules-custom/semgrep-rules-py.yml ` +
        `--exclude '**/node_modules/**' --exclude '**/.venv/**' --exclude '**/dist/**' --exclude '**/build/**' --exclude '**/coverage/**' ` +
        `--json --output "$OUT" --metrics=off --timeout \${BB_SEMGREP_PY_TIMEOUT:-0} --max-memory 2000 --jobs ${jobsVal} \${BB_PY_SCAN_SUBDIR:-.}; ` +
        `rc=$?; ` +
        `if [ -f "$OUT" ]; then cat "$OUT"; fi; ` +
        `rm -f "$OUT" >/dev/null 2>&1 || true; ` +
        `exit $rc`,
    );
    semgrepPyRaw = res.stdout;
    onProgress?.(`pysub:semgrep:${_countSemgrep(semgrepPyRaw)}`);
    await _flush();

    if (res.status === 127) {
      errors.semgrepPy = "semgrep not installed";
    } else {
      // Semgrep commonly uses exit code 1 for findings; treat that as success if JSON parses.
      try {
        const trimmed = semgrepPyRaw.trim();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
          const parsed = JSON.parse(trimmed) as {
            errors?: unknown[];
            results?: unknown[];
          };
          const semgrepErrors = parsed.errors;
          if (Array.isArray(semgrepErrors) && semgrepErrors.length > 0) {
            errors.semgrepPy = `semgrep reported ${semgrepErrors.length} error(s)`;
          } else if (res.status !== 0) {
            const results = parsed.results;
            if (!Array.isArray(results) || results.length === 0) {
              errors.semgrepPy = `semgrep failed (exit ${res.status})${res.stderr ? `: ${res.stderr}` : ""}`;
            }
          }
        } else if (res.status !== 0) {
          errors.semgrepPy = `semgrep failed (exit ${res.status})${res.stderr ? `: ${res.stderr}` : ""}`;
        }
      } catch (e) {
        if (res.status !== 0) {
          errors.semgrepPy = `semgrep failed (exit ${res.status})${res.stderr ? `: ${res.stderr}` : ""}`;
        } else {
          errors.semgrepPy = e instanceof Error ? e.message : "Failed to parse semgrep JSON";
        }
      }
    }
  } catch (e) {
    errors.semgrepPy = e instanceof Error ? e.message : String(e);
  }

  // Python dead code detection (best-effort)
  let vultureRaw = "";
  try {
    const res = runBash(
      "vulture --version 2>/dev/null || true; vulture . --min-confidence 80",
    );
    vultureRaw = res.stdout;
    if (res.status === 127) {
      errors.vulture = "vulture not installed";
    } else if (res.status !== 0 && res.status !== 1) {
      errors.vulture = `vulture failed (exit ${res.status})${res.stderr ? `: ${res.stderr}` : ""}`;
    }
  } catch (e) {
    errors.vulture = e instanceof Error ? e.message : String(e);
  }

  // Python dependency vulnerability scan (best-effort)
  let safetyRaw = "";
  try {
    // Prefer scanning declared requirements files to avoid scanning container env
    const reqFiles = trackedFiles.filter((f) =>
      /(^|\/)requirements[^/]*\.txt$/i.test(f),
    );
    if (reqFiles.length > 0) {
      const outParts: string[] = [];
      for (const rel of reqFiles.slice(0, 25)) {
        try {
          const abs = path.resolve(absolutePath, rel);
          const out = runOfflineAdvisoryDbAudit(abs);
          outParts.push(`# ${rel}\n${out.raw}`);
          if (out.error) {
            errors.safety = out.error;
          }
        } catch (e) {
          const msg = e instanceof Error ? e.message : String(e);
          errors.safety = msg;
        }
      }
      safetyRaw = outParts.join("\n");
    } else {
      const uvLocks = trackedFiles.filter((f) => /(^|\/)uv\.lock$/i.test(f));
      const pyprojects = trackedFiles.filter((f) => /(^|\/)pyproject\.toml$/i.test(f));
      if (uvLocks.length > 0) {
        const maxUvLocksRaw = process.env.BB_SAFETY_MAX_UV_LOCKS || "5";
        const maxUvLocks = Number.parseInt(maxUvLocksRaw, 10);
        const limit = Number.isFinite(maxUvLocks) && maxUvLocks > 0 ? maxUvLocks : 5;

        const scored = uvLocks
          .slice()
          .sort((a, b) => {
            const score = (p: string): number => {
              if (p.includes("libs/core/")) return 0;
              if (p.includes("libs/langchain_v1/")) return 1;
              if (p.includes("libs/langchain/")) return 2;
              if (p.includes("libs/partners/openai/")) return 3;
              if (p.includes("libs/partners/anthropic/")) return 4;
              return 10;
            };
            return score(a) - score(b) || a.localeCompare(b);
          })
          .slice(0, limit);

        const outParts: string[] = [];
        for (const rel of scored) {
          let tmpReq: string | null = null;
          try {
            const absLock = path.resolve(absolutePath, rel);
            const lockContent = fs.readFileSync(absLock, "utf8");
            const converted = requirementsFromUvLock(lockContent);
            tmpReq = makeTmpPath("bb-uv-lock", "requirements.txt");
            fs.writeFileSync(tmpReq, converted.requirements, "utf8");

            const previewLines = converted.requirements
              .split("\n")
              .slice(0, 80)
              .join("\n");
            outParts.push(
              `# uv.lock: ${rel} packages=${converted.packageCount}\n# requirements_preview\n${previewLines}\n`,
            );

            const out = runOfflineAdvisoryDbAudit(tmpReq);
            outParts.push(`# offline_advisory_db: ${rel}\n${out.raw}`);
            if (out.error) {
              errors.safety = out.error;
            }
          } catch (e) {
            const msg = e instanceof Error ? e.message : String(e);
            outParts.push(`# advisory_db_error: ${rel}\n${msg}`);
            errors.safety = msg;
          } finally {
            if (tmpReq) {
              try {
                fs.unlinkSync(tmpReq);
              } catch {
                true;
              }
            }
          }
        }

        safetyRaw = outParts.join("\n");
        if (!errors.safety) errors.safety = null;
      } else if (pyprojects.length > 0) {
        errors.safety =
          "skipped: no requirements*.txt files found (uv/pyproject layout detected)";
        safetyRaw = `# skipped: requirements*.txt not found; uv.lock=${uvLocks.length} pyproject.toml=${pyprojects.length}`;
      } else {
        errors.safety = "skipped: no requirements*.txt files found";
        safetyRaw = "# skipped: requirements*.txt not found";
      }
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    errors.safety = msg;
  }

  return {
    complexityRaw,
    securityRaw,
    semgrepPyRaw,
    vultureRaw,
    safetyRaw,
    errors,
  };
}