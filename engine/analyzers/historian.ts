import * as fs from "node:fs/promises";
import * as path from "node:path";
import { run, parseHerculesOwnershipMinimal } from "./utils.js";

export interface HistorianResult {
  revertsByAuthor: { author: string; count: number }[];
  churnByFolder: { folder: string; count: number }[];
  staleCriticalPaths: { path: string; lastTouchedAt: string | null }[];
  busFactor: {
    byAuthor: { author: string; email: string | null; commits: number }[];
    totalCommits: number;
    top1Share: number;
    top2Share: number;
    top3Share: number;
    scope: "since" | "lifetime";
    hercules?: {
      ownershipByAuthor: { author: string; score: number; share: number }[];
    };
  } | null;
  sqlReverts: { author: string; count: number }[];
  gitShortlogRaw: string;
  gitShortlogLifetimeRaw: string;
  gitqliteRevertsRaw: string;
  herculesRaw: string;
  errors: {
    historianReverts: string | null;
    historianChurn: string | null;
    historianStale: string | null;
    historianBusFactor: string | null;
    historianSQL: string | null;
    historianHercules: string | null;
  };
}

/**
 * Perform a comprehensive historian analysis for a repository and return aggregated results.
 *
 * @param absolutePath - Absolute filesystem path to the git repository to analyze
 * @param churnRaw - Precomputed churn data as a newline-separated string of file paths
 * @param churnSince - Time range marker (e.g., "2 weeks ago") used to scope recent-activity queries
 * @returns The aggregated HistorianResult containing revert counts, top-churn folders, stale critical paths, bus factor (with optional Hercules ownership), SQL-derived reverts, raw tool outputs, and per-feature error messages
 */
export async function runHistorianAnalysis(
  absolutePath: string,
  churnRaw: string,
  churnSince: string,
): Promise<HistorianResult> {
  const errors: HistorianResult["errors"] = {
    historianReverts: null,
    historianChurn: null,
    historianStale: null,
    historianBusFactor: null,
    historianSQL: null,
    historianHercules: null,
  };

  let revertsByAuthor: { author: string; count: number }[] = [];
  let churnByFolder: { folder: string; count: number }[] = [];
  let staleCriticalPaths: { path: string; lastTouchedAt: string | null }[] = [];
  let busFactor: HistorianResult["busFactor"] = null;
  let sqlReverts: { author: string; count: number }[] = [];
  let gitShortlogRaw = "";
  let gitShortlogLifetimeRaw = "";
  let gitqliteRevertsRaw = "";
  let herculesRaw = "";

  // Reverts by author (last N days)
  try {
    const logLines = run(
      "git",
      [
        "-C",
        absolutePath,
        "log",
        `--since=${churnSince}`,
        "--pretty=format:%an\t%s",
      ],
      absolutePath,
    )
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    const counts: Record<string, number> = {};
    for (const l of logLines) {
      const idx = l.indexOf("\t");
      if (idx <= 0) continue;
      const author = l.substring(0, idx);
      const subject = l.substring(idx + 1);
      if (/revert/i.test(subject)) {
        counts[author] = (counts[author] ?? 0) + 1;
      }
    }
    revertsByAuthor = Object.entries(counts)
      .map(([author, count]) => ({ author, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 20);
  } catch (e) {
    errors.historianReverts = e instanceof Error ? e.message : String(e);
  }

  // Churn by top-level folder
  try {
    const lines = churnRaw
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean)
      .filter((p) => !(p === ".git" || p.startsWith(".git/")));
    const skip = /(^|\/)node_modules\//;
    const skip2 = /(^|\/)(dist|build|coverage)\//;
    const folderCounts: Record<string, number> = {};
    for (const p of lines) {
      if (skip.test(p) || skip2.test(p)) continue;
      const seg = p.split("/")[0] || ".";
      folderCounts[seg] = (folderCounts[seg] ?? 0) + 1;
    }
    churnByFolder = Object.entries(folderCounts)
      .map(([folder, count]) => ({ folder, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 25);
  } catch (e) {
    errors.historianChurn = e instanceof Error ? e.message : String(e);
  }

  // Stale critical paths
  try {
    const allPaths = run(
      "git",
      ["-C", absolutePath, "ls-tree", "-r", "--name-only", "HEAD"],
      absolutePath,
    )
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    const candidates = Array.from(
      new Set(
        allPaths
          .filter((p) => /(^|\/)(auth|db|database)\//i.test(p))
          .map((p) => {
            const segs = p.split("/");
            return segs.length >= 2 ? `${segs[0]}/${segs[1]}` : p;
          }),
      ),
    ).slice(0, 50);
    const stale: { path: string; lastTouchedAt: string | null }[] = [];
    for (const rel of candidates) {
      try {
        const hasRecent = run(
          "git",
          [
            "-C",
            absolutePath,
            "log",
            `--since=${churnSince}`,
            "--pretty=format:%H",
            "--",
            rel,
          ],
          absolutePath,
        )
          .split("\n")[0]
          .trim();
        if (!hasRecent) {
          let ts: string | null = null;
          try {
            ts = run(
              "git",
              ["-C", absolutePath, "log", "-1", "--format=%cI", "--", rel],
              absolutePath,
            )
              .split("\n")[0]
              .trim();
            if (!ts) ts = null;
          } catch {
            ts = null;
          }
          stale.push({ path: rel, lastTouchedAt: ts });
        }
      } catch {
        // ignore path-level errors
      }
    }
    staleCriticalPaths = stale.slice(0, 50);
  } catch (e) {
    errors.historianStale = e instanceof Error ? e.message : String(e);
  }

  // Bus factor (shortlog within window)
  try {
    gitShortlogRaw = run(
      "git",
      [
        "-C",
        absolutePath,
        "--no-pager",
        "shortlog",
        "-sne",
        `--since=${churnSince}`,
      ],
      absolutePath,
    );
    const lines = gitShortlogRaw
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    const entries: {
      author: string;
      email: string | null;
      commits: number;
    }[] = [];
    let total = 0;
    const re = /^\s*(\d+)\s+(.+?)(?:\s+<([^>]+)>)?$/;
    for (const line of lines) {
      const m = line.match(re);
      if (!m) continue;
      const commits = parseInt(m[1] ?? "0", 10);
      if (!Number.isFinite(commits)) continue;
      const name = (m[2] ?? "").trim();
      const email = (m[3] ?? null) as string | null;
      if (!name) continue;
      entries.push({ author: name, email, commits });
      total += commits;
    }
    if (!total) {
      try {
        const windowLogRaw = run(
          "git",
          [
            "-C",
            absolutePath,
            "--no-pager",
            "log",
            `--since=${churnSince}`,
            "--format=%an <%ae>",
          ],
          absolutePath,
        );
        const counts: Record<
          string,
          { author: string; email: string | null; commits: number }
        > = {};
        for (const line of windowLogRaw.split("\n")) {
          const s = line.trim();
          if (!s) continue;
          const m = s.match(/^(.*?)(?:\s+<([^>]+)>)?$/);
          if (!m) continue;
          const name = (m[1] ?? "").trim();
          const email = (m[2] ?? null) as string | null;
          if (!name) continue;
          const key = (email && email.toLowerCase()) || name.toLowerCase();
          if (!counts[key]) counts[key] = { author: name, email, commits: 0 };
          counts[key].commits += 1;
        }
        const agg = Object.values(counts).sort((a, b) => b.commits - a.commits);
        if (agg.length) {
          entries.length = 0;
          for (const it of agg) entries.push(it);
          total = agg.reduce((acc, it) => acc + it.commits, 0);
        }
      } catch {
        // ignore fallback errors
      }
    }
    entries.sort((a, b) => b.commits - a.commits);
    const top1 = entries[0]?.commits ?? 0;
    const top2 = entries[1]?.commits ?? 0;
    const top3 = entries[2]?.commits ?? 0;
    const denom = total > 0 ? total : 1;
    busFactor = {
      byAuthor: entries.slice(0, 20),
      totalCommits: total,
      top1Share: Math.round((top1 / denom) * 10000) / 10000,
      top2Share: Math.round(((top1 + top2) / denom) * 10000) / 10000,
      top3Share: Math.round(((top1 + top2 + top3) / denom) * 10000) / 10000,
      scope: "since",
    };
    if (!total) {
      try {
        gitShortlogLifetimeRaw = run(
          "git",
          ["-C", absolutePath, "--no-pager", "shortlog", "-sne"],
          absolutePath,
        );
        const linesL = gitShortlogLifetimeRaw
          .split("\n")
          .map((s) => s.trim())
          .filter(Boolean);
        const entriesL: {
          author: string;
          email: string | null;
          commits: number;
        }[] = [];
        let totalL = 0;
        for (const line of linesL) {
          const mL = line.match(re);
          if (!mL) continue;
          const commits = parseInt(mL[1] ?? "0", 10);
          if (!Number.isFinite(commits)) continue;
          const name = (mL[2] ?? "").trim();
          const email = (mL[3] ?? null) as string | null;
          if (!name) continue;
          entriesL.push({ author: name, email, commits });
          totalL += commits;
        }
        if (!totalL) {
          try {
            const lifetimeLogRaw = run(
              "git",
              ["-C", absolutePath, "--no-pager", "log", "--format=%an <%ae>"],
              absolutePath,
            );
            const countsL: Record<
              string,
              { author: string; email: string | null; commits: number }
            > = {};
            for (const line of lifetimeLogRaw.split("\n")) {
              const s = line.trim();
              if (!s) continue;
              const m = s.match(/^(.*?)(?:\s+<([^>]+)>)?$/);
              if (!m) continue;
              const name = (m[1] ?? "").trim();
              const email = (m[2] ?? null) as string | null;
              if (!name) continue;
              const key = (email && email.toLowerCase()) || name.toLowerCase();
              if (!countsL[key])
                countsL[key] = { author: name, email, commits: 0 };
              countsL[key].commits += 1;
            }
            const aggL = Object.values(countsL).sort(
              (a, b) => b.commits - a.commits,
            );
            if (aggL.length) {
              entriesL.length = 0;
              for (const it of aggL) entriesL.push(it);
              totalL = aggL.reduce((acc, it) => acc + it.commits, 0);
            }
          } catch {
            // ignore lifetime log fallback errors
          }
        }
        entriesL.sort((a, b) => b.commits - a.commits);
        const t1 = entriesL[0]?.commits ?? 0;
        const t2 = entriesL[1]?.commits ?? 0;
        const t3 = entriesL[2]?.commits ?? 0;
        const d = totalL > 0 ? totalL : 1;
        busFactor = {
          byAuthor: entriesL.slice(0, 20),
          totalCommits: totalL,
          top1Share: Math.round((t1 / d) * 10000) / 10000,
          top2Share: Math.round(((t1 + t2) / d) * 10000) / 10000,
          top3Share: Math.round(((t1 + t2 + t3) / d) * 10000) / 10000,
          scope: "lifetime",
        };
      } catch (e) {
        if (!errors.historianBusFactor) {
          errors.historianBusFactor =
            e instanceof Error ? e.message : String(e);
        }
      }
    }
  } catch (e) {
    errors.historianBusFactor = e instanceof Error ? e.message : String(e);
  }

  // Gitqlite SQL queries
  try {
    let query = "";
    try {
      const sqlLib = await fs.readFile(
        path.join("/opt/engine", "historian", "queries.sql"),
        "utf8",
      );
      const m = sqlLib.match(
        /--\s*name:\s*reverts_by_author[\s\S]*?\n([\s\S]*?);/i,
      );
      if (m && m[1]) {
        query = m[1].trim();
      }
    } catch {
      // ignore missing SQL lib
    }
    if (query) {
      const qEsc = query.replace(/'/g, "'\\''");
      try {
        gitqliteRevertsRaw = run(
          "bash",
          [
            "-lc",
            `gitqlite -f json '${qEsc}' 2>/dev/null || gitqlite --format json '${qEsc}' 2>/dev/null || true`,
          ],
          absolutePath,
        );
      } catch {
        // ignore command errors
      }
      try {
        const trimmed = gitqliteRevertsRaw.trim();
        if (trimmed) {
          const parsed: unknown = JSON.parse(trimmed);
          if (Array.isArray(parsed)) {
            const arr = parsed as Array<Record<string, unknown>>;
            sqlReverts = arr
              .map((r) => ({
                author: String(
                  r["author"] ??
                    r["AUTHOR"] ??
                    r["Author"] ??
                    r["author_name"] ??
                    "",
                ),
                count: Number(r["count"] ?? r["COUNT"] ?? r["c"] ?? 0),
              }))
              .filter((r) => r.author && Number.isFinite(r.count));
          } else if (parsed && typeof parsed === "object") {
            const obj = parsed as { rows?: unknown; columns?: unknown };
            if (Array.isArray(obj.rows) && Array.isArray(obj.columns)) {
              const rows = obj.rows as Array<unknown[]>;
              const cols = obj.columns as Array<unknown>;
              const ai = cols.findIndex((c) => /author/i.test(String(c)));
              const ci = cols.findIndex((c) => /count/i.test(String(c)));
              if (ai >= 0 && ci >= 0) {
                sqlReverts = rows
                  .map((row) => ({
                    author: String((row as Array<unknown>)[ai] ?? ""),
                    count: Number((row as Array<unknown>)[ci] ?? 0),
                  }))
                  .filter((r) => r.author && Number.isFinite(r.count));
              }
            }
          }
        }
      } catch (e) {
        errors.historianSQL = e instanceof Error ? e.message : String(e);
      }
    }
  } catch (e) {
    errors.historianSQL = e instanceof Error ? e.message : String(e);
  }

  // Hercules burndown/ownership
  try {
    // Emit per-developer ownership JSON from hercules v10 + labours
    // (installed in an isolated venv, symlinked onto PATH). The prior command
    // used stale flags (`-t HEAD --granularity files`, `labours -format json`)
    // that don't exist in the installed versions, so this analysis silently
    // produced nothing for months and historian fell back to the commit-count
    // proxy below. Correct invocation for the installed tools:
    //   hercules --burndown --burndown-people --pb .   → per-developer protobuf
    //   labours -m ownership -f pb -i <pb> -o <dir>/own.json → ownership JSON
    // labours writes either <dir>/own.json or (via its get_plot_path filename
    // transform) <dir>/own/<name>.json, so we cat both. The JSON carries a
    // `people` key + aligned numeric vectors that parseHerculesOwnershipMinimal
    // aggregates into ownershipByAuthor. If hercules/labours are absent, error,
    // or time out, this prints nothing and the commit-count fallback applies —
    // no regression versus prior behavior.
    const cmd = [
      "-lc",
      [
        "command -v hercules >/dev/null 2>&1 && command -v labours >/dev/null 2>&1 || exit 0; ",
        // Hercules burndown over full history is the analyze long pole. The
        // wall-clock cap is env-overridable (BB_HERCULES_TIMEOUT_S) so a live
        // demo can bound it (e.g. 45s) while the default stays 300s for full
        // audits. On timeout `$TO` kills hercules, `bd.pb` is empty/absent, and
        // the commit-count fallback applies — no regression versus prior behavior.
        // `-k 5 -s TERM`: send SIGTERM at the cap, then escalate to SIGKILL 5s
        // later if Hercules ignores it — so a timed-out burndown can't linger as
        // a process holding the container's stdout pipe open (which, under host
        // load, can stall the container's exit past the outer docker timeout and
        // trigger a spurious full-sweep re-run). On kill, `bd.pb` is empty so the
        // labours step is skipped and the commit-count fallback applies.
        "TO=; command -v timeout >/dev/null 2>&1 && TO=\"timeout -k 5 -s TERM ${BB_HERCULES_TIMEOUT_S:-300}\"; ",
        "D=$(mktemp -d 2>/dev/null || echo /tmp/herc.$$); ",
        '$TO hercules --burndown --burndown-people --pb . > "$D/bd.pb" 2>/dev/null; ',
        'if [ -s "$D/bd.pb" ]; then ',
        '  MPLBACKEND=Agg $TO labours -m ownership -f pb -i "$D/bd.pb" -o "$D/own.json" >/dev/null 2>&1; ',
        '  cat "$D/own.json" 2>/dev/null || cat "$D"/own/*.json 2>/dev/null || true; ',
        "fi; ",
        'rm -rf "$D" >/dev/null 2>&1',
      ].join(""),
    ];
    herculesRaw = run("bash", cmd, absolutePath);
  } catch (e) {
    errors.historianHercules = e instanceof Error ? e.message : String(e);
  }

  // Parse Hercules JSON if present
  try {
    const hTrim = herculesRaw.trim();
    if (hTrim && (hTrim.startsWith("{") || hTrim.startsWith("["))) {
      const hSum = parseHerculesOwnershipMinimal(hTrim);
      if (hSum && busFactor) {
        busFactor = { ...busFactor, hercules: hSum };
      }
    }
  } catch (e) {
    if (!errors.historianHercules) {
      errors.historianHercules = e instanceof Error ? e.message : String(e);
    }
  }

  // Fallback hercules from commit counts
  if (busFactor && !busFactor.hercules) {
    const totalCommitsFallback = busFactor.byAuthor.reduce(
      (s, a) => s + (a.commits || 0),
      0,
    );
    if (totalCommitsFallback > 0) {
      const ownershipByAuthor = busFactor.byAuthor.slice(0, 20).map((a) => ({
        author: a.author,
        score: a.commits,
        share: Math.round((a.commits / totalCommitsFallback) * 10000) / 10000,
      }));
      busFactor = {
        ...busFactor,
        hercules: { ownershipByAuthor },
      };
    }
  }

  return {
    revertsByAuthor,
    churnByFolder,
    staleCriticalPaths,
    busFactor,
    sqlReverts,
    gitShortlogRaw,
    gitShortlogLifetimeRaw,
    gitqliteRevertsRaw,
    herculesRaw,
    errors,
  };
}