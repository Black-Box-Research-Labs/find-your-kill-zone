/**
 * R-005 Schema Validator
 *
 * Validates that analyze.ts output structure matches the expected schema.
 * Used for regression testing during the R-005 decomposition refactor.
 */

export interface AnalysisOutput {
  path: string;
  complexity: {
    highComplexityFileCount: number;
  };
  security: {
    highFindingCount: number;
  };
  js: {
    duplication: { raw: string };
    deps: {
      raw: string;
      byPackage: Record<string, { raw: string; error: string | null }>;
    };
    security: {
      raw: string;
      retireByPackage: Record<string, { raw: string; error: string | null }>;
    };
    modules: { raw: string };
    semgrep: { raw: string };
    complexity: { raw: string };
    knip: { raw: string };
    tsPrune: { raw: string };
    licenses: { raw: string };
    dependencyCruiser: { raw: string };
    typeCoverage: { raw: string };
  };
  py: {
    semgrep: { raw: string };
    vulture: { raw: string };
    safety: { raw: string };
    complexity: { raw: string };
    security: { raw: string };
  };
  go: {
    semgrep: { raw: string };
    security: { raw: string };
    complexity: { raw: string };
  };
  coverage: {
    files: string[];
    covered: number;
    total: number;
    percent: number;
  } | null;
  secrets: {
    detectSecrets: { raw: string };
  };
  hotspots: {
    highChurnFiles: Array<{ file: string; count: number }>;
    churn?: {
      sinceRequested: string;
      sinceEffective: string;
      selectionMode: "strict" | "expanded" | "fallback";
      minCount: number;
      maxCandidates: number;
      commitCount: number;
      fileTouchLines: number;
      uniqueFiles: number;
      maxCount: number;
    };
  };
  historian: {
    revertsByAuthor: Array<{ author: string; count: number }>;
    churnByFolder: Array<{ folder: string; count: number }>;
    staleCriticalPaths: Array<{ path: string; lastTouchedAt: string | null }>;
    busFactor: {
      byAuthor: Array<{
        author: string;
        email: string | null;
        commits: number;
      }>;
      totalCommits: number;
      top1Share: number;
      top2Share: number;
      top3Share: number;
      scope: "since" | "lifetime";
      hercules?: {
        ownershipByAuthor: Array<{
          author: string;
          score: number;
          share: number;
        }>;
      };
    } | null;
    sql: {
      revertsByAuthor: Array<{ author: string; count: number }>;
    };
  };
  churn: {
    since: string;
    sinceRequested?: string;
  };
  raw: {
    radon: string;
    bandit: string;
    gitChurn: string;
    jscpd: string;
    depcheck: string;
    retire: string;
    madge: string;
    semgrep: string;
    semgrepPy: string;
    semgrepGo: string;
    complexityJs: string;
    knip: string;
    tsPrune: string;
    licenseChecker: string;
    dependencyCruiser: string;
    typeCoverage: string;
    detectSecrets: string;
    vulture: string;
    safety: string;
    gosec: string;
    gocyclo: string;
    gitShortlog: string;
    gitShortlogLifetime: string;
    gitqliteReverts: string;
    hercules: string;
  };
  errors: Record<string, string | null>;
}

const REQUIRED_TOP_LEVEL_KEYS = [
  "path",
  "complexity",
  "security",
  "js",
  "py",
  "go",
  "coverage",
  "secrets",
  "hotspots",
  "historian",
  "churn",
  "raw",
  "errors",
] as const;

/**
 * Validate the structure of an analysis output object against the expected schema.
 *
 * @param output - The analysis output to validate
 * @returns An array of validation error messages; empty if the output conforms to the schema
 */
export function validateAnalysisSchema(output: unknown): string[] {
  const errors: string[] = [];

  if (!output || typeof output !== "object") {
    errors.push("Output is not an object");
    return errors;
  }

  const obj = output as Record<string, unknown>;

  const isPlainObject = (v: unknown): v is Record<string, unknown> =>
    Boolean(v) && typeof v === "object" && !Array.isArray(v);

  // Check required top-level keys
  for (const key of REQUIRED_TOP_LEVEL_KEYS) {
    if (!(key in obj)) {
      errors.push(`Missing required top-level key: ${key}`);
    }
  }

  if ("path" in obj && typeof obj.path !== "string") {
    errors.push("path must be a string");
  }

  // Check complexity structure
  if ("complexity" in obj) {
    if (!isPlainObject(obj.complexity)) {
      errors.push("complexity must be an object");
    } else {
      const c = obj.complexity;
      if (typeof c.highComplexityFileCount !== "number") {
        errors.push("complexity.highComplexityFileCount must be a number");
      }
    }
  }

  // Check security structure
  if ("security" in obj) {
    if (!isPlainObject(obj.security)) {
      errors.push("security must be an object");
    } else {
      const s = obj.security;
      if (typeof s.highFindingCount !== "number") {
        errors.push("security.highFindingCount must be a number");
      }
    }
  }

  if ("coverage" in obj) {
    if (obj.coverage !== null && !isPlainObject(obj.coverage)) {
      errors.push("coverage must be an object or null");
    } else if (isPlainObject(obj.coverage)) {
      const cov = obj.coverage;
      if (!Array.isArray(cov.files)) {
        errors.push("coverage.files must be an array");
      }
      if (typeof cov.covered !== "number") {
        errors.push("coverage.covered must be a number");
      }
      if (typeof cov.total !== "number") {
        errors.push("coverage.total must be a number");
      }
      if (typeof cov.percent !== "number") {
        errors.push("coverage.percent must be a number");
      }
    }
  }

  if ("secrets" in obj) {
    if (!isPlainObject(obj.secrets)) {
      errors.push("secrets must be an object");
    } else {
      const secrets = obj.secrets;
      if (!isPlainObject(secrets.detectSecrets)) {
        errors.push("secrets.detectSecrets must be an object");
      } else if (typeof secrets.detectSecrets.raw !== "string") {
        errors.push("secrets.detectSecrets.raw must be a string");
      }
    }
  }

  if ("hotspots" in obj) {
    if (!isPlainObject(obj.hotspots)) {
      errors.push("hotspots must be an object");
    } else {
      const hotspots = obj.hotspots;
      if (!Array.isArray(hotspots.highChurnFiles)) {
        errors.push("hotspots.highChurnFiles must be an array");
      }

      if ("churn" in hotspots && hotspots.churn !== undefined) {
        if (!isPlainObject(hotspots.churn)) {
          errors.push("hotspots.churn must be an object");
        } else {
          const churn = hotspots.churn;
          if (typeof churn.sinceRequested !== "string") {
            errors.push("hotspots.churn.sinceRequested must be a string");
          }
          if (typeof churn.sinceEffective !== "string") {
            errors.push("hotspots.churn.sinceEffective must be a string");
          }
          if (
            churn.selectionMode !== "strict" &&
            churn.selectionMode !== "expanded" &&
            churn.selectionMode !== "fallback"
          ) {
            errors.push(
              "hotspots.churn.selectionMode must be one of strict|expanded|fallback",
            );
          }
          const numericKeys = [
            "minCount",
            "maxCandidates",
            "commitCount",
            "fileTouchLines",
            "uniqueFiles",
            "maxCount",
          ] as const;
          for (const key of numericKeys) {
            if (typeof churn[key] !== "number") {
              errors.push(`hotspots.churn.${key} must be a number`);
            }
          }
        }
      }
    }
  }

  if ("churn" in obj) {
    if (!isPlainObject(obj.churn)) {
      errors.push("churn must be an object");
    } else {
      const churn = obj.churn;
      if (typeof churn.since !== "string") {
        errors.push("churn.since must be a string");
      }
      if ("sinceRequested" in churn && churn.sinceRequested !== undefined) {
        if (typeof churn.sinceRequested !== "string") {
          errors.push("churn.sinceRequested must be a string");
        }
      }
    }
  }

  if ("errors" in obj) {
    if (!isPlainObject(obj.errors)) {
      errors.push("errors must be an object");
    } else {
      for (const [k, v] of Object.entries(obj.errors)) {
        if (v !== null && typeof v !== "string") {
          errors.push(`errors.${k} must be a string or null`);
        }
      }
    }
  }

  // Check js structure has expected nested keys
  if ("js" in obj) {
    if (!isPlainObject(obj.js)) {
      errors.push("js must be an object");
    } else {
      const js = obj.js;
      const jsKeys = [
        "duplication",
        "deps",
        "security",
        "modules",
        "semgrep",
        "complexity",
        "knip",
        "tsPrune",
        "licenses",
        "dependencyCruiser",
        "typeCoverage",
      ];
      for (const k of jsKeys) {
        if (!(k in js)) {
          errors.push(`Missing js.${k}`);
        }
      }
    }
  }

  // Check py structure
  if ("py" in obj) {
    if (!isPlainObject(obj.py)) {
      errors.push("py must be an object");
    } else {
      const py = obj.py;
      const pyKeys = ["semgrep", "vulture", "safety", "complexity", "security"];
      for (const k of pyKeys) {
        if (!(k in py)) {
          errors.push(`Missing py.${k}`);
        }
      }
    }
  }

  // Check go structure
  if ("go" in obj) {
    if (!isPlainObject(obj.go)) {
      errors.push("go must be an object");
    } else {
      const go = obj.go;
      const goKeys = ["semgrep", "security", "complexity"];
      for (const k of goKeys) {
        if (!(k in go)) {
          errors.push(`Missing go.${k}`);
        }
      }
    }
  }

  // Check historian structure
  if ("historian" in obj) {
    if (!isPlainObject(obj.historian)) {
      errors.push("historian must be an object");
    } else {
      const h = obj.historian;
      const hKeys = [
        "revertsByAuthor",
        "churnByFolder",
        "staleCriticalPaths",
        "busFactor",
        "sql",
      ];
      for (const k of hKeys) {
        if (!(k in h)) {
          errors.push(`Missing historian.${k}`);
        }
      }
    }
  }

  // Check raw structure has all expected keys
  if ("raw" in obj) {
    if (!isPlainObject(obj.raw)) {
      errors.push("raw must be an object");
    } else {
      const raw = obj.raw;
      const rawKeys = [
        "radon",
        "bandit",
        "gitChurn",
        "jscpd",
        "depcheck",
        "retire",
        "madge",
        "semgrep",
        "semgrepPy",
        "semgrepGo",
        "complexityJs",
        "knip",
        "tsPrune",
        "licenseChecker",
        "dependencyCruiser",
        "typeCoverage",
        "detectSecrets",
        "vulture",
        "safety",
        "gosec",
        "gocyclo",
        "gitShortlog",
        "gitShortlogLifetime",
        "gitqliteReverts",
        "hercules",
      ];
      for (const k of rawKeys) {
        if (!(k in raw)) {
          errors.push(`Missing raw.${k}`);
        }
      }
    }
  }

  return errors;
}

/**
 * Identify structural differences between two analysis outputs.
 *
 * Compares the baseline and current objects and reports dot-separated paths that were added, removed, or changed.
 *
 * @param baseline - The reference analysis output to compare against
 * @param current - The new analysis output to compare
 * @returns An object with three arrays:
 *  - `added`: paths present in `current` but not in `baseline`
 *  - `removed`: paths present in `baseline` but not in `current`
 *  - `changed`: paths present in both whose values differ (arrays and non-object values are compared by value)
 */
export function compareAnalysisOutputs(
  baseline: unknown,
  current: unknown,
): { added: string[]; removed: string[]; changed: string[] } {
  const result = {
    added: [] as string[],
    removed: [] as string[],
    changed: [] as string[],
  };

  /**
   * Retrieve a nested value from an object using a dot-separated path.
   *
   * @param obj - The object to traverse
   * @param path - Dot-separated key path (e.g. "a.b.c")
   * @returns The value at `path`, or `undefined` if the path does not exist or cannot be traversed (including when an array or non-object is encountered)
   */
  function getValueAtPath(obj: unknown, path: string): unknown {
    const parts = path.split(".");
    let cur: unknown = obj;
    for (const part of parts) {
      if (!cur || typeof cur !== "object" || Array.isArray(cur))
        return undefined;
      cur = (cur as Record<string, unknown>)[part];
    }
    return cur;
  }

  /**
   * Collects all nested object property paths as dot-separated strings.
   *
   * Traverses plain objects recursively and returns each property encountered as a dot-separated path; arrays and non-objects are not traversed.
   *
   * @param obj - The root value to extract keys from; only plain (non-null, non-array) objects are inspected.
   * @param prefix - Optional prefix to prepend to each key when building dot-separated paths.
   * @returns An array of dot-separated property paths found within `obj`.
   */
  function getKeys(obj: unknown, prefix = ""): string[] {
    const keys: string[] = [];
    if (obj && typeof obj === "object" && !Array.isArray(obj)) {
      for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
        const path = prefix ? `${prefix}.${k}` : k;
        keys.push(path);
        if (v && typeof v === "object" && !Array.isArray(v)) {
          keys.push(...getKeys(v, path));
        }
      }
    }
    return keys;
  }

  const baselineKeys = new Set(getKeys(baseline));
  const currentKeys = new Set(getKeys(current));

  for (const k of Array.from(currentKeys)) {
    if (!baselineKeys.has(k)) {
      result.added.push(k);
    }
  }

  for (const k of Array.from(baselineKeys)) {
    if (!currentKeys.has(k)) {
      result.removed.push(k);
    }
  }

  for (const k of Array.from(currentKeys)) {
    if (!baselineKeys.has(k)) continue;
    const a = getValueAtPath(baseline, k);
    const b = getValueAtPath(current, k);

    const aIsObject = a !== null && typeof a === "object";
    const bIsObject = b !== null && typeof b === "object";

    if (Array.isArray(a) || Array.isArray(b) || !aIsObject || !bIsObject) {
      if (JSON.stringify(a) !== JSON.stringify(b)) {
        result.changed.push(k);
      }
    }
  }

  return result;
}