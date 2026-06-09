# Third-Party Notices

`find-your-kill-zone` itself is licensed Apache-2.0 (see `LICENSE`). It contains
**no third-party source code**. The static-analysis toolchain it orchestrates is
**fetched at `docker build` time** into the container image (`pip install`,
`npm install -g`, `go install`, `git clone` — see `infrastructure/Dockerfile`),
not committed to this repository.

**What this means for licensing:**
- Distributing *this source repo* (a Dockerfile recipe + Black Box's own code)
  carries no obligation from the tools below — they aren't here.
- Building the image fetches the tools onto **your** machine; the licenses below
  govern *your* build and any image **you** redistribute.
- ⚠️ **If you publish a prebuilt image** (e.g. push to a registry), you become a
  redistributor of these binaries — including the **GPL-3.0** and **LGPL-2.1**
  components — and must then carry their license texts / source offers. Keeping
  distribution source-only (Dockerfile, not image) keeps that dormant.

Licenses are as of the versions pinned in `infrastructure/Dockerfile`; verify
against upstream before relying on them.

## Copyleft components (note these specifically)

| Tool | Version | License | Role |
|---|---|---|---|
| hercules | v10.7.0 | **GPL-3.0** | historian: bus-factor / burndown |
| semgrep | 1.40.0 | **LGPL-2.1** | python/js/go security scan |
| semgrep-rules (pack) | pinned commit | **LGPL-2.1** | vendored offline rule pack |

Invoked as separate executables across a process/container boundary (mere
aggregation) — they do not relicense this tool's Apache-2.0 code.

### Base-image / apt-layer copyleft tools

Installed via `apt-get install` in `infrastructure/Dockerfile`. Invoked (or
not) as separate executables; mere aggregation, no relicensing.

| Tool | License | Role |
|---|---|---|
| git | **GPL-2.0** | runtime-invoked for churn / clone |
| wget | **GPL-3.0** | build-time fetch of vendored tools |
| cloc | **GPL-2.0** | line-counting utility (not runtime-invoked) |
| tree | **GPL-2.0-or-later** | directory listing utility |
| pkg-config | **GPL-2.0-or-later** | build-time: gitqlite libgit2 build |

## Permissive components

| Tool | Version | License |
|---|---|---|
| bandit | 1.7.5 | Apache-2.0 |
| pbr | 7.0.3 | Apache-2.0 |
| radon | 6.0.1 | MIT |
| safety | 3.7.0 | MIT |
| pip-audit | 2.7.3 | Apache-2.0 |
| detect-secrets | 1.4.0 | Apache-2.0 |
| vulture | 2.7 | MIT |
| PyYAML | 6.0.1 | MIT |
| gosec | v2.19.0 | Apache-2.0 |
| gocyclo | v0.6.0 | MIT |
| labours | 10.7.2 | Apache-2.0 (package metadata; parent hercules project is GPL-3.0) |
| golang-go | (base image) | BSD-3-Clause |
| jq | (base image) | MIT |
| mergestat-lite (gitqlite) | v0.6.2 | MIT |
| eslint | 8.57.1 | MIT |
| @typescript-eslint/parser | 8.46.1 | MIT |
| jscpd | 4.0.7 | MIT |
| depcheck | 1.4.7 | MIT |
| retire | 5.4.2 | Apache-2.0 |
| madge | 8.0.0 | MIT |
| knip | 5.82.1 | ISC |
| ts-prune | 0.10.3 | MIT |
| type-coverage | 2.29.7 | MIT |
| license-checker | 25.0.1 | BSD-3-Clause |
| dependency-cruiser | 17.3.7 | MIT |
| ts-node | 10.9.2 | MIT |
| typescript | 5.9.3 | Apache-2.0 |
| pypa/advisory-database | pinned commit | CC0-1.0 / mixed |
| base image (python-nodejs / Debian) | pinned digest | various (Debian/PSF/MIT) |

### Transitive Python deps (labours venv)

`pip install`ed into the isolated labours venv at `infrastructure/Dockerfile`
(the exact, wheel-only pin set). All permissive / weak-copyleft.

| Tool | Version | License |
|---|---|---|
| numpy | 1.24.4 | BSD-3-Clause |
| pandas | 1.5.3 | BSD-3-Clause |
| scipy | 1.10.1 | BSD-3-Clause |
| protobuf | 3.20.3 | BSD-3-Clause |
| matplotlib | 3.7.5 | PSF-style (matplotlib license) |
| lifelines | 0.27.8 | MIT |
| munch | 4.0.0 | MIT |
| python-dateutil | 2.9.0.post0 | Apache-2.0 / BSD-3-Clause |
| tqdm | 4.67.1 | MPL-2.0 + MIT |

To regenerate the JS portion precisely, the image already vendors
`license-checker` — run it against `/opt/node_modules` inside the container.
