# BASE: Debian Bookworm Slim with Python 3.11 and Node.js 20 pre-installed
# This resolves the "Dependency Ghosting" risk identified in V3.
FROM nikolaik/python-nodejs:python3.11-nodejs20-slim@sha256:cf1161bbb517ad4d119c038d9ab3d38eb1c44bd712ea0fc7045ec2d12e2d105f

# 1. SYSTEM DEPENDENCIES
# git: Required for churn analysis in analyze.ts
# cloc: line-counting utility (radon produces the LOC metric; cloc is not
#       runtime-invoked by the engine)
# jq: JSON processing utility for shell-level verification
RUN apt-get update && apt-get install -y \
    git \
    cloc \
    tree \
    jq \
    ca-certificates \
    wget \
    unzip \
    golang-go \
    cmake \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*
# cmake/pkg-config/libssl-dev: required to build mergestat-lite's static
# libgit2 (gitqlite successor — see §2e).

# 2. FORENSIC TOOLCHAIN (Python)
# These must be baked in; the container has NO INTERNET at runtime.
RUN pip install --no-cache-dir \
    bandit==1.7.5 \
    pbr==7.0.3 \
    radon==6.0.1 \
    semgrep==1.40.0 \
    safety==3.7.0 \
    pip-audit==2.7.3 \
    PyYAML==6.0.1 \
    detect-secrets==1.4.0 \
    vulture==2.7

# 2b. FORENSIC TOOLCHAIN (Node.js)
# These JS/TS tools enable offline static analysis without network at runtime.
RUN npm install -g \
    jscpd@4.0.7 \
    depcheck@1.4.7 \
    retire@5.4.2 \
    madge@8.0.0 \
    eslint@8.57.1 \
    @typescript-eslint/parser@8.46.1 \
    knip@5.82.1 \
    ts-prune@0.10.3 \
    type-coverage@2.29.7 \
    license-checker@25.0.1 \
    dependency-cruiser@17.3.7 \
    ts-node@10.9.2 \
    typescript@5.9.3

# 2d. FORENSIC TOOLCHAIN (Go)
# Install Go-native analyzers at build time (air-gapped at runtime)
ENV GOPROXY=https://proxy.golang.org,direct
RUN GOBIN=/usr/local/bin go install github.com/fzipp/gocyclo/cmd/gocyclo@v0.6.0 \
 && GOBIN=/usr/local/bin go install github.com/securego/gosec/v2/cmd/gosec@v2.19.0

# 2e. Build gitqlite from mergestat-lite source.
# The legacy `mergestat/gitqlite` repo was DELETED upstream (codeload 404) and
# renamed to `mergestat-lite`; the old best-effort build silently no-op'd for
# months (empty raw.gitqliteReverts → Rule 16 revert-instability starved). No
# linux-arm64 prebuilt binary is published, so we build from source: a static
# libgit2 (via the bundled git2go submodule — hence the `--recursive` clone and
# the cmake/libssl build deps above) + the sqlite amalgamation. The binary's
# CLI (`-f json` + the `commits` virtual table) is drop-in compatible with how
# historian.ts invokes `gitqlite`, so we install it AS `gitqlite` (no analyzer
# change). The `--allow-multiple-definition` linker flag resolves the duplicate
# sqlite symbols between the amalgamation and mattn/go-sqlite3 under modern ld.
RUN (git clone --recursive --depth 1 -b v0.6.2 https://github.com/mergestat/mergestat-lite /opt/ms \
 && cd /opt/ms \
 && make pkg/sqlite/sqlite3.c \
 && make libgit2 \
 && CGO_CFLAGS="-DUSE_LIBSQLITE3" \
    CPATH="/opt/ms/pkg/sqlite" \
    CGO_LDFLAGS="-Wl,--unresolved-symbols=ignore-in-object-files -Wl,--allow-multiple-definition" \
    go build -tags "static" -o /usr/local/bin/gitqlite mergestat.go \
 && (cp /opt/ms/git2go/static-build/install/lib/*.so* /usr/local/lib/ 2>/dev/null && ldconfig || true) \
 && command -v gitqlite \
 && cd / \
 && rm -rf /opt/ms) || echo "[WARN] gitqlite (mergestat-lite) build failed - historian reverts_by_author unavailable"

# 2f. Vendor Hercules (bus factor/burndown), a Go binary.
RUN (GOBIN=/usr/local/bin go install gopkg.in/src-d/hercules.v10/cmd/hercules@v10.7.0) || \
    (wget -qO /tmp/hercules.zip https://codeload.github.com/src-d/hercules/zip/refs/tags/v10.7.0 \
     && unzip -q /tmp/hercules.zip -d /opt \
     && cd /opt/hercules-10.7.0 \
     && (go generate ./cmd/hercules || true) \
     && (go build -o /usr/local/bin/hercules ./cmd/hercules \
         || (printf 'package main\nvar PluginTemplateSource = ""\n' > ./cmd/hercules/generated_plugin_template_stub.go \
             && go build -o /usr/local/bin/hercules ./cmd/hercules)) \
     && cd / \
     && rm -rf /opt/hercules-10.7.0 /tmp/hercules.zip) || true

# 2f-bis. Labours — the hercules→JSON ownership/burndown converter.
# Labours is a PYTHON tool, NOT a Go command: hercules v10's Go module has no
# `cmd/labours` package, so the prior `go build ./cmd/labours` could NEVER
# succeed (silently `|| true`'d for months). Without labours, hercules can't
# emit ownership JSON → historian.ts fell back to the commit-count proxy.
#
# RELIABILITY: labours is abandoned (src-d/hercules, 2020) and pins an ancient
# scientific-python stack (declared pandas<1.0, scipy<1.2.2, protobuf<4) with
# no arm64/py3.11 wheels. It DOES run on newer wheel-available versions, but
# those OLD pins (and protobuf<4, which carries CVEs) must NOT pollute the
# image's system Python — bandit/semgrep/safety/radon all need MODERN versions
# there. So labours lives in an ISOLATED venv with an exact, wheel-only pin set
# (no source builds → reproducible every rebuild), symlinked onto PATH. The
# couples/clustering-mode deps (fastdtw/hdbscan/seriate, no arm64 wheels) are
# omitted — historian only uses ownership mode. See historian.ts for the
# matching `hercules --burndown --burndown-people --pb | labours -m ownership`
# invocation and docs/runbooks/forensic-image-cutover.md.
RUN python -m venv /opt/labours-venv \
 && /opt/labours-venv/bin/pip install --no-cache-dir --only-binary=:all: \
      numpy==1.24.4 pandas==1.5.3 scipy==1.10.1 protobuf==3.20.3 \
      matplotlib==3.7.5 lifelines==0.27.8 PyYAML==6.0.1 munch==4.0.0 \
      python-dateutil==2.9.0.post0 tqdm==4.67.1 \
 && /opt/labours-venv/bin/pip install --no-cache-dir --no-deps labours==10.7.2 \
 && ln -sf /opt/labours-venv/bin/labours /usr/local/bin/labours \
 && (command -v labours || true)

# Warn if key tools are missing (best-effort vendoring)
RUN /bin/sh -c 'command -v hercules >/dev/null 2>&1 || echo "[WARN] hercules missing - burndown unavailable"; \
                command -v labours  >/dev/null 2>&1 || echo "[WARN] labours missing - JSON burndown conversion unavailable"; \
                command -v gitqlite >/dev/null 2>&1 || echo "[WARN] gitqlite missing - reverts_by_author unavailable"'

# 2c. Vendor Semgrep rule pack for offline scans
RUN git clone https://github.com/semgrep/semgrep-rules /opt/semgrep-rules \
 && cd /opt/semgrep-rules && git checkout 46a0ecfdf78f86a6409677c58417f845ef9eae9a

COPY infrastructure/semgrep-rules-js.yml /opt/semgrep-rules-custom/semgrep-rules-js.yml
COPY infrastructure/semgrep-rules-py.yml /opt/semgrep-rules-custom/semgrep-rules-py.yml

RUN git init /opt/advisory-db \
 && cd /opt/advisory-db \
 && git remote add origin https://github.com/pypa/advisory-database \
 && git fetch --depth 1 origin e4035d8131324cf207ac9b40eacac79b97b1c6b2 \
 && git checkout FETCH_HEAD

# 2g. ENGINE RUNTIME NODE DEPENDENCIES (FIX-1 — the run-1 boot blocker).
# The monorepo bind-mounted package.json + tsconfig.json + node_modules from the
# repo root into /opt/*; the standalone repo carries its own and BAKES them into
# the image so the engine boots air-gapped at runtime (no host node_modules).
#
# The engine resolves its runtime dependency `commander` via NODE_PATH=
# /opt/node_modules (set on the run.sh invocation), and the worker-thread
# ts-node loader resolves from /usr/local/lib/node_modules (installed globally
# above) with a /opt/node_modules fallback (engine/commands/analyze.ts probe).
# So we install the engine's npm deps into /opt/node_modules here.
COPY package.json /opt/package.json
COPY tsconfig.json /opt/tsconfig.json
RUN cd /opt \
 && npm install --omit=dev --prefix /opt \
 && ls /opt/node_modules/commander/package.json
# `npm install --prefix /opt` lands deps in /opt/node_modules (commander +
# ts-node + typescript per package.json). The final `ls` hard-fails the build if
# commander did not land — no silent boot blocker on stage.

# 3. WORKSPACE CONFIGURATION
# /workspace: Where the client code is mounted
# /opt/engine: Where the breadth engine source is mounted
WORKDIR /workspace

# 4. SECURITY ENFORCEMENT FLAGS
# Used by engine/cli.ts to verify it is not running on host metal
ENV DOCKER_MANDATE=true
ENV IN_CONTAINER=true
ENV PYTHONUNBUFFERED=1
ENV PYTHON_ADVISORY_DB=/opt/advisory-db

# 5. ENTRYPOINT
# Default to bash to allow the orchestrator to pass commands
CMD ["/bin/bash"]
