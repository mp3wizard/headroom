# Automated Security Scan Report

**Target:** `/Users/mp3wizard/Public/Claude Proxy/headroom`
**Scanned at:** 2026-06-14T11:41Z – 13:46Z
**Git HEAD:** `01fdedc`
**Standard:** OWASP APTS-aligned (Scope Enforcement · Auditability · Manipulation Resistance · Reporting)

## Scope Record
```
Scan target: /Users/mp3wizard/Public/Claude Proxy/headroom
Git HEAD:    01fdedc
Include:     all supported (Python ×834, Rust ×175, TS ×93)
Exclude:     vendored node_modules, .git (.gitignore honored by each tool)
```

## Coverage Disclosure (APTS § Reporting)
| Tool | Ran? | Version | Coverage | Notes |
|------|------|---------|----------|-------|
| Gitleaks | OK | 8.30.1 | 1245 commits, 48.6 MB | 59 history hits |
| TruffleHog | OK | 3.94.2 | full git history | live verification |
| Bandit | OK | 1.9.4 | 250,574 LoC Python | node_modules excluded |
| Semgrep | OK | latest | p/owasp-top-ten + p/secrets | re-run manually after wrapper arg-quoting bug |
| Trivy | OK | 0.69.3 | vuln+misconfig+secret | safe version (not 0.69.4–6) |
| OSV-Scanner | OK | 2.3.5 | Cargo/uv/npm/bun lockfiles | — |
| CodeQL | SKIPPED | — | — | requires GitHub Actions run; not invoked |
| mcps-audit | N/A | — | — | no MCP manifests in repo |
| skill-security-auditor | N/A | — | — | no `*.skill`/`SKILL.md` |
| mcp-exfil-scan | N/A | — | 0 MCP/skill files | headroom is a proxy, not an MCP server |
| skillspector | N/A | 2.1.4 (installed) | — | no AI-skill artifacts in repo |
| security-audit (config) | OK | bundled | scanned user `~/.claude` config | findings are about user env, not headroom |

**Coverage gaps:** No Python/Rust/TS source files exceeded Semgrep's 400 KB cap (no silent skips). CodeQL not run. Business logic, IDOR, auth flows, and runtime behavior are out of scope for static scanning.

---

## Executive Summary

**No live/verified secrets. No critical code-execution vulnerabilities in first-party source.** The most actionable items are **dependency upgrades** (several HIGH CVEs in `uv.lock`/`Cargo.lock`) and one **CORS hardening** issue. The 59 gitleaks hits are all test fixtures / example tokens — TruffleHog verified **0** are live.

| Severity | Count | Theme |
|----------|-------|-------|
| 🔴 High | 9 vuln + 4 misconfig | Vulnerable deps (gitpython, pyo3, pyjwt, esbuild, sqlitedict); Dockerfiles run as root |
| 🟠 Medium | ~10 | Wildcard CORS w/ credentials; weak hashes (MD5/SHA1); urllib scheme; HF downloads w/o pinned revision |
| 🟡 Low / FP | many | Test secrets, defended SQLi, credential-logging false positives |

---

## 1. Secrets — Gitleaks + TruffleHog

**Summary: 59 gitleaks history hits (30 JWT, 29 generic-api-key); TruffleHog verified secrets = 0.** [CONFIDENTIAL]

TruffleHog scanned the full git history (23,076 chunks, 77 MB) → **0 verified**, 12 unverified — all 12 are MongoDB example connection strings inside vendored `examples/.../node_modules/zod/.../template-literal.test.ts` (library test fixtures, `mongodb://username:password@host:1234`).

Gitleaks hits cluster in test/fixture files (`crates/.../tests/*.rs`, `tests/test_*.py`, `tests/parity/fixtures/*.json`) — hardcoded test JWTs/keys, expected for an LLM-proxy test suite. A handful sit in source (`headroom/copilot_auth.py:32`, `headroom/cli/proxy.py`, `headroom/telemetry/beacon.py`, `headroom/config.py`) — these are **placeholder/default values, not live credentials** (confirmed by TruffleHog returning 0 verified). Trivy independently flagged one (`crates/headroom-core/benches/auth_mode.rs:48`, a bench JWT — MEDIUM).

**Action:** No rotation required. Optionally add the known test tokens to `.gitleaks.toml` / `.gitguardian.yaml` (the repo already has a `.gitguardian.yaml`) to silence recurring false positives.

## 2. Dependencies — Trivy + OSV-Scanner

**Summary: 9 HIGH, 3 MEDIUM (Trivy) + corroborating OSV entries. These are the top priority.**

| Severity | Package | Installed | Advisory | Fix | Lockfile |
|----------|---------|-----------|----------|-----|----------|
| 🔴 HIGH | `gitpython` | 3.1.46 | CVE-2026-42215, -42284, -44243, -44244, GHSA-mv93-w799-cj2w | **3.1.50** | uv.lock |
| 🔴 HIGH | `pyo3` | 0.24.2 | GHSA-36hh-v3qg-5jq4 / RUSTSEC-2026-0176 (CVSS 8.7) | 0.29.0 | Cargo.lock |
| 🔴 HIGH | `pyjwt` | 2.11.0 | CVE-2026-32597 | 2.12.0 | uv.lock |
| 🔴 HIGH | `esbuild` | 0.27.7 / 0.21.5 / 0.27.4 | GHSA-gv7w-rqvm-qjhr (CVSS 8.1) | 0.28.1 | docs/, plugins/openclaw |
| 🔴 HIGH | `sqlitedict` | 2.1.0 | CVE-2024-35515 | *(no fix released)* | uv.lock |
| 🟠 MED | `pyo3` | 0.24.2 | GHSA-chgr-c6px-7xpp / RUSTSEC-2026-0177 | 0.29.0 | Cargo.lock |
| 🟠 MED | `postcss` | 8.4.31 | CVE-2026-41305 / GHSA-qx2v-qp2m-jg93 | 8.5.10 | docs/ |
| 🟠 MED | `brace-expansion` | 5.0.5 | CVE-2026-45149 | 5.0.6 | docs/ |
| 🟠 CVSS 9.8 | `vitest` | 2.1.9 | GHSA-5xrq-8626-4rwp | upgrade | docs/bun.lock (dev) |
| — | `lru`, `number_prefix`, `paste` | — | RUSTSEC-2026-0002 / 2025-0119 / 2024-0436 | low CVSS / unmaintained | Cargo.lock |

> Note: `pyjwt` is directly relevant — headroom parses JWTs in its auth path. Prioritize it alongside `gitpython` and `pyo3`. Most `docs/`, `plugins/`, and `vitest` items are dev/build-time dependencies (lower runtime exposure but still worth bumping).

**Action:** `uv lock --upgrade-package gitpython --upgrade-package pyjwt` (and friends); `cargo update -p pyo3` (may need a code bump to 0.29). `sqlitedict` has no fix — assess whether it's reachable with untrusted input.

## 3. Code (SAST) — Bandit + Semgrep

**Summary: 4 Bandit HIGH (all weak-hash, non-security use); Semgrep 52 OWASP findings (3 ERROR, 49 WARNING).**

### Genuine hardening items
- 🟠 **Wildcard CORS with credentials** — `headroom/proxy/server.py:2084`
  `allow_origins=["*"]` + `allow_credentials=True` + `allow_methods/headers=["*"]`. For a proxy that forwards API keys this is the most notable code finding. Browsers reject credentialed wildcard, but it's a permissive default worth tightening to an explicit allowlist (or gating behind config).
- 🟠 **Insecure file permissions** — `headroom/proxy/interceptors/astgrep.py:183`, `headroom/proxy/probe_recorder.py:41`. Verify files written here don't contain request/response data with secrets at world-readable perms.
- 🟠 **`urllib.urlopen` permitted-scheme (B310)** ×21 — installers/health checks (`headroom/binaries.py`, `install/health.py`, `graph/installer.py`, `rtk/installer.py`, etc.). Confirm URLs are constant/trusted (not attacker-influenced) to avoid `file://`/SSRF surprises.
- 🟠 **HuggingFace download without pinned revision (B615)** ×23 — `headroom/evals/datasets.py`, `models/ml_models.py`, `tokenizers/huggingface.py`, `onnx_runtime.py`. Supply-chain: pin `revision=` to a commit SHA so a hijacked model repo can't swap weights.

### Low-risk / false positives (verified by reading source)
- **Weak hashes (MD5/SHA1, B324 / Semgrep)** — `log_compressor.py:474`, `cli/init.py:115`, `utils.py:43`, `parser.py:53`, cache keys, feature hashing. All **non-security** uses (cache keys, content fingerprints, profile-name slugs). Fix is cosmetic: add `usedforsecurity=False` to silence.
- **`dangerous-subprocess-use-tainted-env-args` (Semgrep ERROR ×2)** — `copilot_auth.py:251` (invokes `gh` CLI with list args, host from config), `cli/wrap.py:2698` (`sys.executable -m headroom.memory.sync` with `$USER`). List-form args, no `shell=True` → not shell-injectable. Low risk.
- **SQL injection (B608 ×8)** — `memory/adapters/sqlite.py`, `sqlite_vector.py`, `fts5.py`, `storage/sqlite.py`. **Defended:** values use `?` placeholders; `order_column` is allowlist-validated; metadata keys validated against JSON-path injection; `IN (...)` uses generated `?` placeholders. False positives (devs already added `# nosec` + validation comments).
- **`python-logger-credential-disclosure` ×21** — copilot_auth/subscription/oauth2 plugin. Spot-checked `copilot_auth.py:263` logs an *exit code*, not a token. Heuristic matches on nearby `token`/`secret` identifiers. **Recommend a quick manual pass** of the 21 sites to confirm none log raw token *values* at any level — but no confirmed leak found.

### Bandit roll-up
250,574 LoC scanned: 4 High (weak hash), 106 Medium (61 in non-test source — mostly B310/B615/B108 above), 16,555 Low (overwhelmingly assert/try-except-pass test noise).

## 4. Docker / IaC — Trivy misconfig

**Summary: 4 HIGH, 4 MEDIUM, 4 LOW.**
- 🔴 **DS-0002 "Image user should not be 'root'"** ×4 — `.devcontainer/Dockerfile`, `docker/differential-network-capture/Dockerfile.runner`, `e2e/init/Dockerfile`, `e2e/wrap/Dockerfile`. Add a non-root `USER` (the main `Dockerfile` may already; these are dev/e2e images). Lower risk for ephemeral CI/dev containers but a standard hardening fix.

## 5. Claude Config Audit (context note)

The bundled `config-audit.py` scans your **global `~/.claude` environment**, not headroom. It flagged 4 MEDIUM (broad `''` matchers in *your installed plugins*: `claude-plugins-official`, `pordee`) and several LOW (hooks present in `openai-codex`, `addy-agent-skills`, etc.). **These are not part of the headroom repo** — included only for completeness. headroom itself ships no MCP manifests or skills (mcp-exfil-scan: 0 MCP configs, 0 skill files).

---

## Cross-Tool Observations
- **Secrets corroboration:** Gitleaks (59), Trivy secret (1), TruffleHog (12 unverified) all converge on the same conclusion — **test fixtures, 0 live**. The one Trivy hit (`auth_mode.rs:48`) is within the gitleaks set.
- **Dependency corroboration:** Trivy and OSV independently flag `pyo3 0.24.2` (8.7), `esbuild` (8.1), `gitpython`, `postcss`, `brace-expansion` — high confidence these are real.
- **Weak-hash corroboration:** Bandit B324 and Semgrep `insecure-hash-algorithm-*` overlap on `log_compressor.py:474`, `cli/init.py:115` — same (benign) findings, not double-counted.

## Coverage Gaps
Not covered: business logic, IDOR/authorization, runtime/dynamic behavior, CodeQL semantic analysis (not run — no GH Actions invocation). Static tools cannot confirm whether the 21 credential-logging sites emit real token values at runtime — recommend a targeted manual review.

### APTS Audit Log
- **Log:** `/tmp/css-scan-20260614T114118Z.jsonl`
- **Tool runs recorded:** 6 measured (gitleaks, trufflehog, bandit, trivy, osv-scanner, semgrep). Semgrep's wrapper invocation logged exit 127 due to an arg-quoting bug in the wrapper; it was re-run directly (exit 0, 52 findings) and those results are included above.
- **Standard:** OWASP APTS § Auditability
