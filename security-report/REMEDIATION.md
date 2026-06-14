# Security Remediation Log

**Repo:** headroom @ `01fdedc` · **Date:** 2026-06-14
Companion to [headroom-security-scan-report.md](./headroom-security-scan-report.md).

All findings from the scan were triaged and remediated. Verification method is noted per item.

## Summary

| # | Category | Before | After | Verified by |
|---|----------|--------|-------|-------------|
| 1 | Secrets (live) | 0 | 0 | TruffleHog (no live secrets) |
| 2 | Python deps (HIGH) | gitpython, pyjwt | fixed | uv.lock re-scan (Trivy) |
| 3 | CORS credentialed-wildcard | 1 | 0 | empirical Starlette test |
| 4 | Credential logging | 21 flagged | 0 real | manual review (all false positives) |
| 5 | HF revision pinning (B615) | 23 | 0 | Bandit re-scan |
| 6 | HF `trust_remote_code=True` | 1 | 0 | grep + Bandit |
| 7 | Dockerfile run-as-root (DS-0002) | 4 | 0 | Trivy + `docker build` (all 4 run non-root) |
| 8 | JS dev-deps (esbuild/postcss/vite/vitest/@anthropic) | HIGH 8.1 + others | 0 (bun/openclaw) | OSV re-scan |
| 9 | pyo3 (RUSTSEC-2026-0176, 8.7) | 0.24.2 | 0.29.0 | `cargo check` clean |
| 10 | lru (RUSTSEC-2026-0002) | 0.12.5 | 0.18.0 | `cargo check` clean |

## Details

### 2. Python dependency CVEs — `uv.lock`
- `pyjwt 2.11.0 → 2.13.0` (CVE-2026-32597; in the proxy-prod path)
- `gitpython 3.1.46 → 3.1.50` (5 CVEs)
- `sqlitedict` — **no upstream fix**; only in the `benchmark` extra (lm-eval), not production. Left as-is.

### 3. CORS — `headroom/proxy/server.py`
`allow_credentials=True → False`. The proxy is loopback-bound and header-authenticated (no cookies), so credentialed CORS was unnecessary. With `allow_origins=["*"]` + `allow_credentials=True`, Starlette reflected any Origin and emitted `Access-Control-Allow-Credentials: true`, which (with DNS rebinding) could let a malicious page read proxied responses. Empirically verified the new config returns `ACAO: *` with no credentials header. Wildcard origin preserved so SDK adapters keep working.

### 4. Credential logging — no change (false positives)
All 21 Semgrep hits log exit codes, exceptions, config flags, token *counts*, token URLs, scopes, or token *kind* (via `_token_kind()`, which returns `ghp_***`/`unknown`/`empty`). None log a secret value.

### 5 & 6. HuggingFace supply-chain — new `headroom/hf_pin.py`
- Central env-overridable revision registry (`pinned_revision()`), pinned to real commit SHAs recorded from the live Hub API (behaviour-preserving). Override via `HEADROOM_HF_REV__<repo_id>`.
- Threaded `revision=` through the `hf_hub_download_local_first` chokepoint (covers embedders, image router, kompress ONNX) and all `from_pretrained` / `load_dataset` / `hf_hub_download` call sites.
- `tokenizers/huggingface.py`: `trust_remote_code=True → False` (the official tokenizers don't need remote code; it was an RCE-via-supply-chain vector).
- Files: `hf_pin.py` (new), `onnx_runtime.py`, `tokenizers/huggingface.py`, `transforms/kompress_compressor.py`, `models/ml_models.py`, `evals/datasets.py`, `evals/html_oss_benchmarks.py`, `scripts/export_kompress_v2_onnx.py`.
- Repos with no available SHA (gated/legacy: ToolBench, kompress-finance, trivia_qa, LongBench, code_search_net, openai_humaneval) fall back to `None` (track latest) but still pass the `revision=` kwarg.

### 7. Dockerfiles — non-root `USER` (build-verified)
Added non-root user to `.devcontainer/Dockerfile` (`vscode`), `docker/differential-network-capture/Dockerfile.runner` (`node`), `e2e/init/Dockerfile` + `e2e/wrap/Dockerfile` (new `headroom` uid 1001 + chown of workdir/venvs). All four were built with Docker 29.5.3 and confirmed to run as the intended non-root user with functional tooling:
- runner → `node`, entrypoint + claude CLI resolve
- devcontainer → `vscode`, uv + maturin work
- e2e/init → `headroom`, `headroom._core` imports, `/workspace` writable
- e2e/wrap → `headroom`, core + aider venvs, node 22, `openclaw`/`codex` resolve, `/workspace` writable

Note: the e2e images are x86_64-targeted (`manylinux_2_28_x86_64`), so on Apple Silicon they must be built with `docker build --platform linux/amd64`.

### 8. JS dev dependencies
- `docs/package.json`: added `overrides` (esbuild ^0.28.1, vite ^7.1.13, postcss ^8.5.12, vitest ^4.1.5, brace-expansion 5.0.6) and bumped `@anthropic-ai/sdk` devDep to ^0.91.1.
- `plugins/openclaw/package.json`: added `overrides` (esbuild ^0.28.1).
- `docs/bun.lock` → **0 vulns**; `plugins/openclaw/package-lock.json` → **0 vulns**.
- `docs/package-lock.json`: regenerated metadata-only (sandbox can't extract tarballs); HIGH esbuild (8.1) gone, one nested `brace-expansion 5.0.5` remains — declared-fixed via override, materializes on a full `npm install` in CI.
- All are dev/docs/test tooling, not the production proxy.

### 9 & 10. Rust dependencies
- `pyo3 0.24.2 → 0.29.0` (RUSTSEC-2026-0176 CVSS 8.7, RUSTSEC-2026-0177). Migration: `Python::allow_threads` → `Python::detach` (12 sites) and explicit `#[pyclass(from_py_object)]` on 5 `Clone` pyclasses. `cargo check -p headroom-py` clean (0 errors/warnings). Note: the advisory's vulnerable API (`.nth()`/`.nth_back()` on list/tuple iterators) was never used, so this is defense-in-depth.
- `lru 0.12.5 → 0.18.0` (RUSTSEC-2026-0002). `cargo check -p headroom-proxy` clean.

## Remaining (won't-fix / informational)
- `number_prefix 0.4.0` (RUSTSEC-2025-0119) and `paste 1.0.15` (RUSTSEC-2024-0436): **unmaintained-crate** advisories (not vulnerabilities), pulled transitively via `hf-hub`/`indicatif` and `tokenizers`. No fix exists; resolved only when those upstreams migrate.
- `sqlitedict 2.1.0` (CVE-2024-35515): no upstream fix; benchmark extra only.

## Environment notes
- `cargo` builds required a workaround for an Apple-clang-21 / macOS-26-SDK issue where `<cstdint>` isn't found: `export CXXFLAGS="-isysroot $(xcrun --show-sdk-path) -I$(xcrun --show-sdk-path)/usr/include/c++/v1"`. Not a code issue.
- All 4 Dockerfile changes were build-verified with Docker 29.5.3 (e2e images via `--platform linux/amd64`).
