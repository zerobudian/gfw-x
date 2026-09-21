# Changelog

All notable changes to gfw-x are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - Unreleased

### Added

- **Unified data plane** (`internal/pipeline`): `PacketSource` /
  `PacketSink` / `Packet` / `Verdict` abstraction so PCAP replay, the synthetic
  generator, and NFQUEUE share one processing chain
  (`PacketSource → Decode → Flow → DPI → Policy → Verdict → PacketSink`), with
  bounded worker pools and natural backpressure.
- **Linux NFQUEUE backend** (`internal/nfq`, build-tagged `linux`): IPv4,
  `fail_mode: open|closed`, verdict timeouts, queue-overflow
  observability, graceful queue release, and a fail-fast non-Linux stub so PCAP
  mode builds everywhere.
- **DecisionTrace** (`internal/policy`, `internal/gateway`): structured,
  JSON-serializable decision explanations with priority layers
  (explicit allow > block > category > default), matched/skipped rules, fast/
  slow path, action source and latency; served via `GET /api/traces`.
- **Rules versioning** (`internal/rules/version.go`): atomic snapshot-based
  revision apply, rollback, dry-run preview, and diff; routed through
  `POST /api/rules/rollback`, `POST /api/rules/dry-run`,
  `POST /api/rules/apply`,
  `GET /api/rules/revisions[/:id]`. Apply validates, conflict-checks, dry-runs
  and atomically replaces the whole set as a new revision.
- **Shadow mode** (`internal/policy/shadow.go`): observe-only evaluation with
  would_allow / would_block / disagreement; candidate set is loaded from any
  revision via `POST /api/shadow {"revision": id}` and cleared with `{}`, letting
  operators answer "would revision R change this flow's verdict?".
  Exposed via `GET /api/shadow` and `gfwx_shadow_*` metrics.
- **DecisionTrace UI**: the Traffic dashboard now renders recent traces with an
  Explain / Decision Trace panel (DNS/SNI, protocol, fast/slow path, detector +
  confidence + reasons, matched + successively-overridden rules, latency).
- **Rules Revision UI**: the Rules dashboard now offers revision history with
  colored added/removed/modified diffs, one-click diff, confirmed rollback, and
  a dry-run → apply textarea; plus a Shadow card to validate a revision and
  watch disagreement counters.
- **Trace benchmarks** (`internal/policy`): `BenchmarkTraceNoTrace`,
  `BenchmarkTraceSampled`, `BenchmarkTraceFull` quantifying the sampling cost.
- **NFQUEUE integration test** (`internal/nfq`, `linux`): root-gated by
  `GFWX_NFQUEUE_INTEGRATION=1` driving nftables → NFQUEUE → verdict → cleanup;
  skipped with an explicit NOT RUN reason when privileges/module are missing.
- **Observability**: `GET /metrics` Prometheus text with bounded-cardinality
  counters (packets, bytes, flows, fast/slow/hits, policy+detector latency as
  count+sum, NFQUEUE depth/overflows, log drops) and per-detector counters.
- **Detector plugin API** (`internal/detect`): static `Detector` registry,
  panic guard, stateless `Inspect(sample, features)` for safe concurrency, and
  per-detector `gfwx_detector_runs_total` / `gfwx_detector_panics_total`.
- **PCAP regression lab** (`internal/lab`): deterministic fixtures + evidence
  JSON, TP/FP/FN with precision/recall, runnable in CI.
- **Authentication hardening**: Argon2id password hashing with random salt,
  transparent legacy hash migration, session rotation + expiry, `HttpOnly` /
  `SameSite=Strict` / `Secure` cookie, first-run admin setup, login rate limit.
- **Release engineering**: CI builds `linux/amd64` + `linux/arm64`, runs
  `go test -race`, `go vet`, `staticcheck`, `govulncheck`, verifies the embedded
  Web bundle stays in sync, and a `release-artifacts` job emits one merged
  `SHA256SUMS.txt`, a generated SPDX SBOM (`sbom.spdx`) and release notes.
  Makefile `release` / `release-linux` / `sbom` / `notes` targets cross-compile
  with correct `os/arch` pairs.

### Changed

- Default password hashing moved from double salted SHA-256 to Argon2id; the
  legacy scheme is still verified and upgraded on login.
- The repo-root `gfw-x-1.0.0.zip` is no longer committed; releases are produced
  by CI / the Makefile only.
- Session tokens now rotate on each login and expire after 12 hours.
- Default config no longer ships a working default credential: the dashboard is
  locked until the first login sets an Argon2id password (first-run setup).

### Fixed

- Stateless detectors eliminate a data race on shared per-instance state under
  the concurrent worker pool.
- `config.Validate` refuses a non-loopback listener while the well-known default
  admin hash is still configured.
- `POST /api/rules/dry-run` now accepts a JSON `{"content": ...}` body in
  addition to the urlencoded form field, so the dashboard and CLI agree.
- `GET /api/shadow` now reports `active` from whether a candidate revision is
  loaded (matching the `gfwx_shadow_active` gauge), not the config toggle.
- Added `gfwx_shadow_evaluations/disagreements/would_block/would_allow` counters
  and candidate gauges to `/metrics`.

[1.1.0]: https://example.invalid/gfw-x/compare/v1.0.0...v1.1.0