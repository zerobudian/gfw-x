# GFW X — Architecture

> This document describes the architecture of GFW X (v1.1 "Real Gateway"). It
> covers the unified data plane, the Linux NFQUEUE backend, the explainable
> policy engine, rules versioning, observability, the PCAP regression lab, and
> the detector plugin API.

## 1. Data-plane model

Every ingress source feeds the same processing chain through a single, narrow
abstraction in [`internal/pipeline`](../internal/pipeline/pipeline.go):

```
PacketSource → Decode → Flow Tracking → Metadata/DPI → Policy → Verdict → PacketSink
```

The two interfaces every source/sink implement are:

- **`PacketSource`** — `Start() / Next(ctx) / Stop()`. Yields decoded frames.
- **`PacketSink`** — `Write(ctx, pkt, verdict) / Stop()`. Applies the verdict
  (for NFQUEUE this writes ACCEPT/DROP back to the kernel).

The pipeline `Runner` drives a source through a worker pool into a sink with a
bounded number of goroutines and natural backpressure (a fast source blocks the
source's `Next` when workers are saturated). The core policy and detector logic
never depends on a specific provider — Linux specifics are isolated in
[`internal/nfq`](../internal/nfq).

```
                 ┌──────────────────────────────────────────────────┐
   Linux packet  │  NFQUEUE (kernel)                                │
   ─────────────►│  queue → PacketSource ──► Decode ──► Flow table   │
                 │                                    │              │
                 │                    fast-path hit ──► Verdict      │
                 │                                    │              │
                 │       slow path: DNS/TLS/DPI → Detectors → Policy │
                 │                                    │               │
                 │                          Policy (DecisionTrace)   │
                 │                                    │               │
                 │                              Verdict ACCEPT/DROP   │
                 │                                    │               │
                 │                                  PacketSink ──► queue (kernel)
                 └──────────────────────────────────────────────────┘
```

### Modes / sources

| `dataplane.mode` | Source                        | Sink       | Platform        |
| ---------------- | ----------------------------- | ---------- | --------------- |
| `pcap`           | `internal/gateway.Replay`     | no-op      | all             |
| `nfqueue`        | `internal/nfq.Source`         | `nfq.Sink` | Linux           |
| `pcap` + no file | synthetic generator           | no-op      | all             |

`pcap` mode needs no privileges and works on every platform (including
CGO_ENABLED=0). `nfqueue` mode is Linux-only; on other platforms
`internal/nfq` ships a build-tagged stub that fails fast with a clear error
rather than silently degrading.

## 2. Linux NFQUEUE backend

[`internal/nfq`](../internal/nfq) implements the `netfilter_queue` netlink
protocol directly over `NETLINK_NETFILTER` (no third-party NFQUEUE library —
only `golang.org/x/sys/unix`).

- Bind IPv4 (`AF_INET`) via `NFQNL_CFG_CMD_PF_BIND`; IPv6 is reserved.
- Bind the queue and set `COPY_PACKET` with a bounded copy range so whole
  frames (up to 64 KiB) are delivered.
- `parsePacketMsg` extracts the packet id + queue number into `pipeline.Packet.Meta`.
- `Sink.Write` maps a pipeline verdict to `NF_ACCEPT` / `NF_DROP` and submits it.
- **Fail mode**: on a verdict-delivery error (timeout / queue closed) the sink
  retries once, then applies the configured `fail_mode` — `open` → ACCEPT,
  `closed` → DROP — and counts the overflow via `gfwx_nfqueue_overflows_total`.
- Graceful shutdown: `Stop()` closes the socket and the runner joins all
  goroutines, so the queue is cleanly released.

### Enabling NFQUEUE

```yaml
dataplane:
  mode: nfqueue
  nfqueue:
    queue_num: 100
    max_queue_len: 4096
    verdict_timeout_ms: 1000
    fail_mode: open      # open | closed
    max_workers: 4
```

Then steer packets with nftables:

```bash
# enqueue OUTPUT traffic on queue 100 (IPv4)
nft add rule inet filter output ip version 4 queue num 100

# restore / remove afterwards
nft delete rule inet filter output handle <HANDLE>
```

> GFW X never mutates your host firewall itself. You add the rules above and
> remove them the same way; `nfq` only listens on the queue it is told to.
> Back up your firewall state before experimenting:
> `nft list ruleset > firewall-backup.nft`.

### Failure + timeout policy

- Queue overflow (kernel-side) is the kernel's concern; GFW X still replenishes
  its own queue and ACM counters observe depth/overflows.
- A packet that is not answered within the queue/verdict timeout follows
  `fail_mode` (above) so traffic is never silently stranded.

## 3. Fast / Slow path

Documented in the [README](README.md). Classification decisions cache per flow;
known flows are served from the flow table (fast path), and unknown/suspicious/
sampled flows take the slow path through DPI + detectors + policy.

## 4. Policy engine & DecisionTrace

[`internal/policy`](../internal/policy) combines the rule repo's priority layers
with decision tracing. `DecisionTrace` is structured data (flow id, endpoints,
protocol, DNS/SNI metadata, detector verdict + confidence, matched/skipped
rules with the exact priority layer, fast/slow path, final action, action
source, and processing latency) and is JSON-serializable.

Priority is evaluated by layer:

```
explicit allow  >  explicit block  >  category rules  >  default/others
```

Each layer override is visible in the trace so `GET /api/traces` can answer
"why was the final action X?" The trace ring is bounded (sampled), so the fast
path does not allocate large trace objects per packet.

## 5. Detect / policy Explain

- Detectors are statically registered via the `Detector` interface
  (`Info()`, `Inspect(sample, features) Result`) in
  [`internal/detect`](../internal/detect). They are stateless (safe under the
  concurrent worker pool), run under a panic guard, and expose per-detector
  `gfwx_detector_runs_total` / `gfwx_detector_panics_total` counters.
- `GET /api/traces` returns recent DecisionTrace objects for the dashboard.
- `GET /api/shadow` reports shadow-mode disagreement statistics
  (would_allow / would_block / disagreement).

## 6. Rules versioning

[`internal/rules/version.go`](../internal/rules/version.go) adds atomic,
snapshot-based rule revisions on top of the immutable `CompiledSet`.

- **Apply** validates → diffs → snapshots → single atomic `Replace` on the live
  repo, so the data plane never sees a half-applied rule set.
- **Rollback** restores a prior snapshot as a new, audited revision.
- **Dry-run** reports projected diff + conflicts without touching live state.

Endpoints:

| Endpoint                    | Purpose                                  |
| --------------------------- | ---------------------------------------- |
| `GET /api/rules/revisions`  | Revision history                         |
| `GET /api/rules/revisions/:id` | One revision + full snapshot + changes |
| `POST /api/rules/rollback`  | Roll back to a revision                  |
| `POST /api/rules/dry-run`   | Preview a rule change                    |

## 7. Observability

`GET /metrics` (Prometheus text, public to scrapers) exposes gateway counters
with bounded-cardinality labels (never IPs, domains, or flow IDs). Latency is
accumulated as count + sum so collectors can derive averages:

`gfwx_packets_total`, `gfwx_bytes_total`, `gfwx_flows_active`,
`gfwx_fast_path_hits_total`, `gfwx_slow_path_hits_total`,
`gfwx_policy_evaluations_total`, `gfwx_rule_hits_total`,
`gfwx_packets_dropped_total`, `gfwx_detector_runs_total`,
`gfwx_detector_latency_seconds`, `gfwx_policy_latency_seconds`,
`gfwx_nfqueue_depth`, `gfwx_nfqueue_overflows_total`, `gfwx_log_dropped_total`,
and per-detector `{detector=...}` counters.

## 8. PCAP regression lab

[`internal/lab`](../internal/lab) builds deterministic `.pcap` fixtures under
`testdata/pcaps`, replays each through a fresh gateway, and compares the result
against `testdata/expected/*.json`. It reports TP / FP / FN with precision and
recall (values that cannot be computed for the current dataset are reported as
`unavailable`, never fabricated). Run with `go test ./internal/lab/...` (it is
also a CI job).

## 9. Authentication

Session auth uses **Argon2id** (`golang.org/x/crypto/argon2`, 64 MiB, random
salt) plus:

- Transparent migration from the legacy SHA-256 hash format.
- Session **rotation** on each login and **expiry** (12h).
- `HttpOnly` + `SameSite=Strict` cookie, `Secure` set when the request is HTTPS.
- Double-submit CSRF + Origin/Referer checks on mutations.
- Per-client-IP login rate limit with a short lockout.
- First-run setup when no admin password is configured (no hard-coded default).
  If the well-known default hash is still in place, the gateway refuses to bind
  a non-loopback listener (see `config.Validate`).

See [SECURITY.md](SECURITY.md) for the full threat model.

## 10. Release engineering

A GitHub Actions workflow builds `linux/{amd64,arm64}` artifacts, writes
`SHA256SUMS`, and runs `go test`, `go test -race`, `go vet`, `staticcheck`, and
`govulncheck`. Local release packaging lives in the `Makefile`
(`release`, `release-linux`, `sbom`, `notes`). Release ZIPs are **not** committed
to the source root; artifacts are built from the workflow / Makefile only.