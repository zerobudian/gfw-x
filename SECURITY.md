# GFW X — Security

This document captures the security posture of GFW X v1.1. It covers
authentication, packet-parser safety, privilege boundaries, API exposure,
default configuration, and known limitations. Run `.github/workflows/ci.yml`
locally with `govulncheck`, `staticcheck`, and `go vet` before any release.

## Authentication

- **Password hashing**: Argon2id (`golang.org/x/crypto/argon2`), 64 MiB memory,
  2 iterations, 1 thread, 32-byte key, **random 16-byte salt** per password.
  Stored as a PHC string (`$argon2id$v=19$m=...$<salt>$<key>`).
- **Legacy migration**: pre-1.1 hashes (double salted SHA-256) are still
  verified and transparently upgraded to Argon2id on the next successful login,
  so existing deployments are not locked out.
- **No hard-coded default credential**: if no password hash is configured, the
  API requires a first-run admin setup (`requires_setup=true`) instead of
  exposing a working default password. If the well-known default hash is still
  present, `config.Validate` refuses to bind a non-loopback listener.
- **Sessions**: rotated on every login (a fresh login invalidates prior tokens),
  expire after 12 hours, and are carried in an `HttpOnly`, `SameSite=Strict`
  cookie with `Secure` set when the request is HTTPS.
- **CSRF**: double-submit token + Origin/Referer same-origin check on all state
  mutating requests.
- **Login rate limit**: per-client-IP fixed window with a short lockout after
  repeated failures.

## Input validation

- API bodies are size-limited (`io.LimitReader`), JSON decoded with known
  schemas, and rejected on malformed input.
- Rules and config imports are validated before apply: unknown kinds/fields are
  rejected, and import goes through parse → validate → conflict detection →
  (dry-run) → atomic apply.
- Origin/Referer parsing (`allowedOrigin`) handles scheme-ful, port-less, and
  IPv6-literal values without panicking.

## Packet parser safety

- All packet parsing (`internal/pipeline`, `internal/detect`,
  `internal/nfq`) bounds-checks before indexing; malformed/truncated inputs
  return errors or are safely skipped rather than crashing.
- Detector plugins run under a `recover()` guard in `Registry.SafeInspect`, so a
  buggy detector can panic and be counted (`gfwx_detector_panics_total`)
  without taking down the data plane.
- NFQUEUE parsing only handles `NFQNL_MSG_PACKET` and rejects short / malformed
  netlink attributes.

## Privilege boundary

- **NFQUEUE mode requires root** (or `CAP_NET_ADMIN`) in order to open the
  netfilter netlink socket and bind a queue. `pcap` mode needs no privileges.
- The web dashboard binds loopback / LAN only by default. Bringing the listener
  off loopback while still using either the default hash or an unset password is
  blocked by config validation.
- The gateway that reads packets and the HTTP admin surface can be separated by
  putting the web listener behind an authenticated reverse proxy and keeping the
  `dataplane` on a dedicated interface.

## API exposure

- `/api/*` (except `/api/login` and `/api/health`) requires a valid session or
  bearer token; mutations additionally require a valid CSRF token.
- `/metrics` is **public** by design so Prometheus scrapers need no credentials,
  and `resource quotas` on label cardinality keep it bounded (never IPs,
  domains, or flow ids).
- Liveness probe `/api/health` is unauthenticated so health checks work.

## Default configuration

- Listens on `127.0.0.1:8443`.
- LAN-only origin enforcement by default (`server.lan_only`).
- Logging defaults to privacy-preserving: payloads are not stored, DNS/TLS
  plaintext is not logged, and exports default to redacting IPs.
- Detection defaults are conservative (`auto_action=observe`,
  `confidence_threshold=0.85`).

## Known limitations

- NFQUEUE IPv6 is not yet wired (IPv4 only); the `afINET6` family is reserved.
- The recent secret rotation is in-memory only; rotating the config
  `session_token` requires a restart. This is acceptable for a single-binary
  admin panel but should run behind a proper session store for multi-instance
  deployments.
- The first-run setup sets the password in memory; persist the resulting
  Argon2id `password_hash` back into your config so it survives restarts.
- Threat model assumes you own or are authorized to manage the network. The
  software refuses to deploy the well-known default admin credential on a
  non-loopback listener precisely to avoid accidental public exposure.