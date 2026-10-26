# AGENTS.md

Canonical contributor guide for this repository. `CLAUDE.md` defers to this file.

## What this is

`warp-sdk` (Go package `warp`) is a userspace Cloudflare WARP client. It
registers a WARP account, runs WireGuard in-process over a gVisor netstack and
exposes local SOCKS5 and HTTP proxies, so a host application can route traffic
through WARP without a TUN device, cgo, admin rights or route table edits. It is
an UNOFFICIAL SDK: not affiliated with, endorsed by or supported by Cloudflare.
"WARP" and "Cloudflare" are trademarks of Cloudflare, Inc.

## Layout

- `api.go`: the WARP API client (`https://api.cloudflareclient.com/v0a1922`),
  the `CF-Client-Version` and user agent constants, `apiError`, and the TLS
  dialer that tries `crypto/tls` then retries with a Chrome uTLS fingerprint.
- `identity.go`: `Identity`, X25519 key generation, registration against
  `POST /reg`, refresh/license/delete, the persisted `identity.json` document
  (0600, atomic rename) and the WireGuard UAPI config string.
- `client.go`: the `Client` facade, `Config`, `Stats`, listener binding and
  `checkBind`, start/stop, tunnel refcounting and `dial`, and the egress trace
  lookup with its retry and rehandshake policy.
- `tunnel.go`: one WireGuard device plus netstack (`newTunnel`), handshake
  waiting, endpoint moves and rehandshakes, byte counters, refcounted
  acquire/retire/close, and endpoint string resolution.
- `rotate.go`: `Rotate`, the rotation budget, the recent-egress and
  recent-endpoint windows, the ordering heuristic and the failed-walk restore.
- `scanner.go`: `Endpoint`, the Cloudflare ingress CIDR sweep, concurrent
  handshake probing against a void TUN, and the short-lived scan cache.
- `socks5.go`: the SOCKS5 server, CONNECT relay, UDP associate relay with
  per-destination upstream sockets, and the optional `OnSOCKSDial` hook.
- `httpproxy.go`: the HTTP proxy, `CONNECT` tunnelling plus plain forward
  proxying, and hop-by-hop header stripping.
- `*_test.go`: offline unit tests for pure functions; `selfcheck_test.go` and
  `stress_test.go` are the live suites gated on `WARP_LIVE=1`.
- `rotation_table.txt`, `stress_idle.txt`, `stress_keepalive.txt`,
  `stress_report.txt`: committed live-run evidence. Historical, not inputs.

## Build and verify

```powershell
go build ./...
go vet ./...
go test ./...
```

`go test ./...` is fully offline: no network, no account, no tunnel. It must
always pass, and a change is not done until it does.

Live suites talk to the real WARP API, register real accounts and need working
internet. They must never run in CI.

```powershell
$env:WARP_LIVE="1"; go test -run TestLiveSelfCheck -v -timeout 45m
$env:WARP_LIVE="1"; go test -run TestLiveRotationStress -v -timeout 30m
```

Live environment variables:

- `WARP_LIVE=1`: enables both suites. Anything else skips them.
- `WARP_STRESS_N`: rotation attempts, default 30.
- `WARP_STRESS_LOAD`: parallel proxied request loops, default 4.
- `WARP_STRESS_KEEPALIVE=1`: reuses proxy connections during stress.
- `WARP_STRESS_REPORT`: report path, default `stress_report.txt` at the repo
  root. Point it at a temp path unless you intend to update the committed
  evidence.
- `WARP_TLS=std|utls`: pins one TLS dialer instead of try-then-retry.
- `WARP_DEBUG=1`: verbose WireGuard device logging.

## Invariants

- **Tunnels are refcounted, and the reference is taken under `tunMu`'s read
  lock.** `swapTunnel` retires the old device while holding the write lock;
  taking the reference after unlocking can land on a tunnel that was already
  retired and closed, and the dial dies mid-handshake. Keep `t.acquire()` inside
  the critical section in `acquireTunnel`.
- **`Rotate` never reports an egress inside the reuse window, and restores the
  starting ingress when the walk fails.** The pre-rotation egress is recorded as
  used before the walk, so returning to it counts as a repeat. If every
  candidate is rejected, `restoreEndpoint` puts the device back where it started
  rather than leaving it on an ingress that failed its handshake.
- **The whole `Rotate` walk is bounded by one `rotationBudget` deadline.** Each
  probe and each egress lookup derives from that context with
  `candidateProbeTimeout`. The single deliberate exception is `restoreEndpoint`,
  which uses its own short context because the budget is normally spent by the
  time the walk fails. Do not introduce a second independent deadline: an
  unbounded walk over a 64-endpoint pool stalls the caller for minutes.
- **All proxied payload traffic dials through the netstack.** Use `tunnel.dial`
  or `dialFamily`, reached through `Client.dial`. A direct `net.Dial` on the
  proxy path is a leak: it leaves from the host's real address and defeats the
  feature. Direct dials exist only for bootstrap: the WARP API client, endpoint
  resolution in `resolveEndpoint`, and the loopback UDP socket a SOCKS5 UDP
  association binds for its own client.
- **The proxies bind loopback unless `Config.AllowRemote` is set.** `checkBind`
  rejects a non-loopback address otherwise, because the proxies have no
  authentication. Do not weaken this check.
- **`identity.json` holds an X25519 private key in plaintext and stays 0600** in
  a 0700 directory, written to a temp file and renamed. Windows does not enforce
  the mode, so there the protection is the location of `DataDir`.
- **No cgo, no TUN device, no admin rights, no route table edits.** This is the
  reason the library is portable and embeddable; a change that needs any of them
  is a different project.
- **Never commit account material or generated reports.** `warp-data/` and
  `identity.json` are credentials and are ignored. The evidence files already at
  the repo root are deliberate; do not add new ones.

## Code style

- Comments are stripped by policy. Default to none. Where the why is genuinely
  non-obvious and a future reader could reintroduce a bug, allow at most one
  short line of about 12 words.
- No banner comments, no section headers, no restating what the code says.
- `gofmt` always. Run it before claiming a change is done.
- Errors are wrapped with `%w` and prefixed `warp:`. Sentinel errors stay
  comparable with `errors.Is`.
- Prose in comments and docs uses plain punctuation. No em dashes.
- Offline tests are table-driven and cover pure functions. Anything needing a
  socket or an account belongs in the live suites.

## Extending

### A new rotation axis

`Rotate` currently has one axis: the ingress endpoint. The comment in
`rotate.go` records why a second identity axis was dropped (it cannot move the
pinned IPv4 egress). If you add an axis anyway, it must run inside the same
`rotationBudget` context, report through `noteRotation`, and respect
`egressUsed` before it returns, otherwise the no-repeat guarantee breaks.

### A new proxy type

Add a `Config` field, bind it in `NewClient` through `checkBind`, serve it from
`Start`, count connections in `c.active`, close the listener in `Stop`, and dial
every upstream through `c.dial`. Never dial directly, and never bind a
non-loopback address without the existing `AllowRemote` opt-in.

### Changing the WARP API version

`cfClientVersion` and `apiBase` live at the top of `api.go`. The register
endpoint is lenient today, but a version it does not recognise can be rejected.
Re-confirm any bump with a live registration before merging:

```powershell
$env:WARP_LIVE="1"; go test -run TestLiveSelfCheck -v -timeout 45m
```

### Per-attempt timeouts

They are short on purpose. A healthy WARP trace answers in well under a second,
and a stalled path retransmits on a 1s/2s/4s/8s backoff, so a generous cap lets
one stalled attempt own the whole operation.

- `rotationBudget` (10s, `rotate.go`): the entire `Rotate` call.
- `candidateProbeTimeout` (3s, `rotate.go`): one ingress move, handshake plus
  trace.
- `traceTimeout` (1.8s) and `traceAttempts` (5, `client.go`): one egress trace,
  with a rehandshake between failures.
- `endpointHandshake` (8s, `tunnel.go`): handshake after an endpoint change or a
  rehandshake.
- `handshakeTimeout` (10s, `tunnel.go`): initial device bring-up.
- `probeTimeout` (2s, `scanner.go`) and `scanBudget` (20s, `client.go`): one
  scan probe and the whole scan.

## Out of scope

Deliberately not implemented, and not a bug report:

- MASQUE. This library speaks WireGuard only.
- TUN devices and system-wide routing.
- Proxy authentication. The proxies are loopback-only and unauthenticated by
  design; `AllowRemote` is the explicit escape hatch.

## License

MIT, see `LICENSE`.
