# warp-sdk - userspace Cloudflare WARP in Go

**Unofficial, not affiliated with Cloudflare.** This is not an official
Cloudflare SDK and is not affiliated with, endorsed by, or supported by
Cloudflare, Inc. "WARP" and "Cloudflare" are trademarks of Cloudflare, Inc.,
used here only to describe the service this library talks to. It registers real
WARP accounts against Cloudflare's API, so it is subject to Cloudflare's terms
and you use it at your own risk.

A Go module that registers a Cloudflare WARP account, runs WireGuard in-process
over a gVisor netstack, and exposes local SOCKS5 and HTTP proxies.

No `warp-cli`, no `warp-svc`, no admin, no TUN device, no cgo, no route table
edits.

## Install

```sh
go get github.com/SlasshyOverhere/warp-sdk/warp
```

A minimal program:

```go
package main

import (
	"context"
	"log"
	"net/netip"
	"time"

	"github.com/SlasshyOverhere/warp-sdk/warp"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	httpAddr := netip.MustParseAddrPort("127.0.0.1:0")
	c, err := warp.NewClient(warp.Config{DataDir: "./warp-data", HTTP: &httpAddr})
	if err != nil {
		log.Fatal(err)
	}
	defer c.Stop()

	go func() {
		if err := c.Start(ctx); err != nil {
			log.Printf("start: %v", err)
		}
	}()

	var ip netip.Addr
	for until := time.Now().Add(time.Minute); !ip.IsValid() && time.Now().Before(until); {
		if ip, err = c.EgressIP(ctx); err != nil {
			time.Sleep(500 * time.Millisecond)
		}
	}
	log.Printf("socks5=%s http=%s egress=%s", c.SOCKSAddr(), c.HTTPAddr(), ip)
}
```

Point any SOCKS5 client at `c.SOCKSAddr()` (an ephemeral loopback port unless
you set `Config.SOCKS`). The HTTP proxy is enabled by setting `Config.HTTP`.

## What it does

1. **Identity.** `POST /reg` with a locally generated X25519 key, then persist
   the account document plus private key in `DataDir/identity.json` (0600).
   `GET /reg/{id}`, `PUT /reg/{id}/account` (license) and `DELETE /reg/{id}` are
   implemented as `Identity.Get`, `Identity.SetLicense` and `Identity.Delete`.
2. **Tunnel.** `golang.zx2c4.com/wireguard` `device` over
   `tun/netstack` (gVisor). Interface addresses and peer key come from the
   identity; MTU 1280, DNS 1.1.1.1/1.0.0.1, keepalive 25s, all traffic allowed.
   The resulting netstack dialer is the only egress path.
3. **Proxies.** SOCKS5 `CONNECT` + `UDP ASSOCIATE` (no auth) and, optionally,
   HTTP `CONNECT` + absolute-URI forwarding. Everything dials through netstack,
   so stopping the tunnel kills proxy traffic instead of leaking it direct.
4. **Endpoint scanner.** Enumerates Cloudflare's WARP CIDRs on port 2408 and
   performs a real WireGuard handshake against each address, keeping successes
   ranked by handshake RTT. Concurrency-capped (128), 20s default budget, at
   most 64 results, cached for five minutes.
5. **Rotation.** `Rotate` moves to a different handshake-verified endpoint,
   forces a re-handshake and re-checks the egress address. Tunnels are
   refcounted, so in-flight proxied connections survive both endpoint moves and
   shutdown drains.

## Rotation

`Rotate` rotates the family the upstream actually observes (IPv6 when
dual-stack, falling back to any). It visits the **full verified endpoint pool**
from a random starting point, not just the nearest pair:

- endpoints are deduped by `ip:port`;
- endpoints cached to an unused exit are tried first, then unseen endpoints,
  then endpoints known to yield an already-used exit;
- **every exit still inside the reuse window is refused**
  (`Stats.UsedEgress`), so `Rotate` does not return a previously used address;
  with the default `Config.EgressReuseWindow` of 0 that means every exit this
  client has ever rotated to. When the pool is exhausted it reports
  `ErrNoNewEgress` instead of repeating. `Stats.RecentEgress` still shows the
  last 5 for a quick view;
- the last 8 endpoints are avoided, and each rotation starts at a random offset,
  so consecutive rotations do not walk back onto the same ingress;
- a verified pool smaller than 3 distinct endpoints is refused with
  `ErrNoNewEgress` instead of reporting a ping-pong cycle as rotation;
- the whole walk is bounded by `rotationBudget` (10s) and each candidate by
  `candidateProbeTimeout` (3s), so one dead ingress cannot eat the walk;
  budget expiry returns `ErrNoNewEgress`. Ingresses that failed a handshake or
  trace, and endpoints cached to an already-used exit, are parked at the back
  of later walks;
- a failed walk restores the ingress it started from (with its own context,
  since the caller's is what expired), so `ErrNoNewEgress` means "unchanged",
  not "possibly pointing at a dead ingress".

Each egress check is capped at 1.8s (`traceTimeout`) with 5 attempts and a
rehandshake between them. A healthy WARP trace answers well under a second,
while a stalled path retransmits on a 1s/2s/4s/8s backoff, so a generous cap
would let one stalled attempt own the whole operation.

The live self-check writes the rotation table (committed as
`docs/rotation_table.txt`): 20 runs, random start, strict lifetime uniqueness.
It ends with the distinct-address count, the reused-address count (must be 0)
and the sequence cycle length, then a measured IPv4 pinning section: five
endpoint swaps and five fresh `Register` calls. In that measurement every IPv4
row was the same address, which is why there is no identity axis: a second axis
cannot move pinned IPv4. IPv6 rotation, which is what the upstream observes, is
handled by endpoints.

The identity API calls remain public (`Register`, `Identity.Delete`, and so on).

## API

```go
type Config struct {
	DataDir           string
	Identity          *Identity
	SOCKS             *netip.AddrPort // nil => 127.0.0.1:0 (ephemeral loopback)
	HTTP              *netip.AddrPort // nil => HTTP proxy disabled
	Endpoints         []string        // scan targets, e.g. "162.159.192.1:2408"
	MTU               int             // default 1280
	License           string          // WARP+ license key, applied via the account API
	EgressReuseWindow int             // exits may be reused after this many later exits; 0 = never
	AllowRemote       bool            // permit non-loopback proxy binds; proxies have no auth
	OnSOCKSDial       func(target string, err error, took time.Duration)
}

type Stats struct {
	Endpoint          netip.AddrPort
	Uptime            time.Duration
	ActiveConns       int64
	TxBytes           uint64
	RxBytes           uint64
	EndpointRotations uint64
	FailedRotations   uint64
	RecentEgress      []netip.Addr // last 5 rotated-to exits
	UsedEgress        []netip.Addr // exits still refused by Rotate
}

type Endpoint struct {
	AddrPort netip.AddrPort
	RTT      time.Duration
}

var (
	ErrAlreadyStarted = errors.New("warp: client already started")
	ErrStopped        = errors.New("warp: client already stopped")
	ErrNoNewEgress    = errors.New("warp: no new egress IP found")
)

func NewClient(cfg Config) (*Client, error)
func (c *Client) SOCKSAddr() netip.AddrPort
func (c *Client) HTTPAddr() netip.AddrPort
func (c *Client) Identity() *Identity
func (c *Client) Start(ctx context.Context) error
func (c *Client) Stop() error
func (c *Client) EgressIP(ctx context.Context) (netip.Addr, error)  // any / dual-stack
func (c *Client) EgressIP4(ctx context.Context) (netip.Addr, error) // force IPv4
func (c *Client) EgressIP6(ctx context.Context) (netip.Addr, error) // force IPv6
func (c *Client) Endpoints(ctx context.Context) ([]Endpoint, error)
func (c *Client) SetEndpoint(ep Endpoint) error
func (c *Client) Rotate(ctx context.Context) (old, next netip.Addr, err error)
func (c *Client) Stats() Stats

func Register(ctx context.Context) (*Identity, error)
func LoadIdentity(dir string) (*Identity, error)
func (id *Identity) Get(ctx context.Context) error
func (id *Identity) SetLicense(ctx context.Context, license string) error
func (id *Identity) Delete(ctx context.Context) error
func (id *Identity) Save(dir string) error
```

`NewClient` creates `DataDir` (0700) and binds the proxy listeners
immediately, so `SOCKSAddr()` is valid before `Start`. An empty `DataDir`
defaults to `os.UserConfigDir()/warpsdk`. `Start` performs the network work:
it loads or registers an identity (or uses `Config.Identity` and saves it),
applies `Config.License`, brings up the tunnel and serves the proxies. It
returns `ErrAlreadyStarted` if called twice and `ErrStopped` after `Stop`;
otherwise it blocks until `ctx` is done or `Stop` is called.

`EgressIP` keeps the original any-family behaviour; `EgressIP4`/`EgressIP6`
force a family (the trace host is resolved through netstack, then dialed on that
family; a mismatched trace answer is an error).

`Stats` reports the active endpoint, uptime, active connections, tx/rx bytes,
rotation counts (endpoint successes vs failures) and the bounded
`RecentEgress`/`UsedEgress` windows.

A non-loopback `Config.SOCKS` or `Config.HTTP` is rejected by `NewClient`
unless `Config.AllowRemote` is set. Calls made before `Start` return an
unexported "not started" error.

## TLS fingerprint

The WARP API is called with `crypto/tls` first; if the handshake is rejected it
retries the same request with a Chrome uTLS fingerprint. `WARP_TLS=std|utls`
pins one. `TestLiveSelfCheck/tls_dialers` exercises both.

## Limitations

- **WireGuard only, no MASQUE.** Cloudflare is moving its consumer client to
  MASQUE. If the WireGuard ingress is retired for your account/colo, this
  library stops working; MASQUE support is deliberately out of scope.
- **Userspace only.** No TUN, no system routes, no packet capture: only traffic
  sent through the proxies is tunnelled. Other processes are unaffected.
- **Proxies have no authentication** and bind loopback by default. See Security.
- **Free-tier quotas.** Registration is unauthenticated; abusing it is abusive.
  WARP+ needs `Config.License`.
- Endpoint discovery probes Cloudflare with handshakes. Keep the default budget
  and do not run it in a tight loop.
- **Continuous rotation disturbs live proxied traffic.** Every rejected candidate
  moves the tunnel and expires the current keypair, so under back-to-back
  rotations new and in-flight proxy requests can stall. The committed stress
  reports show 9 of 33 proxied requests timing out (27%) at 4 concurrent request
  loops, and none with the load disabled; the errors are client timeouts and the
  tunnel stays healthy. Rotate with a pause in between, or treat a rotation as a
  brief maintenance window, until candidate probing is isolated from the live
  tunnel.

## Security

The local proxies are unauthenticated and loopback-only by design.
`Config.AllowRemote` exists for callers who really want a non-loopback bind, and
turning it on exposes an open proxy to that network.

`identity.json` holds an X25519 private key in plaintext. It is written 0600 in
a 0700 directory, but Windows does not enforce the mode, so there the
protection is the location of `DataDir`.

Report vulnerabilities privately through GitHub Security Advisories on this
repository, not in a public issue.

## Verification

```sh
go build ./...
go vet ./...
go test ./...                        # offline: unit tests, no network
WARP_LIVE=1 go test -run TestLiveSelfCheck -v -timeout 45m
```

The live test registers an account, asserts the egress IP differs from the
host's direct IP, checks `warp=on` through SOCKS5 and HTTP, runs 20 rotations
and writes the table, then asserts the proxy refuses connections after `Stop`.

Rotation stress / benchmark (latency percentiles + concurrent proxy load):

```sh
WARP_LIVE=1 go test -run TestLiveRotationStress -v -timeout 30m
# env: WARP_STRESS_N=30  WARP_STRESS_LOAD=4  WARP_STRESS_KEEPALIVE=1
#      WARP_STRESS_REPORT=<path>
```

Reports are written to `docs/stress_report.txt` (or `WARP_STRESS_REPORT`). The
committed evidence lives in `docs/`: `rotation_table.txt`, `stress_report.txt`,
`stress_idle.txt` and `stress_keepalive.txt`. They are historical output, not
inputs, and a local run should write to a temp path.

## Contributing

`go build ./...`, `go vet ./...` and `go test ./...` must pass offline before a
change is done. Live suites need `WARP_LIVE=1` and a real network, and must
never run in CI. In PowerShell, prefix with `$env:WARP_LIVE="1";`.

Comments are stripped by policy: default to none, and allow at most one short
line where the why is non-obvious.

## License

MIT, see [LICENSE](LICENSE).
