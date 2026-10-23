# warpsdk — userspace Cloudflare WARP in Go

A standalone Go module that registers a Cloudflare WARP account, runs WireGuard
in-process over a gVisor netstack, and exposes local SOCKS5 and HTTP proxies.

No `warp-cli`, no `warp-svc`, no admin, no TUN device, no cgo, no route table
edits.

```go
import warp "github.com/warpsdk/warp"

c, err := warp.NewClient(warp.Config{DataDir: "./warp-data"})
if err != nil {
	return err
}
defer c.Stop()

// Start blocks until ctx is done; it registers (or reloads) the identity,
// brings the tunnel up and serves the proxies.
go c.Start(ctx)

log.Printf("socks5://%s", c.SOCKSAddr())
ip, err := c.EgressIP(ctx)
```

Point any SOCKS5 client at `c.SOCKSAddr()` (an ephemeral loopback port unless
you set `Config.SOCKS`). The HTTP proxy is enabled by setting `Config.HTTP`.

## What it does

1. **Identity.** `POST /reg` with a locally generated X25519 key, then persist
   the account document plus private key in `DataDir/identity.json` (0600).
   `GET /reg/{id}`, `PUT /reg/{id}/account` (license) and `DELETE /reg/{id}` are
   implemented as `Identity.Get`, `Identity.SetLicense` and `Identity.Delete`.
2. **Tunnel.** `golang.zx2c4.com/wireguard` `device` over
   `tun/netstack` (gVisor). Interface addresses/peer key come from the identity;
   MTU 1280, DNS 1.1.1.1/1.0.0.1, keepalive 25s, all traffic allowed. The
   resulting netstack dialer is the only egress path.
3. **Proxies.** SOCKS5 `CONNECT` + `UDP ASSOCIATE` (no auth) and, optionally,
   HTTP `CONNECT` + absolute-URI forwarding. Everything dials through netstack,
   so stopping the tunnel kills proxy traffic instead of leaking it direct.
4. **Endpoint scanner.** Enumerates Cloudflare's WARP CIDRs on port 2408 and
   performs a real WireGuard handshake against each address, keeping successes
   ranked by handshake RTT. Concurrency-capped (128), 20s default budget,
   results cached for five minutes.
5. **Rotation.** `Rotate` moves to a different handshake-verified endpoint,
   forces a re-handshake and re-checks `EgressIP`. Tunnels are refcounted, so
   in-flight proxied connections survive both endpoint moves and shutdown
   drains.

## Rotation axes — evidence

`Rotate` walks the ranked endpoint list and returns the first endpoint whose
egress IP differs from the old one. In the 20-run live check the endpoint axis
succeeded **20/20 times**, so the expensive "deregister + register a fresh
identity" axis was deleted instead of kept as dead weight. The identity API
calls remain public (`Register`, `Identity.Delete`, ...); a future provider that
blocks endpoint hopping can reintroduce an identity axis in `Rotate`.

`rotation_table.txt` is written by the live self-check with columns: run, axis,
old IP, new IP, changed, elapsed.

## API

```go
type Config struct {
	DataDir   string
	Identity  *Identity
	SOCKS     *netip.AddrPort // nil => 127.0.0.1:0 (ephemeral)
	HTTP      *netip.AddrPort // nil => disabled
	Endpoints []string        // initial/override endpoints, e.g. "162.159.192.1:2408"
	MTU       int             // default 1280
	License   string          // WARP+ license key, applied via the account API
	WarpPlus  bool            // documentation only; the license call is the only WARP+ feature
}

func NewClient(cfg Config) (*Client, error)
func (c *Client) SOCKSAddr() netip.AddrPort
func (c *Client) HTTPAddr() netip.AddrPort
func (c *Client) Start(ctx context.Context) error // blocks until ctx done or Stop
func (c *Client) Stop() error
func (c *Client) EgressIP(ctx context.Context) (netip.Addr, error)
func (c *Client) Endpoints(ctx context.Context) ([]Endpoint, error)
func (c *Client) SetEndpoint(ep Endpoint) error
func (c *Client) Rotate(ctx context.Context) (old, new netip.Addr, err error)
func (c *Client) Stats() Stats
```

`NewClient` binds the proxy listeners immediately, so `SOCKSAddr()` is valid
before `Start`. `Start` performs the network work.

`Stats` reports the active endpoint, uptime, active connections, tx/rx bytes
and the rotation counts (endpoint successes vs failures).

## TLS fingerprint

The WARP API is called with `crypto/tls` first; if the handshake is rejected it
retries the same request with a Chrome uTLS fingerprint. `WARP_TLS=std|utls`
pins one. `TestLiveSelfCheck/tls_dialers` exercises both.

## Limitations / risks

- **WireGuard only, no MASQUE.** Cloudflare is moving its consumer client to
  MASQUE. If the WireGuard ingress is retired for your account/colo, this
  library stops working; MASQUE support is deliberately out of scope.
- **Userspace only.** No TUN, no system routes, no packet capture: only traffic
  sent through the proxies is tunnelled. Other processes are unaffected.
- **Proxies have no authentication** and bind loopback by default. Binding them
  to a non-loopback address exposes an unauthenticated open proxy.
- **Free-tier quotas.** Registration is unauthenticated; abusing it is abusive.
  WARP+ needs `Config.License`.
- Endpoint discovery probes Cloudflare with handshakes. Keep the default budget
  and don't run it in a tight loop.

## Verification

```sh
go test ./...                        # offline: unit tests, no network
WARP_LIVE=1 go test -run TestLiveSelfCheck -v -timeout 45m
```

The live test registers an account, asserts the egress IP differs from the
host's direct IP, checks `warp=on` through SOCKS5 and HTTP, runs 20 rotations
and prints/writes the table, then asserts the proxy refuses connections after
`Stop`.

## Module path

The module is `github.com/warpsdk/warp`. Rename it in `go.mod` (and imports) if
you publish under a different path.
