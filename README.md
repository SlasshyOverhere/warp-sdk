# warp-sdk

[![Go Reference](https://pkg.go.dev/badge/github.com/SlasshyOverhere/warp-sdk/warp.svg)](https://pkg.go.dev/github.com/SlasshyOverhere/warp-sdk/warp)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A userspace Cloudflare WARP client for Go. Registers a WARP account, runs
WireGuard in-process over a gVisor netstack, and exposes local SOCKS5 and HTTP
proxies. No TUN device, no admin rights, no cgo, no route table edits.

> **Unofficial.** Not affiliated with, endorsed by, or supported by Cloudflare,
> Inc. "WARP" and "Cloudflare" are trademarks of Cloudflare, Inc., used here only
> to describe the service this library talks to. It registers real accounts
> against Cloudflare's API, so it is subject to Cloudflare's terms and you use it
> at your own risk.

## Install

```sh
go get github.com/SlasshyOverhere/warp-sdk/warp
```

## Usage

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

c, err := warp.NewClient(warp.Config{DataDir: "./warp-data"})
if err != nil {
	log.Fatal(err)
}
defer c.Stop()

go func() {
	if err := c.Start(ctx); err != nil {
		log.Printf("start: %v", err)
	}
}()

log.Printf("socks5 on %s", c.SOCKSAddr())
```

Point any SOCKS5 client at `c.SOCKSAddr()`. The listener is bound by
`NewClient`, so the address is known before `Start` finishes. Set `Config.HTTP`
to also serve an HTTP proxy.

`c.EgressIP(ctx)` returns the exit address. `c.Rotate(ctx)` moves to a different
handshake-verified ingress and re-checks the exit, refusing addresses it already
used unless `Config.EgressReuseWindow` allows it.

## Docs

Full API reference: [pkg.go.dev](https://pkg.go.dev/github.com/SlasshyOverhere/warp-sdk/warp).

Design rules, timeouts and invariants: [AGENTS.md](AGENTS.md).

## Limitations

- **WireGuard only.** No MASQUE. If Cloudflare retires WireGuard ingress for your
  account, this library stops working.
- **Userspace only.** Only traffic sent through the proxies is tunnelled.
- **No proxy authentication.** The proxies bind loopback; a non-loopback bind
  requires `Config.AllowRemote`.
- **Rotation disturbs live traffic.** Each rejected candidate moves the tunnel, so
  rotate with a pause rather than in a tight loop.
- **Free-tier quotas.** Registration is unauthenticated; abusing it is abusive.
  WARP+ needs `Config.License`.

## Security

`identity.json` holds an X25519 private key in plaintext, written 0600 in a 0700
directory. Windows does not enforce the mode, so there the protection is the
location of `DataDir`.

Report vulnerabilities privately through GitHub Security Advisories, not a public
issue.

## Contributing

`go build ./...`, `go vet ./...` and `go test ./...` must pass offline before a
change is done. Live suites need `WARP_LIVE=1` and real internet, and must never
run in CI. See [AGENTS.md](AGENTS.md) for the full contributor guide.

## License

[MIT](LICENSE)
