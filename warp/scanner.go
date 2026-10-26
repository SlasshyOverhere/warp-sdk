package warp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type Endpoint struct {
	AddrPort netip.AddrPort
	RTT      time.Duration
}

const (
	scanConcurrency = 128
	maxScanResults  = 64
	probeTimeout    = 2 * time.Second
	scanCacheTTL    = 5 * time.Minute
)

var warpCIDRs = []string{
	"162.159.192.0/24",
	"162.159.193.0/24",
	"162.159.195.0/24",
	"162.159.204.0/24",
	"188.114.96.0/24",
	"188.114.97.0/24",
	"188.114.98.0/24",
	"188.114.99.0/24",
}

const scanPort = 2408

func (c *Client) Endpoints(ctx context.Context) ([]Endpoint, error) {
	c.scanMu.Lock()
	defer c.scanMu.Unlock()
	if len(c.scanEP) > 0 && time.Since(c.scanAt) < scanCacheTTL {
		return append([]Endpoint(nil), c.scanEP...), nil
	}
	id := c.Identity()
	if id == nil {
		return nil, errNotStarted
	}
	eps, err := scanEndpoints(ctx, id, c.cfg.Endpoints)
	if err != nil {
		return nil, err
	}
	eps = dedupeEndpoints(eps)
	c.scanEP = append([]Endpoint(nil), eps...)
	c.scanAt = time.Now()
	return eps, nil
}

func scanEndpoints(ctx context.Context, id *Identity, override []string) ([]Endpoint, error) {
	targets, err := scanTargets(ctx, override)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, errors.New("warp: no scan targets")
	}
	ctx, cancel := context.WithTimeout(ctx, scanBudget)
	defer cancel()

	var (
		mu   sync.Mutex
		eps  []Endpoint
		wg   sync.WaitGroup
		full atomic.Bool
		sem  = make(chan struct{}, scanConcurrency)
	)
targets:
	for _, ap := range targets {
		if full.Load() {
			break targets
		}
		select {
		case <-ctx.Done():
			break targets
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(ap netip.AddrPort) {
			defer wg.Done()
			defer func() { <-sem }()
			rtt, err := probeHandshake(ctx, id, ap)
			if err != nil {
				return
			}
			mu.Lock()
			eps = append(eps, Endpoint{AddrPort: ap, RTT: rtt})
			n := len(eps)
			mu.Unlock()
			if n >= maxScanResults {
				full.Store(true)
				cancel()
			}
		}(ap)
	}
	wg.Wait()
	sort.Slice(eps, func(i, j int) bool { return eps[i].RTT < eps[j].RTT })
	return eps, nil
}

func scanTargets(ctx context.Context, override []string) ([]netip.AddrPort, error) {
	out := make([]netip.AddrPort, 0, 2048)
	seen := make(map[netip.AddrPort]struct{}, 2048)
	add := func(ap netip.AddrPort) {
		if _, ok := seen[ap]; ok {
			return
		}
		seen[ap] = struct{}{}
		out = append(out, ap)
	}
	if len(override) > 0 {
		var firstErr error
		for _, o := range override {
			ap, err := resolveEndpoint(ctx, o)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			add(ap)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("warp: no endpoint override resolved: %w", firstErr)
		}
		return out, nil
	}
	if ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", "engage.cloudflareclient.com"); err == nil {
		for _, ip := range ips {
			add(netip.AddrPortFrom(ip, scanPort))
		}
	}
	for _, ap := range warpScanTargets() {
		add(ap)
	}
	return out, nil
}

func warpScanTargets() []netip.AddrPort {
	bases := make([][4]byte, 0, len(warpCIDRs))
	for _, cidr := range warpCIDRs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		bases = append(bases, p.Masked().Addr().As4())
	}
	out := make([]netip.AddrPort, 0, len(bases)*254)
	for i := 1; i < 255; i++ {
		for _, base := range bases {
			base[3] = byte(i)
			out = append(out, netip.AddrPortFrom(netip.AddrFrom4(base), scanPort))
		}
	}
	return out
}

func probeHandshake(ctx context.Context, id *Identity, ap netip.AddrPort) (time.Duration, error) {
	peerKey, err := noiseKeyFromB64(id.PeerPublicKey)
	if err != nil {
		return 0, err
	}
	cfg, err := id.uapi(ap)
	if err != nil {
		return 0, err
	}
	vt := newVoidTun()
	dev := device.NewDevice(vt, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	if err := dev.IpcSet(cfg); err != nil {
		return 0, err
	}
	if err := dev.Up(); err != nil {
		return 0, err
	}
	peer := dev.LookupPeer(peerKey)
	if peer == nil {
		return 0, errors.New("warp: probe peer missing")
	}
	start := time.Now()
	if err := peer.SendHandshakeInitiation(false); err != nil {
		return 0, err
	}
	pctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-pctx.Done():
			return 0, pctx.Err()
		case <-tick.C:
			s, err := dev.IpcGet()
			if err == nil && parseHandshakeNano(s) > 0 {
				return time.Since(start), nil
			}
		}
	}
}

type voidTun struct {
	events chan tun.Event
	closed chan struct{}
	once   sync.Once
}

func newVoidTun() *voidTun {
	return &voidTun{events: make(chan tun.Event), closed: make(chan struct{})}
}

func (v *voidTun) File() *os.File           { return nil }
func (v *voidTun) Events() <-chan tun.Event { return v.events }
func (v *voidTun) MTU() (int, error)        { return 1280, nil }
func (v *voidTun) Name() (string, error)    { return "warp-scan", nil }
func (v *voidTun) BatchSize() int           { return 1 }
func (v *voidTun) Write(bufs [][]byte, offset int) (int, error) {
	n := 0
	for _, b := range bufs {
		n += len(b) - offset
	}
	return n, nil
}

func (v *voidTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	<-v.closed
	return 0, os.ErrClosed
}

func (v *voidTun) Close() error {
	v.once.Do(func() {
		close(v.closed)
		close(v.events)
	})
	return nil
}
