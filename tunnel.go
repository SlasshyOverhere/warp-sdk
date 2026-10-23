package warp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var (
	errNotStarted = errors.New("warp: client not started")
	errHandshake  = errors.New("warp: wireguard handshake timed out")
	// ErrNoNewEgress is returned by Rotate when no endpoint produced a new IP.
	ErrNoNewEgress    = errors.New("warp: no new egress IP found")
	handshakeTimeout  = 10 * time.Second
	endpointHandshake = 8 * time.Second
)

// tunnel is one WireGuard device plus its netstack. Its lifetime is refcounted
// so identity rotation never cuts live proxied connections.
type tunnel struct {
	dev     *device.Device
	net     *netstack.Net
	peerKey device.NoisePublicKey
	ep      atomic.Value // netip.AddrPort
	mu      sync.Mutex   // serialises endpoint changes
	refs    atomic.Int64
	retired atomic.Bool
	once    sync.Once
	started time.Time
}

func newDeviceLogger() *device.Logger {
	if os.Getenv("WARP_DEBUG") != "" {
		return device.NewLogger(device.LogLevelVerbose, "warp: ")
	}
	return device.NewLogger(device.LogLevelError, "warp: ")
}

func newTunnel(ctx context.Context, id *Identity, ep netip.AddrPort, mtu int) (*tunnel, error) {
	if mtu <= 0 {
		mtu = 1280
	}
	peerKey, err := noiseKeyFromB64(id.PeerPublicKey)
	if err != nil {
		return nil, err
	}
	addrs := []netip.Addr{id.AddressV4.Addr(), id.AddressV6.Addr()}
	dns := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")}
	tunDev, tnet, err := netstack.CreateNetTUN(addrs, dns, mtu)
	if err != nil {
		return nil, fmt.Errorf("warp: create netstack: %w", err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), newDeviceLogger())
	t := &tunnel{dev: dev, net: tnet, peerKey: peerKey, started: time.Now()}
	t.ep.Store(ep)

	cfg, err := id.uapi(ep)
	if err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.IpcSet(cfg); err != nil {
		dev.Close()
		return nil, fmt.Errorf("warp: configure device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("warp: bring device up: %w", err)
	}
	if _, err := t.waitHandshake(ctx, 0, handshakeTimeout); err != nil {
		dev.Close()
		return nil, fmt.Errorf("warp: handshake with %s: %w", ep, err)
	}
	return t, nil
}

func noiseKeyFromB64(s string) (device.NoisePublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	var k device.NoisePublicKey
	if err != nil || len(raw) != 32 {
		return k, fmt.Errorf("warp: bad peer public key")
	}
	copy(k[:], raw)
	return k, nil
}

func (t *tunnel) endpoint() netip.AddrPort {
	v, _ := t.ep.Load().(netip.AddrPort)
	return v
}

// dial runs a TCP connection through the WireGuard tunnel.
func (t *tunnel) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "", "tcp", "tcp4", "tcp6":
		return t.net.DialContext(ctx, "tcp", addr)
	default:
		return nil, fmt.Errorf("warp: unsupported network %q", network)
	}
}

// lookupHost resolves host through the tunnel's DNS (1.1.1.1/1.0.0.1).
func (t *tunnel) lookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	ips, err := t.net.LookupContextHost(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, s := range ips {
		if ip, err := netip.ParseAddr(s); err == nil {
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("warp: no address for %s", host)
	}
	return out, nil
}

// setEndpoint moves the peer to a new endpoint and forces a fresh handshake.
// In-flight connections survive: they live in netstack and retransmit.
func (t *tunnel) setEndpoint(ctx context.Context, ep netip.AddrPort) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	peerHex := make([]byte, 32)
	copy(peerHex, t.peerKey[:])
	cfg := fmt.Sprintf("public_key=%x\nendpoint=%s\n", peerHex, ep)
	if err := t.dev.IpcSet(cfg); err != nil {
		return fmt.Errorf("warp: set endpoint %s: %w", ep, err)
	}
	peer := t.dev.LookupPeer(t.peerKey)
	if peer == nil {
		return errors.New("warp: peer vanished")
	}
	peer.ExpireCurrentKeypairs()
	baseline, _ := t.handshakeNano()
	if _, err := t.waitHandshake(ctx, baseline, endpointHandshake); err != nil {
		return fmt.Errorf("warp: handshake with %s: %w", ep, err)
	}
	t.ep.Store(ep)
	return nil
}

func (t *tunnel) waitHandshake(ctx context.Context, baseline int64, timeout time.Duration) (time.Duration, error) {
	peer := t.dev.LookupPeer(t.peerKey)
	if peer == nil {
		return 0, errors.New("warp: peer not configured")
	}
	start := time.Now()
	if err := peer.SendHandshakeInitiation(true); err != nil {
		return 0, err
	}
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-deadline.C:
			return 0, errHandshake
		case <-tick.C:
			if n, err := t.handshakeNano(); err == nil && n > baseline {
				return time.Since(start), nil
			}
		}
	}
}

func (t *tunnel) handshakeNano() (int64, error) {
	s, err := t.dev.IpcGet()
	if err != nil {
		return 0, err
	}
	return parseHandshakeNano(s), nil
}

func parseHandshakeNano(s string) int64 {
	var sec, nsec int64
	for _, line := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
			sec, _ = strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		} else if v, ok := strings.CutPrefix(line, "last_handshake_time_nsec="); ok {
			nsec, _ = strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		}
	}
	if sec == 0 {
		return 0
	}
	return sec*int64(time.Second) + nsec
}

func (t *tunnel) counters() (tx, rx uint64) {
	s, err := t.dev.IpcGet()
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(line, "tx_bytes="); ok {
			n, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			tx += n
		} else if v, ok := strings.CutPrefix(line, "rx_bytes="); ok {
			n, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			rx += n
		}
	}
	return tx, rx
}

func (t *tunnel) acquire() func() {
	t.refs.Add(1)
	return func() {
		if t.refs.Add(-1) == 0 && t.retired.Load() {
			t.close()
		}
	}
}

func (t *tunnel) retire() {
	t.retired.Store(true)
	if t.refs.Load() == 0 {
		t.close()
	}
}

func (t *tunnel) close() {
	t.once.Do(func() { t.dev.Close() })
}

// resolveEndpoint accepts "ip", "ip:port", "host:port" or a bare host.
func resolveEndpoint(ctx context.Context, s string) (netip.AddrPort, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.AddrPort{}, errors.New("warp: empty endpoint")
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		if ap.Port() == 0 {
			ap = netip.AddrPortFrom(ap.Addr(), 2408)
		}
		return ap, nil
	}
	host, port := s, uint16(2408)
	if h, p, err := net.SplitHostPort(s); err == nil {
		host = h
		if n, err := strconv.ParseUint(p, 10, 16); err == nil {
			port = uint16(n)
		}
	}
	if ap, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ap, port), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("warp: resolve endpoint %s: %w", s, err)
	}
	// Prefer IPv4: WARP's WireGuard endpoints are v4-first.
	for _, ip := range ips {
		if ip.Is4() {
			return netip.AddrPortFrom(ip, port), nil
		}
	}
	return netip.AddrPortFrom(ips[0], port), nil
}
