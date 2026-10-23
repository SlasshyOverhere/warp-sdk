package warp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config configures a Client. Zero values are usable: SOCKS binds an ephemeral
// loopback port, identity is registered on first Start and persisted in DataDir.
type Config struct {
	DataDir   string
	Identity  *Identity
	SOCKS     *netip.AddrPort
	HTTP      *netip.AddrPort
	Endpoints []string
	MTU       int
	License   string
	WarpPlus  bool
}

const (
	traceURL     = "https://www.cloudflare.com/cdn-cgi/trace"
	drainTimeout = 10 * time.Second
	scanBudget   = 20 * time.Second
)

// Stats is a snapshot of client state. EndpointRotations and IdentityRotations
// are the axes that actually produced a new egress IP.
type Stats struct {
	Endpoint          netip.AddrPort
	Uptime            time.Duration
	ActiveConns       int64
	TxBytes           uint64
	RxBytes           uint64
	LastRotateAxis    string
	EndpointRotations uint64
	FailedRotations   uint64
}

// Client owns the identity and the tunnels. It is safe for concurrent use.
type Client struct {
	cfg     Config
	dataDir string

	socksLn   net.Listener
	httpLn    net.Listener
	socksAddr netip.AddrPort
	httpAddr  netip.AddrPort

	idMu sync.RWMutex
	id   *Identity

	tunMu   sync.RWMutex
	tun     *tunnel
	tunnels []*tunnel

	scanMu sync.Mutex
	scanAt time.Time
	scanEP []Endpoint

	httpTr *http.Transport

	started atomic.Bool
	stopped atomic.Bool
	stopOne sync.Once
	done    chan struct{}
	active  atomic.Int64

	startedAt atomic.Int64 // unix nanos
	endpoint  atomic.Value // netip.AddrPort
	lastAxis  atomic.Value // string
	epRot     atomic.Uint64
	failRot   atomic.Uint64
}

// NewClient binds the local proxy listeners and prepares the data directory.
// No network calls happen here; registration and tunnel setup happen in Start.
func NewClient(cfg Config) (*Client, error) {
	c := &Client{cfg: cfg, done: make(chan struct{})}
	if cfg.DataDir == "" {
		dir, err := defaultDataDir()
		if err != nil {
			return nil, err
		}
		c.dataDir = dir
	} else {
		c.dataDir = cfg.DataDir
	}
	if err := os.MkdirAll(c.dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("warp: create data dir: %w", err)
	}

	socks := netip.MustParseAddrPort("127.0.0.1:0")
	if cfg.SOCKS != nil {
		socks = *cfg.SOCKS
	}
	ln, err := net.Listen("tcp", socks.String())
	if err != nil {
		return nil, fmt.Errorf("warp: listen socks: %w", err)
	}
	c.socksLn = ln
	if c.socksAddr, err = addrPortOf(ln.Addr()); err != nil {
		ln.Close()
		return nil, err
	}

	if cfg.HTTP != nil {
		hln, err := net.Listen("tcp", cfg.HTTP.String())
		if err != nil {
			ln.Close()
			return nil, fmt.Errorf("warp: listen http: %w", err)
		}
		c.httpLn = hln
		if c.httpAddr, err = addrPortOf(hln.Addr()); err != nil {
			ln.Close()
			hln.Close()
			return nil, err
		}
	}

	c.httpTr = &http.Transport{
		DialContext:         c.dial,
		ForceAttemptHTTP2:   false,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     90 * time.Second,
	}
	return c, nil
}

func defaultDataDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("warp: locate config dir: %w", err)
	}
	return filepath.Join(dir, "warpsdk"), nil
}

func addrPortOf(a net.Addr) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("warp: parse listener address %q: %w", a, err)
	}
	return ap, nil
}

// SOCKSAddr is the bound SOCKS5 address. Valid immediately after NewClient.
func (c *Client) SOCKSAddr() netip.AddrPort { return c.socksAddr }

// HTTPAddr is the bound HTTP proxy address, or the zero value when disabled.
func (c *Client) HTTPAddr() netip.AddrPort { return c.httpAddr }

// Identity returns the active WARP identity, or nil before Start.
func (c *Client) Identity() *Identity {
	c.idMu.RLock()
	defer c.idMu.RUnlock()
	return c.id
}

func (c *Client) setIdentity(id *Identity) {
	c.idMu.Lock()
	c.id = id
	c.idMu.Unlock()
}

// Start registers (or reloads) the identity, brings the tunnel up, serves the
// proxies and blocks until ctx is done or Stop is called.
func (c *Client) Start(ctx context.Context) error {
	if c.stopped.Load() {
		return errors.New("warp: client already stopped")
	}
	if !c.started.CompareAndSwap(false, true) {
		return errors.New("warp: client already started")
	}
	if err := c.bringUp(ctx); err != nil {
		c.started.Store(false)
		return err
	}
	c.startedAt.Store(time.Now().UnixNano())
	go c.serveSOCKS()
	if c.httpLn != nil {
		go c.serveHTTP()
	}
	select {
	case <-ctx.Done():
	case <-c.done:
	}
	return c.Stop()
}

func (c *Client) bringUp(ctx context.Context) error {
	id := c.cfg.Identity
	if id == nil {
		var err error
		id, err = loadOrRegisterIdentity(ctx, c.dataDir)
		if err != nil {
			return err
		}
	} else if err := id.Save(c.dataDir); err != nil {
		return fmt.Errorf("warp: persist identity: %w", err)
	}
	if c.cfg.License != "" && id.License != c.cfg.License {
		if err := id.SetLicense(ctx, c.cfg.License); err != nil {
			return fmt.Errorf("warp: apply license: %w", err)
		}
		if err := id.Save(c.dataDir); err != nil {
			return fmt.Errorf("warp: persist identity: %w", err)
		}
	}
	c.setIdentity(id)

	candidates := c.cfg.Endpoints
	if len(candidates) == 0 {
		candidates = []string{id.Endpoint}
	}
	var lastErr error
	for _, cand := range candidates {
		ep, err := resolveEndpoint(ctx, cand)
		if err != nil {
			lastErr = err
			continue
		}
		t, err := newTunnel(ctx, id, ep, c.cfg.MTU)
		if err != nil {
			lastErr = err
			continue
		}
		c.swapTunnel(t)
		c.endpoint.Store(ep)
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("warp: no endpoints configured")
	}
	return lastErr
}

// swapTunnel installs t and retires the old tunnel without closing connections
// that are still using it.
func (c *Client) swapTunnel(t *tunnel) {
	c.tunMu.Lock()
	old := c.tun
	c.tun = t
	if t != nil {
		c.tunnels = append(c.tunnels, t)
	}
	c.tunMu.Unlock()
	if old != nil && old != t {
		old.retire()
	}
}

func (c *Client) acquireTunnel() (*tunnel, func()) {
	c.tunMu.RLock()
	t := c.tun
	c.tunMu.RUnlock()
	if t == nil {
		return nil, func() {}
	}
	return t, t.acquire()
}

// dial connects through the current tunnel. The tunnel reference is held until
// the returned connection is closed.
func (c *Client) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	t, release := c.acquireTunnel()
	if t == nil {
		return nil, errNotStarted
	}
	conn, err := t.dial(ctx, network, addr)
	if err != nil {
		release()
		return nil, err
	}
	return &trackedConn{Conn: conn, release: release}, nil
}

type trackedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func (c *trackedConn) CloseWrite() error {
	err := error(nil)
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		err = cw.CloseWrite()
	}
	return err
}

// Stop stops accepting, drains in-flight connections (bounded), then closes the
// WireGuard devices.
func (c *Client) Stop() error {
	c.stopOne.Do(func() {
		c.stopped.Store(true)
		close(c.done)
		if c.socksLn != nil {
			c.socksLn.Close()
		}
		if c.httpLn != nil {
			c.httpLn.Close()
		}
		if c.httpTr != nil {
			c.httpTr.CloseIdleConnections()
		}
		deadline := time.Now().Add(drainTimeout)
		for c.active.Load() > 0 && time.Now().Before(deadline) {
			time.Sleep(25 * time.Millisecond)
		}
		c.tunMu.Lock()
		tuns := c.tunnels
		c.tun = nil
		c.tunnels = nil
		c.tunMu.Unlock()
		for _, t := range tuns {
			t.retire()
			t.close()
		}
	})
	return nil
}

// EgressIP returns the public IP the tunnel exits from.
func (c *Client) EgressIP(ctx context.Context) (netip.Addr, error) {
	t, release := c.acquireTunnel()
	if t == nil {
		return netip.Addr{}, errNotStarted
	}
	defer release()
	tr := &http.Transport{
		DialContext:       t.dial,
		ForceAttemptHTTP2: false,
	}
	hc := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, traceURL, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	req.Header.Set("User-Agent", warpUserAgent)
	resp, err := hc.Do(req)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("warp: egress lookup: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("warp: egress lookup: %w", err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if v, ok := strings.CutPrefix(line, "ip="); ok {
			ip, err := netip.ParseAddr(strings.TrimSpace(v))
			if err == nil {
				return ip, nil
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("warp: no ip= in trace response")
}

// SetEndpoint moves the tunnel to ep and waits for a handshake.
func (c *Client) SetEndpoint(ep Endpoint) error {
	ap := ep.AddrPort
	if ap.Port() == 0 {
		ap = netip.AddrPortFrom(ap.Addr(), 2408)
	}
	t, release := c.acquireTunnel()
	if t == nil {
		return errNotStarted
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), endpointHandshake+5*time.Second)
	defer cancel()
	if err := t.setEndpoint(ctx, ap); err != nil {
		return err
	}
	c.endpoint.Store(ap)
	return nil
}

// Stats returns a cheap snapshot; byte counters come from the WireGuard peer.
func (c *Client) Stats() Stats {
	ep, _ := c.endpoint.Load().(netip.AddrPort)
	axis, _ := c.lastAxis.Load().(string)
	s := Stats{
		Endpoint:          ep,
		ActiveConns:       c.active.Load(),
		LastRotateAxis:    axis,
		EndpointRotations: c.epRot.Load(),
		FailedRotations:   c.failRot.Load(),
	}
	if ns := c.startedAt.Load(); ns != 0 {
		s.Uptime = time.Since(time.Unix(0, ns))
	}
	if t, release := c.acquireTunnel(); t != nil {
		s.TxBytes, s.RxBytes = t.counters()
		release()
	}
	return s
}
