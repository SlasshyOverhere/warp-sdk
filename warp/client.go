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

type Config struct {
	DataDir           string
	Identity          *Identity
	SOCKS             *netip.AddrPort
	HTTP              *netip.AddrPort
	Endpoints         []string
	MTU               int
	License           string
	EgressReuseWindow int
	AllowRemote       bool
	OnSOCKSDial       func(target string, err error, took time.Duration)
}

var (
	ErrAlreadyStarted = errors.New("warp: client already started")
	ErrStopped        = errors.New("warp: client already stopped")
)

const (
	traceURL     = "https://www.cloudflare.com/cdn-cgi/trace"
	drainTimeout = 10 * time.Second
	scanBudget   = 20 * time.Second

	// Short on purpose: a stalled path retransmits on a 1s/2s/4s/8s backoff.
	traceTimeout  = 1800 * time.Millisecond
	traceAttempts = 5
)

type Stats struct {
	Endpoint          netip.AddrPort
	Uptime            time.Duration
	ActiveConns       int64
	TxBytes           uint64
	RxBytes           uint64
	EndpointRotations uint64
	FailedRotations   uint64
	RecentEgress      []netip.Addr
	UsedEgress        []netip.Addr
}

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

	startedAt atomic.Int64
	endpoint  atomic.Value
	epRot     atomic.Uint64
	failRot   atomic.Uint64

	recentMu     sync.Mutex
	recentEgress []netip.Addr
	usedEgress   []netip.Addr
	recentEP     []netip.AddrPort
	epEgress     map[netip.AddrPort]netip.Addr
}

func NewClient(cfg Config) (*Client, error) {
	if err := checkBind("socks", cfg.SOCKS, cfg.AllowRemote); err != nil {
		return nil, err
	}
	if err := checkBind("http", cfg.HTTP, cfg.AllowRemote); err != nil {
		return nil, err
	}
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

func checkBind(name string, ap *netip.AddrPort, allowRemote bool) error {
	if ap == nil || allowRemote || ap.Addr().IsLoopback() {
		return nil
	}
	return fmt.Errorf("warp: %s proxy would listen on non-loopback %s and has no authentication; set Config.AllowRemote to allow it", name, ap)
}

func addrPortOf(a net.Addr) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("warp: parse listener address %q: %w", a, err)
	}
	return ap, nil
}

func (c *Client) SOCKSAddr() netip.AddrPort { return c.socksAddr }

func (c *Client) HTTPAddr() netip.AddrPort { return c.httpAddr }

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

func (c *Client) Start(ctx context.Context) error {
	if c.stopped.Load() {
		return ErrStopped
	}
	if !c.started.CompareAndSwap(false, true) {
		return ErrAlreadyStarted
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

// Take the reference under the read lock: swapTunnel retires the old tunnel.
func (c *Client) acquireTunnel() (*tunnel, func()) {
	c.tunMu.RLock()
	defer c.tunMu.RUnlock()
	t := c.tun
	if t == nil {
		return nil, func() {}
	}
	return t, t.acquire()
}

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

func (c *Client) EgressIP(ctx context.Context) (netip.Addr, error) {
	return c.egressIP(ctx, 0)
}

func (c *Client) EgressIP4(ctx context.Context) (netip.Addr, error) {
	return c.egressIP(ctx, 4)
}

func (c *Client) EgressIP6(ctx context.Context) (netip.Addr, error) {
	return c.egressIP(ctx, 6)
}

func (c *Client) egressIP(ctx context.Context, family int) (netip.Addr, error) {
	t, release := c.acquireTunnel()
	if t == nil {
		return netip.Addr{}, errNotStarted
	}
	defer release()
	return egressIPVia(ctx, t, family)
}

func egressIPVia(ctx context.Context, t *tunnel, family int) (netip.Addr, error) {
	tr := &http.Transport{
		DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
			if family == 0 {
				return t.dial(dctx, network, addr)
			}
			return t.dialFamily(dctx, addr, family)
		},
		ForceAttemptHTTP2: false,
	}
	hc := &http.Client{Transport: tr, Timeout: traceTimeout}
	defer tr.CloseIdleConnections()
	var lastErr error
	for attempt := 0; attempt < traceAttempts; attempt++ {
		ip, err := traceEgressOnce(ctx, hc, family)
		if err == nil {
			return ip, nil
		}
		lastErr = err
		// A moved ingress can keep a valid keypair while dropping every packet.
		hctx, hcancel := context.WithTimeout(ctx, endpointHandshake)
		_ = t.rehandshake(hctx)
		hcancel()
		select {
		case <-ctx.Done():
			return netip.Addr{}, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 100 * time.Millisecond):
		}
	}
	return netip.Addr{}, lastErr
}

func traceEgressOnce(ctx context.Context, hc *http.Client, family int) (netip.Addr, error) {
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
		v, ok := strings.CutPrefix(line, "ip=")
		if !ok {
			continue
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(v))
		if err != nil {
			return netip.Addr{}, fmt.Errorf("warp: bad ip in trace: %w", err)
		}
		ip = ip.Unmap()
		switch family {
		case 4:
			if !ip.Is4() {
				return netip.Addr{}, fmt.Errorf("warp: IPv4 trace egress is %s", ip)
			}
		case 6:
			if !ip.Is6() || ip.Is4() {
				return netip.Addr{}, fmt.Errorf("warp: IPv6 trace egress is %s", ip)
			}
		}
		return ip, nil
	}
	return netip.Addr{}, fmt.Errorf("warp: no ip= in trace response")
}

func (c *Client) SetEndpoint(ep Endpoint) error {
	ctx, cancel := context.WithTimeout(context.Background(), endpointHandshake+5*time.Second)
	defer cancel()
	return c.setEndpoint(ctx, ep)
}

func (c *Client) setEndpoint(ctx context.Context, ep Endpoint) error {
	ap := ep.AddrPort
	if ap.Port() == 0 {
		ap = netip.AddrPortFrom(ap.Addr(), 2408)
	}
	t, release := c.acquireTunnel()
	if t == nil {
		return errNotStarted
	}
	defer release()
	err := t.setEndpoint(ctx, ap)
	c.endpoint.Store(t.endpoint())
	return err
}

func (c *Client) Stats() Stats {
	ep, _ := c.endpoint.Load().(netip.AddrPort)
	s := Stats{
		Endpoint:          ep,
		ActiveConns:       c.active.Load(),
		EndpointRotations: c.epRot.Load(),
		FailedRotations:   c.failRot.Load(),
	}
	c.recentMu.Lock()
	s.RecentEgress = append([]netip.Addr(nil), c.recentEgress...)
	s.UsedEgress = append([]netip.Addr(nil), c.usedEgress...)
	c.recentMu.Unlock()
	if ns := c.startedAt.Load(); ns != 0 {
		s.Uptime = time.Since(time.Unix(0, ns))
	}
	if t, release := c.acquireTunnel(); t != nil {
		s.TxBytes, s.RxBytes = t.counters()
		release()
	}
	return s
}
