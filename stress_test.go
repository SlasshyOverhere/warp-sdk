package warp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"text/tabwriter"
	"time"

	"golang.org/x/net/proxy"
)

func TestLiveRotationStress(t *testing.T) {
	if os.Getenv("WARP_LIVE") != "1" {
		t.Skip("set WARP_LIVE=1 to run the live rotation stress test")
	}
	attempts := envInt("WARP_STRESS_N", 30)
	loadWorkers := 4
	if v := os.Getenv("WARP_STRESS_LOAD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			loadWorkers = n
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()

	id, err := Register(ctx)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	c, err := NewClient(Config{DataDir: t.TempDir(), Identity: id})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	startErr := make(chan error, 1)
	go func() { startErr <- c.Start(ctx) }()

	deadline := time.Now().Add(90 * time.Second)
	for {
		if _, err := c.EgressIP6(ctx); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("tunnel did not come up in 90s")
		}
		time.Sleep(500 * time.Millisecond)
	}
	socks := c.SOCKSAddr()

	sd, err := proxy.SOCKS5("tcp", socks.String(), nil, proxy.Direct)
	if err != nil {
		t.Fatalf("socks dialer: %v", err)
	}
	cd, ok := sd.(proxy.ContextDialer)
	if !ok {
		t.Fatal("socks dialer has no DialContext")
	}
	keepAlive := os.Getenv("WARP_STRESS_KEEPALIVE") == "1"
	tr := &http.Transport{
		DialContext:         cd.DialContext,
		DisableKeepAlives:   !keepAlive,
		ForceAttemptHTTP2:   false,
		MaxIdleConnsPerHost: 0,
	}
	hc := &http.Client{Transport: tr, Timeout: 25 * time.Second}

	lctx, lcancel := context.WithCancel(ctx)
	var (
		reqOK, reqErr atomic.Int64
		latMu         sync.Mutex
		reqLat        []time.Duration
		errMu         sync.Mutex
		errKinds      = map[string]int{}
	)
	recordErr := func(err error) {
		if lctx.Err() != nil {
			return
		}
		reqErr.Add(1)
		errMu.Lock()
		errKinds[err.Error()]++
		errMu.Unlock()
	}
	var wg sync.WaitGroup
	for i := 0; i < loadWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for lctx.Err() == nil {
				start := time.Now()
				req, err := http.NewRequestWithContext(lctx, http.MethodGet, traceURL, nil)
				if err != nil {
					return
				}
				resp, err := hc.Do(req)
				if err != nil {
					recordErr(err)
					continue
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "warp=on") {
					recordErr(fmt.Errorf("http %d / warp off", resp.StatusCode))
					continue
				}
				reqOK.Add(1)
				latMu.Lock()
				reqLat = append(reqLat, time.Since(start))
				latMu.Unlock()
			}
		}()
	}

	type row struct {
		n     int
		took  time.Duration
		old   netip.Addr
		fresh netip.Addr
		axis  string
		err   error
	}
	rows := make([]row, 0, attempts)
	stressStart := time.Now()
	exhaustedAt := 0
	for i := 1; i <= attempts; i++ {
		rctx, rcancel := context.WithTimeout(ctx, 30*time.Second)
		start := time.Now()
		old, fresh, err := c.Rotate(rctx)
		rcancel()
		axis := "endpoint"
		rows = append(rows, row{n: i, took: time.Since(start), old: old, fresh: fresh, axis: axis, err: err})
		if err != nil {
			if errors.Is(err, ErrNoNewEgress) {
				exhaustedAt = i
				break
			}
			continue
		}
	}
	stressTook := time.Since(stressStart)
	lcancel()
	wg.Wait()
	tr.CloseIdleConnections()

	var okLat, allLat []time.Duration
	var okRows, failRows []row
	used := make(map[string]struct{})
	if len(rows) > 0 {
		used[rows[0].old.String()] = struct{}{}
	}
	reused := 0
	for _, r := range rows {
		allLat = append(allLat, r.took)
		if r.err != nil {
			failRows = append(failRows, r)
			continue
		}
		okRows = append(okRows, r)
		okLat = append(okLat, r.took)
		if _, seen := used[r.fresh.String()]; seen {
			reused++
		}
		used[r.fresh.String()] = struct{}{}
	}
	latMu.Lock()
	reqLatCopy := append([]time.Duration(nil), reqLat...)
	latMu.Unlock()

	var sb strings.Builder
	fmt.Fprintf(&sb, "rotation stress: %d attempts, %d load workers, %s total\n", len(rows), loadWorkers, stressTook.Round(time.Millisecond))
	fmt.Fprintf(&sb, "success=%d failed=%d reused=%d distinct=%d exhausted_at=%d\n",
		len(okRows), len(failRows), reused, len(okRows)-reused, exhaustedAt)
	fmt.Fprintf(&sb, "rotation latency success: %s\n", durStats(okLat))
	fmt.Fprintf(&sb, "rotation latency all:     %s\n", durStats(allLat))
	okReq, badReq := reqOK.Load(), reqErr.Load()
	rate := 0.0
	if okReq+badReq > 0 {
		rate = float64(badReq) / float64(okReq+badReq) * 100
	}
	fmt.Fprintf(&sb, "proxy load: %d ok, %d errors (%.2f%%), latency %s\n", okReq, badReq, rate, durStats(reqLatCopy))
	errMu.Lock()
	for kind, n := range errKinds {
		fmt.Fprintf(&sb, "  error x%d: %s\n", n, kind)
	}
	errMu.Unlock()

	if len(okRows) > 0 {
		tw := tabwriter.NewWriter(&sb, 2, 8, 2, ' ', 0)
		fmt.Fprintln(tw, "\n#\telapsed\told IP\tnew IP")
		for _, r := range rows {
			res := r.fresh.String()
			if r.err != nil {
				res = "FAILED: " + r.err.Error()
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", r.n, r.took.Round(time.Millisecond), r.old, res)
		}
		tw.Flush()
	}

	ip, err := c.EgressIP6(ctx)
	fmt.Fprintf(&sb, "\ntunnel healthy after stress: egress=%v err=%v\n", ip, err)
	t.Logf("\n%s", sb.String())
	report := os.Getenv("WARP_STRESS_REPORT")
	if report == "" {
		report = "stress_report.txt"
	}
	if err := os.WriteFile(report, []byte(sb.String()), 0o644); err != nil {
		t.Logf("write stress report: %v", err)
	}

	if len(okRows) < 5 {
		t.Fatalf("only %d successful rotations", len(okRows))
	}
	if reused != 0 {
		t.Fatalf("%d rotations returned a previously used address", reused)
	}
	if err != nil {
		t.Fatalf("tunnel unhealthy after stress: %v", err)
	}

	if err := c.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	cancel()
	select {
	case err := <-startErr:
		if err != nil {
			t.Logf("Start returned: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func durStats(ds []time.Duration) string {
	if len(ds) == 0 {
		return "n/a"
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	var sum time.Duration
	for _, d := range s {
		sum += d
	}
	pct := func(p float64) time.Duration {
		idx := int(float64(len(s)-1) * p)
		return s[idx]
	}
	return fmt.Sprintf("mean=%s p50=%s p90=%s p99=%s min=%s max=%s (n=%d)",
		(sum / time.Duration(len(s))).Round(time.Millisecond),
		pct(0.50).Round(time.Millisecond), pct(0.90).Round(time.Millisecond), pct(0.99).Round(time.Millisecond),
		s[0].Round(time.Millisecond), s[len(s)-1].Round(time.Millisecond), len(s))
}
