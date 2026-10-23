package warp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"text/tabwriter"
	"time"
)

// TestLiveSelfCheck is the evidence run. It is gated on WARP_LIVE=1 because it
// talks to the real WARP API and expects real internet access.
//
//	WARP_LIVE=1 go test -run TestLiveSelfCheck -v -timeout 45m
func TestLiveSelfCheck(t *testing.T) {
	if os.Getenv("WARP_LIVE") != "1" {
		t.Skip("set WARP_LIVE=1 to run the live WARP self-check")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()

	// 1. Register, assert fields, persist and reload.
	directIP := hostEgressIP(t)
	t.Logf("host direct egress IP: %s", directIP)

	id, err := Register(ctx)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if id.ID == "" || id.Token == "" || id.PeerPublicKey == "" ||
		!id.AddressV4.IsValid() || !id.AddressV6.IsValid() || id.Endpoint == "" {
		t.Fatalf("registration incomplete: %+v", id)
	}
	t.Logf("registered id=%s endpoint=%s v4=%s v6=%s", id.ID, id.Endpoint, id.AddressV4, id.AddressV6)

	dir := t.TempDir()
	if err := id.Save(dir); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	reloaded, err := LoadIdentity(dir)
	if err != nil {
		t.Fatalf("reload identity: %v", err)
	}
	if reloaded.ID != id.ID || reloaded.PrivateKey != id.PrivateKey || reloaded.Token != id.Token {
		t.Fatal("identity did not round-trip through disk")
	}

	t.Run("tls_dialers", func(t *testing.T) {
		os.Setenv("WARP_TLS", "std")
		stdErr := newAPI(id.Token).request(ctx, http.MethodGet, "/reg/"+id.ID, nil, &registrationDoc{})
		if stdErr != nil {
			t.Logf("crypto/tls rejected (%v); retrying with uTLS", stdErr)
		}
		os.Setenv("WARP_TLS", "utls")
		defer os.Unsetenv("WARP_TLS")
		if err := newAPI(id.Token).request(ctx, http.MethodGet, "/reg/"+id.ID, nil, &registrationDoc{}); err != nil {
			t.Fatalf("uTLS dialer failed: %v", err)
		}
	})

	// 2. Start the tunnel and verify the egress IP changed.
	httpAddr := netip.MustParseAddrPort("127.0.0.1:0")
	c, err := NewClient(Config{DataDir: dir, Identity: id, HTTP: &httpAddr})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	startErr := make(chan error, 1)
	go func() { startErr <- c.Start(ctx) }()

	var egress netip.Addr
	deadline := time.Now().Add(90 * time.Second)
	for {
		if ip, err := c.EgressIP(ctx); err == nil {
			egress = ip
			break
		}
		select {
		case err := <-startErr:
			t.Fatalf("start: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("tunnel did not come up in 90s")
		}
		time.Sleep(500 * time.Millisecond)
	}
	if egress == directIP {
		t.Fatalf("egress IP equals direct host IP %s: traffic is not going through WARP", egress)
	}
	t.Logf("WARP egress IP: %s (direct %s)", egress, directIP)

	// 3. SOCKS5 CONNECT, then HTTP CONNECT and absolute-URI forwarding.
	socks := c.SOCKSAddr()
	if _, err := exec.LookPath("curl"); err != nil {
		t.Log("curl not found; skipping curl-based proxy checks")
	} else {
		t.Run("socks5_connect", func(t *testing.T) {
			out := runCurl(t, "--socks5", socks.String(), traceURL)
			if !strings.Contains(out, "warp=on") {
				t.Fatalf("socks5 trace says warp is off:\n%s", out)
			}
			if !strings.Contains(out, "ip="+egress.String()) && !strings.Contains(out, "ip=") {
				t.Fatalf("socks5 trace has no ip:\n%s", out)
			}
		})
		t.Run("http_connect", func(t *testing.T) {
			out := runCurl(t, "-x", "http://"+c.HTTPAddr().String(), traceURL)
			if !strings.Contains(out, "warp=on") {
				t.Fatalf("http CONNECT trace says warp is off:\n%s", out)
			}
		})
		t.Run("http_absolute_uri", func(t *testing.T) {
			out := runCurl(t, "-x", "http://"+c.HTTPAddr().String(), "http://example.com/")
			if !strings.Contains(out, "Example Domain") {
				t.Fatalf("absolute-URI forwarding failed:\n%.200s", out)
			}
		})
	}

	// 4. Twenty rotations, reporting the axis that worked.
	t.Run("rotations", func(t *testing.T) {
		type row struct {
			n       int
			axis    string
			old     string
			new     string
			changed bool
			took    time.Duration
		}
		rows := make([]row, 0, 20)
		for i := 1; i <= 20; i++ {
			rctx, rcancel := context.WithTimeout(ctx, 3*time.Minute)
			start := time.Now()
			old, fresh, err := c.Rotate(rctx)
			rcancel()
			axis := c.Stats().LastRotateAxis
			if err != nil {
				axis = "failed(" + err.Error() + ")"
			}
			rows = append(rows, row{
				n:       i,
				axis:    axis,
				old:     old.String(),
				new:     fresh.String(),
				changed: err == nil && old != fresh,
				took:    time.Since(start).Round(time.Millisecond),
			})
		}
		var sb strings.Builder
		w := tabwriter.NewWriter(&sb, 2, 8, 2, ' ', 0)
		fmt.Fprintln(w, "#\taxis\told IP\tnew IP\tchanged\telapsed")
		epOK, idOK, failed := 0, 0, 0
		for _, r := range rows {
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%v\t%s\n", r.n, r.axis, r.old, r.new, r.changed, r.took)
			switch {
			case !r.changed:
				failed++
			case strings.HasPrefix(r.axis, "endpoint"):
				epOK++
			case strings.HasPrefix(r.axis, "identity"):
				idOK++
			}
		}
		w.Flush()
		if err := os.WriteFile("rotation_table.txt", []byte(sb.String()), 0o644); err != nil {
			t.Logf("write rotation table: %v", err)
		}
		t.Logf("rotation results:\n%s", sb.String())
		t.Logf("endpoint axis=%d identity axis=%d failed=%d", epOK, idOK, failed)
		if epOK+idOK == 0 {
			t.Fatal("all 20 rotations failed to produce a new egress IP")
		}
	})

	// 5. Stop and prove the proxy is dead rather than leaking direct.
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
	conn, err := net.DialTimeout("tcp", socks.String(), 2*time.Second)
	if err == nil {
		conn.Close()
		t.Fatalf("proxy still accepting on %s after Stop", socks)
	}
	t.Logf("proxy refused after stop: %v", err)
}

func hostEgressIP(t *testing.T) netip.Addr {
	t.Helper()
	hc := &http.Client{Timeout: 15 * time.Second}
	resp, err := hc.Get(traceURL)
	if err != nil {
		t.Fatalf("host trace: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		if v, ok := strings.CutPrefix(line, "ip="); ok {
			if ip, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
				return ip
			}
		}
	}
	t.Fatal("host trace has no ip=")
	return netip.Addr{}
}

func runCurl(t *testing.T, args ...string) string {
	t.Helper()
	args = append([]string{"-sS", "--max-time", "40"}, args...)
	out, err := exec.Command("curl", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("curl %v: %v\n%s", args, err, out)
	}
	return string(out)
}
