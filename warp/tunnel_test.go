package warp

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
)

func TestParseHandshakeNanoTable(t *testing.T) {
	t.Parallel()
	const sec = 1700000000
	cases := []struct {
		name string
		in   string
		want int64
	}{
		{"sec and nsec", "last_handshake_time_sec=1700000000\nlast_handshake_time_nsec=5\n", sec*1e9 + 5},
		{"nsec before sec", "last_handshake_time_nsec=5\nlast_handshake_time_sec=1700000000\n", sec*1e9 + 5},
		{"sec only", "last_handshake_time_sec=1700000000\n", sec * 1e9},
		{"sec zero with nsec", "last_handshake_time_sec=0\nlast_handshake_time_nsec=7\n", 0},
		{"absent", "public_key=00\nendpoint=1.2.3.4:2408\n", 0},
		{"empty", "", 0},
		{"garbage sec", "last_handshake_time_sec=abc\nlast_handshake_time_nsec=5\n", 0},
		{"garbage nsec", "last_handshake_time_sec=1700000000\nlast_handshake_time_nsec=zz\n", sec * 1e9},
		{
			"unrelated lines",
			"private_key=00\nlisten_port=51820\nlast_handshake_time_sec=1700000000\n" +
				"last_handshake_time_nsec=5\npersistent_keepalive_interval=25\n",
			sec*1e9 + 5,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := parseHandshakeNano(c.in); got != c.want {
				t.Fatalf("parseHandshakeNano(%q) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}

func TestNoiseKeyFromB64Table(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"valid 32 bytes", base64.StdEncoding.EncodeToString(key), false},
		{"31 bytes", base64.StdEncoding.EncodeToString(key[:31]), true},
		{"33 bytes", base64.StdEncoding.EncodeToString(append(key, 1)), true},
		{"invalid base64", "not!base64!!", true},
		{"empty", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			k, err := noiseKeyFromB64(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("noiseKeyFromB64(%q) = %x, want error", c.in, k)
				}
				return
			}
			if err != nil {
				t.Fatalf("noiseKeyFromB64(%q): %v", c.in, err)
			}
			if string(k[:]) != string(key) {
				t.Fatalf("key = %x, want %x", k, key)
			}
		})
	}
}

func TestResolveEndpointTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"v4 default port", "1.2.3.4", "1.2.3.4:2408"},
		{"v4 explicit port", "1.2.3.4:500", "1.2.3.4:500"},
		{"v4 zero port", "1.2.3.4:0", "1.2.3.4:2408"},
		{"v6 bracketed", "[2606:4700::1]:2408", "[2606:4700::1]:2408"},
		{"v6 bare", "2606:4700::1", "[2606:4700::1]:2408"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveEndpoint(t.Context(), c.in)
			if err != nil {
				t.Fatalf("resolveEndpoint(%q): %v", c.in, err)
			}
			if got.String() != c.want {
				t.Fatalf("resolveEndpoint(%q) = %s, want %s", c.in, got, c.want)
			}
		})
	}
	t.Run("empty", func(t *testing.T) {
		t.Parallel()
		if _, err := resolveEndpoint(t.Context(), ""); err == nil {
			t.Fatal("resolveEndpoint(\"\") succeeded, want error")
		}
	})
}

func TestCountersParseUAPI(t *testing.T) {
	t.Parallel()
	const peerA = "public_key=aa\nendpoint=1.2.3.4:2408\ntx_bytes=1500\nrx_bytes=900\n"
	const peerB = "public_key=bb\nendpoint=1.2.3.5:2408\ntx_bytes=25\nrx_bytes=7\n"
	cases := []struct {
		name string
		in   string
		tx   uint64
		rx   uint64
	}{
		{"single peer", peerA, 1500, 900},
		{"multi peer accumulates", peerA + peerB, 1525, 907},
		{"no counters", "public_key=aa\n", 0, 0},
		{"garbage values", "tx_bytes=zz\nrx_bytes=-\n", 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			tx, rx := countersFromUAPI(c.in)
			if tx != c.tx || rx != c.rx {
				t.Fatalf("counters = (%d, %d), want (%d, %d)", tx, rx, c.tx, c.rx)
			}
		})
	}
}

func countersFromUAPI(s string) (tx, rx uint64) {
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
