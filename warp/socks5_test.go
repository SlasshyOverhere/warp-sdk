package warp

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestReadSocksHost(t *testing.T) {
	v6 := netip.MustParseAddr("2001:db8::1").As16()
	ipv6 := append([]byte{socksAtypIPv6}, v6[:]...)
	ipv6 = append(ipv6, 0x01, 0xbb)
	domain := append([]byte{socksAtypName, 11}, "example.com"...)
	domain = append(domain, 0x00, 0x50)

	tests := []struct {
		name string
		in   []byte
		host string
		port uint16
		err  bool
	}{
		{"ipv4", []byte{socksAtypIPv4, 10, 0, 0, 1, 0x1f, 0x90}, "10.0.0.1", 8080, false},
		{"ipv6", ipv6, "2001:db8::1", 443, false},
		{"domain", domain, "example.com", 80, false},
		{"empty", nil, "", 0, true},
		{"unknown atyp", []byte{0x02, 0, 0}, "", 0, true},
		{"short ipv4", []byte{socksAtypIPv4, 10, 0}, "", 0, true},
		{"short ipv6", []byte{socksAtypIPv6, 0, 0, 0}, "", 0, true},
		{"short name", []byte{socksAtypName, 5, 'a'}, "", 0, true},
		{"missing port", []byte{socksAtypIPv4, 10, 0, 0, 1}, "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := readSocksHost(bytes.NewReader(tt.in))
			if tt.err {
				if err == nil {
					t.Fatalf("expected error, got host=%q port=%d", host, port)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if host != tt.host || port != tt.port {
				t.Fatalf("got %q:%d, want %q:%d", host, port, tt.host, tt.port)
			}
		})
	}
}

func TestSocksUDPRoundTrip(t *testing.T) {
	for _, s := range []string{"192.0.2.7:5353", "[2001:db8::53]:53"} {
		ap := netip.MustParseAddrPort(s)
		payload := []byte("hello")
		host, port, got, err := parseSocksUDP(buildSocksUDP(ap, payload))
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", s, err)
		}
		if host != ap.Addr().String() || port != ap.Port() {
			t.Fatalf("%s: got %q:%d", s, host, port)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("%s: payload %q, want %q", s, got, payload)
		}
	}
}

func TestSocksUDPRejectsFragmented(t *testing.T) {
	frame := buildSocksUDP(netip.MustParseAddrPort("192.0.2.7:5353"), []byte("x"))
	frame[2] = 1
	if _, _, _, err := parseSocksUDP(frame); err == nil {
		t.Fatal("expected fragmented datagram to be rejected")
	}
	if _, _, _, err := parseSocksUDP(frame[:3]); err == nil {
		t.Fatal("expected truncated header to be rejected")
	}
}

func TestWriteSocksReply(t *testing.T) {
	v6 := netip.MustParseAddr("2001:db8::1")
	b6 := v6.As16()
	want6 := append([]byte{socksVersion, socksSucceeded, 0, socksAtypIPv6}, b6[:]...)
	want6 = append(want6, 0x01, 0xbb)

	tests := []struct {
		name string
		rep  byte
		ap   netip.AddrPort
		want []byte
	}{
		{
			"ipv4",
			socksSucceeded,
			netip.MustParseAddrPort("192.0.2.7:5353"),
			[]byte{socksVersion, socksSucceeded, 0, socksAtypIPv4, 192, 0, 2, 7, 0x14, 0xe9},
		},
		{"ipv6", socksSucceeded, netip.AddrPortFrom(v6, 443), want6},
		{"zero", 0x05, netip.AddrPort{}, []byte{socksVersion, 0x05, 0, socksAtypIPv4, 0, 0, 0, 0, 0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			writeSocksReply(&buf, tt.rep, tt.ap)
			if !bytes.Equal(buf.Bytes(), tt.want) {
				t.Fatalf("got % x, want % x", buf.Bytes(), tt.want)
			}
		})
	}
}
