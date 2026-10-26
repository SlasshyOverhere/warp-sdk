package warp

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
)

const fixturePrivKey = "qiG/2e83f0uX14XoUDOObQRlx0giX+2Laz1QssDqXd4="

func loadFixtureIdentity(t *testing.T) *Identity {
	t.Helper()
	b, err := os.ReadFile("testdata/reg.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc registrationDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	id, err := identityFromDoc(fixturePrivKey, doc)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestParseFixtureIdentity(t *testing.T) {
	id := loadFixtureIdentity(t)
	if id.ID == "" || id.Token == "" {
		t.Fatal("id/token empty")
	}
	if id.PeerPublicKey == "" {
		t.Fatal("peer public key empty")
	}
	if id.AddressV4 != netip.MustParsePrefix("172.16.0.2/32") {
		t.Fatalf("v4 = %v", id.AddressV4)
	}
	if !id.AddressV6.Addr().Is6() {
		t.Fatalf("v6 = %v", id.AddressV6)
	}
	if id.Endpoint != "engage.cloudflareclient.com:2408" {
		t.Fatalf("endpoint = %q", id.Endpoint)
	}
	if len(id.Ports) == 0 || id.Ports[0] != 500 {
		t.Fatalf("ports = %v", id.Ports)
	}
	raw, err := base64.StdEncoding.DecodeString(id.PublicKey)
	if err != nil || len(raw) != 32 {
		t.Fatalf("public key = %q", id.PublicKey)
	}
	if id.PublicKey == id.PrivateKey {
		t.Fatal("public key equals private key")
	}
}

func TestIdentitySaveLoad(t *testing.T) {
	dir := t.TempDir()
	want := loadFixtureIdentity(t)
	if err := want.Save(dir); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dir + "/identity.json")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %v, want 0600", st.Mode().Perm())
	}
	got, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.Token != want.Token || got.PrivateKey != want.PrivateKey {
		t.Fatal("identity did not round-trip")
	}
	if got.AddressV4 != want.AddressV4 || got.PeerPublicKey != want.PeerPublicKey {
		t.Fatal("identity fields did not round-trip")
	}
}

func TestUAPIConfig(t *testing.T) {
	id := loadFixtureIdentity(t)
	ep := netip.MustParseAddrPort("162.159.192.7:2408")
	cfg, err := id.uapi(ep)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"private_key=" + hexOf(id.PrivateKey),
		"endpoint=162.159.192.7:2408",
		"persistent_keepalive_interval=25",
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
		"preshared_key=" + strings.Repeat("00", 32),
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("config missing %q:\n%s", want, cfg)
		}
	}
}

func hexOf(b64Key string) string {
	raw, _ := base64.StdEncoding.DecodeString(b64Key)
	const hexdigits = "0123456789abcdef"
	var b strings.Builder
	for _, c := range raw {
		b.WriteByte(hexdigits[c>>4])
		b.WriteByte(hexdigits[c&0xf])
	}
	return b.String()
}

func TestResolveEndpoint(t *testing.T) {
	cases := map[string]string{
		"162.159.192.1":          "162.159.192.1:2408",
		"162.159.192.1:500":      "162.159.192.1:500",
		"162.159.192.1:0":        "162.159.192.1:2408",
		"[2606:4700:d0::1]:2408": "[2606:4700:d0::1]:2408",
	}
	for in, want := range cases {
		got, err := resolveEndpoint(t.Context(), in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got.String() != want {
			t.Fatalf("%s -> %s, want %s", in, got, want)
		}
	}
}

func TestScanTargetsOverride(t *testing.T) {
	got, err := scanTargets(t.Context(), []string{"162.159.192.1", "162.159.192.2:500"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Port() != 2408 || got[1].Port() != 500 {
		t.Fatalf("targets = %v", got)
	}
}

func TestScanTargetsCIDRs(t *testing.T) {
	got, err := scanTargets(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) < 8*250 {
		t.Fatalf("only %d targets", len(got))
	}
	for _, ap := range got {
		if !ap.Addr().Is4() || ap.Port() != scanPort {
			t.Fatalf("unexpected target %v", ap)
		}
	}
}

func TestParseHandshakeNano(t *testing.T) {
	s := "public_key=00\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=5\n"
	if got := parseHandshakeNano(s); got != 1700000000*1e9+5 {
		t.Fatalf("got %d", got)
	}
	if parseHandshakeNano("last_handshake_time_sec=0\n") != 0 {
		t.Fatal("zero handshake should parse as zero")
	}
}

func TestSocksAddrDefaultsLoopbackEphemeral(t *testing.T) {
	c, err := NewClient(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	ap := c.SOCKSAddr()
	if !ap.Addr().IsLoopback() || ap.Port() == 0 {
		t.Fatalf("socks addr = %v", ap)
	}
	if c.HTTPAddr().IsValid() {
		t.Fatal("http should be disabled by default")
	}
}
