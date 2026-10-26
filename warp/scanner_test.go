package warp

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestWarpCIDRsAre24(t *testing.T) {
	if len(warpCIDRs) == 0 {
		t.Fatal("no CIDRs")
	}
	for _, cidr := range warpCIDRs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			t.Fatalf("%q: %v", cidr, err)
		}
		if !p.Addr().Is4() || p.Bits() != 24 {
			t.Fatalf("%q is not an IPv4 /24", cidr)
		}
		if p != p.Masked() {
			t.Fatalf("%q has host bits set", cidr)
		}
	}
}

func TestWarpScanTargetsInterleaved(t *testing.T) {
	targets := warpScanTargets()
	if want := len(warpCIDRs) * 254; len(targets) != want {
		t.Fatalf("targets = %d, want %d", len(targets), want)
	}
	want := make(map[netip.Prefix]struct{}, len(warpCIDRs))
	for _, cidr := range warpCIDRs {
		want[netip.MustParsePrefix(cidr)] = struct{}{}
	}
	first := make(map[netip.Prefix]struct{}, len(want))
	for _, ap := range targets[:len(warpCIDRs)] {
		if ap.Port() != scanPort {
			t.Fatalf("%s: port = %d", ap, ap.Port())
		}
		p, err := ap.Addr().Prefix(24)
		if err != nil {
			t.Fatal(err)
		}
		first[p] = struct{}{}
	}
	if len(first) != len(want) {
		t.Fatalf("first %d targets cover %d CIDRs, want %d", len(warpCIDRs), len(first), len(want))
	}
	for p := range want {
		if _, ok := first[p]; !ok {
			t.Fatalf("first pass never samples %s", p)
		}
	}
}

func TestScanTargetsDedupesRepeatedTargets(t *testing.T) {
	got, err := scanTargets(context.Background(), []string{
		"162.159.192.9",
		"162.159.192.9:2408",
		"162.159.192.9",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %v, want a single target", got)
	}
	if want := netip.MustParseAddrPort("162.159.192.9:2408"); got[0] != want {
		t.Fatalf("got %s, want %s", got[0], want)
	}
}

func TestScanTargetsOverrideResolution(t *testing.T) {
	got, err := scanTargets(context.Background(), []string{
		"162.159.192.1",
		"162.159.195.7:51820",
		"",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.AddrPort{
		netip.MustParseAddrPort("162.159.192.1:2408"),
		netip.MustParseAddrPort("162.159.195.7:51820"),
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestScanTargetsOverrideError(t *testing.T) {
	_, err := scanTargets(context.Background(), []string{"   ", ""})
	if err == nil {
		t.Fatal("expected an error when every override fails")
	}
	if !strings.Contains(err.Error(), "empty endpoint") {
		t.Fatalf("error should carry the first resolution failure: %v", err)
	}
}

func TestVoidTunEventsClose(t *testing.T) {
	v := newVoidTun()
	events := v.Events()
	if events == nil {
		t.Fatal("Events() returned nil")
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("unexpected event")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("events channel not closed by Close")
	}
}
