package warp

import (
	"net/netip"
	"testing"
)

func mustAP(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestDedupeEndpoints(t *testing.T) {
	a := Endpoint{AddrPort: mustAP("162.159.192.1:2408")}
	b := Endpoint{AddrPort: mustAP("162.159.192.2:2408")}
	got := dedupeEndpoints([]Endpoint{a, b, a})
	if len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("got %v", got)
	}
}

func TestRecentEgressIsBounded(t *testing.T) {
	c := &Client{}
	ep := mustAP("162.159.192.1:2408")
	for i := 0; i < 10; i++ {
		ip := netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
		c.noteRotation(ep, ip)
	}
	got := c.Stats().RecentEgress
	if len(got) != recentEgressWindow {
		t.Fatalf("recent window = %d, want %d", len(got), recentEgressWindow)
	}
	for i, ip := range got {
		want := netip.AddrFrom4([4]byte{10, 0, 0, byte(6 + i)})
		if ip != want {
			t.Fatalf("recent[%d] = %s, want %s", i, ip, want)
		}
	}
	for _, ip := range got {
		if ip == netip.AddrFrom4([4]byte{10, 0, 0, 1}) {
			t.Fatal("oldest address should have fallen out of the recent window")
		}
	}
	// The lifetime used-set still remembers it, so it can never be rotated to.
	if !c.egressUsed(netip.AddrFrom4([4]byte{10, 0, 0, 1})) {
		t.Fatal("used set should retain the oldest address")
	}
	if !c.egressUsed(netip.AddrFrom4([4]byte{10, 0, 0, 10})) {
		t.Fatal("newest address missing")
	}
}

func TestRotationOrderSkipsCurrentAndRecent(t *testing.T) {
	c := &Client{}
	eps := []Endpoint{
		{AddrPort: mustAP("1.1.1.1:2408")},
		{AddrPort: mustAP("1.1.1.2:2408")},
		{AddrPort: mustAP("1.1.1.3:2408")},
		{AddrPort: mustAP("1.1.1.4:2408")},
	}
	recentIP := netip.MustParseAddr("104.28.216.196")
	c.noteRotation(eps[0].AddrPort, recentIP)
	// Endpoint 2 is known to land on the recent address; it must be last.
	c.noteEndpointEgress(eps[2].AddrPort, recentIP)

	order := c.rotationOrder(eps, eps[1].AddrPort)
	if len(order) != len(eps)-1 {
		t.Fatalf("order = %v", order)
	}
	for _, ep := range order {
		if ep.AddrPort == eps[1].AddrPort {
			t.Fatal("current endpoint should be skipped")
		}
	}
	if order[0].AddrPort == eps[0].AddrPort || order[0].AddrPort == eps[2].AddrPort {
		t.Fatalf("first candidate is recent/stale: %v", order)
	}
	last := order[len(order)-1].AddrPort
	if last != eps[0].AddrPort && last != eps[2].AddrPort {
		t.Fatalf("last candidate should be stale: %v", order)
	}
}

func TestCycleLength(t *testing.T) {
	if got := cycleLength([]string{"a", "b", "a", "b"}); got != 2 {
		t.Fatalf("cycle = %d, want 2", got)
	}
	if got := cycleLength([]string{"a", "b", "c"}); got != 3 {
		t.Fatalf("no cycle should report len, got %d", got)
	}
}

func TestUsedEgressIsStrict(t *testing.T) {
	c := &Client{}
	a := netip.AddrFrom4([4]byte{10, 9, 9, 1})
	b := netip.AddrFrom4([4]byte{10, 9, 9, 2})
	c.noteRotation(mustAP("162.159.192.1:2408"), a)
	c.noteRotation(mustAP("162.159.192.2:2408"), a)
	c.noteRotation(mustAP("162.159.192.3:2408"), b)
	if !c.egressUsed(a) || !c.egressUsed(b) {
		t.Fatal("both addresses should be marked used")
	}
	if got := c.Stats().UsedEgress; len(got) != 2 {
		t.Fatalf("used set = %v, want 2 unique addresses", got)
	}
	c.noteUsedEgress(a)
	if got := len(c.Stats().UsedEgress); got != 2 {
		t.Fatalf("duplicate note grew used set to %d", got)
	}
	if c.egressUsed(netip.AddrFrom4([4]byte{10, 9, 9, 3})) {
		t.Fatal("unseen address reported used")
	}
}

func TestRotationOrderPrefersCachedUnused(t *testing.T) {
	c := &Client{}
	eps := []Endpoint{
		{AddrPort: mustAP("1.1.1.1:2408")},
		{AddrPort: mustAP("1.1.1.2:2408")},
		{AddrPort: mustAP("1.1.1.3:2408")},
	}
	used := netip.MustParseAddr("10.0.0.1")
	fresh := netip.MustParseAddr("10.0.0.2")
	c.noteRotation(eps[0].AddrPort, used)
	c.noteEndpointEgress(eps[1].AddrPort, used)
	c.noteEndpointEgress(eps[2].AddrPort, fresh)

	order := c.rotationOrder(eps, netip.AddrPort{})
	if len(order) != 3 || order[0].AddrPort != eps[2].AddrPort {
		t.Fatalf("cached-unused endpoint should be first: %v", order)
	}
}
