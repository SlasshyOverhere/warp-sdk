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

func TestRotationOrderFreshUnseenStale(t *testing.T) {
	c := &Client{}
	eps := []Endpoint{
		{AddrPort: mustAP("1.2.3.1:2408")},
		{AddrPort: mustAP("1.2.3.2:2408")},
		{AddrPort: mustAP("1.2.3.3:2408")},
		{AddrPort: mustAP("1.2.3.4:2408")},
		{AddrPort: mustAP("1.2.3.5:2408")},
	}
	used := netip.MustParseAddr("10.4.0.2")
	c.noteEndpointEgress(eps[0].AddrPort, netip.MustParseAddr("10.4.0.1"))
	c.noteEndpointEgress(eps[2].AddrPort, used)
	c.noteRotation(eps[3].AddrPort, used)

	order := c.rotationOrder(eps, eps[4].AddrPort)
	if len(order) != 4 {
		t.Fatalf("order = %v", order)
	}
	if order[0].AddrPort != eps[0].AddrPort {
		t.Fatalf("fresh endpoint should lead: %v", order)
	}
	if order[1].AddrPort != eps[1].AddrPort {
		t.Fatalf("unseen endpoint should follow: %v", order)
	}
	for _, ep := range order[2:] {
		if ep.AddrPort != eps[2].AddrPort && ep.AddrPort != eps[3].AddrPort {
			t.Fatalf("stale endpoints should be last: %v", order)
		}
	}
}

func TestEgressReuseWindowExpires(t *testing.T) {
	ep := mustAP("162.159.192.1:2408")
	exits := []netip.Addr{
		netip.MustParseAddr("10.2.0.1"),
		netip.MustParseAddr("10.2.0.2"),
		netip.MustParseAddr("10.2.0.3"),
		netip.MustParseAddr("10.2.0.4"),
	}
	c := &Client{cfg: Config{EgressReuseWindow: 2}}
	for _, ip := range exits {
		c.noteRotation(ep, ip)
	}
	if c.egressUsed(exits[0]) {
		t.Fatal("exit three newer exits old should have expired")
	}
	for _, ip := range exits[1:] {
		if !c.egressUsed(ip) {
			t.Fatalf("exit %s is inside the window and must stay off limits", ip)
		}
	}
	c.noteUsedEgress(exits[0])
	if !c.egressUsed(exits[0]) {
		t.Fatal("reusing an exit must move it back inside the window")
	}
	if c.egressUsed(exits[1]) {
		t.Fatal("reuse should push the oldest remaining exit out")
	}
	if got := c.Stats().UsedEgress; len(got) != 4 {
		t.Fatalf("history = %v, want all 4 exits", got)
	}
}

func TestEgressReuseWindowZeroNeverReuses(t *testing.T) {
	c := &Client{}
	ep := mustAP("162.159.192.1:2408")
	first := netip.MustParseAddr("10.3.0.1")
	c.noteRotation(ep, first)
	for i := 0; i < 20; i++ {
		c.noteRotation(ep, netip.AddrFrom4([4]byte{10, 3, 1, byte(i + 1)}))
	}
	if !c.egressUsed(first) {
		t.Fatal("default window must never expire an exit")
	}
}

func TestCheckBind(t *testing.T) {
	remote := mustAP("0.0.0.0:1080")
	if err := checkBind("socks", &remote, false); err == nil {
		t.Fatal("non-loopback bind without AllowRemote must fail")
	}
	if err := checkBind("socks", &remote, true); err != nil {
		t.Fatalf("AllowRemote should permit it: %v", err)
	}
	loop := mustAP("127.0.0.1:1080")
	if err := checkBind("socks", &loop, false); err != nil {
		t.Fatalf("loopback bind should be allowed: %v", err)
	}
	if err := checkBind("socks", nil, false); err != nil {
		t.Fatalf("unset bind should be allowed: %v", err)
	}
}

func TestSentinelsAreDistinct(t *testing.T) {
	if ErrAlreadyStarted == ErrStopped || ErrAlreadyStarted == errNotStarted || ErrStopped == errNotStarted {
		t.Fatal("sentinel errors must be distinct")
	}
}
