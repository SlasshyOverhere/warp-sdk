package warp

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"time"
)

const (
	// minRotationEndpoints guards against calling a two-endpoint ping-pong
	// "rotation": below this the verified pool cannot produce variety.
	minRotationEndpoints = 3
	// recentEgressWindow is the last N rotations whose egress Rotate refuses to
	// report again. 5 is small enough that a pool of 6 distinct exits can cycle
	// without repeating inside the window.
	recentEgressWindow = 5
	// recentEndpointWindow avoids walking back onto the same ingress.
	recentEndpointWindow = 8
	// rotationBudget bounds the whole endpoint walk. Probing one endpoint costs
	// a handshake plus a trace; an unbounded walk over a 64-endpoint pool stalls
	// the caller for minutes, which is worse than reporting failure.
	rotationBudget = 10 * time.Second
)

// Rotate finds a new egress address by moving to another handshake-verified
// endpoint, preferring ingresses and exits it has not used recently. In-flight
// proxied connections are never dropped: the netstack stays up and TCP
// retransmits across the endpoint change.
//
// Only the endpoint axis exists. rotation_table.txt records this axis plus a
// separate IPv4 measurement section (five endpoint swaps and five fresh
// Register calls, all exiting the same IPv4 address), which is why a second
// identity axis was not kept: it cannot move the pinned IPv4 egress, and the
// IPv6 egress the upstream actually sees is already covered here.
func (c *Client) Rotate(ctx context.Context) (old, next netip.Addr, err error) {
	old, err = c.rotationEgress(ctx)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	eps, err := c.Endpoints(ctx)
	if err != nil && len(eps) == 0 {
		return old, old, err
	}
	eps = dedupeEndpoints(eps)
	if len(eps) < minRotationEndpoints {
		c.failRot.Add(1)
		return old, old, fmt.Errorf("%w: only %d distinct endpoints verified", ErrNoNewEgress, len(eps))
	}
	cur := c.Stats().Endpoint
	deadline := time.Now().Add(rotationBudget)
	for _, ep := range c.rotationOrder(eps, cur) {
		remaining := time.Until(deadline)
		if remaining <= 0 || ctx.Err() != nil {
			break
		}
		epCtx, cancel := context.WithTimeout(ctx, remaining)
		err := c.setEndpoint(epCtx, ep)
		if err != nil {
			// Park failed ingresses at the back of the walk on later rotations.
			c.noteEndpointEgress(ep.AddrPort, netip.Addr{})
			cancel()
			continue
		}
		ip, err := c.rotationEgress(epCtx)
		cancel()
		if err != nil {
			c.noteEndpointEgress(ep.AddrPort, netip.Addr{})
			continue
		}
		c.noteEndpointEgress(ep.AddrPort, ip)
		if ip == old || c.recentEgressContains(ip) {
			continue
		}
		c.noteRotation(ep.AddrPort, ip)
		c.epRot.Add(1)
		c.lastAxis.Store("endpoint")
		return old, ip, nil
	}
	c.failRot.Add(1)
	return old, old, ErrNoNewEgress
}

// rotationEgress prefers IPv6 because netstack (and therefore the upstream)
// uses the IPv6 egress when the destination is dual-stack.
func (c *Client) rotationEgress(ctx context.Context) (netip.Addr, error) {
	if ip, err := c.EgressIP6(ctx); err == nil {
		return ip, nil
	}
	return c.EgressIP(ctx)
}

// rotationOrder visits the full verified pool from a random starting point:
// unseen endpoints first, then endpoints known to yield a non-recent exit, then
// the current/recently used ones as a last resort. The random start is the
// jitter that keeps consecutive runs off the same pair.
func (c *Client) rotationOrder(eps []Endpoint, cur netip.AddrPort) []Endpoint {
	c.recentMu.Lock()
	recentEG := make(map[netip.Addr]bool, len(c.recentEgress))
	for _, ip := range c.recentEgress {
		recentEG[ip] = true
	}
	recentEP := make(map[netip.AddrPort]bool, len(c.recentEP))
	for _, ep := range c.recentEP {
		recentEP[ep] = true
	}
	known := make(map[netip.AddrPort]netip.Addr, len(c.epEgress))
	for ep, ip := range c.epEgress {
		known[ep] = ip
	}
	c.recentMu.Unlock()

	n := len(eps)
	start := rand.IntN(n)
	var unseen, fresh, stale []Endpoint
	for i := 0; i < n; i++ {
		ep := eps[(start+i)%n]
		if ep.AddrPort == cur {
			continue
		}
		if recentEP[ep.AddrPort] {
			stale = append(stale, ep)
			continue
		}
		ip, ok := known[ep.AddrPort]
		switch {
		case !ok:
			unseen = append(unseen, ep)
		case ip.IsValid() && !recentEG[ip]:
			fresh = append(fresh, ep)
		default:
			stale = append(stale, ep)
		}
	}
	return append(append(unseen, fresh...), stale...)
}

func (c *Client) recentEgressContains(ip netip.Addr) bool {
	c.recentMu.Lock()
	defer c.recentMu.Unlock()
	for _, recent := range c.recentEgress {
		if recent == ip {
			return true
		}
	}
	return false
}

func (c *Client) noteEndpointEgress(ep netip.AddrPort, ip netip.Addr) {
	c.recentMu.Lock()
	defer c.recentMu.Unlock()
	if c.epEgress == nil {
		c.epEgress = make(map[netip.AddrPort]netip.Addr)
	}
	c.epEgress[ep] = ip
}

func (c *Client) noteRotation(ep netip.AddrPort, ip netip.Addr) {
	c.recentMu.Lock()
	defer c.recentMu.Unlock()
	c.recentEgress = append(c.recentEgress, ip)
	if len(c.recentEgress) > recentEgressWindow {
		c.recentEgress = c.recentEgress[len(c.recentEgress)-recentEgressWindow:]
	}
	c.recentEP = append(c.recentEP, ep)
	if len(c.recentEP) > recentEndpointWindow {
		c.recentEP = c.recentEP[len(c.recentEP)-recentEndpointWindow:]
	}
	if c.epEgress == nil {
		c.epEgress = make(map[netip.AddrPort]netip.Addr)
	}
	c.epEgress[ep] = ip
}

// dedupeEndpoints keeps the first occurrence of each address:port.
func dedupeEndpoints(eps []Endpoint) []Endpoint {
	seen := make(map[netip.AddrPort]struct{}, len(eps))
	out := make([]Endpoint, 0, len(eps))
	for _, ep := range eps {
		if _, ok := seen[ep.AddrPort]; ok {
			continue
		}
		seen[ep.AddrPort] = struct{}{}
		out = append(out, ep)
	}
	return out
}
