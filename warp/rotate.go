package warp

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"time"
)

const (
	minRotationEndpoints  = 3
	recentEgressWindow    = 5
	recentEndpointWindow  = 8
	rotationBudget        = 10 * time.Second
	candidateProbeTimeout = 3 * time.Second
)

func (c *Client) Rotate(ctx context.Context) (old, next netip.Addr, err error) {
	ctx, cancel := context.WithTimeout(ctx, rotationBudget)
	defer cancel()
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
	c.noteUsedEgress(old)
	cur := c.Stats().Endpoint
	for _, ep := range c.rotationOrder(eps, cur) {
		if ctx.Err() != nil {
			break
		}
		epCtx, cancel := context.WithTimeout(ctx, candidateProbeTimeout)
		err := c.setEndpoint(epCtx, ep)
		if err != nil {
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
		if ip == old || c.egressUsed(ip) {
			continue
		}
		c.noteRotation(ep.AddrPort, ip)
		c.epRot.Add(1)
		return old, ip, nil
	}
	c.failRot.Add(1)
	// Failed walk leaves the device on the last ingress; put it back.
	if err := c.restoreEndpoint(cur); err != nil {
		return old, old, fmt.Errorf("%w: restore %s failed: %v", ErrNoNewEgress, cur, err)
	}
	return old, old, ErrNoNewEgress
}

func (c *Client) restoreEndpoint(ep netip.AddrPort) error {
	if !ep.IsValid() || c.Stats().Endpoint == ep {
		return nil
	}
	rctx, cancel := context.WithTimeout(context.Background(), endpointHandshake+5*time.Second)
	defer cancel()
	return c.setEndpoint(rctx, Endpoint{AddrPort: ep})
}

func (c *Client) rotationEgress(ctx context.Context) (netip.Addr, error) {
	if ip, err := c.EgressIP6(ctx); err == nil {
		return ip, nil
	}
	return c.EgressIP(ctx)
}

func (c *Client) rotationOrder(eps []Endpoint, cur netip.AddrPort) []Endpoint {
	c.recentMu.Lock()
	used := make(map[netip.Addr]bool, len(c.usedEgress))
	for i, ip := range c.usedEgress {
		if !c.expired(i) {
			used[ip] = true
		}
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
	var fresh, unseen, stale []Endpoint
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
		case ok && ip.IsValid() && !used[ip]:
			fresh = append(fresh, ep)
		case !ok:
			unseen = append(unseen, ep)
		default:
			stale = append(stale, ep)
		}
	}
	return append(append(fresh, unseen...), stale...)
}

func (c *Client) egressUsed(ip netip.Addr) bool {
	c.recentMu.Lock()
	defer c.recentMu.Unlock()
	i := c.usedIndex(ip)
	return i >= 0 && !c.expired(i)
}

func (c *Client) expired(i int) bool {
	w := c.cfg.EgressReuseWindow
	return w > 0 && len(c.usedEgress)-1-i > w
}

func (c *Client) usedIndex(ip netip.Addr) int {
	for i, used := range c.usedEgress {
		if used == ip {
			return i
		}
	}
	return -1
}

func (c *Client) noteUsedEgress(ip netip.Addr) {
	if !ip.IsValid() {
		return
	}
	c.recentMu.Lock()
	defer c.recentMu.Unlock()
	c.markUsed(ip)
}

func (c *Client) markUsed(ip netip.Addr) {
	i := c.usedIndex(ip)
	if i >= 0 && !c.expired(i) {
		return
	}
	if i >= 0 {
		c.usedEgress = append(c.usedEgress[:i], c.usedEgress[i+1:]...)
	}
	c.usedEgress = append(c.usedEgress, ip)
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
	c.markUsed(ip)
}

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
