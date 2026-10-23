package warp

import (
	"context"
	"net/netip"
)

// Rotate finds a new egress IP by moving to another handshake-verified
// endpoint. In-flight proxied connections are never dropped: the netstack stays
// up and TCP retransmits across the endpoint change.
//
// The fresh-identity axis was measured at 0/20 wins against the endpoint axis
// (see rotation_table.txt), so it was deleted rather than kept as dead weight.
func (c *Client) Rotate(ctx context.Context) (old, new netip.Addr, err error) {
	old, err = c.EgressIP(ctx)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	eps, err := c.Endpoints(ctx)
	if err != nil && len(eps) == 0 {
		return old, old, err
	}
	cur := c.Stats().Endpoint
	for _, ep := range eps {
		if ep.AddrPort == cur {
			continue
		}
		if err := c.SetEndpoint(ep); err != nil {
			continue
		}
		ip, err := c.EgressIP(ctx)
		if err == nil && ip.IsValid() && ip != old {
			c.epRot.Add(1)
			c.lastAxis.Store("endpoint")
			return old, ip, nil
		}
	}
	c.failRot.Add(1)
	return old, old, ErrNoNewEgress
}
