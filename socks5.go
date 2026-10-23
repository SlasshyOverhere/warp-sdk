package warp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

const (
	socksVersion   = 0x05
	socksNoAuth    = 0x00
	socksConnect   = 0x01
	socksBind      = 0x02
	socksUDP       = 0x03
	socksAtypIPv4  = 0x01
	socksAtypName  = 0x03
	socksAtypIPv6  = 0x04
	socksSucceeded = 0x00
)

func (c *Client) serveSOCKS() {
	for {
		conn, err := c.socksLn.Accept()
		if err != nil {
			return
		}
		c.active.Add(1)
		go func() {
			defer c.active.Add(-1)
			defer conn.Close()
			c.handleSOCKS(conn)
		}()
	}
}

func (c *Client) handleSOCKS(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(conn)
	ver, err := br.ReadByte()
	if err != nil || ver != socksVersion {
		return
	}
	n, err := br.ReadByte()
	if err != nil {
		return
	}
	methods := make([]byte, n)
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	ok := false
	for _, m := range methods {
		if m == socksNoAuth {
			ok = true
		}
	}
	if !ok {
		_, _ = conn.Write([]byte{socksVersion, 0xff})
		return
	}
	if _, err := conn.Write([]byte{socksVersion, socksNoAuth}); err != nil {
		return
	}
	var hdr [3]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil || hdr[0] != socksVersion {
		return
	}
	host, port, err := readSocksHost(br)
	if err != nil {
		writeSocksStatus(conn, 0x08)
		return
	}
	switch hdr[1] {
	case socksConnect:
		c.socksDoConnect(conn, br, host, port)
	case socksUDP:
		c.socksDoUDP(conn)
	case socksBind:
		writeSocksStatus(conn, 0x07)
	default:
		writeSocksStatus(conn, 0x07)
	}
}

func readSocksHost(r io.Reader) (string, uint16, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", 0, err
	}
	var host string
	switch atyp[0] {
	case socksAtypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom4(b).String()
	case socksAtypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", 0, err
		}
		host = netip.AddrFrom16(b).String()
	case socksAtypName:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", 0, err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	default:
		return "", 0, fmt.Errorf("warp: unsupported socks atyp %d", atyp[0])
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(p[:]), nil
}

func writeSocksStatus(w io.Writer, rep byte) {
	writeSocksReply(w, rep, netip.AddrPort{})
}

func writeSocksReply(w io.Writer, rep byte, ap netip.AddrPort) {
	var b []byte
	switch {
	case ap.Addr().Is6():
		b = make([]byte, 4, 4+16+2)
		b[3] = socksAtypIPv6
		a := ap.Addr().As16()
		b = append(b, a[:]...)
	case ap.Addr().Is4():
		b = make([]byte, 4, 4+4+2)
		b[3] = socksAtypIPv4
		a := ap.Addr().As4()
		b = append(b, a[:]...)
	default:
		b = make([]byte, 4, 4+4+2)
		b[3] = socksAtypIPv4
		b = append(b, 0, 0, 0, 0)
	}
	b[0], b[1], b[2] = socksVersion, rep, 0
	b = binary.BigEndian.AppendUint16(b, ap.Port())
	_, _ = w.Write(b)
}

func (c *Client) socksDoConnect(conn net.Conn, br *bufio.Reader, host string, port uint16) {
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	started := time.Now()
	up, err := c.dial(ctx, "tcp", target)
	c.reportSOCKSDial(target, err, time.Since(started))
	if err != nil {
		writeSocksStatus(conn, 0x05)
		return
	}
	defer up.Close()
	writeSocksReply(conn, socksSucceeded, netip.AddrPort{})
	_ = conn.SetDeadline(time.Time{})
	relay(br, conn, up)
}

// socksDoUDP relays UDP datagrams for one association. Upstream sockets are
// created through the tunnel, one per destination.
func (c *Client) socksDoUDP(conn net.Conn) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		writeSocksStatus(conn, 0x01)
		return
	}
	defer pc.Close()
	relayAddr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(pc.LocalAddr().(*net.UDPAddr).Port))
	writeSocksReply(conn, socksSucceeded, relayAddr)
	_ = conn.SetDeadline(time.Time{})

	t, release := c.acquireTunnel()
	if t == nil {
		return
	}
	defer release()

	a := &udpAssoc{t: t, client: pc, up: make(map[netip.AddrPort]*gonet.UDPConn)}
	defer a.close()
	a.serve()
	_, _ = io.Copy(io.Discard, conn)
}

type udpAssoc struct {
	t       *tunnel
	client  *net.UDPConn
	mu      sync.Mutex
	up      map[netip.AddrPort]*gonet.UDPConn
	closed  bool
	peer    netip.AddrPort
	hasPeer bool
}

func (a *udpAssoc) serve() {
	go a.readClient()
}

func (a *udpAssoc) readClient() {
	buf := make([]byte, 65535)
	for {
		_ = a.client.SetReadDeadline(time.Now().Add(30 * time.Minute))
		n, from, err := a.client.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		a.mu.Lock()
		if !a.hasPeer {
			a.peer, a.hasPeer = from, true
		}
		fromOK := a.hasPeer && a.peer == from
		a.mu.Unlock()
		if !fromOK {
			continue
		}
		host, port, payload, err := parseSocksUDP(buf[:n])
		if err != nil || len(payload) == 0 {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		addrs, err := a.t.lookupHost(ctx, host)
		cancel()
		if err != nil || len(addrs) == 0 {
			continue
		}
		raddr := netip.AddrPortFrom(addrs[0], port)
		uc, err := a.upstream(raddr)
		if err != nil {
			continue
		}
		_, _ = uc.Write(payload)
	}
}

func (a *udpAssoc) upstream(raddr netip.AddrPort) (*gonet.UDPConn, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, errNotStarted
	}
	if uc, ok := a.up[raddr]; ok {
		return uc, nil
	}
	uc, err := a.t.net.DialUDPAddrPort(netip.AddrPort{}, raddr)
	if err != nil {
		return nil, err
	}
	a.up[raddr] = uc
	go a.readUpstream(raddr, uc)
	return uc, nil
}

func (a *udpAssoc) readUpstream(raddr netip.AddrPort, uc *gonet.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, err := uc.Read(buf)
		if err != nil {
			return
		}
		frame := buildSocksUDP(raddr, buf[:n])
		a.mu.Lock()
		hasPeer, peer := a.hasPeer, a.peer
		a.mu.Unlock()
		if hasPeer {
			_, _ = a.client.WriteToUDPAddrPort(frame, peer)
		}
	}
}

func (a *udpAssoc) close() {
	a.mu.Lock()
	a.closed = true
	for k, uc := range a.up {
		uc.Close()
		delete(a.up, k)
	}
	a.mu.Unlock()
}

func parseSocksUDP(b []byte) (host string, port uint16, payload []byte, err error) {
	if len(b) < 4 {
		return "", 0, nil, io.ErrUnexpectedEOF
	}
	if b[2] != 0 {
		return "", 0, nil, fmt.Errorf("warp: fragmented socks udp unsupported")
	}
	r := bufio.NewReader(bytes.NewReader(b[3:]))
	if host, port, err = readSocksHost(r); err != nil {
		return "", 0, nil, err
	}
	rest, _ := io.ReadAll(r)
	return host, port, rest, nil
}

func buildSocksUDP(ap netip.AddrPort, payload []byte) []byte {
	var addr []byte
	if ap.Addr().Is6() {
		a := ap.Addr().As16()
		addr = append([]byte{socksAtypIPv6}, a[:]...)
	} else {
		a := ap.Addr().As4()
		addr = append([]byte{socksAtypIPv4}, a[:]...)
	}
	addr = binary.BigEndian.AppendUint16(addr, ap.Port())
	out := make([]byte, 0, 3+len(addr)+len(payload))
	out = append(out, 0, 0, 0)
	out = append(out, addr...)
	out = append(out, payload...)
	return out
}

func relay(clientReader io.Reader, client net.Conn, up net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(up, clientReader)
		closeWrite(up)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, up)
		closeWrite(client)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// reportSOCKSDial hands one connection to the host's hook, if it set one.
func (c *Client) reportSOCKSDial(target string, err error, took time.Duration) {
	if c.cfg.OnSOCKSDial == nil {
		return
	}
	c.cfg.OnSOCKSDial(target, err, took)
}
