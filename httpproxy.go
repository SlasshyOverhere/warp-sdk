package warp

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

func (c *Client) serveHTTP() {
	srv := &http.Server{
		Handler:           c.httpHandler(),
		ReadHeaderTimeout: 30 * time.Second,
		ConnState: func(_ net.Conn, st http.ConnState) {
			switch st {
			case http.StateNew:
				c.active.Add(1)
			case http.StateHijacked, http.StateClosed:
				c.active.Add(-1)
			}
		},
	}
	_ = srv.Serve(c.httpLn)
}

func (c *Client) httpHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			c.handleConnect(w, r)
			return
		}
		c.handleForward(w, r)
	})
}

func (c *Client) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	up, err := c.dial(ctx, "tcp", target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	defer client.Close()
	defer up.Close()
	c.active.Add(1)
	defer c.active.Add(-1)
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	relay(client, client, up)
}

func (c *Client) handleForward(w http.ResponseWriter, r *http.Request) {
	out := r.Clone(r.Context())
	out.RequestURI = ""
	if out.URL == nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if out.URL.Scheme == "" {
		out.URL.Scheme = "http"
	}
	if out.URL.Host == "" {
		out.URL.Host = r.Host
	}
	stripHopHeaders(out.Header)
	resp, err := c.httpTr.RoundTrip(out)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	stripHopHeaders(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func stripHopHeaders(h http.Header) {
	for _, k := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		h.Del(k)
	}
}
