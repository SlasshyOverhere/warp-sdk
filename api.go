// Package warp is a userspace Cloudflare WARP client.
package warp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

const (
	apiBase = "https://api.cloudflareclient.com/v0a1922"

	// Confirm registration still works before bumping cfClientVersion.
	cfClientVersion = "a-6.30-3596"
	warpUserAgent   = "okhttp/3.12.1"
)

type apiError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("warp: %s %s: http %d: %s", e.Method, e.Path, e.Status, strings.TrimSpace(e.Body))
}

type api struct {
	hc    *http.Client
	base  string
	token string
}

func newAPI(token string) *api {
	tr := &http.Transport{
		DialTLSContext:      tlsDialContext,
		ForceAttemptHTTP2:   false,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}
	return &api{
		hc:    &http.Client{Transport: tr, Timeout: 30 * time.Second},
		base:  apiBase,
		token: token,
	}
}

func (a *api) request(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("warp: encode %s %s: %w", method, path, err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("User-Agent", warpUserAgent)
	req.Header.Set("CF-Client-Version", cfClientVersion)
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return fmt.Errorf("warp: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("warp: read %s %s: %w", method, path, err)
	}
	if resp.StatusCode/100 != 2 {
		return &apiError{Method: method, Path: path, Status: resp.StatusCode, Body: string(b)}
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("warp: decode %s %s: %w", method, path, err)
		}
	}
	return nil
}

func tlsDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	mode := os.Getenv("WARP_TLS")
	var stdErr error
	if mode != "utls" {
		conn, err := dialStdTLS(ctx, network, addr, host)
		if err == nil {
			return conn, nil
		}
		stdErr = err
	}
	if mode != "std" {
		conn, err := dialUTLS(ctx, network, addr, host)
		if err == nil {
			return conn, nil
		}
		if stdErr == nil {
			return nil, fmt.Errorf("warp: tls dial %s: %w", addr, err)
		}
	}
	return nil, fmt.Errorf("warp: tls dial %s: %w", addr, stdErr)
}

func tcpDial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	return d.DialContext(ctx, network, addr)
}

func dialStdTLS(ctx context.Context, network, addr, host string) (net.Conn, error) {
	raw, err := tcpDial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, &tls.Config{
		ServerName: host,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	hctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := conn.HandshakeContext(hctx); err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

func dialUTLS(ctx context.Context, network, addr, host string) (net.Conn, error) {
	raw, err := tcpDial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	conn := utls.UClient(raw, &utls.Config{
		ServerName: host,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	}, utls.HelloCustom)
	// The stock Chrome preset advertises h2; this transport only speaks h1.
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		raw.Close()
		return nil, err
	}
	for i, ext := range spec.Extensions {
		if _, ok := ext.(*utls.ALPNExtension); ok {
			spec.Extensions[i] = &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}}
		}
	}
	if err := conn.ApplyPreset(&spec); err != nil {
		raw.Close()
		return nil, err
	}
	hctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := conn.HandshakeContext(hctx); err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}
