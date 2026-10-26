package warp

import (
	"net/http"
	"testing"
)

func TestStripHopHeaders(t *testing.T) {
	fixed := []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	}
	endToEnd := []string{"Authorization", "Content-Type", "Cookie"}

	tests := []struct {
		name   string
		header http.Header
		gone   []string
		kept   []string
	}{
		{
			name:   "fixed list removed",
			header: headerWithFixed(fixed),
			gone:   fixed,
		},
		{
			name:   "connection nominated removed",
			header: headerWith("Connection", "X-Foo, X-Bar", "X-Foo", "1", "X-Bar", "2", "Authorization", "Bearer t"),
			gone:   []string{"Connection", "X-Foo", "X-Bar"},
			kept:   []string{"Authorization"},
		},
		{
			name: "end-to-end preserved",
			header: headerWith(
				"Connection", "keep-alive",
				"Authorization", "Bearer t",
				"Content-Type", "text/plain",
				"Cookie", "a=b",
			),
			gone: []string{"Connection"},
			kept: endToEnd,
		},
		{
			name:   "case insensitive",
			header: http.Header{"connection": {"x-lower"}, "x-lower": {"v"}, "proxy-authorization": {"v"}},
			gone:   []string{"Connection", "X-Lower", "Proxy-Authorization"},
		},
		{
			name:   "absent connection header",
			header: headerWith("Authorization", "Bearer t", "Content-Type", "text/plain", "Cookie", "a=b"),
			kept:   endToEnd,
		},
		{
			name:   "empty connection header",
			header: http.Header{"Connection": {""}, "Authorization": {"v"}},
			gone:   []string{"Connection"},
			kept:   []string{"Authorization"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stripHopHeaders(tc.header)
			for _, k := range tc.gone {
				if _, ok := tc.header[http.CanonicalHeaderKey(k)]; ok {
					t.Errorf("%q still present", k)
				}
			}
			for _, k := range tc.kept {
				if tc.header.Get(k) == "" {
					t.Errorf("%q wrongly stripped", k)
				}
			}
		})
	}
}

func headerWith(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

func headerWithFixed(keys []string) http.Header {
	h := http.Header{}
	for _, k := range keys {
		h.Set(k, "v")
	}
	return h
}
