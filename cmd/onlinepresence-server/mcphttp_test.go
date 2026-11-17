package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	whoisparser "github.com/likexian/whois-parser"
)

func post(t *testing.T, h http.Handler, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMCPHTTP(t *testing.T) {
	s := newMCPServer(fakeLookups(), mcpOptions{public: true})
	h := s.httpHandler(map[string]bool{"https://claude.ai": true})

	for _, tc := range []struct {
		name, body string
		hdr        map[string]string
		code       int
		want       string
	}{
		{"initialize", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`, nil, 200, `"protocolVersion":"2025-06-18"`},
		{"notification gets 202", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil, 202, ""},
		{"client response gets 202", `{"jsonrpc":"2.0","id":7,"result":{}}`, nil, 202, ""},
		{"tool call", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"domain_registration","arguments":{"domain":"google.com"}}}`, map[string]string{"MCP-Protocol-Version": "2025-06-18"}, 200, `MarkMonitor`},
		{"public mode hides my_public_ip", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"my_public_ip","arguments":{}}}`, nil, 200, `unknown tool: my_public_ip`},
		{"batch refused", `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, nil, 400, `batch requests are not supported`},
		{"parse error", `{nope`, nil, 400, `"code":-32700`},
		{"wrong jsonrpc", `{"jsonrpc":"1.0","id":1,"method":"ping"}`, nil, 400, `"code":-32600`},
		{"bad protocol header", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, map[string]string{"MCP-Protocol-Version": "1999-01-01"}, 400, `unsupported MCP-Protocol-Version`},
		{"foreign origin", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, map[string]string{"Origin": "https://evil.example"}, 403, ""},
		{"allowed origin", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, map[string]string{"Origin": "https://claude.ai"}, 200, `"result":{}`},
		{"wrong content type", `{"jsonrpc":"2.0","id":1,"method":"ping"}`, map[string]string{"Content-Type": "text/plain"}, 415, ""},
		{"oversized body", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"` + strings.Repeat("a", mcpMaxBody) + `"}}`, nil, 413, ""},
	} {
		rec := post(t, h, tc.body, tc.hdr)
		if rec.Code != tc.code {
			t.Errorf("%s: status %d, want %d (%s)", tc.name, rec.Code, tc.code, rec.Body.String())
			continue
		}
		if tc.want != "" && !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: body missing %s:\n%s", tc.name, tc.want, rec.Body.String())
		}
		if tc.code == 200 && rec.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%s: Content-Type %q", tc.name, rec.Header().Get("Content-Type"))
		}
	}

	// tools/list in public mode
	rec := post(t, h, `{"jsonrpc":"2.0","id":9,"method":"tools/list"}`, nil)
	if strings.Contains(rec.Body.String(), "my_public_ip") || !strings.Contains(rec.Body.String(), "online_presence") {
		t.Errorf("public tools/list wrong:\n%s", rec.Body.String())
	}

	for _, m := range []string{"GET", "DELETE"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(m, "/", nil))
		if rec.Code != 405 || rec.Header().Get("Allow") != "POST" {
			t.Errorf("%s /: %d Allow=%q, want 405 Allow=POST", m, rec.Code, rec.Header().Get("Allow"))
		}
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Errorf("/healthz: %d", rec.Code)
	}

	// public + caller-IP header: my_public_ip reports the caller, never cached
	pub := newMCPServer(fakeLookups(), mcpOptions{public: true, callerIPHeader: "X-MCP-Caller-IP", cacheTTL: time.Minute}).httpHandler(nil)
	call := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"my_public_ip","arguments":{}}}`
	for _, tc := range []struct{ hdr, want string }{
		{"203.0.113.7", `\"ip\": \"203.0.113.7\"`},
		{"2001:db8::1", `\"ip\": \"2001:db8::1\"`},
		{"::ffff:198.51.100.9", `\"ip\": \"198.51.100.9\"`},
		{"", `caller IP not available`},
		{"not-an-ip", `caller IP not available`},
	} {
		rec := post(t, pub, call, map[string]string{"X-MCP-Caller-IP": tc.hdr})
		if !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("caller IP %q: body missing %s:\n%s", tc.hdr, tc.want, rec.Body.String())
		}
	}
	if rec := post(t, pub, `{"jsonrpc":"2.0","id":5,"method":"initialize","params":{}}`, nil); !strings.Contains(rec.Body.String(), "the public IP your requests come from") {
		t.Errorf("public instructions don't mention caller IP:\n%s", rec.Body.String())
	}

	// local (non-public) server still lists my_public_ip
	local := newMCPServer(fakeLookups(), mcpOptions{}).httpHandler(nil)
	if rec := post(t, local, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil); !strings.Contains(rec.Body.String(), "my_public_ip") {
		t.Errorf("local tools/list lost my_public_ip")
	}
}

func TestMCPCacheAndBusy(t *testing.T) {
	var calls atomic.Int32
	l := fakeLookups()
	inner := l.whois
	release := make(chan struct{})
	l.whois = func(ctx context.Context, d string) (whoisparser.WhoisInfo, error) {
		calls.Add(1)
		if d == "slow.example" {
			<-release
		}
		return inner(ctx, "google.com")
	}
	s := newMCPServer(l, mcpOptions{cacheTTL: time.Minute, maxCalls: 1, callWait: 50 * time.Millisecond})
	reg, ok := s.byName["domain_registration"]
	if !ok {
		t.Fatal("no domain_registration tool")
	}
	args := map[string]any{"domain": "google.com"}
	s.call(context.Background(), reg, args)
	s.call(context.Background(), reg, map[string]any{"domain": "google.com"})
	if n := calls.Load(); n != 1 {
		t.Errorf("lookups after two identical calls = %d, want 1 (cached)", n)
	}

	// one slot: a second distinct call while the first is in flight gets "busy"
	done := make(chan struct{})
	go func() { s.call(context.Background(), reg, map[string]any{"domain": "slow.example"}); close(done) }()
	for calls.Load() < 2 {
		time.Sleep(time.Millisecond)
	}
	r := s.call(context.Background(), reg, map[string]any{"domain": "other.example"})
	if r["isError"] != true || !strings.Contains(r["content"].([]map[string]any)[0]["text"].(string), "busy") {
		t.Errorf("expected busy error, got %v", r)
	}
	close(release)
	<-done
}

func TestPublicOnlyControl(t *testing.T) {
	for addr, ok := range map[string]bool{
		"93.184.216.34:443": true, "1.1.1.1:43": true, "[2606:4700::1111]:443": true,
		"10.0.0.1:443": false, "127.0.0.1:443": false, "169.254.169.254:80": false,
		"192.168.1.1:443": false, "100.64.1.1:443": false, "[::1]:443": false,
		"[fd00::1]:443": false, "[::ffff:10.0.0.1]:443": false, "0.0.0.0:443": false,
	} {
		err := publicOnlyControl("tcp", addr, nil)
		if (err == nil) != ok {
			t.Errorf("%s: err=%v, want allowed=%v", addr, err, ok)
		}
	}
	if isPublicAddr(netip.Addr{}) {
		t.Error("zero Addr counted as public")
	}
}
