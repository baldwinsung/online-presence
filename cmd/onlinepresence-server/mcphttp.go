package main

// `onlinepresence-server serve-mcp`: the MCP tools over Streamable HTTP
// (MCP spec 2025-03-26 and later), for running behind a reverse proxy or
// gateway that terminates TLS and does authentication/rate limiting.
//
// Deliberately small:
//   - POST only. Every response is a single application/json body; the
//     server never opens an SSE stream, so GET (and DELETE) get 405, which
//     the spec allows for servers without server-initiated messages.
//   - Stateless: no Mcp-Session-Id. Each POST stands alone.
//   - No JSON-RPC batches (removed from the spec in 2025-06-18), 64 KiB body
//     limit, Origin allow-list (DNS-rebinding protection the spec requires
//     for servers reachable from browsers).
//   - Results cached per (tool, arguments) and concurrent calls capped
//     (mcpOptions), so one busy client can't fan out unbounded lookups.
//
// Environment:
//   MCP_LISTEN_ADDR      default 127.0.0.1:8090 (keep it on loopback behind a proxy)
//   MCP_PUBLIC=1         internet-facing mode: refuse outbound connections to
//                        private/reserved addresses (so a crafted domain can't
//                        make the server probe its own network, e.g. a name
//                        whose A record is 10.0.0.1), and my_public_ip reports
//                        the caller's IP from MCP_CALLER_IP_HEADER (dropped
//                        if that's unset) instead of the server's own
//   MCP_CALLER_IP_HEADER request header with the caller's IP, set by the
//                        gateway in front (e.g. X-MCP-Caller-IP). Trusted as
//                        is: only set it when the gateway is the sole client
//   MCP_ALLOWED_ORIGINS  comma-separated Origin values to accept; requests
//                        with any other Origin header get 403 (requests with
//                        no Origin, i.e. non-browser clients, are accepted)

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

const mcpMaxBody = 64 << 10

func runServeMCP() error {
	addr := os.Getenv("MCP_LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8090"
	}
	public := os.Getenv("MCP_PUBLIC") == "1"
	if public {
		enablePublicEgress()
	}
	origins := map[string]bool{}
	for _, o := range strings.Split(os.Getenv("MCP_ALLOWED_ORIGINS"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			origins[o] = true
		}
	}
	s := newMCPServer(liveLookups(), mcpOptions{
		public:         public,
		callerIPHeader: strings.TrimSpace(os.Getenv("MCP_CALLER_IP_HEADER")),
		cacheTTL:       10 * time.Minute,
		maxCalls:       8,
		callWait:       5 * time.Second,
	})
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.httpHandler(origins),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      2*lookupTimeout + 15*time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	log.Printf("onlinepresence MCP (Streamable HTTP) on %s, public=%v, %d tools", addr, public, len(s.tools))
	return srv.ListenAndServe()
}

func (s *mcpServer) httpHandler(allowedOrigins map[string]bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" && !allowedOrigins[o] {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "this server only accepts POST (no SSE stream)", http.StatusMethodNotAllowed)
			return
		}
		s.servePOST(w, r)
	})
	return mux
}

func (s *mcpServer) servePOST(w http.ResponseWriter, r *http.Request) {
	rpcErr := func(status, code int, msg string) {
		writeJSON(w, status, rpcResp{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{code, msg}})
	}
	if v := r.Header.Get("MCP-Protocol-Version"); v != "" && !mcpProtocols[v] {
		rpcErr(http.StatusBadRequest, -32600, "unsupported MCP-Protocol-Version: "+v)
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		rpcErr(http.StatusUnsupportedMediaType, -32700, "Content-Type must be application/json")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, mcpMaxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			rpcErr(http.StatusRequestEntityTooLarge, -32600, fmt.Sprintf("request body over %d bytes", mcpMaxBody))
			return
		}
		rpcErr(http.StatusBadRequest, -32700, "could not read body")
		return
	}
	body = bytes.TrimSpace(body)
	if len(body) > 0 && body[0] == '[' {
		rpcErr(http.StatusBadRequest, -32600, "batch requests are not supported")
		return
	}
	var m rpcMsg
	if err := json.Unmarshal(body, &m); err != nil {
		rpcErr(http.StatusBadRequest, -32700, "parse error")
		return
	}
	if m.JSONRPC != "2.0" {
		rpcErr(http.StatusBadRequest, -32600, `jsonrpc must be "2.0"`)
		return
	}
	ctx := r.Context()
	if h := s.opts.callerIPHeader; h != "" {
		if a, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get(h))); err == nil {
			ctx = withCallerIP(ctx, a.Unmap().String())
		}
	}
	resp, ok := s.handle(ctx, m)
	if !ok { // notification or client response
		w.WriteHeader(http.StatusAccepted)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- result cache ---

type cacheEntry struct {
	v       map[string]any
	expires time.Time
}

type resultCache struct {
	mu  sync.Mutex
	ttl time.Duration
	max int
	m   map[string]cacheEntry
}

func newResultCache(ttl time.Duration, max int) *resultCache {
	return &resultCache{ttl: ttl, max: max, m: map[string]cacheEntry{}}
}

func (c *resultCache) get(k string) (map[string]any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if !ok || time.Now().After(e.expires) {
		delete(c.m, k)
		return nil, false
	}
	return e.v, true
}

func (c *resultCache) put(k string, v map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.max {
		now := time.Now()
		for key, e := range c.m {
			if now.After(e.expires) {
				delete(c.m, key)
			}
		}
		for key := range c.m { // still full: drop arbitrary entries
			if len(c.m) < c.max {
				break
			}
			delete(c.m, key)
		}
	}
	c.m[k] = cacheEntry{v: v, expires: time.Now().Add(c.ttl)}
}

// --- outbound address guard (MCP_PUBLIC=1) ---

// egressControl, when set, runs on every outbound socket (TLS cert dial,
// RDAP/HTTP, port-43 WHOIS) after DNS resolution, so it sees the real
// destination IP and also covers redirects and DNS rebinding.
var egressControl func(network, address string, c syscall.RawConn) error

var nonPublic = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64", "2001:db8::/32",
		"fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func isPublicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

func publicOnlyControl(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("refusing to dial %q: not an IP address", host)
	}
	if !isPublicAddr(a) {
		return fmt.Errorf("refusing to connect to non-public address %s", a)
	}
	return nil
}

func enablePublicEgress() {
	egressControl = publicOnlyControl
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: publicOnlyControl}).DialContext
	http.DefaultClient = &http.Client{Transport: t, Timeout: lookupTimeout}
}
