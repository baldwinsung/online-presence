package main

// `onlinepresence-server mcp`: the same lookups as the REST API, exposed as
// Model Context Protocol tools over stdio (newline-delimited JSON-RPC 2.0).
// Hand-rolled (tools only: initialize, tools/list, tools/call, ping) to keep
// the binary dependency-free beyond the WHOIS libraries. Logs go to stderr;
// stdout carries protocol messages only.

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const mcpLatestProtocol = "2025-06-18"

var mcpProtocols = map[string]bool{
	"2024-11-05": true, "2025-03-26": true, "2025-06-18": true, "2025-11-25": true,
}

// myIPURL answers with the caller's public IP as plain text.
var myIPURL = "https://myip.baldwinsung.com"

type rpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpTool struct {
	Name        string         `json:"name"`
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`
	run         func(ctx context.Context, args map[string]any) (any, error)
	// noCache: the result depends on who is asking, not just the arguments,
	// so it must never be served from the shared result cache.
	noCache bool
}

// callerIPKey carries the caller's public IP (set by the HTTP transport from
// a trusted gateway header) through the request context.
type callerIPKey struct{}

func withCallerIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, callerIPKey{}, ip)
}

func callerIP(ctx context.Context) string {
	ip, _ := ctx.Value(callerIPKey{}).(string)
	return ip
}

func domainSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"domain": map[string]any{"type": "string", "description": "DNS name, e.g. example.com (no scheme or path)"},
		},
		"required": []string{"domain"},
	}
}

var readOnly = map[string]any{"readOnlyHint": true, "openWorldHint": true}

func mcpTools(l lookups) []mcpTool {
	domainArg := func(args map[string]any) (string, error) {
		s, _ := args["domain"].(string)
		s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
		s, _, _ = strings.Cut(s, "/")
		return validDomain(s)
	}
	registration := func(ctx context.Context, d string) (map[string]any, error) {
		info, err := l.whois(ctx, d)
		if err != nil {
			return nil, err
		}
		out := map[string]any{"domain": d, "registrar": nil, "created": nil, "expires": nil}
		if info.Registrar != nil && info.Registrar.Name != "" {
			out["registrar"] = info.Registrar.Name
		}
		if info.Domain != nil {
			out["created"] = isoDate(info.Domain.CreatedDateInTime)
			out["expires"] = isoDate(info.Domain.ExpirationDateInTime)
			if t := info.Domain.ExpirationDateInTime; t != nil {
				out["days_until_expiry"] = int(time.Until(*t).Hours() / 24)
			}
		}
		return out, nil
	}
	hosting := func(ctx context.Context, d string) (map[string]any, error) {
		ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
		defer cancel()
		ips, err := l.resolveA(ctx, d)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, errors.New("no A record found")
		}
		name, err := l.rdapName(ctx, ips[0])
		if err != nil {
			return nil, err
		}
		all := make([]string, len(ips))
		for i, ip := range ips {
			all[i] = ip.String()
		}
		return map[string]any{"domain": d, "ip": ips[0].String(), "all_ipv4": all, "provider": name}, nil
	}
	certInfo := func(ctx context.Context, d string) (map[string]any, error) {
		c, err := l.cert(ctx, d)
		if err != nil {
			return nil, err
		}
		return certMap(d, c), nil
	}

	return []mcpTool{
		{
			Name: "domain_registration", Title: "Domain registration",
			Description: "Registrar, registration date and expiry date of a domain (RDAP, falling back to WHOIS).",
			InputSchema: domainSchema(), Annotations: readOnly,
			run: func(ctx context.Context, a map[string]any) (any, error) {
				d, err := domainArg(a)
				if err != nil {
					return nil, err
				}
				return registration(ctx, d)
			},
		},
		{
			Name: "hosting_provider", Title: "Hosting provider",
			Description: "Resolve a domain's A record and report who holds that IP block (RDAP). Behind a CDN this is the CDN, not the origin host.",
			InputSchema: domainSchema(), Annotations: readOnly,
			run: func(ctx context.Context, a map[string]any) (any, error) {
				d, err := domainArg(a)
				if err != nil {
					return nil, err
				}
				return hosting(ctx, d)
			},
		},
		{
			Name: "ssl_certificate", Title: "TLS certificate",
			Description: "The certificate a domain presents on port 443 (not validated, so expired or self-signed certs are still reported): subject, issuer, validity dates, days remaining, SANs.",
			InputSchema: domainSchema(), Annotations: readOnly,
			run: func(ctx context.Context, a map[string]any) (any, error) {
				d, err := domainArg(a)
				if err != nil {
					return nil, err
				}
				return certInfo(ctx, d)
			},
		},
		{
			Name: "online_presence", Title: "Online presence report",
			Description: "Registration, hosting provider and TLS certificate for a domain in one call. Each section reports its own error if that lookup fails.",
			InputSchema: domainSchema(), Annotations: readOnly,
			run: func(ctx context.Context, a map[string]any) (any, error) {
				d, err := domainArg(a)
				if err != nil {
					return nil, err
				}
				out := map[string]any{"domain": d}
				section := func(k string, v map[string]any, err error) {
					if err != nil {
						out[k] = map[string]any{"error": err.Error()}
						return
					}
					delete(v, "domain")
					out[k] = v
				}
				r, err := registration(ctx, d)
				section("registration", r, err)
				h, err := hosting(ctx, d)
				section("hosting", h, err)
				c, err := certInfo(ctx, d)
				section("certificate", c, err)
				return out, nil
			},
		},
		{
			Name: "ip_info", Title: "IP address info",
			Description: "Who holds an IP address (IPv4 or IPv6) and how to reach them, from the regional registry's RDAP record: network name, range/CIDR, country, holder, and abuse, NOC and technical contacts (name, email, phone). Pass one address or up to 20 separated by commas, spaces or newlines.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"ip": map[string]any{"type": "string", "description": "One IP address, or several separated by commas, spaces or newlines (max 20)"},
				},
				"required": []string{"ip"},
			},
			Annotations: readOnly,
			run: func(ctx context.Context, a map[string]any) (any, error) {
				s, _ := a["ip"].(string)
				return ipInfo(ctx, l, s)
			},
		},
		{
			Name: "my_public_ip", Title: "My public IP",
			Description: "The public IP address this MCP server's outbound traffic appears from, as seen by myip.baldwinsung.com. Behind a forward proxy this is the proxy's egress IP, not the local network's.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
			Annotations: readOnly,
			noCache:     true,
			run: func(ctx context.Context, _ map[string]any) (any, error) {
				return myPublicIP(ctx)
			},
		},
	}
}

func isoDate(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func certMap(d string, c *x509.Certificate) map[string]any {
	now := time.Now()
	return map[string]any{
		"domain":         d,
		"subject":        nameAttr(c.Subject, oidCommonName),
		"issuer":         nameAttr(c.Issuer, oidOrganization),
		"not_before":     c.NotBefore.UTC().Format(time.RFC3339),
		"not_after":      c.NotAfter.UTC().Format(time.RFC3339),
		"days_remaining": int(c.NotAfter.Sub(now).Hours() / 24),
		"expired":        now.After(c.NotAfter),
		"san":            subjectAltNames(c),
	}
}

func myPublicIP(ctx context.Context) (any, error) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, myIPURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", myIPURL, resp.Status)
	}
	return map[string]any{"ip": strings.TrimSpace(string(b)), "source": myIPURL}, nil
}

// callerIPTool is my_public_ip for a public server: the address the caller's
// request arrived from, as the gateway in front saw it.
func callerIPTool(t mcpTool) mcpTool {
	t.Description = "Your public IP address: where your requests to this server come from, as seen at its edge. " +
		"From a local client (Claude Code, Claude Desktop, an IDE) that is your network's egress IP, or your VPN/proxy's. " +
		"From a hosted client (e.g. a claude.ai connector) it is that service's egress IP, not yours."
	t.run = func(ctx context.Context, _ map[string]any) (any, error) {
		ip := callerIP(ctx)
		if ip == "" {
			return nil, errors.New("caller IP not available")
		}
		return map[string]any{"ip": ip, "source": "caller address at the server's edge"}, nil
	}
	return t
}

// mcpOptions shape one server instance. The zero value is the local stdio
// server: every tool, no cache, no concurrency cap.
type mcpOptions struct {
	// public is for a server exposed to the internet. There my_public_ip
	// can't report the server's own egress IP (meaningless to a remote
	// caller): it reports the caller's IP if callerIPHeader is set, and is
	// dropped otherwise.
	public bool
	// callerIPHeader names a request header carrying the caller's public IP,
	// set by a trusted gateway in front (HTTP transport only). Only set it
	// when nothing but that gateway can reach the server.
	callerIPHeader string
	// cacheTTL > 0 caches each tool result per (tool, arguments) for that long.
	cacheTTL time.Duration
	// maxCalls > 0 caps concurrent tools/call; a call that can't get a slot
	// within callWait gets a "busy" tool error instead of queueing forever.
	maxCalls int
	callWait time.Duration
}

type mcpServer struct {
	tools  []mcpTool
	byName map[string]mcpTool
	opts   mcpOptions
	cache  *resultCache
	slots  chan struct{}
}

func newMCPServer(l lookups, o mcpOptions) *mcpServer {
	s := &mcpServer{byName: map[string]mcpTool{}, opts: o}
	for _, t := range mcpTools(l) {
		if o.public && t.Name == "my_public_ip" {
			if o.callerIPHeader == "" {
				continue
			}
			t = callerIPTool(t)
		}
		s.tools = append(s.tools, t)
		s.byName[t.Name] = t
	}
	if o.cacheTTL > 0 {
		s.cache = newResultCache(o.cacheTTL, 2000)
	}
	if o.maxCalls > 0 {
		s.slots = make(chan struct{}, o.maxCalls)
	}
	return s
}

func (s *mcpServer) instructions() string {
	text := "Live lookups about public domains: registration (RDAP/WHOIS), hosting provider (IP RDAP), TLS certificate"
	if _, ok := s.byName["my_public_ip"]; ok {
		if s.opts.public {
			return text + ", plus the public IP your requests come from."
		}
		return text + ", plus this host's public egress IP."
	}
	return text + "."
}

// handle answers one JSON-RPC message. ok is false for notifications and
// client responses, which get no reply.
func (s *mcpServer) handle(ctx context.Context, m rpcMsg) (resp rpcResp, ok bool) {
	if len(m.ID) == 0 || m.Method == "" { // notification (initialized, cancelled, ...) or a response
		return rpcResp{}, false
	}
	resp = rpcResp{JSONRPC: "2.0", ID: m.ID}
	switch m.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(m.Params, &p)
		v := mcpLatestProtocol
		if mcpProtocols[p.ProtocolVersion] {
			v = p.ProtocolVersion
		}
		resp.Result = map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "onlinepresence", "version": "1.1.0"},
			"instructions":    s.instructions(),
		}
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": s.tools}
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(m.Params, &p); err != nil {
			resp.Error = &rpcError{-32602, "invalid params"}
			break
		}
		t, found := s.byName[p.Name]
		if !found {
			resp.Error = &rpcError{-32602, "unknown tool: " + p.Name}
			break
		}
		resp.Result = s.call(ctx, t, p.Arguments)
	default:
		resp.Error = &rpcError{-32601, "method not found: " + m.Method}
	}
	return resp, true
}

func (s *mcpServer) call(ctx context.Context, t mcpTool, args map[string]any) map[string]any {
	key := ""
	if s.cache != nil && !t.noCache {
		b, _ := json.Marshal(args) // map keys marshal sorted, so equal args give equal keys
		key = t.Name + "\x00" + string(b)
		if v, hit := s.cache.get(key); hit {
			return v
		}
	}
	if s.slots != nil {
		wait := s.opts.callWait
		if wait <= 0 {
			wait = 5 * time.Second
		}
		timer := time.NewTimer(wait)
		select {
		case s.slots <- struct{}{}:
			timer.Stop()
			defer func() { <-s.slots }()
		case <-timer.C:
			return toolResult(map[string]string{"error": "server busy, try again shortly"}, true)
		case <-ctx.Done():
			timer.Stop()
			return toolResult(map[string]string{"error": ctx.Err().Error()}, true)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*lookupTimeout)
	defer cancel()
	start := time.Now()
	v, err := t.run(ctx, args)
	if err != nil {
		log.Printf("%s: %v (%s)", t.Name, err, time.Since(start).Round(time.Millisecond))
		// Errors aren't cached: most are transient (timeouts, rate limits).
		return toolResult(map[string]string{"error": err.Error()}, true)
	}
	out := toolResult(v, false)
	if s.cache != nil && !t.noCache {
		s.cache.put(key, out)
	}
	return out
}

// serveMCP runs the stdio loop until in closes.
func serveMCP(in io.Reader, out io.Writer, l lookups) error {
	s := newMCPServer(l, mcpOptions{})
	enc := json.NewEncoder(out)
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m rpcMsg
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			enc.Encode(rpcResp{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
			continue
		}
		resp, ok := s.handle(context.Background(), m)
		if !ok {
			continue
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

func toolResult(v any, isErr bool) map[string]any {
	b, _ := json.MarshalIndent(v, "", "  ")
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(b)}},
		"isError": isErr,
	}
}
