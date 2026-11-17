package main

// Outbound paths that work behind an HTTP forward proxy, for hosts whose
// only internet access is HTTPS through a proxy. So
//   - registration data comes from RDAP (HTTPS, honors HTTPS_PROXY) first,
//     falling back to port-43 WHOIS only if RDAP has nothing;
//   - the TLS certificate fetch tunnels through HTTPS_PROXY with CONNECT
//     when one applies to the domain (http.ProxyFromEnvironment rules,
//     NO_PROXY included), and dials direct otherwise, as before.

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	whoisparser "github.com/likexian/whois-parser"
)

// domainRE accepts plain DNS names only (letters, digits, hyphens, dots;
// IDNs as punycode). It keeps CR/LF, spaces, ports and paths out of the
// CONNECT line and RDAP URLs.
var domainRE = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+\.?$`)

func validDomain(d string) (string, error) {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if len(d) > 253 || !domainRE.MatchString(d) {
		return "", fmt.Errorf("not a domain name: %q", d)
	}
	return d, nil
}

// dialTLS443 opens a TLS connection to domain:443 (unverified: we report
// whatever certificate is there), via CONNECT through the environment's
// HTTPS proxy when one applies.
func dialTLS443(ctx context.Context, domain string) (*tls.Conn, error) {
	cfg := &tls.Config{ServerName: domain, InsecureSkipVerify: true}
	target := net.JoinHostPort(domain, "443")
	nd := &net.Dialer{Timeout: 5 * time.Second}

	proxyURL, err := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: domain}})
	if err != nil {
		return nil, err
	}
	if proxyURL == nil {
		d := tls.Dialer{NetDialer: nd, Config: cfg}
		c, err := d.DialContext(ctx, "tcp", target)
		if err != nil {
			return nil, err
		}
		return c.(*tls.Conn), nil
	}

	phost := proxyURL.Host
	if proxyURL.Port() == "" {
		phost = net.JoinHostPort(proxyURL.Hostname(), "3128")
	}
	raw, err := nd.DialContext(ctx, "tcp", phost)
	if err != nil {
		return nil, fmt.Errorf("proxy %s: %w", phost, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		raw.SetDeadline(dl)
	} else {
		raw.SetDeadline(time.Now().Add(lookupTimeout))
	}
	fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("proxy CONNECT %s: %w", target, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw.Close()
		return nil, fmt.Errorf("proxy CONNECT %s: %s", target, resp.Status)
	}
	if br.Buffered() > 0 {
		raw.Close()
		return nil, errors.New("proxy sent data before the TLS handshake")
	}
	c := tls.Client(raw, cfg)
	if err := c.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	raw.SetDeadline(time.Time{})
	return c, nil
}

func fetchCert(ctx context.Context, domain string) (*x509.Certificate, error) {
	conn, err := dialTLS443(ctx, domain)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("no certificate presented")
	}
	return certs[0], nil
}

// --- RDAP domain lookup (RFC 9224 bootstrap + RFC 9083 response) ---

const ianaDNSBootstrap = "https://data.iana.org/rdap/dns.json"

var (
	bootstrapOnce sync.Once
	bootstrapMap  map[string]string // tld (or multi-label suffix) -> base URL
	bootstrapErr  error
)

func getJSON(ctx context.Context, u string, v any) error {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return whoisparser.ErrNotFoundDomain
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func rdapBase(ctx context.Context, domain string) (string, error) {
	bootstrapOnce.Do(func() {
		var b struct {
			Services [][][]string `json:"services"`
		}
		if bootstrapErr = getJSON(ctx, ianaDNSBootstrap, &b); bootstrapErr != nil {
			return
		}
		bootstrapMap = map[string]string{}
		for _, s := range b.Services {
			if len(s) < 2 || len(s[1]) == 0 {
				continue
			}
			base := s[1][0]
			for _, u := range s[1] { // prefer https
				if strings.HasPrefix(u, "https://") {
					base = u
					break
				}
			}
			for _, tld := range s[0] {
				bootstrapMap[strings.ToLower(tld)] = base
			}
		}
	})
	if bootstrapErr != nil {
		// allow a retry on the next call
		err := bootstrapErr
		bootstrapOnce = sync.Once{}
		return "", err
	}
	labels := strings.Split(domain, ".")
	for i := range labels { // longest suffix first
		if base, ok := bootstrapMap[strings.Join(labels[i:], ".")]; ok {
			return base, nil
		}
	}
	return "", fmt.Errorf("no RDAP server for %q", domain)
}

type rdapDomainResponse struct {
	Events []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Entities []struct {
		rdapEntity
		Roles []string `json:"roles"`
	} `json:"entities"`
}

// rdapDomain returns registrar + dates for domain in whois-parser's shape,
// so the REST routes don't care which source answered.
func rdapDomain(ctx context.Context, domain string) (whoisparser.WhoisInfo, error) {
	base, err := rdapBase(ctx, domain)
	if err != nil {
		return whoisparser.WhoisInfo{}, err
	}
	var r rdapDomainResponse
	if err := getJSON(ctx, strings.TrimSuffix(base, "/")+"/domain/"+domain, &r); err != nil {
		return whoisparser.WhoisInfo{}, err
	}
	info := whoisparser.WhoisInfo{Domain: &whoisparser.Domain{Domain: domain}}
	for _, e := range r.Events {
		t, err := time.Parse(time.RFC3339, e.Date)
		if err != nil {
			continue
		}
		switch e.Action {
		case "registration":
			info.Domain.CreatedDateInTime = &t
		case "expiration":
			info.Domain.ExpirationDateInTime = &t
		}
	}
	for _, e := range r.Entities {
		for _, role := range e.Roles {
			if role == "registrar" {
				if fn := e.fn(); fn != "" {
					info.Registrar = &whoisparser.Contact{Name: fn}
				}
			}
		}
	}
	if info.Registrar == nil && info.Domain.CreatedDateInTime == nil && info.Domain.ExpirationDateInTime == nil {
		return info, errors.New("rdap: no registrar or dates in response")
	}
	return info, nil
}
