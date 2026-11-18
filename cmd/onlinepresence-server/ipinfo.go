package main

// ip_info: who holds an IP address and how to reach them (abuse, NOC,
// technical contacts), from the regional registry's RDAP record.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

const maxIPsPerCall = 20

// rdapIPRaw fetches the RDAP record for ip. rdap.arin.net redirects to the
// right regional registry for addresses outside ARIN.
func rdapIPRaw(ctx context.Context, ip net.IP) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://rdap.arin.net/registry/ip/"+ip.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/rdap+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rdap %s: %s", ip, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 2<<20))
}

// parseIPs splits a comma/space/newline-separated list, validates and
// de-duplicates it, keeping input order.
func parseIPs(s string) ([]net.IP, error) {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t'
	})
	var out []net.IP
	seen := map[string]bool{}
	for _, f := range fields {
		ip := net.ParseIP(f)
		if ip == nil {
			return nil, fmt.Errorf("not an IP address: %q", f)
		}
		if seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		out = append(out, ip)
	}
	if len(out) == 0 {
		return nil, errors.New("no IP address given")
	}
	if len(out) > maxIPsPerCall {
		return nil, fmt.Errorf("at most %d IP addresses per call (got %d)", maxIPsPerCall, len(out))
	}
	return out, nil
}

type rdapIPRecord struct {
	Handle       string `json:"handle"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	Country      string `json:"country"`
	StartAddress string `json:"startAddress"`
	EndAddress   string `json:"endAddress"`
	Port43       string `json:"port43"`
	CIDRs        []struct {
		V4     string `json:"v4prefix"`
		V6     string `json:"v6prefix"`
		Length int    `json:"length"`
	} `json:"cidr0_cidrs"`
	Entities []rdapContactEntity `json:"entities"`
}

type rdapContactEntity struct {
	Handle     string              `json:"handle"`
	Roles      []string            `json:"roles"`
	VCardArray []json.RawMessage   `json:"vcardArray"`
	Entities   []rdapContactEntity `json:"entities"`
}

// vcard returns the first value of each of fn, org, email and tel.
func (e rdapContactEntity) vcard() map[string]string {
	out := map[string]string{}
	if len(e.VCardArray) < 2 {
		return out
	}
	var props [][]json.RawMessage
	if json.Unmarshal(e.VCardArray[1], &props) != nil {
		return out
	}
	for _, p := range props {
		var name, value string
		if len(p) < 4 || json.Unmarshal(p[0], &name) != nil || json.Unmarshal(p[3], &value) != nil {
			continue
		}
		switch name {
		case "fn", "org", "email", "tel":
			if _, ok := out[name]; !ok && value != "" {
				out[name] = strings.TrimPrefix(value, "tel:")
			}
		}
	}
	return out
}

// ipInfoFromRDAP turns an RDAP IP network record into the tool's result.
func ipInfoFromRDAP(ip net.IP, raw []byte) (map[string]any, error) {
	var r rdapIPRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("rdap %s: %w", ip, err)
	}
	out := map[string]any{
		"ip":           ip.String(),
		"network_name": r.Name,
		"handle":       r.Handle,
		"type":         r.Type,
		"range":        strings.TrimSpace(r.StartAddress + " - " + r.EndAddress),
		"country":      nilIfEmpty(r.Country),
		"whois_server": nilIfEmpty(r.Port43),
		"holder":       nil,
	}
	var cidrs []string
	for _, c := range r.CIDRs {
		p := c.V4
		if p == "" {
			p = c.V6
		}
		if p != "" {
			cidrs = append(cidrs, fmt.Sprintf("%s/%d", p, c.Length))
		}
	}
	out["cidr"] = cidrs

	// Contacts can be nested (ARIN puts abuse/tech under the registrant).
	contacts := map[string][]map[string]string{}
	seen := map[string]bool{}
	var walk func([]rdapContactEntity)
	walk = func(es []rdapContactEntity) {
		for _, e := range es {
			v := e.vcard()
			for _, role := range e.Roles {
				switch role {
				case "registrant":
					if out["holder"] == nil {
						name := v["fn"]
						if v["org"] != "" {
							name = v["org"]
						}
						out["holder"] = nilIfEmpty(name)
					}
				case "abuse", "noc", "technical":
					key := role + "|" + e.Handle + "|" + v["email"]
					if seen[key] {
						continue
					}
					seen[key] = true
					c := map[string]string{"handle": e.Handle}
					for _, k := range []string{"fn", "email", "tel"} {
						if v[k] != "" {
							c[map[string]string{"fn": "name", "email": "email", "tel": "phone"}[k]] = v[k]
						}
					}
					contacts[role] = append(contacts[role], c)
				}
			}
			walk(e.Entities)
		}
	}
	walk(r.Entities)
	for _, role := range []string{"abuse", "noc", "technical"} {
		out[role] = contacts[role] // nil marshals as null
	}
	return out, nil
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ipInfo looks up every address in list (at most 4 at a time). Each entry
// carries its own error so one bad lookup doesn't sink the rest.
func ipInfo(ctx context.Context, l lookups, list string) (any, error) {
	ips, err := parseIPs(list)
	if err != nil {
		return nil, err
	}
	results := make([]map[string]any, len(ips))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, ip := range ips {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			raw, err := l.rdapIP(ctx, ip)
			if err == nil {
				results[i], err = ipInfoFromRDAP(ip, raw)
			}
			if err != nil {
				results[i] = map[string]any{"ip": ip.String(), "error": err.Error()}
			}
		}()
	}
	wg.Wait()
	if len(results) == 1 {
		return results[0], nil
	}
	return map[string]any{"results": results}, nil
}
