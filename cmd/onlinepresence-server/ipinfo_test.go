package main

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
)

// Trimmed from rdap.arin.net/registry/ip/8.8.8.8: the abuse and technical
// contacts are nested under the registrant, as ARIN returns them.
const rdapIPFixture = `{
  "handle": "NET-8-8-8-0-2", "name": "GOGL", "type": "DIRECT ALLOCATION",
  "startAddress": "8.8.8.0", "endAddress": "8.8.8.255", "port43": "whois.arin.net",
  "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
  "entities": [{
    "handle": "GOGL", "roles": ["registrant"],
    "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Google LLC"]]],
    "entities": [
      {"handle": "ABUSE5250-ARIN", "roles": ["abuse"],
       "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"], ["email", {}, "text", "network-abuse@google.com"],
                                ["tel", {"type": ["work", "voice"]}, "text", "+1-650-253-0000"]]]},
      {"handle": "ZG39-ARIN", "roles": ["administrative", "technical"],
       "vcardArray": ["vcard", [["fn", {}, "text", "Google LLC"], ["email", {}, "text", "arin-contact@google.com"]]]}
    ]
  }]
}`

func TestIPInfoFromRDAP(t *testing.T) {
	got, err := ipInfoFromRDAP(net.ParseIP("8.8.8.8"), []byte(rdapIPFixture))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(got)
	for _, want := range []string{
		`"holder":"Google LLC"`, `"network_name":"GOGL"`, `"cidr":["8.8.8.0/24"]`,
		`"range":"8.8.8.0 - 8.8.8.255"`, `"whois_server":"whois.arin.net"`,
		`"email":"network-abuse@google.com"`, `"phone":"+1-650-253-0000"`,
		`"technical":[{"email":"arin-contact@google.com"`, `"noc":null`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s in %s", want, b)
		}
	}
}

func TestParseIPs(t *testing.T) {
	ips, err := parseIPs(" 8.8.8.8, 1.1.1.1\n8.8.8.8 2001:4860:4860::8888 ")
	if err != nil || len(ips) != 3 {
		t.Fatalf("got %v, %v", ips, err)
	}
	for _, bad := range []string{"", " , ", "8.8.8.8, example.com", strings.Repeat("10.0.0.1 ", 1) + "999.1.1.1"} {
		if _, err := parseIPs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	var many []string
	for i := 0; i < maxIPsPerCall+1; i++ {
		many = append(many, net.IPv4(10, 0, 0, byte(i+1)).String())
	}
	if _, err := parseIPs(strings.Join(many, ",")); err == nil {
		t.Error("over the limit accepted")
	}
}

func TestIPInfoBulk(t *testing.T) {
	v, err := ipInfo(context.Background(), fakeLookups(), "8.8.8.8, 192.0.2.9")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(v)
	s := string(b)
	if !strings.Contains(s, `"results":[{`) || !strings.Contains(s, `{"error":"rdap 192.0.2.9: 404 Not Found","ip":"192.0.2.9"}`) ||
		strings.Index(s, `"8.8.8.8"`) > strings.Index(s, `"192.0.2.9"`) {
		t.Errorf("bulk result wrong: %s", s)
	}
}
