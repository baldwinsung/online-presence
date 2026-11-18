// Command onlinepresence is a thin command-line client for onlinepresence-server.
// It makes one MCP call (online_presence) over Streamable HTTP and prints the
// report. All lookups happen on the server; the client does no DNS, WHOIS or
// TLS work of its own.
//
//	onlinepresence example.com
//	onlinepresence -json example.com
//	onlinepresence -server http://127.0.0.1:8090/ example.com
//
// The server defaults to the public instance; ONLINEPRESENCE_URL or -server
// overrides it. ONLINEPRESENCE_TOKEN, if set, is sent as a Bearer token.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const defaultServer = "https://mcp.baldwinsung.com/onlinepresence"

func main() {
	server := flag.String("server", envOr("ONLINEPRESENCE_URL", defaultServer), "MCP endpoint (Streamable HTTP)")
	asJSON := flag.Bool("json", false, "print the raw JSON report")
	timeout := flag.Duration("timeout", 60*time.Second, "overall timeout")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: onlinepresence [flags] <domain>\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	raw, err := call(ctx, http.DefaultClient, *server, os.Getenv("ONLINEPRESENCE_TOKEN"), flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "onlinepresence:", err)
		os.Exit(1)
	}
	if *asJSON {
		os.Stdout.Write(append(raw, '\n'))
		return
	}
	var r report
	if err := json.Unmarshal(raw, &r); err != nil {
		fmt.Fprintln(os.Stderr, "onlinepresence: unexpected report:", err)
		os.Exit(1)
	}
	render(os.Stdout, r)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// call runs tools/call online_presence and returns the tool's JSON text.
func call(ctx context.Context, c *http.Client, server, token, domain string) ([]byte, error) {
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "online_presence", "arguments": map[string]any{"domain": domain}},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var rpc struct {
		Result *struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(b, &rpc); err != nil {
		return nil, fmt.Errorf("%s: HTTP %d: %s", server, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if rpc.Error != nil {
		return nil, errors.New(rpc.Error.Message)
	}
	if rpc.Result == nil || len(rpc.Result.Content) == 0 {
		return nil, fmt.Errorf("%s: HTTP %d: empty result", server, resp.StatusCode)
	}
	text := []byte(rpc.Result.Content[0].Text)
	if rpc.Result.IsError {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(text, &e) == nil && e.Error != "" {
			return nil, errors.New(e.Error)
		}
		return nil, errors.New(string(text))
	}
	return text, nil
}

type report struct {
	Domain       string `json:"domain"`
	Registration struct {
		Error     string `json:"error"`
		Registrar string `json:"registrar"`
		Created   string `json:"created"`
		Expires   string `json:"expires"`
	} `json:"registration"`
	Hosting struct {
		Error    string   `json:"error"`
		IP       string   `json:"ip"`
		AllIPv4  []string `json:"all_ipv4"`
		Provider string   `json:"provider"`
	} `json:"hosting"`
	Certificate struct {
		Error         string   `json:"error"`
		Subject       string   `json:"subject"`
		Issuer        string   `json:"issuer"`
		NotBefore     string   `json:"not_before"`
		NotAfter      string   `json:"not_after"`
		DaysRemaining int      `json:"days_remaining"`
		Expired       bool     `json:"expired"`
		SAN           []string `json:"san"`
	} `json:"certificate"`
}

func render(w io.Writer, r report) {
	row := func(k, v string) {
		if v == "" {
			v = "-"
		}
		fmt.Fprintf(w, "%-18s %s\n", k+":", v)
	}
	head := func(t string) { fmt.Fprintf(w, "\n%s\n%s\n", t, strings.Repeat("-", len(t))) }

	head("Domain registration")
	row("Domain", r.Domain)
	if e := r.Registration.Error; e != "" {
		row("Error", e)
	} else {
		row("Registrar", r.Registration.Registrar)
		row("Created", r.Registration.Created)
		row("Expires", r.Registration.Expires)
	}

	head("Hosting")
	if e := r.Hosting.Error; e != "" {
		row("Error", e)
	} else {
		row("A record", strings.Join(r.Hosting.AllIPv4, ", "))
		row("Provider", r.Hosting.Provider)
	}

	head("TLS certificate")
	if e := r.Certificate.Error; e != "" {
		row("Error", e)
	} else {
		c := r.Certificate
		row("Subject", c.Subject)
		row("Issuer", c.Issuer)
		row("Not before", c.NotBefore)
		state := fmt.Sprintf("%d days left", c.DaysRemaining)
		if c.Expired {
			state = "EXPIRED"
		}
		row("Not after", c.NotAfter+" ("+state+")")
		row("SANs", fmt.Sprint(len(c.SAN)))
		for _, s := range c.SAN {
			fmt.Fprintf(w, "%-18s %s\n", "", s)
		}
	}
}
