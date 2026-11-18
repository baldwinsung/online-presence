package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fakeServer(t *testing.T, result map[string]any, check func(*http.Request, map[string]any)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(b, &req)
		if check != nil {
			check(r, req)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	}))
}

func textResult(v any, isErr bool) map[string]any {
	b, _ := json.Marshal(v)
	return map[string]any{"content": []map[string]any{{"type": "text", "text": string(b)}}, "isError": isErr}
}

func TestCallAndRender(t *testing.T) {
	rep := map[string]any{
		"domain":       "example.com",
		"registration": map[string]any{"registrar": "Example Registrar", "created": "1995-08-14T04:00:00Z", "expires": "2027-08-13T04:00:00Z"},
		"hosting":      map[string]any{"ip": "192.0.2.1", "all_ipv4": []string{"192.0.2.1"}, "provider": "Example Net"},
		"certificate":  map[string]any{"error": "dial timeout"},
	}
	srv := fakeServer(t, textResult(rep, false), func(r *http.Request, req map[string]any) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("Authorization = %q", got)
		}
		p := req["params"].(map[string]any)
		if p["name"] != "online_presence" || p["arguments"].(map[string]any)["domain"] != "example.com" {
			t.Errorf("params = %v", p)
		}
	})
	defer srv.Close()

	raw, err := call(context.Background(), srv.Client(), srv.URL, "tok", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	var r report
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	render(&out, r)
	for _, want := range []string{"Example Registrar", "192.0.2.1", "Example Net", "dial timeout"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
}

func TestToolError(t *testing.T) {
	srv := fakeServer(t, textResult(map[string]string{"error": "free calls used up"}, true), nil)
	defer srv.Close()
	_, err := call(context.Background(), srv.Client(), srv.URL, "", "example.com")
	if err == nil || err.Error() != "free calls used up" {
		t.Fatalf("err = %v", err)
	}
}
