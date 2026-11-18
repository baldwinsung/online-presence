# online-presence

**Public GitHub repo.** One Go binary that looks up a domain's registration,
hosting provider and TLS certificate, served as an MCP server (stdio and
Streamable HTTP) and as a REST API, plus `cmd/onlinepresence`, a thin CLI
that calls a server's `online_presence` tool (no lookups of its own). README.md is the user-facing reference.

## Rules

- **Keep deployment details out of this repo**: no internal hostnames, IPs,
  proxy setup, gateway config or infrastructure history. They live in the
  private deployment repos. Mentioning the public endpoint
  (`https://mcp.baldwinsung.com/onlinepresence`) is fine.
- Build Linux binaries with `CGO_ENABLED=0`. A cgo build on a musl host
  (Alpine) won't run on a glibc host (Ubuntu).
- Add MCP tools in `mcpTools` (`mcp.go`) only: the stdio and HTTP transports
  share `mcpServer.handle`. A tool that reveals something about the server
  itself must be dropped (or, like `my_public_ip`, rewritten to answer
  about the caller) in public mode. A tool whose answer depends on the
  caller, not only its arguments, must set `noCache`.
- Every outbound socket must use `egressControl` (the dialer `Control` hook
  that `MCP_PUBLIC=1` sets). It already covers the TLS dial,
  `http.DefaultClient` and port-43 WHOIS. A new outbound path that skips it
  lets a public caller reach private addresses.
- Outbound calls go through the `lookups` struct so tests can fake them;
  tests must not need the network (CI runs offline lookups only).

## Commands

```bash
go vet ./... && go test -race ./...
go build -o bin/ ./cmd/...
```

After changing the code, rebuild and re-install any local MCP copy:
`install -m755 bin/onlinepresence-server ~/.local/bin/` (Claude Code's
registered path is that copy).

## Notes

- `hosting_provider` reports the first RDAP entity for the first A record,
  which behind a CDN is the CDN.
- The certificate fetch doesn't validate, on purpose: expired and self-signed
  certificates are still reported.
- The REST API keeps the original Python app's routes (one PUT per field)
  for compatibility.
