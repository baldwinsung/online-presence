# onlinePresence

Look up the online presence of a domain: **who registered it, who hosts it, and
what TLS certificate it serves**. One small Go binary (no database, no state)
that offers the same lookups three ways:

| Mode | Command | For |
|---|---|---|
| MCP over stdio | `onlinepresence-server mcp` | Claude Code, Claude Desktop and other local MCP clients |
| MCP over HTTP | `onlinepresence-server serve-mcp` | Remote MCP clients, behind a reverse proxy |
| REST API | `onlinepresence-server serve` (default) | Scripts and `curl` |

## Hosted

A public instance runs at **`https://mcp.baldwinsung.com/onlinepresence`**
(MCP over HTTP): 50 free tool calls per IP, then a free personal token from
[mcp.baldwinsung.com](https://mcp.baldwinsung.com).

```bash
claude mcp add --transport http onlinepresence https://mcp.baldwinsung.com/onlinepresence
```

## Install

```bash
go install github.com/baldwinsung/onlinePresence-app/cmd/onlinepresence-server@latest
```

or build from a checkout:

```bash
go build -o bin/onlinepresence-server ./cmd/onlinepresence-server
```

Go 1.26 or newer. The binary is static with `CGO_ENABLED=0`.

## MCP tools

| Tool | Returns |
|---|---|
| `online_presence` | Registration, hosting provider and certificate in one call |
| `domain_registration` | Registrar, created and expiry dates (RDAP, falling back to port-43 WHOIS) |
| `hosting_provider` | The domain's A record and who holds that IP block (IP RDAP). Behind a CDN this is the CDN |
| `ssl_certificate` | Subject, issuer, validity, days remaining and SANs of the certificate on port 443 (not validated, so expired or self-signed certificates are still reported) |
| `my_public_ip` | The server's own public egress IP. Local (stdio) and non-public HTTP mode only |

### Local (stdio)

```bash
claude mcp add --scope user onlinepresence -- /path/to/onlinepresence-server mcp
```

### Remote (Streamable HTTP)

`serve-mcp` speaks MCP's Streamable HTTP transport. It's meant to sit behind a
reverse proxy that terminates TLS and handles authentication and rate limits.

```bash
MCP_PUBLIC=1 onlinepresence-server serve-mcp      # listens on 127.0.0.1:8090
```

| Variable | Default | Meaning |
|---|---|---|
| `MCP_LISTEN_ADDR` | `127.0.0.1:8090` | Listen address |
| `MCP_PUBLIC` | off | `1` for an internet-facing server: drops `my_public_ip`, and refuses outbound connections to private, loopback, link-local and other reserved addresses, so a domain that resolves to `10.0.0.1` or `127.0.0.1` can't make the server probe its own network. Needs direct egress (a proxy on a private IP is refused too) |
| `MCP_ALLOWED_ORIGINS` | none | Comma-separated browser `Origin` values to accept. Other `Origin`s get 403; requests without one (non-browser clients) are accepted |

Behaviour:
- `POST /` only, one JSON response per request; `GET` and `DELETE` get 405 (no
  SSE stream, no sessions). `GET /healthz` for probes.
- Notifications get `202 Accepted`. Batches are refused, bodies are capped at
  64 KiB, and an unsupported `MCP-Protocol-Version` header gets 400.
- Successful results are cached for 10 minutes; errors aren't. At most 8
  lookups run at once; a call that can't start within 5 s gets a "server busy"
  tool error.

## REST API

```bash
LISTEN_ADDR=:8000 onlinepresence-server serve     # default :8080
curl -X PUT http://localhost:8000/domainwhois_registrar/google.com
"MarkMonitor Inc."
```

Every endpoint is `PUT /<endpoint>/<domain>` and returns JSON (errors are
`{"error": "..."}`). `GET /health` for probes.

| Endpoint | Returns |
|---|---|
| `domainwhois_registrar` | Registrar name |
| `domainwhois_created` | Registration date |
| `domainwhois_expires` | Expiry date |
| `hostingprovider` | Holder of the IP block the domain's first A record is in |
| `sslcertificate_subject` | Certificate subject (`CN=...`) |
| `sslcertificate_issuer` | Certificate issuer (`O=...`) |
| `sslcertificate_notbefore` | Valid from |
| `sslcertificate_notafter` | Valid until |
| `sslcertificate_san` | Subject Alternative Names, sorted |

Dates are HTTP dates, e.g. `"Thu, 14 Sep 2028 04:00:00 GMT"`.

## Docker

```bash
docker build -t onlinepresence .
docker run --rm -p 8080:8080 onlinepresence                       # REST
docker run --rm -p 8090:8090 -e MCP_LISTEN_ADDR=0.0.0.0:8090 -e MCP_PUBLIC=1 \
  onlinepresence serve-mcp                                        # MCP over HTTP
```

## How it works

- **Registration:** RDAP first (IANA bootstrap, HTTPS), port-43 WHOIS
  ([likexian/whois](https://github.com/likexian/whois) +
  [whois-parser](https://github.com/likexian/whois-parser)) if RDAP has no answer.
- **Hosting:** the Go resolver for the A record, then an RDAP query for the IP
  (`rdap.arin.net`, which redirects to the right regional registry); the first
  entity's name is reported.
- **Certificate:** a TLS handshake on port 443 without verification, so the
  certificate is reported whatever its state.
- **Proxies:** works behind an HTTP forward proxy. RDAP honours `HTTPS_PROXY`,
  and the certificate fetch tunnels with `CONNECT` (`NO_PROXY` respected).
- Domains are validated before any lookup.

## Development

```bash
go vet ./...
go test -race ./...     # tests use fake lookups, no network needed
```

The code is one package, `cmd/onlinepresence-server/`:

| File | What |
|---|---|
| `main.go` | Commands, REST API, the `lookups` interface tests fake |
| `egress.go` | RDAP domain lookups, proxy-aware TLS dial |
| `mcp.go` | MCP tools and JSON-RPC dispatch (no SDK), stdio transport |
| `mcphttp.go` | Streamable HTTP transport, result cache, public-mode address guard |

## Credits

[Li Kexian](https://github.com/likexian) for `whois` and `whois-parser`, and
[Richard Penman](https://github.com/richardpenman) for python-whois, used by
the original Python version of this project.
