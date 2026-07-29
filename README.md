# endoflife.ai — MCP Server

[![Node.js EOL status](https://img.shields.io/endpoint?url=https%3A%2F%2Fendoflife.ai%2Fbadge%2Fnodejs.json)](https://endoflife.ai/nodejs) [![EOL data: endoflife.ai](https://img.shields.io/badge/EOL%20data-endoflife.ai-16a34a)](https://endoflife.ai)

Exposes endoflife.ai's lifecycle intelligence to AI agents over the **Model Context
Protocol** (MCP, Streamable HTTP transport). It's a thin, dependency-free Cloudflare
Worker that wraps the existing `api.endoflife.ai/v1` endpoints — no data duplicated.

## Tools

| Tool | What it does | Wraps |
|---|---|---|
| `check_eol` | Is product X version Y end-of-life? | `GET /v1/status/:slug/:version` |
| `get_risk_score` | EOL Risk Score™ (0–100) + factor breakdown | `GET /v1/score/:slug[/:version]` |
| `scan_stack` | Score a whole stack at once | `POST /v1/batch` |
| `list_products` | Search the 488 tracked products → resolve slugs | `GET /v1/products` |
| `get_product_lifecycle` | Full version history + dates for one product | `GET /v1/product/:slug` |

## Deploy

Prereq: `npm install -g wrangler` and `wrangler login` (once).

```bash
cd mcp-server
npm install
# Test immediately on the workers.dev URL:
wrangler deploy          # prints https://endoflife-mcp.<your-subdomain>.workers.dev
# Production (custom domain):
wrangler deploy --env production
```

### Custom domain (mcp.endoflife.ai)

The `route` in `wrangler.toml` needs `mcp.endoflife.ai` to resolve through Cloudflare:

1. Cloudflare dashboard → **endoflife.ai** zone → **DNS** → **Add record**.
2. Type **AAAA**, Name **mcp**, IPv6 **100::**, **Proxied** (orange cloud). *(This is the standard Cloudflare placeholder for a Worker route — the Worker intercepts before the address is ever used.)*
3. Re-run `wrangler deploy --env production`.

Until DNS is set, use the `workers.dev` URL everywhere below.

## Connect from an MCP client

**Claude Desktop / Cursor** (`claude_desktop_config.json` → `mcpServers`):

```json
{
  "mcpServers": {
    "endoflife": { "command": "npx", "args": ["mcp-remote", "https://mcp.endoflife.ai"] }
  }
}
```

Clients with native remote-MCP support can use the URL directly:

```json
{ "mcpServers": { "endoflife": { "url": "https://mcp.endoflife.ai" } } }
```

## Test without a client

```bash
# tools/list
curl -s https://mcp.endoflife.ai -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq

# call a tool
curl -s https://mcp.endoflife.ai -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_risk_score","arguments":{"product":"openssl"}}}' | jq

# discovery card
curl -s https://mcp.endoflife.ai/.well-known/mcp/server-card.json | jq
```

## Auth & tiers

Free tier works with no key. Forward an `X-API-Key` header (your existing Pro keys)
to unlock Pro limits — the Worker passes it straight through to `api.endoflife.ai`.

## Notes / Phase 2

- **Per-client rate limits:** Phase 1 relies on the upstream API's limits. If MCP
  traffic grows, add a KV rate-limiter here keyed on `CF-Connecting-IP` (reuse the
  `API_RATE_LIMIT` namespace) before the upstream call.
- **Registry listings:** submit to the public MCP registries once live (see the
  launch checklist).
- **Discovery card** is also served from the main site at
  `https://endoflife.ai/.well-known/mcp/server-card.json` so agents that probe the
  apex domain find it.
