# endoflife.ai — MCP Server

[![Node.js EOL status](https://img.shields.io/endpoint?url=https%3A%2F%2Fendoflife.ai%2Fbadge%2Fnodejs.json)](https://endoflife.ai/nodejs) [![EOL data: endoflife.ai](https://img.shields.io/badge/EOL%20data-endoflife.ai-16a34a)](https://endoflife.ai)

Exposes endoflife.ai's lifecycle intelligence to AI agents over the **Model Context
Protocol** (MCP, Streamable HTTP transport). A dependency-free Cloudflare Worker
that wraps the public `api.endoflife.ai/v1` endpoints and the site's published
feeds — no data duplicated, every answer carries a source URL.

Current version: **1.3.0** (`SERVER_INFO.version` in `src/index.js`, `server.json`,
`package.json` — keep all three in step; CI fails if they disagree; the registry and
Glama read `server.json`).

## Tools (all read-only)

| Tool | What it does | Backed by |
|---|---|---|
| `check_eol` | Is product X version Y end-of-life? | `GET /v1/status/:slug/:version` |
| `get_risk_score` | EOL Risk Score (0–100) + factor breakdown | `GET /v1/score/:slug[/:version]` |
| `scan_stack` | Score a whole stack at once | `POST /v1/batch` |
| `list_products` | Search the 500+ tracked products → resolve slugs | `GET /v1/products` |
| `get_product_lifecycle` | Full version history + dates for one product | `GET /v1/product/:slug` |
| `get_kev_exposure` | Every CISA KEV entry attributed to a product (date added, due date, required action verbatim) + Exploited & Unpatchable entries | `endoflife.ai/kev-products.json`, `exploited-and-unpatchable.json` |
| `get_upcoming_eol` | Everything reaching EOL in the next N days (catalog-wide or a product list) | `endoflife.ai/scanner-db.json` |
| `get_edge_device_status` | EOS Edge Device feed with BOD 26-02 statuses, filter by platform / status / model | `endoflife.ai/eos-edge-devices.json` |
| `get_upgrade_path` | Supported targets, the site's recommendation, vendor-stated successor | `GET /v1/product/:slug`, `checker-db.json`, edge feed |
| `check_sbom` | CycloneDX / SPDX JSON → components resolved by package URL (exact, purl-map.json) or by name when no purl → scored; unmatched listed with a reason, never guessed | `purl-map.json` + `POST /v1/batch` |

Every tool advertises `annotations` (`readOnlyHint`, `idempotentHint`) and a
permissive `outputSchema`; results are returned both as JSON text and as
`structuredContent`. Lookup misses return "did you mean" slug suggestions
(prefix / substring / edit-distance ≤ 2 against the live product list).

**Resources** (`resources/list` / `resources/read`): `llms.txt`, the EOS Edge Device
feed, Exploited & Unpatchable, KEV by product, the edge change log.

**Prompts** (`prompts/list` / `prompts/get`): `audit_stack`, `eol_calendar`,
`edge_device_review`.

**Endpoints:** `POST /` (JSON-RPC), `GET /` (info page), `GET /health` (liveness JSON),
`GET /.well-known/mcp/server-card.json` (discovery card).

## Usage telemetry

With the `USAGE` Analytics Engine binding (see `wrangler.toml`, dataset
`endoflife_mcp_usage`) each method / tool call writes one data point: tool name,
client user agent, ok/error, keyed/anon, latency in ms. No request bodies. Query
via the Cloudflare Analytics Engine SQL API, e.g.

```sql
SELECT blob1 AS tool, count() AS calls, sum(_sample_interval) AS weighted
FROM endoflife_mcp_usage WHERE timestamp > NOW() - INTERVAL '7' DAY
GROUP BY tool ORDER BY calls DESC
```

The binding is optional; the code no-ops without it.

## Deploy

The hosted server at mcp.endoflife.ai is deployed by the maintainers from the
endoflife.ai site repository's GitHub Actions workflow (pinned wrangler, Cloudflare
credentials held there as repository secrets); this public repository carries no
deploy workflow of its own. To run your own copy, `wrangler deploy` from this
repository works with your own Cloudflare account, and `wrangler dev` runs it locally;
the `API` service binding and the `USAGE` dataset in `wrangler.toml` are declared for
both the default and `production` environments.

### Custom domain (mcp.endoflife.ai)

The `route` in `wrangler.toml` needs `mcp.endoflife.ai` to resolve through Cloudflare:
an **AAAA** record, name **mcp**, IPv6 **100::**, proxied. Already in place.

### Test before deploying

CI (`.github/workflows/ci.yml`) runs on every push and pull request and once a day:
syntax checks, manifest validity, the version-agreement check, and a live smoke test
that calls the deployed server's tools. The same smoke test runs locally:

```bash
node --check src/index.js && node --check stdio.js
node .github/scripts/smoke.mjs   # real tool calls against mcp.endoflife.ai, expects 0 failures
```

## Run as a container (Red Hat UBI)

`server.mjs` runs the same handler that serves mcp.endoflife.ai inside a plain Node.js process, and `Dockerfile` packages it on `registry.access.redhat.com/ubi9/nodejs-22-minimal` for cluster deploys (the form the OpenShift AI MCP catalog expects). No build step, no dependencies; the container talks to `https://api.endoflife.ai` over HTTPS and runs as the unprivileged UBI user (uid 1001).

```
docker build -t endoflife-mcp .
docker run --rm -p 8080:8080 endoflife-mcp
curl -s localhost:8080/health
```

Endpoints are the Worker's own: `POST /` (Streamable HTTP JSON-RPC), `GET /health` (readiness), `GET /.well-known/mcp/server-card.json`. Set `ENDOFLIFE_API_KEY` to forward a Pro key. The image is built on Red Hat UBI 9 with Node 22; the maintainers run it on RHEL 9 and 10 as part of their Red Hat partner validation, which lives outside this repository.

## Connect from an MCP client

**Claude Desktop / Cursor / VS Code** (`mcpServers`):

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

# KEV exposure for a product
curl -s https://mcp.endoflife.ai -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_kev_exposure","arguments":{"product":"ivanti-connect-secure"}}}' | jq

# health + discovery card
curl -s https://mcp.endoflife.ai/health | jq
curl -s https://mcp.endoflife.ai/.well-known/mcp/server-card.json | jq
```

## Auth & tiers

The read tools work with no key for individual use and evaluation (anonymous tier:
100 requests a day, 5 components per SBOM or batch call). Agents that run inside a
company's tooling, check inventories or call on a schedule are production use and
belong on a paid key: Starter ($79/month, 10,000 requests a day, 25 per call) or
Pro ($199/month, no daily cap, 50 per call), issued at checkout from
https://endoflife.ai/api?utm_source=mcp#get-key. Forward it as an `X-API-Key`
header; the Worker passes it straight through to `api.endoflife.ai`.

## Notes

- **Same-zone trap:** `api.endoflife.ai` is a Worker on this zone; a plain `fetch()`
  to it goes to origin and fails. The `API` service binding is mandatory in prod.
- **Static feeds** are fetched from the site origin with `cf.cacheTtl = 600` and
  memoised in the isolate for 10 minutes.
- **Per-client rate limits:** relies on the upstream API's limits. If MCP traffic
  grows, add a KV rate-limiter keyed on `CF-Connecting-IP` before the upstream call.
- **Discovery card** is also served from the main site at
  `https://endoflife.ai/.well-known/mcp/server-card.json`.
