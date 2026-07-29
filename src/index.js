/**
 * endoflife.ai — MCP Server (Phase 1)
 * ---------------------------------------------------------------------------
 * A dependency-free Cloudflare Worker that exposes endoflife.ai's lifecycle
 * intelligence to AI agents via the Model Context Protocol (MCP), using the
 * stateless Streamable HTTP transport (JSON-RPC 2.0 over HTTPS POST).
 *
 * It is a thin adapter: every tool calls the existing public API at
 * https://api.endoflife.ai/v1 — single source of truth for scoring, no data
 * duplicated here.
 *
 * Endpoints:
 *   POST /                                  → MCP JSON-RPC (initialize, tools/list, tools/call, ping)
 *   GET  /                                  → human-readable info page
 *   GET  /.well-known/mcp/server-card.json  → discovery card
 *
 * Auth: optional. An incoming `X-API-Key` header is forwarded to the upstream
 * API to unlock Pro limits; without it, callers get the free tier.
 */

const API_BASE = 'https://api.endoflife.ai';
const DEFAULT_PROTOCOL = '2025-06-18';
const SERVER_INFO = {
  name: 'endoflife.ai',
  title: 'endoflife.ai — Software Lifecycle Intelligence',
  version: '1.0.0',
};

// ── Tool definitions (advertised by tools/list) ────────────────────────────
const TOOLS = [
  {
    name: 'check_eol',
    description:
      'Check whether a specific version of a software product is end-of-life (EOL). ' +
      'Returns lifecycle status, the EOL date, days remaining or days past EOL, and the latest release. ' +
      'Use this for "is X version Y still supported?" questions.',
    inputSchema: {
      type: 'object',
      properties: {
        product: { type: 'string', description: 'Product slug or name, e.g. "postgresql", "nodejs", "ubuntu".' },
        version: { type: 'string', description: 'Version/cycle, e.g. "14", "18", "20.04".' },
      },
      required: ['product', 'version'],
    },
  },
  {
    name: 'get_risk_score',
    description:
      'Get the proprietary EOL Risk Score™ (0–100) for a product version, with the four-factor breakdown ' +
      '(EOL recency, attack surface, CISA KEV exposure, extended support). Omit "version" to score the ' +
      "product's highest-risk (most recently end-of-lifed) release. Use this to quantify how dangerous it is " +
      'to keep running something.',
    inputSchema: {
      type: 'object',
      properties: {
        product: { type: 'string', description: 'Product slug or name, e.g. "openssl", "python".' },
        version: { type: 'string', description: 'Optional version/cycle. Omit for the highest-risk release.' },
      },
      required: ['product'],
    },
  },
  {
    name: 'scan_stack',
    description:
      'Audit a whole stack at once. Provide a list of products (optionally with versions) — e.g. parsed from a ' +
      'package.json, Dockerfile, or SBOM — and get an EOL Risk Score for each, so you can see what is unsupported ' +
      'and dangerous in one call. Free tier: up to 5 items; Pro: up to 50.',
    inputSchema: {
      type: 'object',
      properties: {
        items: {
          type: 'array',
          description: 'List of stack components to score.',
          items: {
            type: 'object',
            properties: {
              product: { type: 'string', description: 'Product slug or name.' },
              version: { type: 'string', description: 'Optional version/cycle. Omit for highest-risk release.' },
            },
            required: ['product'],
          },
        },
      },
      required: ['items'],
    },
  },
  {
    name: 'list_products',
    description:
      'List or search the products endoflife.ai tracks (480+). Pass an optional "query" substring to find the ' +
      'canonical slug for a product before calling the other tools (e.g. "postgres" → "postgresql"). ' +
      'Returns matching product slugs.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Optional case-insensitive substring filter.' },
      },
      required: [],
    },
  },
  {
    name: 'get_product_lifecycle',
    description:
      'Get the full version history for one product: every tracked version/cycle with its release date, EOL date, ' +
      'support status, and EOL Risk Score™. Use for "give me the whole EOL schedule for X".',
    inputSchema: {
      type: 'object',
      properties: {
        product: { type: 'string', description: 'Product slug or name, e.g. "postgresql".' },
      },
      required: ['product'],
    },
  },
];

// ── CORS ───────────────────────────────────────────────────────────────────
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key, Mcp-Session-Id, MCP-Protocol-Version',
  'Access-Control-Max-Age': '86400',
};

// ── Upstream API helpers ────────────────────────────────────────────────────
function authHeaders(request) {
  const key = request.headers.get('X-API-Key') ||
    (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const h = { 'Accept': 'application/json', 'User-Agent': 'endoflife-mcp/1.0' };
  if (key) h['X-API-Key'] = key;
  return h;
}

/**
 * api.endoflife.ai is a Worker on the SAME zone as this one. A Worker subrequest
 * to its own zone is not routed back through Workers — Cloudflare sends it to the
 * origin, and this zone has no origin behind api.*, so every call failed. When the
 * API service binding is present we call the API Worker directly through it; the
 * plain fetch remains as a fallback for `wrangler dev` and unbound deploys.
 */
function apiFetch(url, init, env) {
  const req = new Request(url, init);
  return env && env.API && typeof env.API.fetch === 'function' ? env.API.fetch(req) : fetch(req);
}

async function apiGet(path, request, env) {
  const res = await apiFetch(`${API_BASE}${path}`, { headers: authHeaders(request) }, env);
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = { raw: text }; }
  return { ok: res.ok, status: res.status, data };
}

async function apiPost(path, body, request, env) {
  const res = await apiFetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { ...authHeaders(request), 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, env);
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = { raw: text }; }
  return { ok: res.ok, status: res.status, data };
}

// ── Tool implementations ────────────────────────────────────────────────────
async function runTool(name, args, request, env) {
  args = args || {};
  switch (name) {
    case 'check_eol': {
      const p = slugify(args.product), v = encodeURIComponent(String(args.version || ''));
      if (!p || !v) return toolError('Both "product" and "version" are required.');
      const r = await apiGet(`/v1/status/${p}/${v}`, request, env);
      if (!r.ok) return toolError(upstreamMsg(r, `No data for ${args.product} ${args.version}.`));
      return toolJson(r.data);
    }
    case 'get_risk_score': {
      const p = slugify(args.product);
      if (!p) return toolError('"product" is required.');
      const path = args.version
        ? `/v1/score/${p}/${encodeURIComponent(String(args.version))}`
        : `/v1/score/${p}`;
      const r = await apiGet(path, request, env);
      if (!r.ok) return toolError(upstreamMsg(r, `No score for ${args.product}${args.version ? ' ' + args.version : ''}.`));
      return toolJson(r.data);
    }
    case 'scan_stack': {
      const items = Array.isArray(args.items) ? args.items : [];
      if (!items.length) return toolError('"items" must be a non-empty array of {product, version?}.');
      const products = items.map(i => ({
        slug: slugify(i.product),
        ...(i.version ? { version: String(i.version) } : {}),
      })).filter(i => i.slug);
      const r = await apiPost('/v1/batch', { products }, request, env);
      if (!r.ok) return toolError(upstreamMsg(r, 'Batch scan failed.'));
      return toolJson(r.data);
    }
    case 'list_products': {
      const r = await apiGet('/v1/products', request, env);
      if (!r.ok) return toolError(upstreamMsg(r, 'Could not fetch product list.'));
      let products = Array.isArray(r.data.products) ? r.data.products : [];
      const q = (args.query || '').toLowerCase().trim();
      if (q) products = products.filter(s => String(s).toLowerCase().includes(q));
      const capped = products.slice(0, 100);
      return toolJson({
        query: q || null,
        match_count: products.length,
        returned: capped.length,
        products: capped,
        note: products.length > capped.length ? 'Results capped at 100; refine your query.' : undefined,
      });
    }
    case 'get_product_lifecycle': {
      const p = slugify(args.product);
      if (!p) return toolError('"product" is required.');
      const r = await apiGet(`/v1/product/${p}`, request, env);
      if (!r.ok) return toolError(upstreamMsg(r, `Product "${args.product}" not found.`));
      return toolJson(r.data);
    }
    default:
      return toolError(`Unknown tool: ${name}`);
  }
}

function slugify(s) {
  return String(s || '').toLowerCase().trim().replace(/\s+/g, '-');
}
function upstreamMsg(r, fallback) {
  return (r.data && (r.data.error || r.data.message)) || fallback || `Upstream error ${r.status}.`;
}
function toolJson(obj) {
  return { content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] };
}
function toolError(msg) {
  return { content: [{ type: 'text', text: `Error: ${msg}` }], isError: true };
}

// ── MCP JSON-RPC dispatch ───────────────────────────────────────────────────
async function handleRpc(msg, request, env) {
  const { id, method, params } = msg;
  const reply = (result) => ({ jsonrpc: '2.0', id, result });
  const fail = (code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });

  switch (method) {
    case 'initialize': {
      const requested = params && typeof params.protocolVersion === 'string' ? params.protocolVersion : DEFAULT_PROTOCOL;
      return reply({
        protocolVersion: requested,
        capabilities: { tools: { listChanged: false } },
        serverInfo: SERVER_INFO,
        instructions:
          'endoflife.ai tools return software end-of-life dates and the proprietary EOL Risk Score™ (0–100). ' +
          'Resolve a product name to its slug with list_products if a lookup misses.',
      });
    }
    case 'tools/list':
      return reply({ tools: TOOLS });
    case 'tools/call': {
      const name = params && params.name;
      const args = (params && params.arguments) || {};
      if (!name) return fail(-32602, 'Missing tool name.');
      try {
        const result = await runTool(name, args, request, env);
        return reply(result);
      } catch (e) {
        return reply(toolError(`Tool execution failed: ${e && e.message ? e.message : String(e)}`));
      }
    }
    case 'ping':
      return reply({});
    default:
      return fail(-32601, `Method not found: ${method}`);
  }
}

// ── Discovery card ──────────────────────────────────────────────────────────
function serverCard() {
  return {
    $schema: 'https://modelcontextprotocol.io/schemas/draft/server-card.json',
    serverInfo: SERVER_INFO,
    description:
      'Software lifecycle intelligence for AI agents: end-of-life dates, support status, and the EOL Risk Score™ ' +
      '(0–100, factoring EOL recency, attack surface, and CISA KEV exposure) for 480+ products and 8,000+ versions.',
    transport: { type: 'streamable-http', endpoint: 'https://mcp.endoflife.ai' },
    capabilities: { tools: {} },
    tools: [
      { name: 'check_eol', description: 'Check whether a specific product version is end-of-life.' },
      { name: 'get_risk_score', description: 'Get the EOL Risk Score (0–100) for a product version, with the four-factor breakdown.' },
      { name: 'scan_stack', description: 'Audit a whole stack at once and score each component for EOL risk.' },
      { name: 'list_products', description: 'Search the 480+ tracked products to resolve a name to its canonical slug.' },
      { name: 'get_product_lifecycle', description: 'Get the full version history and EOL dates for one product.' },
    ],
    documentation: 'https://endoflife.ai/mcp',
    provider: { name: 'endoflife.ai', url: 'https://endoflife.ai' },
  };
}

// ── Info page ───────────────────────────────────────────────────────────────
function infoPage() {
  const tools = TOOLS.map(t => `  • ${t.name} — ${t.description.split('.')[0]}.`).join('\n');
  return `endoflife.ai — Model Context Protocol (MCP) Server
====================================================

This is a machine endpoint for AI agents. It speaks MCP over the Streamable
HTTP transport (JSON-RPC 2.0 via HTTPS POST to this URL).

Connect from Claude Desktop / Cursor / any MCP client:

  {
    "mcpServers": {
      "endoflife": { "command": "npx", "args": ["mcp-remote", "https://mcp.endoflife.ai"] }
    }
  }

Tools:
${tools}

Optional: send an "X-API-Key" header to unlock Pro limits.
Docs: https://endoflife.ai/mcp   ·   API: https://endoflife.ai/api
`;
}

// ── Worker entry ────────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    if (url.pathname === '/.well-known/mcp/server-card.json') {
      return new Response(JSON.stringify(serverCard(), null, 2), {
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600', ...CORS },
      });
    }

    if (request.method === 'GET') {
      return new Response(infoPage(), {
        headers: { 'Content-Type': 'text/plain; charset=utf-8', ...CORS },
      });
    }

    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405, headers: CORS });
    }

    // MCP Streamable HTTP: JSON-RPC request(s) in the POST body.
    let body;
    try { body = await request.json(); }
    catch { return rpcHttp({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }); }

    // Batch (array) or single message.
    const messages = Array.isArray(body) ? body : [body];
    const responses = [];
    for (const msg of messages) {
      // Notifications (no id) get no response body.
      if (msg && msg.id === undefined) continue;
      responses.push(await handleRpc(msg, request, env));
    }

    if (responses.length === 0) {
      // All notifications → 202 Accepted, no body.
      return new Response(null, { status: 202, headers: CORS });
    }
    return rpcHttp(Array.isArray(body) ? responses : responses[0]);
  },
};

function rpcHttp(payload) {
  return new Response(JSON.stringify(payload), {
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}
