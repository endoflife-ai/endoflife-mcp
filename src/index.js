/**
 * endoflife.ai — MCP Server (1.3.0)
 * ---------------------------------------------------------------------------
 * A dependency-free Cloudflare Worker that exposes endoflife.ai's lifecycle
 * intelligence to AI agents via the Model Context Protocol (MCP), using the
 * stateless Streamable HTTP transport (JSON-RPC 2.0 over HTTPS POST).
 *
 * Two data paths, no data duplicated here:
 *   • the public API at https://api.endoflife.ai/v1 (through a service binding —
 *     a same-zone fetch to api.* goes to origin, and api.* has none) for
 *     scoring, status, lifecycle and batch lookups;
 *   • the site's published feeds at https://endoflife.ai/*.json (static files on
 *     the site origin, edge-cached) for the KEV record, the EOS Edge Device
 *     feed, the exploited-and-unpatchable feed and the scanner database.
 *
 * Endpoints:
 *   POST /                                  → MCP JSON-RPC (initialize, ping, tools/*, resources/*, prompts/*)
 *   GET  /                                  → human-readable info page
 *   GET  /health                            → liveness JSON
 *   GET  /.well-known/mcp/server-card.json  → discovery card
 *
 * Auth: optional. An incoming `X-API-Key` header is forwarded to the upstream
 * API to unlock Pro limits; without it, callers get the free tier.
 *
 * Usage telemetry (1.1.0): when an Analytics Engine binding `USAGE` exists, each
 * method / tool call writes one data point (tool, client user agent, ok/error,
 * latency). No request bodies, no identifiers beyond the user agent.
 */

const API_BASE = 'https://api.endoflife.ai';
const SITE_BASE = 'https://endoflife.ai';
const DEFAULT_PROTOCOL = '2025-06-18';
const SERVER_INFO = {
  name: 'endoflife.ai',
  title: 'endoflife.ai — Software Lifecycle Intelligence',
  // Keep in step with server.json, package.json, and the published registry /
  // Glama release versions — a mismatch here is what clients see in initialize.
  version: '1.3.0',
};

const INSTRUCTIONS =
  'endoflife.ai tools return vendor-verified software end-of-life dates, the EOL Risk Score (0-100), ' +
  'CISA KEV exposure, and the EOS Edge Device feed (CISA BOD 26-02 statuses). Every result carries a ' +
  '"source" URL — cite it. Resolve a product name to its slug with list_products if a lookup misses; ' +
  'errors include "did you mean" suggestions. All tools are read-only.';

// ── Tool definitions (advertised by tools/list) ────────────────────────────
const RO = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };
const LOOSE_OBJECT = { type: 'object', additionalProperties: true };

const TOOLS = [
  {
    name: 'check_eol',
    title: 'Check end-of-life status',
    description:
      'Check whether a specific version of a software product is end-of-life (EOL). ' +
      'Returns lifecycle status, the EOL date, days remaining or days past EOL, the latest release, and eol_date_source ' +
      '(where the date comes from: vendor-override, vendor-fetched, vendor-verified, custom, upstream, or discrepancy) with its source URL. ' +
      'Use this for "is X version Y still supported?" questions.',
    inputSchema: {
      type: 'object',
      properties: {
        product: { type: 'string', description: 'Product slug or name, e.g. "postgresql", "nodejs", "ubuntu".' },
        version: { type: 'string', description: 'Version/cycle, e.g. "14", "18", "20.04".' },
      },
      required: ['product', 'version'],
    },
    outputSchema: LOOSE_OBJECT,
    annotations: { title: 'Check end-of-life status', ...RO },
  },
  {
    name: 'get_risk_score',
    title: 'EOL Risk Score',
    description:
      'Get the proprietary EOL Risk Score (0-100) for a product version, with the four-factor breakdown ' +
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
    outputSchema: LOOSE_OBJECT,
    annotations: { title: 'EOL Risk Score', ...RO },
  },
  {
    name: 'scan_stack',
    title: 'Scan a stack',
    description:
      'Audit a whole stack at once. Provide a list of products (optionally with versions) — e.g. parsed from a ' +
      'package.json or Dockerfile — and get an EOL Risk Score for each, so you can see what is unsupported ' +
      'and dangerous in one call. For CycloneDX or SPDX documents use check_sbom instead. Free tier: up to 5 items; Pro: up to 50.',
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
    outputSchema: LOOSE_OBJECT,
    annotations: { title: 'Scan a stack', ...RO },
  },
  {
    name: 'list_products',
    title: 'Find a product slug',
    description:
      'List or search the products endoflife.ai tracks (500+). Pass an optional "query" substring to find the ' +
      'canonical slug for a product before calling the other tools (e.g. "postgres" → "postgresql"). ' +
      'Returns matching product slugs.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Optional case-insensitive substring filter.' },
      },
      required: [],
    },
    outputSchema: LOOSE_OBJECT,
    annotations: { title: 'Find a product slug', ...RO },
  },
  {
    name: 'get_product_lifecycle',
    title: 'Full lifecycle table',
    description:
      'Get the full version history for one product: every tracked version/cycle with its release date, EOL date, ' +
      'support status, and EOL Risk Score. Use for "give me the whole EOL schedule for X".',
    inputSchema: {
      type: 'object',
      properties: {
        product: { type: 'string', description: 'Product slug or name, e.g. "postgresql".' },
      },
      required: ['product'],
    },
    outputSchema: LOOSE_OBJECT,
    annotations: { title: 'Full lifecycle table', ...RO },
  },
  // ── 1.1.0 additions ──
  {
    name: 'get_kev_exposure',
    title: 'CISA KEV exposure',
    description:
      "The exploited-vulnerability record for a product: every CVE CISA lists against it in the Known Exploited " +
      "Vulnerabilities catalog, with the date added, the federal due date and CISA's required-action text verbatim " +
      '(the "discontinue use" entries are the ones that matter for end-of-life versions), plus any entries from ' +
      "endoflife.ai's Exploited & Unpatchable feed (exploited CVEs whose affected versions will never receive a fix). " +
      'Pass an optional version to include its support status alongside.',
    inputSchema: {
      type: 'object',
      properties: {
        product: { type: 'string', description: 'Product slug or name, e.g. "ivanti-connect-secure", "fortios".' },
        version: { type: 'string', description: 'Optional version/cycle to check support status for.' },
      },
      required: ['product'],
    },
    outputSchema: LOOSE_OBJECT,
    annotations: { title: 'CISA KEV exposure', ...RO },
  },
  {
    name: 'get_upcoming_eol',
    title: 'Upcoming end-of-life calendar',
    description:
      'What reaches end-of-life soon. Returns every tracked version whose EOL date falls within the next N days ' +
      '(default 90), optionally limited to a list of products, sorted by date. Also lists versions that went EOL ' +
      'within the last "recent_past_days" days when set. Use for "what in our stack expires this quarter?".',
    inputSchema: {
      type: 'object',
      properties: {
        products: { type: 'array', items: { type: 'string' }, description: 'Optional product slugs or names to restrict to (max 50). Omit for the whole catalog.' },
        days: { type: 'integer', description: 'Look-ahead window in days (default 90, max 730).' },
        recent_past_days: { type: 'integer', description: 'Also include versions that went EOL within this many days in the past (default 0).' },
      },
      required: [],
    },
    outputSchema: LOOSE_OBJECT,
    annotations: { title: 'Upcoming end-of-life calendar', ...RO },
  },
  {
    name: 'get_edge_device_status',
    title: 'EOS Edge Device status',
    description:
      'Query the EOS Edge Device Intelligence feed — firewalls, VPN gateways and appliances, ADCs, router and switch ' +
      'operating systems — with end-of-support status in the vocabulary of CISA BOD 26-02 (eos, within-12-months, ' +
      'scheduled, no-date-announced). Filter by platform or vendor name, by status, or by model/line. Each platform ' +
      'carries its KEV summary, vendor-stated successor and provenance. Use for "which of our edge devices are past ' +
      'support or expire within 12 months?".',
    inputSchema: {
      type: 'object',
      properties: {
        platform: { type: 'string', description: 'Optional substring matched against platform slug, name, vendor or category, e.g. "fortinet", "ivanti", "vpn".' },
        status: { type: 'string', enum: ['eos', 'within-12-months', 'scheduled', 'no-date-announced'], description: 'Optional status filter.' },
        model: { type: 'string', description: 'Optional substring matched against the line / model name, e.g. "ISA6000", "7.2", "SMA 100".' },
      },
      required: [],
    },
    outputSchema: LOOSE_OBJECT,
    annotations: { title: 'EOS Edge Device status', ...RO },
  },
  {
    name: 'get_upgrade_path',
    title: 'Upgrade path',
    description:
      'Where to move a product version: the current version\'s support status and score, the supported releases with ' +
      "the longest remaining support, endoflife.ai's recommended target, and the vendor's stated successor where one is " +
      'published (edge appliances). Use after check_eol says a version is EOL.',
    inputSchema: {
      type: 'object',
      properties: {
        product: { type: 'string', description: 'Product slug or name.' },
        version: { type: 'string', description: 'Optional current version/cycle.' },
      },
      required: ['product'],
    },
    outputSchema: LOOSE_OBJECT,
    annotations: { title: 'Upgrade path', ...RO },
  },
  {
    name: 'check_sbom',
    title: 'Check an SBOM',
    description:
      'Audit a CycloneDX or SPDX JSON software bill of materials. Components are mapped to tracked products and ' +
      'scored for EOL risk; unmatched components are listed honestly rather than guessed. Pass the SBOM as a JSON ' +
      'string or object. Free tier scores up to 5 matched components per call; Pro up to 50.',
    inputSchema: {
      type: 'object',
      properties: {
        sbom: { description: 'The SBOM document (JSON string or object). CycloneDX (bomFormat/components) or SPDX (spdxVersion/packages).' },
        max_items: { type: 'integer', description: 'Maximum matched components to score (default 50).' },
      },
      required: ['sbom'],
    },
    outputSchema: LOOSE_OBJECT,
    annotations: { title: 'Check an SBOM', ...RO },
  },
];

// ── Resources (read-only feeds exposed to clients) ─────────────────────────
const RESOURCES = [
  { uri: `${SITE_BASE}/llms.txt`, name: 'endoflife.ai guide for assistants', description: 'What endoflife.ai publishes, how to cite it, and the article index.', mimeType: 'text/plain' },
  { uri: `${SITE_BASE}/eos-edge-devices.json`, name: 'EOS Edge Device Intelligence feed', description: 'Edge platforms with BOD 26-02 end-of-support statuses, KEV records, CPEs, provenance (schema 2.0).', mimeType: 'application/json' },
  { uri: `${SITE_BASE}/exploited-and-unpatchable.json`, name: 'Exploited & Unpatchable feed', description: 'Exploited CVEs whose affected versions will never receive a fix.', mimeType: 'application/json' },
  { uri: `${SITE_BASE}/verification.json`, name: 'Accuracy & provenance report', description: 'Where every served date comes from: vendor-sourced share per product and for the commercial tier, live vendor feeds with last-read dates, open vendor disagreements, published corrections and human verification records.', mimeType: 'application/json' },
  { uri: `${SITE_BASE}/purl-map.json`, name: 'Package URL map', description: 'Package URLs (purl) that resolve an SBOM component to a tracked product: products → purls, and a normalised-purl → slug lookup. The join key check_sbom uses; rebuilt at every site build from endoflife.date identifiers, registry ids and human overrides.', mimeType: 'application/json' },
  { uri: `${SITE_BASE}/kev-products.json`, name: 'CISA KEV by product', description: 'Every tracked product with its attributed KEV entries (dates, due dates, required actions).', mimeType: 'application/json' },
  { uri: `${SITE_BASE}/eos-edge-changelog.json`, name: 'EOS Edge feed change log', description: 'Every edge line added, removed, re-dated or status-changed, by build date.', mimeType: 'application/json' },
];

// ── Prompts ────────────────────────────────────────────────────────────────
const PROMPTS = [
  {
    name: 'audit_stack',
    title: 'Audit a stack for EOL and exploited-CVE exposure',
    description: 'Score every component of a stack, then explain what is end-of-life, what is actively exploited, and where to move.',
    arguments: [{ name: 'stack', description: 'The stack: a list of products and versions, a package.json / requirements.txt / Dockerfile excerpt, or an SBOM.', required: true }],
  },
  {
    name: 'eol_calendar',
    title: 'End-of-life calendar for the next N days',
    description: 'List what reaches end-of-life in a window, grouped by month, with the action each one needs.',
    arguments: [
      { name: 'products', description: 'Optional comma-separated product names to restrict to.', required: false },
      { name: 'days', description: 'Window in days (default 90).', required: false },
    ],
  },
  {
    name: 'edge_device_review',
    title: 'Edge device end-of-support review (BOD 26-02)',
    description: 'Review edge devices against CISA BOD 26-02: past end of support, within 12 months, and the KEV exposure of each.',
    arguments: [{ name: 'vendor', description: 'Optional vendor or platform to focus on.', required: false }],
  },
];

function promptMessages(name, args) {
  args = args || {};
  const user = (text) => ({ role: 'user', content: { type: 'text', text } });
  switch (name) {
    case 'audit_stack':
      return [user(
        `Audit this stack for software end-of-life and exploited-vulnerability exposure using the endoflife.ai tools.\n\n` +
        `Stack:\n${args.stack || '(none provided)'}\n\n` +
        `Steps: (1) If it is a CycloneDX or SPDX document, call check_sbom; otherwise parse the components and call scan_stack ` +
        `(use list_products to resolve any name that misses). (2) For every component that is EOL or within 12 months of EOL, ` +
        `call get_kev_exposure and get_upgrade_path. (3) Report in three groups — exploited and unpatchable, end-of-life, ` +
        `expiring soon — with the date, the risk score, and the recommended target for each. Cite the source URL each tool returns.`
      )];
    case 'eol_calendar':
      return [user(
        `Build an end-of-life calendar for the next ${args.days || 90} days using get_upcoming_eol` +
        (args.products ? ` restricted to: ${args.products}` : ' across the whole endoflife.ai catalog') +
        `. Group the results by month, state the EOL date and days remaining for each version, and note which ones ` +
        `have paid extended support available. Cite the source URLs.`
      )];
    case 'edge_device_review':
      return [user(
        `Review edge devices against CISA Binding Operational Directive 26-02 using get_edge_device_status` +
        (args.vendor ? ` for "${args.vendor}"` : '') +
        `. Report (a) lines already past end of support, (b) lines reaching end of support within 12 months, and (c) the ` +
        `KEV exposure of each platform — quoting CISA's required-action text where it says to discontinue use. ` +
        `For each platform with a vendor-stated successor, name it. Cite the feed URL.`
      )];
    default:
      return null;
  }
}

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
  const h = { 'Accept': 'application/json', 'User-Agent': `endoflife-mcp/${SERVER_INFO.version}` };
  if (key) h['X-API-Key'] = key;
  // Tell the API this call comes from the hosted MCP server and forward the agent's address, so keyless
  // agent traffic is metered per agent (the API's MCP bucket) instead of pooling under one anonymous address.
  h['X-EOL-Client'] = 'mcp';
  const clientIp = request.headers.get('CF-Connecting-IP');
  if (clientIp) h['X-EOL-Client-IP'] = clientIp;
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

// ── Static feeds on the site origin (edge-cached, memoised per isolate) ────
const STATIC_TTL_MS = 10 * 60 * 1000;
const staticMemo = new Map();
async function fetchStatic(pathname, asText) {
  const now = Date.now();
  const hit = staticMemo.get(pathname);
  if (hit && hit.until > now) return hit.value;
  const res = await fetch(`${SITE_BASE}${pathname}`, {
    headers: { 'Accept': asText ? 'text/plain' : 'application/json', 'User-Agent': `endoflife-mcp/${SERVER_INFO.version}` },
    // Cache only successes at the edge. A cached 404 (the feed polled before a
    // deploy landed) would otherwise blind the tool for the whole TTL.
    cf: { cacheEverything: true, cacheTtlByStatus: { '200-299': 600, '404': -1, '500-599': -1 } },
  });
  if (!res.ok) throw new Error(`Feed ${pathname} unavailable (HTTP ${res.status}).`);
  const value = asText ? await res.text() : await res.json();
  staticMemo.set(pathname, { value, until: now + STATIC_TTL_MS });
  return value;
}

// Product slug list from the API, memoised (used for suggestions and SBOM mapping).
let productListMemo = { value: null, until: 0 };
async function productSlugs(request, env) {
  if (productListMemo.value && productListMemo.until > Date.now()) return productListMemo.value;
  const r = await apiGet('/v1/products', request, env);
  const list = r.ok && Array.isArray(r.data.products) ? r.data.products.map(String) : [];
  if (list.length) productListMemo = { value: list, until: Date.now() + STATIC_TTL_MS };
  return list;
}

function suggestSlugs(name, slugs, n = 5) {
  const q = slugify(name);
  if (!q) return [];
  const toks = q.split('-').filter(Boolean);
  const scored = slugs.map(s => {
    let score = 0;
    if (s === q) score = 100;
    else if (s.startsWith(q) || q.startsWith(s)) score = 60;
    else if (s.includes(q) || q.includes(s)) score = 40;
    else score = toks.filter(t => t.length > 2 && s.includes(t)).length * 15;
    if (!score) {
      // Typo tolerance: a shared 4+ character prefix, or an edit distance of at most 2.
      let cp = 0; while (cp < q.length && cp < s.length && q[cp] === s[cp]) cp++;
      if (cp >= 4) score = 20 + cp;
      else if (Math.abs(s.length - q.length) <= 2 && editDistance(q, s) <= 2) score = 30;
    }
    return { s, score };
  }).filter(x => x.score > 0).sort((a, b) => b.score - a.score || a.s.localeCompare(b.s));
  return scored.slice(0, n).map(x => x.s);
}

function editDistance(a, b) {
  const m = a.length, n = b.length; if (!m) return n; if (!n) return m;
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    prev = cur;
  }
  return prev[n];
}

async function notFound(request, env, what, name) {
  const slugs = await productSlugs(request, env).catch(() => []);
  const sug = suggestSlugs(name, slugs);
  return toolError(`${what}` + (sug.length ? ` Did you mean: ${sug.join(', ')}? (Use list_products to search.)` : ' Use list_products to find the canonical slug.'));
}

// ── SBOM parsing (mirrors the site's Stack Scanner) ────────────────────────
function parseSbom(input) {
  let doc = input;
  if (typeof doc === 'string') { try { doc = JSON.parse(doc); } catch { return { error: 'The SBOM is not valid JSON.' }; } }
  if (!doc || typeof doc !== 'object') return { error: 'The SBOM must be a JSON object.' };
  const deps = [];
  if (doc.bomFormat === 'CycloneDX' && Array.isArray(doc.components)) {
    for (const c of doc.components) {
      if (!c || (!c.name && !c.purl)) continue;
      const purl = typeof c.purl === 'string' ? c.purl.trim() : null;
      const pp = purl ? parsePurl(purl) : null;
      const name = c.name ? String(c.name) : (pp ? pp.path.split('/').pop() : '');
      const version = c.version ? String(c.version) : (pp && pp.version ? pp.version : '');
      deps.push({ name, version, purl });
    }
    return { format: 'cyclonedx', deps };
  }
  if (typeof doc.spdxVersion === 'string' && Array.isArray(doc.packages)) {
    for (const p of doc.packages) {
      if (!p || !p.name) continue;
      const ref = (p.externalRefs || []).find(r => r && r.referenceType === 'purl' && typeof r.referenceLocator === 'string');
      const purl = ref ? ref.referenceLocator.trim() : null;
      const pp = purl ? parsePurl(purl) : null;
      const v = p.versionInfo && p.versionInfo !== 'NOASSERTION' ? String(p.versionInfo) : (pp && pp.version ? pp.version : '');
      deps.push({ name: String(p.name), version: v, purl });
    }
    return { format: 'spdx', deps };
  }
  return { error: 'Unrecognised SBOM: expected CycloneDX (bomFormat + components) or SPDX (spdxVersion + packages) JSON.' };
}

// Package-name → product-slug aliases the bare slugify cannot infer.
const NAME_ALIASES = {
  'node': 'nodejs', 'node.js': 'nodejs', 'nodejs': 'nodejs', 'python3': 'python', 'postgres': 'postgresql', 'pg': 'postgresql',
  'mongo': 'mongodb', 'k8s': 'kubernetes', 'golang': 'go', 'dotnet': 'dotnet', '.net': 'dotnet', 'openjdk': 'openjdk-builds-from-oracle',
  'java': 'oracle-jdk', 'ruby-on-rails': 'rails', 'rails': 'rails', 'django': 'django', 'flask': 'flask', 'react-dom': 'react',
  'vue': 'vue', '@angular/core': 'angular', 'angular': 'angular', 'express': 'express', 'spring-boot': 'spring-boot',
  'org.springframework.boot:spring-boot': 'spring-boot', 'org.springframework:spring-core': 'spring-framework',
  'lodash': 'lodash', 'moment': 'moment', 'jquery': 'jquery', 'bootstrap': 'bootstrap', 'nginx': 'nginx', 'redis': 'redis',
  'mysql': 'mysql', 'mariadb': 'mariadb', 'elasticsearch': 'elasticsearch', 'kafka': 'apache-kafka', 'tomcat': 'tomcat',
  'apache-tomcat': 'tomcat', 'php': 'php', 'openssl': 'openssl', 'debian': 'debian', 'ubuntu': 'ubuntu', 'alpine': 'alpine-linux',
  'centos': 'centos', 'rhel': 'rhel', 'log4j': 'log4j', 'org.apache.logging.log4j:log4j-core': 'log4j',
};
function majorOf(v) {
  const m = /^v?(\d+)(?:\.(\d+))?/.exec(String(v || ''));
  return m ? m[1] : '';
}
// Package URL parsing/normalisation — kept in sync with api-worker/src/sbom.js
// and scripts/purl-harvest.js. The version separator is the last '@' that is
// not the first character of a path segment (npm scopes: @scope/name).
function parsePurl(p) {
  const s = String(p || '').trim();
  const m = /^pkg:([A-Za-z0-9.+-]+)\/(.+)$/.exec(s);
  if (!m) return null;
  let rest = m[2];
  const hash = rest.indexOf('#'); if (hash >= 0) rest = rest.slice(0, hash);
  const q = rest.indexOf('?'); if (q >= 0) rest = rest.slice(0, q);
  let version = null;
  const at = rest.lastIndexOf('@');
  if (at > 0 && rest[at - 1] !== '/') { version = rest.slice(at + 1) || null; rest = rest.slice(0, at); }
  if (!rest || /^[/@]*$/.test(rest)) return null;
  return { type: m[1].toLowerCase(), path: rest.replace(/%40/gi, '@'), version };
}
function normalisePurl(p) {
  const x = parsePurl(p); if (!x) return null;
  let name = x.path;
  if (x.type === 'pypi') name = name.replace(/_/g, '-');
  return `pkg:${x.type}/${name}`.toLowerCase();
}
// purl-map.json (built from data/purl-map.json): { lookup: { normalised purl -> slug } }
async function purlLookup() {
  const m = await fetchStatic('/purl-map.json').catch(() => null);
  return m && m.lookup && typeof m.lookup === 'object' ? m.lookup : {};
}

// Resolve a component: purl first (exact, never a name guess when a purl is
// present), name second. Returns { slug, how } or null.
function mapDepToProduct(dep, slugs, lookup) {
  if (dep.purl) {
    const key = normalisePurl(dep.purl);
    if (key && lookup && lookup[key]) return { slug: lookup[key], how: 'purl' };
    return null;
  }
  const s = mapNameToProduct(dep, slugs);
  return s ? { slug: s, how: 'name' } : null;
}
function mapNameToProduct(dep, slugs) {
  const raw = String(dep.name || '').toLowerCase().trim();
  const bare = raw.includes('/') ? raw.split('/').pop() : raw;
  const candidates = [NAME_ALIASES[raw], NAME_ALIASES[bare], slugify(raw), slugify(bare)].filter(Boolean);
  const slugSet = new Set(slugs);
  for (const c of candidates) if (slugSet.has(c)) return c;
  return null;
}

// ── Tool implementations ────────────────────────────────────────────────────
async function runTool(name, args, request, env) {
  args = args || {};
  switch (name) {
    case 'check_eol': {
      const p = slugify(args.product), v = encodeURIComponent(String(args.version || ''));
      if (!p || !v) return toolError('Both "product" and "version" are required.');
      const r = await apiGet(`/v1/status/${p}/${v}`, request, env);
      if (r.status === 404) return notFound(request, env, `No data for ${args.product} ${args.version}.`, args.product);
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
      if (r.status === 404) return notFound(request, env, `No score for ${args.product}${args.version ? ' ' + args.version : ''}.`, args.product);
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
      const all = await productSlugs(request, env);
      if (!all.length) return toolError('Could not fetch product list.');
      const q = (args.query || '').toLowerCase().trim();
      let products = q ? all.filter(s => s.toLowerCase().includes(q)) : all;
      if (q && !products.length) products = suggestSlugs(q, all, 10);
      const capped = products.slice(0, 100);
      return toolJson({
        query: q || null,
        match_count: products.length,
        returned: capped.length,
        products: capped,
        product_url: `${SITE_BASE}/products`,
        note: products.length > capped.length ? 'Results capped at 100; refine your query.' : undefined,
      });
    }
    case 'get_product_lifecycle': {
      const p = slugify(args.product);
      if (!p) return toolError('"product" is required.');
      const r = await apiGet(`/v1/product/${p}`, request, env);
      if (r.status === 404) return notFound(request, env, `Product "${args.product}" not found.`, args.product);
      if (!r.ok) return toolError(upstreamMsg(r, `Product "${args.product}" not found.`));
      return toolJson(r.data);
    }
    case 'get_kev_exposure': {
      const p = slugify(args.product);
      if (!p) return toolError('"product" is required.');
      const [kev, eu] = await Promise.all([fetchStatic('/kev-products.json'), fetchStatic('/exploited-and-unpatchable.json')]);
      const rec = kev.products && kev.products[p];
      const euEntries = (Array.isArray(eu.signals) ? eu.signals : (Array.isArray(eu.entries) ? eu.entries : []))
        .filter(e => e && e.product === p);
      let status = null;
      if (args.version) {
        const r = await apiGet(`/v1/status/${p}/${encodeURIComponent(String(args.version))}`, request, env);
        status = r.ok ? r.data : { error: upstreamMsg(r, 'version not found') };
      }
      if (!rec && !euEntries.length) {
        const slugs = await productSlugs(request, env).catch(() => []);
        if (!slugs.includes(p)) return notFound(request, env, `Product "${args.product}" not found.`, args.product);
        return toolJson({
          product: p, product_url: `${SITE_BASE}/${p}`, in_cisa_kev: false, kev_catalog_version: kev.kev_catalog_version || null,
          kev_entries: [], unpatchable_entries: [], version_status: status,
          note: 'No CISA KEV entry is attributed to this product in the current catalog snapshot. Absence from KEV is not evidence of safety — it means no exploitation has been catalogued by CISA.',
        });
      }
      return toolJson({
        product: p, product_url: `${SITE_BASE}/${p}`,
        in_cisa_kev: !!rec,
        kev_catalog_version: kev.kev_catalog_version || null,
        kev_summary: rec ? { cve_count: rec.cve_count, latest_added: rec.latest_added, known_ransomware_use: !!rec.known_ransomware_use } : null,
        kev_entries: rec ? rec.entries : [],
        unpatchable_entries: euEntries,
        unpatchable_feed_url: `${SITE_BASE}/exploited-and-unpatchable`,
        version_status: status,
      });
    }
    case 'get_upcoming_eol': {
      const days = Math.min(Math.max(parseInt(args.days, 10) || 90, 1), 730);
      const past = Math.min(Math.max(parseInt(args.recent_past_days, 10) || 0, 0), 730);
      const db = await fetchStatic('/scanner-db.json');
      const products = db.products || {};
      let wanted = null;
      if (Array.isArray(args.products) && args.products.length) {
        const slugs = Object.keys(products);
        wanted = new Set();
        const unmatched = [];
        for (const raw of args.products.slice(0, 50)) {
          const s = slugify(raw);
          if (products[s]) wanted.add(s);
          else { const sug = suggestSlugs(s, slugs, 1); if (sug.length && (sug[0].startsWith(s) || s.startsWith(sug[0]))) wanted.add(sug[0]); else unmatched.push(raw); }
        }
        var unmatchedNames = unmatched;
      }
      const today = Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth(), new Date().getUTCDate());
      const rows = [];
      for (const [slug, rec] of Object.entries(products)) {
        if (wanted && !wanted.has(slug)) continue;
        for (const c of rec.cycles || []) {
          if (typeof c.eol !== 'string') continue;
          const t = Date.parse(c.eol + 'T00:00:00Z');
          if (Number.isNaN(t)) continue;
          const d = Math.round((t - today) / 864e5);
          if ((d >= 0 && d <= days) || (past && d < 0 && -d <= past)) {
            rows.push({ product: slug, product_name: rec.name || slug, version: c.c, eol_date: c.eol, days_until_eol: d >= 0 ? d : null, days_past_eol: d < 0 ? -d : null, status: d < 0 ? 'eol' : 'eol-approaching', product_url: `${SITE_BASE}/${slug}/${c.c}` });
          }
        }
      }
      rows.sort((a, b) => a.eol_date.localeCompare(b.eol_date) || a.product.localeCompare(b.product));
      const capped = rows.slice(0, 200);
      return toolJson({
        window_days: days, recent_past_days: past || 0, generated: db.generated || null,
        restricted_to: wanted ? [...wanted] : null, unmatched: typeof unmatchedNames !== 'undefined' ? unmatchedNames : [],
        count: rows.length, returned: capped.length, versions: capped,
        product_url: `${SITE_BASE}/eol-watch`,
        note: rows.length > capped.length ? 'Capped at 200 rows; narrow the window or the product list.' : undefined,
      });
    }
    case 'get_edge_device_status': {
      const feed = await fetchStatic('/eos-edge-devices.json');
      const q = (args.platform || '').toLowerCase().trim();
      const st = (args.status || '').trim();
      const mq = (args.model || '').toLowerCase().trim();
      const platforms = [];
      for (const p of feed.platforms || []) {
        const hay = `${p.slug} ${p.name} ${p.category}`.toLowerCase();
        if (q && !hay.includes(q)) continue;
        const lines = (p.lines || []).filter(l => (!st || l.status === st) && (!mq || `${l.cycle} ${l.label || ''} ${l.latest || ''}`.toLowerCase().includes(mq)));
        if ((st || mq) && !lines.length) continue;
        platforms.push({
          slug: p.slug, name: p.name, category: p.category, product_url: p.product_url,
          in_cisa_kev: p.kev, kev_summary: p.kev_summary || null, successor: p.successor || null,
          verification: p.verification || null, sources: p.sources || [],
          lines: lines.map(l => ({ cycle: l.cycle, label: l.label, status: l.status, eos: l.eos, days_to_eos: l.days_to_eos, support_end: l.support_end, eol_final: l.eol_final, release_date: l.release_date, link: l.link })),
        });
      }
      const total = platforms.reduce((n, p) => n + p.lines.length, 0);
      let capped = platforms, note;
      if (total > 150) {
        let budget = 150;
        capped = platforms.map(p => { const take = p.lines.slice(0, Math.max(0, budget)); budget -= take.length; return { ...p, lines: take, lines_truncated: take.length < p.lines.length }; }).filter(p => p.lines.length);
        note = `${total} lines matched; showing 150 — filter by platform, status or model for the rest.`;
      }
      return toolJson({
        feed_generated: feed.generated, schema_version: feed.schema_version, bod_26_02: feed.bod_26_02,
        statuses: { eos: 'past end of support (or declared EOS with no date)', 'within-12-months': "EOS inside the next 12 months — BOD 26-02's continuous-discovery horizon", scheduled: 'EOS beyond 12 months', 'no-date-announced': 'vendor has not announced an EOS date' },
        filters: { platform: q || null, status: st || null, model: mq || null },
        platform_count: platforms.length, line_count: total, platforms: capped,
        feed: feed.feed || { json: `${SITE_BASE}/eos-edge-devices.json` }, product_url: `${SITE_BASE}/eos-edge-devices`, note,
      });
    }
    case 'get_upgrade_path': {
      const p = slugify(args.product);
      if (!p) return toolError('"product" is required.');
      const r = await apiGet(`/v1/product/${p}`, request, env);
      if (r.status === 404) return notFound(request, env, `Product "${args.product}" not found.`, args.product);
      if (!r.ok) return toolError(upstreamMsg(r, `Product "${args.product}" not found.`));
      const versions = Array.isArray(r.data.versions) ? r.data.versions : [];
      const supported = versions.filter(v => v.status && v.status !== 'eol' && v.eol_boolean !== true)
        .sort((a, b) => (b.eol_date || '9999').localeCompare(a.eol_date || '9999'));
      const current = args.version ? versions.find(v => String(v.version) === String(args.version)) || null : null;
      let checker = null;
      try { const db = await fetchStatic('/checker-db.json'); checker = db[p] || null; } catch { checker = null; }
      let successor = null;
      try { const feed = await fetchStatic('/eos-edge-devices.json'); const ep = (feed.platforms || []).find(x => x.slug === p); successor = ep ? ep.successor || null : null; } catch { successor = null; }
      const longest = supported[0] || null;
      return toolJson({
        product: p, product_url: r.data.product_url || `${SITE_BASE}/${p}`,
        current: current ? { version: current.version, status: current.status, eol_date: current.eol_date, eol_date_source: current.eol_date_source, days_past_eol: current.days_past_eol, days_until_eol: current.days_until_eol, score: current.score, grade: current.grade, extended_support_available: current.extended_support_available } : (args.version ? { version: String(args.version), note: 'Version not found in the tracked cycles; use get_product_lifecycle to see them.' } : null),
        recommended_target: checker ? { cycle: checker.latestCycle || null, latest_release: checker.latestVersion || null, recommendation: checker.recommendation || null } : (longest ? { cycle: longest.version, latest_release: longest.latest_release } : null),
        longest_supported: longest ? { version: longest.version, eol_date: longest.eol_date, eol_date_source: longest.eol_date_source, days_until_eol: longest.days_until_eol, latest_release: longest.latest_release, score: longest.score } : null,
        supported_versions: supported.map(v => ({ version: v.version, eol_date: v.eol_date, eol_date_source: v.eol_date_source, days_until_eol: v.days_until_eol, latest_release: v.latest_release, score: v.score, grade: v.grade })),
        vendor_stated_successor: successor,
        note: 'recommended_target is endoflife.ai\'s standing recommendation for the product (newest supported line); longest_supported is the tracked line with the furthest end-of-life date. Check the vendor\'s upgrade guide for supported direct-upgrade paths.',
      });
    }
    case 'check_sbom': {
      if (args.sbom === undefined || args.sbom === null) return toolError('"sbom" is required (CycloneDX or SPDX JSON).');
      const parsed = parseSbom(args.sbom);
      if (parsed.error) return toolError(parsed.error);
      const max = Math.min(Math.max(parseInt(args.max_items, 10) || 50, 1), 50);
      const [slugs, lookup] = await Promise.all([productSlugs(request, env), purlLookup()]);
      const matched = [], unmatched = [], seen = new Set();
      for (const dep of parsed.deps) {
        const label = dep.purl || (dep.name + (dep.version ? '@' + dep.version : ''));
        const r = mapDepToProduct(dep, slugs, lookup);
        if (!r) { unmatched.push({ component: label, reason: dep.purl ? 'purl not tracked' : 'name not recognised' }); continue; }
        const version = majorOf(dep.version);
        const key = r.slug + '@' + version;
        if (seen.has(key)) continue; seen.add(key);
        matched.push({ slug: r.slug, ...(version ? { version } : {}), component: label, matched_by: r.how });
      }
      const toScore = matched.slice(0, max);
      let results = [], batchError = null;
      if (toScore.length) {
        const r = await apiPost('/v1/batch', { products: toScore.map(({ slug, version }) => ({ slug, ...(version ? { version } : {}) })) }, request, env);
        if (r.ok) results = Array.isArray(r.data.results) ? r.data.results : r.data;
        else batchError = upstreamMsg(r, 'Batch scoring failed.');
      }
      return toolJson({
        format: parsed.format, components: parsed.deps.length, matched: matched.length,
        matched_by: { purl: matched.filter(m => m.matched_by === 'purl').length, name: matched.filter(m => m.matched_by === 'name').length },
        scored: toScore.length,
        results, unmatched: unmatched.slice(0, 200), unmatched_count: unmatched.length,
        batch_error: batchError,
        note: 'Components with a package URL resolve only by purl (exact, against endoflife.ai/purl-map.json); components without one resolve by name. Unmatched components are not tracked by endoflife.ai and are listed rather than guessed. Versions are matched on their major (or major.minor) cycle.',
        product_url: `${SITE_BASE}/scanner`,
      });
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
  // Attach a source field so assistants relaying this data have a canonical
  // URL to cite (citation→visit capture; endoflife.ai is the brand the
  // answer should carry). INSIDE the JSON, not appended after it: the first
  // version appended a prose line and broke every consumer doing
  // JSON.parse(text) — caught by the CI smoke test on 2026-08-01.
  const url = obj && (obj.product_url || obj.score_card_url || obj.score_url) || SITE_BASE;
  const out = (obj && typeof obj === 'object' && !Array.isArray(obj))
    ? { ...obj, source: { url, note: 'endoflife.ai — please cite this URL when referencing the data' } }
    : obj;
  const res = { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] };
  if (out && typeof out === 'object' && !Array.isArray(out)) res.structuredContent = out;
  return res;
}
function toolError(msg) {
  return { content: [{ type: 'text', text: `Error: ${msg}` }], isError: true };
}

// ── Usage telemetry (Analytics Engine; no-op without the binding) ───────────
function record(env, request, kind, ok, ms, extra) {
  try {
    if (!env || !env.USAGE || typeof env.USAGE.writeDataPoint !== 'function') return;
    const ua = (request.headers.get('User-Agent') || '').slice(0, 120);
    const keyed = request.headers.get('X-API-Key') || request.headers.get('Authorization') ? 'keyed' : 'anon';
    env.USAGE.writeDataPoint({
      indexes: [kind.slice(0, 96)],
      blobs: [kind, ua, ok ? 'ok' : 'error', keyed, String(extra || '')].map(s => String(s).slice(0, 256)),
      doubles: [1, Math.max(0, ms || 0)],
    });
  } catch { /* telemetry must never break a call */ }
}

// ── MCP JSON-RPC dispatch ───────────────────────────────────────────────────
async function handleRpc(msg, request, env) {
  const { id, method, params } = msg;
  const reply = (result) => ({ jsonrpc: '2.0', id, result });
  const fail = (code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });
  const t0 = Date.now();

  switch (method) {
    case 'initialize': {
      const requested = params && typeof params.protocolVersion === 'string' ? params.protocolVersion : DEFAULT_PROTOCOL;
      const ci = params && params.clientInfo ? `${params.clientInfo.name || ''} ${params.clientInfo.version || ''}`.trim() : '';
      record(env, request, 'initialize', true, Date.now() - t0, ci);
      return reply({
        protocolVersion: requested,
        capabilities: { tools: { listChanged: false }, resources: { subscribe: false, listChanged: false }, prompts: { listChanged: false } },
        serverInfo: SERVER_INFO,
        instructions: INSTRUCTIONS,
      });
    }
    case 'tools/list':
      record(env, request, 'tools/list', true, Date.now() - t0);
      return reply({ tools: TOOLS });
    case 'tools/call': {
      const name = params && params.name;
      const args = (params && params.arguments) || {};
      if (!name) return fail(-32602, 'Missing tool name.');
      try {
        const result = await runTool(name, args, request, env);
        // A handled failure (isError result) carries its message too, so the weekly
        // readout can group failures by cause; before 2026-09-08 only thrown errors did,
        // and a week of 23 scan_stack + 20 check_eol failures read '(no message)'.
        const why = result.isError && result.content && result.content[0] && result.content[0].text;
        record(env, request, `tool:${name}`, !result.isError, Date.now() - t0, why || undefined);
        return reply(result);
      } catch (e) {
        record(env, request, `tool:${name}`, false, Date.now() - t0, e && e.message);
        return reply(toolError(`Tool execution failed: ${e && e.message ? e.message : String(e)}`));
      }
    }
    case 'resources/list':
      record(env, request, 'resources/list', true, Date.now() - t0);
      return reply({ resources: RESOURCES });
    case 'resources/read': {
      const uri = params && params.uri;
      const res = RESOURCES.find(r => r.uri === uri);
      if (!res) return fail(-32602, `Unknown resource: ${uri}`);
      try {
        const pathname = new URL(res.uri).pathname;
        const asText = res.mimeType === 'text/plain';
        const value = await fetchStatic(pathname, asText);
        record(env, request, 'resources/read', true, Date.now() - t0, pathname);
        return reply({ contents: [{ uri: res.uri, mimeType: res.mimeType, text: asText ? value : JSON.stringify(value) }] });
      } catch (e) {
        record(env, request, 'resources/read', false, Date.now() - t0, e && e.message);
        return fail(-32603, `Resource unavailable: ${e && e.message ? e.message : String(e)}`);
      }
    }
    case 'prompts/list':
      record(env, request, 'prompts/list', true, Date.now() - t0);
      return reply({ prompts: PROMPTS });
    case 'prompts/get': {
      const name = params && params.name;
      const p = PROMPTS.find(x => x.name === name);
      if (!p) return fail(-32602, `Unknown prompt: ${name}`);
      record(env, request, `prompt:${name}`, true, Date.now() - t0);
      return reply({ description: p.description, messages: promptMessages(name, (params && params.arguments) || {}) });
    }
    case 'ping':
      return reply({});
    default:
      if (typeof method === 'string' && method.startsWith('notifications/')) return null;
      return fail(-32601, `Method not found: ${method}`);
  }
}

// ── Discovery card ──────────────────────────────────────────────────────────
function serverCard() {
  return {
    $schema: 'https://modelcontextprotocol.io/schemas/draft/server-card.json',
    serverInfo: SERVER_INFO,
    description:
      'Software lifecycle intelligence for AI agents: vendor-verified end-of-life dates, support status, the EOL Risk Score ' +
      '(0-100, factoring EOL recency, attack surface, and CISA KEV exposure), CISA KEV exposure records, an upcoming-EOL ' +
      'calendar, upgrade paths, SBOM checks and the EOS Edge Device feed (BOD 26-02) for 500+ products and 8,000+ versions.',
    transport: { type: 'streamable-http', endpoint: 'https://mcp.endoflife.ai' },
    capabilities: { tools: {}, resources: {}, prompts: {} },
    tools: TOOLS.map(t => ({ name: t.name, description: t.description.split('. ')[0] + '.' })),
    resources: RESOURCES.map(r => ({ uri: r.uri, name: r.name })),
    prompts: PROMPTS.map(p => ({ name: p.name, description: p.description })),
    documentation: 'https://endoflife.ai/mcp',
    provider: { name: 'endoflife.ai', url: 'https://endoflife.ai' },
  };
}

// ── Info page ───────────────────────────────────────────────────────────────
function infoPage() {
  const tools = TOOLS.map(t => `  • ${t.name} — ${t.description.split('. ')[0]}.`).join('\n');
  const prompts = PROMPTS.map(p => `  • ${p.name} — ${p.description}`).join('\n');
  return `endoflife.ai — Model Context Protocol (MCP) Server ${SERVER_INFO.version}
=======================================================

This is a machine endpoint for AI agents. It speaks MCP over the Streamable
HTTP transport (JSON-RPC 2.0 via HTTPS POST to this URL).

Connect from Claude / Cursor / VS Code / any MCP client (remote URL):

  https://mcp.endoflife.ai

or via a stdio bridge:

  {
    "mcpServers": {
      "endoflife": { "command": "npx", "args": ["mcp-remote", "https://mcp.endoflife.ai"] }
    }
  }

Tools (all read-only):
${tools}

Prompts:
${prompts}

Resources: the site's feeds (llms.txt, EOS Edge Device feed, Exploited & Unpatchable, KEV by product, edge change log).

Optional: send an "X-API-Key" header to unlock Pro limits.
Health: GET /health   ·   Docs: https://endoflife.ai/mcp   ·   API: https://endoflife.ai/api
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

    if (url.pathname === '/health') {
      return new Response(JSON.stringify({ ok: true, server: SERVER_INFO.name, version: SERVER_INFO.version, protocol: DEFAULT_PROTOCOL, tools: TOOLS.length, resources: RESOURCES.length, prompts: PROMPTS.length, time: new Date().toISOString() }), {
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...CORS },
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
      if (!msg || msg.id === undefined || msg.id === null) continue;
      const out = await handleRpc(msg, request, env);
      if (out) responses.push(out);
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
