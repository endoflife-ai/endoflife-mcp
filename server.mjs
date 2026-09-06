#!/usr/bin/env node
/**
 * Node host for the endoflife.ai MCP server.
 *
 * Production mcp.endoflife.ai is a Cloudflare Worker (src/index.js, a plain
 * `fetch(request, env)` handler with no Cloudflare-only imports). This file
 * runs that same handler inside a normal Node.js process, so the server can
 * be packaged as a container (see Dockerfile, Red Hat UBI base) and deployed
 * on a cluster - the form the OpenShift AI MCP catalog expects.
 *
 * Bindings: the Worker calls the API through a service binding when one is
 * present and falls back to a plain fetch of https://api.endoflife.ai when it
 * is not (apiFetch in src/index.js); usage telemetry is a no-op without the
 * USAGE binding. So an empty env is a valid, fully working configuration.
 *
 *   PORT=8080 node server.mjs
 *   ENDOFLIFE_API_KEY=...   optional, forwarded by the Worker as usual
 *
 * Endpoints are the Worker's own: POST / (Streamable HTTP JSON-RPC),
 * GET /health, GET /.well-known/mcp/server-card.json.
 */
import http from 'node:http';
import worker from './src/index.js';

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const env = {}; // no API / USAGE bindings: see the note above

async function toRequest(req) {
  const proto = String(req.headers['x-forwarded-proto'] || 'http').split(',')[0].trim();
  const url = new URL(req.url, `${proto}://${req.headers.host || `localhost:${PORT}`}`);
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined) continue;
    headers.set(k, Array.isArray(v) ? v.join(', ') : v);
  }
  let body;
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    body = chunks.length ? Buffer.concat(chunks) : undefined;
  }
  return new Request(url, { method: req.method, headers, body });
}

async function send(res, response) {
  const headers = {};
  response.headers.forEach((v, k) => { headers[k] = v; });
  res.writeHead(response.status, headers);
  if (response.body) {
    for await (const chunk of response.body) res.write(chunk);
  }
  res.end();
}

const server = http.createServer(async (req, res) => {
  try {
    const response = await worker.fetch(await toRequest(req), env, { waitUntil() {} });
    await send(res, response);
  } catch (err) {
    console.error('[endoflife-mcp] request failed:', err && err.stack || err);
    if (!res.headersSent) res.writeHead(500, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32603, message: 'internal error' }, id: null }));
  }
});

server.listen(PORT, HOST, () => {
  console.log(`[endoflife-mcp] listening on http://${HOST}:${PORT} (node ${process.version})`);
});

for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => {
    console.log(`[endoflife-mcp] ${sig} received, shutting down`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  });
}
