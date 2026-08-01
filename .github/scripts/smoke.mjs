#!/usr/bin/env node
/**
 * Live smoke test for the deployed endoflife.ai MCP server.
 *
 * This exists because of a real outage: on 2026-07-29 every tool returned an
 * error in production for an unknown period while the server still looked
 * healthy — `initialize` and `tools/list` are served from a static schema and
 * kept passing, so nothing that only checked "does it respond" would have
 * noticed. This test therefore asserts on the *content* of a real tool call.
 */

const ENDPOINT = process.env.ENDOFLIFE_MCP_URL || 'https://mcp.endoflife.ai';
const EXPECTED_TOOLS = [
  'check_eol',
  'get_risk_score',
  'scan_stack',
  'list_products',
  'get_product_lifecycle',
];

const failures = [];
function check(label, ok, detail = '') {
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${label}${detail ? ' — ' + detail : ''}`);
  if (!ok) failures.push(label);
}

async function rpc(method, params) {
  const res = await fetch(ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${ENDPOINT}`);
  const body = await res.text();
  const payload = body.includes('data:')
    ? body.split(/\r?\n/).filter((l) => l.startsWith('data:')).map((l) => l.slice(5).trim()).join('')
    : body;
  const msg = JSON.parse(payload);
  if (msg.error) throw new Error(`JSON-RPC error: ${JSON.stringify(msg.error)}`);
  return msg.result;
}

const init = await rpc('initialize', {
  protocolVersion: '2025-06-18',
  capabilities: {},
  clientInfo: { name: 'ci-smoke', version: '1' },
});
check('initialize returns serverInfo', Boolean(init?.serverInfo?.name), init?.serverInfo?.name);

const list = await rpc('tools/list', {});
const names = (list?.tools || []).map((t) => t.name);
for (const t of EXPECTED_TOOLS) check(`tools/list advertises ${t}`, names.includes(t));

// The load-bearing assertion: a real call that hits the upstream API.
// A static schema cannot fake this.
const call = await rpc('tools/call', {
  name: 'check_eol',
  arguments: { product: 'nodejs', version: '18' },
});
const text = call?.content?.[0]?.text ?? '';
check('check_eol did not return isError', call?.isError !== true, text.slice(0, 120));

let parsed;
try {
  parsed = JSON.parse(text);
} catch {
  /* left undefined — asserted below */
}
check('check_eol returned parseable data', Boolean(parsed), parsed ? '' : text.slice(0, 120));
check('check_eol reports nodejs 18 as eol', parsed?.status === 'eol', `status=${parsed?.status}`);
check('check_eol carries an eol_date', Boolean(parsed?.eol_date), `eol_date=${parsed?.eol_date}`);
check('check_eol carries source attribution', String(parsed?.source?.url || '').includes('endoflife.ai'), parsed?.source?.url);

if (failures.length) {
  console.error(`\n${failures.length} check(s) failed: ${failures.join(', ')}`);
  process.exit(1);
}
console.log('\nAll checks passed.');
