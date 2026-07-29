#!/usr/bin/env node
/**
 * stdio <-> Streamable-HTTP bridge for the endoflife.ai MCP server.
 *
 * The server itself is a Cloudflare Worker at https://mcp.endoflife.ai speaking
 * Streamable HTTP, so there is nothing to `npm start` locally. Some MCP hosts
 * (and Glama's build/security checks, which run `mcp-proxy -- <cmd>`) need to
 * spawn a *stdio* server instead. This script is that entrypoint: it reads
 * newline-delimited JSON-RPC on stdin, forwards each message to the Worker, and
 * writes the reply to stdout.
 *
 * Zero dependencies — Node's global fetch only. Requests are forwarded verbatim,
 * so this stays correct as tools are added to the Worker; there is no second
 * implementation of the protocol to keep in sync.
 *
 *   node stdio.js
 *   ENDOFLIFE_MCP_URL=http://localhost:8787 node stdio.js   # against wrangler dev
 */

const ENDPOINT = process.env.ENDOFLIFE_MCP_URL || "https://mcp.endoflife.ai";
const API_KEY = process.env.ENDOFLIFE_API_KEY || "";

/** Streamable HTTP may answer as JSON or as an SSE stream; accept both. */
function extractPayload(contentType, body) {
  if (!body) return "";
  if ((contentType || "").includes("text/event-stream")) {
    // Pull the `data:` lines out of the SSE framing.
    return body
      .split(/\r?\n/)
      .filter((l) => l.startsWith("data:"))
      .map((l) => l.slice(5).trim())
      .filter(Boolean)
      .join("\n");
  }
  return body.trim();
}

async function forward(message) {
  // A JSON-RPC notification has no id and must not receive a reply.
  const isNotification = message.id === undefined || message.id === null;

  try {
    const headers = {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    };
    if (API_KEY) headers["X-API-Key"] = API_KEY;

    const res = await fetch(ENDPOINT, {
      method: "POST",
      headers,
      body: JSON.stringify(message),
    });

    const payload = extractPayload(res.headers.get("content-type"), await res.text());
    if (isNotification || !payload) return;
    process.stdout.write(payload + "\n");
  } catch (err) {
    if (isNotification) return;
    process.stdout.write(
      JSON.stringify({
        jsonrpc: "2.0",
        id: message.id,
        error: { code: -32603, message: `bridge: ${err && err.message ? err.message : err}` },
      }) + "\n"
    );
  }
}

// In-flight forwards. stdin closing does not mean we are done: a piped session
// (`echo ... | node stdio.js`, which is how build checks drive it) ends stdin
// immediately, and exiting there would drop every reply still in flight.
const pending = new Set();

let buffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  let idx;
  while ((idx = buffer.indexOf("\n")) !== -1) {
    const line = buffer.slice(0, idx).trim();
    buffer = buffer.slice(idx + 1);
    if (!line) continue;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      continue; // ignore malformed frames rather than killing the session
    }
    // Replies may return out of order; JSON-RPC correlates by id.
    const task = forward(message).finally(() => pending.delete(task));
    pending.add(task);
  }
});

process.stdin.on("end", async () => {
  await Promise.allSettled([...pending]);
  process.exit(0);
});
