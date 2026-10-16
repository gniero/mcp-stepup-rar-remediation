/**
 * The same MCP server (same tools, same authorization logic) over stdio.
 *
 * stdio has no HTTP status codes and no Authorization header, so:
 *  - the SESSION token comes from the environment (MCP auth spec: stdio servers take credentials
 *    from the environment): MCP_ACCESS_TOKEN, a JWT with scope=mcp:basic;
 *  - a mid-tool challenge is answered IN-BAND: JSON-RPC error AUTHORIZATION_REQUIRED (-32010)
 *    with the RAR remediation (see challenge.ts);
 *  - the client retries as a new request carrying `_meta["lab.stepup/operation_id"]` and the
 *    one-shot token in `_meta["lab.stepup/access_token"]`.
 *
 *   MCP_ACCESS_TOKEN=... node src/stdio.ts
 */
// stdout is the protocol channel: route all logging to stderr.
console.log = (...args: unknown[]) => console.error(...args);

import { StdioServerTransport, serveStdio } from "@modelcontextprotocol/server/stdio";
import { authenticate } from "./auth.ts";
import { StdioAuthTransport } from "./challenge.ts";
import { buildServer } from "./tools.ts";

const token = process.env.MCP_ACCESS_TOKEN;
if (!token) {
  console.error("MCP_ACCESS_TOKEN (session token, scope=mcp:basic) is required for the stdio transport");
  process.exit(2);
}
const session = await authenticate(`Bearer ${token}`);
if (session.oneShot) {
  console.error("MCP_ACCESS_TOKEN must be a session token (mcp:basic), not a one-shot operation token");
  process.exit(2);
}

// serveStdio negotiates the era (server/discover for 2026-07-28, initialize for 2025 clients) and
// pins one instance from the factory for the connection.
serveStdio(() => buildServer(), {
  transport: new StdioAuthTransport(new StdioServerTransport(), {
    defaultAuth: session,
    authenticateMetaToken: (t) => authenticate(`Bearer ${t}`),
  }),
  onerror: (e) => console.error(`[stdio] ${e.message}`),
});
console.error(`[stdio] MCP server ready for sub=${session.sub} (in-band challenges)`);
