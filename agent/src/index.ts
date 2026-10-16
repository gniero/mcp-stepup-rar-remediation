/**
 * "Agentic" client: an LLM (Claude, or a local model via an OpenAI-compatible API) decides which
 * MCP tools to call; the MCP client underneath transparently handles Bearer challenges
 * (initial auth + per-operation authorization).
 *
 *   node src/index.ts                 interactive REPL
 *   node src/index.ts "some prompt"   one-shot
 */
import readline from "node:readline/promises";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { OAuthSession } from "./oauth.ts";
import { stepUpFetch } from "./stepup-fetch.ts";
import { log } from "./log.ts";
import { elicitationHandler, registerElicitation } from "./elicitation.ts";
import { EXTENSION_ID, callToolWithAuthorization } from "./call-tool.ts";
import { createChat, type ToolOutcome } from "./llm.ts";

const MCP_URL = process.env.MCP_URL ?? "http://mcp-server:3000/mcp";
const CALLBACK_PORT = Number(process.env.CALLBACK_PORT ?? "8765");
// In-band "authorization required" forms this client handles, in preference order (lab extension).
// "" = declare nothing: the server then uses the interoperable 401.
const BINDINGS = (process.env.AGENT_BINDINGS ?? "mrtr,inband").split(",").map((b) => b.trim()).filter(Boolean);
// A request held for step-up waits on a human in a browser: the SDK's default
// 60s request timeout is too short, so every MCP request gets a longer one.
const HELD_REQUEST_TIMEOUT_MS = Number(process.env.HELD_REQUEST_TIMEOUT_MS ?? "300000");

const oauth = new OAuthSession(
  process.env.OAUTH_CLIENT_ID ?? "mcp-agent",
  process.env.OAUTH_REDIRECT_URI ?? `http://localhost:${CALLBACK_PORT}/callback`,
  CALLBACK_PORT,
);

// ---- MCP connection ---------------------------------------------------------
log.tool(
  "stepup-lab agent (MCP 2026-07-28): session token (mcp:basic) + RAR remediation client (one-shot authorization_details tokens); " +
    `in-band forms declared: ${BINDINGS.length ? BINDINGS.join(" > ") : "none (401 only)"}`,
);
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const mcp = new Client(
  { name: "stepup-lab-agent", version: "0.2.0" },
  {
    capabilities: {
      elicitation: { form: {} },
      // Lab extension: the in-band forms of "authorization required" this client handles, in
      // preference order. The server picks the first it offers; without it, the client gets the 401.
      ...(BINDINGS.length ? { extensions: { [EXTENSION_ID]: { bindings: BINDINGS } } } : {}),
    },
    // MCP 2026-07-28 only (the lab server rejects 2025-era traffic): server/discover instead of
    // initialize, no session, the _meta envelope on every request.
    versionNegotiation: { mode: { pin: "2026-07-28" } },
    // MRTR rounds of tools/call are driven by call-tool.ts in manual mode (allowInputRequired), so
    // it can see the authorization step; the SDK driver still serves any other request.
    inputRequired: { autoFulfill: true, maxRounds: 4 },
  },
);
const elicit = elicitationHandler((q) => rl.question(q));
registerElicitation(mcp, elicit);
const transport = new StreamableHTTPClientTransport(new URL(MCP_URL), { fetch: stepUpFetch(oauth) });
await mcp.connect(transport, { timeout: HELD_REQUEST_TIMEOUT_MS }); // server/discover gets 401 -> login -> replay
const { tools } = await mcp.listTools(undefined, { timeout: HELD_REQUEST_TIMEOUT_MS });
log.tool(`connected to ${MCP_URL}; tools: ${tools.map((t) => t.name).join(", ")}`);

// ---- LLM loop (Claude or any OpenAI-compatible local model, see llm.ts) ---------
async function callTool(name: string, args: Record<string, unknown>): Promise<ToolOutcome> {
  log.tool(`${name} ${JSON.stringify(args)}`);
  try {
    // HTTP binding (401) is handled inside stepUpFetch; in-band (-32010) and MRTR bindings here.
    const r = await callToolWithAuthorization(mcp, oauth, elicit, { name, arguments: args }, { timeout: HELD_REQUEST_TIMEOUT_MS });
    const text = (r.content as any[]).map((c) => (c.type === "text" ? c.text : JSON.stringify(c))).join("\n");
    log.tool(`result${r.isError ? " (error)" : ""}: ${text.split("\n")[0]}`);
    return { text, isError: Boolean(r.isError) };
  } catch (e) {
    // Transport/protocol failures only: a refused authorization arrives as an isError result.
    const msg = (e as Error).message;
    log.tool(`call failed: ${msg}`);
    return { text: `Tool call failed: ${msg}`, isError: true };
  }
}

const chat = createChat(tools, callTool);
log.tool(`LLM: ${chat.describe}`);
const turn = chat.turn;

const oneShot = process.argv.slice(2).join(" ").trim();
if (oneShot) {
  await turn(oneShot);
} else {
  console.log('Try: "what are my balances?", then "send R$ 800 to carol@pix.example from checking", then balances again');
  for (;;) {
    const q = (await rl.question("you> ")).trim();
    if (!q || q === "exit") break;
    await turn(q);
  }
}
rl.close();
await mcp.close();
