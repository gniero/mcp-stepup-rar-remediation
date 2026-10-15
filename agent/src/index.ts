/**
 * "Agentic" client: Claude decides which MCP tools to call; the MCP client
 * underneath transparently handles Bearer challenges (initial auth + step-up).
 *
 *   node src/index.ts                 interactive REPL
 *   node src/index.ts "some prompt"   one-shot
 */
import readline from "node:readline/promises";
import Anthropic from "@anthropic-ai/sdk";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { OAuthSession } from "./oauth.ts";
import { stepUpFetch } from "./stepup-fetch.ts";
import { log } from "./log.ts";
import { registerElicitation } from "./elicitation.ts";

const MCP_URL = process.env.MCP_URL ?? "http://mcp-server:3000/mcp";
const MODEL = process.env.ANTHROPIC_MODEL ?? "claude-sonnet-4-6";
const CALLBACK_PORT = Number(process.env.CALLBACK_PORT ?? "8765");
// A request held for step-up waits on a human in a browser: the SDK's default
// 60s request timeout is too short, so every MCP request gets a longer one.
const HELD_REQUEST_TIMEOUT_MS = Number(process.env.HELD_REQUEST_TIMEOUT_MS ?? "300000");

const oauth = new OAuthSession(
  process.env.OAUTH_CLIENT_ID ?? "mcp-agent",
  process.env.OAUTH_REDIRECT_URI ?? `http://localhost:${CALLBACK_PORT}/callback`,
  CALLBACK_PORT,
);

// ---- MCP connection ---------------------------------------------------------
log.tool("stepup-lab agent: session token (mcp:basic) + RAR remediation client (one-shot authorization_details tokens)");
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const mcp = new Client(
  { name: "stepup-lab-agent", version: "0.1.0" },
  { capabilities: { elicitation: { form: {} } } },
);
registerElicitation(mcp, (q) => rl.question(q));
const transport = new StreamableHTTPClientTransport(new URL(MCP_URL), { fetch: stepUpFetch(oauth) });
await mcp.connect(transport, { timeout: HELD_REQUEST_TIMEOUT_MS }); // first request gets 401 -> login -> replay
const { tools } = await mcp.listTools(undefined, { timeout: HELD_REQUEST_TIMEOUT_MS });
log.tool(`connected to ${MCP_URL}; tools: ${tools.map((t) => t.name).join(", ")}`);

// ---- LLM loop -----------------------------------------------------------------
const anthropic = new Anthropic();
const llmTools: Anthropic.Tool[] = tools.map((t) => ({
  name: t.name,
  description: t.description ?? "",
  input_schema: t.inputSchema as Anthropic.Tool.InputSchema,
}));
const system =
  "You are a banking assistant for a Brazilian user. Use the tools to act. " +
  "Amounts are in BRL. Be brief. If a tool fails, explain the failure to the user.";
const messages: Anthropic.MessageParam[] = [];

async function turn(userText: string) {
  messages.push({ role: "user", content: userText });
  for (;;) {
    const resp = await anthropic.messages.create({ model: MODEL, max_tokens: 1024, system, tools: llmTools, messages });
    messages.push({ role: "assistant", content: resp.content });
    for (const b of resp.content) if (b.type === "text" && b.text.trim()) console.log(`\nassistant> ${b.text}\n`);
    if (resp.stop_reason !== "tool_use") return;

    const results: Anthropic.ToolResultBlockParam[] = [];
    for (const b of resp.content) {
      if (b.type !== "tool_use") continue;
      log.tool(`${b.name} ${JSON.stringify(b.input)}`);
      try {
        const r = await mcp.callTool(
          { name: b.name, arguments: b.input as Record<string, unknown> },
          undefined,
          { timeout: HELD_REQUEST_TIMEOUT_MS },
        );
        const out = (r.content as any[]).map((c) => (c.type === "text" ? c.text : JSON.stringify(c))).join("\n");
        log.tool(`result${r.isError ? " (error)" : ""}: ${out.split("\n")[0]}`);
        results.push({ type: "tool_result", tool_use_id: b.id, content: out, is_error: Boolean(r.isError) });
      } catch (e) {
        // e.g. the user refused the step-up: the original 403 surfaces here.
        const msg = (e as Error).message;
        log.tool(`call failed: ${msg}`);
        results.push({ type: "tool_result", tool_use_id: b.id, content: `Tool call failed: ${msg}`, is_error: true });
      }
    }
    messages.push({ role: "user", content: results });
  }
}

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
