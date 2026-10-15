/**
 * Headless walkthrough of the IN-BAND binding over stdio (no LLM, no browser).
 *
 *   docker compose run --rm mcp-server node src/stdio-probe.ts
 *
 * Spawns `node src/stdio.ts` as a child process (the same server, stdio transport), gets tokens
 * from the AS with the lab-only password grant, and shows:
 *   transfer -> JSON-RPC error -32043 AUTHORIZATION_REQUIRED + remediation
 *   -> one-shot token for exactly those authorization_details
 *   -> retry as a NEW request with _meta {operation_id, access_token} -> success
 *   -> same retry again -> stored result (no second debit)
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import { AUTHORIZATION_REQUIRED, META_ACCESS_TOKEN, META_OPERATION_ID } from "./challenge.ts";

const TOKEN_URL = process.env.PROBE_TOKEN_URL ?? "http://idp:8080/token";

async function token(field: Record<string, string>) {
  const r = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${Buffer.from("mcp-probe:probe-secret").toString("base64")}`,
    },
    body: new URLSearchParams({ grant_type: "urn:lab:params:oauth:grant-type:password", username: "alice", password: "alice", ...field }),
  });
  const j = await r.json();
  if (!r.ok) throw new Error(JSON.stringify(j));
  return j.access_token as string;
}
const text = (r: any) => r.content?.map((c: any) => c.text).join(" | ");
const H = (s: string) => console.log(`\n=== ${s}`);

const session = await token({ scope: "mcp:basic" });
const client = new Client({ name: "stdio-probe", version: "0" });
await client.connect(
  new StdioClientTransport({
    command: "node",
    args: ["src/stdio.ts"],
    env: { ...(process.env as Record<string, string>), MCP_ACCESS_TOKEN: session },
    stderr: "inherit",
  }),
);

H("1. get_accounts with the session token (from the environment)");
console.log(text(await client.callTool({ name: "get_accounts", arguments: {} })));

const args = { from_account: "checking", pix_key: "carol@pix.example", amount: 800 };
H("2. transfer -> in-band AUTHORIZATION_REQUIRED (no HTTP, no 401)");
let data: any;
try {
  await client.callTool({ name: "transfer", arguments: args });
  throw new Error("expected AUTHORIZATION_REQUIRED");
} catch (e) {
  if (!(e instanceof McpError) || e.code !== AUTHORIZATION_REQUIRED) throw e;
  data = e.data;
  console.log(`code=${e.code} message="${e.message}"`);
  console.log(JSON.stringify(data, null, 2));
}

const oneShot = await token({ authorization_details: JSON.stringify(data.authorization_remediation.authorization_details) });
const retryMeta = { [META_OPERATION_ID]: data.operation_id, [META_ACCESS_TOKEN]: oneShot };

H(`3. retry as a NEW request with _meta {operation_id: ${data.operation_id}, access_token: <one-shot>}`);
console.log(text(await client.callTool({ name: "transfer", arguments: args, _meta: retryMeta })));

H("4. same retry again -> stored result, no second debit");
console.log(text(await client.callTool({ name: "transfer", arguments: args, _meta: retryMeta })));

H("5. one-shot token on a non-payment call -> rejected");
try {
  await client.callTool({ name: "get_accounts", arguments: {}, _meta: { [META_ACCESS_TOKEN]: oneShot } });
} catch (e) {
  console.log(`rejected: ${(e as Error).message}`);
}

H("6. balances (session token)");
console.log(text(await client.callTool({ name: "get_accounts", arguments: {} })));
await client.close();
