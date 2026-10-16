/**
 * Client-side form elicitation in the terminal. The server uses it right before a step-up
 * challenge to show the user what is pending and get their intent, so the browser
 * redirect that follows is not a surprise.
 *
 * MCP 2026-07-28: the server no longer sends elicitation/create as a request. It returns an
 * `input_required` result embedding it (MRTR); the call driver (call-tool.ts) hands each embedded
 * request to this handler and retries the call with the answer in `inputResponses`.
 */
import type { Client, ElicitRequest, ElicitResult } from "@modelcontextprotocol/client";
import { log } from "./log.ts";

export type Ask = (question: string) => Promise<string>;
export type ElicitationHandler = (params: ElicitRequest["params"]) => Promise<ElicitResult>;

export function elicitationHandler(ask: Ask): ElicitationHandler {
  return async (p) => {
    if (p.mode === "url") return { action: "decline" }; // not used in this lab
    log.elicit(`server asks:\n${p.message.replace(/^/gm, "   ")}`);

    const content: Record<string, string | number | boolean> = {};
    for (const [name, prop] of Object.entries(p.requestedSchema.properties) as [string, any][]) {
      const label = prop.title ?? name;
      if (prop.type === "boolean") {
        const a = (await ask(`   ${label}? [Y/n/c=cancel] `)).trim().toLowerCase();
        if (a === "c") return { action: "cancel" };
        content[name] = a === "" || a.startsWith("y") || a.startsWith("s");
      } else {
        const a = (await ask(`   ${label}${prop.default !== undefined ? ` [${prop.default}]` : ""}: `)).trim();
        const v = a === "" ? prop.default : a;
        content[name] = prop.type === "number" || prop.type === "integer" ? Number(v) : v;
      }
    }
    log.elicit(`answering accept ${JSON.stringify(content)}`);
    return { action: "accept", content };
  };
}

/** Also register it the standard way, for MRTR rounds on requests other than tools/call. */
export function registerElicitation(client: Client, handler: ElicitationHandler) {
  client.setRequestHandler("elicitation/create", (req) => handler(req.params));
}
