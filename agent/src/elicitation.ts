/**
 * Client-side form elicitation handler. The server uses it right before a step-up
 * challenge to show the user what is pending and get their intent, so the browser
 * redirect that follows is not a surprise.
 */
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { ElicitRequestSchema, type ElicitResult } from "@modelcontextprotocol/sdk/types.js";
import { log } from "./log.ts";

export type Ask = (question: string) => Promise<string>;

export function registerElicitation(client: Client, ask: Ask) {
  client.setRequestHandler(ElicitRequestSchema, async (req): Promise<ElicitResult> => {
    const p = req.params;
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
  });
}
