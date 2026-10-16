/**
 * The LLM side of the agent, behind one small interface so the model can be swapped without
 * touching the MCP / OAuth code (which is where everything interesting about this lab lives).
 *
 *   LLM_PROVIDER=anthropic   Claude via the Anthropic API (ANTHROPIC_API_KEY)
 *   LLM_PROVIDER=openai      any OpenAI-compatible /v1/chat/completions endpoint with tool calling:
 *                            Ollama, LM Studio, llama.cpp server, vLLM, ... (OPENAI_BASE_URL)
 */
import Anthropic from "@anthropic-ai/sdk";
import type { Tool } from "@modelcontextprotocol/client";
import { log } from "./log.ts";

export type ToolOutcome = { text: string; isError: boolean };
export type CallTool = (name: string, args: Record<string, unknown>) => Promise<ToolOutcome>;
export type Chat = { describe: string; turn: (userText: string) => Promise<void> };

export const SYSTEM_PROMPT =
  "You are a banking assistant for a Brazilian user. Use the tools to act. " +
  "Amounts are in BRL. Be brief. If a tool fails, explain the failure to the user. " +
  "If the user declined an authorization, do not retry that operation unless they ask again. " +
  "Call each tool at most once per user request unless the user asks for more.";

/** Max model round-trips per user message (small local models can loop on tool calls). */
const MAX_STEPS = Number(process.env.LLM_MAX_STEPS ?? "8");

const say = (text: string) => {
  const clean = text.replace(/<think>[\s\S]*?<\/think>/g, "").trim(); // reasoning models (e.g. Llama 3.2)
  if (clean) console.log(`\nassistant> ${clean}\n`);
};

export function createChat(tools: Tool[], callTool: CallTool): Chat {
  const provider = (process.env.LLM_PROVIDER ?? "anthropic").toLowerCase();
  if (provider === "anthropic") return anthropicChat(tools, callTool);
  if (provider === "openai") return openAiCompatibleChat(tools, callTool);
  throw new Error(`unknown LLM_PROVIDER "${provider}" (use "anthropic" or "openai")`);
}

// ---- Anthropic (Claude) --------------------------------------------------------------

function anthropicChat(tools: Tool[], callTool: CallTool): Chat {
  const model = process.env.LLM_MODEL || process.env.ANTHROPIC_MODEL || "claude-sonnet-4-6";
  const anthropic = new Anthropic();
  const llmTools: Anthropic.Tool[] = tools.map((t) => ({
    name: t.name,
    description: t.description ?? "",
    input_schema: t.inputSchema as Anthropic.Tool.InputSchema,
  }));
  const messages: Anthropic.MessageParam[] = [];

  return {
    describe: `anthropic / ${model}`,
    async turn(userText) {
      messages.push({ role: "user", content: userText });
      for (let step = 0; step < MAX_STEPS; step++) {
        const resp = await anthropic.messages.create({ model, max_tokens: 1024, system: SYSTEM_PROMPT, tools: llmTools, messages });
        messages.push({ role: "assistant", content: resp.content });
        for (const b of resp.content) if (b.type === "text") say(b.text);
        if (resp.stop_reason !== "tool_use") return;

        const results: Anthropic.ToolResultBlockParam[] = [];
        for (const b of resp.content) {
          if (b.type !== "tool_use") continue;
          const r = await callTool(b.name, b.input as Record<string, unknown>);
          results.push({ type: "tool_result", tool_use_id: b.id, content: r.text, is_error: r.isError });
        }
        messages.push({ role: "user", content: results });
      }
      log.tool(`stopped after ${MAX_STEPS} model steps`);
    },
  };
}

// ---- OpenAI-compatible (local models) ---------------------------------------------------

type OAIMessage =
  | { role: "system" | "user"; content: string }
  | { role: "assistant"; content: string | null; tool_calls?: OAIToolCall[] }
  | { role: "tool"; tool_call_id: string; content: string };
type OAIToolCall = { id: string; type: "function"; function: { name: string; arguments: string } };

function openAiCompatibleChat(tools: Tool[], callTool: CallTool): Chat {
  const baseUrl = (process.env.OPENAI_BASE_URL ?? "http://host.docker.internal:11434/v1").replace(/\/$/, "");
  const model = process.env.LLM_MODEL || "llama3.2:1b";
  const apiKey = process.env.OPENAI_API_KEY ?? "local"; // Ollama / LM Studio ignore it
  const temperature = Number(process.env.LLM_TEMPERATURE ?? "0.2");
  const byName = new Map(tools.map((t) => [t.name, t]));
  const oaiTools = tools.map((t) => ({
    type: "function" as const,
    // Drop "$schema": some local servers' grammar converters choke on it.
    function: { name: t.name, description: t.description ?? "", parameters: (({ $schema, ...rest }) => rest)(t.inputSchema as any) },
  }));
  const messages: OAIMessage[] = [{ role: "system", content: SYSTEM_PROMPT }];

  async function complete(): Promise<{ content: string | null; tool_calls?: OAIToolCall[] }> {
    const r = await fetch(`${baseUrl}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ model, messages, tools: oaiTools, tool_choice: "auto", temperature, stream: false }),
    });
    if (!r.ok) throw new Error(`LLM ${baseUrl} -> ${r.status} ${await r.text()}`);
    const j = await r.json();
    return j.choices?.[0]?.message ?? { content: "" };
  }

  return {
    describe: `openai-compatible / ${model} @ ${baseUrl}`,
    async turn(userText) {
      messages.push({ role: "user", content: userText });
      for (let step = 0; step < MAX_STEPS; step++) {
        const msg = await complete();
        const calls = msg.tool_calls ?? [];
        messages.push({ role: "assistant", content: msg.content ?? null, ...(calls.length ? { tool_calls: calls } : {}) });
        if (msg.content) say(msg.content);
        if (!calls.length) return;

        for (const [i, c] of calls.entries()) {
          const id = c.id || `call_${step}_${i}`;
          let out: ToolOutcome;
          const tool = byName.get(c.function.name);
          if (!tool) {
            out = { text: `Unknown tool "${c.function.name}". Available: ${[...byName.keys()].join(", ")}`, isError: true };
          } else {
            const args = parseArgs(c.function.arguments);
            out = args.ok
              ? await callTool(tool.name, coerceToSchema(args.value, tool.inputSchema))
              : { text: `Invalid JSON arguments for ${tool.name}: ${args.error}. Call it again with valid JSON.`, isError: true };
          }
          messages.push({ role: "tool", tool_call_id: id, content: out.isError ? `ERROR: ${out.text}` : out.text });
        }
      }
      log.tool(`stopped after ${MAX_STEPS} model steps`);
    },
  };
}

function parseArgs(raw: unknown): { ok: true; value: Record<string, unknown> } | { ok: false; error: string } {
  if (raw && typeof raw === "object") return { ok: true, value: raw as Record<string, unknown> }; // some servers send objects
  try {
    const v = JSON.parse(String(raw || "{}"));
    return v && typeof v === "object" ? { ok: true, value: v } : { ok: false, error: "not an object" };
  } catch (e) {
    return { ok: false, error: (e as Error).message };
  }
}

/**
 * Small models often send `"800"` for a number or `"R$ 800,00"`. Coerce top-level primitives to the
 * JSON Schema type; anything still wrong is rejected by the server's own validation (zod), so this
 * only improves the hit rate, it never bypasses a check.
 */
export function coerceToSchema(args: Record<string, unknown>, schema: Tool["inputSchema"]): Record<string, unknown> {
  const props = (schema.properties ?? {}) as Record<string, { type?: string }>;
  const out: Record<string, unknown> = { ...args };
  for (const [k, v] of Object.entries(out)) {
    const t = props[k]?.type;
    if ((t === "number" || t === "integer") && typeof v === "string") {
      const n = Number(v.replace(/[^\d,.-]/g, "").replace(/\.(?=\d{3}(\D|$))/g, "").replace(",", "."));
      if (!Number.isNaN(n)) out[k] = n;
    } else if (t === "boolean" && typeof v === "string") {
      out[k] = v.toLowerCase() === "true";
    }
  }
  return out;
}
