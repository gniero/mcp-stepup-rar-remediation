/**
 * The client half of the proposal: a fetch wrapper handed to the MCP transport.
 *
 * Any MCP HTTP request (initialize, tools/call, ...) that comes back with a
 * Bearer challenge is *held*: the wrapper runs the OAuth flow the challenge
 * asks for, then replays the very same HTTP request (same JSON-RPC id, same
 * Mcp-Session-Id) with the new token. The MCP layer and the LLM only ever see
 * the final response; the step-up is transparent to them.
 *
 * Compare with the SDK's built-in authProvider path, where an interactive
 * redirect throws UnauthorizedError and the in-flight tool call fails.
 */
import type { FetchLike } from "@modelcontextprotocol/sdk/shared/transport.js";
import { AuthorizationDenied, parseBearerChallenge, type OAuthSession } from "./oauth.ts";
import { log } from "./log.ts";

const MAX_CHALLENGES_PER_REQUEST = 2;

function label(init?: RequestInit): string {
  try {
    const m = JSON.parse(String(init?.body));
    if (m.method === "tools/call") return `tools/call:${m.params.name}#${m.id}`;
    return m.method ?? `response#${m.id} (to a server request, e.g. elicitation)`;
  } catch {
    return init?.method === "DELETE" ? "session" : "sse-stream";
  }
}

export function stepUpFetch(oauth: OAuthSession): FetchLike {
  return async (url, init) => {
    const what = label(init);
    let lastHeader: string | null = null;

    for (let attempt = 0; ; attempt++) {
      const headers = new Headers(init?.headers);
      if (oauth.token) headers.set("authorization", `Bearer ${oauth.token}`);
      const res = await fetch(url, { ...init, headers });
      log.http(`${init?.method ?? "GET"} ${what} -> ${res.status}${attempt ? ` (replay #${attempt})` : ""}`);

      if (res.status !== 401 && res.status !== 403) return res;

      const header = res.headers.get("www-authenticate");
      const ch = parseBearerChallenge(res.status, header);
      const actionable = ch && (res.status === 401 || ch.error === "insufficient_scope");
      // Give up on: non-Bearer errors, too many rounds, or the same challenge right after satisfying it.
      if (!actionable || attempt >= MAX_CHALLENGES_PER_REQUEST || header === lastHeader) return res;
      lastHeader = header;

      try {
        await oauth.authorize(ch);
      } catch (e) {
        if (e instanceof AuthorizationDenied) {
          log.oauth(`user denied the step-up: ${e.message}`);
          return res; // surface the original 403 to the MCP layer
        }
        throw e;
      }
      // loop: replay the identical request with the new token
    }
  };
}
