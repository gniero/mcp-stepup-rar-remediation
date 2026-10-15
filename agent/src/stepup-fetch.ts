/**
 * The client half of the proposal: a fetch wrapper handed to the MCP transport.
 *
 * Any MCP HTTP request (initialize, tools/call, ...) that comes back with a Bearer challenge
 * is *held*: the wrapper runs the OAuth flow the challenge asks for, then replays the very
 * same HTTP request (same JSON-RPC id, same Mcp-Session-Id). The MCP layer and the LLM only
 * ever see the final response.
 *
 *  - 401 (no error / invalid_token) or 403 insufficient_scope
 *      -> (re)obtain the SESSION token, replay, keep using it afterwards.
 *  - 401 insufficient_authorization + authorization_remediation (RAR remediation draft)
 *      -> obtain a ONE-SHOT token for exactly the remediation's authorization_details,
 *         replay this single request with it, discard it. The session token is untouched,
 *         so later requests (balances, other tools) keep using it.
 */
import type { FetchLike } from "@modelcontextprotocol/sdk/shared/transport.js";
import { AuthorizationDenied, parseBearerChallenge, type OAuthSession } from "./oauth.ts";
import { log } from "./log.ts";

const MAX_SESSION_CHALLENGES = 2;

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
    let sessionChallenges = 0;
    let oneShotToken: string | undefined; // only ever set for the single remediation replay
    let remediated = false;

    for (let attempt = 0; ; attempt++) {
      const headers = new Headers(init?.headers);
      const bearer = oneShotToken ?? oauth.token;
      if (bearer) headers.set("authorization", `Bearer ${bearer}`);
      const res = await fetch(url, { ...init, headers });
      log.http(
        `${init?.method ?? "GET"} ${what} -> ${res.status}` +
          `${attempt ? ` (replay #${attempt})` : ""}${oneShotToken ? " [one-shot token]" : ""}`,
      );
      oneShotToken = undefined; // one request, then gone

      if (res.status !== 401 && res.status !== 403) return res;
      const header = res.headers.get("www-authenticate");
      const ch = parseBearerChallenge(res.status, header);
      if (!ch) return res;

      // ---- RAR remediation: one-shot operation token ------------------------------
      if (res.status === 401 && ch.error === "insufficient_authorization") {
        // No authorization_reference => tokens are single-use, nothing to look up in a cache (§7.1 step 2).
        // After one fresh authorization, a second insufficient_authorization is non-remediable (§7.1 step 4, §7.3.3).
        if (remediated) {
          log.oauth("insufficient_authorization again after remediation -> giving up (no loop)");
          return res;
        }
        remediated = true;
        try {
          oneShotToken = await oauth.authorizeOperation(ch);
        } catch (e) {
          log.oauth(
            e instanceof AuthorizationDenied ? `user denied the operation: ${e.message}` : `remediation failed: ${(e as Error).message}`,
          );
          return res; // surface the original 401 to the MCP layer
        }
        continue; // replay with the one-shot token
      }

      // ---- Session token (baseline) ------------------------------------------------
      const sessionChallenge = res.status === 401 || ch.error === "insufficient_scope";
      if (!sessionChallenge || sessionChallenges >= MAX_SESSION_CHALLENGES || header === lastHeader) return res;
      lastHeader = header;
      sessionChallenges++;
      try {
        await oauth.authorize(ch);
      } catch (e) {
        if (e instanceof AuthorizationDenied) {
          log.oauth(`user denied: ${e.message}`);
          return res;
        }
        throw e;
      }
    }
  };
}
