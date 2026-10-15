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
 *
 * If the user declines (or the remediation is impossible) the tools/call is answered with a
 * synthesized CallToolResult { isError: true } instead of surfacing a transport error: for the
 * model, "the user said no" is a tool outcome, not a protocol failure, and must not invite a retry.
 *
 * In-band binding (JSON-RPC error -32043, see inband.ts): the retry is a new request that names
 * the operation in _meta; `oauth.armOneShot()` makes this wrapper attach the one-shot token to
 * exactly that request.
 */
import type { FetchLike } from "@modelcontextprotocol/sdk/shared/transport.js";
import { AuthorizationDenied, parseBearerChallenge, type OAuthSession } from "./oauth.ts";
import { log } from "./log.ts";

const MAX_SESSION_CHALLENGES = 2;

function parseBody(init?: RequestInit): any {
  try {
    return JSON.parse(String(init?.body));
  } catch {
    return undefined;
  }
}

/** A JSON-RPC response carrying a tool-level error, for a tools/call the client gives up on. */
function declinedToolResult(init: RequestInit | undefined, reason: string): Response | undefined {
  const m = parseBody(init);
  if (m?.method !== "tools/call" || m.id === undefined) return undefined;
  const body = {
    jsonrpc: "2.0",
    id: m.id,
    result: {
      content: [{ type: "text", text: `${reason} Nothing was executed. Do not retry unless the user asks again.` }],
      isError: true,
      _meta: { "lab.stepup/authorization": "declined" },
    },
  };
  log.oauth(`answering tools/call#${m.id} locally with isError=true (${reason})`);
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
}

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
      // In-band retry: a one-shot token armed for the operation this request names in _meta.
      oneShotToken ??= attempt === 0 ? oauth.takeArmedOneShot(parseBody(init)?.params?._meta?.["lab.stepup/operation_id"]) : undefined;
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
          return declinedToolResult(init, "Authorization was obtained but the server still refused this operation.") ?? res;
        }
        remediated = true;
        try {
          oneShotToken = await oauth.authorizeOperation(ch);
        } catch (e) {
          const denied = e instanceof AuthorizationDenied;
          log.oauth(denied ? `user denied the operation: ${e.message}` : `remediation failed: ${(e as Error).message}`);
          return (
            declinedToolResult(
              init,
              denied ? "The user declined to authorize this operation." : `The operation could not be authorized (${(e as Error).message}).`,
            ) ?? res
          );
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
