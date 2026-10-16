/**
 * MCP 2026-07-28 over Streamable HTTP: stateless (no initialize, no Mcp-Session-Id). Every POST is
 * a self-contained request: authenticate the bearer token, run the request through a per-request
 * McpServer (createMcpHandler), and, if a tool discovered it needs authorization for an operation,
 * replace the response with the binding's challenge.
 */
import { createServer } from "node:http";
import { getRequestListener } from "@hono/node-server";
import { createMcpHandler } from "@modelcontextprotocol/server";
import { config, prmPath } from "./config.ts";
import { AuthError, authenticate, bearerChallenge, insufficientAuthorizationChallenge, protectedResourceMetadata } from "./auth.ts";
import { newRequestContext, requestContext } from "./stepup.ts";
import { buildServer } from "./tools.ts";
import { PAYMENT_TOOLS, inbandHttpResponse } from "./challenge.ts";

const mcp = createMcpHandler(() => buildServer(), {
  // JSON mode: the status line is written only after the tool finishes,
  // so a tool can still turn the response into a 401 challenge.
  responseMode: "json",
  // Modern-only: 2025-era requests (initialize, no _meta envelope) get UnsupportedProtocolVersion.
  // The SDK's legacy stateless leg answers over SSE, which commits a 200 before the tool runs and
  // so could not carry the mid-tool 401 this lab is about.
  legacy: "reject",
  onerror: (e) => console.log(`[mcp] ${e.message}`),
});

/**
 * RFC 9457 problem details for HTTP-level auth failures. Deliberately NOT a JSON-RPC response:
 * a transport challenge means the JSON-RPC request has not been answered, so the client may
 * replay the same request (same id) once it holds an acceptable token.
 */
const problem = (status: 401 | 403, title: string, detail: string, extra: Record<string, unknown> = {}, headers: Record<string, string> = {}) =>
  new Response(
    JSON.stringify({
      type: "about:blank",
      title,
      status,
      detail,
      ...extra,
      note: "Transport-level challenge: no JSON-RPC response was produced for this request. Replay the same request with an acceptable token.",
    }),
    { status, headers: { "content-type": "application/problem+json", ...headers } },
  );

function describe(body: unknown): string {
  const msgs = Array.isArray(body) ? body : body ? [body] : [];
  return msgs.map((m: any) => (m.method === "tools/call" ? `tools/call:${m.params?.name}` : m.method ?? "response")).join(",");
}

async function handleMcp(req: Request): Promise<Response> {
  // ---- 1. Baseline authentication (every request) -------------------------
  let principal;
  try {
    principal = await authenticate(req.headers.get("authorization") ?? undefined);
  } catch (e) {
    if (e instanceof AuthError) {
      console.log(`[http] ${req.method} /mcp -> ${e.status} (${e.message})`);
      return problem(e.status, e.status === 401 ? "unauthorized" : "insufficient_scope", e.message, {}, {
        "www-authenticate": e.wwwAuthenticate,
      });
    }
    throw e;
  }

  const body = req.method === "POST" ? await req.clone().json().catch(() => undefined) : undefined;

  // A one-shot operation token (authorization_details only, no baseline scope) is good for
  // exactly one thing: the tool call that executes the operation it authorizes.
  if (principal.oneShot) {
    const isPaymentCall =
      req.method === "POST" && (body as any)?.method === "tools/call" && PAYMENT_TOOLS.has((body as any)?.params?.name);
    if (!isPaymentCall) {
      console.log(`[http] ${req.method} /mcp ${describe(body)} -> 403 (one-shot token used outside a payment call)`);
      const description = "one-shot operation token can only be used for the operation it authorizes";
      return problem(403, "insufficient_scope", description, {}, {
        "www-authenticate": bearerChallenge({ error: "insufficient_scope", scope: [config.baseScope], description }),
      });
    }
  }

  // ---- 2. Dispatch, with a per-request context (principal + challenge slot) the tools use ----
  const ctx = newRequestContext(principal);
  let res = await requestContext.run(ctx, () => mcp.fetch(req, { authInfo: principal, parsedBody: body }));

  // ---- 3a. In-band binding: the JSON-RPC result becomes AUTHORIZATION_REQUIRED (-32010), still 200
  if (ctx.challenge && config.challengeBinding === "inband") {
    console.log(`[http] POST /mcp ${describe(body)} -> 200 AUTHORIZATION_REQUIRED in-band (${ctx.challenge.reason})`);
    return inbandHttpResponse(res, ctx.challenge);
  }

  // ---- 3b. HTTP binding: replace the JSON-RPC result with
  //          401 insufficient_authorization + authorization_remediation (RAR remediation draft)
  if (ctx.challenge) {
    const { header, remediation } = insufficientAuthorizationChallenge(
      ctx.challenge.authorizationDetails,
      `Additional authorization is required: ${ctx.challenge.reason}`,
    );
    console.log(`[http] POST /mcp ${describe(body)} -> 401 insufficient_authorization (${ctx.challenge.reason})`);
    return problem(
      401,
      "insufficient_authorization",
      `Additional authorization is required: ${ctx.challenge.reason}`,
      // Non-normative convenience copy; the normative carrier is the WWW-Authenticate header.
      {
        type: "https://datatracker.ietf.org/doc/draft-ietf-oauth-rar-metadata-remediation/",
        authorization_remediation: remediation,
        operation_id: ctx.challenge.operationId,
      },
      { "www-authenticate": header },
    );
  }

  if (res.status >= 400) res = await logged(res);
  const who = principal.oneShot ? `one-shot token ${principal.jti}` : `scopes=[${principal.scopes.join(" ")}]`;
  console.log(`[http] ${req.method} /mcp ${describe(body)} -> ${res.status} ${who}`);
  return res;
}

/** Surface SDK-level rejections (bad headers, unsupported version, ...) in the server log. */
async function logged(res: Response): Promise<Response> {
  const text = await res.text();
  console.log(`[http] ${res.status} ${text.slice(0, 300)}`);
  return new Response(text, { status: res.status, headers: res.headers });
}

const mcpListener = getRequestListener(handleMcp);
const mcpPath = new URL(config.resource).pathname;

createServer((req, res) => {
  const path = (req.url ?? "/").split("?")[0];
  if (req.method === "GET" && (path === prmPath || path === "/.well-known/oauth-protected-resource")) {
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(protectedResourceMetadata(), null, 2));
    return;
  }
  if (path === "/healthz") return void res.writeHead(200).end("ok");
  if (path === mcpPath) return void mcpListener(req, res);
  res.writeHead(404).end();
}).listen(config.port, () => {
  console.log(
    `MCP server on :${config.port}${mcpPath}  resource=${config.resource}  issuer=${config.issuer}  challenge binding=${config.challengeBinding}`,
  );
});
