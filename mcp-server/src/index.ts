import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { getRequestListener } from "@hono/node-server";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { config, prmPath } from "./config.ts";
import { AuthError, authenticate, bearerChallenge, insufficientAuthorizationChallenge, protectedResourceMetadata } from "./auth.ts";
import { newRequestContext, requestContext } from "./stepup.ts";
import { buildServer } from "./tools.ts";

const PAYMENT_TOOLS = new Set(["transfer", "naive_batch_transfer"]);

type Session = { transport: WebStandardStreamableHTTPServerTransport; sub: string };
const sessions = new Map<string, Session>();

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

const rpcError = (id: unknown, code: number, message: string, data?: unknown) => ({
  jsonrpc: "2.0",
  id: id ?? null,
  error: { code, message, ...(data ? { data } : {}) },
});

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
      return json(e.status, { error: e.message }, { "www-authenticate": e.wwwAuthenticate });
    }
    throw e;
  }

  const body = req.method === "POST" ? await req.json().catch(() => undefined) : undefined;
  const sessionId = req.headers.get("mcp-session-id");
  let session = sessionId ? sessions.get(sessionId) : undefined;

  if (sessionId && !session) return json(404, rpcError(null, -32001, "Session not found"));

  // A one-shot operation token (authorization_details only, no baseline scope) is good for
  // exactly one thing: the tool call that executes the operation it authorizes.
  if (principal.oneShot) {
    const isPaymentCall =
      req.method === "POST" && (body as any)?.method === "tools/call" && PAYMENT_TOOLS.has((body as any)?.params?.name);
    if (!isPaymentCall) {
      console.log(`[http] ${req.method} /mcp ${describe(body)} -> 403 (one-shot token used outside a payment call)`);
      return json(403, rpcError((body as any)?.id, -32003, "insufficient_scope"), {
        "www-authenticate": bearerChallenge({
          error: "insufficient_scope",
          scope: [config.baseScope],
          description: "one-shot operation token can only be used for the operation it authorizes",
        }),
      });
    }
  }

  // A stepped-up token must belong to the same user that opened the session.
  if (session && session.sub !== principal.sub) {
    return json(401, rpcError(null, -32001, "token subject does not match session"), {
      "www-authenticate": bearerChallenge({ error: "invalid_token", description: "subject mismatch for session" }),
    });
  }

  // ---- 2. New session on initialize --------------------------------------
  if (!session) {
    if (req.method !== "POST" || !isInitializeRequest(body)) {
      return json(400, rpcError(null, -32000, "Bad Request: no valid session ID"));
    }
    const sub = principal.sub;
    const transport: WebStandardStreamableHTTPServerTransport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      // JSON mode: status line is written only after the tool finishes,
      // so a tool can still turn the response into a 401 challenge.
      enableJsonResponse: true,
      onsessioninitialized: (id) => {
        sessions.set(id, { transport, sub });
        console.log(`[session] ${id} opened for sub=${sub} (${principal.username ?? "?"})`);
      },
    });
    transport.onclose = () => {
      if (transport.sessionId) sessions.delete(transport.sessionId);
    };
    await buildServer().connect(transport);
    session = { transport, sub };
  }

  // ---- 3. Dispatch, with a per-request context the tools can write to ------
  const ctx = newRequestContext();
  const res = await requestContext.run(ctx, () =>
    session.transport.handleRequest(req, { authInfo: principal, parsedBody: body }),
  );

  // ---- 4. Tool needs authorization for this operation: replace the JSON-RPC result with
  //         401 insufficient_authorization + authorization_remediation (RAR remediation draft)
  if (ctx.challenge) {
    const { header, remediation } = insufficientAuthorizationChallenge(
      ctx.challenge.authorizationDetails,
      `Additional authorization is required: ${ctx.challenge.reason}`,
    );
    console.log(`[http] POST /mcp ${describe(body)} -> 401 insufficient_authorization (${ctx.challenge.reason})`);
    return json(
      401,
      // Non-normative body: the draft carries the remediation in the header only. The JSON-RPC
      // error keeps the request id so clients that don't remediate still get a well-formed error.
      rpcError((body as any)?.id, -32001, "insufficient_authorization", {
        authorization_remediation: remediation,
        operation_id: ctx.challenge.operationId,
      }),
      { "www-authenticate": header },
    );
  }

  const who = principal.oneShot ? `one-shot token ${principal.jti}` : `scopes=[${principal.scopes.join(" ")}]`;
  console.log(`[http] ${req.method} /mcp ${describe(body)} -> ${res.status} ${who}`);
  return res;
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
  console.log(`MCP server on :${config.port}${mcpPath}  resource=${config.resource}  issuer=${config.issuer}`);
});
