/**
 * Transport-independent form of the mid-tool authorization challenge.
 *
 * The abstract outcome is "AUTHORIZATION REQUIRED for these authorization_details; nothing was
 * executed". Each binding carries it in its own way:
 *
 *  - Streamable HTTP, binding "http" (default): 401 + WWW-Authenticate insufficient_authorization
 *    (draft-ietf-oauth-rar-metadata-remediation). No JSON-RPC response exists for the request; the
 *    client replays the SAME request with the one-shot token. See index.ts.
 *  - Any transport, binding "inband" (and always over stdio): a JSON-RPC error response with code
 *    AUTHORIZATION_REQUIRED carrying the same remediation. The request IS answered, so the client
 *    retries as a NEW request that references the pending operation in `_meta`.
 *
 * Lab-defined protocol extension (not part of MCP):
 *   error.code   = -32010  (MCP 2026-07-28 reserves -32020..-32099 for the spec; -32000..-32019 is
 *                           implementation-defined, so a lab code lives there)
 *   error.data   = { error, error_description, authorization_remediation: {authorization_details},
 *                    resource_metadata, operation_id }
 *   request _meta "lab.stepup/operation_id"  -> resume this pending operation
 *   request _meta "lab.stepup/access_token"  -> one-shot token, ONLY on transports without an
 *                                               Authorization header (stdio)
 */
import { isJSONRPCRequest, type JSONRPCMessage, type Transport } from "@modelcontextprotocol/server";
import { prmUrl } from "./config.ts";
import { newRequestContext, requestContext, type Challenge } from "./stepup.ts";
import type { Principal } from "./auth.ts";

export const AUTHORIZATION_REQUIRED = -32010;
/** Tools a one-shot operation token may be presented to. */
export const PAYMENT_TOOLS = new Set(["transfer", "naive_batch_transfer"]);
export const META_OPERATION_ID = "lab.stepup/operation_id";
export const META_ACCESS_TOKEN = "lab.stepup/access_token";

export function authorizationRequiredError(id: string | number, ch: Challenge): JSONRPCMessage {
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code: AUTHORIZATION_REQUIRED,
      message: "Authorization required",
      data: {
        error: "insufficient_authorization",
        error_description: `Additional authorization is required: ${ch.reason}`,
        authorization_remediation: { authorization_details: ch.authorizationDetails },
        resource_metadata: prmUrl,
        operation_id: ch.operationId,
      },
    },
  } as JSONRPCMessage;
}

/**
 * Streamable HTTP, binding "inband": the tool's (discarded) isError result in a JSON-mode
 * response is replaced by the AUTHORIZATION_REQUIRED JSON-RPC error, still inside a 200.
 */
export async function inbandHttpResponse(res: Response, ch: Challenge): Promise<Response> {
  const body = await res.json();
  const headers = new Headers(res.headers);
  headers.delete("content-length");
  return new Response(JSON.stringify(authorizationRequiredError(body.id, ch)), { status: 200, headers });
}

type StdioOptions = {
  /** Principal for requests that carry no token of their own (the session token from the environment). */
  defaultAuth: Principal;
  /** Validate a token passed in request `_meta`. */
  authenticateMetaToken: (token: string) => Promise<Principal>;
};

/**
 * stdio: a Transport wrapper handed to `serveStdio` (which owns era negotiation and the pinned
 * server instance). Every inbound request runs in a request context (principal = environment
 * token, or a one-shot token from `_meta` on a payment tools/call), and a challenge recorded by a
 * tool is answered in-band with AUTHORIZATION_REQUIRED instead of the tool's result.
 */
export class StdioAuthTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: Transport["onmessage"];
  private ctxById = new Map<string | number, ReturnType<typeof newRequestContext>>();
  private inner: Transport;
  private opts: StdioOptions;

  constructor(inner: Transport, opts: StdioOptions) {
    this.inner = inner;
    this.opts = opts;
    inner.onclose = () => this.onclose?.();
    inner.onerror = (e) => this.onerror?.(e);
    inner.onmessage = (msg, extra) => void this.receive(msg, extra);
  }

  start() {
    return this.inner.start();
  }
  close() {
    return this.inner.close();
  }

  private async receive(msg: JSONRPCMessage, extra?: Parameters<NonNullable<Transport["onmessage"]>>[1]) {
    if (!isJSONRPCRequest(msg)) return this.onmessage?.(msg, extra);
    let authInfo = this.opts.defaultAuth;
    const metaToken = (msg.params as any)?._meta?.[META_ACCESS_TOKEN];
    if (metaToken) {
      try {
        if (msg.method !== "tools/call") throw new Error("a _meta access token is only accepted on tools/call");
        const p = await this.opts.authenticateMetaToken(metaToken);
        if (p.oneShot && !PAYMENT_TOOLS.has((msg.params as any)?.name))
          throw new Error("one-shot operation token can only be used for the operation it authorizes");
        if (p.sub !== this.opts.defaultAuth.sub) throw new Error("token subject does not match the server's user");
        authInfo = p;
      } catch (e) {
        await this.inner.send({ jsonrpc: "2.0", id: msg.id, error: { code: -32011, message: `invalid _meta access token: ${(e as Error).message}` } } as JSONRPCMessage);
        return;
      }
    }
    const ctx = newRequestContext(authInfo);
    this.ctxById.set(msg.id, ctx);
    requestContext.run(ctx, () => this.onmessage?.(msg, extra));
  }

  async send(msg: JSONRPCMessage, options?: Parameters<Transport["send"]>[1]) {
    const id = (msg as any).id;
    if (id !== undefined && ("result" in msg || "error" in msg) && this.ctxById.has(id)) {
      const ctx = this.ctxById.get(id)!;
      this.ctxById.delete(id);
      if (ctx.challenge) {
        console.error(`[inband] request ${id} -> AUTHORIZATION_REQUIRED (${ctx.challenge.reason})`);
        msg = authorizationRequiredError(id, ctx.challenge);
      }
    }
    return this.inner.send(msg, options);
  }
}
