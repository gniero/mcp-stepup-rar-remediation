/**
 * Transport-independent form of the mid-tool authorization challenge.
 *
 * The abstract outcome is "AUTHORIZATION REQUIRED for these authorization_details; nothing was
 * executed". Each binding carries it in its own way:
 *
 *  - Streamable HTTP, binding "http": 401 + WWW-Authenticate insufficient_authorization
 *    (draft-ietf-oauth-rar-metadata-remediation). No JSON-RPC response exists for the request; the
 *    client replays the SAME request with the one-shot token. See index.ts.
 *  - Any transport, binding "inband" (and the stdio fallback): a JSON-RPC error response with code
 *    AUTHORIZATION_REQUIRED carrying the same remediation. The request IS answered, so the client
 *    retries as a NEW request that references the pending operation in `_meta`.
 *  - Any transport, binding "mrtr" (MCP 2026-07-28 Multi Round-Trip Requests): NOT an error. The
 *    tool returns `resultType: "input_required"` with a sealed `requestState` naming the operation
 *    and the remediation in `_meta["lab.stepup/authorization_required"]`; there are no
 *    `inputRequests` (MRTR has no input type for "obtain an access token"). The client gets the
 *    one-shot token and retries the call with the echoed `requestState`, the token in the
 *    Authorization header (stdio: `_meta["lab.stepup/access_token"]`).
 *
 * Negotiation (CHALLENGE_BINDING=negotiate, the default): the in-band forms are only understood by
 * clients that know this lab's extension, so the CLIENT discloses which ones it handles, per request
 * (MCP 2026-07-28 sends client capabilities in every request's _meta):
 *
 *   capabilities.extensions["lab.stepup/rar-remediation"] = { bindings: ["mrtr", "inband"] }
 *
 * in order of preference. The server answers with the first one its policy allows and advertises
 * that policy on server/discover (same extension key, `bindings` = what it offers). A client that
 * declares nothing, or nothing the server offers, gets the interoperable default: the 401 (stdio:
 * -32010, since stdio has no HTTP status). The extension declared without `bindings` means ["mrtr"].
 * Without negotiation a client that ignored the MRTR hint would just retry (the spec lets a client
 * retry a requestState-only result immediately) and loop until its round cap; one that does not
 * know -32010 would see an unexplained protocol error.
 *
 * Lab-defined protocol extension (not part of MCP):
 *   error.code   = -32010  (MCP 2026-07-28 reserves -32020..-32099 for the spec; -32000..-32019 is
 *                           implementation-defined, so a lab code lives there)
 *   error.data   = { error, error_description, authorization_remediation: {authorization_details},
 *                    resource_metadata, operation_id }
 *   request _meta "lab.stepup/operation_id"  -> resume this pending operation
 *   request _meta "lab.stepup/access_token"  -> one-shot token, ONLY on transports without an
 *                                               Authorization header (stdio)
 *   capabilities.extensions "lab.stepup/rar-remediation" {bindings} -> client: forms it handles, in
 *                                                    preference order; server: forms it offers
 *   result _meta "lab.stepup/authorization_required"  -> the MRTR authorization step (same data as
 *                                                        the -32010 error.data)
 */
import { isJSONRPCRequest, type JSONRPCMessage, type Transport } from "@modelcontextprotocol/server";
import { config, prmUrl } from "./config.ts";
import { newRequestContext, requestContext, type Challenge } from "./stepup.ts";
import type { Principal } from "./auth.ts";

export const AUTHORIZATION_REQUIRED = -32010;
/** Tools a one-shot operation token may be presented to. */
export const PAYMENT_TOOLS = new Set(["transfer", "naive_batch_transfer"]);
export const META_OPERATION_ID = "lab.stepup/operation_id";
export const META_ACCESS_TOKEN = "lab.stepup/access_token";
/** Extension a client declares (capabilities.extensions) to receive the MRTR authorization step. */
export const EXTENSION_ID = "lab.stepup/rar-remediation";
export const META_AUTHORIZATION_REQUIRED = "lab.stepup/authorization_required";

export type Binding = "http" | "inband" | "mrtr";
type NegotiableBinding = Exclude<Binding, "http">;

/** In-band forms this server offers to clients that negotiate (advertised on server/discover). */
export const OFFERED_BINDINGS: NegotiableBinding[] =
  config.challengeBinding === "negotiate" ? ["mrtr", "inband"] : config.challengeBinding === "mrtr" ? ["mrtr"] : [];

/** Forms the client declared in capabilities.extensions, in its preference order (undefined: none). */
export function declaredBindings(caps: { extensions?: Record<string, unknown> } | undefined): string[] | undefined {
  const ext = caps?.extensions?.[EXTENSION_ID] as { bindings?: unknown } | undefined;
  if (!ext) return undefined;
  return Array.isArray(ext.bindings) ? ext.bindings.filter((b): b is string => typeof b === "string") : ["mrtr"];
}

/**
 * How to answer "authorization required" for this request: the server policy, then the client's
 * declared preferences. "http" means the transport's own challenge (401; stdio: -32010).
 */
export function chooseBinding(caps: { extensions?: Record<string, unknown> } | undefined): { binding: Binding; why: string } {
  if (config.challengeBinding === "http") return { binding: "http", why: "server policy: http" };
  if (config.challengeBinding === "inband") return { binding: "inband", why: "server policy: inband" };
  const declared = declaredBindings(caps);
  if (!declared) return { binding: "http", why: `client did not declare ${EXTENSION_ID}` };
  const pick = declared.find((b): b is NegotiableBinding => (OFFERED_BINDINGS as string[]).includes(b));
  if (!pick) return { binding: "http", why: `client offers [${declared.join(", ")}], server offers [${OFFERED_BINDINGS.join(", ")}]` };
  return { binding: pick, why: `client prefers [${declared.join(", ")}], server offers [${OFFERED_BINDINGS.join(", ")}]` };
}

/** The remediation payload, shared by the -32010 error data and the MRTR `_meta` hint. */
export function authorizationRequiredData(ch: Challenge) {
  return {
    error: "insufficient_authorization",
    error_description: `Additional authorization is required: ${ch.reason}`,
    authorization_remediation: { authorization_details: ch.authorizationDetails },
    resource_metadata: prmUrl,
    operation_id: ch.operationId,
  };
}

export function authorizationRequiredError(id: string | number, ch: Challenge): JSONRPCMessage {
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code: AUTHORIZATION_REQUIRED,
      message: "Authorization required",
      data: authorizationRequiredData(ch),
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
