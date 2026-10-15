/**
 * Transport-independent form of the mid-tool authorization challenge.
 *
 * The abstract outcome is "AUTHORIZATION REQUIRED for these authorization_details; nothing was
 * executed". Each transport carries it in its own way:
 *
 *  - Streamable HTTP, binding "http" (default): 401 + WWW-Authenticate insufficient_authorization
 *    (draft-ietf-oauth-rar-metadata-remediation). No JSON-RPC response exists for the request; the
 *    client replays the SAME request (same id) with the one-shot token. See index.ts.
 *  - Any transport, binding "inband" (and always over stdio): a JSON-RPC error response with code
 *    AUTHORIZATION_REQUIRED carrying the same remediation. The request IS answered, so the client
 *    retries as a NEW request that references the pending operation in `_meta`.
 *
 * Lab-defined protocol extension (not part of MCP today):
 *   error.code   = -32043  (next to -32042 URL elicitation required)
 *   error.data   = { error, error_description, authorization_remediation: {authorization_details},
 *                    resource_metadata, operation_id }
 *   request _meta "lab.stepup/operation_id"  -> resume this pending operation
 *   request _meta "lab.stepup/access_token"  -> one-shot token, ONLY on transports without an
 *                                               Authorization header (stdio)
 */
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { isJSONRPCRequest, type JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { prmUrl } from "./config.ts";
import { newRequestContext, requestContext, type Challenge } from "./stepup.ts";
import type { Principal } from "./auth.ts";

export const AUTHORIZATION_REQUIRED = -32043;
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

type InbandOptions = {
  /** Principal to use when the transport supplies none (stdio: the session token from the environment). */
  defaultAuth?: Principal;
  /** Validate a token passed in request `_meta` (stdio only). */
  authenticateMetaToken?: (token: string) => Promise<Principal>;
};

/**
 * Wrap a connected server transport so a challenge recorded by a tool is answered in-band: the
 * tool's (discarded) isError result is replaced by an AUTHORIZATION_REQUIRED JSON-RPC error.
 * Call AFTER `server.connect(transport)`.
 */
export function bindInband(transport: Transport, opts: InbandOptions = {}) {
  const ctxById = new Map<string | number, ReturnType<typeof newRequestContext>>();
  const onmessage = transport.onmessage!;
  const send = transport.send.bind(transport);

  transport.onmessage = (msg, extra) => {
    if (!isJSONRPCRequest(msg)) return onmessage(msg, extra);
    const ctx = newRequestContext();
    ctxById.set(msg.id, ctx);
    void (async () => {
      let authInfo = (extra?.authInfo as Principal | undefined) ?? opts.defaultAuth;
      const metaToken = (msg.params as any)?._meta?.[META_ACCESS_TOKEN];
      if (metaToken && opts.authenticateMetaToken) {
        try {
          if (msg.method !== "tools/call") throw new Error("a _meta access token is only accepted on tools/call");
          const p = await opts.authenticateMetaToken(metaToken);
          if (p.oneShot && !PAYMENT_TOOLS.has((msg.params as any)?.name))
            throw new Error("one-shot operation token can only be used for the operation it authorizes");
          if (opts.defaultAuth && p.sub !== opts.defaultAuth.sub) throw new Error("token subject does not match session");
          authInfo = p;
        } catch (e) {
          ctxById.delete(msg.id);
          await send({ jsonrpc: "2.0", id: msg.id, error: { code: -32001, message: `invalid _meta access token: ${(e as Error).message}` } } as JSONRPCMessage);
          return;
        }
      }
      requestContext.run(ctx, () => onmessage(msg, { ...extra, authInfo }));
    })();
  };

  transport.send = async (msg, options) => {
    const id = (msg as any).id;
    if (id !== undefined && ("result" in msg || "error" in msg) && ctxById.has(id)) {
      const ctx = ctxById.get(id)!;
      ctxById.delete(id);
      if (ctx.challenge) {
        console.error(`[inband] request ${id} -> AUTHORIZATION_REQUIRED (${ctx.challenge.reason})`);
        msg = authorizationRequiredError(id, ctx.challenge);
      }
    }
    return send(msg, options);
  };
}
