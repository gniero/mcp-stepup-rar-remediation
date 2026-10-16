/**
 * The tool-call driver: every MCP tools/call from the LLM loop goes through
 * callToolWithAuthorization(), which handles the two NON-transport forms of "this operation
 * needs its own authorization". (The HTTP 401 form never reaches this layer: stepUpFetch holds
 * and replays the request below the SDK.)
 *
 * 1. MRTR binding (MCP 2026-07-28 Multi Round-Trip Requests, CHALLENGE_BINDING=mrtr): the call
 *    returns a SUCCESSFUL result with `resultType: "input_required"`. This driver runs in the SDK's
 *    manual mode (`allowInputRequired: true`), so it sees every round:
 *     - `inputRequests` (the pre-authorization confirmation): answered with the elicitation
 *       handler, then the call is retried with `inputResponses` + the echoed `requestState`;
 *     - `_meta["lab.stepup/authorization_required"]` (lab extension, declared by this client in
 *       capabilities.extensions): obtain a one-shot token for exactly those authorization_details
 *       and retry with the echoed `requestState`; stepUpFetch puts the token in the Authorization
 *       header of exactly that retry (it matches the requestState).
 *    A second authorization step after a fresh token is final (no loop).
 *
 * 2. In-band binding (CHALLENGE_BINDING=inband, or stdio): the call FAILS with the JSON-RPC error
 *    AUTHORIZATION_REQUIRED (-32010). The request was answered, so it is retried as a NEW tools/call
 *    that names the operation in _meta["lab.stepup/operation_id"].
 *
 * In every binding a refusal (or an impossible remediation) becomes a CallToolResult with
 * isError: true, so the model sees a tool outcome and is told not to retry.
 */
import {
  ProtocolError,
  isInputRequiredResult,
  type CallToolResult,
  type Client,
  type ElicitRequest,
  type InputRequiredResult,
  type RequestOptions,
} from "@modelcontextprotocol/client";
import { AuthorizationDenied, type OAuthSession } from "./oauth.ts";
import type { ElicitationHandler } from "./elicitation.ts";
import { log } from "./log.ts";

/** Lab-defined code, in the implementation-defined range (-32000..-32019) of MCP 2026-07-28. */
export const AUTHORIZATION_REQUIRED = -32010;
export const META_OPERATION_ID = "lab.stepup/operation_id";
/** Lab extension: declared in capabilities.extensions; the server then uses the MRTR binding. */
export const EXTENSION_ID = "lab.stepup/rar-remediation";
export const META_AUTHORIZATION_REQUIRED = "lab.stepup/authorization_required";
const MAX_ROUNDS = 5;

type CallParams = {
  name: string;
  arguments?: Record<string, unknown>;
  _meta?: Record<string, unknown>;
  inputResponses?: Record<string, unknown>;
  requestState?: string;
};
type AuthorizationData = {
  error?: string;
  error_description?: string;
  authorization_remediation?: { authorization_details?: { type: string; [k: string]: unknown }[] };
  resource_metadata?: string;
  operation_id?: string;
};

const declined = (reason: string): CallToolResult => ({
  content: [{ type: "text", text: `${reason} Nothing was executed. Do not retry unless the user asks again.` }],
  isError: true,
  _meta: { "lab.stepup/authorization": "declined" },
});

export async function callToolWithAuthorization(
  mcp: Client,
  oauth: OAuthSession,
  elicit: ElicitationHandler,
  params: CallParams,
  options?: RequestOptions,
): Promise<CallToolResult> {
  let call: CallParams = params;
  let authorized = false; // one fresh authorization per tool call, then any further demand is final

  /** Obtain a one-shot token for the remediation, or a refusal result. */
  const authorize = async (d: AuthorizationData, via: string): Promise<string | CallToolResult> => {
    if (authorized) return declined("Authorization was obtained but the server still refused this operation.");
    authorized = true;
    log.oauth(`${via} for operation ${d.operation_id}`);
    try {
      return await oauth.authorizeOperation({
        status: 200,
        error: d.error,
        description: d.error_description,
        resourceMetadata: d.resource_metadata,
        remediation: d.authorization_remediation,
        raw: "",
      });
    } catch (err) {
      return declined(
        err instanceof AuthorizationDenied
          ? "The user declined to authorize this operation."
          : `The operation could not be authorized (${(err as Error).message}).`,
      );
    }
  };

  for (let round = 1; ; round++) {
    if (round > MAX_ROUNDS) return declined(`The server kept asking for input after ${MAX_ROUNDS} rounds.`);
    let r: CallToolResult | InputRequiredResult;
    try {
      // Manual MRTR mode: an input_required result comes back to us instead of being auto-fulfilled.
      r = (await mcp.callTool(call as any, { ...options, allowInputRequired: true } as any)) as CallToolResult | InputRequiredResult;
    } catch (e) {
      // ---- In-band binding: JSON-RPC error -32010 ----------------------------------------
      if (!(e instanceof ProtocolError) || e.code !== AUTHORIZATION_REQUIRED) throw e;
      const d = (e.data ?? {}) as AuthorizationData;
      const token = await authorize(d, `in-band AUTHORIZATION_REQUIRED (${AUTHORIZATION_REQUIRED})`);
      if (typeof token !== "string") return token;
      oauth.armOneShot(token, { operationId: d.operation_id });
      call = { ...params, _meta: { ...(params._meta ?? {}), [META_OPERATION_ID]: d.operation_id } };
      continue;
    }
    if (!isInputRequiredResult(r)) return r as CallToolResult;

    // ---- MRTR: a successful, non-final result -----------------------------------------
    const hint = (r._meta as Record<string, unknown> | undefined)?.[META_AUTHORIZATION_REQUIRED] as AuthorizationData | undefined;
    if (hint) {
      const token = await authorize(hint, `MRTR input_required: authorization step (round ${round})`);
      if (typeof token !== "string") return token;
      oauth.armOneShot(token, { requestState: r.requestState });
      call = { ...params, ...(r.requestState ? { requestState: r.requestState } : {}) };
      continue;
    }
    const requests = Object.entries(r.inputRequests ?? {});
    log.tool(`MRTR input_required (round ${round}): ${requests.map(([k, q]) => `${k}=${(q as any).method}`).join(", ") || "requestState only"}`);
    const inputResponses: Record<string, unknown> = {};
    for (const [key, req] of requests) {
      if ((req as any).method !== "elicitation/create") throw new Error(`unsupported embedded request ${(req as any).method}`);
      inputResponses[key] = await elicit((req as ElicitRequest).params);
    }
    call = {
      ...params,
      ...(requests.length ? { inputResponses } : {}),
      ...(r.requestState ? { requestState: r.requestState } : {}),
    };
  }
}
