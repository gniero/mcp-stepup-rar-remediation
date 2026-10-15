/**
 * Client side of the IN-BAND binding: the server answered a tools/call with the JSON-RPC error
 * AUTHORIZATION_REQUIRED (-32043) instead of an HTTP 401 (CHALLENGE_BINDING=inband, or stdio).
 *
 * The request WAS answered, so it cannot be replayed with the same id. Instead:
 *   1. obtain a one-shot token for the remediation's authorization_details (same code path as the
 *      HTTP binding: OAuthSession.authorizeOperation),
 *   2. retry as a NEW tools/call that names the pending operation in
 *      _meta["lab.stepup/operation_id"], so the server resumes it (no second elicitation),
 *   3. the one-shot token travels in the Authorization header of exactly that request
 *      (stepUpFetch picks it up via oauth.takeArmedOneShot). Over stdio it would go in
 *      _meta["lab.stepup/access_token"] instead.
 * A second AUTHORIZATION_REQUIRED for the retry is final (no loop).
 */
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { McpError, type CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { RequestOptions } from "@modelcontextprotocol/sdk/shared/protocol.js";
import { AuthorizationDenied, type OAuthSession } from "./oauth.ts";
import { log } from "./log.ts";

export const AUTHORIZATION_REQUIRED = -32043;
export const META_OPERATION_ID = "lab.stepup/operation_id";

type CallParams = { name: string; arguments?: Record<string, unknown>; _meta?: Record<string, unknown> };

const declined = (reason: string): CallToolResult => ({
  content: [{ type: "text", text: `${reason} Nothing was executed. Do not retry unless the user asks again.` }],
  isError: true,
  _meta: { "lab.stepup/authorization": "declined" },
});

export async function callToolWithAuthorization(
  mcp: Client,
  oauth: OAuthSession,
  params: CallParams,
  options?: RequestOptions,
): Promise<CallToolResult> {
  try {
    return (await mcp.callTool(params, undefined, options)) as CallToolResult;
  } catch (e) {
    if (!(e instanceof McpError) || e.code !== AUTHORIZATION_REQUIRED) throw e;
    const d = (e.data ?? {}) as any;
    log.oauth(`in-band AUTHORIZATION_REQUIRED (-32043) for operation ${d.operation_id}`);
    let token: string;
    try {
      token = await oauth.authorizeOperation({
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
    oauth.armOneShot(token, d.operation_id);
    try {
      return (await mcp.callTool(
        { ...params, _meta: { ...(params._meta ?? {}), [META_OPERATION_ID]: d.operation_id } },
        undefined,
        options,
      )) as CallToolResult;
    } catch (e2) {
      if (e2 instanceof McpError && e2.code === AUTHORIZATION_REQUIRED)
        return declined("Authorization was obtained but the server still refused this operation.");
      throw e2;
    }
  }
}
