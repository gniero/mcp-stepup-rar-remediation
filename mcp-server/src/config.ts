const env = (k: string, d?: string): string => {
  const v = process.env[k] ?? d;
  if (v === undefined) throw new Error(`missing env ${k}`);
  return v;
};

export const config = {
  port: Number(env("PORT", "3000")),
  /** Canonical resource identifier of this MCP server (RFC 8707 / RFC 9728 `resource`). */
  resource: env("MCP_RESOURCE", "http://mcp-server:3000/mcp"),
  /** Issuer as it appears in tokens and in PRM `authorization_servers` (front-channel URL). */
  issuer: env("OIDC_ISSUER", "http://localhost:8080"),
  /** Where this container actually fetches the JWKS from (back-channel URL). */
  jwksUri: env("OIDC_JWKS_URI", "http://idp:8080/jwks"),
  baseScope: env("BASE_SCOPE", "mcp:basic"),
  /** RFC 9396 authorization details type every transfer must be authorized with. */
  paymentDetailsType: env("PAYMENT_DETAILS_TYPE", "money_transfer"),
  /** How long the server waits for the user to answer the pre-authorization elicitation. */
  elicitationTimeoutMs: Number(env("ELICITATION_TIMEOUT_MS", "120000")),
  /** Registers `naive_batch_transfer`, a deliberately badly-ordered tool that trips the commit guard (with new payees). */
  demoUnsafeTool: env("DEMO_UNSAFE_TOOL", "true") === "true",
  /**
   * Server POLICY for how a mid-tool authorization challenge is carried (see challenge.ts).
   * The three forms: "http" (401 insufficient_authorization; Streamable HTTP only), "inband"
   * (JSON-RPC error -32010), "mrtr" (a successful `input_required` result).
   *  - "negotiate" (default): the client picks. A client that declares the lab extension with
   *              {bindings: [...]} gets its first preference the server allows (mrtr, inband);
   *              any other client gets "http" (on stdio, which has no 401: "inband").
   *  - "mrtr":   negotiate, but only "mrtr" is offered.
   *  - "http":   always 401, no negotiation (stdio: "inband").
   *  - "inband": always -32010, no negotiation.
   */
  challengeBinding: env("CHALLENGE_BINDING", "negotiate") as "negotiate" | "http" | "inband" | "mrtr",
  /** Informational only (shown to the user): transfers above this amount are flagged as high value. */
  riskAmountThreshold: Number(env("RISK_AMOUNT_THRESHOLD", "500")),
};

const url = new URL(config.resource);
/** RFC 9728 §3.1: well-known URI is inserted between host and path of the resource. */
export const prmPath = `/.well-known/oauth-protected-resource${url.pathname === "/" ? "" : url.pathname}`;
export const prmUrl = `${url.origin}${prmPath}`;
