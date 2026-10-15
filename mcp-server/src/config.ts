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
   * How a mid-tool authorization challenge is carried over Streamable HTTP:
   *  - "http":   401 + WWW-Authenticate insufficient_authorization (RAR remediation draft). Default.
   *  - "inband": JSON-RPC error AUTHORIZATION_REQUIRED (-32043) with the same remediation data,
   *              i.e. the transport-independent form (the only one available over stdio).
   */
  challengeBinding: env("CHALLENGE_BINDING", "http") as "http" | "inband",
  /** Informational only (shown to the user): transfers above this amount are flagged as high value. */
  riskAmountThreshold: Number(env("RISK_AMOUNT_THRESHOLD", "500")),
};

const url = new URL(config.resource);
/** RFC 9728 §3.1: well-known URI is inserted between host and path of the resource. */
export const prmPath = `/.well-known/oauth-protected-resource${url.pathname === "/" ? "" : url.pathname}`;
export const prmUrl = `${url.origin}${prmPath}`;
