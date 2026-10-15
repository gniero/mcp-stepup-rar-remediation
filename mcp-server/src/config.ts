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
  issuer: env("OIDC_ISSUER", "http://localhost:8080/realms/mcp"),
  /** Where this container actually fetches the JWKS from (back-channel URL). */
  jwksUri: env("OIDC_JWKS_URI", "http://keycloak:8080/realms/mcp/protocol/openid-connect/certs"),
  baseScope: env("BASE_SCOPE", "mcp:basic"),
  /** Parameterized scope prefix: `payment-op:<operation-id>` authorizes one pending operation. */
  operationScopePrefix: env("OPERATION_SCOPE_PREFIX", "payment-op:"),
  /** How long the server waits for the user to answer the pre-step-up elicitation. */
  elicitationTimeoutMs: Number(env("ELICITATION_TIMEOUT_MS", "120000")),
  /** Registers `naive_batch_transfer`, a deliberately badly-ordered tool that trips the commit guard. */
  demoUnsafeTool: env("DEMO_UNSAFE_TOOL", "true") === "true",
  /** Transfers above this amount (BRL) need per-operation authorization. */
  riskAmountThreshold: Number(env("RISK_AMOUNT_THRESHOLD", "500")),
};

const url = new URL(config.resource);
/** RFC 9728 §3.1: well-known URI is inserted between host and path of the resource. */
export const prmPath = `/.well-known/oauth-protected-resource${url.pathname === "/" ? "" : url.pathname}`;
export const prmUrl = `${url.origin}${prmPath}`;
