import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { AuthInfo } from "@modelcontextprotocol/server";
import { config, prmUrl } from "./config.ts";

const jwks = createRemoteJWKSet(new URL(config.jwksUri));

export type AuthorizationDetail = { type: string; [k: string]: unknown };

export type Principal = AuthInfo & {
  sub: string;
  username?: string;
  jti?: string;
  /** RFC 9396 authorization_details carried by the token (if any). */
  authorizationDetails?: AuthorizationDetail[];
  /** True for a token that carries ONLY authorization_details (no baseline scope): a one-shot operation token. */
  oneShot: boolean;
};

export class AuthError extends Error {
  status: 401 | 403;
  wwwAuthenticate: string;
  constructor(status: 401 | 403, wwwAuthenticate: string, message: string) {
    super(message);
    this.status = status;
    this.wwwAuthenticate = wwwAuthenticate;
  }
}

const q = (s: string) => s.replace(/["\\]/g, "'");

/** Build an RFC 6750 §3 / RFC 9728 §5.1 Bearer challenge. */
export function bearerChallenge(params: {
  error?: "invalid_token" | "insufficient_scope" | "invalid_request";
  scope?: string[];
  description?: string;
}): string {
  const parts: string[] = [];
  if (params.error) parts.push(`error="${params.error}"`);
  if (params.description) parts.push(`error_description="${q(params.description)}"`);
  if (params.scope?.length) parts.push(`scope="${params.scope.join(" ")}"`);
  parts.push(`resource_metadata="${prmUrl}"`);
  return `Bearer ${parts.join(", ")}`;
}

/**
 * draft-ietf-oauth-rar-metadata-remediation §4: 401 + error="insufficient_authorization" with a
 * base64url-encoded JSON `authorization_remediation` built from the failed request.
 * No `authorization_reference`: tokens issued for these details are single-use (§4).
 * `resource_metadata` is added so the client can locate the AS (RFC 9728), as §7.1 allows.
 */
export function insufficientAuthorizationChallenge(authorizationDetails: AuthorizationDetail[], description: string) {
  const remediation = { authorization_details: authorizationDetails };
  const encoded = Buffer.from(JSON.stringify(remediation)).toString("base64url");
  return {
    remediation,
    header:
      `Bearer error="insufficient_authorization", error_description="${q(description)}", ` +
      `authorization_remediation=${encoded}, resource_metadata="${prmUrl}"`,
  };
}

/** Validate the bearer token on every HTTP request. */
export async function authenticate(authorization: string | undefined): Promise<Principal> {
  if (!authorization?.startsWith("Bearer ")) {
    throw new AuthError(401, bearerChallenge({ scope: [config.baseScope] }), "missing bearer token");
  }
  const token = authorization.slice(7).trim();
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, jwks, { issuer: config.issuer, audience: config.resource }));
  } catch (e) {
    throw new AuthError(
      401,
      bearerChallenge({ error: "invalid_token", description: (e as Error).message }),
      `invalid token: ${(e as Error).message}`,
    );
  }
  const scopes = String(payload.scope ?? "").split(" ").filter(Boolean);
  const details = Array.isArray(payload.authorization_details)
    ? (payload.authorization_details as AuthorizationDetail[])
    : undefined;
  const hasBase = scopes.includes(config.baseScope);
  if (!hasBase && !details?.length) {
    throw new AuthError(
      403,
      bearerChallenge({ error: "insufficient_scope", scope: [config.baseScope] }),
      "baseline scope missing",
    );
  }
  return {
    token,
    clientId: String(payload.client_id ?? payload.azp ?? "unknown"),
    scopes,
    expiresAt: payload.exp,
    resource: new URL(config.resource),
    sub: String(payload.sub),
    username: payload.preferred_username as string | undefined,
    jti: payload.jti,
    authorizationDetails: details,
    oneShot: !hasBase && Boolean(details?.length),
    extra: { claims: payload },
  };
}

/** RFC 9728 Protected Resource Metadata document. */
export function protectedResourceMetadata() {
  return {
    resource: config.resource,
    authorization_servers: [config.issuer],
    bearer_methods_supported: ["header"],
    // Only the baseline is advertised; per-operation authorization_details are discovered mid-interaction.
    scopes_supported: [config.baseScope],
    resource_name: "MCP Step-Up Lab (fake bank)",
  };
}
