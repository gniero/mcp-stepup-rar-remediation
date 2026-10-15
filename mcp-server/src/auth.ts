import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { config, prmUrl } from "./config.ts";

const jwks = createRemoteJWKSet(new URL(config.jwksUri));

export type Principal = AuthInfo & { sub: string; username?: string };

export class AuthError extends Error {
  status: 401 | 403;
  wwwAuthenticate: string;
  constructor(status: 401 | 403, wwwAuthenticate: string, message: string) {
    super(message);
    this.status = status;
    this.wwwAuthenticate = wwwAuthenticate;
  }
}

/** Build an RFC 6750 §3 / RFC 9728 §5.1 Bearer challenge. */
export function bearerChallenge(params: {
  error?: "invalid_token" | "insufficient_scope" | "invalid_request";
  scope?: string[];
  description?: string;
}): string {
  const parts = [`resource_metadata="${prmUrl}"`];
  if (params.error) parts.unshift(`error="${params.error}"`);
  if (params.scope?.length) parts.push(`scope="${params.scope.join(" ")}"`);
  if (params.description) parts.push(`error_description="${params.description.replace(/"/g, "'")}"`);
  return `Bearer ${parts.join(", ")}`;
}

/** Validate the bearer token on every HTTP request (baseline access only). */
export async function authenticate(authorization: string | undefined): Promise<Principal> {
  if (!authorization?.startsWith("Bearer ")) {
    // No token at all: plain challenge, no error code (RFC 6750 §3.1).
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
  if (!scopes.includes(config.baseScope)) {
    throw new AuthError(
      403,
      bearerChallenge({ error: "insufficient_scope", scope: [config.baseScope] }),
      "baseline scope missing",
    );
  }
  return {
    token,
    clientId: String(payload.azp ?? payload.client_id ?? "unknown"),
    scopes,
    expiresAt: payload.exp,
    resource: new URL(config.resource),
    sub: String(payload.sub),
    username: payload.preferred_username as string | undefined,
    extra: { claims: payload },
  };
}

/** RFC 9728 Protected Resource Metadata document. */
export function protectedResourceMetadata() {
  return {
    resource: config.resource,
    authorization_servers: [config.issuer],
    bearer_methods_supported: ["header"],
    // Only the baseline is advertised on purpose: per-operation scopes are discovered mid-interaction.
    scopes_supported: [config.baseScope],
    resource_name: "MCP Step-Up Lab (fake bank)",
  };
}
