/**
 * Mid-interaction authorization for MCP tools, driven by the resource server.
 *
 * A tool handler runs, does its read-only business logic and only *then* finds out the
 * current token does not authorize the operation. It calls `requireAuthorizationDetails()`,
 * which records a challenge in the per-HTTP-request AsyncLocalStorage and aborts the handler.
 * The HTTP layer (index.ts) replaces the JSON-RPC response with
 *
 *   HTTP/1.1 401 Unauthorized
 *   WWW-Authenticate: Bearer error="insufficient_authorization", error_description="...",
 *                     authorization_remediation=<base64url({authorization_details:[...]})>
 *
 * (draft-ietf-oauth-rar-metadata-remediation).
 *
 * Contract (the "atomic challenge" rule): a 4xx means *nothing was done*. A tool may only
 * challenge BEFORE any side effect. Side effects go through `commit()`, and a challenge
 * after a commit is refused by the guard below.
 *
 * One-shot tokens: a token that authorizes an operation is consumed when the operation
 * commits (by `jti`); it can never authorize anything again.
 *
 * Needs JSON response mode (enableJsonResponse): with SSE the 200 status line is on the wire
 * before the tool runs.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import type { RequestHandlerExtra } from "@modelcontextprotocol/sdk/shared/protocol.js";
import type { ServerNotification, ServerRequest } from "@modelcontextprotocol/sdk/types.js";
import type { AuthorizationDetail, Principal } from "./auth.ts";

export type Challenge = { authorizationDetails: AuthorizationDetail[]; reason: string; operationId?: string };
type Ctx = { challenge?: Challenge; committed: string[] };

export const requestContext = new AsyncLocalStorage<Ctx>();
export const newRequestContext = (): Ctx => ({ committed: [] });

export type Extra = RequestHandlerExtra<ServerRequest, ServerNotification>;

export class AuthorizationRequired extends Error {
  challenge: Challenge;
  constructor(challenge: Challenge) {
    super(`authorization required: ${challenge.reason}`);
    this.challenge = challenge;
  }
}

/** Raised when a tool tries to challenge after it already changed state. */
export class ChallengeAfterCommit extends Error {}

/** jti of one-shot tokens already used to commit an operation. */
const consumedTokens = new Map<string, number>();

function ctx(): Ctx {
  const c = requestContext.getStore();
  if (!c) throw new Error("called outside an HTTP request context");
  return c;
}

/** Run a side effect and remember that this request is no longer "clean". */
export function commit<T>(label: string, fn: () => T): T {
  const result = fn();
  ctx().committed.push(label);
  return result;
}

const canon = (v: unknown): unknown =>
  v && typeof v === "object" && !Array.isArray(v)
    ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon((v as any)[k])]))
    : v;
export const sameDetail = (a: unknown, b: unknown) => JSON.stringify(canon(a)) === JSON.stringify(canon(b));

/**
 * Assert the caller's token carries authorization_details entries equal to every `required` one and
 * has not been consumed yet. Otherwise abort the tool and make the HTTP layer answer 401
 * insufficient_authorization with a remediation for exactly this operation.
 */
export function requireAuthorizationDetails(
  extra: Extra,
  required: AuthorizationDetail | AuthorizationDetail[],
  reason: string,
  operationId?: string,
): void {
  const p = extra.authInfo as Principal;
  const all = Array.isArray(required) ? required : [required];
  const granted = all.every((r) => p.authorizationDetails?.some((d) => sameDetail(d, r)) ?? false);
  const consumed = p.jti ? consumedTokens.has(p.jti) : false;
  if (granted && !consumed) return;
  if (granted && consumed) console.log(`[auth] token ${p.jti} already consumed (one-shot) -> new authorization needed`);

  const c = ctx();
  if (c.committed.length) {
    // Guard: a 4xx now would lie ("nothing happened") and the replay would redo work.
    console.log(`[guard] challenge refused, request already committed: ${c.committed.join(", ")}`);
    throw new ChallengeAfterCommit(
      `server guard: this operation needs additional authorization (${reason}) but these effects were ` +
        `already committed in the same request: ${c.committed.join("; ")}. Not retrying automatically.`,
    );
  }
  c.challenge = { authorizationDetails: all, reason, operationId };
  throw new AuthorizationRequired(c.challenge);
}

/** Burn the one-shot token used to authorize the operation that just committed. */
export function consumeToken(extra: Extra): void {
  const p = extra.authInfo as Principal;
  if (p.jti && p.oneShot) {
    consumedTokens.set(p.jti, Number(p.expiresAt ?? 0));
    console.log(`[auth] one-shot token ${p.jti} consumed`);
  }
}
