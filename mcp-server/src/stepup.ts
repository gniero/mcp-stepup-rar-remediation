/**
 * Mid-interaction authorization for MCP tools, driven by the resource server.
 *
 * A tool handler runs, does its read-only business logic and only *then* finds out the
 * current token does not authorize the operation. It calls `requireAuthorizationDetails()`,
 * which records a challenge in the per-HTTP-request AsyncLocalStorage and aborts the handler.
 * The transport layer then replaces the JSON-RPC response with the binding's form of
 * "authorization required" (see challenge.ts), e.g. for the HTTP binding:
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
 * Binding + one-shot: the required authorization_details embed the operation id
 * (`instruction_id`), and the token's jti is consumed atomically when the operation is claimed for
 * execution, so a token executes exactly one operation, exactly once.
 *
 * Needs JSON response mode (createMcpHandler responseMode: "json"): with SSE the 200 status line
 * is on the wire before the tool runs.
 *
 * The per-request context also carries the authenticated principal, so tools read it the same
 * way over HTTP (bearer header) and stdio (environment token or `_meta` one-shot token).
 */
import { AsyncLocalStorage } from "node:async_hooks";
import type { AuthorizationDetail, Principal } from "./auth.ts";
import { setStatus, type Operation } from "./operations.ts";

export type Challenge = {
  authorizationDetails: AuthorizationDetail[];
  reason: string;
  operationId?: string;
  /** Transport form chosen for this request (see challenge.ts chooseBinding). Default "http". */
  binding?: "http" | "inband";
};
type Ctx = { principal: Principal; challenge?: Challenge; committed: string[] };

export const requestContext = new AsyncLocalStorage<Ctx>();
export const newRequestContext = (principal: Principal): Ctx => ({ principal, committed: [] });

export class AuthorizationRequired extends Error {
  challenge: Challenge;
  constructor(challenge: Challenge) {
    super(`authorization required: ${challenge.reason}`);
    this.challenge = challenge;
  }
}

/** Raised when a tool tries to challenge after it already changed state. */
export class ChallengeAfterCommit extends Error {}

/** jti of one-shot tokens -> the operation that consumed them. */
const consumedTokens = new Map<string, string>();

function ctx(): Ctx {
  const c = requestContext.getStore();
  if (!c) throw new Error("called outside a request context");
  return c;
}

/** The principal of the request being handled (validated token). */
export const principal = (): Principal => ctx().principal;

/** The tool answered the challenge itself (MRTR binding): the transport must not rewrite the response. */
export const clearChallenge = () => void (ctx().challenge = undefined);

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
 * Authorize `op` for execution and CLAIM it.
 *
 * Passes only if the caller's token carries authorization_details equal to every `required` one
 * (which embed `instruction_id = op.id`, so a token for another operation never matches) and the
 * token's jti has not been spent. On success, in one synchronous step and before any side effect:
 *   op.status := "executing", jti := consumed by op.id
 * so the token is spent on exactly this operation and the operation can only run once, regardless
 * of any `await` between here and the commit.
 *
 * Otherwise abort the tool and make the transport answer "authorization required" with a
 * remediation for exactly this operation (401 insufficient_authorization, or -32010 in-band).
 */
export function requireAuthorizationDetails(op: Operation<unknown>, required: AuthorizationDetail[], reason: string): void {
  const p = principal();
  const granted = required.every((r) => p.authorizationDetails?.some((d) => sameDetail(d, r)) ?? false);
  const spentOn = p.jti ? consumedTokens.get(p.jti) : undefined;

  if (granted && !spentOn && op.status === "awaiting_authorization") {
    consumedTokens.set(p.jti ?? `anon-${op.id}`, op.id);
    op.authorizedBy = p.jti;
    setStatus(op, "executing");
    console.log(`[auth] one-shot token ${p.jti} consumed by ${op.id}`);
    return;
  }
  if (granted && spentOn) console.log(`[auth] token ${p.jti} already spent on ${spentOn} -> new authorization needed`);

  const c = ctx();
  if (c.committed.length) {
    // Guard: a 4xx now would lie ("nothing happened") and the replay would redo work.
    console.log(`[guard] challenge refused, request already committed: ${c.committed.join(", ")}`);
    throw new ChallengeAfterCommit(
      `server guard: this operation needs additional authorization (${reason}) but these effects were ` +
        `already committed in the same request: ${c.committed.join("; ")}. Not retrying automatically.`,
    );
  }
  c.challenge = { authorizationDetails: required, reason, operationId: op.id };
  throw new AuthorizationRequired(c.challenge);
}
