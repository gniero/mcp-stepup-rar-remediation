/**
 * Mid-interaction step-up for MCP tools, without elicitation-as-authorization.
 *
 * A tool handler runs, does its (read-only) business logic and only *then*
 * finds out the current token is not enough. It calls `requireScopes()`, which
 * records a challenge in the per-HTTP-request AsyncLocalStorage and aborts the
 * handler. The HTTP layer (index.ts) replaces the JSON-RPC response with
 *
 *   HTTP/1.1 403 Forbidden
 *   WWW-Authenticate: Bearer error="insufficient_scope", scope="...", resource_metadata="..."
 *
 * Contract (the "atomic 403" rule): a 4xx means *nothing was done*. So a tool
 * may only challenge BEFORE any side effect. Side effects go through
 * `commit()`, and `requireScopes()` after a commit is refused by the guard
 * below: the tool gets a server error instead of a 403, and must report
 * partial progress in-band.
 *
 * Needs JSON response mode (enableJsonResponse): with SSE the 200 status line
 * is on the wire before the tool runs.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import type { RequestHandlerExtra } from "@modelcontextprotocol/sdk/shared/protocol.js";
import type { ServerNotification, ServerRequest } from "@modelcontextprotocol/sdk/types.js";
import { config } from "./config.ts";

export type Challenge = { scope: string[]; reason: string; operationId?: string };
type Ctx = { challenge?: Challenge; committed: string[] };

export const requestContext = new AsyncLocalStorage<Ctx>();
export const newRequestContext = (): Ctx => ({ committed: [] });

export type Extra = RequestHandlerExtra<ServerRequest, ServerNotification>;

export class StepUpRequired extends Error {
  challenge: Challenge;
  constructor(challenge: Challenge) {
    super(`step-up required: ${challenge.reason}`);
    this.challenge = challenge;
  }
}

/** Raised when a tool tries to step up after it already changed state. */
export class StepUpAfterCommit extends Error {}

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

/**
 * Assert the caller's token carries `needed` scopes. If not, abort the tool and
 * make the HTTP layer answer 403 insufficient_scope.
 */
export function requireScopes(
  extra: Extra,
  needed: string[],
  reason: string,
  operationId?: string,
): void {
  const have = new Set(extra.authInfo?.scopes ?? []);
  const missing = needed.filter((s) => !have.has(s));
  if (missing.length === 0) return;

  const c = ctx();
  if (c.committed.length) {
    // Guard: a 403 now would lie ("nothing happened") and the replay would redo work.
    console.log(`[guard] step-up refused, request already committed: ${c.committed.join(", ")}`);
    throw new StepUpAfterCommit(
      `server guard: this operation needs additional authorization (${reason}) but these effects were ` +
        `already committed in the same request: ${c.committed.join("; ")}. Not retrying automatically.`,
    );
  }

  // Ask for what we need on top of what the client holds, minus stale per-operation scopes.
  const keep = (extra.authInfo?.scopes ?? []).filter((s) => !s.startsWith(config.operationScopePrefix));
  const scope = [...new Set([...keep, ...needed])];
  c.challenge = { scope, reason, operationId };
  throw new StepUpRequired(c.challenge);
}
