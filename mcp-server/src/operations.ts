/**
 * Pending-operation store: the server-side checkpoint that makes "challenge + retry" safe.
 *
 * - Keyed by (MCP session, JSON-RPC request id), which the client reuses on an HTTP-level replay,
 *   and by operation id, which the client sends back in `_meta` on an in-band retry. Either way the
 *   retry resumes the operation instead of starting it over.
 * - The operation's authorization_details (RFC 9396) are what the one-shot token must carry.
 * - Completed operations keep their result, so a duplicate replay returns the stored
 *   result instead of executing twice (idempotency).
 */
import { createHash, randomBytes } from "node:crypto";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

export type OpStatus = "awaiting_confirmation" | "awaiting_authorization" | "completed" | "cancelled" | "failed";

export type Operation<C = unknown> = {
  id: string;
  sub: string;
  requestKey: string;
  tool: string;
  argsHash: string;
  summary: string;
  status: OpStatus;
  checkpoint: C;
  result?: CallToolResult;
  createdAt: number;
  expiresAt: number;
};

const TTL_MS = 10 * 60_000;
const byId = new Map<string, Operation>();
const byRequest = new Map<string, string>();

export const requestKey = (sessionId: string | undefined, requestId: string | number) => `${sessionId ?? "-"}:${requestId}`;

export function hashArgs(args: unknown): string {
  const canon = (v: any): any =>
    v && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])]))
      : v;
  return createHash("sha256").update(JSON.stringify(canon(args))).digest("base64url");
}

export function findByRequest(key: string): Operation | undefined {
  const id = byRequest.get(key);
  return findById(id);
}

/** Explicit operation handle (in-band retries arrive as a NEW JSON-RPC request carrying it in _meta). */
export function findById(id: string | undefined): Operation | undefined {
  const op = id ? byId.get(id) : undefined;
  if (op && op.expiresAt < Date.now() && op.status !== "completed") {
    op.status = "failed";
  }
  return op;
}

export function createOperation<C>(o: Omit<Operation<C>, "id" | "status" | "createdAt" | "expiresAt">): Operation<C> {
  const op: Operation<C> = {
    ...o,
    id: `op_${randomBytes(9).toString("base64url")}`,
    status: "awaiting_confirmation",
    createdAt: Date.now(),
    expiresAt: Date.now() + TTL_MS,
  };
  byId.set(op.id, op);
  byRequest.set(o.requestKey, op.id);
  return op;
}

export function setStatus(op: Operation, status: OpStatus, result?: CallToolResult) {
  op.status = status;
  if (result) op.result = result;
  console.log(`[op] ${op.id} -> ${status}  (${op.summary})`);
}
