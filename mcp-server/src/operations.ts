/**
 * Pending-operation store: the server-side state that makes "challenge + retry" safe AND binds
 * every authorization to exactly one operation instance.
 *
 * Binding: the operation id is placed in the authorization_details the client must obtain
 * (`instruction_id`). A one-shot token can therefore only ever execute the operation it names.
 *
 * Lookup order when a call arrives (first match wins):
 *   1. the operation named by the token's authorization_details.instruction_id  (authoritative)
 *   2. the MRTR `requestState` (HMAC-sealed {op}) echoed on a multi-round-trip retry
 *   3. `_meta["lab.stepup/operation_id"]`  (in-band retry after -32010 AUTHORIZATION_REQUIRED)
 *   4. (sub, tool, idempotency_key)        (business-level dedupe across NEW requests)
 * There is no (session, request id) key any more: MCP 2026-07-28 has no sessions, and every
 * retry is a new JSON-RPC request with a new id.
 *
 * Lifecycle (one-way):
 *   awaiting_confirmation -> awaiting_authorization -> executing -> completed | failed
 *                        \-> cancelled
 * `executing` is entered atomically together with consuming the token's jti (see stepup.ts), so a
 * token is spent on one operation and an operation is executed once, independently of timing.
 * Completed operations keep their result: any later retry returns it (idempotency).
 */
import { createHash, randomBytes } from "node:crypto";
import type { CallToolResult } from "@modelcontextprotocol/server";

export type OpStatus =
  | "awaiting_confirmation"
  | "awaiting_authorization"
  | "executing"
  | "completed"
  | "cancelled"
  | "failed";

export type Operation<C = unknown> = {
  id: string;
  sub: string;
  clientId: string;
  tool: string;
  argsHash: string;
  idempotencyKey?: string;
  summary: string;
  status: OpStatus;
  checkpoint: C;
  result?: CallToolResult;
  /** jti of the one-shot token that authorized (and was consumed by) this operation. */
  authorizedBy?: string;
  createdAt: number;
  expiresAt: number;
};

/** Operation lifetime. Must be >= the one-shot token TTL so a valid token never meets an expired operation. */
const TTL_MS = 10 * 60_000;
const byId = new Map<string, Operation>();
const byIdempotencyKey = new Map<string, string>();

const idemKey = (sub: string, tool: string, key: string) => `${sub}\u0000${tool}\u0000${key}`;

export function hashArgs(args: unknown): string {
  const canon = (v: any): any =>
    v && typeof v === "object" && !Array.isArray(v)
      ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])]))
      : v;
  return createHash("sha256").update(JSON.stringify(canon(args))).digest("base64url");
}

export function findById(id: string | undefined): Operation | undefined {
  const op = id ? byId.get(id) : undefined;
  if (op && op.expiresAt < Date.now() && !["completed", "executing", "failed", "cancelled"].includes(op.status)) {
    setStatus(op, "failed");
  }
  return op;
}
export const findByIdempotencyKey = (sub: string, tool: string, key: string) =>
  findById(byIdempotencyKey.get(idemKey(sub, tool, key)));

/**
 * Hex ids (no "-" or "_" after the prefix) so batch item references `op_<hex>-<n>` are unambiguous.
 * `checkpoint` may be a function of the new id: the authorization_details embed it.
 */
export function createOperation<C>(
  o: Omit<Operation<C>, "id" | "status" | "createdAt" | "expiresAt" | "checkpoint"> & { checkpoint: (id: string) => C },
): Operation<C> {
  const id = `op_${randomBytes(8).toString("hex")}`;
  const op: Operation<C> = {
    ...o,
    id,
    checkpoint: o.checkpoint(id),
    status: "awaiting_confirmation",
    createdAt: Date.now(),
    expiresAt: Date.now() + TTL_MS,
  };
  byId.set(id, op);
  if (o.idempotencyKey) byIdempotencyKey.set(idemKey(o.sub, o.tool, o.idempotencyKey), id);
  return op;
}

export function setStatus(op: Operation, status: OpStatus, result?: CallToolResult) {
  op.status = status;
  if (result) op.result = result;
  console.log(`[op] ${op.id} -> ${status}  (${op.summary})`);
}

/** instruction_id of a single transfer, or of item n (1-based) of a batch. */
export const instructionId = (opId: string, item?: number) => (item ? `${opId}-${item}` : opId);
/** Operation ids referenced by authorization_details (batch item suffixes stripped). */
export function operationIdsIn(details: { instruction_id?: unknown }[] | undefined): string[] {
  const ids = (details ?? [])
    .map((d) => (typeof d.instruction_id === "string" ? d.instruction_id.replace(/-\d+$/, "") : undefined))
    .filter((x): x is string => Boolean(x));
  return [...new Set(ids)];
}
