/**
 * MRTR `requestState` (MCP 2026-07-28, SEP-2322): opaque, server-minted state the client echoes
 * back verbatim when it retries a call after an `input_required` result.
 *
 * Here it carries the pending operation id across rounds (it replaces the old
 * (session, request id) lookup: there are no sessions, and each retry has a new request id).
 * It is attacker-controlled input on re-entry, so it is HMAC-sealed, expires, and is bound to
 * the authenticated user (spec MUST for state that influences authorization).
 */
import { randomBytes } from "node:crypto";
import { createRequestStateCodec } from "@modelcontextprotocol/server";
import { principal } from "./stepup.ts";

export type OperationState = { op: string };

export const requestStateCodec = createRequestStateCodec<OperationState>({
  // One process serves every round in this lab; set REQUEST_STATE_KEY when running several replicas.
  key: process.env.REQUEST_STATE_KEY ?? randomBytes(32).toString("base64url"),
  // Same as the operation lifetime (operations.ts): a state never outlives the operation it names.
  ttlSeconds: 600,
  // Bound to the user: a state minted for alice is rejected when echoed under bob's token.
  bind: () => principal().sub,
});
