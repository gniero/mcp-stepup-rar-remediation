import {
  McpServer,
  inputRequired,
  inputResponse,
  type CallToolResult,
  type InputRequiredResult,
  type ServerContext,
} from "@modelcontextprotocol/server";
import { z } from "zod";
import { config } from "./config.ts";
import { ChallengeAfterCommit, commit, principal, requireAuthorizationDetails } from "./stepup.ts";
import {
  createOperation,
  findById,
  findByIdempotencyKey,
  hashArgs,
  instructionId,
  operationIdsIn,
  setStatus,
  type Operation,
} from "./operations.ts";
import { META_OPERATION_ID } from "./challenge.ts";
import { requestStateCodec, type OperationState } from "./request-state.ts";
import type { AuthorizationDetail } from "./auth.ts";

type Account = { id: string; name: string; balance: number };
type Ledger = { accounts: Account[]; payees: Set<string>; history: string[] };

// Toy in-memory bank, one ledger per subject.
const ledgers = new Map<string, Ledger>();
function ledgerFor(sub: string): Ledger {
  let l = ledgers.get(sub);
  if (!l) {
    l = {
      accounts: [
        { id: "checking", name: "Conta corrente", balance: 2500 },
        { id: "savings", name: "Poupança", balance: 10000 },
      ],
      payees: new Set(["bob@pix.example", "landlord@pix.example"]),
      history: [],
    };
    ledgers.set(sub, l);
  }
  return l;
}

const text = (t: string): CallToolResult & { content: [{ type: "text"; text: string }] } => ({
  content: [{ type: "text", text: t }],
});
const brl = (n: number) => `R$ ${n.toFixed(2)}`;

/** One McpServer per request (createMcpHandler factory) or per stdio connection; state lives in module maps. */
export function buildServer(): McpServer {
  const server = new McpServer(
    { name: "stepup-lab-bank", version: "0.2.0" },
    // MRTR: every echoed requestState is HMAC-verified (and user-bound) before a handler runs.
    { requestState: { verify: requestStateCodec.verify } },
  );

  server.registerTool(
    "get_accounts",
    { description: "List the user's accounts and balances.", inputSchema: z.object({}) },
    async () => {
      const l = ledgerFor(principal().sub);
      return text(l.accounts.map((a) => `${a.id} (${a.name}): ${brl(a.balance)}`).join("\n"));
    },
  );

  server.registerTool(
    "list_payees",
    { description: "List payees (Pix keys) the user has paid before.", inputSchema: z.object({}) },
    async () => text([...ledgerFor(principal().sub).payees].join("\n")),
  );

  // NOTE: nothing in this tool's metadata says it needs more than the session token.
  // The need is discovered while executing: every transfer must be authorized by a one-shot
  // token whose authorization_details (RFC 9396) describe exactly this operation INSTANCE
  // (instruction_id = operation id).
  server.registerTool(
    "transfer",
    {
      description: "Send a Pix transfer from one of the user's accounts to a Pix key.",
      inputSchema: z.object({
        from_account: z.string().describe("Account id, e.g. 'checking'"),
        pix_key: z.string().describe("Destination Pix key"),
        amount: z.number().positive().describe("Amount in BRL"),
        description: z.string().optional(),
        idempotency_key: z
          .string()
          .min(8)
          .optional()
          .describe("Optional client-generated unique key. Repeating a call with the same key never creates a second transfer."),
      }),
    },
    async (args, ctx): Promise<CallToolResult | InputRequiredResult> => {
      const { from_account, pix_key, amount } = args;
      const p = principal();
      const l = ledgerFor(p.sub);
      const argsHash = hashArgs(args);

      const found = await resolveOperation<Checkpoint>(ctx, "transfer", argsHash, args.idempotency_key);
      if ("error" in found) return fail(found.error);
      let op = found.op;

      if (op) {
        // ---- Retry / duplicate of an operation we have already seen -------------
        if (op.status === "completed") {
          console.log(`[op] ${op.id} already completed -> returning stored result (no re-execution)`);
          return op.result!;
        }
        if (op.status !== "awaiting_authorization" && op.status !== "awaiting_confirmation")
          return fail(`Operation ${op.id} is ${op.status}; nothing was executed by this call.`);
        console.log(`[op] ${op.id} resumed (status ${op.status})`);
      } else {
        // ---- First execution: read-only work only ----------------------------
        const acct = l.accounts.find((a) => a.id === from_account);
        if (!acct) return fail(`Unknown account '${from_account}'.`);
        if (acct.balance < amount) return fail(`Insufficient funds in ${acct.id}.`);

        // Informational risk notes shown to the user (every transfer needs authorization anyway).
        const notes: string[] = [];
        if (amount > config.riskAmountThreshold) notes.push(`high value (above ${brl(config.riskAmountThreshold)})`);
        if (!l.payees.has(pix_key)) notes.push("first transfer to this Pix key");

        op = createOperation<Checkpoint>({
          sub: p.sub,
          clientId: p.clientId,
          tool: "transfer",
          argsHash,
          idempotencyKey: args.idempotency_key,
          summary: `${brl(amount)} from ${from_account} to ${pix_key}`,
          // The required authorization_details embed the operation id: the grant is for THIS instance.
          checkpoint: (id) => ({ detail: moneyTransferDetail(instructionId(id), from_account, pix_key, amount), notes }),
        });
        console.log(`[op] ${op.id} created (${op.summary})${notes.length ? `: ${notes.join("; ")}` : ""}`);
      }

      // ---- Tell the user something is in course, and get explicit intent BEFORE the redirect.
      //      MRTR round: input_required {confirm} + requestState {op}; the client retries with the answer.
      if (op.status === "awaiting_confirmation") {
        const step = await confirmationRound(server, ctx, op, found.via === "requestState");
        if (step !== "proceed") return step;
        setStatus(op, "awaiting_authorization");
      }

      // ---- Authorization for THIS operation; claims it (executing) + spends the token ----
      requireAuthorizationDetails(
        op,
        [op.checkpoint.detail],
        `${config.paymentDetailsType} ${op.id}: ${op.summary}`,
      );

      // ---- Claimed: re-validate (state may have changed while the user was away), then commit
      const acct = l.accounts.find((a) => a.id === from_account)!;
      if (acct.balance < amount) {
        const result = fail(`Insufficient funds in ${acct.id} at execution time; operation ${op.id} failed, nothing executed.`);
        setStatus(op, "failed", result);
        return result;
      }
      try {
        const result = commit(`transfer ${op.id}`, () => doTransfer(l, args, op.id));
        setStatus(op, "completed", result);
        return result;
      } catch (e) {
        setStatus(op, "failed", fail(`Execution failed: ${(e as Error).message}`));
        throw e;
      }
    },
  );

  // A deliberately badly-ordered tool: it first registers new payees (a side effect), and only
  // then discovers the transfers need authorization. With new payees the commit guard turns what
  // would be a lying 401 ("nothing happened") into an in-band partial-progress report. With known
  // payees nothing was committed, so it challenges honestly with ONE remediation carrying N
  // authorization_details (one consent for the whole batch), each with its own instruction_id.
  if (config.demoUnsafeTool) {
    server.registerTool(
      "naive_batch_transfer",
      {
        description:
          "LAB DEMO ONLY. Registers any new payees, then executes several Pix transfers in one call. Use only when the user explicitly asks for a naive batch.",
        inputSchema: z.object({
          from_account: z.string(),
          items: z.array(z.object({ pix_key: z.string(), amount: z.number().positive() })).min(1),
          idempotency_key: z.string().min(8).optional(),
        }),
      },
      async (args, ctx) => {
        const { from_account, items } = args;
        const p = principal();
        const l = ledgerFor(p.sub);
        const argsHash = hashArgs(args);
        const found = await resolveOperation<BatchCheckpoint>(ctx, "naive_batch_transfer", argsHash, args.idempotency_key);
        if ("error" in found) return fail(found.error);
        let op = found.op;
        if (op?.status === "completed") return op.result!;
        if (op && op.status !== "awaiting_authorization") return fail(`Operation ${op.id} is ${op.status}; nothing was executed by this call.`);

        const registered: string[] = [];
        if (!op) {
          for (const it of items) {
            if (!l.payees.has(it.pix_key)) {
              commit(`register payee ${it.pix_key}`, () => l.payees.add(it.pix_key));
              registered.push(it.pix_key);
            }
          }
          op = createOperation<BatchCheckpoint>({
            sub: p.sub,
            clientId: p.clientId,
            tool: "naive_batch_transfer",
            argsHash,
            idempotencyKey: args.idempotency_key,
            summary: `batch of ${items.length} transfers from ${from_account}`,
            checkpoint: (id) => ({
              details: items.map((it, i) => moneyTransferDetail(instructionId(id, i + 1), from_account, it.pix_key, it.amount)),
            }),
          });
          setStatus(op, "awaiting_authorization");
        }
        try {
          requireAuthorizationDetails(op, op.checkpoint.details, `batch ${op.id} of ${items.length} transfers`);
        } catch (e) {
          if (!(e instanceof ChallengeAfterCommit)) throw e; // nothing committed yet -> the challenge is honest
          const result = fail(
            `Partially executed. Registered new payees: ${registered.join(", ")}.\n` +
              `No transfer was executed: the transfers need authorization, which cannot be requested after ` +
              `this call already changed state. Submit the transfers again (payees are now registered).`,
          );
          setStatus(op, "failed", result);
          return result;
        }
        const acct = l.accounts.find((a) => a.id === from_account);
        const total = items.reduce((s, it) => s + it.amount, 0);
        if (!acct || acct.balance < total) {
          const result = fail("Unknown account or insufficient funds; nothing executed.");
          setStatus(op, "failed", result);
          return result;
        }
        const done = items.map((it) => commit(`batch ${it.pix_key}`, () => doTransfer(l, { from_account, ...it })));
        const result = text(`Batch done (operation ${op.id}):\n${done.map((r) => r.content[0].text.split("\n")[0]).join("\n")}`);
        setStatus(op, "completed", result);
        return result;
      },
    );
  }

  return server;
}

type Checkpoint = { detail: AuthorizationDetail; notes: string[] };
type BatchCheckpoint = { details: AuthorizationDetail[] };

/**
 * Find the operation this call belongs to (see operations.ts for the order) and check that it
 * really is this call: same user, same tool, same arguments. A token bound to another operation,
 * or an idempotency key reused with different arguments, is refused without side effects.
 */
async function resolveOperation<C>(
  ctx: ServerContext,
  tool: string,
  argsHash: string,
  idempotencyKey: string | undefined,
): Promise<{ op?: Operation<C>; via?: string } | { error: string }> {
  const p = principal();
  const fromToken = operationIdsIn(p.authorizationDetails as { instruction_id?: unknown }[] | undefined);
  if (fromToken.length > 1) return { error: "Token authorizes several operations; one operation per token is required." };
  // Already HMAC-verified and user-bound by the requestState hook (request-state.ts).
  const fromState = ctx.mcpReq.requestState<OperationState>()?.op;
  const handle = ctx.mcpReq._meta?.[META_OPERATION_ID] as string | undefined;

  let op: Operation<C> | undefined;
  let via: string;
  if (fromToken.length) {
    via = "token instruction_id";
    op = findById(fromToken[0]) as Operation<C> | undefined;
    if (!op) return { error: `The token authorizes operation ${fromToken[0]}, which is unknown or expired. Nothing was executed.` };
    // Strict binding in both directions: if this request already belongs to a different operation
    // (via requestState, _meta or idempotency key), the token cannot be redirected to it.
    const own =
      (fromState && findById(fromState)) ||
      (handle && findById(handle)) ||
      (idempotencyKey && findByIdempotencyKey(p.sub, tool, idempotencyKey));
    if (own && own.id !== op.id)
      return { error: `The token is bound to operation ${op.id}, but this request is operation ${own.id}. Nothing was executed.` };
  } else if (fromState) {
    via = "requestState";
    op = findById(fromState) as Operation<C> | undefined;
    if (!op) return { error: `Unknown or expired operation ${fromState}; nothing was executed.` };
  } else if (handle) {
    via = "_meta operation_id";
    op = findById(handle) as Operation<C> | undefined;
    if (!op) return { error: `Unknown or expired operation ${handle}; nothing was executed.` };
  } else if (idempotencyKey) {
    via = "idempotency_key";
    op = findByIdempotencyKey(p.sub, tool, idempotencyKey) as Operation<C> | undefined;
  } else {
    return {}; // a new call: no sessions, no request-id lookup (each retry has a new id)
  }
  if (!op) return {};
  if (op.sub !== p.sub || op.tool !== tool)
    return { error: `Operation ${op.id} belongs to another user or tool. Nothing was executed.` };
  if (op.argsHash !== argsHash)
    return {
      error:
        via === "idempotency_key"
          ? `idempotency_key already used for operation ${op.id} with different parameters. Nothing was executed.`
          : `This request does not match operation ${op.id} (found via ${via}). Nothing was executed.`,
    };
  console.log(`[op] ${op.id} matched via ${via} (status ${op.status})`);
  return { op, via };
}

/** The RFC 9396 authorization details object that authorizes exactly one transfer instance. */
function moneyTransferDetail(instruction_id: string, from: string, pixKey: string, amount: number): AuthorizationDetail {
  return {
    type: config.paymentDetailsType,
    instruction_id,
    debtor_account: { account_id: from },
    creditor_account: { pix_key: pixKey },
    instructed_amount: { currency: "BRL", amount: amount.toFixed(2) },
  };
}

function fail(msg: string) {
  return { ...text(msg), isError: true };
}

function doTransfer(
  l: Ledger,
  a: { from_account: string; pix_key: string; amount: number; description?: string },
  opId?: string,
) {
  const acct = l.accounts.find((x) => x.id === a.from_account)!;
  acct.balance -= a.amount;
  l.payees.add(a.pix_key);
  const line = `${new Date().toISOString()} ${brl(a.amount)} ${acct.id} -> ${a.pix_key}${a.description ? ` (${a.description})` : ""}`;
  l.history.push(line);
  return text(`Transfer done${opId ? ` (operation ${opId})` : ""}: ${line}\nNew balance of ${acct.id}: ${brl(acct.balance)}`);
}

/**
 * Pre-authorization confirmation, as an MRTR round (MCP 2026-07-28). Not used to collect
 * credentials: it shows the user what is pending and gets their intent before the client is sent
 * to the AS.
 *
 * Round 1 returns `input_required` with an embedded form elicitation and a sealed requestState
 * naming the operation. The client asks the user and retries the SAME call with `inputResponses`
 * and the echoed requestState; round 2 reads the answer. An answer is only trusted when the
 * operation was found through the requestState (i.e. it answers THIS operation's question).
 */
async function confirmationRound(
  server: McpServer,
  ctx: ServerContext,
  op: Operation<Checkpoint>,
  answeringThisOp: boolean,
): Promise<"proceed" | CallToolResult | InputRequiredResult> {
  if (!server.server.getClientCapabilities()?.elicitation) {
    console.log(`[op] ${op.id} client has no elicitation capability -> straight to authorization`);
    return "proceed";
  }
  const answer = answeringThisOp ? inputResponse(ctx.mcpReq.inputResponses, "confirm") : { kind: "missing" as const };
  if (answer.kind === "missing") {
    console.log(`[op] ${op.id} -> input_required (confirm)`);
    return inputRequired({
      inputRequests: {
        confirm: inputRequired.elicit({
          message:
            `Pending payment ${op.id}: ${op.summary}.\n` +
            (op.checkpoint.notes.length ? `Notes: ${op.checkpoint.notes.join("; ")}.\n` : "") +
            `Every payment needs your explicit approval. If you continue, you will be sent to your bank to ` +
            `approve THIS payment only (one-time authorization).`,
          requestedSchema: {
            type: "object",
            properties: { proceed: { type: "boolean", title: "Continue to authorization", default: true } },
            required: ["proceed"],
          },
        }),
      },
      requestState: await requestStateCodec.mint({ op: op.id }, ctx),
    });
  }
  const outcome = answer.kind === "elicit" ? answer.action : answer.kind;
  console.log(`[op] ${op.id} confirmation -> ${outcome} ${JSON.stringify(answer.kind === "elicit" ? answer.content ?? {} : {})}`);
  if (answer.kind === "elicit" && answer.action === "accept" && answer.content?.proceed === true) return "proceed";
  const why = answer.kind === "elicit" && answer.action === "accept" ? "user chose not to continue" : `elicitation ${outcome}`;
  const result = text(`Operation ${op.id} cancelled by the user before authorization (${why}). Nothing was executed.`);
  setStatus(op, "cancelled", result);
  return result;
}
