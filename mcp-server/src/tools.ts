import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { config } from "./config.ts";
import { ChallengeAfterCommit, commit, consumeToken, requireAuthorizationDetails } from "./stepup.ts";
import { createOperation, findByRequest, hashArgs, requestKey, setStatus, type Operation } from "./operations.ts";
import type { AuthorizationDetail, Principal } from "./auth.ts";

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

const text = (t: string) => ({ content: [{ type: "text" as const, text: t }] });
const brl = (n: number) => `R$ ${n.toFixed(2)}`;

export function buildServer(): McpServer {
  const server = new McpServer({ name: "stepup-lab-bank", version: "0.1.0" });

  server.registerTool(
    "get_accounts",
    { description: "List the user's accounts and balances.", inputSchema: {} },
    async (_args, extra) => {
      const p = extra.authInfo as Principal;
      const l = ledgerFor(p.sub);
      return text(l.accounts.map((a) => `${a.id} (${a.name}): ${brl(a.balance)}`).join("\n"));
    },
  );

  server.registerTool(
    "list_payees",
    { description: "List payees (Pix keys) the user has paid before.", inputSchema: {} },
    async (_args, extra) => {
      const p = extra.authInfo as Principal;
      return text([...ledgerFor(p.sub).payees].join("\n"));
    },
  );

  // NOTE: nothing in this tool's metadata says it needs more than the session token.
  // The need is discovered while executing: every transfer must be authorized by a one-shot
  // token whose authorization_details (RFC 9396) describe exactly this operation.
  server.registerTool(
    "transfer",
    {
      description: "Send a Pix transfer from one of the user's accounts to a Pix key.",
      inputSchema: {
        from_account: z.string().describe("Account id, e.g. 'checking'"),
        pix_key: z.string().describe("Destination Pix key"),
        amount: z.number().positive().describe("Amount in BRL"),
        description: z.string().optional(),
      },
    },
    async (args, extra) => {
      const { from_account, pix_key, amount } = args;
      const p = extra.authInfo as Principal;
      const l = ledgerFor(p.sub);
      const key = requestKey(extra.sessionId, extra.requestId);
      const argsHash = hashArgs(args);
      let op = findByRequest(key) as Operation<Checkpoint> | undefined;

      if (op) {
        // ---- Replay of a request we have already seen -------------------------
        if (op.sub !== p.sub || op.argsHash !== argsHash) return fail("Replay does not match the pending operation.");
        if (op.status === "completed") {
          console.log(`[op] ${op.id} duplicate replay -> returning stored result (no re-execution)`);
          return op.result!;
        }
        if (op.status !== "awaiting_authorization") return fail(`Operation ${op.id} is ${op.status}; nothing was executed.`);
        console.log(`[op] ${op.id} resumed from checkpoint (validation + user confirmation already done)`);
      } else {
        // ---- First execution: read-only work only ----------------------------
        const acct = l.accounts.find((a) => a.id === from_account);
        if (!acct) return fail(`Unknown account '${from_account}'.`);
        if (acct.balance < amount) return fail(`Insufficient funds in ${acct.id}.`);

        // Informational risk notes shown to the user (every transfer needs authorization anyway).
        const notes: string[] = [];
        if (amount > config.riskAmountThreshold) notes.push(`high value (above ${brl(config.riskAmountThreshold)})`);
        if (!l.payees.has(pix_key)) notes.push("first transfer to this Pix key");

        const detail = moneyTransferDetail(from_account, pix_key, amount);
        op = createOperation<Checkpoint>({
          sub: p.sub,
          requestKey: key,
          tool: "transfer",
          argsHash,
          summary: `${brl(amount)} from ${from_account} to ${pix_key}`,
          checkpoint: { detail, notes },
        });
        console.log(`[op] ${op.id} created (${op.summary})${notes.length ? `: ${notes.join("; ")}` : ""}`);

        // Tell the user something is in course, and get explicit intent BEFORE the redirect.
        const answer = await confirmWithUser(server, op);
        if (answer !== "proceed") {
          const result = text(
            `Operation ${op.id} cancelled by the user before authorization (${answer}). Nothing was executed.`,
          );
          setStatus(op, "cancelled", result);
          return result;
        }
        setStatus(op, "awaiting_authorization");
      }

      // ---- Authorization for THIS operation (RFC 9396 authorization_details) ----
      requireAuthorizationDetails(
        extra,
        op.checkpoint.detail,
        `${config.paymentDetailsType} for ${op.summary} [operation ${op.id}]`,
        op.id,
      );

      // ---- Authorized: re-validate (state may have changed while the user was away), then commit
      const acct = l.accounts.find((a) => a.id === from_account)!;
      if (acct.balance < amount) {
        const result = fail(`Insufficient funds in ${acct.id} at execution time; operation ${op.id} failed, nothing executed.`);
        setStatus(op, "failed", result);
        return result;
      }
      const result = commit(`transfer ${op.id}`, () => doTransfer(l, args, op.id));
      consumeToken(extra); // one-shot: this token can never authorize anything again
      setStatus(op, "completed", result);
      return result;
    },
  );

  // A deliberately badly-ordered tool: it first registers new payees (a side effect), and only
  // then discovers the transfers need authorization. With new payees the commit guard turns what
  // would be a lying 401 ("nothing happened") into an in-band partial-progress report. With known
  // payees nothing was committed, so it challenges honestly with ONE remediation carrying N
  // authorization_details (one consent for the whole batch).
  if (config.demoUnsafeTool) {
    server.registerTool(
      "naive_batch_transfer",
      {
        description:
          "LAB DEMO ONLY. Registers any new payees, then executes several Pix transfers in one call. Use only when the user explicitly asks for a naive batch.",
        inputSchema: {
          from_account: z.string(),
          items: z.array(z.object({ pix_key: z.string(), amount: z.number().positive() })).min(1),
        },
      },
      async ({ from_account, items }, extra) => {
        const p = extra.authInfo as Principal;
        const l = ledgerFor(p.sub);
        const registered: string[] = [];
        for (const it of items) {
          if (!l.payees.has(it.pix_key)) {
            commit(`register payee ${it.pix_key}`, () => l.payees.add(it.pix_key));
            registered.push(it.pix_key);
          }
        }
        // One remediation can carry several authorization_details: one consent covers the whole batch.
        const details = items.map((it) => moneyTransferDetail(from_account, it.pix_key, it.amount));
        try {
          requireAuthorizationDetails(extra, details, `batch of ${items.length} transfers`);
        } catch (e) {
          if (!(e instanceof ChallengeAfterCommit)) throw e; // nothing committed yet -> 401 is honest
          return fail(
            `Partially executed. Registered new payees: ${registered.join(", ")}.\n` +
              `No transfer was executed: the transfers need authorization, which cannot be requested after ` +
              `this call already changed state. Submit the transfers again (payees are now registered).`,
          );
        }
        const acct = l.accounts.find((a) => a.id === from_account);
        const total = items.reduce((s, it) => s + it.amount, 0);
        if (!acct || acct.balance < total) return fail("Unknown account or insufficient funds; nothing executed.");
        const done = items.map((it) => commit(`batch ${it.pix_key}`, () => doTransfer(l, { from_account, ...it })));
        consumeToken(extra);
        return text(`Batch done:\n${done.map((r) => r.content[0].text.split("\n")[0]).join("\n")}`);
      },
    );
  }

  return server;
}

type Checkpoint = { detail: AuthorizationDetail; notes: string[] };

/** The RFC 9396 authorization details object that authorizes exactly one transfer. */
function moneyTransferDetail(from: string, pixKey: string, amount: number): AuthorizationDetail {
  return {
    type: config.paymentDetailsType,
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
 * Pre-authorization elicitation (form mode). Not used to collect credentials: it shows the
 * user what is pending and gets their intent before the client is sent to the AS.
 *
 * Sent WITHOUT relatedRequestId on purpose: in JSON response mode the POST has no
 * stream for server->client requests, so it goes out on the standalone GET SSE stream.
 */
async function confirmWithUser(server: McpServer, op: Operation<Checkpoint>): Promise<"proceed" | string> {
  if (!server.server.getClientCapabilities()?.elicitation) {
    console.log(`[op] ${op.id} client has no elicitation capability -> straight to authorization`);
    return "proceed";
  }
  try {
    const r = await server.server.elicitInput(
      {
        mode: "form",
        message:
          `Pending payment ${op.id}: ${op.summary}.\n` +
          (op.checkpoint.notes.length ? `Notes: ${op.checkpoint.notes.join("; ")}.\n` : "") +
          `Every payment needs your explicit approval. If you continue, you will be sent to your bank to ` +
          `approve THIS payment only (one-time authorization).`,
        requestedSchema: {
          type: "object",
          properties: {
            proceed: { type: "boolean", title: "Continue to authorization", default: true },
          },
          required: ["proceed"],
        },
      },
      { timeout: config.elicitationTimeoutMs },
    );
    console.log(`[op] ${op.id} elicitation -> ${r.action} ${JSON.stringify(r.content ?? {})}`);
    if (r.action === "accept" && r.content?.proceed === true) return "proceed";
    return r.action === "accept" ? "user chose not to continue" : `elicitation ${r.action}`;
  } catch (e) {
    return `elicitation failed: ${(e as Error).message}`;
  }
}
