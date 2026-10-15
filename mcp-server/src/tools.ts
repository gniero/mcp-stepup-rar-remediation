import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { config } from "./config.ts";
import { StepUpAfterCommit, commit, requireScopes } from "./stepup.ts";
import { createOperation, findByRequest, hashArgs, requestKey, setStatus, type Operation } from "./operations.ts";
import type { Principal } from "./auth.ts";

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

  // NOTE: nothing in this tool's metadata says it may need more authorization.
  // The need is discovered while executing, from business/risk rules.
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
        if (op.status !== "awaiting_step_up") return fail(`Operation ${op.id} is ${op.status}; nothing was executed.`);
        console.log(`[op] ${op.id} resumed from checkpoint (risk + user confirmation already done)`);
      } else {
        // ---- First execution: read-only work only ----------------------------
        const acct = l.accounts.find((a) => a.id === from_account);
        if (!acct) return fail(`Unknown account '${from_account}'.`);
        if (acct.balance < amount) return fail(`Insufficient funds in ${acct.id}.`);

        // Risk evaluation (stand-in for a PDP / OPA / risk engine call).
        const reasons: string[] = [];
        if (amount > config.riskAmountThreshold) reasons.push(`amount above ${brl(config.riskAmountThreshold)}`);
        if (!l.payees.has(pix_key)) reasons.push("first transfer to this Pix key");
        console.log(`[tool transfer] sub=${p.sub} ${brl(amount)} -> ${pix_key} risk=${reasons.join("; ") || "low"} scopes=${p.scopes.join(" ")}`);

        if (!reasons.length) return commit(`transfer ${brl(amount)} -> ${pix_key}`, () => doTransfer(l, args));

        // Only now do we know the grant is not enough: checkpoint the operation.
        op = createOperation<Checkpoint>({
          sub: p.sub,
          requestKey: key,
          tool: "transfer",
          argsHash,
          summary: `${brl(amount)} from ${from_account} to ${pix_key}`,
          checkpoint: { reasons },
        });
        console.log(`[op] ${op.id} created (${op.summary}): ${reasons.join("; ")}`);

        // Tell the user something is in course, and get explicit intent BEFORE the redirect.
        const answer = await confirmWithUser(server, op);
        if (answer !== "proceed") {
          const result = text(
            `Operation ${op.id} cancelled by the user before authorization (${answer}). Nothing was executed.`,
          );
          setStatus(op, "cancelled", result);
          return result;
        }
        setStatus(op, "awaiting_step_up");
      }

      // ---- Authorization for THIS operation (parameterized scope) --------------
      requireScopes(
        extra,
        [`${config.operationScopePrefix}${op.id}`],
        `${op.checkpoint.reasons.join("; ")} [operation ${op.id}]`,
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
      setStatus(op, "completed", result);
      return result;
    },
  );

  // A deliberately badly-ordered tool: it commits item by item and only then
  // discovers it needs step-up. The commit guard turns what would be a lying 403
  // into an in-band partial-progress report.
  if (config.demoUnsafeTool) {
    server.registerTool(
      "naive_batch_transfer",
      {
        description:
          "LAB DEMO ONLY. Executes several Pix transfers one by one, in order. Use only when the user explicitly asks for a naive batch.",
        inputSchema: {
          from_account: z.string(),
          items: z.array(z.object({ pix_key: z.string(), amount: z.number().positive() })).min(1),
        },
      },
      async ({ from_account, items }, extra) => {
        const p = extra.authInfo as Principal;
        const l = ledgerFor(p.sub);
        const done: string[] = [];
        for (const [i, it] of items.entries()) {
          const risky = it.amount > config.riskAmountThreshold || !l.payees.has(it.pix_key);
          try {
            if (risky) {
              const key = requestKey(extra.sessionId, extra.requestId);
              const op =
                (findByRequest(key) as Operation<Checkpoint> | undefined) ??
                createOperation<Checkpoint>({
                  sub: p.sub,
                  requestKey: key,
                  tool: "naive_batch_transfer",
                  argsHash: hashArgs({ from_account, items }),
                  summary: `batch item ${i + 1}: ${brl(it.amount)} -> ${it.pix_key}`,
                  checkpoint: { reasons: ["high-risk batch item"] },
                });
              requireScopes(extra, [`${config.operationScopePrefix}${op.id}`], `batch item ${i + 1} is high risk`, op.id);
            }
            commit(`batch item ${i + 1}`, () => doTransfer(l, { from_account, ...it }));
            done.push(`${i + 1}. ${brl(it.amount)} -> ${it.pix_key}`);
          } catch (e) {
            if (!(e instanceof StepUpAfterCommit)) throw e; // StepUpRequired (nothing committed yet) -> 403
            return fail(
              `Partially executed. Completed:\n${done.join("\n")}\n` +
                `Stopped at item ${i + 1} (${brl(it.amount)} -> ${it.pix_key}): it needs additional authorization, ` +
                `which cannot be requested after funds already moved in this call. Items ${i + 1}..${items.length} were NOT executed; ` +
                `submit them as separate transfers.`,
            );
          }
        }
        return text(`Batch done:\n${done.join("\n")}`);
      },
    );
  }

  return server;
}

type Checkpoint = { reasons: string[] };

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
 * Pre-step-up elicitation (form mode). Not used to collect credentials: it shows the
 * user what is pending and gets their intent before the client is sent to the AS.
 *
 * Sent WITHOUT relatedRequestId on purpose: in JSON response mode the POST has no
 * stream for server->client requests, so it goes out on the standalone GET SSE stream.
 */
async function confirmWithUser(server: McpServer, op: Operation<Checkpoint>): Promise<"proceed" | string> {
  if (!server.server.getClientCapabilities()?.elicitation) {
    console.log(`[op] ${op.id} client has no elicitation capability -> straight to step-up`);
    return "proceed";
  }
  try {
    const r = await server.server.elicitInput(
      {
        mode: "form",
        message:
          `Pending payment ${op.id}: ${op.summary}.\n` +
          `It needs your additional authorization because: ${op.checkpoint.reasons.join("; ")}.\n` +
          `If you continue, you will be sent to your bank's login page to approve THIS payment only.`,
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
