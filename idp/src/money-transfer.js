/**
 * The `money_transfer` authorization details type (RFC 9396), shared by the AS
 * (validation, consent rendering, type metadata endpoint).
 *
 *   {
 *     "type": "money_transfer",
 *     "instruction_id": "op_3AGwNbPor1GD",          <- the RS's pending-operation id: binds the
 *                                                     grant to ONE operation instance
 *     "debtor_account":   { "account_id": "checking" },
 *     "creditor_account": { "pix_key": "carol@pix.example" },
 *     "instructed_amount": { "currency": "BRL", "amount": "800.00" }
 *   }
 */
export const TYPE = "money_transfer";
export const INSTRUCTION_ID_PATTERN = /^op_[A-Za-z0-9_-]{8,64}$/;

/** draft-ietf-oauth-rar-metadata-remediation §5: one entry of the types metadata response. */
export const metadata = {
  [TYPE]: {
    version: "1.0",
    description:
      "Authorize exactly one Pix transfer instance: the resource server's instruction_id, the debtor account, the creditor Pix key and the amount are fixed.",
    documentation_uri: "http://localhost:3000/docs/money_transfer",
    schema: {
      $schema: "https://json-schema.org/draft/2020-12/schema",
      type: "object",
      required: ["type", "instruction_id", "debtor_account", "creditor_account", "instructed_amount"],
      additionalProperties: false,
      properties: {
        type: { const: TYPE },
        instruction_id: {
          type: "string",
          pattern: INSTRUCTION_ID_PATTERN.source,
          description: "Identifier of the pending operation at the resource server (cf. ISO 20022 InstrId). Single use.",
        },
        debtor_account: {
          type: "object",
          required: ["account_id"],
          additionalProperties: false,
          properties: { account_id: { type: "string", minLength: 1 } },
        },
        creditor_account: {
          type: "object",
          required: ["pix_key"],
          additionalProperties: false,
          properties: { pix_key: { type: "string", minLength: 1 } },
        },
        instructed_amount: {
          type: "object",
          required: ["currency", "amount"],
          additionalProperties: false,
          properties: {
            currency: { const: "BRL" },
            amount: { type: "string", pattern: "^[0-9]+\\.[0-9]{2}$" },
          },
        },
      },
    },
    examples: [
      {
        type: TYPE,
        instruction_id: "op_3AGwNbPor1GD",
        debtor_account: { account_id: "checking" },
        creditor_account: { pix_key: "carol@pix.example" },
        instructed_amount: { currency: "BRL", amount: "800.00" },
      },
    ],
  },
};

/** Minimal validator matching the schema above (no JSON Schema engine needed). Returns an error string or null. */
export function validate(d) {
  const keys = (o, allowed) => o && typeof o === "object" && !Array.isArray(o) && Object.keys(o).every((k) => allowed.includes(k));
  if (!keys(d, ["type", "instruction_id", "debtor_account", "creditor_account", "instructed_amount"])) return "unexpected members";
  if (d.type !== TYPE) return "wrong type";
  if (typeof d.instruction_id !== "string" || !INSTRUCTION_ID_PATTERN.test(d.instruction_id))
    return "instruction_id required (resource server operation id, e.g. op_XXXXXXXX)";
  if (!keys(d.debtor_account, ["account_id"]) || typeof d.debtor_account.account_id !== "string" || !d.debtor_account.account_id)
    return "debtor_account.account_id required";
  if (!keys(d.creditor_account, ["pix_key"]) || typeof d.creditor_account.pix_key !== "string" || !d.creditor_account.pix_key)
    return "creditor_account.pix_key required";
  const a = d.instructed_amount;
  if (!keys(a, ["currency", "amount"]) || a.currency !== "BRL" || !/^[0-9]+\.[0-9]{2}$/.test(String(a.amount)))
    return "instructed_amount must be {currency:'BRL', amount:'0.00'}";
  return null;
}

export function describe(d) {
  return `Pix transfer ${d.instruction_id}: R$ ${d.instructed_amount.amount} from account "${d.debtor_account.account_id}" to Pix key "${d.creditor_account.pix_key}"`;
}
