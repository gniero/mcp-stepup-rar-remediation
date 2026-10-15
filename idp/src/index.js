/**
 * Lab Authorization Server: node-oidc-provider with Rich Authorization Requests (RFC 9396)
 * and the authorization details types metadata endpoint from
 * draft-ietf-oauth-rar-metadata-remediation.
 *
 * - Baseline grant:   scope=mcp:basic                  -> 10 min JWT access token
 * - One-shot grant:   authorization_details=[money_transfer] (no scope) -> 2 min JWT access token
 *                     carrying ONLY that authorization_details entry (single use is enforced by the RS)
 */
import { createServer } from "node:http";
import { generateKeyPair, exportJWK } from "jose";
import Provider, { errors } from "oidc-provider";
import * as MoneyTransfer from "./money-transfer.js";

const ISSUER = process.env.ISSUER ?? "http://localhost:8080";
const PORT = Number(process.env.PORT ?? 8080);
const MCP_RESOURCE = process.env.MCP_RESOURCE ?? "http://mcp-server:3000/mcp";
const BASE_SCOPE = process.env.BASE_SCOPE ?? "mcp:basic";
const BASE_TTL = Number(process.env.BASE_TOKEN_TTL ?? 600);
const ONE_SHOT_TTL = Number(process.env.ONE_SHOT_TOKEN_TTL ?? 120);
const TYPES_METADATA_PATH = "/authorization-details-types";

// Lab users. Real deployments: your user store.
const USERS = { alice: "alice" };

const { privateKey } = await generateKeyPair("RS256", { extractable: true });
const jwk = { ...(await exportJWK(privateKey)), kid: "lab-rs256", alg: "RS256", use: "sig" };

/** Only the authorization_details of THIS request; never re-issue details stored on the grant. */
function currentRequestDetails(ctx) {
  const raw = ctx.oidc.params?.authorization_details;
  return raw ? JSON.parse(raw) : undefined;
}

const configuration = {
  clients: [
    {
      client_id: "mcp-agent",
      client_name: "MCP Step-Up Lab Agent",
      token_endpoint_auth_method: "none",
      redirect_uris: ["http://localhost:8765/callback"],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      authorization_details_types: [MoneyTransfer.TYPE],
    },
    {
      // Lab-only headless client for scripts/probe.sh (custom password grant below).
      client_id: "mcp-probe",
      client_secret: "probe-secret",
      grant_types: ["urn:lab:params:oauth:grant-type:password"],
      response_types: [],
      redirect_uris: [],
      authorization_details_types: [MoneyTransfer.TYPE],
    },
  ],
  jwks: { keys: [jwk] },
  cookies: { keys: ["lab-cookie-key-change-me"] },
  scopes: ["openid", BASE_SCOPE],
  claims: { openid: ["sub"] },
  pkce: { required: () => true },
  async findAccount(_ctx, id) {
    if (!Object.hasOwn(USERS, id)) return undefined;
    return { accountId: id, claims: async () => ({ sub: id, preferred_username: id }) };
  },
  extraTokenClaims: async (_ctx, token) => (token.accountId ? { preferred_username: token.accountId } : undefined),
  interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
  features: {
    devInteractions: { enabled: false },
    resourceIndicators: {
      enabled: true,
      defaultResource: () => MCP_RESOURCE,
      useGrantedResource: () => true,
      getResourceServerInfo(ctx, resource) {
        if (resource !== MCP_RESOURCE) throw new errors.InvalidTarget(`unknown resource ${resource}`);
        const oneShot = Boolean(ctx.oidc.entities?.AuthorizationCode?.rar?.length || ctx.oidc.params?.authorization_details);
        return {
          scope: BASE_SCOPE,
          audience: MCP_RESOURCE,
          accessTokenFormat: "jwt",
          accessTokenTTL: oneShot ? ONE_SHOT_TTL : BASE_TTL,
          jwt: { sign: { alg: "RS256" } },
        };
      },
    },
    richAuthorizationRequests: {
      enabled: true,
      types: {
        [MoneyTransfer.TYPE]: {
          validate(_ctx, detail) {
            const err = MoneyTransfer.validate(detail);
            if (err) throw new errors.InvalidAuthorizationDetails(`money_transfer: ${err}`);
          },
        },
      },
      // Code gets exactly what was requested (and consented) in this authorization request.
      authorizationDetailsForGrantSource: (ctx) => currentRequestDetails(ctx),
      // Access token gets exactly what the code carried. Nothing accumulates across requests.
      authorizationDetailsForAccessToken: (_ctx, _token, source) => source?.rar,
      authorizationDetailsForIntrospection: (_ctx, token) => token.rar,
    },
  },
  discovery: {
    authorization_details_types_metadata_endpoint: `${ISSUER}${TYPES_METADATA_PATH}`,
  },
  ttl: {
    AccessToken: (_ctx, token) => token.resourceServer?.accessTokenTTL ?? BASE_TTL,
    Interaction: 600,
    Session: 3600,
    Grant: 3600,
    AuthorizationCode: 60,
  },
  renderError(ctx, out) {
    ctx.type = "html";
    ctx.body = page("Error", `<pre>${esc(JSON.stringify(out, null, 2))}</pre>`);
  },
};

const provider = new Provider(ISSUER, configuration);

// ---- Lab-only password grant for the headless probe --------------------------------
const PASSWORD_GRANT = "urn:lab:params:oauth:grant-type:password";
provider.registerGrantType(
  PASSWORD_GRANT,
  async (ctx) => {
    const { username, password, scope, authorization_details } = ctx.oidc.params;
    if (USERS[username] !== password) throw new errors.InvalidGrant("bad credentials");
    const rar = authorization_details ? JSON.parse(authorization_details) : undefined;
    for (const d of rar ?? []) {
      const err = MoneyTransfer.validate(d);
      if (err) throw new errors.InvalidAuthorizationDetails(err);
    }
    const scopes = (scope ?? "").split(" ").filter((s) => s === BASE_SCOPE).join(" ");
    const grant = new provider.Grant({ accountId: username, clientId: ctx.oidc.client.clientId });
    if (scopes) grant.addResourceScope(MCP_RESOURCE, scopes);
    const grantId = await grant.save();
    const at = new provider.AccessToken({
      accountId: username,
      client: ctx.oidc.client,
      grantId,
      gty: "password",
      scope: scopes || undefined,
      rar,
    });
    at.resourceServer = new provider.ResourceServer(MCP_RESOURCE, {
      scope: BASE_SCOPE,
      audience: MCP_RESOURCE,
      accessTokenFormat: "jwt",
      accessTokenTTL: rar ? ONE_SHOT_TTL : BASE_TTL,
      jwt: { sign: { alg: "RS256" } },
    });
    console.log(`[token] probe sub=${username} scope="${scopes}" authorization_details=${rar ? JSON.stringify(rar) : "-"}`);
    ctx.body = {
      access_token: await at.save(),
      token_type: "Bearer",
      expires_in: at.expiration,
      ...(scopes ? { scope: scopes } : {}),
      ...(rar ? { authorization_details: rar } : {}),
    };
  },
  ["username", "password", "scope", "authorization_details"],
);

provider.on("grant.success", (ctx) => {
  const at = ctx.oidc.entities.AccessToken;
  console.log(
    `[token] client=${ctx.oidc.client?.clientId} sub=${at?.accountId} scope="${at?.scope ?? ""}" ` +
      `authorization_details=${at?.rar ? JSON.stringify(at.rar) : "-"} ttl=${at?.expiration}s`,
  );
});
provider.on("server_error", (_ctx, err) => console.error("[server_error]", err));

// ---- Interactions (login + consent) -------------------------------------------------
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
function page(title, body) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>
body{font-family:-apple-system,system-ui,Segoe UI,Roboto,sans-serif;background:#f4f6f8;margin:0;padding:40px 16px;color:#1d2433}
.card{max-width:440px;margin:0 auto;background:#fff;border-radius:12px;padding:28px;box-shadow:0 2px 12px rgba(0,0,0,.08)}
h1{font-size:20px;margin:0 0 6px} p.sub{color:#5b6475;margin:0 0 20px;font-size:14px}
label{display:block;font-size:13px;margin:12px 0 4px;color:#3b4252} input{width:100%;box-sizing:border-box;padding:10px;border:1px solid #cdd3dc;border-radius:8px;font-size:15px}
.row{display:flex;gap:10px;margin-top:22px} button,a.btn{flex:1;padding:11px;border-radius:8px;border:0;font-size:15px;cursor:pointer;text-align:center;text-decoration:none}
button.primary{background:#1f6feb;color:#fff} a.btn{background:#eef1f5;color:#1d2433}
.pay{border:1px solid #d7dde6;border-radius:10px;padding:14px 16px;margin:10px 0;background:#fafbfd}
.pay .amt{font-size:26px;font-weight:600;margin-bottom:8px} .kv{display:flex;justify-content:space-between;font-size:14px;padding:4px 0;border-top:1px solid #edf0f4}
.kv span:first-child{color:#5b6475} .tag{display:inline-block;font-size:12px;background:#fff4d6;color:#7a5a00;border-radius:6px;padding:2px 8px;margin-top:10px}
ul{padding-left:18px;font-size:14px}
</style></head><body><div class="card">${body}</div></body></html>`;
}

async function readForm(req) {
  let raw = "";
  for await (const chunk of req) raw += chunk;
  return Object.fromEntries(new URLSearchParams(raw));
}

function consentBody(uid, details, clientName) {
  const rar = details.prompt.details.rar ?? [];
  const scopes = Object.values(details.prompt.details.missingResourceScopes ?? {}).flat();
  const oneShot = rar.length > 0;
  let html = `<h1>${oneShot ? (rar.length > 1 ? "Approve these payments" : "Approve this payment") : "Grant access"}</h1>
<p class="sub"><b>${esc(clientName)}</b> is asking for ${
    oneShot ? (rar.length > 1 ? `permission to execute these ${rar.length} payments, once` : "permission to execute exactly one payment") : "access to your accounts"
  }.</p>`;
  for (const d of rar) {
    html += `<div class="pay"><div class="amt">R$ ${esc(d.instructed_amount?.amount)}</div>
<div class="kv"><span>From (debtor account)</span><span>${esc(d.debtor_account?.account_id)}</span></div>
<div class="kv"><span>To (creditor Pix key)</span><span>${esc(d.creditor_account?.pix_key)}</span></div>
<div class="kv"><span>Type</span><span>${esc(d.type)}</span></div>
<span class="tag">One-time authorization · valid for this payment only</span></div>`;
  }
  if (rar.length > 1) {
    const total = rar.reduce((t, d) => t + Number(d.instructed_amount?.amount ?? 0), 0);
    html += `<div class="kv"><span>Total</span><span><b>R$ ${total.toFixed(2)}</b></span></div>`;
  }
  if (scopes.length) html += `<ul>${scopes.map((s) => `<li>${s === BASE_SCOPE ? "Read your accounts and balances" : esc(s)} <code>(${esc(s)})</code></li>`).join("")}</ul>`;
  html += `<form method="post" action="/interaction/${uid}/confirm"><div class="row">
<a class="btn" href="/interaction/${uid}/abort" id="deny">Deny</a>
<button class="primary" type="submit" id="approve">${oneShot ? "Approve payment" : "Allow"}</button></div></form>`;
  return html;
}

const providerCallback = provider.callback();

createServer(async (req, res) => {
  try {
    // Containers reach us as http://idp:8080, browsers as http://localhost:8080. Pin the Host so every
    // URL we emit (discovery, redirects, endpoints) is the issuer's front-channel URL.
    req.headers.host = new URL(ISSUER).host;
    delete req.headers["x-forwarded-host"];
    const url = new URL(req.url, ISSUER);
    const m = url.pathname.match(/^\/interaction\/([^/]+)(?:\/(login|confirm|abort))?$/);

    if (req.method === "GET" && url.pathname === TYPES_METADATA_PATH) {
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(MoneyTransfer.metadata, null, 2));
      return;
    }
    if (req.method === "GET" && url.pathname === "/healthz") return void res.writeHead(200).end("ok");
    if (!m) return void providerCallback(req, res);

    const [, uid, action] = m;
    const details = await provider.interactionDetails(req, res);
    if (details.uid !== uid) throw new Error("interaction mismatch");
    const client = await provider.Client.find(details.params.client_id);
    const clientName = client?.clientName ?? details.params.client_id;

    if (!action && req.method === "GET") {
      const body =
        details.prompt.name === "login"
          ? `<h1>Sign in</h1><p class="sub">to continue to <b>${esc(clientName)}</b></p>
<form method="post" action="/interaction/${uid}/login" autocomplete="off">
<label>Username</label><input name="login" id="username" autofocus>
<label>Password</label><input name="password" id="password" type="password">
<div class="row"><a class="btn" href="/interaction/${uid}/abort">Cancel</a><button class="primary" type="submit" id="kc-login">Sign in</button></div></form>`
          : consentBody(uid, details, clientName);
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }).end(page(clientName, body));
      return;
    }

    if (action === "login" && req.method === "POST") {
      const { login, password } = await readForm(req);
      if (USERS[login] !== password) {
        res.writeHead(200, { "content-type": "text/html" }).end(
          page("Sign in", `<h1>Sign in</h1><p class="sub" style="color:#b42318">Invalid credentials.</p><p><a href="/interaction/${uid}">Try again</a></p>`),
        );
        return;
      }
      await provider.interactionFinished(req, res, { login: { accountId: login } }, { mergeWithLastSubmission: false });
      return;
    }

    if (action === "confirm" && req.method === "POST") {
      await readForm(req);
      const { prompt, params, session, grantId } = details;
      const grant = grantId
        ? await provider.Grant.find(grantId)
        : new provider.Grant({ accountId: session.accountId, clientId: params.client_id });
      const d = prompt.details;
      if (d.missingOIDCScope) grant.addOIDCScope(d.missingOIDCScope.join(" "));
      if (d.missingOIDCClaims) grant.addOIDCClaims(d.missingOIDCClaims);
      for (const [indicator, scopes] of Object.entries(d.missingResourceScopes ?? {})) grant.addResourceScope(indicator, scopes.join(" "));
      for (const detail of d.rar ?? []) grant.addRar(detail);
      const result = { consent: { grantId: await grant.save() } };
      console.log(`[consent] ${session.accountId} approved ${d.rar ? JSON.stringify(d.rar) : Object.values(d.missingResourceScopes ?? {}).flat().join(" ")}`);
      await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: true });
      return;
    }

    if (action === "abort") {
      console.log(`[consent] ${details.session?.accountId ?? "?"} denied`);
      await provider.interactionFinished(req, res, { error: "access_denied", error_description: "End-User denied the request" }, { mergeWithLastSubmission: false });
      return;
    }

    res.writeHead(405).end();
  } catch (e) {
    console.error("[interaction]", e);
    if (!res.headersSent) res.writeHead(400, { "content-type": "text/html" }).end(page("Error", `<pre>${esc(e.message)}</pre>`));
  }
}).listen(PORT, () => console.log(`AS ${ISSUER} on :${PORT}  resource=${MCP_RESOURCE}`));
