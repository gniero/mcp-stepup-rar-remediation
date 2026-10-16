/**
 * Minimal OAuth 2.1 public client (auth code + PKCE) driven by Bearer challenges.
 *
 *   WWW-Authenticate ─▶ resource_metadata (RFC 9728) ─▶ authorization_servers[0]
 *   ─▶ AS metadata (OIDC discovery / RFC 8414) ─▶ /authorize (browser) ─▶ /token
 *
 * Two kinds of grants:
 *  - Session grant (scope=mcp:basic): obtained on 401 without error / invalid_token, or on 403
 *    insufficient_scope. Stored and used for every MCP request.
 *  - One-shot operation grant (authorization_details only, NO scope): obtained from an
 *    `insufficient_authorization` remediation (draft-ietf-oauth-rar-metadata-remediation).
 *    Returned to the caller for a single replay and never stored; the session token is untouched.
 */
import { createServer, type Server } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { log } from "./log.ts";

export type Challenge = {
  status: number;
  error?: string;
  scope?: string[];
  resourceMetadata?: string;
  description?: string;
  /** Decoded `authorization_remediation` (base64url JSON) when present. */
  remediation?: { authorization_details?: AuthorizationDetail[]; authorization_reference?: string };
  raw: string;
};
export type AuthorizationDetail = { type: string; [k: string]: unknown };

export class AuthorizationDenied extends Error {}

/** Parse `Bearer k="v", k2=token68ish` (RFC 6750 §3; auth-param values may be token or quoted-string). */
export function parseBearerChallenge(status: number, header: string | null): Challenge | undefined {
  if (!header || !/^Bearer\b/i.test(header)) return undefined;
  const params: Record<string, string> = {};
  for (const m of header.matchAll(/([a-zA-Z_]+)=(?:"((?:[^"\\]|\\.)*)"|([^\s,"]+))/g)) params[m[1]] = m[2] ?? m[3];
  let remediation: Challenge["remediation"];
  if (params.authorization_remediation) {
    try {
      remediation = JSON.parse(Buffer.from(params.authorization_remediation, "base64url").toString("utf8"));
    } catch {
      remediation = undefined; // malformed: treated as non-remediable by the caller
    }
  }
  return {
    status,
    error: params.error,
    scope: params.scope?.split(" ").filter(Boolean),
    resourceMetadata: params.resource_metadata,
    description: params.error_description,
    remediation,
    raw: header,
  };
}

const b64url = (b: Buffer) => b.toString("base64url");

/** Front-channel URLs (browser) vs back-channel URLs (container network). */
const rewrites = (process.env.BACKCHANNEL_REWRITE ?? "")
  .split(",")
  .filter(Boolean)
  .map((p) => p.split("=") as [string, string]);
const backchannel = (url: string) => rewrites.reduce((u, [from, to]) => (u.startsWith(from) ? to + u.slice(from.length) : u), url);

type AsMetadata = {
  issuer: string;
  authorization_response_iss_parameter_supported?: boolean;
  authorization_endpoint: string;
  token_endpoint: string;
  authorization_details_types_supported?: string[];
};

type TokenResponse = {
  access_token: string;
  expires_in?: number;
  scope?: string;
  authorization_details?: AuthorizationDetail[];
};

export class OAuthSession {
  private accessToken?: string;
  private grantedScopes: string[] = [];
  private inflight?: Promise<void>;
  private asMeta?: AsMetadata;
  private resource?: string;

  private readonly clientId: string;
  private readonly redirectUri: string;
  private readonly callbackPort: number;

  constructor(clientId: string, redirectUri: string, callbackPort: number) {
    this.clientId = clientId;
    this.redirectUri = redirectUri;
    this.callbackPort = callbackPort;
  }

  /**
   * One-shot token waiting for the retry of a specific operation: the in-band retry names the
   * operation in _meta; the MRTR retry echoes the requestState the authorization step came with.
   */
  private armed?: { token: string; operationId?: string; requestState?: string };

  armOneShot(token: string, match: { operationId?: string; requestState?: string }) {
    this.armed = { token, ...match };
  }

  /** Hand out the armed token once, only to the JSON-RPC request it was obtained for. */
  takeArmedOneShot(body: any): string | undefined {
    const a = this.armed;
    if (!a || body?.method !== "tools/call") return undefined;
    const matches =
      (a.operationId !== undefined && body.params?._meta?.["lab.stepup/operation_id"] === a.operationId) ||
      (a.requestState !== undefined && body.params?.requestState === a.requestState);
    if (!matches) return undefined;
    this.armed = undefined;
    return a.token;
  }

  /** The session token (baseline scope). Never replaced by a one-shot token. */
  get token() {
    return this.accessToken;
  }
  get scopes() {
    return this.grantedScopes;
  }

  // ---- Session grant -------------------------------------------------------------

  /** Single-flight: concurrent requests hitting a challenge share one authorization. */
  authorize(ch: Challenge): Promise<void> {
    this.inflight ??= this.runSessionAuthorization(ch).finally(() => (this.inflight = undefined));
    return this.inflight;
  }

  private async runSessionAuthorization(ch: Challenge) {
    const prmScopes = await this.discover(ch.resourceMetadata);
    // On 403 insufficient_scope the server's scope list is authoritative; otherwise keep what we
    // hold and add what the challenge / metadata suggest.
    const requested =
      ch.status === 403 && ch.scope?.length ? ch.scope : [...new Set([...this.grantedScopes, ...(ch.scope ?? prmScopes ?? [])])];
    const scope = requested.join(" ");

    log.oauth(`authentication needed (${ch.status}${ch.error ? ` ${ch.error}` : ""}) requesting scope="${scope}"`);
    const tok = await this.codeFlow({ scope });
    this.accessToken = tok.access_token;
    this.grantedScopes = String(tok.scope ?? scope).split(" ").filter(Boolean);
    log.oauth(`session token issued, scope="${this.grantedScopes.join(" ")}" expires_in=${tok.expires_in}s`);
  }

  // ---- One-shot operation grant (RAR remediation) ------------------------------------

  /**
   * draft-ietf-oauth-rar-metadata-remediation §7.1 step 3: send the remediation's
   * authorization_details in a new authorization request (RFC 9396). Deliberately NO `scope`:
   * the resulting token must authorize this operation and nothing else.
   */
  async authorizeOperation(ch: Challenge): Promise<string> {
    const details = ch.remediation?.authorization_details;
    if (!details?.length) throw new Error("insufficient_authorization without authorization_details: not remediable");
    await this.discover(ch.resourceMetadata);
    const unsupported = details.filter((d) => !this.asMeta!.authorization_details_types_supported?.includes(d.type));
    if (unsupported.length) throw new Error(`AS does not support authorization_details type(s): ${unsupported.map((d) => d.type).join(", ")}`);

    log.oauth(
      `OPERATION AUTHORIZATION needed (${ch.error}): ${ch.description ?? ""}\n` +
        `   authorization_details=${JSON.stringify(details)}\n` +
        `   (no scope requested: one-shot token; session token kept for everything else)`,
    );
    const tok = await this.codeFlow({ authorization_details: JSON.stringify(details) });
    log.oauth(
      `one-shot token issued, scope="${tok.scope ?? ""}" authorization_details=${JSON.stringify(tok.authorization_details)} ` +
        `expires_in=${tok.expires_in}s (used for ONE replay, then discarded)`,
    );
    return tok.access_token;
  }

  // ---- Shared plumbing -------------------------------------------------------------

  /** PRM -> AS metadata. Returns the PRM's scopes_supported. */
  private async discover(resourceMetadata?: string): Promise<string[] | undefined> {
    if (!resourceMetadata) {
      if (!this.asMeta) throw new Error("no authorization server known; challenge lacked resource_metadata");
      return undefined;
    }
    const prm = await getJson(backchannel(resourceMetadata));
    log.oauth(`PRM ${resourceMetadata} -> resource=${prm.resource} as=${prm.authorization_servers?.[0]}`);
    this.resource = prm.resource;
    const issuer: string = prm.authorization_servers[0];
    if (!this.asMeta || this.asMeta.issuer !== issuer) {
      const meta: AsMetadata = await getJson(backchannel(`${issuer}/.well-known/openid-configuration`));
      if (meta.issuer !== issuer) throw new Error(`issuer mismatch: ${meta.issuer} != ${issuer}`);
      this.asMeta = meta;
    }
    return prm.scopes_supported;
  }

  /** Authorization code + PKCE through the user's browser, then the token request. */
  private async codeFlow(extra: Record<string, string>): Promise<TokenResponse> {
    const verifier = b64url(randomBytes(32));
    const state = b64url(randomBytes(16));
    const authUrl = new URL(this.asMeta!.authorization_endpoint);
    authUrl.search = new URLSearchParams({
      response_type: "code",
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      state,
      code_challenge: b64url(createHash("sha256").update(verifier).digest()),
      code_challenge_method: "S256",
      ...extra,
      ...(this.resource ? { resource: this.resource } : {}), // RFC 8707, required by MCP auth spec
    }).toString();
    log.prompt(`Open this URL in your browser to continue:\n\n   ${authUrl}\n`);

    const { code, iss } = await this.waitForCallback(state);
    // RFC 9207 (MCP 2026-07-28: clients MUST validate a present `iss` before redeeming the code;
    // an AS that advertises support must send it). Defends against AS mix-up.
    if (iss !== undefined ? iss !== this.asMeta!.issuer : this.asMeta!.authorization_response_iss_parameter_supported)
      throw new Error(`authorization response issuer mismatch: got ${iss ?? "(none)"}, expected ${this.asMeta!.issuer}`);

    const tokenRes = await fetch(backchannel(this.asMeta!.token_endpoint), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: this.redirectUri,
        client_id: this.clientId,
        code_verifier: verifier,
        ...(this.resource ? { resource: this.resource } : {}),
      }),
    });
    const tok = await tokenRes.json();
    if (!tokenRes.ok) throw new Error(`token endpoint: ${JSON.stringify(tok)}`);
    return tok;
  }

  /** One long-lived redirect_uri listener; pending authorizations are keyed by `state`. */
  private callbackServer?: Server;
  private pending = new Map<string, { resolve: (r: { code: string; iss?: string }) => void; reject: (e: Error) => void }>();

  private waitForCallback(state: string): Promise<{ code: string; iss?: string }> {
    this.callbackServer ??= createServer((req, res) => {
      const u = new URL(req.url ?? "/", this.redirectUri);
      if (u.pathname !== new URL(this.redirectUri).pathname) return void res.writeHead(404).end();
      const reply = (msg: string) =>
        res.writeHead(200, { "content-type": "text/html" }).end(`<p>${msg}</p><p>You can close this tab.</p>`);
      const p = this.pending.get(u.searchParams.get("state") ?? "");
      if (!p) return reply("Unknown or already used state.");
      this.pending.delete(u.searchParams.get("state")!);
      const err = u.searchParams.get("error");
      if (err) {
        reply(`Authorization failed: ${err}`);
        return p.reject(new AuthorizationDenied(`${err}: ${u.searchParams.get("error_description") ?? ""}`));
      }
      reply("Authorized. Back to the agent.");
      p.resolve({ code: u.searchParams.get("code")!, iss: u.searchParams.get("iss") ?? undefined });
    }).listen(this.callbackPort, "0.0.0.0");
    this.callbackServer.unref();
    return new Promise((resolve, reject) => this.pending.set(state, { resolve, reject }));
  }
}

async function getJson(url: string) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`GET ${url} -> ${r.status}`);
  return r.json();
}
