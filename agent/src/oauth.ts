/**
 * Minimal OAuth 2.1 public client (auth code + PKCE) driven by Bearer challenges.
 *
 *   WWW-Authenticate ─▶ resource_metadata (RFC 9728) ─▶ authorization_servers[0]
 *   ─▶ AS metadata (OIDC discovery / RFC 8414) ─▶ /authorize (browser) ─▶ /token
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
  raw: string;
};

export class AuthorizationDenied extends Error {}

/** Parse `Bearer k="v", k2="v2"` (RFC 6750 §3). */
export function parseBearerChallenge(status: number, header: string | null): Challenge | undefined {
  if (!header || !/^Bearer\b/i.test(header)) return undefined;
  const params: Record<string, string> = {};
  for (const m of header.matchAll(/([a-zA-Z_]+)="((?:[^"\\]|\\.)*)"/g)) params[m[1]] = m[2];
  return {
    status,
    error: params.error,
    scope: params.scope?.split(" ").filter(Boolean),
    resourceMetadata: params.resource_metadata,
    description: params.error_description,
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

type AsMetadata = { issuer: string; authorization_endpoint: string; token_endpoint: string };

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

  get token() {
    return this.accessToken;
  }
  get scopes() {
    return this.grantedScopes;
  }

  /** Single-flight: concurrent requests hitting a challenge share one authorization. */
  authorize(ch: Challenge): Promise<void> {
    this.inflight ??= this.runAuthorization(ch).finally(() => (this.inflight = undefined));
    return this.inflight;
  }

  private async runAuthorization(ch: Challenge) {
    // 1. Discover AS from the protected resource metadata.
    if (ch.resourceMetadata) {
      const prm = await getJson(backchannel(ch.resourceMetadata));
      log.oauth(`PRM ${ch.resourceMetadata} -> resource=${prm.resource} as=${prm.authorization_servers?.[0]}`);
      this.resource = prm.resource;
      const issuer: string = prm.authorization_servers[0];
      if (!this.asMeta || this.asMeta.issuer !== issuer) {
        this.asMeta = await getJson(backchannel(`${issuer}/.well-known/openid-configuration`));
        if (this.asMeta!.issuer !== issuer) throw new Error(`issuer mismatch: ${this.asMeta!.issuer} != ${issuer}`);
      }
      ch.scope ??= prm.scopes_supported;
    }
    if (!this.asMeta) throw new Error("no authorization server known; challenge lacked resource_metadata");

    // 2. Scope. The server's `scope` in an insufficient_scope challenge is authoritative: it already
    //    includes what we hold that is still useful and drops stale per-operation scopes. Without
    //    one, keep what we hold and add what metadata suggests.
    const scope = (
      ch.status === 403 && ch.scope?.length ? ch.scope : [...new Set([...this.grantedScopes, ...(ch.scope ?? [])])]
    ).join(" ");
    const isStepUp = ch.status === 403;

    // 3. Authorization code + PKCE through the user's browser.
    const verifier = b64url(randomBytes(32));
    const state = b64url(randomBytes(16));
    const authUrl = new URL(this.asMeta.authorization_endpoint);
    authUrl.search = new URLSearchParams({
      response_type: "code",
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      scope,
      state,
      code_challenge: b64url(createHash("sha256").update(verifier).digest()),
      code_challenge_method: "S256",
      // Step-up authorizes a specific operation: always show the consent screen, even if the AS
      // remembers consent for the (parameterized) scope family.
      ...(isStepUp ? { prompt: "consent" } : {}),
      ...(this.resource ? { resource: this.resource } : {}), // RFC 8707, required by MCP auth spec
    }).toString();

    log.oauth(
      ch.status === 403
        ? `STEP-UP needed (${ch.error}): ${ch.description ?? ""}\n   requesting scope="${scope}"`
        : `authentication needed (${ch.status}) requesting scope="${scope}"`,
    );
    log.prompt(`Open this URL in your browser to continue:\n\n   ${authUrl}\n`);

    const code = await this.waitForCallback(state);

    // 4. Token request (back-channel).
    const tokenRes = await fetch(backchannel(this.asMeta.token_endpoint), {
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
    this.accessToken = tok.access_token;
    this.grantedScopes = String(tok.scope ?? scope).split(" ").filter(Boolean);
    log.oauth(`token issued, scope="${this.grantedScopes.join(" ")}" expires_in=${tok.expires_in}s`);
  }

  /** One long-lived redirect_uri listener; pending authorizations are keyed by `state`. */
  private callbackServer?: Server;
  private pending = new Map<string, { resolve: (code: string) => void; reject: (e: Error) => void }>();

  private waitForCallback(state: string): Promise<string> {
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
      p.resolve(u.searchParams.get("code")!);
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
