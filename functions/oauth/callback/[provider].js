import { sha256Hex, randomToken } from "../../_shared/crypto.js";
import { getCookie, clearTxCookie, setSessionCookie } from "../../_shared/cookies.js";
import { PROVIDERS, clientIdFor, clientSecretFor } from "../../_shared/providers.js";
import { validateGoogleIdToken } from "../../_shared/oidc.js";

const NO_STORE = { "Cache-Control": "no-store" };
const fail = (message, status = 400) =>
  new Response(message, { status, headers: NO_STORE }); 

export async function onRequestGet(context) {
  const { provider } = context.params;
  if (provider !== "google" && provider !== "github") {
    return fail("Not found", 404);
  }

  const url = new URL(context.request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");
  if (error || !code || !state) {
    return fail("Requisição inválida");
  }

  const txCookie = getCookie(context.request, "__Host-oauth-tx");
  if (!txCookie) return fail("Transação ausente");

  const txHash = await sha256Hex(txCookie);
  const stateHash = await sha256Hex(state);
  const now = Math.floor(Date.now() / 1000);

  const tx = await context.env.DB.prepare(
    `SELECT * FROM oauth_transactions WHERE id_hash = ? AND provider = ? AND expires_at > ?`
  ).bind(txHash, provider, now).first();

  if (!tx || tx.state_hash !== stateHash) {
    return fail("Transação inválida ou expirada");
  }

  await context.env.DB.prepare(`DELETE FROM oauth_transactions WHERE id_hash = ?`).bind(txHash).run();

  const cfg = PROVIDERS[provider];
  const clientId = clientIdFor(provider, context.env);
  const clientSecret = clientSecretFor(provider, context.env);
  const redirectUri = `${context.env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;

  const tokenResponse = await fetch(cfg.tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
      code_verifier: tx.code_verifier,
    }),
  });
  if (!tokenResponse.ok) return fail("Falha na troca de tokens");
  const tokenData = await tokenResponse.json();

  let issuer, subject, email = null, displayName = null;

  if (provider === "google") {
    let claims;
    try { 
      claims = await validateGoogleIdToken(tokenData.id_token, {
        audience: clientId,
        nonce: tx.nonce,
      });
    } catch (e) { // Variável (e) adicionada por precaução de compatibilidade
      return fail("Identidade não confirmada");
    }
    issuer = "https://accounts.google.com";
    subject = claims.sub;
    email = claims.email ?? null;
    displayName = claims.name ?? null;
  } else {
    if (!tokenData.access_token || !/^bearer$/i.test(tokenData.token_type || "")) {
      return fail("Resposta de token inválida");
    }
    const userResponse = await fetch(cfg.userEndpoint, {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", 
        "User-Agent": "avalia-o2-oauth-lab",  
      },
    });
    if (userResponse.status !== 200) return fail("Falha ao consultar perfil");
    const profile = await userResponse.json();
    if (!Number.isInteger(profile.id)) return fail("Falha ao consultar perfil"); 

    issuer = "https://github.com";
    subject = String(profile.id);
    email = profile.email ?? null;
    displayName = profile.name || profile.login;

    const revokeResponse = await fetch(cfg.revokeEndpoint(clientId), {
      method: "DELETE",
      headers: {
        Authorization: "Basic " + btoa(`${clientId}:${clientSecret}`),
        "Content-Type": "application/json",
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "avalia-o2-oauth-lab",
      },
      body: JSON.stringify({ access_token: tokenData.access_token }),
    });
    if (revokeResponse.status !== 204) { 
      return fail("Falha ao revogar autorização");
    }
  }

  const sessionValue = randomToken();
  const sessionExpires = now + 28800;
  await context.env.DB.prepare(
    `INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(await sha256Hex(sessionValue), issuer, subject, email, displayName, sessionExpires, now).run();

  const headers = new Headers();
  headers.set("Location", context.env.PUBLIC_BASE_URL);
  headers.append("Set-Cookie", setSessionCookie(sessionValue));
  headers.append("Set-Cookie", clearTxCookie());
  headers.set("Cache-Control", "no-store");

  return new Response(null, { status: 302, headers });
}
