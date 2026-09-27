import { sha256Hex, randomToken } from "../../_shared/crypto.js";
import { getCookie, clearTxCookie, setSessionCookie } from "../../_shared/cookies.js";
import { PROVIDERS, clientIdFor, clientSecretFor } from "../../_shared/providers.js";
import { validateGoogleIdToken } from "../../_shared/oidc.js";

export async function onRequestGet(context) {
  const { provider } = context.params;
  if (provider !== "google" && provider !== "github") {
    return new Response("Not found", { status: 404 });
  }

  const url = new URL(context.request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");
  if (error || !code || !state) {
    return new Response("Requisição inválida", { status: 400 });
  }

  const txCookie = getCookie(context.request, "__Host-oauth-tx");
  if (!txCookie) return new Response("Transação ausente", { status: 400 });

  const txHash = await sha256Hex(txCookie);
  const stateHash = await sha256Hex(state);
  const now = Math.floor(Date.now() / 1000);

  const tx = await context.env.DB.prepare(
    `SELECT * FROM oauth_transactions WHERE id_hash = ? AND provider = ? AND expires_at > ?`
  ).bind(txHash, provider, now).first();

  if (!tx || tx.state_hash !== stateHash) {
    return new Response("Transação inválida ou expirada", { status: 400 });
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
  if (!tokenResponse.ok) return new Response("Falha na troca de tokens", { status: 400 });
  const tokenData = await tokenResponse.json();

  let issuer, subject, email = null, displayName = null;

  if (provider === "google") {
    const claims = await validateGoogleIdToken(tokenData.id_token, {
      audience: clientId,
      nonce: tx.nonce,
    });
    issuer = "https://accounts.google.com";
    subject = claims.sub;
    email = claims.email ?? null;
    displayName = claims.name ?? null;
  } else {
    if (!tokenData.access_token || !/^bearer$/i.test(tokenData.token_type || "")) {
      return new Response("Resposta de token inválida", { status: 400 });
    }
    const userResponse = await fetch(cfg.userEndpoint, {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "avalia-o2-oauth-lab",
      },
    });
    if (userResponse.status !== 200) {
  const errBody = await userResponse.text();
  return new Response(`Falha ao consultar perfil: status=${userResponse.status} body=${errBody}`, { status: 400 });
}

    issuer = "https://github.com";
    subject = String(profile.id);
    email = profile.email ?? null;
    displayName = profile.name || profile.login;

    await fetch(cfg.revokeEndpoint(clientId), {
      method: "DELETE",
      headers: {
        Authorization: "Basic " + btoa(`${clientId}:${clientSecret}`),
        "Content-Type": "application/json",
        Accept: "application/vnd.github+json",
      },
      body: JSON.stringify({ access_token: tokenData.access_token }),
    });
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
