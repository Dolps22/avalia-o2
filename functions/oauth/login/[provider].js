import { randomToken, sha256Hex, pkceChallenge } from "../../_shared/crypto.js";
import { setTxCookie } from "../../_shared/cookies.js";
import { PROVIDERS, clientIdFor } from "../../_shared/providers.js";

export async function onRequestGet(context) {
  const { provider } = context.params;
  if (provider !== "google" && provider !== "github") {
    return new Response("Not found", { status: 404 });
  }

  const cfg = PROVIDERS[provider];
  const clientId = clientIdFor(provider, context.env);
  const baseUrl = context.env.PUBLIC_BASE_URL;

  const txValue = randomToken();
  const state = randomToken();
  const codeVerifier = randomToken();
  const codeChallenge = await pkceChallenge(codeVerifier);
  const nonce = provider === "google" ? randomToken() : null;

  const expiresAt = Math.floor(Date.now() / 1000) + 600;

  await context.env.DB.prepare(
    `INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(
    await sha256Hex(txValue),
    provider,
    await sha256Hex(state),
    nonce,
    codeVerifier,
    expiresAt
  ).run();

  const redirectUri = `${baseUrl}/oauth/callback/${provider}`;
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  });
  if (provider === "google") {
    params.set("scope", cfg.scope);
    params.set("nonce", nonce);
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: `${cfg.authEndpoint}?${params.toString()}`,
      "Set-Cookie": setTxCookie(txValue),
      "Cache-Control": "no-store",
    },
  });
}
