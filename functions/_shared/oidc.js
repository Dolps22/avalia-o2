export async function validateGoogleIdToken(idToken, { audience, nonce }) {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("JWT malformado");

  const [headerB64, payloadB64, signatureB64] = parts;
  const header = JSON.parse(base64UrlDecode(headerB64));
  const payload = JSON.parse(base64UrlDecode(payloadB64));

  if (header.alg !== "RS256") throw new Error("Algoritmo inesperado");

  const discovery = await fetch("https://accounts.google.com/.well-known/openid-configuration")
    .then((r) => r.json());
  const jwks = await fetch(discovery.jwks_uri).then((r) => r.json());

  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error("Chave (kid) não encontrada no JWKS");

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signedData = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = base64UrlDecodeToBytes(signatureB64);
  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, signature, signedData);
  if (!valid) throw new Error("Assinatura inválida");

  const now = Math.floor(Date.now() / 1000);
  if (payload.iss !== discovery.issuer) throw new Error("Emissor (iss) inválido");
  if (payload.aud !== audience) throw new Error("Audiência (aud) inválida");
  if (payload.exp < now) throw new Error("Token expirado");
  if (!payload.iat || payload.iat > now + 60) throw new Error("Claim iat inválida"); // AJUSTE: PDF 13.5 item 8 pede validar iat
  if (payload.nonce !== nonce) throw new Error("Nonce não confere");

  return payload;
}

function base64UrlDecode(str) {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(str.length / 4) * 4, "=");
  return atob(padded);
}

function base64UrlDecodeToBytes(str) {
  const binary = base64UrlDecode(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
