import { sha256Hex } from "../_shared/crypto.js";
import { getCookie, clearSessionCookie } from "../_shared/cookies.js";

const NO_STORE = { "Cache-Control": "no-store" };

export async function onRequestPost(context) {
  const origin = context.request.headers.get("Origin");
  if (origin !== context.env.PUBLIC_BASE_URL) {
    return new Response("Origem não permitida", { status: 403, headers: NO_STORE }); 
  }

  const cookie = getCookie(context.request, "__Host-session");
  if (cookie) {
    await context.env.DB.prepare(`DELETE FROM sessions WHERE id_hash = ?`)
      .bind(await sha256Hex(cookie)).run();
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: context.env.PUBLIC_BASE_URL,
      "Set-Cookie": clearSessionCookie(),
      "Cache-Control": "no-store",
    },
  });
}
