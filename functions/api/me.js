import { sha256Hex } from "../_shared/crypto.js";
import { getCookie } from "../_shared/cookies.js";

const NO_STORE = { "Cache-Control": "no-store" };

export async function onRequestGet(context) {
  const cookie = getCookie(context.request, "__Host-session");
  if (!cookie) return new Response("Não autenticado", { status: 401, headers: NO_STORE }); 

  const now = Math.floor(Date.now() / 1000);
  const session = await context.env.DB.prepare(
    `SELECT * FROM sessions WHERE id_hash = ? AND expires_at > ?`
  ).bind(await sha256Hex(cookie), now).first();

  if (!session) return new Response("Não autenticado", { status: 401, headers: NO_STORE }); 

  return Response.json(
    { email: session.email, displayName: session.display_name },
    { headers: NO_STORE }
  );
}
