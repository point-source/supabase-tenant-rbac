import { createClient } from "https://esm.sh/@supabase/supabase-js@2.97.0";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY");

/// Accept an invitation code and add the user to the group atomically via RPC.
/// The accept_invite() database function handles all invite validation,
/// the UPDATE + INSERT, and race-condition prevention inside a single transaction.
Deno.serve(async (req) => {
  if (!(SUPABASE_URL && SUPABASE_ANON_KEY)) {
    console.error("Missing SUPABASE_URL or SUPABASE_ANON_KEY");
    return new Response("Server misconfiguration", { status: 500 });
  }

  if (req.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  // Require an explicit Bearer token.
  const authHeader = req.headers.get("Authorization") ?? "";
  const tokenMatch = authHeader.match(/^Bearer\s+(.+)$/i);
  const token = tokenMatch?.[1]?.trim();
  if (!token) {
    return new Response("Missing or invalid Authorization header", { status: 401 });
  }

  // Prefer request body over query params to avoid invite-code leakage in logs/URLs.
  let invite_code: string | null = null;
  try {
    const payload = await req.json();
    invite_code =
      payload && typeof payload.invite_code === "string"
        ? payload.invite_code
        : null;
  } catch {
    invite_code = null;
  }

  if (!invite_code) {
    return new Response("Missing invite_code in JSON body", { status: 400 });
  }

  // Create a client using the user's own JWT (not service_role) so that
  // auth.uid() resolves correctly inside accept_invite().
  const userClient = createClient(SUPABASE_URL!, SUPABASE_ANON_KEY!, {
    global: { headers: { Authorization: `Bearer ${token}` } },
    auth: { persistSession: false },
  });

  const { error } = await userClient.rpc("accept_invite", {
    p_invite_id: invite_code.trim(),
  });

  if (error) {
    console.error(`Error accepting invite ${invite_code}: ${error.message}`);
    return new Response("Unable to accept invite", { status: 400 });
  }

  return new Response(null, { status: 201 });
});

// To invoke:
// curl -i --location --request POST \
//   'http://localhost:54321/functions/v1/invite' \
//   --header 'Authorization: Bearer <user-jwt>' \
//   --header 'Content-Type: application/json' \
//   --data '{"invite_code":"<uuid>"}'
