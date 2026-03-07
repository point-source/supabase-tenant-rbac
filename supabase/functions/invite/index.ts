import { createClient } from "https://esm.sh/@supabase/supabase-js@2.97.0";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY");

type InviteRpcError = { message: string } | null;
type InviteRpc = (token: string, inviteCode: string) => Promise<{ error: InviteRpcError }>;

function buildDefaultInviteRpc(
  supabaseUrl: string,
  supabaseAnonKey: string,
): InviteRpc {
  return async (token: string, inviteCode: string) => {
    const userClient = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: `Bearer ${token}` } },
      auth: { persistSession: false },
    });

    return await userClient.rpc("accept_invite", {
      p_invite_id: inviteCode.trim(),
    });
  };
}

export function createInviteHandler(options?: {
  supabaseUrl?: string | null;
  supabaseAnonKey?: string | null;
  inviteRpc?: InviteRpc;
}) {
  const supabaseUrl = options?.supabaseUrl ?? SUPABASE_URL;
  const supabaseAnonKey = options?.supabaseAnonKey ?? SUPABASE_ANON_KEY;
  const inviteRpc =
    options?.inviteRpc ??
    (supabaseUrl && supabaseAnonKey
      ? buildDefaultInviteRpc(supabaseUrl, supabaseAnonKey)
      : null);

  return async (req: Request) => {
    if (!(supabaseUrl && supabaseAnonKey && inviteRpc)) {
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

    const { error } = await inviteRpc(token, invite_code);
    if (error) {
      console.error(`Error accepting invite ${invite_code}: ${error.message}`);
      return new Response("Unable to accept invite", { status: 400 });
    }

    return new Response(null, { status: 201 });
  };
}

/// Accept an invitation code and add the user to the group atomically via RPC.
/// The accept_invite() database function handles all invite validation,
/// the UPDATE + INSERT, and race-condition prevention inside a single transaction.
if (import.meta.main) {
  Deno.serve(createInviteHandler());
}

// To invoke:
// curl -i --location --request POST \
//   'http://localhost:54321/functions/v1/invite' \
//   --header 'Authorization: Bearer <user-jwt>' \
//   --header 'Content-Type: application/json' \
//   --data '{"invite_code":"<uuid>"}'
