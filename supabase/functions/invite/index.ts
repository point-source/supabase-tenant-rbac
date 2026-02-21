import { createClient } from "https://esm.sh/@supabase/supabase-js@2.97.0";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY");

if (!(SUPABASE_URL && SUPABASE_ANON_KEY)) {
  console.log("A required environment variable is missing");
}

/// Accept an invitation code and add the user to the group atomically via RPC.
/// The accept_group_invite() database function handles all invite validation,
/// the UPDATE + INSERT, and race-condition prevention inside a single transaction.
Deno.serve(async (req) => {
  if (req.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  // Get the token from the Authorization header
  const token = req.headers.get("Authorization")?.replace("Bearer ", "");
  if (!token) {
    return new Response("No authorization token", { status: 400 });
  }

  // Get the invite code from the query string
  const url = new URL(req.url);
  const invite_code = url.searchParams.get("invite_code");
  if (!invite_code) {
    return new Response("No invite code provided", { status: 400 });
  }

  // Create a client using the user's own JWT (not service_role) so that
  // auth.uid() resolves correctly inside accept_group_invite().
  const userClient = createClient(SUPABASE_URL!, SUPABASE_ANON_KEY!, {
    global: { headers: { Authorization: `Bearer ${token}` } },
    auth: { persistSession: false },
  });

  const { error } = await userClient.rpc("accept_group_invite", {
    p_invite_id: invite_code,
  });

  if (error) {
    console.error(`Error accepting invite ${invite_code}: ${error.message}`);
    return new Response(error.message, { status: 400 });
  }

  return new Response(null, { status: 201 });
});

// To invoke:
// curl -i --location --request POST \
//   'http://localhost:54321/functions/v1/invite?invite_code=<uuid>' \
//   --header 'Authorization: Bearer <user-jwt>'
