// Follow this setup guide to integrate the Deno language server with your editor:
// https://deno.land/manual/getting_started/setup_your_environment
// This enables autocomplete, go to definition, etc.

import { json, opine } from "https://deno.land/x/opine@2.3.4/mod.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.97.0";
import { verify } from "https://deno.land/x/djwt@v3.0.2/mod.ts";

const env = Deno.env.toObject();

const SUPABASE_URL = env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = env.SUPABASE_SERVICE_ROLE_KEY;
const SB_JWT_SECRET = env.SB_JWT_SECRET;

if (
  !(
    SUPABASE_URL &&
    SUPABASE_SERVICE_ROLE_KEY &&
    SB_JWT_SECRET
  )
) {
  console.log("A secret is missing");
}

const app = opine();
app.use(json());

/// Accept an invitation code and add the user to the group
app.post("/invite/accept", function (request, response, next) {
  Promise.resolve()
    .then(async function () {
      // Get the token from the Authorization header
      const token = request.headers.get("Authorization")?.replace(
        "Bearer ",
        "",
      );
      if (!token) return response.setStatus(400).send("No authorization token");

      // Get the invite code from the query string
      const invite_code = request.query.invite_code;
      if (!invite_code) {
        return response.setStatus(400).send("No invite code provided");
      }

      // Verify the token
      const encoder = new TextEncoder();
      const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(SB_JWT_SECRET),
        { name: "HMAC", hash: "SHA-256" },
        true,
        ["verify"],
      );
      const user = await verify(token, key);
      if (!user?.sub) {
        console.log("User ID could not be retrieved from token.");
        return response.setStatus(500).send("User ID could not be retrieved");
      }

      // Add the user to the group
      const supabase = createClient(
        SUPABASE_URL,
        SUPABASE_SERVICE_ROLE_KEY,
      );

      const res = await supabase.from("group_invites")
        .update({
          user_id: user.sub,
          accepted_at: new Date().toISOString(),
        })
        .eq("id", invite_code)
        .is("user_id", null)
        .is("accepted_at", null)
        // Reject expired invites; null expires_at means the invite never expires
        .or(`expires_at.is.null,expires_at.gt.${new Date().toISOString()}`)
        .select("id, group_id, roles");

      if (res.error != null || res.data[0] == null) {
        console.log(
          `Invite code not found: ${invite_code}.`,
          `Error: ${res.error?.message || "none"}.`,
          `Data: ${res.data}`,
        );
        return response.setStatus(500).send("Invalid invite code");
      }

      const group_users = res.data[0].roles.map((role: string) => ({
        user_id: user.sub,
        group_id: res.data[0].group_id,
        role: role,
      }));

      if (group_users.length == 0) {
        console.log(`No roles assigned for invite code: ${invite_code}.`);
        return response.setStatus(500).send(
          "No roles assigned for invite code",
        );
      }

      const res2 = await supabase.from("group_users")
        .upsert(group_users, {
          onConflict: "group_id,user_id,role",
          ignoreDuplicates: true,
        });

      if (res2.error != null) {
        console.log(
          `Error adding user to group: ${res2.error?.message || "none"}.`,
          `Data: ${JSON.stringify(group_users)}`,
        );
        return response.setStatus(500).send("Error adding user to group");
      } else {
        return response.setStatus(201).send(); // Created
      }
    })
    .catch(next);
});

// deno-lint-ignore no-explicit-any
app.use(function (err: any, _req: any, res: any, _next: any) {
  console.error(err.stack);
  res.status(500).send("Something broke!");
});

app.listen(8000);

// To invoke:
// curl -i --location --request POST 'http://localhost:54321/functions/v1/' \
//   --header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0' \
//   --header 'Content-Type: application/json' \
//   --data '{"name":"Functions"}'
