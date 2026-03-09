import { createClient } from "https://esm.sh/@supabase/supabase-js@2.97.0";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

type RpcError = { message: string } | null;
export type AddMemberRpc = (
  groupId: string,
  userId: string,
  roles: string[],
) => Promise<{ data: string | null; error: RpcError }>;

function buildDefaultAddMemberRpc(
  supabaseUrl: string,
  serviceRoleKey: string,
): AddMemberRpc {
  return async (groupId: string, userId: string, roles: string[]) => {
    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { persistSession: false },
    });

    return await admin.rpc("add_member", {
      p_group_id: groupId,
      p_user_id: userId,
      p_roles: roles,
    });
  };
}

export function createAddMemberHandler(options?: {
  supabaseUrl?: string | null;
  serviceRoleKey?: string | null;
  addMemberRpc?: AddMemberRpc;
  authorizeRequest?: (req: Request) => boolean;
}) {
  const supabaseUrl = options?.supabaseUrl ?? SUPABASE_URL;
  const serviceRoleKey = options?.serviceRoleKey ?? SUPABASE_SERVICE_ROLE_KEY;
  const addMemberRpc =
    options?.addMemberRpc ??
    (supabaseUrl && serviceRoleKey
      ? buildDefaultAddMemberRpc(supabaseUrl, serviceRoleKey)
      : null);
  const authorizeRequest = options?.authorizeRequest ?? (() => true);

  return async (req: Request) => {
    if (!(supabaseUrl && serviceRoleKey && addMemberRpc)) {
      console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY");
      return new Response("Server misconfiguration", { status: 500 });
    }

    if (req.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    if (!authorizeRequest(req)) {
      return new Response("Unauthorized", { status: 401 });
    }

    let group_id: string | null = null;
    let user_id: string | null = null;
    let roles: string[] | null = null;
    try {
      const payload = await req.json();
      group_id =
        payload && typeof payload.group_id === "string"
          ? payload.group_id
          : null;
      user_id =
        payload && typeof payload.user_id === "string"
          ? payload.user_id
          : null;
      roles =
        payload && Array.isArray(payload.roles) &&
        payload.roles.every((r: unknown) => typeof r === "string")
          ? payload.roles
          : null;
    } catch {
      // invalid JSON
    }

    if (!group_id || !user_id || !roles || roles.length === 0) {
      return new Response(
        "Missing or invalid group_id, user_id, or roles in JSON body",
        { status: 400 },
      );
    }

    const { data, error } = await addMemberRpc(group_id, user_id, roles);
    if (error) {
      console.error(`Error adding member: ${error.message}`);
      return new Response(JSON.stringify({ error: error.message }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    return new Response(JSON.stringify({ member_id: data }), {
      status: 201,
      headers: { "Content-Type": "application/json" },
    });
  };
}

/// Add a member to a group using service_role (admin-level operation).
/// The add_member() database function handles role validation and membership creation.
///
/// IMPORTANT — PostgREST schema routing:
/// rbac.add_member lives in the `rbac` schema, which is NOT in PostgREST's
/// default exposed schemas (public, graphql_public). The supabase-js .rpc()
/// call routes through PostgREST, so calling admin.rpc("add_member", ...)
/// will return a 404 unless you expose it via a public wrapper.
///
/// To make this edge function work, create a service-role-only wrapper:
///
///   CREATE OR REPLACE FUNCTION public.add_member(
///       p_group_id uuid, p_user_id uuid, p_roles text[] DEFAULT '{}'::text[]
///   )
///   RETURNS uuid LANGUAGE sql
///   SET search_path = rbac
///   AS $f$ SELECT rbac.add_member($1, $2, $3) $f$;
///
///   REVOKE EXECUTE ON FUNCTION public.add_member(uuid, uuid, text[]) FROM PUBLIC;
///   GRANT EXECUTE ON FUNCTION public.add_member(uuid, uuid, text[]) TO service_role;
///
/// This exposes add_member to PostgREST but restricts it to service_role only,
/// so authenticated clients cannot call it directly — only your edge functions
/// (which use the service_role key) can reach it.
///
/// See examples/setup/create_service_role_wrapper.sql for a ready-to-run script.

if (import.meta.main) {
  Deno.serve(createAddMemberHandler());
}

// To invoke:
// curl -i --location --request POST \
//   'http://localhost:54321/functions/v1/add-member' \
//   --header 'Content-Type: application/json' \
//   --data '{"group_id":"<uuid>","user_id":"<uuid>","roles":["editor"]}'
