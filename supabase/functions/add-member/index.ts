import { createClient } from "https://esm.sh/@supabase/supabase-js@2.97.0";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
const ADD_MEMBER_ALLOWED_APP_ROLES = Deno.env.get("ADD_MEMBER_ALLOWED_APP_ROLES");

type RpcError = {
  message: string;
  code?: string;
  details?: string;
  hint?: string;
} | null;
type AuthError = { message: string } | null;
type AuthUser = {
  app_metadata?: {
    is_super_admin?: boolean;
    role?: string;
    roles?: string[];
  } | null;
} | null;
type AuthorizeRequest = (req: Request) => boolean | Promise<boolean>;
type GetUserByToken = (
  token: string,
) => Promise<{ user: AuthUser; error: AuthError }>;
export type AddMemberRpc = (
  groupId: string,
  userId: string,
  roles: string[],
) => Promise<{ data: string | null; error: RpcError }>;

function buildDefaultAddMemberRpc(
  supabaseUrl: string,
  serviceRoleKey: string,
): AddMemberRpc {
  let admin: ReturnType<typeof createClient<any, any, any>> | null = null;

  return async (groupId: string, userId: string, roles: string[]) => {
    if (!admin) {
      admin = createClient(supabaseUrl, serviceRoleKey, {
        auth: { persistSession: false },
      });
    }

    return await admin.rpc("add_member", {
      p_group_id: groupId,
      p_user_id: userId,
      p_roles: roles,
    });
  };
}

function parseAllowedRoles(raw: string | null | undefined): string[] {
  const roles = (raw ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);

  return roles;
}

function buildDefaultGetUserByToken(
  supabaseUrl: string,
  serviceRoleKey: string,
): GetUserByToken {
  let admin: ReturnType<typeof createClient<any, any, any>> | null = null;

  return async (token: string) => {
    if (!admin) {
      admin = createClient(supabaseUrl, serviceRoleKey, {
        auth: { persistSession: false },
      });
    }

    const { data, error } = await admin.auth.getUser(token);
    return { user: data.user as AuthUser, error: error as AuthError };
  };
}

function parseBearerToken(req: Request): string | null {
  const authHeader = req.headers.get("Authorization") ?? "";
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  const token = match?.[1]?.trim();
  return token && token.length > 0 ? token : null;
}

function buildDefaultAuthorizeRequest(
  getUserByToken: GetUserByToken,
  allowedRoles: string[],
): AuthorizeRequest {
  return async (req: Request) => {
    const token = parseBearerToken(req);
    if (!token) return false;

    const { user, error } = await getUserByToken(token);
    if (error || !user) return false;

    if (user.app_metadata?.is_super_admin === true) {
      return true;
    }

    const appRoles = new Set<string>();
    const singleRole = user.app_metadata?.role;
    if (typeof singleRole === "string" && singleRole.length > 0) {
      appRoles.add(singleRole);
    }

    const rolesArray = user.app_metadata?.roles;
    if (Array.isArray(rolesArray)) {
      for (const role of rolesArray) {
        if (typeof role === "string" && role.length > 0) appRoles.add(role);
      }
    }

    return allowedRoles.some((allowedRole) => appRoles.has(allowedRole));
  };
}

function statusForRpcError(error: NonNullable<RpcError>): number {
  const code = (error.code ?? "").toUpperCase();
  const message = error.message.toLowerCase();

  if (
    code === "42501" ||
    message.includes("permission denied") ||
    message.includes("not allowed")
  ) {
    return 403;
  }

  if (
    message.includes("not authenticated") ||
    message.includes("unauthorized") ||
    message.includes("jwt")
  ) {
    return 401;
  }

  if (
    code === "22P02" ||
    code === "23503" ||
    code === "23505" ||
    message.includes("undefined role") ||
    message.includes("not found") ||
    message.includes("invalid")
  ) {
    return 400;
  }

  return 500;
}

export function createAddMemberHandler(options?: {
  supabaseUrl?: string | null;
  serviceRoleKey?: string | null;
  addMemberRpc?: AddMemberRpc;
  authorizeRequest?: AuthorizeRequest;
  getUserByToken?: GetUserByToken;
  allowedAppRoles?: string[];
}) {
  const supabaseUrl = options?.supabaseUrl ?? SUPABASE_URL;
  const serviceRoleKey = options?.serviceRoleKey ?? SUPABASE_SERVICE_ROLE_KEY;
  const addMemberRpc =
    options?.addMemberRpc ??
    (supabaseUrl && serviceRoleKey
      ? buildDefaultAddMemberRpc(supabaseUrl, serviceRoleKey)
      : null);
  let authorizeRequest: AuthorizeRequest;
  if (options?.authorizeRequest) {
    authorizeRequest = options.authorizeRequest;
  } else {
    const getUserByToken =
      options?.getUserByToken ??
      (supabaseUrl && serviceRoleKey
        ? buildDefaultGetUserByToken(supabaseUrl, serviceRoleKey)
        : null);
    const allowedAppRoles =
      options?.allowedAppRoles ?? parseAllowedRoles(ADD_MEMBER_ALLOWED_APP_ROLES);
    authorizeRequest = getUserByToken
      ? buildDefaultAuthorizeRequest(getUserByToken, allowedAppRoles)
      : (() => false);
  }

  return async (req: Request) => {
    if (!(supabaseUrl && serviceRoleKey && addMemberRpc)) {
      console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY");
      return new Response("Server misconfiguration", { status: 500 });
    }

    if (req.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    if (!(await authorizeRequest(req))) {
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
      const status = statusForRpcError(error);
      console.error(`Error adding member: ${error.message}`);
      return new Response(JSON.stringify({
        error: status >= 500 ? "Internal server error" : error.message,
      }), {
        status,
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
/// Default authorization policy:
///   - Requires `Authorization: Bearer <user-jwt>`
///   - Validates the token via `auth.getUser()` using service_role
///   - Allows only:
///       1) users with `app_metadata.is_super_admin = true`, or
///       2) users with app role in `ADD_MEMBER_ALLOWED_APP_ROLES` (CSV),
///          if configured
/// You can override this by passing `authorizeRequest` to createAddMemberHandler.
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
///   REVOKE EXECUTE ON FUNCTION public.add_member(uuid, uuid, text[]) FROM anon;
///   REVOKE EXECUTE ON FUNCTION public.add_member(uuid, uuid, text[]) FROM authenticated;
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
//   --header 'Authorization: Bearer <user-jwt>' \
//   --header 'Content-Type: application/json' \
//   --data '{"group_id":"<uuid>","user_id":"<uuid>","roles":["editor"]}'
