-- ═══════════════════════════════════════════════════════════════════════════════
-- Create Public Wrappers (Opt-In)
-- ═══════════════════════════════════════════════════════════════════════════════
-- Run this script after installing the extension if you want thin public.*
-- wrapper functions for:
--   1. PostgREST RPC discovery   (supabase.rpc('has_role', ...))
--   2. Unqualified RLS policies  (USING (has_role(group_id, 'owner')))
--
-- Without these wrappers, use schema-qualified names everywhere:
--   USING (rbac.has_role(group_id, 'owner'))
--   supabase.schema('rbac').rpc('create_group', { p_name: '...' })
--
-- Prerequisites: extension must already be installed in the rbac schema.
-- Replace 'rbac' with your schema name if different.
-- ═══════════════════════════════════════════════════════════════════════════════

DO $wrapper$ BEGIN
IF 'rbac' <> 'public' THEN

    -- ── RLS / Claims helpers ────────────────────────────────────────────────

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.get_claims()
        RETURNS jsonb LANGUAGE sql STABLE
        SET search_path = rbac
        AS $f$ SELECT rbac.get_claims() $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.has_role(group_id uuid, role text)
        RETURNS boolean LANGUAGE sql STABLE
        SET search_path = rbac
        AS $f$ SELECT rbac.has_role($1, $2) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.is_member(group_id uuid)
        RETURNS boolean LANGUAGE sql STABLE
        SET search_path = rbac
        AS $f$ SELECT rbac.is_member($1) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.has_any_role(group_id uuid, roles text[])
        RETURNS boolean LANGUAGE sql STABLE
        SET search_path = rbac
        AS $f$ SELECT rbac.has_any_role($1, $2) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.has_all_roles(group_id uuid, roles text[])
        RETURNS boolean LANGUAGE sql STABLE
        SET search_path = rbac
        AS $f$ SELECT rbac.has_all_roles($1, $2) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.has_permission(group_id uuid, permission text)
        RETURNS boolean LANGUAGE sql STABLE
        SET search_path = rbac
        AS $f$ SELECT rbac.has_permission($1, $2) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.has_any_permission(group_id uuid, permissions text[])
        RETURNS boolean LANGUAGE sql STABLE
        SET search_path = rbac
        AS $f$ SELECT rbac.has_any_permission($1, $2) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.has_all_permissions(group_id uuid, permissions text[])
        RETURNS boolean LANGUAGE sql STABLE
        SET search_path = rbac
        AS $f$ SELECT rbac.has_all_permissions($1, $2) $f$
    $sql$;

    -- ── Management RPCs (authenticated) ─────────────────────────────────────

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.create_group(
            p_name text, p_metadata jsonb DEFAULT '{}'::jsonb, p_creator_roles text[] DEFAULT ARRAY['owner']
        )
        RETURNS uuid LANGUAGE sql SECURITY DEFINER
        SET search_path = rbac
        AS $f$ SELECT rbac.create_group($1, $2, $3) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.delete_group(p_group_id uuid)
        RETURNS void LANGUAGE sql
        SET search_path = rbac
        AS $f$ SELECT rbac.delete_group($1) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.add_member(
            p_group_id uuid, p_user_id uuid, p_roles text[] DEFAULT '{}'::text[]
        )
        RETURNS uuid LANGUAGE sql
        SET search_path = rbac
        AS $f$ SELECT rbac.add_member($1, $2, $3) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.remove_member(p_group_id uuid, p_user_id uuid)
        RETURNS void LANGUAGE sql
        SET search_path = rbac
        AS $f$ SELECT rbac.remove_member($1, $2) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.update_member_roles(
            p_group_id uuid, p_user_id uuid, p_roles text[]
        )
        RETURNS void LANGUAGE sql
        SET search_path = rbac
        AS $f$ SELECT rbac.update_member_roles($1, $2, $3) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.list_members(p_group_id uuid)
        RETURNS TABLE(id uuid, user_id uuid, roles text[], metadata jsonb, created_at timestamptz)
        LANGUAGE sql STABLE
        SET search_path = rbac
        AS $f$ SELECT * FROM rbac.list_members($1) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.accept_invite(p_invite_id uuid)
        RETURNS void LANGUAGE sql SECURITY DEFINER
        SET search_path = rbac
        AS $f$ SELECT rbac.accept_invite($1) $f$
    $sql$;

    -- ── Member permission override RPCs (authenticated) ─────────────────────

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.grant_member_permission(
            p_group_id uuid, p_user_id uuid, p_permission text
        )
        RETURNS void LANGUAGE sql
        SET search_path = rbac
        AS $f$ SELECT rbac.grant_member_permission($1, $2, $3) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.revoke_member_permission(
            p_group_id uuid, p_user_id uuid, p_permission text
        )
        RETURNS void LANGUAGE sql
        SET search_path = rbac
        AS $f$ SELECT rbac.revoke_member_permission($1, $2, $3) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.list_member_permissions(
            p_group_id uuid, p_user_id uuid DEFAULT NULL
        )
        RETURNS TABLE(user_id uuid, permission text, created_at timestamptz)
        LANGUAGE sql STABLE
        SET search_path = rbac
        AS $f$ SELECT * FROM rbac.list_member_permissions($1, $2) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.create_invite(
            p_group_id uuid, p_roles text[], p_expires_at timestamptz DEFAULT NULL
        )
        RETURNS uuid LANGUAGE sql
        SET search_path = rbac
        AS $f$ SELECT rbac.create_invite($1, $2, $3) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.delete_invite(p_invite_id uuid)
        RETURNS void LANGUAGE sql
        SET search_path = rbac
        AS $f$ SELECT rbac.delete_invite($1) $f$
    $sql$;

    -- ── Auth Hook wrapper ────────────────────────────────────────────────────
    -- NOTE: If you create this wrapper, update config.toml to point to the
    -- public wrapper instead of the schema-qualified function:
    --   uri = "pg-functions://postgres/public/custom_access_token_hook"

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.custom_access_token_hook(event jsonb)
        RETURNS jsonb LANGUAGE sql STABLE
        SET search_path = rbac
        AS $f$ SELECT rbac.custom_access_token_hook($1) $f$
    $sql$;

    -- ── REVOKE / GRANT on public wrappers ───────────────────────────────────

    -- RLS helpers: authenticated and service_role only.
    -- anon is excluded — these functions always return false for anon callers
    -- (handled internally), so granting anon is unnecessary attack surface.
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.get_claims() FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.has_role(uuid, text) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.is_member(uuid) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.has_any_role(uuid, text[]) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.has_all_roles(uuid, text[]) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.has_permission(uuid, text) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.has_any_permission(uuid, text[]) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.has_all_permissions(uuid, text[]) FROM PUBLIC';

    EXECUTE 'GRANT EXECUTE ON FUNCTION public.get_claims() TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.has_role(uuid, text) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.is_member(uuid) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.has_any_role(uuid, text[]) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.has_all_roles(uuid, text[]) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.has_permission(uuid, text) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.has_any_permission(uuid, text[]) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.has_all_permissions(uuid, text[]) TO authenticated, service_role';

    -- Management RPCs: authenticated only
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.create_group(text, jsonb, text[]) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.delete_group(uuid) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.add_member(uuid, uuid, text[]) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.remove_member(uuid, uuid) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.update_member_roles(uuid, uuid, text[]) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.list_members(uuid) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.accept_invite(uuid) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.create_invite(uuid, text[], timestamptz) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.delete_invite(uuid) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.grant_member_permission(uuid, uuid, text) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.revoke_member_permission(uuid, uuid, text) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.list_member_permissions(uuid, uuid) FROM PUBLIC';

    EXECUTE 'GRANT EXECUTE ON FUNCTION public.create_group(text, jsonb, text[]) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.delete_group(uuid) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.add_member(uuid, uuid, text[]) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.remove_member(uuid, uuid) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.update_member_roles(uuid, uuid, text[]) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.list_members(uuid) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.accept_invite(uuid) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.create_invite(uuid, text[], timestamptz) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.delete_invite(uuid) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.grant_member_permission(uuid, uuid, text) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.revoke_member_permission(uuid, uuid, text) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.list_member_permissions(uuid, uuid) TO authenticated';

    -- Auth hook: supabase_auth_admin only
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.custom_access_token_hook(jsonb) FROM PUBLIC';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.custom_access_token_hook(jsonb) TO supabase_auth_admin';

END IF;
END $wrapper$;
