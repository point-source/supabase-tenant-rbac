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
        RETURNS uuid LANGUAGE sql
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
        RETURNS void LANGUAGE sql
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

    -- ── Role/Permission management RPCs (service_role only) ─────────────────────

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.create_role(
            p_name text, p_description text DEFAULT NULL,
            p_permissions text[] DEFAULT '{}'::text[],
            p_grantable_roles text[] DEFAULT '{}'::text[]
        )
        RETURNS void LANGUAGE sql
        SET search_path = rbac
        AS $f$ SELECT rbac.create_role($1, $2, $3, $4) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.delete_role(p_name text)
        RETURNS void LANGUAGE sql
        SET search_path = rbac
        AS $f$ SELECT rbac.delete_role($1) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.list_roles()
        RETURNS TABLE(name text, description text, permissions text[], grantable_roles text[], created_at timestamptz)
        LANGUAGE sql STABLE
        SET search_path = rbac
        AS $f$ SELECT * FROM rbac.list_roles() $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.set_role_permissions(
            p_role_name text, p_permissions text[]
        )
        RETURNS void LANGUAGE sql
        SET search_path = rbac
        AS $f$ SELECT rbac.set_role_permissions($1, $2) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.grant_permission(
            p_role_name text, p_permission text
        )
        RETURNS void LANGUAGE sql
        SET search_path = rbac
        AS $f$ SELECT rbac.grant_permission($1, $2) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.revoke_permission(
            p_role_name text, p_permission text
        )
        RETURNS void LANGUAGE sql
        SET search_path = rbac
        AS $f$ SELECT rbac.revoke_permission($1, $2) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.list_role_permissions(
            p_role_name text DEFAULT NULL
        )
        RETURNS TABLE(role_name text, permission text)
        LANGUAGE sql STABLE
        SET search_path = rbac
        AS $f$ SELECT * FROM rbac.list_role_permissions($1) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.create_permission(
            p_name text, p_description text DEFAULT NULL
        )
        RETURNS void LANGUAGE sql
        SET search_path = rbac
        AS $f$ SELECT rbac.create_permission($1, $2) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.delete_permission(p_name text)
        RETURNS void LANGUAGE sql
        SET search_path = rbac
        AS $f$ SELECT rbac.delete_permission($1) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.list_permissions()
        RETURNS TABLE(name text, description text, created_at timestamptz)
        LANGUAGE sql STABLE
        SET search_path = rbac
        AS $f$ SELECT * FROM rbac.list_permissions() $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.set_role_grantable_roles(
            p_role_name text, p_grantable_roles text[]
        )
        RETURNS void LANGUAGE sql
        SET search_path = rbac
        AS $f$ SELECT rbac.set_role_grantable_roles($1, $2) $f$
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
    --
    -- IMPORTANT: Supabase default privileges (pg_default_acl) auto-grant
    -- EXECUTE to anon, authenticated, and service_role for any function
    -- created in the public schema by postgres. REVOKE FROM PUBLIC alone
    -- does NOT undo these per-role grants. We must explicitly revoke from
    -- each role and then grant back to only the intended roles.

    -- RLS helpers: authenticated and service_role only.
    -- anon is excluded — these functions always return false for anon callers
    -- (handled internally), so granting anon is unnecessary attack surface.
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.get_claims() FROM PUBLIC, anon';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.has_role(uuid, text) FROM PUBLIC, anon';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.is_member(uuid) FROM PUBLIC, anon';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.has_any_role(uuid, text[]) FROM PUBLIC, anon';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.has_all_roles(uuid, text[]) FROM PUBLIC, anon';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.has_permission(uuid, text) FROM PUBLIC, anon';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.has_any_permission(uuid, text[]) FROM PUBLIC, anon';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.has_all_permissions(uuid, text[]) FROM PUBLIC, anon';

    EXECUTE 'GRANT EXECUTE ON FUNCTION public.get_claims() TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.has_role(uuid, text) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.is_member(uuid) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.has_any_role(uuid, text[]) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.has_all_roles(uuid, text[]) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.has_permission(uuid, text) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.has_any_permission(uuid, text[]) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.has_all_permissions(uuid, text[]) TO authenticated, service_role';

    -- Management RPCs: authenticated and service_role
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.create_group(text, jsonb, text[]) FROM PUBLIC, anon';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.delete_group(uuid) FROM PUBLIC, anon';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.add_member(uuid, uuid, text[]) FROM PUBLIC, anon';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.remove_member(uuid, uuid) FROM PUBLIC, anon';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.update_member_roles(uuid, uuid, text[]) FROM PUBLIC, anon';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.list_members(uuid) FROM PUBLIC, anon';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.accept_invite(uuid) FROM PUBLIC, anon';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.create_invite(uuid, text[], timestamptz) FROM PUBLIC, anon';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.delete_invite(uuid) FROM PUBLIC, anon';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.grant_member_permission(uuid, uuid, text) FROM PUBLIC, anon';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.revoke_member_permission(uuid, uuid, text) FROM PUBLIC, anon';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.list_member_permissions(uuid, uuid) FROM PUBLIC, anon';

    EXECUTE 'GRANT EXECUTE ON FUNCTION public.create_group(text, jsonb, text[]) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.delete_group(uuid) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.add_member(uuid, uuid, text[]) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.remove_member(uuid, uuid) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.update_member_roles(uuid, uuid, text[]) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.list_members(uuid) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.accept_invite(uuid) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.create_invite(uuid, text[], timestamptz) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.delete_invite(uuid) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.grant_member_permission(uuid, uuid, text) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.revoke_member_permission(uuid, uuid, text) TO authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.list_member_permissions(uuid, uuid) TO authenticated, service_role';

    -- Role/Permission management RPCs: service_role only
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.create_role(text, text, text[], text[]) FROM PUBLIC, anon, authenticated';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.delete_role(text) FROM PUBLIC, anon, authenticated';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.list_roles() FROM PUBLIC, anon, authenticated';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.set_role_permissions(text, text[]) FROM PUBLIC, anon, authenticated';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.grant_permission(text, text) FROM PUBLIC, anon, authenticated';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.revoke_permission(text, text) FROM PUBLIC, anon, authenticated';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.list_role_permissions(text) FROM PUBLIC, anon, authenticated';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.create_permission(text, text) FROM PUBLIC, anon, authenticated';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.delete_permission(text) FROM PUBLIC, anon, authenticated';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.list_permissions() FROM PUBLIC, anon, authenticated';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.set_role_grantable_roles(text, text[]) FROM PUBLIC, anon, authenticated';

    EXECUTE 'GRANT EXECUTE ON FUNCTION public.create_role(text, text, text[], text[]) TO service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.delete_role(text) TO service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.list_roles() TO service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.set_role_permissions(text, text[]) TO service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.grant_permission(text, text) TO service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.revoke_permission(text, text) TO service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.list_role_permissions(text) TO service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.create_permission(text, text) TO service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.delete_permission(text) TO service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.list_permissions() TO service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.set_role_grantable_roles(text, text[]) TO service_role';

    -- Auth hook: supabase_auth_admin only
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.custom_access_token_hook(jsonb) FROM PUBLIC, anon, authenticated, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.custom_access_token_hook(jsonb) TO supabase_auth_admin';

END IF;
END $wrapper$;
