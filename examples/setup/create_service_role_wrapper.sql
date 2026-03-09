-- ═══════════════════════════════════════════════════════════════════════════════
-- Service-Role-Only Wrapper for add_member (Opt-In)
-- ═══════════════════════════════════════════════════════════════════════════════
-- Run this script if you want to call rbac.add_member from an edge function
-- (or other server-side code) using the service_role key, WITHOUT exposing
-- add_member to authenticated clients.
--
-- Why this is needed:
--   rbac.add_member lives in the `rbac` schema, which is not in PostgREST's
--   default exposed schemas (public, graphql_public). supabase-js .rpc()
--   routes through PostgREST, so admin.rpc("add_member", ...) returns 404
--   unless a public-schema wrapper exists.
--
-- What this does:
--   Creates a thin public.add_member wrapper and GRANTs EXECUTE only to
--   service_role. Authenticated and anon users cannot call it directly —
--   they get a "permission denied" error. Only your edge functions (which
--   use the SUPABASE_SERVICE_ROLE_KEY) can reach it.
--
-- Note on default privileges:
--   Supabase auto-grants EXECUTE to anon, authenticated, and service_role
--   for any function created in the public schema by postgres. A simple
--   REVOKE FROM PUBLIC does NOT undo these per-role grants. We must
--   explicitly revoke from each role.
--
-- If you already ran create_public_wrappers.sql, you do NOT need this script —
-- that script already creates public.add_member (granted to authenticated).
-- This script is for the case where you want add_member callable ONLY from
-- server-side code.
--
-- Prerequisites: extension must already be installed in the rbac schema.
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE OR REPLACE FUNCTION public.add_member(
    p_group_id uuid, p_user_id uuid, p_roles text[] DEFAULT '{}'::text[]
)
RETURNS uuid LANGUAGE sql
SET search_path = rbac
AS $f$ SELECT rbac.add_member($1, $2, $3) $f$;

-- Lock down: revoke from all roles, then grant only to service_role.
-- REVOKE FROM PUBLIC alone is not enough — Supabase default privileges
-- auto-grant EXECUTE to anon, authenticated, and service_role individually.
REVOKE EXECUTE ON FUNCTION public.add_member(uuid, uuid, text[]) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.add_member(uuid, uuid, text[]) FROM anon;
REVOKE EXECUTE ON FUNCTION public.add_member(uuid, uuid, text[]) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.add_member(uuid, uuid, text[]) TO service_role;
