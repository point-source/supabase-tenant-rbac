-- Example: Hardened table permissions for defense-in-depth
--
-- In v5.0.0, the extension installs in a private schema (e.g. rbac) and ships
-- with table-level GRANT statements to authenticated/service_role. RLS (deny-all,
-- no policies by default) controls row access.
--
-- This hardened setup goes further by revoking the extension's default grants
-- and re-granting only the minimum required for your application. This means
-- both privilege AND RLS must allow an operation — defense-in-depth.
--
-- Tradeoff:
--   + Defense-in-depth: privilege + RLS must both allow an operation
--   + Anon users cannot touch RBAC tables at all
--   - You must explicitly GRANT privileges for every operation your app needs
--   - SECURITY INVOKER RPCs may fail if the underlying table grant is missing

-- ──────────────────────────────────────────────────────────────────────────────
-- Step 1: Revoke the extension's default table grants
-- ──────────────────────────────────────────────────────────────────────────────

REVOKE ALL ON rbac.groups             FROM authenticated;
REVOKE ALL ON rbac.members            FROM authenticated;
REVOKE ALL ON rbac.invites            FROM authenticated;
-- rbac.roles: no authenticated grant to revoke in v5.2.1+ (revoked by default).
-- If you are on v5.2.0 or earlier, uncomment the line below:
-- REVOKE ALL ON rbac.roles           FROM authenticated;
REVOKE ALL ON rbac.member_permissions FROM authenticated;
-- rbac.user_claims: authenticated only has SELECT (for Storage RLS fallback).
-- Revoking it will break Storage RLS policies that use has_role/has_permission.
-- Only revoke if you are not using the Storage fallback path.
REVOKE ALL ON rbac.user_claims        FROM authenticated;

-- ──────────────────────────────────────────────────────────────────────────────
-- Step 2: Grant the minimum required privileges
-- ──────────────────────────────────────────────────────────────────────────────

GRANT SELECT ON rbac.groups  TO authenticated;
GRANT SELECT ON rbac.members TO authenticated;
GRANT SELECT ON rbac.invites TO authenticated;
-- rbac.roles: omitted — authenticated has no SELECT by default (v5.2.1+).
-- Opt-in: GRANT SELECT ON rbac.roles TO authenticated; (plus an RLS policy)

-- member_permissions: SELECT is needed for list_member_permissions() and RLS.
GRANT SELECT ON rbac.member_permissions TO authenticated;

-- user_claims: SELECT is needed for _get_user_groups() (Storage RLS fallback).
-- Re-grant only if you revoked it above and are using the Storage fallback path.
GRANT SELECT ON rbac.user_claims TO authenticated;

-- ──────────────────────────────────────────────────────────────────────────────
-- Step 3: Add targeted grants for admin operations
-- ──────────────────────────────────────────────────────────────────────────────

-- If your app uses SECURITY INVOKER management RPCs (add_member, remove_member,
-- update_member_roles), the underlying DML needs these grants:
-- GRANT INSERT, UPDATE, DELETE ON rbac.members TO authenticated;

-- If your app allows authorized users to create invites directly:
-- GRANT INSERT ON rbac.invites TO authenticated;

-- If your app allows authorized users to grant/revoke member permission overrides:
-- GRANT INSERT, DELETE ON rbac.member_permissions TO authenticated;

-- ──────────────────────────────────────────────────────────────────────────────
-- Notes
-- ──────────────────────────────────────────────────────────────────────────────
--
-- 1. create_group() and accept_invite() are SECURITY DEFINER — they always have
--    access regardless of the table grants above.
--
-- 2. db_pre_request() is REVOKE'd from anon/authenticated and GRANT'd only to
--    authenticator. This is handled by the extension itself.
--
-- 3. service_role retains ALL on all tables (granted by the extension).
--
-- 4. _validate_roles() is SECURITY DEFINER (v5.2.1+) — management RPCs
--    (add_member, update_member_roles, create_invite) can validate role names
--    against rbac.roles without the caller needing SELECT on that table.
