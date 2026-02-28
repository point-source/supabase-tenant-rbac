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

REVOKE ALL ON rbac.groups  FROM authenticated;
REVOKE ALL ON rbac.members FROM authenticated;
REVOKE ALL ON rbac.invites FROM authenticated;
REVOKE ALL ON rbac.roles   FROM authenticated;

-- ──────────────────────────────────────────────────────────────────────────────
-- Step 2: Grant the minimum required privileges
-- ──────────────────────────────────────────────────────────────────────────────

GRANT SELECT ON rbac.groups  TO authenticated;
GRANT SELECT ON rbac.members TO authenticated;
GRANT SELECT ON rbac.invites TO authenticated;
GRANT SELECT ON rbac.roles   TO authenticated;

-- ──────────────────────────────────────────────────────────────────────────────
-- Step 3: Add targeted grants for admin operations
-- ──────────────────────────────────────────────────────────────────────────────

-- If your app uses SECURITY INVOKER management RPCs (add_member, remove_member,
-- update_member_roles), the underlying DML needs these grants:
-- GRANT INSERT, UPDATE, DELETE ON rbac.members TO authenticated;

-- If your app allows authorized users to create invites directly:
-- GRANT INSERT ON rbac.invites TO authenticated;

-- If your app allows authorized users to manage role definitions:
-- GRANT INSERT, DELETE ON rbac.roles TO authenticated;

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
