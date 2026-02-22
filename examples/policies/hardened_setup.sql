-- Example: Hardened table permissions for defense-in-depth
--
-- By default, Supabase grants SELECT/INSERT/UPDATE/DELETE on all tables in the
-- public schema to the 'anon' and 'authenticated' roles. Combined with RLS
-- policies, this is generally safe — but it means any gap in your RLS policies
-- could accidentally expose data.
--
-- The hardened approach: REVOKE all table privileges first, then GRANT only the
-- minimum required for your application to function. RLS policies become the
-- second line of defense rather than the only one.
--
-- Tradeoff:
--   ✓ Defense-in-depth: privilege + RLS must both allow an operation
--   ✓ Anon users cannot touch RBAC tables at all
--   ✗ You must explicitly GRANT privileges for every operation your app needs
--   ✗ More maintenance when adding new tables or access patterns
--
-- Run this AFTER installing the extension and BEFORE writing your RLS policies.

-- ──────────────────────────────────────────────────────────────────────────────
-- Step 1: Revoke all default table privileges
-- ──────────────────────────────────────────────────────────────────────────────

-- Remove the Supabase default grants so that RLS is not the only guard.
REVOKE ALL ON public.groups       FROM anon, authenticated;
REVOKE ALL ON public.group_users  FROM anon, authenticated;
REVOKE ALL ON public.group_invites FROM anon, authenticated;

-- ──────────────────────────────────────────────────────────────────────────────
-- Step 2: Grant the minimum required privileges
-- ──────────────────────────────────────────────────────────────────────────────

-- Authenticated users can list groups (needed to display group names in your UI).
-- Your RLS policy restricts which rows they can actually see.
GRANT SELECT ON public.groups TO authenticated;

-- Authenticated users can read group_users (needed for RLS policy sub-selects
-- and for UIs that display group membership lists).
GRANT SELECT ON public.group_users TO authenticated;

-- Authenticated users can read and claim invites (SELECT needed to query invite
-- details; UPDATE needed if your app updates the invite directly rather than
-- using the accept_group_invite() RPC).
-- If you use the accept_group_invite() RPC exclusively, omit the UPDATE grant
-- here — the SECURITY DEFINER function handles the write itself.
GRANT SELECT, UPDATE ON public.group_invites TO authenticated;

-- ──────────────────────────────────────────────────────────────────────────────
-- Step 3: Add targeted grants for admin operations
-- ──────────────────────────────────────────────────────────────────────────────

-- If your app allows users to create groups directly (not via a service-role
-- edge function), grant INSERT. Your RLS policy controls who can actually do it.
-- GRANT INSERT ON public.groups TO authenticated;

-- If your app allows group owners/admins to manage membership directly:
-- GRANT INSERT, UPDATE, DELETE ON public.group_users TO authenticated;

-- If your app allows authorized users to create invites:
-- GRANT INSERT ON public.group_invites TO authenticated;

-- ──────────────────────────────────────────────────────────────────────────────
-- Notes
-- ──────────────────────────────────────────────────────────────────────────────
--
-- 1. anon users have zero access to all RBAC tables after this setup. Any
--    unauthenticated request to these tables will be rejected at the privilege
--    level before RLS even runs.
--
-- 2. The accept_group_invite() RPC function is SECURITY DEFINER, so it can
--    always perform its internal INSERT/UPDATE regardless of the table grants
--    above. You do NOT need to grant INSERT on group_users or UPDATE on
--    group_invites to authenticated just to support invite acceptance via RPC.
--
-- 3. The db_pre_request() function is REVOKE'd from anon/authenticated and
--    GRANT'd only to authenticator. This is handled by the extension itself;
--    no action needed here.
--
-- 4. If you install the extension in a non-public schema (e.g., 'rbac'), replace
--    'public.' with 'rbac.' throughout this file.
