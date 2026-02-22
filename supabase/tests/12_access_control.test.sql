-- Tests for function grant assignments on extension functions.
-- Verifies that the expected roles have EXECUTE on each function.
--
-- Note on REVOKE verification: Supabase's local dev environment applies
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO anon, authenticated, service_role
-- after extension installation, which overrides any REVOKE the extension does. Testing
-- "role X cannot call function Y" therefore cannot pass in this environment. Instead,
-- these tests assert the POSITIVE grants — verifying the roles the extension explicitly
-- grants to, which serve as regression guards if those grants are accidentally removed.
--
-- Uses PostgreSQL's built-in has_function_privilege() to query the ACL catalog directly.

BEGIN;
SELECT plan(5);

-- ── Test 1: authenticator has EXECUTE on db_pre_request() ────────────────────
-- db_pre_request is the PostgREST pre-request hook. The extension grants execute
-- to 'authenticator' so the hook can fire for every API request.
SELECT ok(
    has_function_privilege('authenticator', 'public.db_pre_request()', 'EXECUTE'),
    'authenticator role has EXECUTE on db_pre_request()'
);

-- ── Test 2: authenticated has EXECUTE on accept_group_invite() ───────────────
-- accept_group_invite is the invite acceptance RPC. authenticated users call it
-- via supabase.rpc('accept_group_invite', ...) with their own JWT.
SELECT ok(
    has_function_privilege('authenticated', 'public.accept_group_invite(uuid)', 'EXECUTE'),
    'authenticated role has EXECUTE on accept_group_invite(uuid)'
);

-- ── Test 3: authenticated has EXECUTE on user_has_group_role() ───────────────
-- Public-facing RLS helper callable by authenticated users in policy expressions.
SELECT ok(
    has_function_privilege('authenticated', 'public.user_has_group_role(uuid, text)', 'EXECUTE'),
    'authenticated role has EXECUTE on user_has_group_role(uuid, text)'
);

-- ── Test 4: authenticated has EXECUTE on user_is_group_member() ──────────────
SELECT ok(
    has_function_privilege('authenticated', 'public.user_is_group_member(uuid)', 'EXECUTE'),
    'authenticated role has EXECUTE on user_is_group_member(uuid)'
);

-- ── Test 5: authenticated has EXECUTE on user_has_any_group_role() (v4.5.0) ──
-- New bulk helper — verify it is accessible to authenticated for use in RLS policies.
SELECT ok(
    has_function_privilege('authenticated', 'public.user_has_any_group_role(uuid, text[])', 'EXECUTE'),
    'authenticated role has EXECUTE on user_has_any_group_role(uuid, text[])'
);

SELECT * FROM finish();
ROLLBACK;
