-- Tests for function grant assignments on extension functions.
-- Verifies that the expected roles have EXECUTE on each function.
--
-- In v5.0.0, public wrappers are opt-in (not auto-created), so we test
-- the rbac.* originals directly. Wrapper grants are covered separately
-- if the opt-in script has been run.

BEGIN;
SELECT plan(12);

-- ── Test 1: authenticator has EXECUTE on db_pre_request() ────────────────────
SELECT ok(
    has_function_privilege('authenticator', 'rbac.db_pre_request()', 'EXECUTE'),
    'authenticator role has EXECUTE on rbac.db_pre_request()'
);

-- ── Test 2: authenticated has EXECUTE on accept_invite() ─────────────────────
SELECT ok(
    has_function_privilege('authenticated', 'rbac.accept_invite(uuid)', 'EXECUTE'),
    'authenticated role has EXECUTE on rbac.accept_invite(uuid)'
);

-- ── Test 3: authenticated has EXECUTE on has_role() ──────────────────────────
SELECT ok(
    has_function_privilege('authenticated', 'rbac.has_role(uuid, text)', 'EXECUTE'),
    'authenticated role has EXECUTE on rbac.has_role(uuid, text)'
);

-- ── Test 4: authenticated has EXECUTE on is_member() ─────────────────────────
SELECT ok(
    has_function_privilege('authenticated', 'rbac.is_member(uuid)', 'EXECUTE'),
    'authenticated role has EXECUTE on rbac.is_member(uuid)'
);

-- ── Test 5: authenticated has EXECUTE on has_any_role() ──────────────────────
SELECT ok(
    has_function_privilege('authenticated', 'rbac.has_any_role(uuid, text[])', 'EXECUTE'),
    'authenticated role has EXECUTE on rbac.has_any_role(uuid, text[])'
);

-- ── Test 6: authenticated has EXECUTE on has_permission() ────────────────────
SELECT ok(
    has_function_privilege('authenticated', 'rbac.has_permission(uuid, text)', 'EXECUTE'),
    'authenticated role has EXECUTE on rbac.has_permission(uuid, text)'
);

-- ── Test 7: authenticated has EXECUTE on create_group() ──────────────────────
SELECT ok(
    has_function_privilege('authenticated', 'rbac.create_group(text, jsonb, text[])', 'EXECUTE'),
    'authenticated role has EXECUTE on rbac.create_group(text, jsonb, text[])'
);

-- ── Test 8: service_role has EXECUTE on create_role() ────────────────────────
SELECT ok(
    has_function_privilege('service_role', 'rbac.create_role(text, text)', 'EXECUTE'),
    'service_role has EXECUTE on rbac.create_role(text, text)'
);

-- ── Test 9: service_role has EXECUTE on set_role_permissions() ───────────────
SELECT ok(
    has_function_privilege('service_role', 'rbac.set_role_permissions(text, text[])', 'EXECUTE'),
    'service_role has EXECUTE on rbac.set_role_permissions(text, text[])'
);

-- ── Test 10: service_role has EXECUTE on grant_permission() ──────────────────
SELECT ok(
    has_function_privilege('service_role', 'rbac.grant_permission(text, text)', 'EXECUTE'),
    'service_role has EXECUTE on rbac.grant_permission(text, text)'
);

-- ── Test 11: service_role has EXECUTE on list_role_permissions() ─────────────
SELECT ok(
    has_function_privilege('service_role', 'rbac.list_role_permissions(text)', 'EXECUTE'),
    'service_role has EXECUTE on rbac.list_role_permissions(text)'
);

-- ── Test 12: supabase_auth_admin has EXECUTE on custom_access_token_hook() ───
SELECT ok(
    has_function_privilege('supabase_auth_admin', 'rbac.custom_access_token_hook(jsonb)', 'EXECUTE'),
    'supabase_auth_admin role has EXECUTE on rbac.custom_access_token_hook(jsonb)'
);

SELECT * FROM finish();
ROLLBACK;
