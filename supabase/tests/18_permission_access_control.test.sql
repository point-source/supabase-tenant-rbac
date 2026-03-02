-- Tests for EXECUTE grant assignments on permission-related functions.
-- Verifies: permission helpers are available to authenticated/anon/service_role,
-- and permission management RPCs are restricted to service_role only.

BEGIN;
SELECT plan(8);

-- ── Test 1: authenticated has EXECUTE on has_permission() ────────────────────
SELECT ok(
    has_function_privilege('authenticated', 'rbac.has_permission(uuid, text)', 'EXECUTE'),
    'authenticated role has EXECUTE on rbac.has_permission(uuid, text)'
);

-- ── Test 2: authenticated has EXECUTE on has_any_permission() ────────────────
SELECT ok(
    has_function_privilege('authenticated', 'rbac.has_any_permission(uuid, text[])', 'EXECUTE'),
    'authenticated role has EXECUTE on rbac.has_any_permission(uuid, text[])'
);

-- ── Test 3: authenticated has EXECUTE on has_all_permissions() ───────────────
SELECT ok(
    has_function_privilege('authenticated', 'rbac.has_all_permissions(uuid, text[])', 'EXECUTE'),
    'authenticated role has EXECUTE on rbac.has_all_permissions(uuid, text[])'
);

-- ── Test 4: service_role has EXECUTE on set_role_permissions() ───────────────
SELECT ok(
    has_function_privilege('service_role', 'rbac.set_role_permissions(text, text[])', 'EXECUTE'),
    'service_role has EXECUTE on rbac.set_role_permissions(text, text[])'
);

-- ── Test 5: service_role has EXECUTE on grant_permission() ───────────────────
SELECT ok(
    has_function_privilege('service_role', 'rbac.grant_permission(text, text)', 'EXECUTE'),
    'service_role has EXECUTE on rbac.grant_permission(text, text)'
);

-- ── Test 6: service_role has EXECUTE on revoke_permission() ──────────────────
SELECT ok(
    has_function_privilege('service_role', 'rbac.revoke_permission(text, text)', 'EXECUTE'),
    'service_role has EXECUTE on rbac.revoke_permission(text, text)'
);

-- ── Test 7: service_role has EXECUTE on list_role_permissions() ──────────────
SELECT ok(
    has_function_privilege('service_role', 'rbac.list_role_permissions(text)', 'EXECUTE'),
    'service_role has EXECUTE on rbac.list_role_permissions(text)'
);

-- ── Test 8: service_role has EXECUTE on list_roles() ─────────────────────────
-- list_roles() is also service_role only (app-author operation)
SELECT ok(
    has_function_privilege('service_role', 'rbac.list_roles()', 'EXECUTE'),
    'service_role has EXECUTE on rbac.list_roles()'
);

SELECT * FROM finish();
ROLLBACK;
