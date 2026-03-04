-- Negative EXECUTE grant tests — verifies that roles do NOT have EXECUTE on
-- functions they should be excluded from (v5.2.1 security hardening).
--
-- Complements 12_access_control.test.sql and 18_permission_access_control.test.sql
-- which verify positive grants. This file tests the negative cases:
--   - anon lacks EXECUTE on all management RPCs
--   - authenticated lacks EXECUTE on service_role-only RPCs
--   - anon/authenticated lack EXECUTE on internal _-prefixed helpers

BEGIN;
SELECT plan(14);

-- ── Tests 1-5: anon lacks EXECUTE on management RPCs ─────────────────────────
-- All management RPCs are REVOKE'd from PUBLIC and GRANT'd to authenticated only.

-- ── Test 1: anon lacks EXECUTE on rbac.add_member() ─────────────────────────
SELECT ok(
    NOT has_function_privilege('anon', 'rbac.add_member(uuid, uuid, text[])', 'EXECUTE'),
    'anon lacks EXECUTE on rbac.add_member(uuid, uuid, text[])'
);

-- ── Test 2: anon lacks EXECUTE on rbac.remove_member() ───────────────────────
SELECT ok(
    NOT has_function_privilege('anon', 'rbac.remove_member(uuid, uuid)', 'EXECUTE'),
    'anon lacks EXECUTE on rbac.remove_member(uuid, uuid)'
);

-- ── Test 3: anon lacks EXECUTE on rbac.update_member_roles() ─────────────────
SELECT ok(
    NOT has_function_privilege('anon', 'rbac.update_member_roles(uuid, uuid, text[])', 'EXECUTE'),
    'anon lacks EXECUTE on rbac.update_member_roles(uuid, uuid, text[])'
);

-- ── Test 4: anon lacks EXECUTE on rbac.delete_group() ────────────────────────
SELECT ok(
    NOT has_function_privilege('anon', 'rbac.delete_group(uuid)', 'EXECUTE'),
    'anon lacks EXECUTE on rbac.delete_group(uuid)'
);

-- ── Test 5: anon lacks EXECUTE on rbac.create_group() ────────────────────────
SELECT ok(
    NOT has_function_privilege('anon', 'rbac.create_group(text, jsonb, text[])', 'EXECUTE'),
    'anon lacks EXECUTE on rbac.create_group(text, jsonb, text[])'
);

-- ── Tests 6-9: authenticated lacks EXECUTE on service_role-only RPCs ─────────
-- Role/permission management RPCs are REVOKE'd from PUBLIC and GRANT'd to
-- service_role only — they are admin/migration operations, not end-user API.

-- ── Test 6: authenticated lacks EXECUTE on rbac.create_role() ────────────────
SELECT ok(
    NOT has_function_privilege('authenticated', 'rbac.create_role(text, text)', 'EXECUTE'),
    'authenticated lacks EXECUTE on rbac.create_role(text, text)'
);

-- ── Test 7: authenticated lacks EXECUTE on rbac.delete_role() ────────────────
SELECT ok(
    NOT has_function_privilege('authenticated', 'rbac.delete_role(text)', 'EXECUTE'),
    'authenticated lacks EXECUTE on rbac.delete_role(text)'
);

-- ── Test 8: authenticated lacks EXECUTE on rbac.set_role_permissions() ───────
SELECT ok(
    NOT has_function_privilege('authenticated', 'rbac.set_role_permissions(text, text[])', 'EXECUTE'),
    'authenticated lacks EXECUTE on rbac.set_role_permissions(text, text[])'
);

-- ── Test 9: authenticated lacks EXECUTE on rbac.list_roles() ─────────────────
SELECT ok(
    NOT has_function_privilege('authenticated', 'rbac.list_roles()', 'EXECUTE'),
    'authenticated lacks EXECUTE on rbac.list_roles()'
);

-- ── Tests 10-14: no one but internal callers can run _-prefixed helpers ───────
-- v5.2.1 adds REVOKE EXECUTE FROM PUBLIC on all five internal helpers.
-- _build_user_claims: no re-grant (trigger functions only, DEFINER callers)
-- _validate_roles: no re-grant (now DEFINER itself, no external callers need it)
-- _get_user_groups: re-granted to authenticated + service_role
-- _jwt_is_expired: re-granted to authenticated + anon + service_role
-- _set_updated_at: no re-grant (trigger mechanism only)

-- ── Test 10: anon lacks EXECUTE on rbac._build_user_claims() ─────────────────
SELECT ok(
    NOT has_function_privilege('anon', 'rbac._build_user_claims(uuid)', 'EXECUTE'),
    'anon lacks EXECUTE on rbac._build_user_claims(uuid)'
);

-- ── Test 11: authenticated lacks EXECUTE on rbac._build_user_claims() ────────
SELECT ok(
    NOT has_function_privilege('authenticated', 'rbac._build_user_claims(uuid)', 'EXECUTE'),
    'authenticated lacks EXECUTE on rbac._build_user_claims(uuid)'
);

-- ── Test 12: authenticated lacks EXECUTE on rbac._validate_roles() ───────────
-- _validate_roles is now SECURITY DEFINER — callers of add_member,
-- update_member_roles, and create_invite do not need direct EXECUTE.
SELECT ok(
    NOT has_function_privilege('authenticated', 'rbac._validate_roles(text[])', 'EXECUTE'),
    'authenticated lacks EXECUTE on rbac._validate_roles(text[]) (now SECURITY DEFINER)'
);

-- ── Test 13: anon lacks EXECUTE on rbac._validate_roles() ────────────────────
SELECT ok(
    NOT has_function_privilege('anon', 'rbac._validate_roles(text[])', 'EXECUTE'),
    'anon lacks EXECUTE on rbac._validate_roles(text[])'
);

-- ── Test 14: anon lacks EXECUTE on rbac._get_user_groups() ──────────────────
-- _get_user_groups is re-granted to authenticated + service_role, not anon.
SELECT ok(
    NOT has_function_privilege('anon', 'rbac._get_user_groups()', 'EXECUTE'),
    'anon lacks EXECUTE on rbac._get_user_groups()'
);

SELECT * FROM finish();
ROLLBACK;
