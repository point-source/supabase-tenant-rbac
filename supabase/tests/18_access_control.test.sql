-- EXECUTE grant verification for the v5.0.0 extension surface.
-- Verifies: authenticated can call management RPCs, cannot call service_role-only
-- RPCs, cannot call internal helpers. Anon cannot call management RPCs.
-- Complements 12_access_control.test.sql and 26_negative_execute_grants.test.sql.

BEGIN;
SELECT plan(24);

-- ── Tests 1-6: authenticated has EXECUTE on management RPCs ──────────────────

-- ── Test 1: authenticated has EXECUTE on rbac.create_group() ─────────────────
SELECT ok(
    has_function_privilege('authenticated',
        'rbac.create_group(text, jsonb, text[])', 'EXECUTE'),
    'authenticated has EXECUTE on rbac.create_group(text, jsonb, text[])'
);

-- ── Test 2: authenticated has EXECUTE on rbac.add_member() ───────────────────
SELECT ok(
    has_function_privilege('authenticated',
        'rbac.add_member(uuid, uuid, text[])', 'EXECUTE'),
    'authenticated has EXECUTE on rbac.add_member(uuid, uuid, text[])'
);

-- ── Test 3: authenticated has EXECUTE on rbac.remove_member() ────────────────
SELECT ok(
    has_function_privilege('authenticated',
        'rbac.remove_member(uuid, uuid)', 'EXECUTE'),
    'authenticated has EXECUTE on rbac.remove_member(uuid, uuid)'
);

-- ── Test 4: authenticated has EXECUTE on rbac.update_member_roles() ──────────
SELECT ok(
    has_function_privilege('authenticated',
        'rbac.update_member_roles(uuid, uuid, text[])', 'EXECUTE'),
    'authenticated has EXECUTE on rbac.update_member_roles(uuid, uuid, text[])'
);

-- ── Test 5: authenticated has EXECUTE on rbac.grant_member_permission() ───────
SELECT ok(
    has_function_privilege('authenticated',
        'rbac.grant_member_permission(uuid, uuid, text)', 'EXECUTE'),
    'authenticated has EXECUTE on rbac.grant_member_permission(uuid, uuid, text)'
);

-- ── Test 6: authenticated has EXECUTE on rbac.revoke_member_permission() ──────
SELECT ok(
    has_function_privilege('authenticated',
        'rbac.revoke_member_permission(uuid, uuid, text)', 'EXECUTE'),
    'authenticated has EXECUTE on rbac.revoke_member_permission(uuid, uuid, text)'
);

-- ── Tests 7-10: authenticated CANNOT call service_role-only RPCs ──────────────

-- ── Test 7: authenticated lacks EXECUTE on rbac.create_role() ────────────────
SELECT ok(
    NOT has_function_privilege('authenticated',
        'rbac.create_role(text, text, text[], text[])', 'EXECUTE'),
    'authenticated lacks EXECUTE on rbac.create_role(text, text, text[], text[])'
);

-- ── Test 8: authenticated lacks EXECUTE on rbac.delete_role() ────────────────
SELECT ok(
    NOT has_function_privilege('authenticated',
        'rbac.delete_role(text)', 'EXECUTE'),
    'authenticated lacks EXECUTE on rbac.delete_role(text)'
);

-- ── Test 9: authenticated lacks EXECUTE on rbac.set_role_permissions() ────────
SELECT ok(
    NOT has_function_privilege('authenticated',
        'rbac.set_role_permissions(text, text[])', 'EXECUTE'),
    'authenticated lacks EXECUTE on rbac.set_role_permissions(text, text[])'
);

-- ── Test 10: authenticated lacks EXECUTE on rbac.list_roles() ────────────────
SELECT ok(
    NOT has_function_privilege('authenticated',
        'rbac.list_roles()', 'EXECUTE'),
    'authenticated lacks EXECUTE on rbac.list_roles()'
);

-- ── Tests 11-12: authenticated CANNOT call internal _-prefixed helpers ─────────

-- ── Test 11: authenticated lacks EXECUTE on rbac._build_user_claims() ─────────
SELECT ok(
    NOT has_function_privilege('authenticated',
        'rbac._build_user_claims(uuid)', 'EXECUTE'),
    'authenticated lacks EXECUTE on rbac._build_user_claims(uuid)'
);

-- ── Test 12: authenticated lacks EXECUTE on rbac._sync_member_permission() ─────
SELECT ok(
    NOT has_function_privilege('authenticated',
        'rbac._sync_member_permission()', 'EXECUTE'),
    'authenticated lacks EXECUTE on rbac._sync_member_permission() — trigger-only function locked'
);

-- ── Tests 13-14: anon CANNOT call management RPCs ────────────────────────────

-- ── Test 13: anon lacks EXECUTE on rbac.create_group() ───────────────────────
SELECT ok(
    NOT has_function_privilege('anon',
        'rbac.create_group(text, jsonb, text[])', 'EXECUTE'),
    'anon lacks EXECUTE on rbac.create_group(text, jsonb, text[])'
);

-- ── Test 14: anon lacks EXECUTE on rbac.add_member() ─────────────────────────
SELECT ok(
    NOT has_function_privilege('anon',
        'rbac.add_member(uuid, uuid, text[])', 'EXECUTE'),
    'anon lacks EXECUTE on rbac.add_member(uuid, uuid, text[])'
);

-- ── Tests 15-24: anon lacks EXECUTE on remaining management RPCs ──────────────

-- ── Test 15: anon lacks EXECUTE on rbac.remove_member() ──────────────────────
SELECT ok(
    NOT has_function_privilege('anon',
        'rbac.remove_member(uuid, uuid)', 'EXECUTE'),
    'anon lacks EXECUTE on rbac.remove_member(uuid, uuid)'
);

-- ── Test 16: anon lacks EXECUTE on rbac.update_member_roles() ────────────────
SELECT ok(
    NOT has_function_privilege('anon',
        'rbac.update_member_roles(uuid, uuid, text[])', 'EXECUTE'),
    'anon lacks EXECUTE on rbac.update_member_roles(uuid, uuid, text[])'
);

-- ── Test 17: anon lacks EXECUTE on rbac.list_members() ───────────────────────
SELECT ok(
    NOT has_function_privilege('anon',
        'rbac.list_members(uuid)', 'EXECUTE'),
    'anon lacks EXECUTE on rbac.list_members(uuid)'
);

-- ── Test 18: anon lacks EXECUTE on rbac.accept_invite() ──────────────────────
SELECT ok(
    NOT has_function_privilege('anon',
        'rbac.accept_invite(uuid)', 'EXECUTE'),
    'anon lacks EXECUTE on rbac.accept_invite(uuid)'
);

-- ── Test 19: anon lacks EXECUTE on rbac.create_invite() ──────────────────────
SELECT ok(
    NOT has_function_privilege('anon',
        'rbac.create_invite(uuid, text[], timestamp with time zone)', 'EXECUTE'),
    'anon lacks EXECUTE on rbac.create_invite(uuid, text[], timestamptz)'
);

-- ── Test 20: anon lacks EXECUTE on rbac.delete_invite() ──────────────────────
SELECT ok(
    NOT has_function_privilege('anon',
        'rbac.delete_invite(uuid)', 'EXECUTE'),
    'anon lacks EXECUTE on rbac.delete_invite(uuid)'
);

-- ── Test 21: anon lacks EXECUTE on rbac.delete_group() ───────────────────────
SELECT ok(
    NOT has_function_privilege('anon',
        'rbac.delete_group(uuid)', 'EXECUTE'),
    'anon lacks EXECUTE on rbac.delete_group(uuid)'
);

-- ── Test 22: anon lacks EXECUTE on rbac.grant_member_permission() ────────────
SELECT ok(
    NOT has_function_privilege('anon',
        'rbac.grant_member_permission(uuid, uuid, text)', 'EXECUTE'),
    'anon lacks EXECUTE on rbac.grant_member_permission(uuid, uuid, text)'
);

-- ── Test 23: anon lacks EXECUTE on rbac.revoke_member_permission() ───────────
SELECT ok(
    NOT has_function_privilege('anon',
        'rbac.revoke_member_permission(uuid, uuid, text)', 'EXECUTE'),
    'anon lacks EXECUTE on rbac.revoke_member_permission(uuid, uuid, text)'
);

-- ── Test 24: anon lacks EXECUTE on rbac.list_member_permissions() ────────────
SELECT ok(
    NOT has_function_privilege('anon',
        'rbac.list_member_permissions(uuid, uuid)', 'EXECUTE'),
    'anon lacks EXECUTE on rbac.list_member_permissions(uuid, uuid)'
);

SELECT * FROM finish();
ROLLBACK;
