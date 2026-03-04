-- Tests that the anon role cannot access any rbac tables or execute management RPCs.
-- The anon role has USAGE on the rbac schema but no table grants and no function
-- execute grants (management RPCs are REVOKE'd from PUBLIC and GRANT'd to authenticated only).

BEGIN;
SELECT plan(8);

-- ── Tests 1-6: anon has no table-level SELECT on rbac tables ─────────────────

-- ── Test 1: anon cannot SELECT from rbac.groups ───────────────────────────────
SELECT ok(
    NOT has_table_privilege('anon', 'rbac.groups', 'SELECT'),
    'anon role does not have SELECT privilege on rbac.groups'
);

-- ── Test 2: anon cannot SELECT from rbac.members ─────────────────────────────
SELECT ok(
    NOT has_table_privilege('anon', 'rbac.members', 'SELECT'),
    'anon role does not have SELECT privilege on rbac.members'
);

-- ── Test 3: anon cannot SELECT from rbac.invites ─────────────────────────────
SELECT ok(
    NOT has_table_privilege('anon', 'rbac.invites', 'SELECT'),
    'anon role does not have SELECT privilege on rbac.invites'
);

-- ── Test 4: anon cannot SELECT from rbac.roles ───────────────────────────────
SELECT ok(
    NOT has_table_privilege('anon', 'rbac.roles', 'SELECT'),
    'anon role does not have SELECT privilege on rbac.roles'
);

-- ── Test 5: anon cannot SELECT from rbac.user_claims ─────────────────────────
SELECT ok(
    NOT has_table_privilege('anon', 'rbac.user_claims', 'SELECT'),
    'anon role does not have SELECT privilege on rbac.user_claims'
);

-- ── Test 6: anon cannot SELECT from rbac.member_permissions ──────────────────
SELECT ok(
    NOT has_table_privilege('anon', 'rbac.member_permissions', 'SELECT'),
    'anon role does not have SELECT privilege on rbac.member_permissions'
);

-- ── Tests 7-8: anon lacks EXECUTE on management RPCs ─────────────────────────
-- Management RPCs are REVOKE'd from PUBLIC and GRANT'd to authenticated only.

-- ── Test 7: anon lacks EXECUTE on rbac.create_group() ────────────────────────
SELECT ok(
    NOT has_function_privilege('anon', 'rbac.create_group(text, jsonb, text[])', 'EXECUTE'),
    'anon role does not have EXECUTE on rbac.create_group(text, jsonb, text[])'
);

-- ── Test 8: anon lacks EXECUTE on rbac.add_member() ──────────────────────────
SELECT ok(
    NOT has_function_privilege('anon', 'rbac.add_member(uuid, uuid, text[])', 'EXECUTE'),
    'anon role does not have EXECUTE on rbac.add_member(uuid, uuid, text[])'
);

SELECT * FROM finish();
ROLLBACK;
