-- Tests for the permission layer (Issue #42).
-- Verifies: permission CRUD RPCs (set_role_permissions, grant_permission,
-- revoke_permission, list_role_permissions), claims resolution with permissions,
-- has_permission/has_any_permission/has_all_permissions for all auth tiers,
-- and deduplication of permissions across multiple roles.

BEGIN;
SELECT plan(15);

-- Setup: test user and group
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    'cccccccc-0000-0000-0000-000000000001'::uuid,
    'perms-test@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

INSERT INTO rbac.groups (id, name)
VALUES ('cccccccc-0000-0000-0000-000000000002'::uuid, 'Permissions Test Group');

-- Ensure test roles exist
INSERT INTO rbac.roles (name) VALUES ('editor'), ('viewer') ON CONFLICT DO NOTHING;

-- ── Test 1: set_role_permissions() replaces permissions on a role ─────────────
SELECT rbac.set_role_permissions('editor', ARRAY['posts.create', 'posts.update']);

SELECT is(
    (SELECT permissions FROM rbac.roles WHERE name = 'editor'),
    ARRAY['posts.create', 'posts.update'],
    'set_role_permissions() sets permissions on a role'
);

-- ── Test 2: grant_permission() adds a single permission (idempotent) ──────────
SELECT rbac.grant_permission('editor', 'posts.delete');

SELECT ok(
    (SELECT permissions @> ARRAY['posts.create', 'posts.update', 'posts.delete']
     FROM rbac.roles WHERE name = 'editor'),
    'grant_permission() adds a new permission to the role'
);

-- ── Test 3: grant_permission() is idempotent ──────────────────────────────────
SELECT rbac.grant_permission('editor', 'posts.create');  -- already present

SELECT is(
    (SELECT count(*)::int FROM unnest(
        (SELECT permissions FROM rbac.roles WHERE name = 'editor')
    ) AS p WHERE p = 'posts.create'),
    1,
    'grant_permission() does not duplicate an existing permission'
);

-- ── Test 4: revoke_permission() removes a permission ─────────────────────────
SELECT rbac.revoke_permission('editor', 'posts.delete');

SELECT ok(
    NOT (SELECT permissions @> ARRAY['posts.delete']
         FROM rbac.roles WHERE name = 'editor'),
    'revoke_permission() removes the permission from the role'
);

-- ── Test 5: revoke_permission() is a no-op when permission is not present ─────
SELECT lives_ok(
    $$SELECT rbac.revoke_permission('editor', 'nonexistent.permission')$$,
    'revoke_permission() does not throw when permission is not present'
);

-- ── Test 6: list_role_permissions() returns permissions for a specific role ───
SELECT is(
    (SELECT count(*)::int FROM rbac.list_role_permissions('editor')),
    2,
    'list_role_permissions() returns correct count for a role'
);

-- ── Test 7: claims contain permissions after member INSERT ────────────────────
-- Set viewer permissions first
SELECT rbac.set_role_permissions('viewer', ARRAY['posts.read']);

INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('cccccccc-0000-0000-0000-000000000002'::uuid,
        'cccccccc-0000-0000-0000-000000000001'::uuid,
        ARRAY['editor', 'viewer']);

SELECT ok(
    (SELECT claims->'cccccccc-0000-0000-0000-000000000002'->'permissions'
     @> '["posts.create","posts.read","posts.update"]'::jsonb
     FROM rbac.user_claims WHERE user_id = 'cccccccc-0000-0000-0000-000000000001'::uuid),
    'claims.permissions contains merged permissions from all roles'
);

-- ── Test 8: permissions are deduplicated across roles ─────────────────────────
-- Give viewer the same permission as editor
SELECT rbac.grant_permission('viewer', 'posts.create');

SELECT is(
    jsonb_array_length(
        (SELECT claims->'cccccccc-0000-0000-0000-000000000002'->'permissions'
         FROM rbac.user_claims WHERE user_id = 'cccccccc-0000-0000-0000-000000000001'::uuid)
    ),
    3,  -- posts.create, posts.read, posts.update — no duplicates
    'permissions are deduplicated across multiple roles in claims'
);

-- Restore viewer permissions for remaining tests
SELECT rbac.revoke_permission('viewer', 'posts.create');

-- ── Test 9: role permissions change trigger rebuilds claims ───────────────────
SELECT rbac.grant_permission('editor', 'posts.publish');

SELECT ok(
    (SELECT claims->'cccccccc-0000-0000-0000-000000000002'->'permissions'
     ? 'posts.publish'
     FROM rbac.user_claims WHERE user_id = 'cccccccc-0000-0000-0000-000000000001'::uuid),
    'claims are rebuilt when role permissions change (trigger fires on UPDATE)'
);

-- ── Tests 10-14: has_permission helpers as authenticated user ─────────────────
-- Must use SET LOCAL ROLE authenticated + JWT so auth.role() = 'authenticated'
-- and the function uses the claims-checking path instead of the superuser bypass.

SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"cccccccc-0000-0000-0000-000000000001","exp":9999999999}',
    true);
SELECT set_config('request.groups',
    (SELECT claims::text FROM rbac.user_claims
     WHERE user_id = 'cccccccc-0000-0000-0000-000000000001'::uuid), true);

-- ── Test 10: has_permission() returns true for a held permission ──────────────
SET LOCAL ROLE authenticated;
SELECT is(
    rbac.has_permission('cccccccc-0000-0000-0000-000000000002'::uuid, 'posts.create'),
    true,
    'has_permission() returns true for a permission the user holds'
);
RESET ROLE;

-- ── Test 11: has_permission() returns false for an ungranted permission ────────
SET LOCAL ROLE authenticated;
SELECT is(
    rbac.has_permission('cccccccc-0000-0000-0000-000000000002'::uuid, 'posts.destroy'),
    false,
    'has_permission() returns false for a permission the user does not hold'
);
RESET ROLE;

-- ── Test 12: has_any_permission() returns true when at least one matches ──────
SET LOCAL ROLE authenticated;
SELECT is(
    rbac.has_any_permission('cccccccc-0000-0000-0000-000000000002'::uuid,
        ARRAY['posts.destroy', 'posts.create']),
    true,
    'has_any_permission() returns true when at least one permission matches'
);
RESET ROLE;

-- ── Test 13: has_all_permissions() returns true only when all match ────────────
SET LOCAL ROLE authenticated;
SELECT is(
    rbac.has_all_permissions('cccccccc-0000-0000-0000-000000000002'::uuid,
        ARRAY['posts.create', 'posts.read']),
    true,
    'has_all_permissions() returns true when all permissions match'
);
RESET ROLE;

-- ── Test 14: has_all_permissions() returns false when any permission missing ───
SET LOCAL ROLE authenticated;
SELECT is(
    rbac.has_all_permissions('cccccccc-0000-0000-0000-000000000002'::uuid,
        ARRAY['posts.create', 'posts.destroy']),
    false,
    'has_all_permissions() returns false when any permission is missing'
);
RESET ROLE;

-- ── Test 15: set_role_permissions() errors on unknown role ────────────────────
SELECT throws_ok(
    $$SELECT rbac.set_role_permissions('nonexistent_role', ARRAY['perm.x'])$$,
    'P0001',
    'Role "nonexistent_role" not found',
    'set_role_permissions() raises an error for an unknown role'
);

SELECT * FROM finish();
ROLLBACK;
