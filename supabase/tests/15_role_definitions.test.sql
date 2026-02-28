-- Tests for the roles table and role management RPCs.
-- Verifies: pre-seeded 'owner' role exists, create_role happy path,
-- _validate_roles rejects undefined roles, delete_role blocked when in use.

BEGIN;
SELECT plan(8);

-- Setup: test user
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    'aaaaaaaa-2222-0000-0000-000000000001'::uuid,
    'role-def-test@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

INSERT INTO rbac.groups (id, name)
VALUES ('aaaaaaaa-2222-0000-0000-000000000002'::uuid, 'Role Def Test Group');

-- ── Test 1: 'owner' role is pre-seeded ───────────────────────────────────────
SELECT ok(
    EXISTS(SELECT 1 FROM rbac.roles WHERE name = 'owner'),
    'owner role is pre-seeded in the roles table'
);

-- ── Test 2: create_role adds a new role ──────────────────────────────────────
SELECT rbac.create_role('test_role', 'A test role');

SELECT ok(
    EXISTS(SELECT 1 FROM rbac.roles WHERE name = 'test_role'),
    'create_role() adds a new role to the roles table'
);

-- ── Test 3: role description is stored ───────────────────────────────────────
SELECT is(
    (SELECT description FROM rbac.roles WHERE name = 'test_role'),
    'A test role',
    'create_role() stores the description'
);

-- ── Test 4: duplicate role creation fails ────────────────────────────────────
SELECT throws_ok(
    $$SELECT rbac.create_role('owner')$$,
    '23505',
    NULL,
    'create_role() fails with unique violation for duplicate role name'
);

-- ── Test 5: _validate_roles accepts existing roles ───────────────────────────
SELECT lives_ok(
    $$SELECT rbac._validate_roles(ARRAY['owner', 'test_role'])$$,
    '_validate_roles() accepts roles that exist in the roles table'
);

-- ── Test 6: _validate_roles rejects undefined roles ──────────────────────────
SELECT throws_ok(
    $$SELECT rbac._validate_roles(ARRAY['owner', 'nonexistent_role'])$$,
    'P0001',
    NULL,
    '_validate_roles() raises exception for undefined roles'
);

-- ── Test 7: delete_role blocked when role is in use ──────────────────────────
INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('aaaaaaaa-2222-0000-0000-000000000002'::uuid,
        'aaaaaaaa-2222-0000-0000-000000000001'::uuid,
        ARRAY['test_role']);

SELECT throws_ok(
    $$SELECT rbac.delete_role('test_role')$$,
    'P0001',
    NULL,
    'delete_role() raises exception when role is in use by a member'
);

-- ── Test 8: delete_role succeeds when role is unused ─────────────────────────
-- Remove the member using the role first
DELETE FROM rbac.members
WHERE group_id = 'aaaaaaaa-2222-0000-0000-000000000002'::uuid
  AND user_id = 'aaaaaaaa-2222-0000-0000-000000000001'::uuid;

SELECT lives_ok(
    $$SELECT rbac.delete_role('test_role')$$,
    'delete_role() succeeds when the role is no longer in use'
);

SELECT * FROM finish();
ROLLBACK;
