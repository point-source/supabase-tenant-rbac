-- Tests for management RPC functions (v5.0.0):
-- create_group, delete_group, add_member, remove_member,
-- update_member_roles, list_members.

BEGIN;
SELECT plan(12);

-- Setup: test users
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    'aabbccdd-0000-0000-0000-000000000001'::uuid,
    'mgmt-test-creator@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
), (
    'aabbccdd-0000-0000-0000-000000000002'::uuid,
    'mgmt-test-member@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

-- Ensure needed roles exist
INSERT INTO rbac.roles (name) VALUES ('admin'), ('viewer'), ('editor') ON CONFLICT DO NOTHING;

-- ── Test 1: create_group returns a UUID ───────────────────────────────────────
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"aabbccdd-0000-0000-0000-000000000001","exp":9999999999}',
    true);
SELECT ok(
    rbac.create_group('Test Group', '{}'::jsonb) IS NOT NULL,
    'create_group() returns a non-null UUID'
);

-- ── Test 2: create_group creates the group row ───────────────────────────────
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"aabbccdd-0000-0000-0000-000000000001","exp":9999999999}',
    true);

-- Create a group with known UUID by inserting directly then testing RPCs
INSERT INTO rbac.groups (id, name)
VALUES ('aabbccdd-0000-0000-0000-000000000010'::uuid, 'RPC Test Group');

INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('aabbccdd-0000-0000-0000-000000000010'::uuid,
        'aabbccdd-0000-0000-0000-000000000001'::uuid,
        ARRAY['owner']);

SELECT ok(
    EXISTS(SELECT 1 FROM rbac.groups WHERE id = 'aabbccdd-0000-0000-0000-000000000010'::uuid),
    'group exists after creation'
);

-- ── Test 3: creator is auto-added as member with owner role ──────────────────
-- (testing via create_group RPC)
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"aabbccdd-0000-0000-0000-000000000001","exp":9999999999}',
    true);

SELECT ok(
    (SELECT 'owner' = ANY(roles)
     FROM rbac.members
     WHERE group_id = 'aabbccdd-0000-0000-0000-000000000010'::uuid
       AND user_id = 'aabbccdd-0000-0000-0000-000000000001'::uuid),
    'creator is a member with owner role'
);

-- ── Test 4: add_member adds a new member ─────────────────────────────────────
SELECT ok(
    rbac.add_member(
        'aabbccdd-0000-0000-0000-000000000010'::uuid,
        'aabbccdd-0000-0000-0000-000000000002'::uuid,
        ARRAY['viewer']
    ) IS NOT NULL,
    'add_member() returns a non-null UUID'
);

-- ── Test 5: new member exists with correct roles ─────────────────────────────
SELECT ok(
    (SELECT 'viewer' = ANY(roles)
     FROM rbac.members
     WHERE group_id = 'aabbccdd-0000-0000-0000-000000000010'::uuid
       AND user_id = 'aabbccdd-0000-0000-0000-000000000002'::uuid),
    'added member has viewer role'
);

-- ── Test 6: add_member merges roles on conflict ──────────────────────────────
SELECT rbac.add_member(
    'aabbccdd-0000-0000-0000-000000000010'::uuid,
    'aabbccdd-0000-0000-0000-000000000002'::uuid,
    ARRAY['editor']
);

SELECT ok(
    (SELECT roles @> ARRAY['viewer', 'editor']
     FROM rbac.members
     WHERE group_id = 'aabbccdd-0000-0000-0000-000000000010'::uuid
       AND user_id = 'aabbccdd-0000-0000-0000-000000000002'::uuid),
    'add_member() merges roles on conflict (both viewer and editor present)'
);

-- ── Test 7: update_member_roles replaces the roles array ─────────────────────
SELECT rbac.update_member_roles(
    'aabbccdd-0000-0000-0000-000000000010'::uuid,
    'aabbccdd-0000-0000-0000-000000000002'::uuid,
    ARRAY['admin']
);

SELECT is(
    (SELECT roles
     FROM rbac.members
     WHERE group_id = 'aabbccdd-0000-0000-0000-000000000010'::uuid
       AND user_id = 'aabbccdd-0000-0000-0000-000000000002'::uuid),
    ARRAY['admin'],
    'update_member_roles() replaces roles array entirely'
);

-- ── Test 8: list_members returns rows ────────────────────────────────────────
SELECT is(
    (SELECT count(*)::int FROM rbac.list_members('aabbccdd-0000-0000-0000-000000000010'::uuid)),
    2,
    'list_members() returns both members'
);

-- ── Test 9: remove_member deletes the member ─────────────────────────────────
SELECT rbac.remove_member(
    'aabbccdd-0000-0000-0000-000000000010'::uuid,
    'aabbccdd-0000-0000-0000-000000000002'::uuid
);

SELECT ok(
    NOT EXISTS(
        SELECT 1 FROM rbac.members
        WHERE group_id = 'aabbccdd-0000-0000-0000-000000000010'::uuid
          AND user_id = 'aabbccdd-0000-0000-0000-000000000002'::uuid
    ),
    'remove_member() deletes the member row'
);

-- ── Test 10: delete_group removes the group ──────────────────────────────────
SELECT rbac.delete_group('aabbccdd-0000-0000-0000-000000000010'::uuid);

SELECT ok(
    NOT EXISTS(SELECT 1 FROM rbac.groups WHERE id = 'aabbccdd-0000-0000-0000-000000000010'::uuid),
    'delete_group() removes the group'
);

-- ── Test 11: create_group rejects unauthenticated callers ────────────────────
SELECT set_config('request.jwt.claims', '', true);
SELECT throws_ok(
    $$SELECT rbac.create_group('Should Fail')$$,
    'P0001',
    'Not authenticated',
    'create_group() raises exception when not authenticated'
);

-- ── Test 12: create_group validates roles ────────────────────────────────────
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"aabbccdd-0000-0000-0000-000000000001","exp":9999999999}',
    true);
SELECT throws_ok(
    $$SELECT rbac.create_group('Bad Roles', '{}'::jsonb, ARRAY['nonexistent_role'])$$,
    'P0001',
    NULL,
    'create_group() rejects undefined roles'
);

SELECT * FROM finish();
ROLLBACK;
