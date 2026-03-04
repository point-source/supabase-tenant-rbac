-- Tests for the member_permissions table (v5.1.0):
-- grant_member_permission (idempotent), revoke_member_permission,
-- list_member_permissions, and cascade behavior on member/group delete.

BEGIN;
SELECT plan(7);

-- Setup: one test user and group
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    'eeeeeeee-0000-0000-0000-000000000001'::uuid,
    'mp-crud@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

INSERT INTO rbac.groups (id, name)
VALUES ('eeeeeeee-0000-0000-0000-000000000002'::uuid, 'MP CRUD Test Group');

-- Member is required before inserting permission overrides (FK constraint)
INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('eeeeeeee-0000-0000-0000-000000000002'::uuid,
        'eeeeeeee-0000-0000-0000-000000000001'::uuid, ARRAY['owner']);

-- ── Test 1: grant_member_permission() inserts a row ──────────────────────────
SELECT rbac.grant_member_permission(
    'eeeeeeee-0000-0000-0000-000000000002'::uuid,
    'eeeeeeee-0000-0000-0000-000000000001'::uuid,
    'data.export'
);

SELECT is(
    (SELECT count(*)::int FROM rbac.member_permissions
     WHERE group_id = 'eeeeeeee-0000-0000-0000-000000000002'::uuid
       AND user_id = 'eeeeeeee-0000-0000-0000-000000000001'::uuid
       AND permission = 'data.export'),
    1,
    'grant_member_permission() inserts a permission override row'
);

-- ── Test 2: grant_member_permission() is idempotent ──────────────────────────
SELECT lives_ok(
    $$SELECT rbac.grant_member_permission(
        'eeeeeeee-0000-0000-0000-000000000002'::uuid,
        'eeeeeeee-0000-0000-0000-000000000001'::uuid,
        'data.export'
    )$$,
    'grant_member_permission() does not raise on duplicate grant'
);

-- ── Test 3: no duplicate row after idempotent grant ───────────────────────────
SELECT is(
    (SELECT count(*)::int FROM rbac.member_permissions
     WHERE group_id = 'eeeeeeee-0000-0000-0000-000000000002'::uuid
       AND user_id = 'eeeeeeee-0000-0000-0000-000000000001'::uuid
       AND permission = 'data.export'),
    1,
    'no duplicate row created by idempotent grant'
);

-- ── Test 4: revoke_member_permission() removes the row ───────────────────────
SELECT rbac.revoke_member_permission(
    'eeeeeeee-0000-0000-0000-000000000002'::uuid,
    'eeeeeeee-0000-0000-0000-000000000001'::uuid,
    'data.export'
);

SELECT is(
    (SELECT count(*)::int FROM rbac.member_permissions
     WHERE group_id = 'eeeeeeee-0000-0000-0000-000000000002'::uuid
       AND user_id = 'eeeeeeee-0000-0000-0000-000000000001'::uuid
       AND permission = 'data.export'),
    0,
    'revoke_member_permission() removes the permission override row'
);

-- ── Test 5: revoke_member_permission() raises when override not found ─────────
SELECT throws_ok(
    $$SELECT rbac.revoke_member_permission(
        'eeeeeeee-0000-0000-0000-000000000002'::uuid,
        'eeeeeeee-0000-0000-0000-000000000001'::uuid,
        'data.export'
    )$$,
    'P0001',
    'Permission override not found for member',
    'revoke_member_permission() raises when override does not exist'
);

-- ── Test 6: member_permissions rows CASCADE-DELETE when member is removed ──────
SELECT rbac.grant_member_permission(
    'eeeeeeee-0000-0000-0000-000000000002'::uuid,
    'eeeeeeee-0000-0000-0000-000000000001'::uuid,
    'data.archive'
);

DELETE FROM rbac.members
WHERE group_id = 'eeeeeeee-0000-0000-0000-000000000002'::uuid
  AND user_id = 'eeeeeeee-0000-0000-0000-000000000001'::uuid;

SELECT is(
    (SELECT count(*)::int FROM rbac.member_permissions
     WHERE user_id = 'eeeeeeee-0000-0000-0000-000000000001'::uuid),
    0,
    'member_permissions rows are cascade-deleted when member is removed'
);

-- ── Test 7: member_permissions rows CASCADE-DELETE when group is deleted ────────
-- Re-add member and grant a permission so we have something to cascade
INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('eeeeeeee-0000-0000-0000-000000000002'::uuid,
        'eeeeeeee-0000-0000-0000-000000000001'::uuid, ARRAY['owner']);

SELECT rbac.grant_member_permission(
    'eeeeeeee-0000-0000-0000-000000000002'::uuid,
    'eeeeeeee-0000-0000-0000-000000000001'::uuid,
    'data.export'
);

DELETE FROM rbac.groups WHERE id = 'eeeeeeee-0000-0000-0000-000000000002'::uuid;

SELECT is(
    (SELECT count(*)::int FROM rbac.member_permissions
     WHERE group_id = 'eeeeeeee-0000-0000-0000-000000000002'::uuid),
    0,
    'member_permissions rows are cascade-deleted when group is deleted'
);

SELECT * FROM finish();
ROLLBACK;
