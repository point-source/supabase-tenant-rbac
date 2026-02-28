-- Tests for the core role synchronization trigger (_sync_member_metadata).
-- Verifies that INSERT/UPDATE/DELETE on members correctly propagates
-- changes to rbac.user_claims.
--
-- In v5.0.0, members stores roles as a text[] array (one row per membership).
-- The trigger rebuilds the entire user's claims from the members table and
-- upserts into user_claims (replaces auth.users.raw_app_meta_data as cache).

BEGIN;
SELECT plan(8);

-- Setup: two test users (second needed for immutability tests)
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    'dddddddd-0000-0000-0000-000000000001'::uuid,
    'sync-test@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
), (
    'dddddddd-0000-0000-0000-000000000009'::uuid,
    'sync-test-alt@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

INSERT INTO rbac.groups (id, name) VALUES
    ('dddddddd-0000-0000-0000-000000000002'::uuid, 'Sync Test Group'),
    ('dddddddd-0000-0000-0000-000000000008'::uuid, 'Alt Group');

-- Test 1: INSERT into members syncs roles to user_claims
INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('dddddddd-0000-0000-0000-000000000002'::uuid,
        'dddddddd-0000-0000-0000-000000000001'::uuid, ARRAY['viewer']);

SELECT is(
    (SELECT claims->'dddddddd-0000-0000-0000-000000000002'
     FROM rbac.user_claims WHERE user_id = 'dddddddd-0000-0000-0000-000000000001'::uuid),
    '["viewer"]'::jsonb,
    'INSERT into members syncs roles array to rbac.user_claims'
);

-- Test 2: UPDATE adds roles to the array
UPDATE rbac.members
SET roles = ARRAY['viewer', 'admin']
WHERE group_id = 'dddddddd-0000-0000-0000-000000000002'::uuid
  AND user_id = 'dddddddd-0000-0000-0000-000000000001'::uuid;

SELECT ok(
    (SELECT claims->'dddddddd-0000-0000-0000-000000000002'
     FROM rbac.user_claims WHERE user_id = 'dddddddd-0000-0000-0000-000000000001'::uuid)
    @> '["viewer","admin"]'::jsonb,
    'UPDATE on roles syncs both roles to user_claims'
);

-- Test 3: roles array length matches after update
SELECT is(
    jsonb_array_length(
        (SELECT claims->'dddddddd-0000-0000-0000-000000000002'
         FROM rbac.user_claims WHERE user_id = 'dddddddd-0000-0000-0000-000000000001'::uuid)
    ),
    2,
    'user_claims has exactly 2 roles after update'
);

-- Test 4: UPDATE removing a role from the array
UPDATE rbac.members
SET roles = ARRAY['admin']
WHERE group_id = 'dddddddd-0000-0000-0000-000000000002'::uuid
  AND user_id = 'dddddddd-0000-0000-0000-000000000001'::uuid;

SELECT is(
    (SELECT claims->'dddddddd-0000-0000-0000-000000000002'
     FROM rbac.user_claims WHERE user_id = 'dddddddd-0000-0000-0000-000000000001'::uuid),
    '["admin"]'::jsonb,
    'UPDATE removing viewer leaves only admin in user_claims'
);

-- Test 5: DELETE of membership removes the group key from user_claims
DELETE FROM rbac.members
WHERE group_id = 'dddddddd-0000-0000-0000-000000000002'::uuid
  AND user_id = 'dddddddd-0000-0000-0000-000000000001'::uuid;

SELECT ok(
    NOT coalesce(
        (SELECT claims ? 'dddddddd-0000-0000-0000-000000000002'
         FROM rbac.user_claims WHERE user_id = 'dddddddd-0000-0000-0000-000000000001'::uuid),
        false
    ),
    'DELETE of membership removes the group key from user_claims entirely'
);

-- Test 6: UPDATE replaces roles correctly
INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('dddddddd-0000-0000-0000-000000000002'::uuid,
        'dddddddd-0000-0000-0000-000000000001'::uuid, ARRAY['viewer']);

UPDATE rbac.members
SET roles = ARRAY['owner']
WHERE group_id = 'dddddddd-0000-0000-0000-000000000002'::uuid
  AND user_id = 'dddddddd-0000-0000-0000-000000000001'::uuid;

SELECT is(
    (SELECT claims->'dddddddd-0000-0000-0000-000000000002'
     FROM rbac.user_claims WHERE user_id = 'dddddddd-0000-0000-0000-000000000001'::uuid),
    '["owner"]'::jsonb,
    'UPDATE replacing roles is reflected in user_claims'
);

-- Test 7: attempting to change user_id raises an exception
SELECT throws_ok(
    $$UPDATE rbac.members
      SET user_id = 'dddddddd-0000-0000-0000-000000000009'::uuid
      WHERE group_id = 'dddddddd-0000-0000-0000-000000000002'::uuid
        AND user_id = 'dddddddd-0000-0000-0000-000000000001'::uuid$$,
    'P0001',
    'Changing user_id or group_id is not allowed',
    'UPDATE on user_id raises an exception'
);

-- Test 8: attempting to change group_id raises an exception
SELECT throws_ok(
    $$UPDATE rbac.members
      SET group_id = 'dddddddd-0000-0000-0000-000000000008'::uuid
      WHERE user_id = 'dddddddd-0000-0000-0000-000000000001'::uuid$$,
    'P0001',
    'Changing user_id or group_id is not allowed',
    'UPDATE on group_id raises an exception'
);

SELECT * FROM finish();
ROLLBACK;
