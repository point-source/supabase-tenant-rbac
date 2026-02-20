-- Tests for the core role synchronization trigger (update_user_roles).
-- Verifies that INSERT/UPDATE/DELETE on group_users correctly propagates
-- changes to auth.users.raw_app_meta_data.

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

INSERT INTO public.groups (id, metadata) VALUES
    ('dddddddd-0000-0000-0000-000000000002'::uuid, '{"name":"Sync Test Group"}'),
    ('dddddddd-0000-0000-0000-000000000008'::uuid, '{"name":"Alt Group"}');

-- Test 1: INSERT into group_users syncs role to auth.users
INSERT INTO public.group_users (group_id, user_id, role)
VALUES ('dddddddd-0000-0000-0000-000000000002'::uuid,
        'dddddddd-0000-0000-0000-000000000001'::uuid, 'viewer');

SELECT is(
    (SELECT raw_app_meta_data->'groups'->'dddddddd-0000-0000-0000-000000000002'
     FROM auth.users WHERE id = 'dddddddd-0000-0000-0000-000000000001'::uuid),
    '["viewer"]'::jsonb,
    'INSERT into group_users adds role to auth.users.raw_app_meta_data'
);

-- Test 2: second INSERT adds second role (multi-role support)
INSERT INTO public.group_users (group_id, user_id, role)
VALUES ('dddddddd-0000-0000-0000-000000000002'::uuid,
        'dddddddd-0000-0000-0000-000000000001'::uuid, 'admin');

SELECT ok(
    (SELECT raw_app_meta_data->'groups'->'dddddddd-0000-0000-0000-000000000002'
     FROM auth.users WHERE id = 'dddddddd-0000-0000-0000-000000000001'::uuid)
    @> '["viewer","admin"]'::jsonb,
    'second INSERT adds second role (both roles present in metadata)'
);

-- Test 3: duplicate INSERT (via upsert) does not duplicate roles in metadata
INSERT INTO public.group_users (group_id, user_id, role)
VALUES ('dddddddd-0000-0000-0000-000000000002'::uuid,
        'dddddddd-0000-0000-0000-000000000001'::uuid, 'viewer')
ON CONFLICT (group_id, user_id, role) DO NOTHING;

SELECT is(
    jsonb_array_length(
        (SELECT raw_app_meta_data->'groups'->'dddddddd-0000-0000-0000-000000000002'
         FROM auth.users WHERE id = 'dddddddd-0000-0000-0000-000000000001'::uuid)
    ),
    2,
    'duplicate role INSERT does not create duplicate entries in metadata'
);

-- Test 4: DELETE removes the specific role from metadata
DELETE FROM public.group_users
WHERE group_id = 'dddddddd-0000-0000-0000-000000000002'::uuid
  AND user_id = 'dddddddd-0000-0000-0000-000000000001'::uuid
  AND role = 'viewer';

SELECT is(
    (SELECT raw_app_meta_data->'groups'->'dddddddd-0000-0000-0000-000000000002'
     FROM auth.users WHERE id = 'dddddddd-0000-0000-0000-000000000001'::uuid),
    '["admin"]'::jsonb,
    'DELETE from group_users removes only that role from metadata (admin remains)'
);

-- Test 5: DELETE of last role removes the group key from metadata
DELETE FROM public.group_users
WHERE group_id = 'dddddddd-0000-0000-0000-000000000002'::uuid
  AND user_id = 'dddddddd-0000-0000-0000-000000000001'::uuid
  AND role = 'admin';

SELECT ok(
    NOT (SELECT raw_app_meta_data->'groups' ? 'dddddddd-0000-0000-0000-000000000002'
         FROM auth.users WHERE id = 'dddddddd-0000-0000-0000-000000000001'::uuid),
    'DELETE of last role removes the group key from metadata entirely'
);

-- Test 6: UPDATE on role column changes the role in metadata
INSERT INTO public.group_users (group_id, user_id, role)
VALUES ('dddddddd-0000-0000-0000-000000000002'::uuid,
        'dddddddd-0000-0000-0000-000000000001'::uuid, 'viewer');

UPDATE public.group_users
SET role = 'owner'
WHERE group_id = 'dddddddd-0000-0000-0000-000000000002'::uuid
  AND user_id = 'dddddddd-0000-0000-0000-000000000001'::uuid
  AND role = 'viewer';

SELECT is(
    (SELECT raw_app_meta_data->'groups'->'dddddddd-0000-0000-0000-000000000002'
     FROM auth.users WHERE id = 'dddddddd-0000-0000-0000-000000000001'::uuid),
    '["owner"]'::jsonb,
    'UPDATE role replaces old role with new role in metadata'
);

-- Test 7: attempting to change user_id raises an exception
-- Use an existing valid user_id so the FK passes and the trigger can check
SELECT throws_ok(
    $$UPDATE public.group_users
      SET user_id = 'dddddddd-0000-0000-0000-000000000009'::uuid
      WHERE group_id = 'dddddddd-0000-0000-0000-000000000002'::uuid
        AND user_id = 'dddddddd-0000-0000-0000-000000000001'::uuid$$,
    'P0001',
    'Changing user_id or group_id is not allowed',
    'UPDATE on user_id raises an exception'
);

-- Test 8: attempting to change group_id raises an exception
-- Use an existing valid group_id so the FK passes and the trigger can check
SELECT throws_ok(
    $$UPDATE public.group_users
      SET group_id = 'dddddddd-0000-0000-0000-000000000008'::uuid
      WHERE user_id = 'dddddddd-0000-0000-0000-000000000001'::uuid$$,
    'P0001',
    'Changing user_id or group_id is not allowed',
    'UPDATE on group_id raises an exception'
);

SELECT * FROM finish();
ROLLBACK;
