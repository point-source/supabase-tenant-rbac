-- Tests for issue #38: ON DELETE CASCADE on foreign keys.
-- Verifies that deleting a group cleans up group_users and group_invites,
-- and that orphaned roles are removed from auth.users.raw_app_meta_data.

BEGIN;
SELECT plan(7);

-- Setup: test user
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    'cccccccc-0000-0000-0000-000000000001'::uuid,
    'cascade-test@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

-- Setup: two test groups
INSERT INTO public.groups (id, metadata) VALUES
    ('cccccccc-0000-0000-0000-000000000002'::uuid, '{"name":"Group A"}'),
    ('cccccccc-0000-0000-0000-000000000003'::uuid, '{"name":"Group B"}');

-- Assign role in Group A
INSERT INTO public.group_users (group_id, user_id, role)
VALUES ('cccccccc-0000-0000-0000-000000000002'::uuid,
        'cccccccc-0000-0000-0000-000000000001'::uuid, 'admin');

-- Also assign in Group B (to verify only Group A is cleaned up)
INSERT INTO public.group_users (group_id, user_id, role)
VALUES ('cccccccc-0000-0000-0000-000000000003'::uuid,
        'cccccccc-0000-0000-0000-000000000001'::uuid, 'viewer');

-- Create an invite in Group A
INSERT INTO public.group_invites (id, group_id, roles, invited_by)
VALUES (
    'cccccccc-0000-0000-0000-000000000004'::uuid,
    'cccccccc-0000-0000-0000-000000000002'::uuid,
    ARRAY['viewer'],
    'cccccccc-0000-0000-0000-000000000001'::uuid
);

-- Test 1: role was synced to auth.users for Group A
SELECT ok(
    (SELECT raw_app_meta_data->'groups' ? 'cccccccc-0000-0000-0000-000000000002'
     FROM auth.users WHERE id = 'cccccccc-0000-0000-0000-000000000001'::uuid),
    'Group A role is in auth.users before group deletion'
);

-- Test 2: role was synced to auth.users for Group B
SELECT ok(
    (SELECT raw_app_meta_data->'groups' ? 'cccccccc-0000-0000-0000-000000000003'
     FROM auth.users WHERE id = 'cccccccc-0000-0000-0000-000000000001'::uuid),
    'Group B role is in auth.users before group deletion'
);

-- Delete Group A
DELETE FROM public.groups WHERE id = 'cccccccc-0000-0000-0000-000000000002'::uuid;

-- Test 3: group_users for Group A was cascade-deleted
SELECT is(
    (SELECT count(*)::integer FROM public.group_users
     WHERE group_id = 'cccccccc-0000-0000-0000-000000000002'::uuid),
    0,
    'group_users rows are cascade-deleted when group is deleted'
);

-- Test 4: group_invites for Group A was cascade-deleted
SELECT is(
    (SELECT count(*)::integer FROM public.group_invites
     WHERE group_id = 'cccccccc-0000-0000-0000-000000000002'::uuid),
    0,
    'group_invites rows are cascade-deleted when group is deleted'
);

-- Test 5: Group B membership is still intact
SELECT is(
    (SELECT count(*)::integer FROM public.group_users
     WHERE group_id = 'cccccccc-0000-0000-0000-000000000003'::uuid),
    1,
    'Group B group_users row is not affected by Group A deletion'
);

-- Test 6: Group A role removed from auth.users.raw_app_meta_data
SELECT ok(
    NOT (SELECT raw_app_meta_data->'groups' ? 'cccccccc-0000-0000-0000-000000000002'
         FROM auth.users WHERE id = 'cccccccc-0000-0000-0000-000000000001'::uuid),
    'Group A role is removed from auth.users.raw_app_meta_data after group deletion'
);

-- Test 7: Group B role still in auth.users.raw_app_meta_data
SELECT ok(
    (SELECT raw_app_meta_data->'groups' ? 'cccccccc-0000-0000-0000-000000000003'
     FROM auth.users WHERE id = 'cccccccc-0000-0000-0000-000000000001'::uuid),
    'Group B role remains in auth.users.raw_app_meta_data after Group A deletion'
);

SELECT * FROM finish();
ROLLBACK;
