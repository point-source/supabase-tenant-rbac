-- Regression tests for issue #11:
-- Deleting a user from auth.users cascaded to group_users, which fired the
-- update_user_roles trigger, which then tried to UPDATE the now-deleted user
-- in auth.users — causing an error.

BEGIN;
SELECT plan(4);

-- Setup: create a test user and group
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    'ffffffff-0000-0000-0000-000000000001'::uuid,
    'deletion-test@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

INSERT INTO public.groups (id, metadata)
VALUES ('ffffffff-0000-0000-0000-000000000002'::uuid, '{"name":"Test Group"}');

-- Assign a role (this fires the trigger and syncs to raw_app_meta_data)
INSERT INTO public.group_users (group_id, user_id, role)
VALUES (
    'ffffffff-0000-0000-0000-000000000002'::uuid,
    'ffffffff-0000-0000-0000-000000000001'::uuid,
    'member'
);

-- Test 1: trigger correctly synced the role to auth.users
SELECT is(
    (SELECT raw_app_meta_data->'groups'->'ffffffff-0000-0000-0000-000000000002'
     FROM auth.users WHERE id = 'ffffffff-0000-0000-0000-000000000001'::uuid),
    '["member"]'::jsonb,
    'trigger synced role to auth.users.raw_app_meta_data on INSERT'
);

-- Test 2: deleting the user does not crash (regression for #11)
SELECT lives_ok(
    $$DELETE FROM auth.users WHERE id = 'ffffffff-0000-0000-0000-000000000001'$$,
    'deleting a user with group memberships does not throw an error'
);

-- Test 3: group_users row was cascade-deleted (fix #38)
SELECT is(
    (SELECT count(*)::integer FROM public.group_users
     WHERE user_id = 'ffffffff-0000-0000-0000-000000000001'::uuid),
    0,
    'group_users rows are cascade-deleted when user is deleted'
);

-- Test 4: the user is actually gone
SELECT is(
    (SELECT count(*)::integer FROM auth.users
     WHERE id = 'ffffffff-0000-0000-0000-000000000001'::uuid),
    0,
    'user is deleted from auth.users'
);

SELECT * FROM finish();
ROLLBACK;
