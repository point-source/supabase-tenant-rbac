-- Regression tests for issue #11:
-- Deleting a user from auth.users cascaded to members, which fired the
-- _sync_member_metadata trigger, which then tried to UPDATE the now-deleted user.
-- In v5.0.0, user_claims has ON DELETE CASCADE on user_id FK, so the trigger's
-- INSERT into user_claims will fail with a foreign_key_violation (caught and
-- ignored). The user_claims row is also cleaned up automatically by the CASCADE.

BEGIN;
SELECT plan(5);

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

INSERT INTO rbac.groups (id, name)
VALUES ('ffffffff-0000-0000-0000-000000000002'::uuid, 'Test Group');

-- Assign roles (this fires the trigger and syncs to user_claims)
INSERT INTO rbac.members (group_id, user_id, roles)
VALUES (
    'ffffffff-0000-0000-0000-000000000002'::uuid,
    'ffffffff-0000-0000-0000-000000000001'::uuid,
    ARRAY['member']
);

-- Test 1: trigger correctly synced the roles to user_claims
SELECT is(
    (SELECT claims->'ffffffff-0000-0000-0000-000000000002'
     FROM rbac.user_claims WHERE user_id = 'ffffffff-0000-0000-0000-000000000001'::uuid),
    '["member"]'::jsonb,
    'trigger synced roles to rbac.user_claims on INSERT'
);

-- Test 2: deleting the user does not crash (regression for #11)
SELECT lives_ok(
    $$DELETE FROM auth.users WHERE id = 'ffffffff-0000-0000-0000-000000000001'$$,
    'deleting a user with group memberships does not throw an error'
);

-- Test 3: members row was cascade-deleted
SELECT is(
    (SELECT count(*)::integer FROM rbac.members
     WHERE user_id = 'ffffffff-0000-0000-0000-000000000001'::uuid),
    0,
    'members rows are cascade-deleted when user is deleted'
);

-- Test 4: the user is actually gone
SELECT is(
    (SELECT count(*)::integer FROM auth.users
     WHERE id = 'ffffffff-0000-0000-0000-000000000001'::uuid),
    0,
    'user is deleted from auth.users'
);

-- Test 5: user_claims row is also cascade-deleted when user is deleted
SELECT is(
    (SELECT count(*)::integer FROM rbac.user_claims
     WHERE user_id = 'ffffffff-0000-0000-0000-000000000001'::uuid),
    0,
    'user_claims row is cascade-deleted when user is deleted (FK ON DELETE CASCADE)'
);

SELECT * FROM finish();
ROLLBACK;
