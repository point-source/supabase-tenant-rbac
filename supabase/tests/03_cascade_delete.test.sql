-- Tests for issue #38: ON DELETE CASCADE on foreign keys.
-- Verifies that deleting a group cleans up members and invites,
-- and that orphaned roles are removed from rbac.user_claims.

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
INSERT INTO rbac.groups (id, name) VALUES
    ('cccccccc-0000-0000-0000-000000000002'::uuid, 'Group A'),
    ('cccccccc-0000-0000-0000-000000000003'::uuid, 'Group B');

-- Assign role in Group A
INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('cccccccc-0000-0000-0000-000000000002'::uuid,
        'cccccccc-0000-0000-0000-000000000001'::uuid, ARRAY['admin']);

-- Also assign in Group B (to verify only Group A is cleaned up)
INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('cccccccc-0000-0000-0000-000000000003'::uuid,
        'cccccccc-0000-0000-0000-000000000001'::uuid, ARRAY['viewer']);

-- Create an invite in Group A
INSERT INTO rbac.invites (id, group_id, roles, invited_by)
VALUES (
    'cccccccc-0000-0000-0000-000000000004'::uuid,
    'cccccccc-0000-0000-0000-000000000002'::uuid,
    ARRAY['viewer'],
    'cccccccc-0000-0000-0000-000000000001'::uuid
);

-- Test 1: role was synced to user_claims for Group A
SELECT ok(
    (SELECT claims ? 'cccccccc-0000-0000-0000-000000000002'
     FROM rbac.user_claims WHERE user_id = 'cccccccc-0000-0000-0000-000000000001'::uuid),
    'Group A role is in user_claims before group deletion'
);

-- Test 2: role was synced to user_claims for Group B
SELECT ok(
    (SELECT claims ? 'cccccccc-0000-0000-0000-000000000003'
     FROM rbac.user_claims WHERE user_id = 'cccccccc-0000-0000-0000-000000000001'::uuid),
    'Group B role is in user_claims before group deletion'
);

-- Delete Group A
DELETE FROM rbac.groups WHERE id = 'cccccccc-0000-0000-0000-000000000002'::uuid;

-- Test 3: members for Group A was cascade-deleted
SELECT is(
    (SELECT count(*)::integer FROM rbac.members
     WHERE group_id = 'cccccccc-0000-0000-0000-000000000002'::uuid),
    0,
    'members rows are cascade-deleted when group is deleted'
);

-- Test 4: invites for Group A was cascade-deleted
SELECT is(
    (SELECT count(*)::integer FROM rbac.invites
     WHERE group_id = 'cccccccc-0000-0000-0000-000000000002'::uuid),
    0,
    'invites rows are cascade-deleted when group is deleted'
);

-- Test 5: Group B membership is still intact
SELECT is(
    (SELECT count(*)::integer FROM rbac.members
     WHERE group_id = 'cccccccc-0000-0000-0000-000000000003'::uuid),
    1,
    'Group B members row is not affected by Group A deletion'
);

-- Test 6: Group A role removed from user_claims
SELECT ok(
    NOT (SELECT claims ? 'cccccccc-0000-0000-0000-000000000002'
         FROM rbac.user_claims WHERE user_id = 'cccccccc-0000-0000-0000-000000000001'::uuid),
    'Group A role is removed from user_claims after group deletion'
);

-- Test 7: Group B role still in user_claims
SELECT ok(
    (SELECT claims ? 'cccccccc-0000-0000-0000-000000000003'
     FROM rbac.user_claims WHERE user_id = 'cccccccc-0000-0000-0000-000000000001'::uuid),
    'Group B role remains in user_claims after Group A deletion'
);

SELECT * FROM finish();
ROLLBACK;
