-- Tests for group CRUD operations and related invariants:
-- group creation, default values, metadata updates, the _set_updated_at trigger,
-- deletion, and duplicate-invite-acceptance prevention.

BEGIN;
SELECT plan(9);

-- Setup: a user to act as inviter / group member
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    'ffffffff-0000-0000-0000-000000000001'::uuid,
    'group-crud-user@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

-- Setup: a second user (used for re-accept attempt)
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    'ffffffff-0000-0000-0000-000000000002'::uuid,
    'group-crud-user2@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

-- Insert the test group with an explicit updated_at in the past so we can
-- detect the _set_updated_at trigger firing.
INSERT INTO rbac.groups (id, name, metadata, created_at, updated_at)
VALUES (
    'ffffffff-0000-0000-0000-000000000003'::uuid,
    'CRUD Test',
    '{}'::jsonb,
    '2000-01-01 00:00:00+00'::timestamptz,
    '2000-01-01 00:00:00+00'::timestamptz
);

-- Test 1: group can be created and exists in the table
SELECT ok(
    EXISTS(SELECT 1 FROM rbac.groups WHERE id = 'ffffffff-0000-0000-0000-000000000003'::uuid),
    'group can be inserted into groups table'
);

-- Test 2: default metadata is the empty JSONB object we inserted
SELECT is(
    (SELECT metadata FROM rbac.groups WHERE id = 'ffffffff-0000-0000-0000-000000000003'::uuid),
    '{}'::jsonb,
    'group is created with empty metadata'
);

-- Update the group metadata
UPDATE rbac.groups
SET metadata = '{"active": true}'::jsonb
WHERE id = 'ffffffff-0000-0000-0000-000000000003'::uuid;

-- Test 3: metadata update is reflected correctly
SELECT is(
    (SELECT metadata->>'active' FROM rbac.groups WHERE id = 'ffffffff-0000-0000-0000-000000000003'::uuid),
    'true',
    'group metadata can be updated and new value is readable'
);

-- Test 4: _set_updated_at trigger fires — updated_at is now greater than the
-- epoch value we set at insert time
SELECT ok(
    (SELECT updated_at > '2000-01-01 00:00:00+00'::timestamptz
     FROM rbac.groups
     WHERE id = 'ffffffff-0000-0000-0000-000000000003'::uuid),
    '_set_updated_at trigger updates updated_at on group UPDATE'
);

-- Test 5: created_at is unchanged after the update
SELECT is(
    (SELECT created_at FROM rbac.groups WHERE id = 'ffffffff-0000-0000-0000-000000000003'::uuid),
    '2000-01-01 00:00:00+00'::timestamptz,
    'created_at is not modified by updates'
);

-- Delete the group (no members rows, so no cascade needed)
DELETE FROM rbac.groups WHERE id = 'ffffffff-0000-0000-0000-000000000003'::uuid;

-- Test 6: deleted group is gone from the table
SELECT ok(
    NOT EXISTS(SELECT 1 FROM rbac.groups WHERE id = 'ffffffff-0000-0000-0000-000000000003'::uuid),
    'group is removed from groups table after DELETE'
);

-- ── Duplicate-invite-acceptance prevention ──────────────────────────────────
-- Setup: a group and invite for the prevention tests
INSERT INTO rbac.groups (id, name)
VALUES ('ffffffff-0000-0000-0000-000000000004'::uuid, 'Invite Test');

-- Ensure 'viewer' role exists
INSERT INTO rbac.roles (name) VALUES ('viewer') ON CONFLICT DO NOTHING;

INSERT INTO rbac.invites (id, group_id, roles, invited_by)
VALUES (
    'ffffffff-0000-0000-0000-000000000005'::uuid,
    'ffffffff-0000-0000-0000-000000000004'::uuid,
    ARRAY['viewer'],
    'ffffffff-0000-0000-0000-000000000001'::uuid
);

-- First acceptance (legitimate)
UPDATE rbac.invites
SET user_id     = 'ffffffff-0000-0000-0000-000000000001'::uuid,
    accepted_at = now()
WHERE id = 'ffffffff-0000-0000-0000-000000000005'::uuid
  AND user_id IS NULL
  AND accepted_at IS NULL
  AND (expires_at IS NULL OR expires_at > now());

-- Test 7: first acceptance succeeded (accepted_at set)
SELECT ok(
    (SELECT accepted_at IS NOT NULL
     FROM rbac.invites
     WHERE id = 'ffffffff-0000-0000-0000-000000000005'::uuid),
    'first invite acceptance sets accepted_at'
);

-- Second acceptance attempt (re-use same invite, different user)
UPDATE rbac.invites
SET user_id     = 'ffffffff-0000-0000-0000-000000000002'::uuid,
    accepted_at = now()
WHERE id = 'ffffffff-0000-0000-0000-000000000005'::uuid
  AND user_id IS NULL
  AND accepted_at IS NULL
  AND (expires_at IS NULL OR expires_at > now());

-- Test 8: second acceptance attempt did not overwrite user_id
SELECT is(
    (SELECT user_id FROM rbac.invites
     WHERE id = 'ffffffff-0000-0000-0000-000000000005'::uuid),
    'ffffffff-0000-0000-0000-000000000001'::uuid,
    'already-accepted invite cannot be re-accepted by a different user'
);

-- Test 9: members upsert uniqueness — only one row per (group_id, user_id)
INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('ffffffff-0000-0000-0000-000000000004'::uuid,
        'ffffffff-0000-0000-0000-000000000001'::uuid, ARRAY['viewer']);

INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('ffffffff-0000-0000-0000-000000000004'::uuid,
        'ffffffff-0000-0000-0000-000000000001'::uuid, ARRAY['viewer'])
ON CONFLICT (group_id, user_id) DO NOTHING;

SELECT is(
    (SELECT count(*)::integer FROM rbac.members
     WHERE group_id = 'ffffffff-0000-0000-0000-000000000004'::uuid
       AND user_id  = 'ffffffff-0000-0000-0000-000000000001'::uuid),
    1,
    'inserting duplicate members row is idempotent (ON CONFLICT DO NOTHING)'
);

SELECT * FROM finish();
ROLLBACK;
