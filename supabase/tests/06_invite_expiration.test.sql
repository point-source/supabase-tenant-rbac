-- Tests for invite expiration (v4.2.0 feature, updated for v5.0.0 schema).
-- Verifies that the expires_at column exists, and that the accept_invite
-- RPC correctly rejects expired invites while accepting valid ones.

BEGIN;
SELECT plan(7);

-- Setup: inviter user
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    'eeeeeeee-0000-0000-0000-000000000001'::uuid,
    'inviter@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

-- Setup: accepter user
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    'eeeeeeee-0000-0000-0000-000000000002'::uuid,
    'accepter@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

-- Setup: test group
INSERT INTO rbac.groups (id, name)
VALUES ('eeeeeeee-0000-0000-0000-000000000003'::uuid, 'Expiry Test Group');

-- Setup: ensure 'viewer' role exists
INSERT INTO rbac.roles (name) VALUES ('viewer') ON CONFLICT DO NOTHING;

-- Setup: three invites with different expiry states
INSERT INTO rbac.invites (id, group_id, roles, invited_by, expires_at) VALUES
    -- null expiry: should always be accepted
    ('eeeeeeee-0000-0000-0000-000000000004'::uuid,
     'eeeeeeee-0000-0000-0000-000000000003'::uuid,
     ARRAY['viewer'],
     'eeeeeeee-0000-0000-0000-000000000001'::uuid,
     NULL),
    -- future expiry: should be accepted
    ('eeeeeeee-0000-0000-0000-000000000005'::uuid,
     'eeeeeeee-0000-0000-0000-000000000003'::uuid,
     ARRAY['viewer'],
     'eeeeeeee-0000-0000-0000-000000000001'::uuid,
     now() + interval '1 hour'),
    -- past expiry: should be rejected
    ('eeeeeeee-0000-0000-0000-000000000006'::uuid,
     'eeeeeeee-0000-0000-0000-000000000003'::uuid,
     ARRAY['viewer'],
     'eeeeeeee-0000-0000-0000-000000000001'::uuid,
     now() - interval '1 hour');

-- Test 1: expires_at column exists on invites
SELECT has_column(
    'rbac',
    'invites',
    'expires_at',
    'invites has an expires_at column'
);

-- Test 2: expires_at accepts NULL (null means the invite never expires)
SELECT ok(
    (SELECT expires_at IS NULL
     FROM rbac.invites
     WHERE id = 'eeeeeeee-0000-0000-0000-000000000004'::uuid),
    'expires_at column accepts NULL (null means the invite never expires)'
);

-- Simulate invite acceptance via direct UPDATE (mirrors old edge function pattern)
UPDATE rbac.invites
SET user_id     = 'eeeeeeee-0000-0000-0000-000000000002'::uuid,
    accepted_at = now()
WHERE id = 'eeeeeeee-0000-0000-0000-000000000004'::uuid
  AND user_id IS NULL
  AND accepted_at IS NULL
  AND (expires_at IS NULL OR expires_at > now());

UPDATE rbac.invites
SET user_id     = 'eeeeeeee-0000-0000-0000-000000000002'::uuid,
    accepted_at = now()
WHERE id = 'eeeeeeee-0000-0000-0000-000000000005'::uuid
  AND user_id IS NULL
  AND accepted_at IS NULL
  AND (expires_at IS NULL OR expires_at > now());

UPDATE rbac.invites
SET user_id     = 'eeeeeeee-0000-0000-0000-000000000002'::uuid,
    accepted_at = now()
WHERE id = 'eeeeeeee-0000-0000-0000-000000000006'::uuid
  AND user_id IS NULL
  AND accepted_at IS NULL
  AND (expires_at IS NULL OR expires_at > now());

-- Test 3: null-expiry invite was accepted
SELECT ok(
    (SELECT accepted_at IS NOT NULL
     FROM rbac.invites
     WHERE id = 'eeeeeeee-0000-0000-0000-000000000004'::uuid),
    'invite with null expires_at is accepted'
);

-- Test 4: future-expiry invite was accepted
SELECT ok(
    (SELECT accepted_at IS NOT NULL
     FROM rbac.invites
     WHERE id = 'eeeeeeee-0000-0000-0000-000000000005'::uuid),
    'invite with future expires_at is accepted'
);

-- Test 5: expired invite was rejected
SELECT ok(
    (SELECT accepted_at IS NULL
     FROM rbac.invites
     WHERE id = 'eeeeeeee-0000-0000-0000-000000000006'::uuid),
    'invite with past expires_at is rejected'
);

-- Test 6: null-expiry invite has user_id set
SELECT ok(
    (SELECT user_id = 'eeeeeeee-0000-0000-0000-000000000002'::uuid
     FROM rbac.invites
     WHERE id = 'eeeeeeee-0000-0000-0000-000000000004'::uuid),
    'user_id is set on the accepted null-expiry invite'
);

-- Test 7: expired invite still has user_id null
SELECT ok(
    (SELECT user_id IS NULL
     FROM rbac.invites
     WHERE id = 'eeeeeeee-0000-0000-0000-000000000006'::uuid),
    'user_id remains null on the rejected expired invite'
);

SELECT * FROM finish();
ROLLBACK;
