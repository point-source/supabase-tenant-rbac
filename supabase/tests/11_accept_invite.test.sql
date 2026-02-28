-- Tests for accept_invite() RPC (v5.0.0).
-- Verifies that the function: accepts valid invites atomically, marks the invite
-- as consumed, syncs roles to auth.users via trigger, rejects expired/used/missing
-- invites, and merges roles into single membership row.

BEGIN;
SELECT plan(9);

-- Setup: inviter user
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    'bbbbbbbb-0000-0000-0000-000000000001'::uuid,
    'inviter-11@example.local',
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
    'bbbbbbbb-0000-0000-0000-000000000002'::uuid,
    'accepter-11@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

-- Setup: test group
INSERT INTO rbac.groups (id, name)
VALUES ('bbbbbbbb-0000-0000-0000-000000000003'::uuid, 'Accept Invite Test Group');

-- Setup: ensure needed roles exist
INSERT INTO rbac.roles (name) VALUES ('member'), ('viewer'), ('admin') ON CONFLICT DO NOTHING;

-- Setup: three invites
INSERT INTO rbac.invites (id, group_id, roles, invited_by, expires_at) VALUES
    -- valid, single role
    ('bbbbbbbb-0000-0000-0000-000000000004'::uuid,
     'bbbbbbbb-0000-0000-0000-000000000003'::uuid,
     ARRAY['member'],
     'bbbbbbbb-0000-0000-0000-000000000001'::uuid,
     NULL),
    -- expired
    ('bbbbbbbb-0000-0000-0000-000000000005'::uuid,
     'bbbbbbbb-0000-0000-0000-000000000003'::uuid,
     ARRAY['viewer'],
     'bbbbbbbb-0000-0000-0000-000000000001'::uuid,
     now() - interval '1 hour'),
    -- multi-role
    ('bbbbbbbb-0000-0000-0000-000000000006'::uuid,
     'bbbbbbbb-0000-0000-0000-000000000003'::uuid,
     ARRAY['owner', 'admin', 'viewer'],
     'bbbbbbbb-0000-0000-0000-000000000001'::uuid,
     NULL);

-- ── Test 1: valid invite acceptance succeeds ──────────────────────────────────
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"bbbbbbbb-0000-0000-0000-000000000002","exp":9999999999}',
    true);
SELECT lives_ok(
    'SELECT rbac.accept_invite(''bbbbbbbb-0000-0000-0000-000000000004''::uuid)',
    'accept_invite() succeeds for a valid invite'
);

-- ── Test 2: accepted_at is set after acceptance ───────────────────────────────
SELECT ok(
    (SELECT accepted_at IS NOT NULL
     FROM rbac.invites
     WHERE id = 'bbbbbbbb-0000-0000-0000-000000000004'::uuid),
    'accepted_at is set on the accepted invite'
);

-- ── Test 3: user_id is set to the accepter ───────────────────────────────────
SELECT ok(
    (SELECT user_id = 'bbbbbbbb-0000-0000-0000-000000000002'::uuid
     FROM rbac.invites
     WHERE id = 'bbbbbbbb-0000-0000-0000-000000000004'::uuid),
    'user_id is set to the accepter on the accepted invite'
);

-- ── Test 4: trigger synced roles to rbac.user_claims ─────────────────────────
SELECT ok(
    (SELECT claims ? 'bbbbbbbb-0000-0000-0000-000000000003'
     FROM rbac.user_claims
     WHERE user_id = 'bbbbbbbb-0000-0000-0000-000000000002'::uuid),
    'roles synced to rbac.user_claims after invite acceptance'
);

-- ── Test 5: expired invite raises exception ───────────────────────────────────
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"bbbbbbbb-0000-0000-0000-000000000002","exp":9999999999}',
    true);
SELECT throws_ok(
    'SELECT rbac.accept_invite(''bbbbbbbb-0000-0000-0000-000000000005''::uuid)',
    'P0001',
    'Invite not found, already used, or expired',
    'accept_invite() raises exception for an expired invite'
);

-- ── Test 6: already-accepted invite raises exception ─────────────────────────
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"bbbbbbbb-0000-0000-0000-000000000002","exp":9999999999}',
    true);
SELECT throws_ok(
    'SELECT rbac.accept_invite(''bbbbbbbb-0000-0000-0000-000000000004''::uuid)',
    'P0001',
    'Invite not found, already used, or expired',
    'accept_invite() raises exception for an already-accepted invite'
);

-- ── Test 7: nonexistent invite ID raises exception ────────────────────────────
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"bbbbbbbb-0000-0000-0000-000000000002","exp":9999999999}',
    true);
SELECT throws_ok(
    'SELECT rbac.accept_invite(''00000000-dead-dead-dead-000000000000''::uuid)',
    'P0001',
    'Invite not found, already used, or expired',
    'accept_invite() raises exception for a nonexistent invite ID'
);

-- ── Test 8: multi-role invite acceptance succeeds ─────────────────────────────
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"bbbbbbbb-0000-0000-0000-000000000002","exp":9999999999}',
    true);
SELECT lives_ok(
    'SELECT rbac.accept_invite(''bbbbbbbb-0000-0000-0000-000000000006''::uuid)',
    'accept_invite() succeeds for a multi-role invite'
);

-- ── Test 9: multi-role invite merges all roles into the single membership row ─
-- In v5.0.0, one row per membership with roles[] array. The multi-role invite
-- merges with the existing 'member' role from test 1.
SELECT ok(
    (SELECT roles @> ARRAY['owner', 'admin', 'viewer', 'member']
     FROM rbac.members
     WHERE user_id = 'bbbbbbbb-0000-0000-0000-000000000002'::uuid
       AND group_id = 'bbbbbbbb-0000-0000-0000-000000000003'::uuid),
    'multi-role invite merges all roles into single membership row'
);

SELECT * FROM finish();
ROLLBACK;
