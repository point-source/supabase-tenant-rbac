-- Tests for accept_group_invite() RPC (v4.4.0 feature).
-- Verifies that the function: accepts valid invites atomically, marks the invite
-- as consumed, syncs roles to auth.users via trigger, rejects expired/used/missing
-- invites, and inserts one group_users row per role in multi-role invites.
--
-- accept_group_invite() uses auth.uid() (reads request.jwt.claims) so the
-- accepter identity is controlled via set_config. The function is SECURITY DEFINER
-- so it runs as its owner (postgres) regardless of the current role — no SET LOCAL
-- ROLE is needed to call it; we just need the JWT claims set.

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
INSERT INTO public.groups (id, metadata)
VALUES ('bbbbbbbb-0000-0000-0000-000000000003'::uuid, '{"name":"Accept Invite Test Group"}');

-- Setup: three invites
INSERT INTO public.group_invites (id, group_id, roles, invited_by, expires_at) VALUES
    -- valid, single role — used for happy-path tests
    ('bbbbbbbb-0000-0000-0000-000000000004'::uuid,
     'bbbbbbbb-0000-0000-0000-000000000003'::uuid,
     ARRAY['member'],
     'bbbbbbbb-0000-0000-0000-000000000001'::uuid,
     NULL),
    -- expired — must be rejected
    ('bbbbbbbb-0000-0000-0000-000000000005'::uuid,
     'bbbbbbbb-0000-0000-0000-000000000003'::uuid,
     ARRAY['viewer'],
     'bbbbbbbb-0000-0000-0000-000000000001'::uuid,
     now() - interval '1 hour'),
    -- multi-role — used to verify all roles are inserted
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
    'SELECT public.accept_group_invite(''bbbbbbbb-0000-0000-0000-000000000004''::uuid)',
    'accept_group_invite() succeeds for a valid invite'
);

-- ── Test 2: accepted_at is set after acceptance ───────────────────────────────
SELECT ok(
    (SELECT accepted_at IS NOT NULL
     FROM public.group_invites
     WHERE id = 'bbbbbbbb-0000-0000-0000-000000000004'::uuid),
    'accepted_at is set on the accepted invite'
);

-- ── Test 3: user_id is set to the accepter ───────────────────────────────────
SELECT ok(
    (SELECT user_id = 'bbbbbbbb-0000-0000-0000-000000000002'::uuid
     FROM public.group_invites
     WHERE id = 'bbbbbbbb-0000-0000-0000-000000000004'::uuid),
    'user_id is set to the accepter on the accepted invite'
);

-- ── Test 4: trigger synced roles to auth.users.raw_app_meta_data ─────────────
-- The on_change_update_user_metadata trigger fires after the group_users INSERT,
-- adding the group to the accepter's raw_app_meta_data.
SELECT ok(
    (SELECT raw_app_meta_data->'groups' ? 'bbbbbbbb-0000-0000-0000-000000000003'
     FROM auth.users
     WHERE id = 'bbbbbbbb-0000-0000-0000-000000000002'::uuid),
    'roles synced to auth.users.raw_app_meta_data after invite acceptance'
);

-- ── Test 5: expired invite raises exception ───────────────────────────────────
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"bbbbbbbb-0000-0000-0000-000000000002","exp":9999999999}',
    true);
SELECT throws_ok(
    'SELECT public.accept_group_invite(''bbbbbbbb-0000-0000-0000-000000000005''::uuid)',
    'P0001',
    'Invite not found, already used, or expired',
    'accept_group_invite() raises exception for an expired invite'
);

-- ── Test 6: already-accepted invite raises exception ─────────────────────────
-- Invite bbbbbbbb-...0004 was accepted in test 1; attempting to accept it again
-- should fail because user_id IS NULL AND accepted_at IS NULL no longer matches.
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"bbbbbbbb-0000-0000-0000-000000000002","exp":9999999999}',
    true);
SELECT throws_ok(
    'SELECT public.accept_group_invite(''bbbbbbbb-0000-0000-0000-000000000004''::uuid)',
    'P0001',
    'Invite not found, already used, or expired',
    'accept_group_invite() raises exception for an already-accepted invite'
);

-- ── Test 7: nonexistent invite ID raises exception ────────────────────────────
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"bbbbbbbb-0000-0000-0000-000000000002","exp":9999999999}',
    true);
SELECT throws_ok(
    'SELECT public.accept_group_invite(''00000000-dead-dead-dead-000000000000''::uuid)',
    'P0001',
    'Invite not found, already used, or expired',
    'accept_group_invite() raises exception for a nonexistent invite ID'
);

-- ── Test 8: multi-role invite acceptance succeeds ─────────────────────────────
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"bbbbbbbb-0000-0000-0000-000000000002","exp":9999999999}',
    true);
SELECT lives_ok(
    'SELECT public.accept_group_invite(''bbbbbbbb-0000-0000-0000-000000000006''::uuid)',
    'accept_group_invite() succeeds for a multi-role invite'
);

-- ── Test 9: one group_users row per role in the multi-role invite ─────────────
SELECT is(
    (SELECT count(*)::int FROM public.group_users
     WHERE user_id = 'bbbbbbbb-0000-0000-0000-000000000002'::uuid
       AND group_id = 'bbbbbbbb-0000-0000-0000-000000000003'::uuid
       AND role = ANY(ARRAY['owner', 'admin', 'viewer'])),
    3,
    'multi-role invite creates one group_users row per role'
);

SELECT * FROM finish();
ROLLBACK;
