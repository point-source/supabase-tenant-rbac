-- Tests for SECURITY DEFINER function isolation (SD-01 through SD-06).
-- Verifies that create_group/accept_invite behave atomically and only affect
-- the specified scope, that internal trigger functions are inaccessible to
-- authenticated/anon, and that accept_invite cannot be called twice.

BEGIN;
SELECT plan(6);

-- ─────────────────────────────────────────────────────────────────────────────
-- Setup: alice user, group G, group G2 for invite tests
-- ─────────────────────────────────────────────────────────────────────────────

INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES
    ('aa000000-0000-0000-0000-000000000001'::uuid, 'sd-alice@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('bb000000-0000-0000-0000-000000000001'::uuid, 'sd-bob@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated');

INSERT INTO rbac.groups (id, name) VALUES
    ('f0000000-0000-0000-0000-000000000001'::uuid, 'SD Test Group G'),
    ('f0000000-0000-0000-0000-000000000002'::uuid, 'SD Test Group G2');

-- Alice is a member of both G and G2 (so invited_by FK is satisfied)
INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'aa000000-0000-0000-0000-000000000001'::uuid, ARRAY['owner']),
    ('f0000000-0000-0000-0000-000000000002'::uuid,
     'aa000000-0000-0000-0000-000000000001'::uuid, ARRAY['owner']);

-- Create two invites: invite_1 for G, invite_2 for G2
INSERT INTO rbac.invites (id, group_id, roles, invited_by) VALUES
    ('aa000001-0000-0000-0000-000000000001'::uuid,
     'f0000000-0000-0000-0000-000000000001'::uuid,
     ARRAY['viewer'],
     'aa000000-0000-0000-0000-000000000001'::uuid),
    ('aa000002-0000-0000-0000-000000000001'::uuid,
     'f0000000-0000-0000-0000-000000000002'::uuid,
     ARRAY['viewer'],
     'aa000000-0000-0000-0000-000000000001'::uuid);

-- ── SD-01: create_group creates exactly one group and one member row ───────────
-- Track counts before and after to verify atomic creation.
DO $$
DECLARE
    v_new_group_id uuid;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"aa000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM set_config('request.groups',
        (SELECT claims::text FROM rbac.user_claims
         WHERE user_id = 'aa000000-0000-0000-0000-000000000001'::uuid),
        true);
    SET LOCAL ROLE authenticated;
    v_new_group_id := rbac.create_group('SD Alpha Group', '{}', ARRAY['owner']);
    RESET ROLE;
    PERFORM set_config('test.sd01_group_id', v_new_group_id::text, true);
END$$;

SELECT ok(
    (SELECT count(*)::int FROM rbac.groups
     WHERE id = current_setting('test.sd01_group_id')::uuid
       AND name = 'SD Alpha Group') = 1
    AND
    (SELECT count(*)::int FROM rbac.members
     WHERE group_id = current_setting('test.sd01_group_id')::uuid
       AND 'owner' = ANY(roles)) = 1,
    'SD-01: create_group creates exactly one group row and one membership row'
);

-- ── SD-02: create_group uses caller auth.uid() for membership ─────────────────
-- The members row created by create_group must have user_id = alice's uuid.
SELECT ok(
    EXISTS (
        SELECT 1 FROM rbac.members
        WHERE group_id = current_setting('test.sd01_group_id')::uuid
          AND user_id = 'aa000000-0000-0000-0000-000000000001'::uuid
          AND 'owner' = ANY(roles)
    ),
    'SD-02: create_group membership row uses caller auth.uid() — not a spoofable parameter'
);

-- ── SD-03: accept_invite(invite_1) adds bob to G only, invite_2 untouched ─────
DO $$
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"bb000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM set_config('request.groups', '{}', true);
    SET LOCAL ROLE authenticated;
    PERFORM rbac.accept_invite('aa000001-0000-0000-0000-000000000001'::uuid);
    RESET ROLE;
END$$;

SELECT ok(
    -- bob is now in G (invite_1's group)
    (SELECT count(*)::int FROM rbac.members
     WHERE group_id = 'f0000000-0000-0000-0000-000000000001'::uuid
       AND user_id = 'bb000000-0000-0000-0000-000000000001'::uuid) = 1
    AND
    -- bob is NOT in G2 (invite_2's group)
    (SELECT count(*)::int FROM rbac.members
     WHERE group_id = 'f0000000-0000-0000-0000-000000000002'::uuid
       AND user_id = 'bb000000-0000-0000-0000-000000000001'::uuid) = 0
    AND
    -- invite_2 is still pending (not accepted)
    (SELECT accepted_at IS NULL FROM rbac.invites
     WHERE id = 'aa000002-0000-0000-0000-000000000001'::uuid),
    'SD-03: accept_invite(invite_1) adds bob to G only — invite_2 unaffected'
);

-- ── SD-04: accept_invite cannot be called twice on the same invite ─────────────
-- invite_1 is already accepted above. Bob calls it again → DENY.
DO $$
DECLARE
    v_blocked boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"bb000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM set_config('request.groups',
        (SELECT claims::text FROM rbac.user_claims
         WHERE user_id = 'bb000000-0000-0000-0000-000000000001'::uuid),
        true);
    SET LOCAL ROLE authenticated;
    BEGIN
        PERFORM rbac.accept_invite('aa000001-0000-0000-0000-000000000001'::uuid);
    EXCEPTION WHEN OTHERS THEN
        v_blocked := true;
    END;
    RESET ROLE;
    PERFORM set_config('test.sd04', v_blocked::text, true);
END$$;

SELECT ok(
    current_setting('test.sd04') = 'true',
    'SD-04: accept_invite raises when invite is already accepted — idempotency guard'
);

-- ── SD-05: authenticated cannot call rbac._sync_member_metadata() directly ────
-- _sync_member_metadata is a trigger function (RETURNS trigger) that also lacks
-- EXECUTE grant for authenticated. Verify the privilege check.
SELECT ok(
    NOT has_function_privilege('authenticated', 'rbac._sync_member_metadata()', 'EXECUTE'),
    'SD-05: authenticated does not have EXECUTE on rbac._sync_member_metadata() — internal trigger function'
);

-- ── SD-06: anon cannot call rbac._build_user_claims(uuid) ─────────────────────
-- _build_user_claims was revoked from PUBLIC in v5.2.1. Neither anon nor
-- authenticated have a re-grant on it.
SELECT ok(
    NOT has_function_privilege('anon', 'rbac._build_user_claims(uuid)', 'EXECUTE'),
    'SD-06: anon does not have EXECUTE on rbac._build_user_claims(uuid) — internal helper locked down'
);

SELECT * FROM finish();
ROLLBACK;
