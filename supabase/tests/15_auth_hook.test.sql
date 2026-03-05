-- Tests for AH-01 through AH-03: custom_access_token_hook() behaviour.
-- Verifies that the hook correctly injects group claims into JWT app_metadata,
-- returns empty groups for groupless users, and handles NULL/missing claims rows
-- without raising an exception.

BEGIN;
SELECT plan(3);

-- Setup: alice (owner in G), groupless user
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    '32000000-0000-0000-0000-000000000001'::uuid,
    'ah-alice@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
), (
    '32000000-0000-0000-0000-000000000003'::uuid,
    'ah-groupless@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

INSERT INTO rbac.groups (id, name)
VALUES ('32000000-0000-0000-0000-000000000002'::uuid, 'AH Test Group');

INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('32000000-0000-0000-0000-000000000002'::uuid,
     '32000000-0000-0000-0000-000000000001'::uuid,
     ARRAY['owner']);

-- ── AH-01: hook injects group claims for a user with memberships ──────────────
-- Call the hook directly as postgres (bypasses auth check).
-- Verify the returned event has app_metadata.groups containing the group key.
SELECT ok(
    (rbac.custom_access_token_hook(
        jsonb_build_object(
            'user_id', '32000000-0000-0000-0000-000000000001',
            'claims', jsonb_build_object(
                'sub', '32000000-0000-0000-0000-000000000001',
                'app_metadata', '{}'::jsonb
            )
        )
    ))->'claims'->'app_metadata'->'groups'
        ? '32000000-0000-0000-0000-000000000002',
    'AH-01: custom_access_token_hook() injects group G into claims.app_metadata.groups'
);

-- ── AH-02: hook returns empty groups object for a groupless user ──────────────
SELECT is(
    (rbac.custom_access_token_hook(
        jsonb_build_object(
            'user_id', '32000000-0000-0000-0000-000000000003',
            'claims', jsonb_build_object('app_metadata', '{}'::jsonb)
        )
    ))->'claims'->'app_metadata'->'groups',
    '{}'::jsonb,
    'AH-02: hook returns empty groups object for a user with no memberships'
);

-- ── AH-03: hook handles NULL user_claims row without raising ──────────────────
-- Delete alice's user_claims row to simulate corrupted/missing state.
-- The hook uses coalesce(user_groups, '{}') so it must not raise.
DELETE FROM rbac.user_claims
WHERE user_id = '32000000-0000-0000-0000-000000000001'::uuid;

SELECT lives_ok(
    $$SELECT rbac.custom_access_token_hook(
        jsonb_build_object(
            'user_id', '32000000-0000-0000-0000-000000000001',
            'claims', jsonb_build_object('app_metadata', '{}'::jsonb)
        )
    )$$,
    'AH-03: hook does not raise when user_claims row is absent (NULL coalesce to {})'
);

SELECT * FROM finish();
ROLLBACK;
