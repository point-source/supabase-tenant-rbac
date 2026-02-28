-- Tests for custom_access_token_hook() (v5.0.0).
-- Verifies that the Supabase Auth Hook injects group claims into JWT
-- app_metadata by reading from rbac.user_claims.
--
-- Register this hook in supabase/config.toml:
--   [auth.hook.custom_access_token]
--   enabled = true
--   uri = "pg-functions://postgres/public/custom_access_token_hook"

BEGIN;
SELECT plan(5);

-- Setup: test user with group membership
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    'eeeeeeee-0000-0000-0000-000000000001'::uuid,
    'hook-test@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
), (
    'eeeeeeee-0000-0000-0000-000000000009'::uuid,
    'hook-test-groupless@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

INSERT INTO rbac.groups (id, name)
VALUES ('eeeeeeee-0000-0000-0000-000000000002'::uuid, 'Hook Test Group');

-- Insert membership — trigger populates user_claims automatically
INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('eeeeeeee-0000-0000-0000-000000000002'::uuid,
        'eeeeeeee-0000-0000-0000-000000000001'::uuid, ARRAY['owner']);

-- ── Test 1: hook is callable without error ────────────────────────────────────
SELECT lives_ok(
    $$SELECT rbac.custom_access_token_hook(
        '{"user_id":"eeeeeeee-0000-0000-0000-000000000001",
          "claims":{"sub":"eeeeeeee-0000-0000-0000-000000000001","app_metadata":{}}}'::jsonb
    )$$,
    'custom_access_token_hook() does not throw when called with a valid event'
);

-- ── Test 2: hook injects groups into app_metadata ─────────────────────────────
SELECT is(
    (rbac.custom_access_token_hook(
        '{"user_id":"eeeeeeee-0000-0000-0000-000000000001",
          "claims":{"sub":"eeeeeeee-0000-0000-0000-000000000001","app_metadata":{}}}'::jsonb
    ))->'claims'->'app_metadata'->'groups'->'eeeeeeee-0000-0000-0000-000000000002',
    '["owner"]'::jsonb,
    'hook injects correct group/role data into claims.app_metadata.groups'
);

-- ── Test 3: hook with no memberships returns empty groups ──────────────────────
SELECT is(
    (rbac.custom_access_token_hook(
        '{"user_id":"eeeeeeee-0000-0000-0000-000000000009",
          "claims":{"app_metadata":{}}}'::jsonb
    ))->'claims'->'app_metadata'->'groups',
    '{}'::jsonb,
    'hook returns empty groups object for user with no memberships'
);

-- ── Test 4: hook with nonexistent user_id returns empty groups ─────────────────
SELECT is(
    (rbac.custom_access_token_hook(
        '{"user_id":"00000000-dead-dead-dead-000000000000",
          "claims":{"app_metadata":{}}}'::jsonb
    ))->'claims'->'app_metadata'->'groups',
    '{}'::jsonb,
    'hook returns empty groups object for nonexistent user_id'
);

-- ── Test 5: hook preserves existing app_metadata fields ───────────────────────
SELECT ok(
    (rbac.custom_access_token_hook(
        '{"user_id":"eeeeeeee-0000-0000-0000-000000000001",
          "claims":{"app_metadata":{"custom_key":"custom_value"}}}'::jsonb
    ))->'claims'->'app_metadata' @> '{"custom_key":"custom_value"}'::jsonb,
    'hook preserves existing app_metadata fields when merging groups'
);

SELECT * FROM finish();
ROLLBACK;
