-- Regression tests for issue #34:
-- db_pre_request does not fire for Supabase Storage requests.
-- Fixed in v4.3.0: get_claims() now falls back to _get_user_groups()
-- which reads rbac.user_claims directly instead of relying on the
-- PostgREST pre-request hook. Storage RLS policies now get the same
-- freshness guarantee as PostgREST requests.

BEGIN;
SELECT plan(8);

-- Setup: a user with group memberships in user_claims
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    'ffffffff-0000-0000-0000-000000000001'::uuid,
    'storage-test@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb,
    '{}'::jsonb,
    false, 'authenticated'
), (
    'ffffffff-0000-0000-0000-000000000009'::uuid,
    'storage-test-groupless@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

-- Populate user_claims directly (normally done by the trigger on members)
INSERT INTO rbac.user_claims (user_id, claims)
VALUES (
    'ffffffff-0000-0000-0000-000000000001'::uuid,
    '{"ffffffff-0000-0000-0000-000000000002":["member","editor"]}'::jsonb
);

-- Test 1: _get_user_groups() is callable without error
SELECT lives_ok(
    $$SELECT rbac._get_user_groups()$$,
    '_get_user_groups() does not throw when called with no user context'
);

-- Test 2: _get_user_groups() returns '{}' when auth.uid() is NULL
SELECT set_config('request.jwt.claims', '', true);
SELECT is(
    rbac._get_user_groups(),
    '{}'::jsonb,
    '_get_user_groups() returns empty object when auth.uid() is NULL'
);

-- Test 3: get_claims() returns request.groups when set (PostgREST path unchanged)
SELECT set_config('request.groups', '{"ffffffff-0000-0000-0000-000000000002":["admin"]}', true);
SELECT is(
    rbac.get_claims(),
    '{"ffffffff-0000-0000-0000-000000000002":["admin"]}'::jsonb,
    'get_claims() returns request.groups when set (PostgREST path takes precedence)'
);

-- Test 4: get_claims() returns '{}' when request.groups is empty and no user context
SELECT set_config('request.groups', '', true);
SELECT set_config('request.jwt.claims', '', true);
SELECT is(
    rbac.get_claims(),
    '{}'::jsonb,
    'get_claims() returns empty object when request.groups is empty and auth.uid() is NULL'
);

-- Test 5: _get_user_groups() reads fresh data from user_claims when user JWT is set
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"ffffffff-0000-0000-0000-000000000001"}',
    true);
SELECT is(
    rbac._get_user_groups(),
    '{"ffffffff-0000-0000-0000-000000000002":["member","editor"]}'::jsonb,
    '_get_user_groups() reads correct groups from rbac.user_claims for an authenticated user'
);

-- Test 6: get_claims() still prefers request.groups over _get_user_groups()
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"ffffffff-0000-0000-0000-000000000001"}',
    true);
SELECT set_config('request.groups',
    '{"ffffffff-0000-0000-0000-000000000002":["cached-role"]}',
    true);
SELECT is(
    rbac.get_claims(),
    '{"ffffffff-0000-0000-0000-000000000002":["cached-role"]}'::jsonb,
    'get_claims() prefers request.groups over _get_user_groups() when both are available'
);

-- Test 7: get_claims() falls back to _get_user_groups() when request.groups is empty
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"ffffffff-0000-0000-0000-000000000001"}',
    true);
SELECT set_config('request.groups', '', true);
SELECT is(
    rbac.get_claims(),
    '{"ffffffff-0000-0000-0000-000000000002":["member","editor"]}'::jsonb,
    'get_claims() falls back to _get_user_groups() (fresh DB read) when request.groups is empty (Storage path)'
);

-- Test 8: _get_user_groups() returns '{}' for a user with no group memberships
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"ffffffff-0000-0000-0000-000000000009"}',
    true);
SELECT is(
    rbac._get_user_groups(),
    '{}'::jsonb,
    '_get_user_groups() returns empty object for a user with no group memberships'
);

SELECT * FROM finish();
ROLLBACK;
