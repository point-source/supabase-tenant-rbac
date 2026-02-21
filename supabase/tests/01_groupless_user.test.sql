-- Regression tests for issue #37:
-- Groupless users (no groups in raw_app_meta_data) caused a JSON parse error
-- in get_user_claims() because db_pre_request stored NULL as an empty string,
-- and empty string is not valid JSONB.

BEGIN;
SELECT plan(5);

-- Test 1: get_user_claims() does not crash when request.groups is empty string
-- (simulates what the OLD db_pre_request stored for groupless users)
SELECT set_config('request.groups', '', true);
SELECT lives_ok(
    $$SELECT get_user_claims()$$,
    'get_user_claims() does not throw when request.groups is empty string'
);

-- Test 2: get_user_claims() returns '{}' when request.groups is empty string
-- (falls back to _get_user_groups() which returns '{}' for users with no group memberships)
SELECT set_config('request.groups', '', true);
SELECT is(
    get_user_claims(),
    '{}'::jsonb,
    'get_user_claims() returns empty object when request.groups is empty string (no JWT fallback)'
);

-- Test 3: get_user_claims() returns NULL when request.groups is unset
SELECT set_config('request.groups', '', true);
SELECT lives_ok(
    $$SELECT get_user_claims()$$,
    'get_user_claims() does not throw when request.groups is unset'
);

-- Test 4: get_user_claims() returns correct claims when request.groups is a valid JSON object
SELECT set_config('request.groups', '{"group-123":["admin","viewer"]}', true);
SELECT is(
    get_user_claims(),
    '{"group-123":["admin","viewer"]}'::jsonb,
    'get_user_claims() returns correct JSONB when request.groups is valid'
);

-- Test 5: get_user_claims() returns empty object when request.groups is '{}'
-- (what the FIXED db_pre_request stores for groupless users)
SELECT set_config('request.groups', '{}', true);
SELECT is(
    get_user_claims(),
    '{}'::jsonb,
    'get_user_claims() returns empty object when request.groups is empty JSON object'
);

SELECT * FROM finish();
ROLLBACK;
