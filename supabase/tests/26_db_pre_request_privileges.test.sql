-- Tests for db_pre_request() privilege and behavioral correctness.
--
-- PostgREST calls db_pre_request() AFTER "SET LOCAL ROLE <role>", so the
-- function runs as the switched role (authenticated/anon/service_role), NOT
-- as authenticator. Every role PostgREST can switch to must have EXECUTE.
--
-- These tests use SET LOCAL ROLE to simulate PostgREST's actual behavior,
-- catching privilege gaps that has_function_privilege() alone cannot detect
-- (e.g. missing SELECT on user_claims inside the INVOKER function body).

BEGIN;
SELECT plan(16);

-- ─── Setup: create a test user with claims ─────────────────────────────────

INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    '26000000-0000-0000-0000-000000000001'::uuid,
    'prereq-alice@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

INSERT INTO rbac.groups (id, name)
VALUES ('26000000-0000-0000-0000-000000000002'::uuid, 'PreReq Test Group');

INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('26000000-0000-0000-0000-000000000002'::uuid,
     '26000000-0000-0000-0000-000000000001'::uuid,
     ARRAY['owner']);

-- ─── Part 1: EXECUTE privilege checks ──────────────────────────────────────
-- These verify the grant surface is correct.

-- Test 1: authenticated has EXECUTE on db_pre_request
SELECT ok(
    has_function_privilege('authenticated', 'rbac.db_pre_request()', 'EXECUTE'),
    'authenticated has EXECUTE on rbac.db_pre_request()'
);

-- Test 2: anon has EXECUTE on db_pre_request
SELECT ok(
    has_function_privilege('anon', 'rbac.db_pre_request()', 'EXECUTE'),
    'anon has EXECUTE on rbac.db_pre_request()'
);

-- Test 3: service_role has EXECUTE on db_pre_request
SELECT ok(
    has_function_privilege('service_role', 'rbac.db_pre_request()', 'EXECUTE'),
    'service_role has EXECUTE on rbac.db_pre_request()'
);

-- Test 4: authenticator has EXECUTE on db_pre_request
SELECT ok(
    has_function_privilege('authenticator', 'rbac.db_pre_request()', 'EXECUTE'),
    'authenticator has EXECUTE on rbac.db_pre_request()'
);

-- ─── Part 2: Behavioral tests with actual role switching ───────────────────
-- These simulate what PostgREST actually does: SET LOCAL ROLE then call.
-- They catch issues that privilege checks alone miss (e.g. INVOKER function
-- failing on inner SELECT because the switched role lacks table access).

-- Test 5: authenticated can call db_pre_request and gets claims populated
DO $$
BEGIN
    SET LOCAL ROLE authenticated;
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"26000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM rbac.db_pre_request();
    PERFORM set_config('test.t5_groups', current_setting('request.groups', true), true);
    RESET ROLE;
END$$;

SELECT ok(
    current_setting('test.t5_groups', true) LIKE '%26000000-0000-0000-0000-000000000002%',
    'authenticated: db_pre_request() populates request.groups with user claims'
);

-- Test 6: authenticated user with no memberships gets empty claims
DO $$
BEGIN
    SET LOCAL ROLE authenticated;
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"00000000-0000-0000-0000-000000000099","exp":9999999999}',
        true);
    PERFORM rbac.db_pre_request();
    PERFORM set_config('test.t6_groups', current_setting('request.groups', true), true);
    RESET ROLE;
END$$;

SELECT is(
    current_setting('test.t6_groups', true),
    '{}',
    'authenticated: db_pre_request() returns {} for user with no memberships'
);

-- Test 7: anon can call db_pre_request without error (short-circuits on NULL uid)
DO $$
BEGIN
    SET LOCAL ROLE anon;
    -- anon has no JWT sub, so auth.uid() returns NULL
    PERFORM set_config('request.jwt.claims', '{}', true);
    PERFORM rbac.db_pre_request();
    PERFORM set_config('test.t7_groups', current_setting('request.groups', true), true);
    RESET ROLE;
END$$;

SELECT is(
    current_setting('test.t7_groups', true),
    '{}',
    'anon: db_pre_request() succeeds and returns {} (no user context)'
);

-- Test 8: service_role can call db_pre_request
DO $$
BEGIN
    SET LOCAL ROLE service_role;
    PERFORM set_config('request.jwt.claims',
        '{"role":"service_role","sub":"26000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM rbac.db_pre_request();
    PERFORM set_config('test.t8_groups', current_setting('request.groups', true), true);
    RESET ROLE;
END$$;

SELECT ok(
    current_setting('test.t8_groups', true) LIKE '%26000000-0000-0000-0000-000000000002%',
    'service_role: db_pre_request() populates request.groups with user claims'
);

-- ─── Part 3: Security invariants ───────────────────────────────────────────
-- Verify that granting EXECUTE on db_pre_request does NOT grant broader access.

-- Test 9: anon still lacks SELECT on user_claims (no table-level leak)
SELECT ok(
    NOT has_table_privilege('anon', 'rbac.user_claims', 'SELECT'),
    'anon lacks SELECT on rbac.user_claims (db_pre_request short-circuits, no table access needed)'
);

-- Test 10: anon lacks SELECT on members
SELECT ok(
    NOT has_table_privilege('anon', 'rbac.members', 'SELECT'),
    'anon lacks SELECT on rbac.members'
);

-- Test 11: anon lacks SELECT on groups
SELECT ok(
    NOT has_table_privilege('anon', 'rbac.groups', 'SELECT'),
    'anon lacks SELECT on rbac.groups'
);

-- Test 12: anon still cannot call management RPCs
SELECT ok(
    NOT has_function_privilege('anon', 'rbac.add_member(uuid, uuid, text[])', 'EXECUTE'),
    'anon still lacks EXECUTE on rbac.add_member (db_pre_request grant is scoped)'
);

-- Test 13: authenticated cannot write to user_claims (claims forgery prevention)
SELECT ok(
    NOT has_table_privilege('authenticated', 'rbac.user_claims', 'INSERT'),
    'authenticated lacks INSERT on rbac.user_claims'
);

SELECT ok(
    NOT has_table_privilege('authenticated', 'rbac.user_claims', 'UPDATE'),
    'authenticated lacks UPDATE on rbac.user_claims'
);

-- ─── Part 4: db_pre_request is scoped to caller's own claims ──────────────
-- Verify that a user cannot see another user's claims via db_pre_request.

-- Test 15: authenticated user only sees own claims, not other users'
DO $$
BEGIN
    SET LOCAL ROLE authenticated;
    -- JWT sub is a user who is NOT a member of any group
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"00000000-0000-0000-0000-000000000099","exp":9999999999}',
        true);
    PERFORM rbac.db_pre_request();
    PERFORM set_config('test.t15_groups', current_setting('request.groups', true), true);
    RESET ROLE;
END$$;

SELECT is(
    current_setting('test.t15_groups', true),
    '{}',
    'authenticated: db_pre_request() only reads caller''s own claims (auth.uid() scoped)'
);

-- Test 16: anon with a crafted JWT sub still gets empty claims (short-circuit)
DO $$
BEGIN
    SET LOCAL ROLE anon;
    -- Even if someone crafts a JWT with a sub, anon's auth.uid() returns NULL
    -- in Supabase because the role is not 'authenticated'
    PERFORM set_config('request.jwt.claims',
        '{"role":"anon","sub":"26000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM rbac.db_pre_request();
    PERFORM set_config('test.t16_groups', current_setting('request.groups', true), true);
    RESET ROLE;
END$$;

SELECT is(
    current_setting('test.t16_groups', true),
    '{}',
    'anon: db_pre_request() returns {} even with crafted JWT sub (auth.uid() is NULL for anon)'
);

SELECT * FROM finish();
ROLLBACK;
