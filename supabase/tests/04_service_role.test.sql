-- Tests for issue #39:
-- has_role() and is_member() should return true when called in a service_role
-- context (consistent with service_role bypassing RLS).

BEGIN;
SELECT plan(8);

-- Setup: a group to test against
INSERT INTO rbac.groups (id, name)
VALUES ('eeeeeeee-0000-0000-0000-000000000001'::uuid, 'Service Role Test Group');

-- Test 1: has_role returns true in postgres session context
SELECT ok(
    rbac.has_role('eeeeeeee-0000-0000-0000-000000000001'::uuid, 'any_role'),
    'has_role returns true in postgres session context'
);

-- Test 2: is_member returns true in postgres session context
SELECT ok(
    rbac.is_member('eeeeeeee-0000-0000-0000-000000000001'::uuid),
    'is_member returns true in postgres session context'
);

-- Test 3: has_role returns true when jwt claims role is 'service_role'
SELECT set_config('request.jwt.claims', '{"role":"service_role"}', true);
SELECT ok(
    rbac.has_role('eeeeeeee-0000-0000-0000-000000000001'::uuid, 'any_role'),
    'has_role returns true when auth.role() = service_role'
);

-- Test 4: is_member returns true when jwt claims role is 'service_role'
SELECT set_config('request.jwt.claims', '{"role":"service_role"}', true);
SELECT ok(
    rbac.is_member('eeeeeeee-0000-0000-0000-000000000001'::uuid),
    'is_member returns true when auth.role() = service_role'
);

-- Test 5: has_role returns false for anon
SELECT set_config('request.jwt.claims', '{"role":"anon"}', true);
SELECT ok(
    NOT rbac.has_role('eeeeeeee-0000-0000-0000-000000000001'::uuid, 'any_role'),
    'has_role returns false for anon role'
);

-- Test 6: is_member returns false for anon
SELECT set_config('request.jwt.claims', '{"role":"anon"}', true);
SELECT ok(
    NOT rbac.is_member('eeeeeeee-0000-0000-0000-000000000001'::uuid),
    'is_member returns false for anon role'
);

-- Reset JWT claims so auth.role() falls to ELSE branch (session_user = 'postgres')
SELECT set_config('request.jwt.claims', '', true);

-- Test 7: has_any_role returns true in postgres session context
SELECT ok(
    rbac.has_any_role('eeeeeeee-0000-0000-0000-000000000001'::uuid, ARRAY['any_role']),
    'has_any_role returns true in postgres session context'
);

-- Test 8: has_all_roles returns true in postgres session context
SELECT ok(
    rbac.has_all_roles('eeeeeeee-0000-0000-0000-000000000001'::uuid, ARRAY['any_role']),
    'has_all_roles returns true in postgres session context'
);

SELECT * FROM finish();
ROLLBACK;
