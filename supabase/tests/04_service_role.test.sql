-- Tests for issue #39:
-- user_has_group_role() and user_is_group_member() should return true when
-- called in a service_role context (consistent with service_role bypassing RLS).
--
-- These tests run as the postgres superuser. The service_role auth context is
-- simulated by setting request.jwt.claims, since auth.role() reads from that
-- config key. The session_user = 'postgres' path also returns true, so these
-- tests verify the full "elevated context" behavior.

BEGIN;
SELECT plan(6);

-- Setup: a group to test against
INSERT INTO public.groups (id, metadata)
VALUES ('eeeeeeee-0000-0000-0000-000000000001'::uuid, '{"name":"Service Role Test Group"}');

-- Test 1: user_has_group_role returns true in postgres session context
-- (session_user = 'postgres' path)
SELECT ok(
    user_has_group_role('eeeeeeee-0000-0000-0000-000000000001'::uuid, 'any_role'),
    'user_has_group_role returns true in postgres session context'
);

-- Test 2: user_is_group_member returns true in postgres session context
SELECT ok(
    user_is_group_member('eeeeeeee-0000-0000-0000-000000000001'::uuid),
    'user_is_group_member returns true in postgres session context'
);

-- Test 3: user_has_group_role returns true when jwt claims role is 'service_role'
SELECT set_config('request.jwt.claims', '{"role":"service_role"}', true);
SELECT ok(
    user_has_group_role('eeeeeeee-0000-0000-0000-000000000001'::uuid, 'any_role'),
    'user_has_group_role returns true when auth.role() = service_role'
);

-- Test 4: user_is_group_member returns true when jwt claims role is 'service_role'
SELECT set_config('request.jwt.claims', '{"role":"service_role"}', true);
SELECT ok(
    user_is_group_member('eeeeeeee-0000-0000-0000-000000000001'::uuid),
    'user_is_group_member returns true when auth.role() = service_role'
);

-- Test 5: user_has_group_role returns false for anon
SELECT set_config('request.jwt.claims', '{"role":"anon"}', true);
SELECT ok(
    NOT user_has_group_role('eeeeeeee-0000-0000-0000-000000000001'::uuid, 'any_role'),
    'user_has_group_role returns false for anon role'
);

-- Test 6: user_is_group_member returns false for anon
SELECT set_config('request.jwt.claims', '{"role":"anon"}', true);
SELECT ok(
    NOT user_is_group_member('eeeeeeee-0000-0000-0000-000000000001'::uuid),
    'user_is_group_member returns false for anon role'
);

SELECT * FROM finish();
ROLLBACK;
