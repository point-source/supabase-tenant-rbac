-- Tests for RB-01 through RB-06: role-based access bypass rules.
-- Verifies that postgres/service_role bypass RLS, that anon helpers return false,
-- that expired JWTs raise invalid_jwt, and that has_role() returns true for postgres.

BEGIN;
SELECT plan(8);

-- Setup: alice (owner in G), eve (non-member)
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    '34000000-0000-0000-0000-000000000001'::uuid,
    'rb-alice@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
), (
    '34000000-0000-0000-0000-000000000003'::uuid,
    'rb-eve@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

INSERT INTO rbac.groups (id, name)
VALUES ('34000000-0000-0000-0000-000000000002'::uuid, 'RB Test Group');

INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('34000000-0000-0000-0000-000000000002'::uuid,
     '34000000-0000-0000-0000-000000000001'::uuid,
     ARRAY['owner']);

-- Add RLS policies needed for members table operations within this test
CREATE POLICY "rb test manage members" ON rbac.members
    FOR ALL TO authenticated
    USING (rbac.has_permission(group_id, 'members.manage'))
    WITH CHECK (rbac.has_permission(group_id, 'members.manage'));

-- ── RB-01: postgres (superuser) can add_member() without RLS ─────────────────
-- Call add_member() directly as postgres — no JWT context, no RLS.
SELECT rbac.add_member(
    '34000000-0000-0000-0000-000000000002'::uuid,
    '34000000-0000-0000-0000-000000000003'::uuid,
    ARRAY['owner']
);

SELECT ok(
    EXISTS (
        SELECT 1 FROM rbac.members
        WHERE group_id = '34000000-0000-0000-0000-000000000002'::uuid
          AND user_id  = '34000000-0000-0000-0000-000000000003'::uuid
          AND 'owner' = ANY(roles)
    ),
    'RB-01: postgres can add_member() without RLS enforcement'
);

-- ── RB-02: postgres can SELECT directly from rbac.members ─────────────────────
SELECT ok(
    (SELECT count(*)::int FROM rbac.members
     WHERE group_id = '34000000-0000-0000-0000-000000000002'::uuid) > 0,
    'RB-02: postgres can SELECT from rbac.members without RLS (table has rows)'
);

-- ── RB-03: postgres can INSERT directly into rbac.groups ─────────────────────
INSERT INTO rbac.groups (id, name)
VALUES ('34000000-0000-0000-0000-000000000099'::uuid, 'Superuser Direct Insert Test');

SELECT ok(
    EXISTS (
        SELECT 1 FROM rbac.groups
        WHERE id = '34000000-0000-0000-0000-000000000099'::uuid
    ),
    'RB-03: postgres can INSERT directly into rbac.groups (superuser bypasses RLS)'
);

-- ── RB-04: anon role gets false from is_member() ─────────────────────────────
-- Set JWT to anon, switch role, call is_member() — must return false for anon.
DO $$
DECLARE v_result boolean;
BEGIN
    PERFORM set_config('request.jwt.claims', '{"role":"anon"}', true);
    SET LOCAL ROLE anon;
    SELECT rbac.is_member('34000000-0000-0000-0000-000000000002'::uuid) INTO v_result;
    RESET ROLE;
    PERFORM set_config('test.rb04_result', v_result::text, true);
END$$;

SELECT ok(
    current_setting('test.rb04_result') = 'false',
    'RB-04: is_member() returns false for the anon role'
);

-- ── RB-05: expired JWT raises invalid_jwt in has_role() ──────────────────────
DO $$
DECLARE v_raised boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"34000000-0000-0000-0000-000000000001","exp":1}',
        true);
    SET LOCAL ROLE authenticated;
    BEGIN
        PERFORM rbac.has_role(
            '34000000-0000-0000-0000-000000000002'::uuid,
            'owner'
        );
    EXCEPTION WHEN OTHERS THEN
        v_raised := (SQLERRM = 'invalid_jwt');
    END;
    RESET ROLE;
    PERFORM set_config('test.rb05_raised', v_raised::text, true);
END$$;

SELECT ok(
    current_setting('test.rb05_raised') = 'true',
    'RB-05: expired JWT raises invalid_jwt exception in has_role()'
);

-- ── RB-06: has_role() returns true for postgres (any group, any role) ─────────
-- When session_user = 'postgres', has_role() short-circuits to return true.
-- This is by design: superuser bypasses all RBAC checks.
-- Reset JWT claims so auth.role() returns NULL (not 'authenticated') for this test.
SELECT set_config('request.jwt.claims', '{}', true);

SELECT ok(
    rbac.has_role('00000000-0000-0000-0000-000000000000'::uuid, 'nonexistent-role'),
    'RB-06: has_role() returns true when called as postgres (superuser bypass)'
);

-- ── RB-07: service_role bypasses escalation checks in _check_role_escalation ──
-- service_role is not 'authenticated', so the escalation guard returns immediately.
-- A viewer (grantable_roles=[]) attempting to grant 'owner' would fail; service_role
-- must succeed. We verify by calling _check_role_escalation() directly — it should
-- return without raising even for a role far outside a typical grantable set.
DO $$
DECLARE v_raised boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"service_role","sub":"34000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    SET LOCAL ROLE service_role;
    BEGIN
        PERFORM rbac._check_role_escalation(
            '34000000-0000-0000-0000-000000000002'::uuid,
            ARRAY['owner']
        );
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
    END;
    RESET ROLE;
    PERFORM set_config('test.rb07_raised', v_raised::text, true);
END$$;

SELECT ok(
    current_setting('test.rb07_raised') = 'false',
    'RB-07: service_role bypasses _check_role_escalation — no exception raised for any role'
);

-- ── RB-08: service_role bypasses _check_permission_escalation ────────────────
DO $$
DECLARE v_raised boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"service_role","sub":"34000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    SET LOCAL ROLE service_role;
    BEGIN
        PERFORM rbac._check_permission_escalation(
            '34000000-0000-0000-0000-000000000002'::uuid,
            'data.export'
        );
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
    END;
    RESET ROLE;
    PERFORM set_config('test.rb08_raised', v_raised::text, true);
END$$;

SELECT ok(
    current_setting('test.rb08_raised') = 'false',
    'RB-08: service_role bypasses _check_permission_escalation — no exception raised for any permission'
);

SELECT * FROM finish();
ROLLBACK;
