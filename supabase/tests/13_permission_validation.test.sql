-- Tests for PV-01 through PV-07: permission and role validation at write time.
-- Verifies that RPCs reject undefined roles in add_member/update_member_roles,
-- that set_role_permissions rejects no-op when role is missing,
-- and that grant_member_permission rejects empty strings.

BEGIN;
SELECT plan(8);

-- Setup: standard users and group using seed data UUIDs
-- devuser (d55f3b79...) is owner in RED (ffc83b57...)
-- dave is not in the seed — create a test user
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    '30000000-0000-0000-0000-000000000001'::uuid,
    'pv-actor@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
), (
    '30000000-0000-0000-0000-000000000002'::uuid,
    'pv-target@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

INSERT INTO rbac.groups (id, name)
VALUES ('30000000-0000-0000-0000-000000000003'::uuid, 'PV Test Group');

-- actor is owner in G so RLS allows management
INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('30000000-0000-0000-0000-000000000003'::uuid,
     '30000000-0000-0000-0000-000000000001'::uuid,
     ARRAY['owner']),
    ('30000000-0000-0000-0000-000000000003'::uuid,
     '30000000-0000-0000-0000-000000000002'::uuid,
     ARRAY['viewer']);

-- ── PV-01: add_member() rejects undefined roles ───────────────────────────────
SELECT throws_ok(
    $$SELECT rbac.add_member(
        '30000000-0000-0000-0000-000000000003'::uuid,
        '30000000-0000-0000-0000-000000000002'::uuid,
        ARRAY['superadmin']
    )$$,
    'P0001',
    NULL,
    'PV-01: add_member() raises for undefined role name'
);

-- ── PV-02: update_member_roles() rejects undefined roles ─────────────────────
SELECT throws_ok(
    $$SELECT rbac.update_member_roles(
        '30000000-0000-0000-0000-000000000003'::uuid,
        '30000000-0000-0000-0000-000000000002'::uuid,
        ARRAY['editor', 'moderator']
    )$$,
    'P0001',
    NULL,
    'PV-02: update_member_roles() raises for undefined role in array'
);

-- Verify target still has original roles (update was rejected)
SELECT ok(
    (SELECT roles = ARRAY['viewer']
     FROM rbac.members
     WHERE group_id = '30000000-0000-0000-0000-000000000003'::uuid
       AND user_id  = '30000000-0000-0000-0000-000000000002'::uuid),
    'PV-02b: roles are unchanged after rejected update_member_roles() call'
);

-- ── PV-03: create_invite() rejects undefined roles ────────────────────────────
-- Must set JWT context because create_invite() calls auth.uid()
DO $$
DECLARE v_raised boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"30000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    BEGIN
        PERFORM rbac.create_invite(
            '30000000-0000-0000-0000-000000000003'::uuid,
            ARRAY['nonexistent-role-xyz']
        );
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
    END;
    PERFORM set_config('test.pv03_raised', v_raised::text, true);
END$$;

SELECT ok(
    current_setting('test.pv03_raised') = 'true',
    'PV-03: create_invite() raises for undefined role name'
);

-- ── PV-04: set_role_permissions() raises for nonexistent role ─────────────────
SELECT throws_ok(
    $$SELECT rbac.set_role_permissions('nonexistent-role-xyz', ARRAY['data.read'])$$,
    'P0001',
    NULL,
    'PV-04: set_role_permissions() raises when role does not exist'
);

-- ── PV-05: delete_role() refuses if any member holds the role ─────────────────
-- target holds 'viewer'. Attempting to delete 'viewer' should raise.
SELECT throws_ok(
    $$SELECT rbac.delete_role('viewer')$$,
    'P0001',
    NULL,
    'PV-05: delete_role() raises when role is in use by one or more members'
);

-- ── PV-06: grant_member_permission() rejects empty permission string ──────────
-- actor (owner) tries to grant an empty string permission to target
DO $$
DECLARE v_raised boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"30000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM set_config('request.groups',
        (SELECT claims::text FROM rbac.user_claims
         WHERE user_id = '30000000-0000-0000-0000-000000000001'::uuid),
        true);
    SET LOCAL ROLE authenticated;
    BEGIN
        PERFORM rbac.grant_member_permission(
            '30000000-0000-0000-0000-000000000003'::uuid,
            '30000000-0000-0000-0000-000000000002'::uuid,
            ''  -- empty string
        );
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
    END;
    RESET ROLE;
    PERFORM set_config('test.pv06_raised', v_raised::text, true);
END$$;

SELECT ok(
    current_setting('test.pv06_raised') = 'true',
    'PV-06: grant_member_permission() raises for empty permission string'
);

-- ── PV-07: revoke_member_permission() rejects empty permission string ─────────
-- Same guard applies to revoke_member_permission()
DO $$
DECLARE v_raised boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"30000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM set_config('request.groups',
        (SELECT claims::text FROM rbac.user_claims
         WHERE user_id = '30000000-0000-0000-0000-000000000001'::uuid),
        true);
    SET LOCAL ROLE authenticated;
    BEGIN
        PERFORM rbac.revoke_member_permission(
            '30000000-0000-0000-0000-000000000003'::uuid,
            '30000000-0000-0000-0000-000000000002'::uuid,
            ''  -- empty string
        );
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
    END;
    RESET ROLE;
    PERFORM set_config('test.pv07_raised', v_raised::text, true);
END$$;

SELECT ok(
    current_setting('test.pv07_raised') = 'true',
    'PV-07: revoke_member_permission() raises for empty permission string'
);

SELECT * FROM finish();
ROLLBACK;
