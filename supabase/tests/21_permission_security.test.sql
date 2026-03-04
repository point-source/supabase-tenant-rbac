-- Tests for EXECUTE grant assignments and RLS on member permission overrides (v5.1.0).
-- Verifies: EXECUTE grants on new RPCs, admin claims contain group.manage_access,
-- viewer claims do not, and RLS blocks unauthorized direct writes.

BEGIN;
SELECT plan(7);

-- Setup: two users in the same group with different access levels
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    '11111111-0000-0000-0000-000000000001'::uuid,
    'perm-admin@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
), (
    '11111111-0000-0000-0000-000000000002'::uuid,
    'perm-viewer@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

INSERT INTO rbac.groups (id, name)
VALUES ('11111111-0000-0000-0000-000000000003'::uuid, 'Permission Security Test Group');

-- Create roles: admin has group.manage_access, viewer does not
INSERT INTO rbac.roles (name) VALUES ('access-admin'), ('access-viewer') ON CONFLICT DO NOTHING;
SELECT rbac.set_role_permissions('access-admin', ARRAY['group.manage_access']);
SELECT rbac.set_role_permissions('access-viewer', ARRAY['group_data.read']);

INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('11111111-0000-0000-0000-000000000003'::uuid,
        '11111111-0000-0000-0000-000000000001'::uuid, ARRAY['access-admin']),
       ('11111111-0000-0000-0000-000000000003'::uuid,
        '11111111-0000-0000-0000-000000000002'::uuid, ARRAY['access-viewer']);

-- ── Test 1: authenticated has EXECUTE on grant_member_permission() ────────────
SELECT ok(
    has_function_privilege('authenticated',
        'rbac.grant_member_permission(uuid, uuid, text)', 'EXECUTE'),
    'authenticated role has EXECUTE on rbac.grant_member_permission(uuid, uuid, text)'
);

-- ── Test 2: authenticated has EXECUTE on revoke_member_permission() ───────────
SELECT ok(
    has_function_privilege('authenticated',
        'rbac.revoke_member_permission(uuid, uuid, text)', 'EXECUTE'),
    'authenticated role has EXECUTE on rbac.revoke_member_permission(uuid, uuid, text)'
);

-- ── Test 3: authenticated has EXECUTE on list_member_permissions() ────────────
SELECT ok(
    has_function_privilege('authenticated',
        'rbac.list_member_permissions(uuid, uuid)', 'EXECUTE'),
    'authenticated role has EXECUTE on rbac.list_member_permissions(uuid, uuid)'
);

-- ── Test 4: admin user claims contain group.manage_access permission ──────────
SELECT ok(
    (SELECT claims->'11111111-0000-0000-0000-000000000003'->'permissions'
     ? 'group.manage_access'
     FROM rbac.user_claims
     WHERE user_id = '11111111-0000-0000-0000-000000000001'::uuid),
    'admin user claims contain group.manage_access permission'
);

-- ── Test 5: viewer user claims do NOT contain group.manage_access ─────────────
SELECT ok(
    NOT (SELECT claims->'11111111-0000-0000-0000-000000000003'->'permissions'
         ? 'group.manage_access'
         FROM rbac.user_claims
         WHERE user_id = '11111111-0000-0000-0000-000000000002'::uuid),
    'viewer user claims do not contain group.manage_access permission'
);

-- ── Test 6: RLS blocks viewer from writing to member_permissions ──────────────
-- Use a plpgsql DO block to switch roles, attempt an INSERT, and catch the
-- RLS violation. Communicate the result back via set_config.
DO $$
DECLARE
    v_blocked boolean := false;
BEGIN
    -- Set JWT context for the viewer (no group.manage_access)
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"11111111-0000-0000-0000-000000000002","exp":9999999999}',
        true);
    PERFORM set_config('request.groups',
        (SELECT claims::text FROM rbac.user_claims
         WHERE user_id = '11111111-0000-0000-0000-000000000002'::uuid),
        true);

    SET LOCAL ROLE authenticated;
    BEGIN
        INSERT INTO rbac.member_permissions (group_id, user_id, permission)
        VALUES ('11111111-0000-0000-0000-000000000003'::uuid,
                '11111111-0000-0000-0000-000000000002'::uuid,
                'data.export');
    EXCEPTION WHEN insufficient_privilege THEN
        v_blocked := true;
    END;
    RESET ROLE;

    PERFORM set_config('test.rls_blocked', v_blocked::text, true);
END$$;

SELECT ok(
    current_setting('test.rls_blocked') = 'true',
    'RLS blocks viewer from inserting into member_permissions (insufficient group.manage_access)'
);

-- ── Test 7: cross-group grant is blocked — admin of one group cannot grant in another ─
-- Create a second group that perm-admin is NOT a member of.
INSERT INTO rbac.groups (id, name)
VALUES ('11111111-0000-0000-0000-000000000005'::uuid, 'Other Group (no perm-admin)');

-- Add perm-viewer to the other group so the FK would not block the INSERT if reached.
INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('11111111-0000-0000-0000-000000000005'::uuid,
        '11111111-0000-0000-0000-000000000002'::uuid, ARRAY['access-viewer']);

DO $$
DECLARE
    v_blocked boolean := false;
BEGIN
    -- perm-admin has group.manage_access in group 3, but is NOT a member of group 5
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"11111111-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM set_config('request.groups',
        (SELECT claims::text FROM rbac.user_claims
         WHERE user_id = '11111111-0000-0000-0000-000000000001'::uuid),
        true);

    SET LOCAL ROLE authenticated;
    BEGIN
        -- Attempt to grant a permission in group 5 — admin is NOT a member there
        PERFORM rbac.grant_member_permission(
            '11111111-0000-0000-0000-000000000005'::uuid,
            '11111111-0000-0000-0000-000000000002'::uuid,
            'data.export');
    EXCEPTION WHEN insufficient_privilege THEN
        v_blocked := true;
    END;
    RESET ROLE;

    PERFORM set_config('test.cross_group_blocked', v_blocked::text, true);
END$$;

SELECT ok(
    current_setting('test.cross_group_blocked') = 'true',
    'grant_member_permission blocks caller who is not a member of the target group'
);

SELECT * FROM finish();
ROLLBACK;
