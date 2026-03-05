-- Tests for privilege escalation prevention in permission overrides (ESC-P-01 through ESC-P-05).
-- Verifies that callers cannot grant permissions outside their grantable_permissions set,
-- that registry validation is enforced, and that grantable_permissions are cached correctly.

BEGIN;
SELECT plan(5);

-- ─────────────────────────────────────────────────────────────────────────────
-- Setup: four users, one group
-- alice=owner, bob=admin, carol=editor, dave=viewer
-- ─────────────────────────────────────────────────────────────────────────────

INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES
    ('aa000000-0000-0000-0000-000000000001'::uuid, 'escp-alice@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('bb000000-0000-0000-0000-000000000001'::uuid, 'escp-bob@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('cc000000-0000-0000-0000-000000000001'::uuid, 'escp-carol@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('dd000000-0000-0000-0000-000000000001'::uuid, 'escp-dave@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated');

INSERT INTO rbac.groups (id, name)
VALUES ('f0000000-0000-0000-0000-000000000001'::uuid, 'ESC-P Test Group G');

INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'aa000000-0000-0000-0000-000000000001'::uuid, ARRAY['owner']),
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'bb000000-0000-0000-0000-000000000001'::uuid, ARRAY['admin']),
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'cc000000-0000-0000-0000-000000000001'::uuid, ARRAY['editor']),
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'dd000000-0000-0000-0000-000000000001'::uuid, ARRAY['viewer']);

-- ── ESC-P-01: carol (editor) cannot grant data.write — outside grantable perms ─
-- carol's grantable_permissions are derived from grantable_roles=['viewer'],
-- meaning only viewer's permissions: ['data.read'].
-- data.write is NOT in carol's grantable_permissions.
DO $$
DECLARE
    v_blocked boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"cc000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM set_config('request.groups',
        (SELECT claims::text FROM rbac.user_claims
         WHERE user_id = 'cc000000-0000-0000-0000-000000000001'::uuid),
        true);
    SET LOCAL ROLE authenticated;
    BEGIN
        PERFORM rbac.grant_member_permission(
            'f0000000-0000-0000-0000-000000000001'::uuid,
            'dd000000-0000-0000-0000-000000000001'::uuid,
            'data.write'
        );
    EXCEPTION WHEN OTHERS THEN
        v_blocked := true;
    END;
    RESET ROLE;
    PERFORM set_config('test.escp01', v_blocked::text, true);
END$$;

SELECT ok(
    current_setting('test.escp01') = 'true',
    'ESC-P-01: carol (editor) cannot grant data.write — outside grantable permissions'
);

-- ── ESC-P-02: carol CAN grant data.read — within grantable permissions ─────────
-- carol's grantable_roles=['viewer']; viewer has data.read. So carol can
-- grant data.read to dave as a direct permission override.
DO $$
DECLARE
    v_succeeded boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"cc000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM set_config('request.groups',
        (SELECT claims::text FROM rbac.user_claims
         WHERE user_id = 'cc000000-0000-0000-0000-000000000001'::uuid),
        true);
    SET LOCAL ROLE authenticated;
    BEGIN
        PERFORM rbac.grant_member_permission(
            'f0000000-0000-0000-0000-000000000001'::uuid,
            'dd000000-0000-0000-0000-000000000001'::uuid,
            'data.read'
        );
        v_succeeded := true;
    EXCEPTION WHEN OTHERS THEN
        v_succeeded := false;
    END;
    RESET ROLE;
    PERFORM set_config('test.escp02', v_succeeded::text, true);
END$$;

SELECT ok(
    current_setting('test.escp02') = 'true',
    'ESC-P-02: carol (editor) can grant data.read — within grantable permissions'
);

-- ── ESC-P-03: alice cannot grant a nonexistent permission ─────────────────────
-- Even with grantable_permissions=['*'], the permission must exist in the registry.
-- _validate_permissions should reject 'nonexistent.perm'.
DO $$
DECLARE
    v_blocked boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"aa000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM set_config('request.groups',
        (SELECT claims::text FROM rbac.user_claims
         WHERE user_id = 'aa000000-0000-0000-0000-000000000001'::uuid),
        true);
    SET LOCAL ROLE authenticated;
    BEGIN
        PERFORM rbac.grant_member_permission(
            'f0000000-0000-0000-0000-000000000001'::uuid,
            'dd000000-0000-0000-0000-000000000001'::uuid,
            'nonexistent.perm'
        );
    EXCEPTION WHEN OTHERS THEN
        v_blocked := true;
    END;
    RESET ROLE;
    PERFORM set_config('test.escp03', v_blocked::text, true);
END$$;

SELECT ok(
    current_setting('test.escp03') = 'true',
    'ESC-P-03: alice cannot grant nonexistent.perm — permission not in registry'
);

-- ── ESC-P-04: alice CAN grant group.delete — exists in registry, alice has wildcard ─
-- group.delete is a valid permission in the system.
-- alice (owner with grantable_permissions=['*']) can grant it as a direct override.
DO $$
DECLARE
    v_succeeded boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"aa000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM set_config('request.groups',
        (SELECT claims::text FROM rbac.user_claims
         WHERE user_id = 'aa000000-0000-0000-0000-000000000001'::uuid),
        true);
    SET LOCAL ROLE authenticated;
    BEGIN
        PERFORM rbac.grant_member_permission(
            'f0000000-0000-0000-0000-000000000001'::uuid,
            'dd000000-0000-0000-0000-000000000001'::uuid,
            'group.delete'
        );
        v_succeeded := true;
    EXCEPTION WHEN OTHERS THEN
        v_succeeded := false;
    END;
    RESET ROLE;
    PERFORM set_config('test.escp04', v_succeeded::text, true);
END$$;

SELECT ok(
    current_setting('test.escp04') = 'true',
    'ESC-P-04: alice (owner) can grant group.delete override — permission exists in registry'
);

-- ── ESC-P-05: bob's cached permissions include union of admin perms ────────────
-- bob is admin. admin.permissions = [group.update, members.manage, data.read, data.write].
-- Verify bob has these permissions in user_claims.
SELECT ok(
    (
        SELECT
            (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'permissions') ? 'group.update'
            AND
            (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'permissions') ? 'members.manage'
            AND
            (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'permissions') ? 'data.read'
            AND
            (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'permissions') ? 'data.write'
        FROM rbac.user_claims
        WHERE user_id = 'bb000000-0000-0000-0000-000000000001'::uuid
    ),
    'ESC-P-05: bob (admin) cached permissions include all admin permissions (group.update, members.manage, data.read, data.write)'
);

SELECT * FROM finish();
ROLLBACK;
