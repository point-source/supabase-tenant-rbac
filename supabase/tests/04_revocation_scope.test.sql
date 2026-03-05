-- Tests for revocation scope enforcement (REV-01 through REV-04).
-- Verifies that callers can only revoke permissions within their grantable set,
-- that service_role always bypasses scope checks, and that retrospective scope
-- changes do not allow revocation of previously granted overrides.

BEGIN;
SELECT plan(4);

-- ─────────────────────────────────────────────────────────────────────────────
-- Setup: four users, one group
-- alice=owner, bob=admin, carol=editor, dave=viewer
-- ─────────────────────────────────────────────────────────────────────────────

INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES
    ('aa000000-0000-0000-0000-000000000001'::uuid, 'rev-alice@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('bb000000-0000-0000-0000-000000000001'::uuid, 'rev-bob@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('cc000000-0000-0000-0000-000000000001'::uuid, 'rev-carol@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('dd000000-0000-0000-0000-000000000001'::uuid, 'rev-dave@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated');

INSERT INTO rbac.groups (id, name)
VALUES ('f0000000-0000-0000-0000-000000000001'::uuid, 'REV Test Group G');

INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'aa000000-0000-0000-0000-000000000001'::uuid, ARRAY['owner']),
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'bb000000-0000-0000-0000-000000000001'::uuid, ARRAY['admin']),
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'cc000000-0000-0000-0000-000000000001'::uuid, ARRAY['editor']),
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'dd000000-0000-0000-0000-000000000001'::uuid, ARRAY['viewer']);

-- ── REV-01: bob (admin) can revoke data.read override from dave ────────────────
-- Setup: alice grants dave a data.read override (as postgres, bypasses escalation).
-- bob (admin, grantable_permissions includes data.read from editor/viewer)
-- calls revoke_member_permission → ALLOW.
SELECT rbac.grant_member_permission(
    'f0000000-0000-0000-0000-000000000001'::uuid,
    'dd000000-0000-0000-0000-000000000001'::uuid,
    'data.read'
);

DO $$
DECLARE
    v_succeeded boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"bb000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM set_config('request.groups',
        (SELECT claims::text FROM rbac.user_claims
         WHERE user_id = 'bb000000-0000-0000-0000-000000000001'::uuid),
        true);
    SET LOCAL ROLE authenticated;
    BEGIN
        PERFORM rbac.revoke_member_permission(
            'f0000000-0000-0000-0000-000000000001'::uuid,
            'dd000000-0000-0000-0000-000000000001'::uuid,
            'data.read'
        );
        v_succeeded := true;
    EXCEPTION WHEN OTHERS THEN
        v_succeeded := false;
    END;
    RESET ROLE;
    PERFORM set_config('test.rev01', v_succeeded::text, true);
END$$;

SELECT ok(
    current_setting('test.rev01') = 'true',
    'REV-01: bob (admin) can revoke data.read override — within grantable permissions'
);

-- ── REV-02: carol (editor) cannot revoke group.delete override from dave ───────
-- Setup: alice grants dave a group.delete override.
-- carol (editor, grantable_permissions=['data.read']) cannot revoke group.delete
-- because group.delete is NOT in carol's grantable_permissions → DENY.
SELECT rbac.grant_member_permission(
    'f0000000-0000-0000-0000-000000000001'::uuid,
    'dd000000-0000-0000-0000-000000000001'::uuid,
    'group.delete'
);

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
        PERFORM rbac.revoke_member_permission(
            'f0000000-0000-0000-0000-000000000001'::uuid,
            'dd000000-0000-0000-0000-000000000001'::uuid,
            'group.delete'
        );
    EXCEPTION WHEN OTHERS THEN
        v_blocked := true;
    END;
    RESET ROLE;
    PERFORM set_config('test.rev02', v_blocked::text, true);
END$$;

SELECT ok(
    current_setting('test.rev02') = 'true',
    'REV-02: carol (editor) cannot revoke group.delete override — outside grantable permissions'
);

-- ── REV-03: service_role (postgres) can revoke any permission ─────────────────
-- The group.delete override on dave still exists (carol was blocked in REV-02).
-- Calling revoke_member_permission as postgres (session_user='postgres') bypasses
-- all escalation checks — this is the service_role / superuser escape hatch.
SELECT rbac.revoke_member_permission(
    'f0000000-0000-0000-0000-000000000001'::uuid,
    'dd000000-0000-0000-0000-000000000001'::uuid,
    'group.delete'
);

SELECT ok(
    NOT EXISTS (
        SELECT 1 FROM rbac.member_permissions
        WHERE group_id = 'f0000000-0000-0000-0000-000000000001'::uuid
          AND user_id = 'dd000000-0000-0000-0000-000000000001'::uuid
          AND permission = 'group.delete'
    ),
    'REV-03: postgres (service_role) can revoke any permission override — no escalation check'
);

-- ── REV-04: Scope change makes previous override irrevocable by bob ───────────
-- Setup: alice grants dave data.write override.
-- Then narrow editor's permissions to remove data.write, which removes data.write
-- from admin's grantable_permissions (since admin.grantable_roles = [editor, viewer]).
-- After the trigger fires, bob's cached grantable_permissions no longer include data.write.
-- bob tries to revoke → DENY (override survives). postgres can still revoke.
SELECT rbac.grant_member_permission(
    'f0000000-0000-0000-0000-000000000001'::uuid,
    'dd000000-0000-0000-0000-000000000001'::uuid,
    'data.write'
);

-- Narrow editor's permissions: remove data.write.
-- The on_role_definition_change trigger fires and rebuilds claims for:
-- - carol (directly holds editor)
-- - bob (holds admin, whose grantable_roles includes editor)
-- After rebuild: bob's grantable_permissions = [data.read] (no longer data.write).
UPDATE rbac.roles
SET permissions = array_remove(permissions, 'data.write')
WHERE name = 'editor';

-- Reload bob's claims (now rebuilt by trigger).
DO $$
DECLARE
    v_blocked boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"bb000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    -- Reload bob's claims after the trigger has rebuilt them
    PERFORM set_config('request.groups',
        (SELECT claims::text FROM rbac.user_claims
         WHERE user_id = 'bb000000-0000-0000-0000-000000000001'::uuid),
        true);
    SET LOCAL ROLE authenticated;
    BEGIN
        PERFORM rbac.revoke_member_permission(
            'f0000000-0000-0000-0000-000000000001'::uuid,
            'dd000000-0000-0000-0000-000000000001'::uuid,
            'data.write'
        );
    EXCEPTION WHEN OTHERS THEN
        v_blocked := true;
    END;
    RESET ROLE;
    PERFORM set_config('test.rev04_blocked', v_blocked::text, true);
END$$;

-- Verify: bob was blocked AND dave's override still exists
SELECT ok(
    current_setting('test.rev04_blocked') = 'true'
    AND EXISTS (
        SELECT 1 FROM rbac.member_permissions
        WHERE group_id = 'f0000000-0000-0000-0000-000000000001'::uuid
          AND user_id = 'dd000000-0000-0000-0000-000000000001'::uuid
          AND permission = 'data.write'
    ),
    'REV-04: after editor scope narrowing, bob cannot revoke data.write — override survives'
);

-- Cleanup: postgres can still revoke (service_role escape hatch)
SELECT rbac.revoke_member_permission(
    'f0000000-0000-0000-0000-000000000001'::uuid,
    'dd000000-0000-0000-0000-000000000001'::uuid,
    'data.write'
);

SELECT * FROM finish();
ROLLBACK;
