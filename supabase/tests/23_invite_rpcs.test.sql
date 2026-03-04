-- Tests for create_invite() and delete_invite() RPCs (v5.2.0).
-- Verifies: EXECUTE grants, invite creation, role validation, deletion,
-- and that RLS enforces who may create/delete invites.

BEGIN;
SELECT plan(8);

-- Setup: two users, one group, one role
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    '23000000-0000-0000-0000-000000000001'::uuid,
    'invite-owner@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
), (
    '23000000-0000-0000-0000-000000000002'::uuid,
    'invite-viewer@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

INSERT INTO rbac.groups (id, name)
VALUES ('23000000-0000-0000-0000-000000000003'::uuid, 'Invite RPC Test Group');

-- Ensure 'owner' role exists and has group_user.invite permission
UPDATE rbac.roles
SET permissions = array_append(permissions, 'group_user.invite')
WHERE name = 'owner'
  AND NOT ('group_user.invite' = ANY(permissions));

INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('23000000-0000-0000-0000-000000000003'::uuid,
        '23000000-0000-0000-0000-000000000001'::uuid, ARRAY['owner']),
       ('23000000-0000-0000-0000-000000000003'::uuid,
        '23000000-0000-0000-0000-000000000002'::uuid, ARRAY['viewer']);

-- ── Test 1: authenticated has EXECUTE on create_invite() ──────────────────────
SELECT ok(
    has_function_privilege('authenticated',
        'rbac.create_invite(uuid, text[], timestamptz)', 'EXECUTE'),
    'authenticated role has EXECUTE on rbac.create_invite(uuid, text[], timestamptz)'
);

-- ── Test 2: authenticated has EXECUTE on delete_invite() ──────────────────────
SELECT ok(
    has_function_privilege('authenticated',
        'rbac.delete_invite(uuid)', 'EXECUTE'),
    'authenticated role has EXECUTE on rbac.delete_invite(uuid)'
);

-- ── Test 3: create_invite() returns a UUID ────────────────────────────────────
-- create_invite() calls auth.uid(), which requires a JWT context.
-- Set up JWT for the owner user before calling it.
DO $$
DECLARE
    v_invite_id uuid;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"23000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM set_config('request.groups',
        (SELECT claims::text FROM rbac.user_claims
         WHERE user_id = '23000000-0000-0000-0000-000000000001'::uuid),
        true);

    v_invite_id := rbac.create_invite(
        '23000000-0000-0000-0000-000000000003'::uuid,
        ARRAY['viewer']
    );
    PERFORM set_config('test.invite_id', v_invite_id::text, true);
END$$;

SELECT ok(
    current_setting('test.invite_id') ~ '^[0-9a-f-]{36}$',
    'create_invite() returns a valid UUID'
);

-- ── Test 4: created invite row exists with correct fields ─────────────────────
SELECT ok(
    EXISTS (
        SELECT 1 FROM rbac.invites
        WHERE id = current_setting('test.invite_id')::uuid
          AND group_id = '23000000-0000-0000-0000-000000000003'::uuid
          AND 'viewer' = ANY(roles)
          AND user_id IS NULL
          AND accepted_at IS NULL
    ),
    'created invite row has correct group_id, roles, and is unaccepted'
);

-- ── Test 5: create_invite() rejects undefined roles ───────────────────────────
DO $$
DECLARE
    v_raised boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"23000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    BEGIN
        PERFORM rbac.create_invite(
            '23000000-0000-0000-0000-000000000003'::uuid,
            ARRAY['nonexistent-role-xyz']
        );
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
    END;
    PERFORM set_config('test.bad_role_raised', v_raised::text, true);
END$$;

SELECT ok(
    current_setting('test.bad_role_raised') = 'true',
    'create_invite() raises for undefined roles'
);

-- ── Test 6: delete_invite() removes the invite row ───────────────────────────
DO $$
BEGIN
    PERFORM rbac.delete_invite(current_setting('test.invite_id')::uuid);
END$$;

SELECT ok(
    NOT EXISTS (
        SELECT 1 FROM rbac.invites
        WHERE id = current_setting('test.invite_id')::uuid
    ),
    'delete_invite() removes the invite row'
);

-- ── Test 7: delete_invite() raises for nonexistent invite ─────────────────────
DO $$
DECLARE
    v_raised boolean := false;
BEGIN
    BEGIN
        PERFORM rbac.delete_invite('00000000-0000-0000-0000-000000000000'::uuid);
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
    END;
    PERFORM set_config('test.delete_missing_raised', v_raised::text, true);
END$$;

SELECT ok(
    current_setting('test.delete_missing_raised') = 'true',
    'delete_invite() raises when invite does not exist'
);

-- ── Test 8: RLS blocks viewer from creating an invite ─────────────────────────
-- create_invite() INSERTs into rbac.invites subject to RLS.
-- The dev migration policy ("Has invite permission") requires group_user.invite
-- permission. viewer role does NOT have group_user.invite.
DO $$
DECLARE
    v_blocked boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"23000000-0000-0000-0000-000000000002","exp":9999999999}',
        true);
    PERFORM set_config('request.groups',
        (SELECT claims::text FROM rbac.user_claims
         WHERE user_id = '23000000-0000-0000-0000-000000000002'::uuid),
        true);

    SET LOCAL ROLE authenticated;
    BEGIN
        PERFORM rbac.create_invite(
            '23000000-0000-0000-0000-000000000003'::uuid,
            ARRAY['viewer']
        );
    EXCEPTION WHEN OTHERS THEN
        v_blocked := true;
    END;
    RESET ROLE;

    PERFORM set_config('test.viewer_invite_blocked', v_blocked::text, true);
END$$;

SELECT ok(
    current_setting('test.viewer_invite_blocked') = 'true',
    'RLS blocks viewer from creating an invite (lacks group_user.invite permission)'
);

SELECT * FROM finish();
ROLLBACK;
