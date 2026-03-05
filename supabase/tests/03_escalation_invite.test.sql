-- Tests for privilege escalation prevention in invite creation (ESC-I-01 through ESC-I-03).
-- Verifies that callers cannot create invites with roles outside their grantable set,
-- and that non-members cannot create invites at all.

BEGIN;
SELECT plan(3);

-- ─────────────────────────────────────────────────────────────────────────────
-- Setup: four users, one group
-- alice=owner, bob=admin, carol=editor, dave=viewer, eve=non-member
-- ─────────────────────────────────────────────────────────────────────────────

INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES
    ('aa000000-0000-0000-0000-000000000001'::uuid, 'esci-alice@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('bb000000-0000-0000-0000-000000000001'::uuid, 'esci-bob@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('cc000000-0000-0000-0000-000000000001'::uuid, 'esci-carol@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('dd000000-0000-0000-0000-000000000001'::uuid, 'esci-dave@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('ee000000-0000-0000-0000-000000000001'::uuid, 'esci-eve@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated');

INSERT INTO rbac.groups (id, name)
VALUES ('f0000000-0000-0000-0000-000000000001'::uuid, 'ESC-I Test Group G');

INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'aa000000-0000-0000-0000-000000000001'::uuid, ARRAY['owner']),
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'bb000000-0000-0000-0000-000000000001'::uuid, ARRAY['admin']),
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'cc000000-0000-0000-0000-000000000001'::uuid, ARRAY['editor']),
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'dd000000-0000-0000-0000-000000000001'::uuid, ARRAY['viewer']);
-- eve (ee...) is NOT inserted as a member

-- The migration RLS policy "Has invite permission" on rbac.invites requires
-- group_user.invite permission. The owner role has group_user.invite.
-- admin role also has group_user.invite (per seed.sql).
-- editor and viewer do NOT have group_user.invite — verified via seed roles.

-- ── ESC-I-01: bob (admin) cannot create invite with owner role ─────────────────
-- owner is not in admin's grantable_roles, so this should be denied.
DO $$
DECLARE
    v_blocked boolean := false;
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
        PERFORM rbac.create_invite(
            'f0000000-0000-0000-0000-000000000001'::uuid,
            ARRAY['owner']
        );
    EXCEPTION WHEN OTHERS THEN
        v_blocked := true;
    END;
    RESET ROLE;
    PERFORM set_config('test.esci01', v_blocked::text, true);
END$$;

SELECT ok(
    current_setting('test.esci01') = 'true',
    'ESC-I-01: bob (admin) cannot create invite with owner role — outside grantable set'
);

-- ── ESC-I-02: bob (admin) CAN create invite with [editor, viewer] ─────────────
-- editor and viewer are both in admin's grantable_roles; invite should succeed.
-- Verify by checking that the invite row is created in rbac.invites.
-- Pre-initialize config so it's always set even if the block errors.
SELECT set_config('test.esci02_invite_id', '00000000-0000-0000-0000-000000000000', true);
SELECT set_config('test.esci02_succeeded', 'false', true);
DO $$
DECLARE
    v_invite_id uuid;
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
        v_invite_id := rbac.create_invite(
            'f0000000-0000-0000-0000-000000000001'::uuid,
            ARRAY['editor', 'viewer']
        );
        PERFORM set_config('test.esci02_invite_id', v_invite_id::text, true);
        PERFORM set_config('test.esci02_succeeded', 'true', true);
    EXCEPTION WHEN OTHERS THEN
        PERFORM set_config('test.esci02_succeeded', 'false', true);
    END;
    RESET ROLE;
END$$;

SELECT ok(
    current_setting('test.esci02_succeeded') = 'true'
    AND EXISTS (
        SELECT 1 FROM rbac.invites
        WHERE id = current_setting('test.esci02_invite_id')::uuid
          AND group_id = 'f0000000-0000-0000-0000-000000000001'::uuid
          AND 'editor' = ANY(roles)
          AND 'viewer' = ANY(roles)
          AND accepted_at IS NULL
    ),
    'ESC-I-02: bob (admin) can create invite with [editor, viewer] — invite row created'
);

-- ── ESC-I-03: eve (non-member) cannot create invite ───────────────────────────
-- eve has no membership in G. The is_member guard inside create_invite (and RLS
-- policy) should block this.
DO $$
DECLARE
    v_blocked boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"ee000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    -- Eve has no claims (no memberships), so request.groups = '{}'
    PERFORM set_config('request.groups', '{}', true);
    SET LOCAL ROLE authenticated;
    BEGIN
        PERFORM rbac.create_invite(
            'f0000000-0000-0000-0000-000000000001'::uuid,
            ARRAY['viewer']
        );
    EXCEPTION WHEN OTHERS THEN
        v_blocked := true;
    END;
    RESET ROLE;
    PERFORM set_config('test.esci03', v_blocked::text, true);
END$$;

SELECT ok(
    current_setting('test.esci03') = 'true',
    'ESC-I-03: eve (non-member) cannot create invite — no claims in G'
);

SELECT * FROM finish();
ROLLBACK;
