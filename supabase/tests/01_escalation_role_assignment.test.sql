-- Tests for privilege escalation prevention in role assignment (ESC-R-01 through ESC-R-09).
-- Verifies that callers cannot assign roles outside their grantable_roles set,
-- cannot escalate via update_member_roles, and cross-group membership is enforced.

BEGIN;
SELECT plan(9);

-- ─────────────────────────────────────────────────────────────────────────────
-- Setup: five users, two groups
-- ─────────────────────────────────────────────────────────────────────────────

INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES
    ('aa000000-0000-0000-0000-000000000001'::uuid, 'escr-alice@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('bb000000-0000-0000-0000-000000000001'::uuid, 'escr-bob@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('cc000000-0000-0000-0000-000000000001'::uuid, 'escr-carol@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('dd000000-0000-0000-0000-000000000001'::uuid, 'escr-dave@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('ee000000-0000-0000-0000-000000000001'::uuid, 'escr-eve@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated');

INSERT INTO rbac.groups (id, name) VALUES
    ('f0000000-0000-0000-0000-000000000001'::uuid, 'ESC-R Test Group G'),
    ('f0000000-0000-0000-0000-000000000002'::uuid, 'ESC-R Test Group G2');

-- alice=owner, bob=admin, carol=editor, dave=viewer in group G.
-- Eve is NOT a member of either group.
-- Bob is NOT a member of G2.
INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'aa000000-0000-0000-0000-000000000001'::uuid, ARRAY['owner']),
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'bb000000-0000-0000-0000-000000000001'::uuid, ARRAY['admin']),
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'cc000000-0000-0000-0000-000000000001'::uuid, ARRAY['editor']),
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'dd000000-0000-0000-0000-000000000001'::uuid, ARRAY['viewer']);

-- ── ESC-R-01: bob (admin) cannot assign 'owner' role — outside grantable set ──
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
        PERFORM rbac.add_member(
            'f0000000-0000-0000-0000-000000000001'::uuid,
            'ee000000-0000-0000-0000-000000000001'::uuid,
            ARRAY['owner']
        );
    EXCEPTION WHEN OTHERS THEN
        v_blocked := true;
    END;
    RESET ROLE;
    PERFORM set_config('test.escr01', v_blocked::text, true);
END$$;

SELECT ok(
    current_setting('test.escr01') = 'true',
    'ESC-R-01: bob (admin) cannot assign owner role — outside grantable set'
);

-- ── ESC-R-02: bob (admin) CAN assign 'editor' role — within grantable set ────
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
        PERFORM rbac.add_member(
            'f0000000-0000-0000-0000-000000000001'::uuid,
            'ee000000-0000-0000-0000-000000000001'::uuid,
            ARRAY['editor']
        );
        v_succeeded := true;
    EXCEPTION WHEN OTHERS THEN
        v_succeeded := false;
    END;
    RESET ROLE;
    PERFORM set_config('test.escr02', v_succeeded::text, true);
END$$;

SELECT ok(
    current_setting('test.escr02') = 'true',
    'ESC-R-02: bob (admin) can assign editor role — within grantable set'
);

-- Remove eve after ESC-R-02 so she can be re-used in later tests
DELETE FROM rbac.members
WHERE group_id = 'f0000000-0000-0000-0000-000000000001'::uuid
  AND user_id = 'ee000000-0000-0000-0000-000000000001'::uuid;

-- ── ESC-R-03: bob cannot assign mixed roles where any is outside grantable set ─
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
        PERFORM rbac.add_member(
            'f0000000-0000-0000-0000-000000000001'::uuid,
            'ee000000-0000-0000-0000-000000000001'::uuid,
            ARRAY['viewer', 'owner']
        );
    EXCEPTION WHEN OTHERS THEN
        v_blocked := true;
    END;
    RESET ROLE;
    PERFORM set_config('test.escr03', v_blocked::text, true);
END$$;

SELECT ok(
    current_setting('test.escr03') = 'true',
    'ESC-R-03: bob cannot assign mixed roles containing owner — entire operation rejected'
);

-- ── ESC-R-04: bob cannot escalate dave to owner via update_member_roles ───────
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
        PERFORM rbac.update_member_roles(
            'f0000000-0000-0000-0000-000000000001'::uuid,
            'dd000000-0000-0000-0000-000000000001'::uuid,
            ARRAY['owner']
        );
    EXCEPTION WHEN OTHERS THEN
        v_blocked := true;
    END;
    RESET ROLE;
    PERFORM set_config('test.escr04', v_blocked::text, true);
END$$;

SELECT ok(
    current_setting('test.escr04') = 'true',
    'ESC-R-04: bob cannot escalate dave to owner via update_member_roles'
);

-- ── ESC-R-05: bob CAN update dave to [editor, viewer] — within grantable set ──
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
        PERFORM rbac.update_member_roles(
            'f0000000-0000-0000-0000-000000000001'::uuid,
            'dd000000-0000-0000-0000-000000000001'::uuid,
            ARRAY['editor', 'viewer']
        );
        v_succeeded := true;
    EXCEPTION WHEN OTHERS THEN
        v_succeeded := false;
    END;
    RESET ROLE;
    PERFORM set_config('test.escr05', v_succeeded::text, true);
END$$;

SELECT ok(
    current_setting('test.escr05') = 'true',
    'ESC-R-05: bob can update dave to [editor, viewer] — within grantable set'
);

-- ── ESC-R-06: dave (viewer, grantable_roles=[]) cannot assign any role ────────
DO $$
DECLARE
    v_blocked boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"dd000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM set_config('request.groups',
        (SELECT claims::text FROM rbac.user_claims
         WHERE user_id = 'dd000000-0000-0000-0000-000000000001'::uuid),
        true);
    SET LOCAL ROLE authenticated;
    BEGIN
        PERFORM rbac.add_member(
            'f0000000-0000-0000-0000-000000000001'::uuid,
            'ee000000-0000-0000-0000-000000000001'::uuid,
            ARRAY['viewer']
        );
    EXCEPTION WHEN OTHERS THEN
        v_blocked := true;
    END;
    RESET ROLE;
    PERFORM set_config('test.escr06', v_blocked::text, true);
END$$;

SELECT ok(
    current_setting('test.escr06') = 'true',
    'ESC-R-06: dave (viewer) cannot assign any role — no grantable roles'
);

-- ── ESC-R-07: bob (admin, grantable_roles includes editor) CAN add editor ─────
-- bob's admin role has grantable_roles=['editor','viewer']. Verify he can add
-- eve with editor role — this tests the positive case of union-based grantable check.
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
        PERFORM rbac.add_member(
            'f0000000-0000-0000-0000-000000000001'::uuid,
            'ee000000-0000-0000-0000-000000000001'::uuid,
            ARRAY['editor']
        );
        v_succeeded := true;
    EXCEPTION WHEN OTHERS THEN
        v_succeeded := false;
    END;
    RESET ROLE;
    PERFORM set_config('test.escr07', v_succeeded::text, true);
END$$;

SELECT ok(
    current_setting('test.escr07') = 'true',
    'ESC-R-07: bob (admin, grantable_roles includes editor) can add member with editor role'
);

-- Remove eve before ESC-R-08
DELETE FROM rbac.members
WHERE group_id = 'f0000000-0000-0000-0000-000000000001'::uuid
  AND user_id = 'ee000000-0000-0000-0000-000000000001'::uuid;

-- ── ESC-R-08: bob cannot add members to G2 — not a member of G2 ───────────────
-- bob has admin in G but is NOT in G2. The is_member check should block this.
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
        PERFORM rbac.add_member(
            'f0000000-0000-0000-0000-000000000002'::uuid,
            'ee000000-0000-0000-0000-000000000001'::uuid,
            ARRAY['viewer']
        );
    EXCEPTION WHEN OTHERS THEN
        v_blocked := true;
    END;
    RESET ROLE;
    PERFORM set_config('test.escr08', v_blocked::text, true);
END$$;

SELECT ok(
    current_setting('test.escr08') = 'true',
    'ESC-R-08: bob cannot add members to G2 — not a member of G2 (cross-group denial)'
);

-- ── ESC-R-09: carol (editor, grantable_roles=[viewer]) cannot assign admin ────
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
        PERFORM rbac.add_member(
            'f0000000-0000-0000-0000-000000000001'::uuid,
            'dd000000-0000-0000-0000-000000000001'::uuid,
            ARRAY['admin']
        );
    EXCEPTION WHEN OTHERS THEN
        v_blocked := true;
    END;
    RESET ROLE;
    PERFORM set_config('test.escr09', v_blocked::text, true);
END$$;

SELECT ok(
    current_setting('test.escr09') = 'true',
    'ESC-R-09: carol (editor) cannot assign admin role — outside editor grantable set'
);

SELECT * FROM finish();
ROLLBACK;
