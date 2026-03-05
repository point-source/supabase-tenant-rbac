-- Tests for wildcard grantable_roles behavior (WC-01 through WC-05).
-- Verifies that alice (owner with grantable_roles=['*']) can grant any role,
-- grant any permission, and that new roles are covered by the wildcard,
-- while non-wildcard users are still restricted.

BEGIN;
SELECT plan(5);

-- ─────────────────────────────────────────────────────────────────────────────
-- Setup: five users, one group
-- alice=owner (grantable_roles=['*']), bob=admin, carol=editor, dave=viewer
-- eve=non-member
-- ─────────────────────────────────────────────────────────────────────────────

INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES
    ('aa000000-0000-0000-0000-000000000001'::uuid, 'wc-alice@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('bb000000-0000-0000-0000-000000000001'::uuid, 'wc-bob@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('cc000000-0000-0000-0000-000000000001'::uuid, 'wc-carol@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('dd000000-0000-0000-0000-000000000001'::uuid, 'wc-dave@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('ee000000-0000-0000-0000-000000000001'::uuid, 'wc-eve@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated');

INSERT INTO rbac.groups (id, name)
VALUES ('f0000000-0000-0000-0000-000000000001'::uuid, 'WC Test Group G');

INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'aa000000-0000-0000-0000-000000000001'::uuid, ARRAY['owner']),
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'bb000000-0000-0000-0000-000000000001'::uuid, ARRAY['admin']),
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'cc000000-0000-0000-0000-000000000001'::uuid, ARRAY['editor']),
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'dd000000-0000-0000-0000-000000000001'::uuid, ARRAY['viewer']);
-- eve is NOT a member

-- ── WC-01: alice (owner, grantable_roles=['*']) can add eve as admin ──────────
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
        PERFORM rbac.add_member(
            'f0000000-0000-0000-0000-000000000001'::uuid,
            'ee000000-0000-0000-0000-000000000001'::uuid,
            ARRAY['admin']
        );
        v_succeeded := true;
    EXCEPTION WHEN OTHERS THEN
        v_succeeded := false;
    END;
    RESET ROLE;
    PERFORM set_config('test.wc01', v_succeeded::text, true);
END$$;

SELECT ok(
    current_setting('test.wc01') = 'true',
    'WC-01: alice (owner, grantable_roles=[*]) can add member with any role including admin'
);

-- Remove eve between tests
DELETE FROM rbac.members
WHERE group_id = 'f0000000-0000-0000-0000-000000000001'::uuid
  AND user_id = 'ee000000-0000-0000-0000-000000000001'::uuid;

-- ── WC-02: alice (owner, grantable_permissions=['*']) can grant group.delete ───
-- group.delete is in alice's permissions (she's owner) and is a valid permission.
-- The wildcard grantable_permissions means alice can grant any registered permission.
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
    PERFORM set_config('test.wc02', v_succeeded::text, true);
END$$;

SELECT ok(
    current_setting('test.wc02') = 'true',
    'WC-02: alice (owner, grantable_permissions=[*]) can grant any registered permission override'
);

-- ── WC-03: alice's cached permissions include all owner permissions ────────────
-- The owner role has the full permission set. Verify alice's claims reflect this.
-- We can verify by checking that owner's full permission array is present in claims.
SELECT ok(
    (
        SELECT
            (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'permissions') ? 'group.delete'
            AND
            (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'permissions') ? 'group.update'
            AND
            (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'permissions') ? 'members.manage'
            AND
            (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'permissions') ? 'data.read'
            AND
            (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'roles') ? 'owner'
        FROM rbac.user_claims
        WHERE user_id = 'aa000000-0000-0000-0000-000000000001'::uuid
    ),
    'WC-03: alice (owner) cached claims include all owner permissions and correct roles'
);

-- ── WC-04: alice (wildcard) can add member with a newly created role ───────────
-- Create the 'moderator' role inside this transaction. alice's wildcard
-- grantable_roles covers it without cache rebuild.
INSERT INTO rbac.roles (name, description, permissions)
VALUES ('moderator', 'Test moderator role', ARRAY['data.read', 'data.write']);

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
        PERFORM rbac.add_member(
            'f0000000-0000-0000-0000-000000000001'::uuid,
            'ee000000-0000-0000-0000-000000000001'::uuid,
            ARRAY['moderator']
        );
        v_succeeded := true;
    EXCEPTION WHEN OTHERS THEN
        v_succeeded := false;
    END;
    RESET ROLE;
    PERFORM set_config('test.wc04', v_succeeded::text, true);
END$$;

SELECT ok(
    current_setting('test.wc04') = 'true',
    'WC-04: alice (wildcard) can add member with newly created moderator role — wildcard covers new roles'
);

-- Remove eve again before WC-05
DELETE FROM rbac.members
WHERE group_id = 'f0000000-0000-0000-0000-000000000001'::uuid
  AND user_id = 'ee000000-0000-0000-0000-000000000001'::uuid;

-- ── WC-05: bob (non-wildcard) cannot add member with moderator role ────────────
-- bob's admin role has grantable_roles=['editor','viewer']. moderator is NOT
-- in that explicit list, so bob cannot assign it.
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
            ARRAY['moderator']
        );
    EXCEPTION WHEN OTHERS THEN
        v_blocked := true;
    END;
    RESET ROLE;
    PERFORM set_config('test.wc05', v_blocked::text, true);
END$$;

SELECT ok(
    current_setting('test.wc05') = 'true',
    'WC-05: bob (admin, non-wildcard) cannot add member with moderator role — not in [editor, viewer]'
);

SELECT * FROM finish();
ROLLBACK;
