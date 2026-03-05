-- Tests for EC-01 through EC-08: edge cases and boundary conditions.
-- Covers empty-roles membership, deduplication in add_member(), empty claims
-- after removing all memberships, multi-group claims, cascading permission
-- cleanup, and bulk claims rebuild when a role's permissions change.

BEGIN;
SELECT plan(9);

-- Setup: users and groups
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    '33000000-0000-0000-0000-000000000001'::uuid,
    'ec-alice@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
), (
    '33000000-0000-0000-0000-000000000002'::uuid,
    'ec-eve@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
), (
    '33000000-0000-0000-0000-000000000005'::uuid,
    'ec-user5@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
), (
    '33000000-0000-0000-0000-000000000006'::uuid,
    'ec-user6@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

INSERT INTO rbac.groups (id, name)
VALUES
    ('33000000-0000-0000-0000-000000000003'::uuid, 'EC Test Group G1'),
    ('33000000-0000-0000-0000-000000000004'::uuid, 'EC Test Group G2'),
    ('33000000-0000-0000-0000-000000000007'::uuid, 'EC Test Group G3');

INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('33000000-0000-0000-0000-000000000003'::uuid,
     '33000000-0000-0000-0000-000000000001'::uuid,
     ARRAY['owner']);

-- ── EC-01: user_claims = '{}' after removing from all groups ─────────────────
-- Add eve to G1 and G2, then remove from both. Claims should be empty object.
SELECT rbac.add_member(
    '33000000-0000-0000-0000-000000000003'::uuid,
    '33000000-0000-0000-0000-000000000002'::uuid,
    ARRAY['viewer']
);
SELECT rbac.add_member(
    '33000000-0000-0000-0000-000000000004'::uuid,
    '33000000-0000-0000-0000-000000000002'::uuid,
    ARRAY['viewer']
);
SELECT rbac.remove_member(
    '33000000-0000-0000-0000-000000000003'::uuid,
    '33000000-0000-0000-0000-000000000002'::uuid
);
SELECT rbac.remove_member(
    '33000000-0000-0000-0000-000000000004'::uuid,
    '33000000-0000-0000-0000-000000000002'::uuid
);

SELECT is(
    (SELECT claims FROM rbac.user_claims
     WHERE user_id = '33000000-0000-0000-0000-000000000002'::uuid),
    '{}'::jsonb,
    'EC-01: user_claims is empty object (not NULL) after removal from all groups'
);

-- ── EC-02: add_member() with empty roles[] creates valid membership ────────────
-- Eve joins G1 with no roles. She IS a member but has no roles or permissions.
SELECT rbac.add_member(
    '33000000-0000-0000-0000-000000000003'::uuid,
    '33000000-0000-0000-0000-000000000002'::uuid,
    '{}'::text[]
);

SELECT ok(
    (SELECT claims ? '33000000-0000-0000-0000-000000000003'
     FROM rbac.user_claims
     WHERE user_id = '33000000-0000-0000-0000-000000000002'::uuid),
    'EC-02: add_member() with empty roles[] still creates group key in claims (is_member)'
);

-- Verify roles array is empty
SELECT is(
    (SELECT roles FROM rbac.members
     WHERE group_id = '33000000-0000-0000-0000-000000000003'::uuid
       AND user_id  = '33000000-0000-0000-0000-000000000002'::uuid),
    '{}'::text[],
    'EC-02b: member created with empty roles[] has an empty roles array'
);

-- ── EC-03: direct postgres remove_member() bypasses RLS ──────────────────────
-- Remove alice directly as postgres (no role context, bypasses RLS).
DELETE FROM rbac.members
WHERE group_id = '33000000-0000-0000-0000-000000000003'::uuid
  AND user_id  = '33000000-0000-0000-0000-000000000001'::uuid;

SELECT ok(
    NOT EXISTS (
        SELECT 1 FROM rbac.members
        WHERE group_id = '33000000-0000-0000-0000-000000000003'::uuid
          AND user_id  = '33000000-0000-0000-0000-000000000001'::uuid
    ),
    'EC-03: postgres can directly DELETE from rbac.members (bypasses RLS)'
);

-- Restore alice for subsequent tests
INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('33000000-0000-0000-0000-000000000003'::uuid,
     '33000000-0000-0000-0000-000000000001'::uuid,
     ARRAY['owner']);

-- ── EC-04: create_group() with custom creator roles ───────────────────────────
-- Alice calls create_group() with ARRAY['viewer'] as creator roles.
-- Result: alice is a member with roles=['viewer'], not owner.
DO $$
DECLARE v_gid uuid;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"33000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    v_gid := rbac.create_group('Custom Roles Group', '{}'::jsonb, ARRAY['viewer']);
    PERFORM set_config('test.ec04_gid', v_gid::text, true);
END$$;

SELECT ok(
    (SELECT roles = ARRAY['viewer']
     FROM rbac.members
     WHERE group_id = current_setting('test.ec04_gid')::uuid
       AND user_id  = '33000000-0000-0000-0000-000000000001'::uuid),
    'EC-04: create_group() assigns the requested creator roles (not forced owner)'
);

-- ── EC-05: add_member() deduplicates roles ────────────────────────────────────
-- Add eve to G2 with duplicate role values. The ON CONFLICT merge path deduplicates.
SELECT rbac.add_member(
    '33000000-0000-0000-0000-000000000004'::uuid,
    '33000000-0000-0000-0000-000000000002'::uuid,
    ARRAY['viewer', 'viewer']
);

SELECT is(
    array_length(
        (SELECT roles FROM rbac.members
         WHERE group_id = '33000000-0000-0000-0000-000000000004'::uuid
           AND user_id  = '33000000-0000-0000-0000-000000000002'::uuid),
        1
    ),
    1,
    'EC-05: add_member() deduplicates roles — duplicate entries collapse to one element'
);

-- ── EC-06: idempotent grant_member_permission() does not create duplicates ────
-- Grant data.export to alice in G1 twice — count should remain 1.
SELECT rbac.grant_member_permission(
    '33000000-0000-0000-0000-000000000003'::uuid,
    '33000000-0000-0000-0000-000000000001'::uuid,
    'data.export'
);
SELECT rbac.grant_member_permission(
    '33000000-0000-0000-0000-000000000003'::uuid,
    '33000000-0000-0000-0000-000000000001'::uuid,
    'data.export'
);

SELECT is(
    (SELECT count(*)::int FROM rbac.member_permissions
     WHERE group_id   = '33000000-0000-0000-0000-000000000003'::uuid
       AND user_id    = '33000000-0000-0000-0000-000000000001'::uuid
       AND permission = 'data.export'),
    1,
    'EC-06: duplicate grant_member_permission() calls are idempotent (ON CONFLICT DO NOTHING)'
);

-- ── EC-07: multi-group membership — user_claims has multiple group keys ────────
-- user5 joins G1, G2, G3. Claims should have exactly 3 group keys.
SELECT rbac.add_member(
    '33000000-0000-0000-0000-000000000003'::uuid,
    '33000000-0000-0000-0000-000000000005'::uuid,
    ARRAY['viewer']
);
SELECT rbac.add_member(
    '33000000-0000-0000-0000-000000000004'::uuid,
    '33000000-0000-0000-0000-000000000005'::uuid,
    ARRAY['viewer']
);
SELECT rbac.add_member(
    '33000000-0000-0000-0000-000000000007'::uuid,
    '33000000-0000-0000-0000-000000000005'::uuid,
    ARRAY['viewer']
);

SELECT is(
    (SELECT count(*)::int
     FROM (
         SELECT jsonb_object_keys(claims)
         FROM rbac.user_claims
         WHERE user_id = '33000000-0000-0000-0000-000000000005'::uuid
     ) AS keys),
    3,
    'EC-07: user with 3 group memberships has 3 keys in user_claims'
);

-- ── EC-08: bulk claims rebuild when a role's permissions change ───────────────
-- Add user5 and user6 both as viewers in G1. Change viewer.permissions.
-- Both users' claims should be updated by the trigger.
INSERT INTO rbac.permissions (name, description) VALUES
    ('perm.bulk',  'EC-08 bulk rebuild test permission 1'),
    ('perm.bulk2', 'EC-08 bulk rebuild test permission 2')
ON CONFLICT DO NOTHING;

INSERT INTO rbac.roles (name, description, permissions)
VALUES ('ec08-role', 'EC-08 bulk rebuild test role', ARRAY['perm.bulk'])
ON CONFLICT DO NOTHING;

SELECT rbac.add_member(
    '33000000-0000-0000-0000-000000000003'::uuid,
    '33000000-0000-0000-0000-000000000006'::uuid,
    ARRAY['ec08-role']
);
-- user5 also gets this role via update
SELECT rbac.update_member_roles(
    '33000000-0000-0000-0000-000000000003'::uuid,
    '33000000-0000-0000-0000-000000000005'::uuid,
    ARRAY['ec08-role']
);

-- Change the role's permissions — trigger must rebuild both users
SELECT rbac.grant_permission('ec08-role', 'perm.bulk2');

SELECT ok(
    (SELECT claims -> '33000000-0000-0000-0000-000000000003' -> 'permissions' ? 'perm.bulk2'
     FROM rbac.user_claims
     WHERE user_id = '33000000-0000-0000-0000-000000000005'::uuid)
    AND
    (SELECT claims -> '33000000-0000-0000-0000-000000000003' -> 'permissions' ? 'perm.bulk2'
     FROM rbac.user_claims
     WHERE user_id = '33000000-0000-0000-0000-000000000006'::uuid),
    'EC-08: changing role permissions triggers bulk rebuild for all members holding that role'
);

SELECT * FROM finish();
ROLLBACK;
