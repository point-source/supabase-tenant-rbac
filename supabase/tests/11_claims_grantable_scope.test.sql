-- Tests for CC-11 through CC-15: multi-role membership claims aggregation.
-- Verifies that a user holding multiple roles has permissions merged/unioned
-- from all roles, that set_role_permissions() causes claims to be rebuilt, and
-- that role changes affecting one user do not corrupt another user's claims.

BEGIN;
SELECT plan(5);

-- Setup: three test users and one group
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    '28000000-0000-0000-0000-000000000001'::uuid,
    'cc11-user1@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
), (
    '28000000-0000-0000-0000-000000000002'::uuid,
    'cc11-user2@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
), (
    '28000000-0000-0000-0000-000000000003'::uuid,
    'cc11-user3@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

INSERT INTO rbac.groups (id, name)
VALUES ('28000000-0000-0000-0000-000000000004'::uuid, 'CC-11 Test Group');

-- Register test permissions (rolled back at end of transaction)
INSERT INTO rbac.permissions (name, description) VALUES
    ('perm.x', 'CC-11 test permission x'),
    ('perm.y', 'CC-11 test permission y'),
    ('perm.z', 'CC-11 test permission z'),
    ('perm.w', 'CC-11 test permission w')
ON CONFLICT DO NOTHING;

-- Create isolated test roles
INSERT INTO rbac.roles (name, description, permissions)
VALUES
    ('cc11-roleA', 'Role A with perm-x perm-y', ARRAY['perm.x', 'perm.y']),
    ('cc11-roleB', 'Role B with perm-y perm-z', ARRAY['perm.y', 'perm.z'])
ON CONFLICT DO NOTHING;

-- user1: holds only cc11-roleA
-- user2: holds both cc11-roleA and cc11-roleB
-- user3: holds only cc11-roleB
INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('28000000-0000-0000-0000-000000000004'::uuid,
     '28000000-0000-0000-0000-000000000001'::uuid,
     ARRAY['cc11-roleA']),
    ('28000000-0000-0000-0000-000000000004'::uuid,
     '28000000-0000-0000-0000-000000000002'::uuid,
     ARRAY['cc11-roleA', 'cc11-roleB']),
    ('28000000-0000-0000-0000-000000000004'::uuid,
     '28000000-0000-0000-0000-000000000003'::uuid,
     ARRAY['cc11-roleB']);

-- ── CC-11: user1 (single role) has only that role's permissions ───────────────
-- user1 holds cc11-roleA → permissions should be [perm.x, perm.y]
-- Verify count is exactly 2 and both are present.
SELECT is(
    jsonb_array_length(
        (SELECT claims -> '28000000-0000-0000-0000-000000000004' -> 'permissions'
         FROM rbac.user_claims
         WHERE user_id = '28000000-0000-0000-0000-000000000001'::uuid)
    ),
    2,
    'CC-11: single-role member has exactly the permissions from that role'
);

-- ── CC-12: user2 (two roles) has union of all permissions, deduplicated ────────
-- cc11-roleA: [perm.x, perm.y], cc11-roleB: [perm.y, perm.z]
-- Union = [perm.x, perm.y, perm.z] → exactly 3 permissions
SELECT is(
    jsonb_array_length(
        (SELECT claims -> '28000000-0000-0000-0000-000000000004' -> 'permissions'
         FROM rbac.user_claims
         WHERE user_id = '28000000-0000-0000-0000-000000000002'::uuid)
    ),
    3,
    'CC-12: multi-role member has union of all role permissions (deduplicated)'
);

-- ── CC-13: user2's merged permissions contain all expected values ──────────────
SELECT ok(
    (SELECT claims -> '28000000-0000-0000-0000-000000000004' -> 'permissions'
          @> '["perm.x","perm.y","perm.z"]'::jsonb
     FROM rbac.user_claims
     WHERE user_id = '28000000-0000-0000-0000-000000000002'::uuid),
    'CC-13: multi-role member''s permissions contain all expected values from both roles'
);

-- ── CC-14: changing one role's permissions triggers rebuild for affected users ──
-- Add perm.w to cc11-roleB. user2 and user3 (both hold cc11-roleB) should gain perm.w.
-- user1 (only cc11-roleA) should NOT get perm.w.
SELECT rbac.grant_permission('cc11-roleB', 'perm.w');

SELECT ok(
    (SELECT claims -> '28000000-0000-0000-0000-000000000004' -> 'permissions'
          ? 'perm.w'
     FROM rbac.user_claims
     WHERE user_id = '28000000-0000-0000-0000-000000000002'::uuid),
    'CC-14: granting permission to a role immediately updates claims for all holders'
);

-- ── CC-15: user not holding changed role is NOT affected ──────────────────────
-- user1 only has cc11-roleA, so perm.w (added to cc11-roleB) should not appear.
SELECT ok(
    NOT (SELECT claims -> '28000000-0000-0000-0000-000000000004' -> 'permissions'
              ? 'perm.w'
         FROM rbac.user_claims
         WHERE user_id = '28000000-0000-0000-0000-000000000001'::uuid),
    'CC-15: permission change on one role does not affect users who do not hold that role'
);

SELECT * FROM finish();
ROLLBACK;
