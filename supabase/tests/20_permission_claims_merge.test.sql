-- Tests for direct permission overrides merging into the claims cache (v5.1.0).
-- Verifies: direct perm appears in claims, merges with role perms,
-- deduplication, has_permission() works, revoke updates claims.

BEGIN;
SELECT plan(8);

-- Setup: test user and group
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    'ffffffff-0000-0000-0000-000000000001'::uuid,
    'claims-merge@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

INSERT INTO rbac.groups (id, name)
VALUES ('ffffffff-0000-0000-0000-000000000002'::uuid, 'Claims Merge Test Group');

-- Create a role with known permissions
INSERT INTO rbac.roles (name) VALUES ('base-role') ON CONFLICT DO NOTHING;
SELECT rbac.set_role_permissions('base-role', ARRAY['base.read', 'base.write']);

INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('ffffffff-0000-0000-0000-000000000002'::uuid,
        'ffffffff-0000-0000-0000-000000000001'::uuid,
        ARRAY['base-role']);

-- ── Test 1: role permissions appear in claims after member INSERT ──────────────
SELECT ok(
    (SELECT claims->'ffffffff-0000-0000-0000-000000000002'->'permissions'
     @> '["base.read","base.write"]'::jsonb
     FROM rbac.user_claims
     WHERE user_id = 'ffffffff-0000-0000-0000-000000000001'::uuid),
    'role permissions appear in claims after member INSERT'
);

-- ── Test 2: direct permission override appears in claims after grant ───────────
INSERT INTO rbac.member_permissions (group_id, user_id, permission)
VALUES ('ffffffff-0000-0000-0000-000000000002'::uuid,
        'ffffffff-0000-0000-0000-000000000001'::uuid,
        'data.export');

SELECT ok(
    (SELECT claims->'ffffffff-0000-0000-0000-000000000002'->'permissions'
     ? 'data.export'
     FROM rbac.user_claims
     WHERE user_id = 'ffffffff-0000-0000-0000-000000000001'::uuid),
    'direct permission override appears in claims after grant'
);

-- ── Test 3: role permissions still present alongside direct override ───────────
SELECT ok(
    (SELECT claims->'ffffffff-0000-0000-0000-000000000002'->'permissions'
     @> '["base.read","base.write"]'::jsonb
     FROM rbac.user_claims
     WHERE user_id = 'ffffffff-0000-0000-0000-000000000001'::uuid),
    'role permissions remain in claims alongside direct overrides'
);

-- ── Test 4: total permissions count is correct (3: base.read, base.write, data.export) ─
SELECT is(
    jsonb_array_length(
        (SELECT claims->'ffffffff-0000-0000-0000-000000000002'->'permissions'
         FROM rbac.user_claims
         WHERE user_id = 'ffffffff-0000-0000-0000-000000000001'::uuid)
    ),
    3,
    'merged permissions array has correct count (role perms + direct override)'
);

-- ── Test 5: duplicate direct permission is deduplicated in claims ──────────────
-- Grant a permission that base-role already provides
INSERT INTO rbac.member_permissions (group_id, user_id, permission)
VALUES ('ffffffff-0000-0000-0000-000000000002'::uuid,
        'ffffffff-0000-0000-0000-000000000001'::uuid,
        'base.read');  -- already in claims via role

SELECT is(
    jsonb_array_length(
        (SELECT claims->'ffffffff-0000-0000-0000-000000000002'->'permissions'
         FROM rbac.user_claims
         WHERE user_id = 'ffffffff-0000-0000-0000-000000000001'::uuid)
    ),
    3,  -- still 3: base.read, base.write, data.export — no duplicate
    'duplicate between direct override and role permission is deduplicated in claims'
);

-- ── Test 6: has_permission() returns true for a directly-granted permission ────
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"ffffffff-0000-0000-0000-000000000001","exp":9999999999}',
    true);
SELECT set_config('request.groups',
    (SELECT claims::text FROM rbac.user_claims
     WHERE user_id = 'ffffffff-0000-0000-0000-000000000001'::uuid), true);

SET LOCAL ROLE authenticated;
SELECT is(
    rbac.has_permission('ffffffff-0000-0000-0000-000000000002'::uuid, 'data.export'),
    true,
    'has_permission() returns true for a directly-granted permission override'
);
RESET ROLE;

-- ── Test 7: revoking a direct permission removes it from claims ────────────────
DELETE FROM rbac.member_permissions
WHERE group_id = 'ffffffff-0000-0000-0000-000000000002'::uuid
  AND user_id  = 'ffffffff-0000-0000-0000-000000000001'::uuid
  AND permission = 'data.export';

-- Refresh request.groups to reflect updated claims
SELECT set_config('request.groups',
    (SELECT claims::text FROM rbac.user_claims
     WHERE user_id = 'ffffffff-0000-0000-0000-000000000001'::uuid), true);

SET LOCAL ROLE authenticated;
SELECT is(
    rbac.has_permission('ffffffff-0000-0000-0000-000000000002'::uuid, 'data.export'),
    false,
    'has_permission() returns false after direct permission override is revoked'
);
RESET ROLE;

-- ── Test 8: role permissions remain in claims after direct permission revoked ───
SELECT ok(
    (SELECT claims->'ffffffff-0000-0000-0000-000000000002'->'permissions'
     @> '["base.read","base.write"]'::jsonb
     FROM rbac.user_claims
     WHERE user_id = 'ffffffff-0000-0000-0000-000000000001'::uuid),
    'role permissions remain intact after direct permission override is revoked'
);

SELECT * FROM finish();
ROLLBACK;
