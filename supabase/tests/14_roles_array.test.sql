-- Tests for roles text[] array behavior in the members table.
-- Verifies: empty arrays, merge on conflict via add_member, dedup,
-- and metadata sync with array roles.

BEGIN;
SELECT plan(7);

-- Setup: test user
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    'aaaaaaaa-1111-0000-0000-000000000001'::uuid,
    'roles-array-test@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

INSERT INTO rbac.groups (id, name)
VALUES ('aaaaaaaa-1111-0000-0000-000000000002'::uuid, 'Roles Array Test Group');

-- Ensure needed roles exist
INSERT INTO rbac.roles (name) VALUES ('admin'), ('viewer'), ('editor') ON CONFLICT DO NOTHING;

-- ── Test 1: empty roles array is valid ───────────────────────────────────────
INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('aaaaaaaa-1111-0000-0000-000000000002'::uuid,
        'aaaaaaaa-1111-0000-0000-000000000001'::uuid,
        ARRAY[]::text[]);

SELECT is(
    (SELECT roles
     FROM rbac.members
     WHERE group_id = 'aaaaaaaa-1111-0000-0000-000000000002'::uuid
       AND user_id = 'aaaaaaaa-1111-0000-0000-000000000001'::uuid),
    ARRAY[]::text[],
    'empty roles array is stored correctly'
);

-- ── Test 2: empty array syncs to empty JSONB array in user_claims ────────────
SELECT is(
    (SELECT claims->'aaaaaaaa-1111-0000-0000-000000000002'
     FROM rbac.user_claims WHERE user_id = 'aaaaaaaa-1111-0000-0000-000000000001'::uuid),
    '[]'::jsonb,
    'empty roles array syncs as empty JSONB array in user_claims'
);

-- ── Test 3: update to non-empty array ────────────────────────────────────────
UPDATE rbac.members
SET roles = ARRAY['viewer', 'editor']
WHERE group_id = 'aaaaaaaa-1111-0000-0000-000000000002'::uuid
  AND user_id = 'aaaaaaaa-1111-0000-0000-000000000001'::uuid;

SELECT ok(
    (SELECT claims->'aaaaaaaa-1111-0000-0000-000000000002'
     FROM rbac.user_claims WHERE user_id = 'aaaaaaaa-1111-0000-0000-000000000001'::uuid)
    @> '["viewer","editor"]'::jsonb,
    'non-empty roles array syncs to JSONB array in user_claims with both roles'
);

-- ── Test 4: add_member merges and deduplicates roles ─────────────────────────
SELECT rbac.add_member(
    'aaaaaaaa-1111-0000-0000-000000000002'::uuid,
    'aaaaaaaa-1111-0000-0000-000000000001'::uuid,
    ARRAY['viewer', 'admin']  -- viewer already exists, admin is new
);

SELECT ok(
    (SELECT roles @> ARRAY['viewer', 'editor', 'admin']
     FROM rbac.members
     WHERE group_id = 'aaaaaaaa-1111-0000-0000-000000000002'::uuid
       AND user_id = 'aaaaaaaa-1111-0000-0000-000000000001'::uuid),
    'add_member() merges and deduplicates roles (viewer not duplicated, admin added)'
);

-- ── Test 5: no duplicate entries in merged array ─────────────────────────────
SELECT is(
    (SELECT count(*)::int
     FROM unnest(
         (SELECT roles FROM rbac.members
          WHERE group_id = 'aaaaaaaa-1111-0000-0000-000000000002'::uuid
            AND user_id = 'aaaaaaaa-1111-0000-0000-000000000001'::uuid)
     ) AS r
     WHERE r = 'viewer'),
    1,
    'viewer appears exactly once after merge (no duplicates)'
);

-- ── Test 6: roles are sorted alphabetically after merge ──────────────────────
SELECT is(
    (SELECT roles
     FROM rbac.members
     WHERE group_id = 'aaaaaaaa-1111-0000-0000-000000000002'::uuid
       AND user_id = 'aaaaaaaa-1111-0000-0000-000000000001'::uuid),
    ARRAY['admin', 'editor', 'viewer'],
    'roles are sorted alphabetically after merge'
);

-- ── Test 7: user_claims matches the roles array ──────────────────────────────
SELECT ok(
    (SELECT claims->'aaaaaaaa-1111-0000-0000-000000000002'
     FROM rbac.user_claims WHERE user_id = 'aaaaaaaa-1111-0000-0000-000000000001'::uuid)
    @> '["admin","editor","viewer"]'::jsonb,
    'user_claims contains all merged roles'
);

SELECT * FROM finish();
ROLLBACK;
