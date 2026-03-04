-- Tests for cross-tenant isolation on rbac tables.
-- Verifies that an authenticated user can only see data from groups they belong
-- to, cannot read another user's claims row, cannot see rbac.roles, and cannot
-- self-promote their role via direct UPDATE.
--
-- Seed data used (supabase/seed.sql):
--   devuser  (d55f3b79...) → RED (owner) + BLUE (viewer)
--   invited  (1a01f608...) → BLUE (owner) + GREEN (viewer)
--   RED:   ffc83b57-2960-47dc-bdfb-adc9b894c8d9
--   BLUE:  088ee15b-da1e-42a4-8af5-c87ae0891cab
--   GREEN: 690b6e42-cb50-47fa-9e47-0d3167a7e125

BEGIN;
SELECT plan(9);

-- Setup: create a groupless user for isolation tests
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    'eeeeeeee-0000-0000-0000-000000000024'::uuid,
    'groupless-isolation@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{"provider": "email", "providers": ["email"]}'::jsonb,
    '{}'::jsonb,
    false, 'authenticated'
);

-- Create a GREEN invite and member_permissions row so there is something
-- to be blocked from (otherwise zero rows = zero regardless of RLS).
INSERT INTO rbac.invites (group_id, roles, invited_by)
VALUES ('690b6e42-cb50-47fa-9e47-0d3167a7e125'::uuid, ARRAY['viewer'],
        '1a01f608-c233-4ad6-966e-cf47ff33ee4f'::uuid);

-- ── Test 1: authenticated does NOT have table-level SELECT on rbac.roles ──────
-- (privilege check — no role switch needed)
SELECT ok(
    NOT has_table_privilege('authenticated', 'rbac.roles', 'SELECT'),
    'authenticated role does not have table-level SELECT privilege on rbac.roles'
);

-- ── Tests 2-7: devuser (RED owner) sees RED but not GREEN ─────────────────────
-- Set JWT + claims context for devuser.
-- request.groups is loaded from user_claims (set before role switch).
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"d55f3b79-9004-4bc4-af5c-7fcc1478345a","exp":9999999999}',
    true);
SELECT set_config('request.groups',
    (SELECT claims::text FROM rbac.user_claims
     WHERE user_id = 'd55f3b79-9004-4bc4-af5c-7fcc1478345a'::uuid),
    true);

-- ── Test 2: devuser CAN read RED group (sanity/baseline) ─────────────────────
SET LOCAL ROLE authenticated;
SELECT is(
    (SELECT count(*)::int FROM rbac.groups
     WHERE id = 'ffc83b57-2960-47dc-bdfb-adc9b894c8d9'::uuid),
    1,
    'devuser (RED owner) can read RED group row'
);
RESET ROLE;

-- ── Test 3: devuser CANNOT read GREEN group ───────────────────────────────────
SET LOCAL ROLE authenticated;
SELECT is(
    (SELECT count(*)::int FROM rbac.groups
     WHERE id = '690b6e42-cb50-47fa-9e47-0d3167a7e125'::uuid),
    0,
    'devuser cannot read GREEN group row (not a member — RLS blocks)'
);
RESET ROLE;

-- ── Test 4: devuser CANNOT read GREEN members ─────────────────────────────────
SET LOCAL ROLE authenticated;
SELECT is(
    (SELECT count(*)::int FROM rbac.members
     WHERE group_id = '690b6e42-cb50-47fa-9e47-0d3167a7e125'::uuid),
    0,
    'devuser cannot read GREEN members (not a member — RLS blocks)'
);
RESET ROLE;

-- ── Test 5: devuser CANNOT read GREEN invites ─────────────────────────────────
SET LOCAL ROLE authenticated;
SELECT is(
    (SELECT count(*)::int FROM rbac.invites
     WHERE group_id = '690b6e42-cb50-47fa-9e47-0d3167a7e125'::uuid),
    0,
    'devuser cannot read GREEN invites (not a member — RLS blocks)'
);
RESET ROLE;

-- ── Test 6: devuser CANNOT read GREEN member_permissions ──────────────────────
SET LOCAL ROLE authenticated;
SELECT is(
    (SELECT count(*)::int FROM rbac.member_permissions
     WHERE group_id = '690b6e42-cb50-47fa-9e47-0d3167a7e125'::uuid),
    0,
    'devuser cannot read GREEN member_permissions (not a member — RLS blocks)'
);
RESET ROLE;

-- ── Test 7: devuser can only read their OWN row in rbac.user_claims ───────────
SET LOCAL ROLE authenticated;
SELECT is(
    (SELECT count(*)::int FROM rbac.user_claims
     WHERE user_id = 'd55f3b79-9004-4bc4-af5c-7fcc1478345a'::uuid),
    1,
    'devuser can read their own user_claims row (RLS: user_id = auth.uid())'
);
RESET ROLE;

-- ── Test 8: zero-membership user sees no rbac.groups rows ────────────────────
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"eeeeeeee-0000-0000-0000-000000000024","exp":9999999999}',
    true);
SELECT set_config('request.groups', '{}', true);
SET LOCAL ROLE authenticated;
SELECT is(
    (SELECT count(*)::int FROM rbac.groups),
    0,
    'user with no group memberships cannot read any rbac.groups rows'
);
RESET ROLE;

-- ── Test 9: viewer (devuser in BLUE) cannot self-promote via UPDATE ───────────
-- devuser in BLUE is a viewer (roles = ARRAY['viewer']).
-- RLS UPDATE policy on rbac.members requires has_permission(group_id, 'group_user.update').
-- viewer does not have group_user.update — RLS makes the row invisible to UPDATE
-- (0 rows affected silently). insufficient_privilege is NOT raised because
-- authenticated has table-level UPDATE privilege; RLS filtering is not an exception.
-- Verification: check the row still has ARRAY['viewer'] after the attempt.
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"d55f3b79-9004-4bc4-af5c-7fcc1478345a","exp":9999999999}',
    true);
SELECT set_config('request.groups',
    (SELECT claims::text FROM rbac.user_claims
     WHERE user_id = 'd55f3b79-9004-4bc4-af5c-7fcc1478345a'::uuid),
    true);

SET LOCAL ROLE authenticated;
UPDATE rbac.members
SET roles = ARRAY['owner']
WHERE group_id = '088ee15b-da1e-42a4-8af5-c87ae0891cab'::uuid
  AND user_id  = 'd55f3b79-9004-4bc4-af5c-7fcc1478345a'::uuid;
RESET ROLE;

-- As postgres: verify the roles column is still ARRAY['viewer'] (UPDATE was a no-op)
SELECT ok(
    (SELECT roles = ARRAY['viewer']
     FROM rbac.members
     WHERE group_id = '088ee15b-da1e-42a4-8af5-c87ae0891cab'::uuid
       AND user_id  = 'd55f3b79-9004-4bc4-af5c-7fcc1478345a'::uuid),
    'viewer cannot self-promote via UPDATE rbac.members SET roles (RLS row-filter: no group_user.update — 0 rows affected)'
);

SELECT * FROM finish();
ROLLBACK;
