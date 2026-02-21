-- Tests for RLS policy enforcement on sensitive_data.
-- Verifies that group isolation works end-to-end: users can only read rows
-- belonging to groups they are members of; anon and groupless users get nothing.
--
-- Uses seed-data UUIDs (supabase/seed.sql):
--   devuser  (d55f3b79...) → RED group (full perms) + BLUE group (read-only)
--   invited  (1a01f608...) → BLUE group (full perms) + GREEN group (read-only)
--   sensitive_data: one row per group (RED, BLUE, GREEN)
--
-- RLS policy under test (20240512101038_add_rls_policies.sql):
--   "Allow group member to read" → user_is_group_member(owned_by_group)
--
-- Uses SET LOCAL ROLE to exercise RLS as an unprivileged caller, then
-- RESET ROLE to return to postgres for subsequent setup steps.

BEGIN;
SELECT plan(5);

-- Setup: a groupless user (no group_users rows, no groups in raw_app_meta_data)
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    'ffffffff-0000-0000-0000-000000000099'::uuid,
    'rls-groupless@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{"provider": "email", "providers": ["email"]}'::jsonb,
    '{}'::jsonb,
    false, 'authenticated'
);

-- ── Test 1: devuser can read RED sensitive_data ───────────────────────────────
-- devuser is a member of RED (has group_data.read and more), so the
-- "Allow group member to read" policy should pass for the RED row.
SELECT set_config('request.groups', '', true);
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"d55f3b79-9004-4bc4-af5c-7fcc1478345a","exp":9999999999}',
    true);
SET LOCAL ROLE authenticated;
SELECT is(
    (SELECT count(*)::int FROM public.sensitive_data
     WHERE owned_by_group = 'ffc83b57-2960-47dc-bdfb-adc9b894c8d9'::uuid),
    1,
    'devuser can read sensitive_data owned by RED group (is a member)'
);
RESET ROLE;

-- ── Test 2: devuser cannot read GREEN sensitive_data ─────────────────────────
-- devuser has no membership in GREEN, so the RLS check should return false
-- and the GREEN row should be invisible.
SELECT set_config('request.groups', '', true);
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"d55f3b79-9004-4bc4-af5c-7fcc1478345a","exp":9999999999}',
    true);
SET LOCAL ROLE authenticated;
SELECT is(
    (SELECT count(*)::int FROM public.sensitive_data
     WHERE owned_by_group = '690b6e42-cb50-47fa-9e47-0d3167a7e125'::uuid),
    0,
    'devuser cannot read sensitive_data owned by GREEN group (not a member)'
);
RESET ROLE;

-- ── Test 3: invited user can read BLUE sensitive_data ────────────────────────
-- invited is a member of BLUE (has full permissions), so the BLUE row should
-- be visible.
SELECT set_config('request.groups', '', true);
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"1a01f608-c233-4ad6-966e-cf47ff33ee4f","exp":9999999999}',
    true);
SET LOCAL ROLE authenticated;
SELECT is(
    (SELECT count(*)::int FROM public.sensitive_data
     WHERE owned_by_group = '088ee15b-da1e-42a4-8af5-c87ae0891cab'::uuid),
    1,
    'invited user can read sensitive_data owned by BLUE group (is a member)'
);
RESET ROLE;

-- ── Test 4: anon role gets zero rows ─────────────────────────────────────────
-- The "Allow group member to read" policy is restricted to the authenticated
-- role, so anon callers should always see an empty result set.
SELECT set_config('request.groups', '', true);
SELECT set_config('request.jwt.claims', '{"role":"anon"}', true);
SET LOCAL ROLE anon;
SELECT is(
    (SELECT count(*)::int FROM public.sensitive_data),
    0,
    'anon role cannot read any sensitive_data rows'
);
RESET ROLE;

-- ── Test 5: groupless user gets zero rows ────────────────────────────────────
-- A user with no group memberships has an empty groups object in auth.users.
-- user_is_group_member() returns false for every row → no rows visible.
SELECT set_config('request.groups', '', true);
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"ffffffff-0000-0000-0000-000000000099","exp":9999999999}',
    true);
SET LOCAL ROLE authenticated;
SELECT is(
    (SELECT count(*)::int FROM public.sensitive_data),
    0,
    'user with no group memberships cannot read any sensitive_data rows'
);
RESET ROLE;

SELECT * FROM finish();
ROLLBACK;
