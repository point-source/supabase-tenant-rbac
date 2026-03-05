-- Tests for deny-all default enforcement (DA-01 through DA-08).
-- Verifies that authenticated users with no group membership cannot read
-- group data, that sensitive tables lack table-level grants for authenticated,
-- and that create_group (SECURITY DEFINER) still works despite deny-all RLS.

BEGIN;
SELECT plan(8);

-- ─────────────────────────────────────────────────────────────────────────────
-- Setup: alice (owner of group G) and eve (no group membership)
-- ─────────────────────────────────────────────────────────────────────────────

INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES
    ('aa000000-0000-0000-0000-000000000001'::uuid, 'da-alice@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('ee000000-0000-0000-0000-000000000001'::uuid, 'da-eve@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated');

INSERT INTO rbac.groups (id, name)
VALUES ('f0000000-0000-0000-0000-000000000001'::uuid, 'DA Test Group G');

-- Add alice as owner so group G has content for RLS filtering tests.
-- An invite is also created so there's data in rbac.invites to be blocked from.
INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('f0000000-0000-0000-0000-000000000001'::uuid,
        'aa000000-0000-0000-0000-000000000001'::uuid, ARRAY['owner']);

INSERT INTO rbac.invites (group_id, roles, invited_by)
VALUES ('f0000000-0000-0000-0000-000000000001'::uuid, ARRAY['viewer'],
        'aa000000-0000-0000-0000-000000000001'::uuid);

INSERT INTO rbac.member_permissions (group_id, user_id, permission)
VALUES ('f0000000-0000-0000-0000-000000000001'::uuid,
        'aa000000-0000-0000-0000-000000000001'::uuid, 'group.update');

-- ── DA-01: eve (no membership) sees 0 rows from rbac.groups ──────────────────
-- Even though the migration RLS policy is present, eve has no membership
-- so is_member() always returns false for her — effective deny.
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"ee000000-0000-0000-0000-000000000001","exp":9999999999}',
    true);
SELECT set_config('request.groups', '{}', true);

SET LOCAL ROLE authenticated;
SELECT is(
    (SELECT count(*)::int FROM rbac.groups),
    0,
    'DA-01: eve (no membership) sees 0 rows from rbac.groups — RLS effective deny'
);
RESET ROLE;

-- ── DA-02: eve (no membership) sees 0 rows from rbac.members ─────────────────
SET LOCAL ROLE authenticated;
SELECT is(
    (SELECT count(*)::int FROM rbac.members),
    0,
    'DA-02: eve (no membership) sees 0 rows from rbac.members — RLS effective deny'
);
RESET ROLE;

-- ── DA-03: eve (no membership) sees 0 rows from rbac.invites ─────────────────
SET LOCAL ROLE authenticated;
SELECT is(
    (SELECT count(*)::int FROM rbac.invites),
    0,
    'DA-03: eve (no membership) sees 0 rows from rbac.invites — RLS effective deny'
);
RESET ROLE;

-- ── DA-04: eve (no membership) sees 0 rows from rbac.member_permissions ───────
SET LOCAL ROLE authenticated;
SELECT is(
    (SELECT count(*)::int FROM rbac.member_permissions),
    0,
    'DA-04: eve (no membership) sees 0 rows from rbac.member_permissions — RLS effective deny'
);
RESET ROLE;

-- ── DA-05: authenticated does NOT have table-level SELECT on rbac.roles ────────
-- v5.2.1 removed SELECT grant from authenticated on rbac.roles.
SELECT ok(
    NOT has_table_privilege('authenticated', 'rbac.roles', 'SELECT'),
    'DA-05: authenticated does not have table-level SELECT privilege on rbac.roles'
);

-- ── DA-06: authenticated does NOT have table-level SELECT on rbac.permissions ──
-- There is no standalone rbac.permissions table — permissions live in roles.permissions[].
-- This test validates that authenticated cannot SELECT from rbac.roles (the registry).
-- DA-06 reframes as: authenticated has no INSERT on rbac.roles (cannot alter role defs).
SELECT ok(
    NOT has_table_privilege('authenticated', 'rbac.roles', 'INSERT'),
    'DA-06: authenticated does not have INSERT privilege on rbac.roles — role mgmt is service_role only'
);

-- ── DA-07: authenticated does NOT have INSERT or UPDATE on rbac.user_claims ────
-- v5.2.1 reduced user_claims grants to SELECT-only for authenticated.
-- Trigger functions (SECURITY DEFINER) handle all writes.
SELECT ok(
    NOT has_table_privilege('authenticated', 'rbac.user_claims', 'INSERT')
    AND NOT has_table_privilege('authenticated', 'rbac.user_claims', 'UPDATE'),
    'DA-07: authenticated has no INSERT or UPDATE on rbac.user_claims — claims are trigger-managed'
);

-- ── DA-08: alice calls create_group (SECURITY DEFINER) — succeeds despite RLS ──
-- create_group is SECURITY DEFINER and bypasses RLS for INSERTs into groups/members.
-- It uses auth.uid() for the creator user_id, not a spoofable parameter.
DO $$
DECLARE
    v_new_group_id uuid;
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
        v_new_group_id := rbac.create_group('DA Test New Group', '{}', ARRAY['owner']);
        PERFORM set_config('test.da08_group_id', v_new_group_id::text, true);
        PERFORM set_config('test.da08_succeeded', 'true', true);
    EXCEPTION WHEN OTHERS THEN
        PERFORM set_config('test.da08_succeeded', 'false', true);
    END;
    RESET ROLE;
END$$;

SELECT ok(
    current_setting('test.da08_succeeded') = 'true'
    AND EXISTS (
        SELECT 1 FROM rbac.groups
        WHERE id = current_setting('test.da08_group_id')::uuid
          AND name = 'DA Test New Group'
    )
    AND EXISTS (
        SELECT 1 FROM rbac.members
        WHERE group_id = current_setting('test.da08_group_id')::uuid
          AND user_id = 'aa000000-0000-0000-0000-000000000001'::uuid
          AND 'owner' = ANY(roles)
    ),
    'DA-08: create_group (SECURITY DEFINER) bypasses deny-all RLS — group and membership created'
);

SELECT * FROM finish();
ROLLBACK;
