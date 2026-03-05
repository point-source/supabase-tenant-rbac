-- Tests for claims cache integrity (CC-01 through CC-07).
-- Verifies that the trigger-based sync mechanism correctly maintains
-- rbac.user_claims as memberships, role updates, and permission overrides change.
-- All tests run as postgres (no role switching needed) since we query user_claims directly.

BEGIN;
SELECT plan(7);

-- ─────────────────────────────────────────────────────────────────────────────
-- Setup: alice (owner), bob (viewer initially), eve (non-member), two groups
-- ─────────────────────────────────────────────────────────────────────────────

INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES
    ('aa000000-0000-0000-0000-000000000001'::uuid, 'cc-alice@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('bb000000-0000-0000-0000-000000000001'::uuid, 'cc-bob@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('ee000000-0000-0000-0000-000000000001'::uuid, 'cc-eve@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated');

INSERT INTO rbac.groups (id, name) VALUES
    ('f0000000-0000-0000-0000-000000000001'::uuid, 'CC Test Group G'),
    ('f0000000-0000-0000-0000-000000000002'::uuid, 'CC Test Group G2');

INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('f0000000-0000-0000-0000-000000000001'::uuid,
     'aa000000-0000-0000-0000-000000000001'::uuid, ARRAY['owner']);

-- ── CC-01: adding bob as viewer → user_claims updated ─────────────────────────
-- Insert bob as viewer. The on_change_sync_member_metadata trigger fires and
-- builds bob's claims. Verify: roles=['viewer'], permissions includes data.read,
-- and the group G key is present in claims.
INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('f0000000-0000-0000-0000-000000000001'::uuid,
        'bb000000-0000-0000-0000-000000000001'::uuid, ARRAY['viewer']);

SELECT ok(
    (
        SELECT
            (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'roles') ? 'viewer'
            AND
            (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'permissions') ? 'data.read'
            AND
            claims ? 'f0000000-0000-0000-0000-000000000001'
        FROM rbac.user_claims
        WHERE user_id = 'bb000000-0000-0000-0000-000000000001'::uuid
    ),
    'CC-01: adding bob as viewer auto-populates user_claims with correct roles and permissions'
);

-- ── CC-02: removing bob from group → G key removed from claims ────────────────
DELETE FROM rbac.members
WHERE group_id = 'f0000000-0000-0000-0000-000000000001'::uuid
  AND user_id = 'bb000000-0000-0000-0000-000000000001'::uuid;

SELECT ok(
    (
        SELECT
            NOT (claims ? 'f0000000-0000-0000-0000-000000000001')
            AND claims = '{}'::jsonb
        FROM rbac.user_claims
        WHERE user_id = 'bb000000-0000-0000-0000-000000000001'::uuid
    ),
    'CC-02: removing bob from group removes G key from user_claims — claims = {} when no memberships remain'
);

-- ── CC-03: update_member_roles rebuilds all four cache fields ─────────────────
-- Re-add bob as viewer, then update to editor. Verify claims reflect editor role/perms.
INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('f0000000-0000-0000-0000-000000000001'::uuid,
        'bb000000-0000-0000-0000-000000000001'::uuid, ARRAY['viewer']);

-- Update via the management RPC (runs as postgres — no auth context needed)
SELECT rbac.update_member_roles(
    'f0000000-0000-0000-0000-000000000001'::uuid,
    'bb000000-0000-0000-0000-000000000001'::uuid,
    ARRAY['editor']
);

SELECT ok(
    (
        SELECT
            (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'roles') ? 'editor'
            AND NOT (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'roles') ? 'viewer'
            AND (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'permissions') ? 'data.read'
            AND (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'permissions') ? 'data.write'
        FROM rbac.user_claims
        WHERE user_id = 'bb000000-0000-0000-0000-000000000001'::uuid
    ),
    'CC-03: update_member_roles to editor rebuilds claims — roles=[editor], permissions include data.read and data.write'
);

-- ── CC-04: grant_member_permission → cached permissions updated ────────────────
-- Add eve as viewer in G. Grant eve a data.export override.
-- Verify eve's cached permissions include data.export (from override) + data.read (from role).
INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('f0000000-0000-0000-0000-000000000001'::uuid,
        'ee000000-0000-0000-0000-000000000001'::uuid, ARRAY['viewer']);

SELECT rbac.grant_member_permission(
    'f0000000-0000-0000-0000-000000000001'::uuid,
    'ee000000-0000-0000-0000-000000000001'::uuid,
    'data.export'
);

SELECT ok(
    (
        SELECT
            (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'permissions') ? 'data.read'
            AND
            (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'permissions') ? 'data.export'
        FROM rbac.user_claims
        WHERE user_id = 'ee000000-0000-0000-0000-000000000001'::uuid
    ),
    'CC-04: granting eve a direct override adds data.export to cached permissions (merged with role perms)'
);

-- ── CC-05: revoke_member_permission → cached permissions revert to role-derived ─
-- Revoke the data.export override. Eve should revert to viewer perms only.
SELECT rbac.revoke_member_permission(
    'f0000000-0000-0000-0000-000000000001'::uuid,
    'ee000000-0000-0000-0000-000000000001'::uuid,
    'data.export'
);

SELECT ok(
    (
        SELECT
            (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'permissions') ? 'data.read'
            AND NOT
            (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'permissions') ? 'data.export'
        FROM rbac.user_claims
        WHERE user_id = 'ee000000-0000-0000-0000-000000000001'::uuid
    ),
    'CC-05: revoking data.export override restores viewer-only permissions (data.read only)'
);

-- ── CC-06: multi-group user has independent claims per group ───────────────────
-- Add eve as editor in G2. Eve now has G (viewer) and G2 (editor) — independent.
INSERT INTO rbac.members (group_id, user_id, roles)
VALUES ('f0000000-0000-0000-0000-000000000002'::uuid,
        'ee000000-0000-0000-0000-000000000001'::uuid, ARRAY['editor']);

SELECT ok(
    (
        SELECT
            -- G: viewer role
            (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'roles') ? 'viewer'
            AND NOT (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'roles') ? 'editor'
            AND
            -- G2: editor role
            (claims -> 'f0000000-0000-0000-0000-000000000002' -> 'roles') ? 'editor'
            AND NOT (claims -> 'f0000000-0000-0000-0000-000000000002' -> 'roles') ? 'viewer'
            AND
            -- Both keys present
            claims ? 'f0000000-0000-0000-0000-000000000001'
            AND claims ? 'f0000000-0000-0000-0000-000000000002'
        FROM rbac.user_claims
        WHERE user_id = 'ee000000-0000-0000-0000-000000000001'::uuid
    ),
    'CC-06: multi-group user has independent claims per group — G=viewer, G2=editor, no cross-contamination'
);

-- ── CC-07: deleting group G2 removes G2 key from eve's claims ─────────────────
-- Delete G2. The CASCADE from groups → members → user_claims trigger should
-- clean up G2 from eve's claims. G entry must remain intact.
DELETE FROM rbac.groups WHERE id = 'f0000000-0000-0000-0000-000000000002'::uuid;

SELECT ok(
    (
        SELECT
            NOT (claims ? 'f0000000-0000-0000-0000-000000000002')
            AND (claims ? 'f0000000-0000-0000-0000-000000000001')
            AND (claims -> 'f0000000-0000-0000-0000-000000000001' -> 'roles') ? 'viewer'
        FROM rbac.user_claims
        WHERE user_id = 'ee000000-0000-0000-0000-000000000001'::uuid
    ),
    'CC-07: deleting G2 removes G2 key from eve claims — G entry remains with viewer role'
);

SELECT * FROM finish();
ROLLBACK;
