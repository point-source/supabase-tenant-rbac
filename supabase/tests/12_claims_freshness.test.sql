-- Tests for CF-01 through CF-06: claims cache freshness and db_pre_request().
-- Verifies that db_pre_request() correctly populates request.groups from
-- user_claims, that membership changes are reflected immediately in subsequent
-- requests, and that _get_user_groups() provides a correct Storage RLS fallback.

BEGIN;
SELECT plan(6);

-- Setup: alice (owner in G), eve (viewer in G), groupless user
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    '29000000-0000-0000-0000-000000000001'::uuid,
    'cf-alice@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
), (
    '29000000-0000-0000-0000-000000000003'::uuid,
    'cf-eve@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
), (
    '29000000-0000-0000-0000-000000000004'::uuid,
    'cf-groupless@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

INSERT INTO rbac.groups (id, name)
VALUES ('29000000-0000-0000-0000-000000000002'::uuid, 'CF Test Group');

INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('29000000-0000-0000-0000-000000000002'::uuid,
     '29000000-0000-0000-0000-000000000001'::uuid,
     ARRAY['owner']),
    ('29000000-0000-0000-0000-000000000002'::uuid,
     '29000000-0000-0000-0000-000000000003'::uuid,
     ARRAY['viewer']);

-- ── CF-01: db_pre_request() populates request.groups with alice's claims ───────
-- Call db_pre_request() with alice's JWT context and verify request.groups
-- contains the group key for G.
DO $$
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"29000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM rbac.db_pre_request();
    PERFORM set_config('test.cf01_groups', current_setting('request.groups', true), true);
END$$;

SELECT ok(
    current_setting('test.cf01_groups') LIKE '%29000000-0000-0000-0000-000000000002%',
    'CF-01: db_pre_request() populates request.groups with alice''s group claims'
);

-- ── CF-02: updated roles appear in request.groups after membership change ──────
-- Update eve's roles from viewer to editor.
-- Then call db_pre_request() with eve's JWT — verify roles=['editor'] in claims.
SELECT rbac.update_member_roles(
    '29000000-0000-0000-0000-000000000002'::uuid,
    '29000000-0000-0000-0000-000000000003'::uuid,
    ARRAY['editor']
);

DO $$
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"29000000-0000-0000-0000-000000000003","exp":9999999999}',
        true);
    PERFORM rbac.db_pre_request();
    PERFORM set_config('test.cf02_groups', current_setting('request.groups', true), true);
END$$;

SELECT ok(
    current_setting('test.cf02_groups')::jsonb
        -> '29000000-0000-0000-0000-000000000002'
        -> 'roles'
        ? 'editor',
    'CF-02: db_pre_request() reflects updated roles after update_member_roles()'
);

-- ── CF-03: removed member has empty claims after remove_member() ──────────────
-- Remove eve from G. db_pre_request() should now set request.groups = '{}'.
SELECT rbac.remove_member(
    '29000000-0000-0000-0000-000000000002'::uuid,
    '29000000-0000-0000-0000-000000000003'::uuid
);

DO $$
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"29000000-0000-0000-0000-000000000003","exp":9999999999}',
        true);
    PERFORM rbac.db_pre_request();
    PERFORM set_config('test.cf03_groups', current_setting('request.groups', true), true);
END$$;

SELECT ok(
    current_setting('test.cf03_groups') = '{}',
    'CF-03: db_pre_request() returns empty claims after member is removed from all groups'
);

-- ── CF-04: groupless user produces empty request.groups ───────────────────────
DO $$
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"29000000-0000-0000-0000-000000000004","exp":9999999999}',
        true);
    PERFORM rbac.db_pre_request();
    PERFORM set_config('test.cf04_groups', current_setting('request.groups', true), true);
END$$;

SELECT ok(
    current_setting('test.cf04_groups') = '{}',
    'CF-04: db_pre_request() returns empty claims for a user with no group memberships'
);

-- ── CF-05: _get_user_groups() returns correct claims when request.groups empty ─
-- Set alice's JWT, clear request.groups, then call get_claims() which falls back
-- to _get_user_groups() for the Storage RLS path. Verify alice's group is present.
DO $$
DECLARE
    v_claims jsonb;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"29000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    -- Clear request.groups to force fallback to _get_user_groups()
    PERFORM set_config('request.groups', '', true);

    SET LOCAL ROLE authenticated;
    SELECT rbac.get_claims() INTO v_claims;
    RESET ROLE;

    PERFORM set_config('test.cf05_has_group',
        (v_claims ? '29000000-0000-0000-0000-000000000002')::text,
        true);
END$$;

SELECT ok(
    current_setting('test.cf05_has_group') = 'true',
    'CF-05: get_claims() falls back to _get_user_groups() when request.groups is empty'
);

-- ── CF-06: has_role() works via Storage fallback path ─────────────────────────
-- Same scenario: clear request.groups so get_claims() must read user_claims directly.
-- Alice is owner of G — has_role should return true.
DO $$
DECLARE
    v_result boolean;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"29000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM set_config('request.groups', '', true);

    SET LOCAL ROLE authenticated;
    SELECT rbac.has_role(
        '29000000-0000-0000-0000-000000000002'::uuid,
        'owner'
    ) INTO v_result;
    RESET ROLE;

    PERFORM set_config('test.cf06_has_role', v_result::text, true);
END$$;

SELECT ok(
    current_setting('test.cf06_has_role') = 'true',
    'CF-06: has_role() returns true via Storage fallback when request.groups is empty'
);

SELECT * FROM finish();
ROLLBACK;
