-- Tests that direct INSERT and UPDATE on rbac.user_claims are blocked for the
-- authenticated role (v5.2.0+: trigger functions are SECURITY DEFINER, so
-- authenticated no longer needs — or has — INSERT/UPDATE on user_claims).

BEGIN;
SELECT plan(4);

-- Setup: insert a test user directly (as postgres)
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    '22222222-0000-0000-0000-000000000001'::uuid,
    'claims-guard@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

-- ── Test 1: authenticated does NOT have INSERT privilege on user_claims ────────
SELECT ok(
    NOT has_table_privilege('authenticated', 'rbac.user_claims', 'INSERT'),
    'authenticated role does not have INSERT privilege on rbac.user_claims'
);

-- ── Test 2: authenticated does NOT have UPDATE privilege on user_claims ────────
SELECT ok(
    NOT has_table_privilege('authenticated', 'rbac.user_claims', 'UPDATE'),
    'authenticated role does not have UPDATE privilege on rbac.user_claims'
);

-- ── Test 3: Direct INSERT into user_claims is blocked for authenticated ────────
DO $$
DECLARE
    v_blocked boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"22222222-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM set_config('request.groups', '{}', true);

    SET LOCAL ROLE authenticated;
    BEGIN
        INSERT INTO rbac.user_claims (user_id, claims)
        VALUES ('22222222-0000-0000-0000-000000000001'::uuid,
                '{"forged-group": {"roles": ["owner"], "permissions": ["everything"]}}'::jsonb);
    EXCEPTION WHEN insufficient_privilege THEN
        v_blocked := true;
    END;
    RESET ROLE;

    PERFORM set_config('test.insert_blocked', v_blocked::text, true);
END$$;

SELECT ok(
    current_setting('test.insert_blocked') = 'true',
    'direct INSERT into rbac.user_claims is blocked for authenticated (insufficient_privilege)'
);

-- ── Test 4: Direct UPDATE into user_claims is blocked for authenticated ───────
-- First, insert a claims row as postgres so UPDATE has something to target.
INSERT INTO rbac.user_claims (user_id, claims)
VALUES ('22222222-0000-0000-0000-000000000001'::uuid, '{}'::jsonb)
ON CONFLICT DO NOTHING;

DO $$
DECLARE
    v_blocked boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"22222222-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM set_config('request.groups', '{}', true);

    SET LOCAL ROLE authenticated;
    BEGIN
        UPDATE rbac.user_claims
        SET claims = '{"forged-group": {"roles": ["owner"], "permissions": ["everything"]}}'::jsonb
        WHERE user_id = '22222222-0000-0000-0000-000000000001'::uuid;
    EXCEPTION WHEN insufficient_privilege THEN
        v_blocked := true;
    END;
    RESET ROLE;

    PERFORM set_config('test.update_blocked', v_blocked::text, true);
END$$;

SELECT ok(
    current_setting('test.update_blocked') = 'true',
    'direct UPDATE on rbac.user_claims is blocked for authenticated (insufficient_privilege)'
);

SELECT * FROM finish();
ROLLBACK;
