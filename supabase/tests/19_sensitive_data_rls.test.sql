-- End-to-end RLS tests for the sensitive_data table (SD-01 through SD-05).
-- Verifies that rbac.has_permission() correctly gates access to app-level data:
-- users with data.read can SELECT, users with data.write can INSERT/UPDATE,
-- and users without the required permission are denied.
-- Uses the policy-gated sensitive_data table from the local dev migration.

BEGIN;
SELECT plan(5);

-- ─────────────────────────────────────────────────────────────────────────────
-- Setup: alice (viewer = data.read), bob (editor = data.read + data.write),
--        eve (non-member, no permissions), one group G
-- ─────────────────────────────────────────────────────────────────────────────

INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES
    ('5d000000-0000-0000-0000-000000000001'::uuid, 'sd-alice@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('5d000000-0000-0000-0000-000000000002'::uuid, 'sd-bob@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('5d000000-0000-0000-0000-000000000003'::uuid, 'sd-eve@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated');

INSERT INTO rbac.groups (id, name)
VALUES ('5d000000-0000-0000-0000-000000000099'::uuid, 'SD Test Group G');

INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('5d000000-0000-0000-0000-000000000099'::uuid,
     '5d000000-0000-0000-0000-000000000001'::uuid, ARRAY['viewer']),   -- data.read only
    ('5d000000-0000-0000-0000-000000000099'::uuid,
     '5d000000-0000-0000-0000-000000000002'::uuid, ARRAY['editor']);   -- data.read + data.write

-- Seed a sensitive_data row owned by group G
INSERT INTO public.sensitive_data (id, data, owned_by_group)
VALUES ('5d000000-0000-0000-0000-000000000001'::uuid,
        'secret payload', '5d000000-0000-0000-0000-000000000099'::uuid);

-- ── SD-01: alice (viewer, data.read) can SELECT from sensitive_data ───────────
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"5d000000-0000-0000-0000-000000000001","exp":9999999999}',
    true);
SELECT set_config('request.groups',
    (SELECT claims::text FROM rbac.user_claims
     WHERE user_id = '5d000000-0000-0000-0000-000000000001'::uuid),
    true);

SET LOCAL ROLE authenticated;
SELECT is(
    (SELECT count(*)::int FROM public.sensitive_data
     WHERE owned_by_group = '5d000000-0000-0000-0000-000000000099'::uuid),
    1,
    'SD-01: alice (viewer, data.read) can SELECT from sensitive_data'
);
RESET ROLE;

-- ── SD-02: eve (non-member) cannot SELECT from sensitive_data ─────────────────
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"5d000000-0000-0000-0000-000000000003","exp":9999999999}',
    true);
SELECT set_config('request.groups', '{}', true);

SET LOCAL ROLE authenticated;
SELECT is(
    (SELECT count(*)::int FROM public.sensitive_data
     WHERE owned_by_group = '5d000000-0000-0000-0000-000000000099'::uuid),
    0,
    'SD-02: eve (non-member, no data.read) sees 0 rows from sensitive_data'
);
RESET ROLE;

-- ── SD-03: alice (viewer, data.read only) cannot INSERT into sensitive_data ────
-- alice has data.read but not data.write; the "Has data write insert"/update/delete
-- policies block mutations. Expect an RLS error.
DO $$
DECLARE v_raised boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"5d000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM set_config('request.groups',
        (SELECT claims::text FROM rbac.user_claims
         WHERE user_id = '5d000000-0000-0000-0000-000000000001'::uuid),
        true);
    SET LOCAL ROLE authenticated;
    BEGIN
        INSERT INTO public.sensitive_data (data, owned_by_group)
        VALUES ('should fail', '5d000000-0000-0000-0000-000000000099'::uuid);
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
    END;
    RESET ROLE;
    PERFORM set_config('test.sd03_raised', v_raised::text, true);
END$$;

SELECT ok(
    current_setting('test.sd03_raised') = 'true',
    'SD-03: alice (viewer, no data.write) cannot INSERT into sensitive_data — RLS blocks write'
);

-- ── SD-04: bob (editor, data.read + data.write) can INSERT into sensitive_data ─
DO $$
DECLARE v_raised boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"5d000000-0000-0000-0000-000000000002","exp":9999999999}',
        true);
    PERFORM set_config('request.groups',
        (SELECT claims::text FROM rbac.user_claims
         WHERE user_id = '5d000000-0000-0000-0000-000000000002'::uuid),
        true);
    SET LOCAL ROLE authenticated;
    BEGIN
        INSERT INTO public.sensitive_data (data, owned_by_group)
        VALUES ('bob payload', '5d000000-0000-0000-0000-000000000099'::uuid);
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
    END;
    RESET ROLE;
    PERFORM set_config('test.sd04_raised', v_raised::text, true);
END$$;

SELECT ok(
    current_setting('test.sd04_raised') = 'false',
    'SD-04: bob (editor, data.write) can INSERT into sensitive_data'
);

-- ── SD-05: bob (editor, data.read) can SELECT the newly inserted row ──────────
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"5d000000-0000-0000-0000-000000000002","exp":9999999999}',
    true);
SELECT set_config('request.groups',
    (SELECT claims::text FROM rbac.user_claims
     WHERE user_id = '5d000000-0000-0000-0000-000000000002'::uuid),
    true);

SET LOCAL ROLE authenticated;
SELECT ok(
    (SELECT count(*)::int FROM public.sensitive_data
     WHERE owned_by_group = '5d000000-0000-0000-0000-000000000099'::uuid) >= 2,
    'SD-05: bob (editor, data.read) can SELECT all sensitive_data rows for the group'
);
RESET ROLE;

SELECT * FROM finish();
ROLLBACK;
