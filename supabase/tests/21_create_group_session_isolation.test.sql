-- Tests for CG-SI-01 through CG-SI-03.
-- Verifies create_group creator-role behavior and non-leaky defaults.

BEGIN;
SELECT plan(3);

INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    '41000000-0000-0000-0000-000000000001'::uuid,
    'cgsi-alice@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

CREATE POLICY "CG-SI allow group inserts"
    ON rbac.groups FOR INSERT TO authenticated WITH CHECK (true);

DO $$
DECLARE
    g_custom uuid;
    g_default uuid;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"41000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM set_config('request.groups', '{}', true);
    SET LOCAL ROLE authenticated;

    g_custom := rbac.create_group('CG-SI custom', '{}'::jsonb, ARRAY['viewer']);
    g_default := rbac.create_group('CG-SI default');

    -- Simulate "unset": empty value causes _on_group_created fallback to owner.
    PERFORM set_config('rbac.creator_roles', '', true);
    INSERT INTO rbac.groups (id, name)
    VALUES ('41000000-0000-0000-0000-000000000010'::uuid, 'CG-SI direct insert');

    RESET ROLE;

    PERFORM set_config('test.cgsi_g_custom', g_custom::text, true);
    PERFORM set_config('test.cgsi_g_default', g_default::text, true);
END$$;

SELECT ok(
    EXISTS (
        SELECT 1
        FROM rbac.members
        WHERE group_id = current_setting('test.cgsi_g_custom')::uuid
          AND user_id  = '41000000-0000-0000-0000-000000000001'::uuid
          AND roles    = ARRAY['viewer']::text[]
    ),
    'CG-SI-01: create_group(custom_roles) applies the specified creator roles'
);

SELECT ok(
    EXISTS (
        SELECT 1
        FROM rbac.members
        WHERE group_id = current_setting('test.cgsi_g_default')::uuid
          AND user_id  = '41000000-0000-0000-0000-000000000001'::uuid
          AND roles    = ARRAY['owner']::text[]
    ),
    'CG-SI-02: create_group(default) still assigns owner after prior custom call'
);

SELECT ok(
    EXISTS (
        SELECT 1
        FROM rbac.members
        WHERE group_id = '41000000-0000-0000-0000-000000000010'::uuid
          AND user_id  = '41000000-0000-0000-0000-000000000001'::uuid
          AND roles    = ARRAY['owner']::text[]
    ),
    'CG-SI-03: _on_group_created falls back to owner when creator_roles setting is unset/invalid'
);

SELECT * FROM finish();
ROLLBACK;
