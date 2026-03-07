-- Tests for HS-01 through HS-02.
-- Verifies privilege hardening behavior described in examples/policies/hardened_setup.sql.

BEGIN;
SELECT plan(2);

INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES
    ('44000000-0000-0000-0000-000000000001'::uuid, 'hs-alice@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('44000000-0000-0000-0000-000000000002'::uuid, 'hs-bob@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated');

INSERT INTO rbac.groups (id, name)
VALUES ('44000000-0000-0000-0000-000000000010'::uuid, 'HS Group');

INSERT INTO rbac.members (group_id, user_id, roles)
VALUES (
    '44000000-0000-0000-0000-000000000010'::uuid,
    '44000000-0000-0000-0000-000000000001'::uuid,
    ARRAY['owner']
);

DO $$
DECLARE
    blocked boolean := false;
BEGIN
    -- Harden: remove write privileges from authenticated on members table.
    REVOKE INSERT, UPDATE, DELETE ON rbac.members FROM authenticated;

    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"44000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM set_config('request.groups',
        (SELECT claims::text FROM rbac.user_claims
         WHERE user_id = '44000000-0000-0000-0000-000000000001'::uuid),
        true);
    SET LOCAL ROLE authenticated;
    BEGIN
        PERFORM rbac.add_member(
            '44000000-0000-0000-0000-000000000010'::uuid,
            '44000000-0000-0000-0000-000000000002'::uuid,
            ARRAY['viewer']
        );
    EXCEPTION WHEN OTHERS THEN
        blocked := true;
    END;
    RESET ROLE;

    PERFORM set_config('test.hs_blocked', blocked::text, true);

    -- Re-grant targeted privileges as recommended by hardened setup.
    GRANT INSERT, UPDATE, DELETE ON rbac.members TO authenticated;

    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"44000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM set_config('request.groups',
        (SELECT claims::text FROM rbac.user_claims
         WHERE user_id = '44000000-0000-0000-0000-000000000001'::uuid),
        true);
    SET LOCAL ROLE authenticated;
    PERFORM rbac.add_member(
        '44000000-0000-0000-0000-000000000010'::uuid,
        '44000000-0000-0000-0000-000000000002'::uuid,
        ARRAY['viewer']
    );
    RESET ROLE;
END$$;

SELECT ok(
    current_setting('test.hs_blocked') = 'true',
    'HS-01: hardened privilege revokes block add_member() even with valid RLS'
);

SELECT ok(
    EXISTS (
        SELECT 1 FROM rbac.members
        WHERE group_id = '44000000-0000-0000-0000-000000000010'::uuid
          AND user_id  = '44000000-0000-0000-0000-000000000002'::uuid
          AND 'viewer' = ANY(roles)
    ),
    'HS-02: targeted members-table re-grants restore add_member() behavior'
);

SELECT * FROM finish();
ROLLBACK;
