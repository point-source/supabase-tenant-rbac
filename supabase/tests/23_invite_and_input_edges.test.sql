-- Tests for IE-01 through IE-05.
-- Verifies invite role normalization and management RPC input edge handling.

BEGIN;
SELECT plan(5);

INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES
    ('43000000-0000-0000-0000-000000000001'::uuid, 'ie-alice@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('43000000-0000-0000-0000-000000000002'::uuid, 'ie-bob@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated');

INSERT INTO rbac.groups (id, name)
VALUES ('43000000-0000-0000-0000-000000000010'::uuid, 'IE Group');

INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('43000000-0000-0000-0000-000000000010'::uuid, '43000000-0000-0000-0000-000000000001'::uuid, ARRAY['owner']),
    ('43000000-0000-0000-0000-000000000010'::uuid, '43000000-0000-0000-0000-000000000002'::uuid, ARRAY['viewer']);

DO $$
DECLARE
    inv_id      uuid;
    empty_block boolean := false;
    ws_block    boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"43000000-0000-0000-0000-000000000001","exp":9999999999}',
        true);
    PERFORM set_config('request.groups',
        (SELECT claims::text FROM rbac.user_claims
         WHERE user_id = '43000000-0000-0000-0000-000000000001'::uuid),
        true);
    SET LOCAL ROLE authenticated;

    inv_id := rbac.create_invite(
        '43000000-0000-0000-0000-000000000010'::uuid,
        ARRAY['viewer', 'editor', 'viewer']
    );

    -- NULL p_roles now canonicalizes to empty array.
    PERFORM rbac.update_member_roles(
        '43000000-0000-0000-0000-000000000010'::uuid,
        '43000000-0000-0000-0000-000000000002'::uuid,
        NULL
    );

    BEGIN
        PERFORM rbac.create_invite(
            '43000000-0000-0000-0000-000000000010'::uuid,
            '{}'::text[]
        );
    EXCEPTION WHEN OTHERS THEN
        empty_block := true;
    END;

    BEGIN
        PERFORM rbac.create_invite(
            '43000000-0000-0000-0000-000000000010'::uuid,
            ARRAY[' viewer ']
        );
    EXCEPTION WHEN OTHERS THEN
        ws_block := true;
    END;

    RESET ROLE;

    PERFORM set_config('test.ie_inv_id', inv_id::text, true);
    PERFORM set_config('test.ie_empty_block', empty_block::text, true);
    PERFORM set_config('test.ie_ws_block', ws_block::text, true);
END$$;

SELECT is(
    (SELECT roles FROM rbac.invites WHERE id = current_setting('test.ie_inv_id')::uuid),
    ARRAY['editor', 'viewer']::text[],
    'IE-01: create_invite() stores deduplicated, sorted roles'
);

SELECT is(
    (SELECT roles
     FROM rbac.members
     WHERE group_id = '43000000-0000-0000-0000-000000000010'::uuid
       AND user_id  = '43000000-0000-0000-0000-000000000002'::uuid),
    '{}'::text[],
    'IE-02: update_member_roles(NULL) canonicalizes to an empty roles array'
);

SELECT ok(
    current_setting('test.ie_empty_block') = 'true',
    'IE-03: create_invite() rejects empty role arrays'
);

SELECT ok(
    current_setting('test.ie_ws_block') = 'true',
    'IE-04: create_invite() rejects undefined/whitespace role names'
);

SELECT ok(
    EXISTS (
        SELECT 1
        FROM rbac.invites
        WHERE id = current_setting('test.ie_inv_id')::uuid
          AND accepted_at IS NULL
    ),
    'IE-05: normalized invite remains pending and usable'
);

SELECT * FROM finish();
ROLLBACK;
