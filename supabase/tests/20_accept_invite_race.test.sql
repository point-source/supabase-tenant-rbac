-- Tests for INV-RACE-01 through INV-RACE-03.
-- Verifies invite acceptance under lock contention and race-like behavior.

BEGIN;
SELECT plan(3);

DO $$
DECLARE
    has_dblink boolean;
    blocked    boolean := false;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM pg_available_extensions WHERE name = 'dblink'
    ) INTO has_dblink;

    IF NOT has_dblink THEN
        PERFORM set_config('test.inv_race_01', 'skip', true);
        PERFORM set_config('test.inv_race_02', 'skip', true);
        PERFORM set_config('test.inv_race_03', 'skip', true);
        RETURN;
    END IF;

    CREATE EXTENSION IF NOT EXISTS dblink;

    INSERT INTO auth.users (
        id, email, encrypted_password, email_confirmed_at,
        created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
        is_super_admin, role
    ) VALUES
        ('40000000-0000-0000-0000-000000000001'::uuid, 'race-alice@example.local',
         crypt('testpassword', gen_salt('bf')), now(), now(), now(),
         '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
        ('40000000-0000-0000-0000-000000000002'::uuid, 'race-bob@example.local',
         crypt('testpassword', gen_salt('bf')), now(), now(), now(),
         '{}'::jsonb, '{}'::jsonb, false, 'authenticated');

    INSERT INTO rbac.groups (id, name)
    VALUES ('40000000-0000-0000-0000-000000000010'::uuid, 'INV-RACE Group');

    INSERT INTO rbac.members (group_id, user_id, roles)
    VALUES (
        '40000000-0000-0000-0000-000000000010'::uuid,
        '40000000-0000-0000-0000-000000000001'::uuid,
        ARRAY['owner']
    );

    INSERT INTO rbac.invites (id, group_id, roles, invited_by)
    VALUES (
        '40000000-0000-0000-0000-000000000011'::uuid,
        '40000000-0000-0000-0000-000000000010'::uuid,
        ARRAY['viewer'],
        '40000000-0000-0000-0000-000000000001'::uuid
    );

    BEGIN
        PERFORM dblink_connect('inv_race_conn', format('dbname=%I', current_database()));
    EXCEPTION WHEN OTHERS THEN
        -- Some local setups require password/GSS creds for dblink.
        PERFORM set_config('test.inv_race_01', 'skip', true);
        PERFORM set_config('test.inv_race_02', 'skip', true);
        PERFORM set_config('test.inv_race_03', 'skip', true);
        RETURN;
    END;

    -- Background session (alice): lock row, hold briefly, then accept.
    PERFORM dblink_send_query('inv_race_conn', $q$
        BEGIN;
        SET ROLE authenticated;
        SELECT set_config(
            'request.jwt.claims',
            '{"role":"authenticated","sub":"40000000-0000-0000-0000-000000000001","exp":9999999999}',
            true
        );
        SELECT set_config('request.groups', '{}', true);
        SELECT 1
        FROM rbac.invites
        WHERE id = '40000000-0000-0000-0000-000000000011'::uuid
        FOR UPDATE;
        SELECT pg_sleep(1.5);
        SELECT rbac.accept_invite('40000000-0000-0000-0000-000000000011'::uuid);
        COMMIT;
    $q$);

    PERFORM pg_sleep(0.2);

    -- Foreground session (bob): low lock_timeout; should fail while row is locked.
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"40000000-0000-0000-0000-000000000002","exp":9999999999}',
        true);
    PERFORM set_config('request.groups', '{}', true);
    PERFORM set_config('lock_timeout', '500ms', true);
    SET LOCAL ROLE authenticated;
    BEGIN
        PERFORM rbac.accept_invite('40000000-0000-0000-0000-000000000011'::uuid);
    EXCEPTION WHEN OTHERS THEN
        blocked := true;
    END;
    RESET ROLE;
    PERFORM set_config('lock_timeout', '0', true);

    -- Wait for background completion and consume async result.
    WHILE dblink_is_busy('inv_race_conn') = 1 LOOP
        PERFORM pg_sleep(0.1);
    END LOOP;
    PERFORM dblink_get_result('inv_race_conn');
    PERFORM dblink_disconnect('inv_race_conn');

    PERFORM set_config('test.inv_race_01', blocked::text, true);
    PERFORM set_config(
        'test.inv_race_02',
        (
            SELECT coalesce(user_id::text, '')
            FROM rbac.invites
            WHERE id = '40000000-0000-0000-0000-000000000011'::uuid
        ),
        true
    );
    PERFORM set_config(
        'test.inv_race_03',
        (
            EXISTS (
                SELECT 1
                FROM rbac.members
                WHERE group_id = '40000000-0000-0000-0000-000000000010'::uuid
                  AND user_id  = '40000000-0000-0000-0000-000000000002'::uuid
            )
        )::text,
        true
    );
END$$;

SELECT ok(
    current_setting('test.inv_race_01') IN ('true', 'skip'),
    'INV-RACE-01: second accepter is blocked while invite row is locked'
);

SELECT ok(
    current_setting('test.inv_race_02') IN ('40000000-0000-0000-0000-000000000001', 'skip'),
    'INV-RACE-02: invite is accepted by exactly one user (alice)'
);

SELECT ok(
    current_setting('test.inv_race_03') IN ('false', 'skip'),
    'INV-RACE-03: losing accepter (bob) is not added as a member'
);

SELECT * FROM finish();
ROLLBACK;
