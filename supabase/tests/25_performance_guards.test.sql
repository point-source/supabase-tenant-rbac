-- Tests for PERF-01 through PERF-03.
-- Planner guardrails: ensure key lookups can use intended indexes.

BEGIN;
SELECT plan(3);

INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    '45000000-0000-0000-0000-000000000001'::uuid,
    'perf-user@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

INSERT INTO rbac.groups (id, name)
VALUES ('45000000-0000-0000-0000-000000000010'::uuid, 'PERF Group');

INSERT INTO rbac.members (group_id, user_id, roles)
SELECT
    '45000000-0000-0000-0000-000000000010'::uuid,
    '45000000-0000-0000-0000-000000000001'::uuid,
    CASE
        WHEN i = 1 THEN ARRAY['perf_role']
        ELSE ARRAY['viewer']
    END
FROM generate_series(1, 1) s(i)
ON CONFLICT (group_id, user_id)
DO UPDATE SET roles = EXCLUDED.roles;

INSERT INTO rbac.member_permissions (group_id, user_id, permission)
VALUES (
    '45000000-0000-0000-0000-000000000010'::uuid,
    '45000000-0000-0000-0000-000000000001'::uuid,
    'perf.permission'
)
ON CONFLICT DO NOTHING;

SET LOCAL enable_seqscan = off;

DO $$
DECLARE
    line  text;
    plan1 text := '';
    plan2 text := '';
    plan3 text := '';
BEGIN
    FOR line IN EXECUTE $q$
        EXPLAIN (FORMAT TEXT)
        SELECT 1
        FROM rbac.members
        WHERE roles @> ARRAY['perf_role']::text[]
    $q$ LOOP
        plan1 := plan1 || line || E'\n';
    END LOOP;

    FOR line IN EXECUTE $q$
        EXPLAIN (FORMAT TEXT)
        SELECT 1
        FROM rbac.members
        WHERE group_id = '45000000-0000-0000-0000-000000000010'::uuid
          AND user_id  = '45000000-0000-0000-0000-000000000001'::uuid
    $q$ LOOP
        plan2 := plan2 || line || E'\n';
    END LOOP;

    FOR line IN EXECUTE $q$
        EXPLAIN (FORMAT TEXT)
        SELECT 1
        FROM rbac.member_permissions
        WHERE group_id   = '45000000-0000-0000-0000-000000000010'::uuid
          AND user_id    = '45000000-0000-0000-0000-000000000001'::uuid
          AND permission = 'perf.permission'
    $q$ LOOP
        plan3 := plan3 || line || E'\n';
    END LOOP;

    PERFORM set_config('test.perf_01', (plan1 LIKE '%members_roles_gin_idx%')::text, true);
    PERFORM set_config(
        'test.perf_02',
        ((plan2 LIKE '%members_group_user_idx%') OR (plan2 LIKE '%members_group_user_uq%'))::text,
        true
    );
    PERFORM set_config('test.perf_03', (plan3 LIKE '%member_permissions_group_user_perm_idx%')::text, true);
END$$;

SELECT ok(
    current_setting('test.perf_01') = 'true',
    'PERF-01: array containment lookup can use members_roles_gin_idx'
);

SELECT ok(
    current_setting('test.perf_02') = 'true',
    'PERF-02: member point lookup can use members_group_user_idx'
);

SELECT ok(
    current_setting('test.perf_03') = 'true',
    'PERF-03: permission override point lookup can use member_permissions_group_user_perm_idx'
);

SELECT * FROM finish();
ROLLBACK;
