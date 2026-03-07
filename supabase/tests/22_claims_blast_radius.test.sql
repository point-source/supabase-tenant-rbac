-- Tests for BR-01 through BR-04.
-- Verifies role-definition updates rebuild claims for the right users only.

BEGIN;
SELECT plan(4);

INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES
    ('42000000-0000-0000-0000-000000000001'::uuid, 'br-u1@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('42000000-0000-0000-0000-000000000002'::uuid, 'br-u2@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated'),
    ('42000000-0000-0000-0000-000000000003'::uuid, 'br-u3@example.local',
     crypt('testpassword', gen_salt('bf')), now(), now(), now(),
     '{}'::jsonb, '{}'::jsonb, false, 'authenticated');

INSERT INTO rbac.permissions (name, description) VALUES
    ('br.perm.old', 'blast radius old'),
    ('br.perm.new', 'blast radius new')
ON CONFLICT DO NOTHING;

INSERT INTO rbac.roles (name, description, permissions, grantable_roles) VALUES
    ('br_target',  'target role', ARRAY['br.perm.old'], '{}'::text[]),
    ('br_manager', 'indirect holder via grantable scope', '{}'::text[], ARRAY['br_target']),
    ('br_other',   'unrelated role', ARRAY['br.perm.old'], '{}'::text[])
ON CONFLICT DO NOTHING;

INSERT INTO rbac.groups (id, name)
VALUES ('42000000-0000-0000-0000-000000000010'::uuid, 'BR Group');

INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('42000000-0000-0000-0000-000000000010'::uuid, '42000000-0000-0000-0000-000000000001'::uuid, ARRAY['br_target']),
    ('42000000-0000-0000-0000-000000000010'::uuid, '42000000-0000-0000-0000-000000000002'::uuid, ARRAY['br_manager']),
    ('42000000-0000-0000-0000-000000000010'::uuid, '42000000-0000-0000-0000-000000000003'::uuid, ARRAY['br_other']);

SELECT set_config(
    'test.br_before_u1',
    (SELECT claims::text FROM rbac.user_claims WHERE user_id = '42000000-0000-0000-0000-000000000001'::uuid),
    true
);
SELECT set_config(
    'test.br_before_u2',
    (SELECT claims::text FROM rbac.user_claims WHERE user_id = '42000000-0000-0000-0000-000000000002'::uuid),
    true
);
SELECT set_config(
    'test.br_before_u3',
    (SELECT claims::text FROM rbac.user_claims WHERE user_id = '42000000-0000-0000-0000-000000000003'::uuid),
    true
);

SELECT rbac.grant_permission('br_target', 'br.perm.new');

SELECT ok(
    (SELECT claims::text FROM rbac.user_claims WHERE user_id = '42000000-0000-0000-0000-000000000001'::uuid)
    <> current_setting('test.br_before_u1'),
    'BR-01: direct holders of changed role have claims rebuilt'
);

SELECT ok(
    (SELECT claims::text FROM rbac.user_claims WHERE user_id = '42000000-0000-0000-0000-000000000002'::uuid)
    <> current_setting('test.br_before_u2'),
    'BR-02: indirect holders (via grantable_roles reference) have claims rebuilt'
);

SELECT ok(
    (SELECT claims::text FROM rbac.user_claims WHERE user_id = '42000000-0000-0000-0000-000000000003'::uuid)
    = current_setting('test.br_before_u3'),
    'BR-03: unrelated users do not get unnecessary claims rewrites'
);

SELECT ok(
    (SELECT claims -> '42000000-0000-0000-0000-000000000010' -> 'grantable_permissions' ? 'br.perm.new'
     FROM rbac.user_claims
     WHERE user_id = '42000000-0000-0000-0000-000000000002'::uuid),
    'BR-04: indirect holder picks up updated grantable_permissions from role change'
);

SELECT * FROM finish();
ROLLBACK;
