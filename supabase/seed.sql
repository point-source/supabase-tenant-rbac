-- ─────────────────────────────────────────────────────────────────────────────
-- Seed data for local development environment.
-- Sets up: permissions registry, role definitions, 5 test users, 1 group.
-- ─────────────────────────────────────────────────────────────────────────────

-- Test users (password: 'password' for all)
INSERT INTO auth.users (
    instance_id, id, aud, "role", email,
    encrypted_password, email_confirmed_at,
    confirmation_token, recovery_token, email_change_token_new, email_change,
    last_sign_in_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, created_at, updated_at
)
VALUES
    (
        '00000000-0000-0000-0000-000000000000',
        'aaaaaaaa-0000-0000-0000-000000000001',
        'authenticated', 'authenticated',
        'alice@example.local',
        '$2a$10$I5DJXjQ7LfIGuvR2riGVXOzcJP7uk.pFB7ZvloA/TApxBv1TRrxNO',
        now(), '', '', '', '', now(),
        '{"provider": "email", "providers": ["email"]}',
        '{"firstName": "Alice", "lastName": "Owner"}',
        NULL, now(), now()
    ),
    (
        '00000000-0000-0000-0000-000000000000',
        'bbbbbbbb-0000-0000-0000-000000000001',
        'authenticated', 'authenticated',
        'bob@example.local',
        '$2a$10$I5DJXjQ7LfIGuvR2riGVXOzcJP7uk.pFB7ZvloA/TApxBv1TRrxNO',
        now(), '', '', '', '', now(),
        '{"provider": "email", "providers": ["email"]}',
        '{"firstName": "Bob", "lastName": "Admin"}',
        NULL, now(), now()
    ),
    (
        '00000000-0000-0000-0000-000000000000',
        'cccccccc-0000-0000-0000-000000000001',
        'authenticated', 'authenticated',
        'carol@example.local',
        '$2a$10$I5DJXjQ7LfIGuvR2riGVXOzcJP7uk.pFB7ZvloA/TApxBv1TRrxNO',
        now(), '', '', '', '', now(),
        '{"provider": "email", "providers": ["email"]}',
        '{"firstName": "Carol", "lastName": "Editor"}',
        NULL, now(), now()
    ),
    (
        '00000000-0000-0000-0000-000000000000',
        'dddddddd-0000-0000-0000-000000000001',
        'authenticated', 'authenticated',
        'dave@example.local',
        '$2a$10$I5DJXjQ7LfIGuvR2riGVXOzcJP7uk.pFB7ZvloA/TApxBv1TRrxNO',
        now(), '', '', '', '', now(),
        '{"provider": "email", "providers": ["email"]}',
        '{"firstName": "Dave", "lastName": "Viewer"}',
        NULL, now(), now()
    ),
    (
        '00000000-0000-0000-0000-000000000000',
        'eeeeeeee-0000-0000-0000-000000000001',
        'authenticated', 'authenticated',
        'eve@example.local',
        '$2a$10$I5DJXjQ7LfIGuvR2riGVXOzcJP7uk.pFB7ZvloA/TApxBv1TRrxNO',
        now(), '', '', '', '', now(),
        '{"provider": "email", "providers": ["email"]}',
        '{"firstName": "Eve", "lastName": "NonMember"}',
        NULL, now(), now()
    );

-- Permissions registry (canonical; all permissions must be registered here before use)
INSERT INTO rbac.permissions (name, description) VALUES
    ('group.update',   'Update group name and metadata'),
    ('group.delete',   'Delete a group'),
    ('members.manage', 'Add, remove, and update group members'),
    ('data.read',      'Read group data'),
    ('data.write',     'Write and modify group data'),
    ('data.export',    'Export group data (not assigned to any role by default)');

-- Role definitions (owner pre-seeded by extension with grantable_roles=['*'])
-- Update owner with full permissions set
UPDATE rbac.roles
SET permissions = ARRAY[
    'group.update', 'group.delete', 'members.manage',
    'data.read', 'data.write'
]
WHERE name = 'owner';

INSERT INTO rbac.roles (name, description, permissions, grantable_roles) VALUES
    ('admin',
     'Manage members and data (all except group.delete)',
     ARRAY['group.update', 'members.manage', 'data.read', 'data.write'],
     ARRAY['editor', 'viewer']),
    ('editor',
     'Read and write group data',
     ARRAY['data.read', 'data.write'],
     ARRAY['viewer']),
    ('viewer',
     'Read-only access to group data',
     ARRAY['data.read'],
     ARRAY[]::text[]);

-- Test group
INSERT INTO rbac.groups (id, name, metadata, created_at)
VALUES (
    'f1111111-1111-1111-1111-111111111111',
    'Alpha',
    '{}',
    now()
);

-- Memberships: alice=owner, bob=admin, carol=editor, dave=viewer
-- (eve is a non-member — not inserted)
INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('f1111111-1111-1111-1111-111111111111', 'aaaaaaaa-0000-0000-0000-000000000001', ARRAY['owner']),
    ('f1111111-1111-1111-1111-111111111111', 'bbbbbbbb-0000-0000-0000-000000000001', ARRAY['admin']),
    ('f1111111-1111-1111-1111-111111111111', 'cccccccc-0000-0000-0000-000000000001', ARRAY['editor']),
    ('f1111111-1111-1111-1111-111111111111', 'dddddddd-0000-0000-0000-000000000001', ARRAY['viewer']);

-- Test data for the sensitive_data table (for RLS testing)
INSERT INTO public.sensitive_data (id, "data", created_at, owned_by_group)
VALUES (
    '9baf6dc9-fdda-40cb-a708-cf8e59d8927b',
    'group alpha data',
    now(),
    'f1111111-1111-1111-1111-111111111111'
);
