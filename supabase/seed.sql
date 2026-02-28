INSERT INTO
    auth.users (
        instance_id,
        id,
        aud,
        "role",
        email,
        encrypted_password,
        email_confirmed_at,
        confirmation_token,
        recovery_token,
        email_change_token_new,
        email_change,
        last_sign_in_at,
        raw_app_meta_data,
        raw_user_meta_data,
        is_super_admin,
        created_at,
        updated_at
    )
VALUES
    (
        '00000000-0000-0000-0000-000000000000',
        'd55f3b79-9004-4bc4-af5c-7fcc1478345a',
        'authenticated',
        'authenticated',
        'devuser@email.local',
        '$2a$10$I5DJXjQ7LfIGuvR2riGVXOzcJP7uk.pFB7ZvloA/TApxBv1TRrxNO',
        '2023-04-03 16:40:17.367996-07',
        '',
        '',
        '',
        '',
        '2023-04-03 16:40:17.367996-07',
        '{"provider": "email", "providers": ["email"]}',
        '{"lastName": "User", "firstName": "Dev", "phoneNumber": ""}',
        NULL,
        '2023-04-03 16:39:30.424482-07',
        '2023-04-03 16:40:17.36902-07'
    ),
    (
        '00000000-0000-0000-0000-000000000000',
        '1a01f608-c233-4ad6-966e-cf47ff33ee4f',
        'authenticated',
        'authenticated',
        'invited@email.local',
        '$2a$10$I5DJXjQ7LfIGuvR2riGVXOzcJP7uk.pFB7ZvloA/TApxBv1TRrxNO',
        '2023-04-03 16:40:17.367996-07',
        '',
        '',
        '',
        '',
        '2023-04-03 16:40:17.367996-07',
        '{"provider": "email", "providers": ["email"]}',
        '{"lastName": "User", "firstName": "Invited", "phoneNumber": ""}',
        NULL,
        '2023-04-03 16:39:30.424482-07',
        '2023-04-03 16:40:17.36902-07'
    );

-- Add role definitions used in test data
INSERT INTO rbac.roles (name, description) VALUES
    ('group.update',       'Can update group metadata'),
    ('group.delete',       'Can delete the group'),
    ('group_user.create',  'Can add members to the group'),
    ('group_user.read',    'Can view group members'),
    ('group_user.update',  'Can update member roles'),
    ('group_user.delete',  'Can remove group members'),
    ('group_user.invite',  'Can create invites'),
    ('group_data.create',  'Can create group data'),
    ('group_data.read',    'Can read group data'),
    ('group_data.update',  'Can update group data'),
    ('group_data.delete',  'Can delete group data');

INSERT INTO
    rbac.groups (id, name, metadata, created_at)
VALUES
    (
        'ffc83b57-2960-47dc-bdfb-adc9b894c8d9',
        'RED',
        '{}',
        '2024-01-15 11:33:11.949478-08'
    ),
    (
        '088ee15b-da1e-42a4-8af5-c87ae0891cab',
        'BLUE',
        '{}',
        '2024-01-15 11:33:18.002604-08'
    ),
    (
        '690b6e42-cb50-47fa-9e47-0d3167a7e125',
        'GREEN',
        '{}',
        '2024-01-15 11:33:27.099108-08'
    );

-- devuser in RED: full permissions
INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('ffc83b57-2960-47dc-bdfb-adc9b894c8d9', 'd55f3b79-9004-4bc4-af5c-7fcc1478345a',
     ARRAY['group.update','group.delete','group_user.create','group_user.read','group_user.update','group_user.delete','group_user.invite','group_data.create','group_data.read','group_data.update','group_data.delete']);

-- invited user in BLUE: full permissions
INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('088ee15b-da1e-42a4-8af5-c87ae0891cab', '1a01f608-c233-4ad6-966e-cf47ff33ee4f',
     ARRAY['group.update','group.delete','group_user.create','group_user.read','group_user.update','group_user.delete','group_user.invite','group_data.create','group_data.read','group_data.update','group_data.delete']);

-- devuser in BLUE: read-only
INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('088ee15b-da1e-42a4-8af5-c87ae0891cab', 'd55f3b79-9004-4bc4-af5c-7fcc1478345a',
     ARRAY['group_data.read']);

-- invited user in GREEN: read-only
INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('690b6e42-cb50-47fa-9e47-0d3167a7e125', '1a01f608-c233-4ad6-966e-cf47ff33ee4f',
     ARRAY['group_data.read']);

INSERT INTO
    public.sensitive_data (id, "data", created_at, owned_by_group)
VALUES
    (
        '9baf6dc9-fdda-40cb-a708-cf8e59d8927b',
        'only for reds',
        '2024-01-15 11:33:44.611894-08',
        'ffc83b57-2960-47dc-bdfb-adc9b894c8d9'
    ),
    (
        'fb58fe8b-54f4-425b-8f8c-827b14cf3a85',
        'only for blues',
        '2024-01-15 11:33:54.084476-08',
        '088ee15b-da1e-42a4-8af5-c87ae0891cab'
    ),
    (
        '17800d26-e345-4d49-a831-4fa15fb47533',
        'only for greens',
        '2024-01-15 11:34:03.771107-08',
        '690b6e42-cb50-47fa-9e47-0d3167a7e125'
    );
