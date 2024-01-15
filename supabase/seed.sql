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

INSERT INTO
    public."groups" (id, name, created_at)
VALUES
    (
        'ffc83b57-2960-47dc-bdfb-adc9b894c8d9',
        'RED',
        '2024-01-15 11:33:11.949478-08'
    ),
    (
        '088ee15b-da1e-42a4-8af5-c87ae0891cab',
        'BLUE',
        '2024-01-15 11:33:18.002604-08'
    ),
    (
        '690b6e42-cb50-47fa-9e47-0d3167a7e125',
        'GREEN',
        '2024-01-15 11:33:27.099108-08'
    );

INSERT INTO
    public.group_users (id, group_id, user_id, "role", created_at)
VALUES
    (
        '9a7c9b00-f96c-4135-8a09-fbc36de27b90',
        'ffc83b57-2960-47dc-bdfb-adc9b894c8d9',
        'd55f3b79-9004-4bc4-af5c-7fcc1478345a',
        'admin',
        '2024-01-15 11:34:22.487187-08'
    ),
    (
        'fd3c03cd-85f9-4cb0-93f2-52bdc7e6c4df',
        '088ee15b-da1e-42a4-8af5-c87ae0891cab',
        'd55f3b79-9004-4bc4-af5c-7fcc1478345a',
        'viewer',
        '2024-01-15 11:36:50.966208-08'
    ),
    (
        'a7102f7d-4780-4a49-91b5-35d25f5ae9f2',
        '088ee15b-da1e-42a4-8af5-c87ae0891cab',
        '1a01f608-c233-4ad6-966e-cf47ff33ee4f',
        'admin',
        '2024-01-15 11:37:06.794894-08'
    ),
    (
        '9d9d254c-2a3e-4405-a6a3-3c0a887fbbc9',
        '690b6e42-cb50-47fa-9e47-0d3167a7e125',
        '1a01f608-c233-4ad6-966e-cf47ff33ee4f',
        'viewer',
        '2024-01-15 11:37:19.370607-08'
    );

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