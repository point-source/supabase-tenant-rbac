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
    public."groups" (id, metadata, created_at)
VALUES
    (
        'ffc83b57-2960-47dc-bdfb-adc9b894c8d9',
        '{"name": "RED"}',
        '2024-01-15 11:33:11.949478-08'
    ),
    (
        '088ee15b-da1e-42a4-8af5-c87ae0891cab',
        '{"name": "BLUE"}',
        '2024-01-15 11:33:18.002604-08'
    ),
    (
        '690b6e42-cb50-47fa-9e47-0d3167a7e125',
        '{"name": "GREEN"}',
        '2024-01-15 11:33:27.099108-08'
    );

INSERT INTO public.group_users (id,group_id,user_id,"role") VALUES
	 ('52a65b1e-a999-4e3b-b283-ffc2cedac280','ffc83b57-2960-47dc-bdfb-adc9b894c8d9','d55f3b79-9004-4bc4-af5c-7fcc1478345a','group.update'),
	 ('891560c1-8724-45ce-9ad2-cab9c430e0d5','ffc83b57-2960-47dc-bdfb-adc9b894c8d9','d55f3b79-9004-4bc4-af5c-7fcc1478345a','group.delete'),
	 ('8d364c18-d74f-48e5-9697-d14bcc5c9c59','ffc83b57-2960-47dc-bdfb-adc9b894c8d9','d55f3b79-9004-4bc4-af5c-7fcc1478345a','group_user.create'),
	 ('a706772b-efa8-4ea4-ac59-50225dbc2dbf','ffc83b57-2960-47dc-bdfb-adc9b894c8d9','d55f3b79-9004-4bc4-af5c-7fcc1478345a','group_user.read'),
	 ('faee57f0-466b-451f-9426-1c791fdcad45','ffc83b57-2960-47dc-bdfb-adc9b894c8d9','d55f3b79-9004-4bc4-af5c-7fcc1478345a','group_user.update'),
	 ('d99a293d-5a99-40e8-8749-c56c5d1d1b9d','ffc83b57-2960-47dc-bdfb-adc9b894c8d9','d55f3b79-9004-4bc4-af5c-7fcc1478345a','group_user.delete'),
	 ('4cf094ac-c5ba-4c10-98f5-755778416822','ffc83b57-2960-47dc-bdfb-adc9b894c8d9','d55f3b79-9004-4bc4-af5c-7fcc1478345a','group_invite.create'),
	 ('b37ff4d9-3fd6-491e-9eb9-856cebcfaaf4','088ee15b-da1e-42a4-8af5-c87ae0891cab','1a01f608-c233-4ad6-966e-cf47ff33ee4f','group.update'),
	 ('0bc61929-edfc-4734-9a53-54500db7ee64','088ee15b-da1e-42a4-8af5-c87ae0891cab','1a01f608-c233-4ad6-966e-cf47ff33ee4f','group.delete'),
	 ('896539c5-c9d7-4f17-8727-ed070eb13f0b','088ee15b-da1e-42a4-8af5-c87ae0891cab','1a01f608-c233-4ad6-966e-cf47ff33ee4f','group_user.create');
INSERT INTO public.group_users (id,group_id,user_id,"role") VALUES
	 ('11e98239-a7cd-4a48-b4cc-48f56be14f67','088ee15b-da1e-42a4-8af5-c87ae0891cab','1a01f608-c233-4ad6-966e-cf47ff33ee4f','group_user.read'),
	 ('51bb1729-e151-48cc-9ec2-6ed1e52ae3a6','088ee15b-da1e-42a4-8af5-c87ae0891cab','1a01f608-c233-4ad6-966e-cf47ff33ee4f','group_user.update'),
	 ('34420433-c8f7-46b0-8515-ac973ad2d633','088ee15b-da1e-42a4-8af5-c87ae0891cab','1a01f608-c233-4ad6-966e-cf47ff33ee4f','group_user.delete'),
	 ('97b49026-68f3-40e0-9fbd-b119504b5251','088ee15b-da1e-42a4-8af5-c87ae0891cab','1a01f608-c233-4ad6-966e-cf47ff33ee4f','group_invite.create'),
	 ('e15071e4-c8b3-48d9-94dc-e6a44b7851a4','088ee15b-da1e-42a4-8af5-c87ae0891cab','1a01f608-c233-4ad6-966e-cf47ff33ee4f','group_data.create'),
	 ('146dacd1-f403-4d6c-a739-d52579f7848c','088ee15b-da1e-42a4-8af5-c87ae0891cab','1a01f608-c233-4ad6-966e-cf47ff33ee4f','group_data.read'),
	 ('12968726-0bee-4b90-a17e-6453cefbe0bd','088ee15b-da1e-42a4-8af5-c87ae0891cab','1a01f608-c233-4ad6-966e-cf47ff33ee4f','group_data.update'),
	 ('ae6e0e6c-f5df-41dd-ac51-73addf1007aa','088ee15b-da1e-42a4-8af5-c87ae0891cab','1a01f608-c233-4ad6-966e-cf47ff33ee4f','group_data.delete'),
	 ('63fbbaf6-2dd1-413d-8bb7-d438c1899c14','ffc83b57-2960-47dc-bdfb-adc9b894c8d9','d55f3b79-9004-4bc4-af5c-7fcc1478345a','group_data.create'),
	 ('3961c179-eccf-4dbb-8bca-e5ad7864b8cc','ffc83b57-2960-47dc-bdfb-adc9b894c8d9','d55f3b79-9004-4bc4-af5c-7fcc1478345a','group_data.read');
INSERT INTO public.group_users (id,group_id,user_id,"role") VALUES
	 ('0363dc36-c48e-4c14-a424-ff44378491b9','ffc83b57-2960-47dc-bdfb-adc9b894c8d9','d55f3b79-9004-4bc4-af5c-7fcc1478345a','group_data.update'),
	 ('59571d02-e69c-4555-8a54-1967dee40f2d','ffc83b57-2960-47dc-bdfb-adc9b894c8d9','d55f3b79-9004-4bc4-af5c-7fcc1478345a','group_data.delete'),
	 ('b0ea2567-40ab-4ce0-bca1-9d24e27dbce6','088ee15b-da1e-42a4-8af5-c87ae0891cab','d55f3b79-9004-4bc4-af5c-7fcc1478345a','group_data.read'),
	 ('78397550-d600-40c9-9b54-7e7c85f73bed','690b6e42-cb50-47fa-9e47-0d3167a7e125','1a01f608-c233-4ad6-966e-cf47ff33ee4f','group_data.read');


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