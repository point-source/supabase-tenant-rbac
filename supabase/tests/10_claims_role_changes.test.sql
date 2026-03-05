-- Tests for CC-08 through CC-10: claims cache rebuild when role permissions change.
-- Verifies that revoke_permission() and grant_permission() on a role cause all
-- members holding that role to have their claims updated immediately via trigger.

BEGIN;
SELECT plan(3);

-- Setup: two test users and one group
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    '27000000-0000-0000-0000-000000000001'::uuid,
    'cc08-user1@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
), (
    '27000000-0000-0000-0000-000000000003'::uuid,
    'cc08-user2@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

INSERT INTO rbac.groups (id, name)
VALUES ('27000000-0000-0000-0000-000000000002'::uuid, 'CC-08 Test Group');

-- Create isolated test roles so modifications do not disturb shared seed data.
-- These will be rolled back at the end of the transaction.
INSERT INTO rbac.roles (name, description, permissions)
VALUES
    ('cc08-editor', 'Test editor role', ARRAY['data.read', 'data.write']),
    ('cc08-viewer', 'Test viewer role', ARRAY['data.read'])
ON CONFLICT DO NOTHING;

-- user1 holds cc08-editor; user2 holds cc08-editor as well (for CC-09 analogue)
INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('27000000-0000-0000-0000-000000000002'::uuid,
     '27000000-0000-0000-0000-000000000001'::uuid,
     ARRAY['cc08-editor']),
    ('27000000-0000-0000-0000-000000000002'::uuid,
     '27000000-0000-0000-0000-000000000003'::uuid,
     ARRAY['cc08-viewer']);

-- ── CC-08: revoke_permission removes the permission from a role holder's claims ─
-- user1 has cc08-editor, which includes data.write. Revoke data.write from the role.
-- The on_role_permissions_change trigger rebuilds user1's claims automatically.
SELECT rbac.revoke_permission('cc08-editor', 'data.write');

SELECT ok(
    NOT (
        SELECT claims
             -> '27000000-0000-0000-0000-000000000002'
             -> 'permissions'
             ? 'data.write'
        FROM rbac.user_claims
        WHERE user_id = '27000000-0000-0000-0000-000000000001'::uuid
    ),
    'CC-08: revoking permission from role removes it from all holders'' claims'
);

-- ── CC-09: revoke_permission removes the permission from a second role holder ──
-- user2 holds cc08-viewer (data.read only). Revoke data.read from cc08-viewer.
-- Verify that data.read is no longer in user2's claims.
SELECT rbac.revoke_permission('cc08-viewer', 'data.read');

SELECT ok(
    NOT (
        SELECT claims
             -> '27000000-0000-0000-0000-000000000002'
             -> 'permissions'
             ? 'data.read'
        FROM rbac.user_claims
        WHERE user_id = '27000000-0000-0000-0000-000000000003'::uuid
    ),
    'CC-09: revoking permission from second role removes it from that role''s members'' claims'
);

-- ── CC-10: grant_permission adds the new permission to a role holder's claims ──
-- user2 now holds cc08-viewer with no permissions (revoked in CC-09).
-- Grant data.export to cc08-viewer — trigger should rebuild user2's claims.
SELECT rbac.grant_permission('cc08-viewer', 'data.export');

SELECT ok(
    (SELECT claims
          -> '27000000-0000-0000-0000-000000000002'
          -> 'permissions'
          ? 'data.export'
     FROM rbac.user_claims
     WHERE user_id = '27000000-0000-0000-0000-000000000003'::uuid),
    'CC-10: granting permission to role adds it to all holders'' claims immediately'
);

SELECT * FROM finish();
ROLLBACK;
