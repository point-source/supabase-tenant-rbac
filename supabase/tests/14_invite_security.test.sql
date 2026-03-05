-- Tests for INV-01 through INV-07: invite security and acceptance rules.
-- Verifies expired invite rejection, double-acceptance prevention, null-expiry
-- acceptance, atomic membership creation, user_id binding, and orphaned-role
-- rejection when a role is deleted after the invite is created.

BEGIN;
SELECT plan(7);

-- Setup: alice (owner in G), eve (non-member), carol (non-member)
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    '31000000-0000-0000-0000-000000000001'::uuid,
    'inv-alice@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
), (
    '31000000-0000-0000-0000-000000000003'::uuid,
    'inv-eve@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
), (
    '31000000-0000-0000-0000-000000000004'::uuid,
    'inv-carol@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(), '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

INSERT INTO rbac.groups (id, name)
VALUES ('31000000-0000-0000-0000-000000000002'::uuid, 'INV Security Test Group');

INSERT INTO rbac.members (group_id, user_id, roles) VALUES
    ('31000000-0000-0000-0000-000000000002'::uuid,
     '31000000-0000-0000-0000-000000000001'::uuid,
     ARRAY['owner']);

-- ── INV-01: accept_invite() rejects an expired invite ─────────────────────────
INSERT INTO rbac.invites (id, group_id, roles, invited_by, expires_at)
VALUES (
    '31000001-0000-0000-0000-000000000001'::uuid,
    '31000000-0000-0000-0000-000000000002'::uuid,
    ARRAY['viewer'],
    '31000000-0000-0000-0000-000000000001'::uuid,
    now() - interval '1 hour'  -- already expired
);

DO $$
DECLARE v_raised boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"31000000-0000-0000-0000-000000000003","exp":9999999999}',
        true);
    BEGIN
        PERFORM rbac.accept_invite('31000001-0000-0000-0000-000000000001'::uuid);
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
    END;
    PERFORM set_config('test.inv01_raised', v_raised::text, true);
END$$;

SELECT ok(
    current_setting('test.inv01_raised') = 'true',
    'INV-01: accept_invite() rejects an expired invite'
);

-- ── INV-02: double-acceptance is rejected ─────────────────────────────────────
-- Create a valid invite and accept it once. The second acceptance must fail.
INSERT INTO rbac.invites (id, group_id, roles, invited_by, expires_at)
VALUES (
    '31000002-0000-0000-0000-000000000001'::uuid,
    '31000000-0000-0000-0000-000000000002'::uuid,
    ARRAY['viewer'],
    '31000000-0000-0000-0000-000000000001'::uuid,
    NULL  -- no expiry
);

-- First acceptance (must succeed)
DO $$
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"31000000-0000-0000-0000-000000000003","exp":9999999999}',
        true);
    PERFORM rbac.accept_invite('31000002-0000-0000-0000-000000000001'::uuid);
END$$;

-- Second acceptance by same user (must fail — invite already consumed)
DO $$
DECLARE v_raised boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"31000000-0000-0000-0000-000000000003","exp":9999999999}',
        true);
    BEGIN
        PERFORM rbac.accept_invite('31000002-0000-0000-0000-000000000001'::uuid);
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
    END;
    PERFORM set_config('test.inv02_raised', v_raised::text, true);
END$$;

SELECT ok(
    current_setting('test.inv02_raised') = 'true',
    'INV-02: accept_invite() rejects a second attempt on an already-accepted invite'
);

-- ── INV-03: invite with NULL expires_at is accepted ───────────────────────────
-- carol accepts a fresh invite with no expiry — should succeed.
INSERT INTO rbac.invites (id, group_id, roles, invited_by, expires_at)
VALUES (
    '31000003-0000-0000-0000-000000000001'::uuid,
    '31000000-0000-0000-0000-000000000002'::uuid,
    ARRAY['viewer'],
    '31000000-0000-0000-0000-000000000001'::uuid,
    NULL
);

DO $$
DECLARE v_succeeded boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"31000000-0000-0000-0000-000000000004","exp":9999999999}',
        true);
    BEGIN
        PERFORM rbac.accept_invite('31000003-0000-0000-0000-000000000001'::uuid);
        v_succeeded := true;
    EXCEPTION WHEN OTHERS THEN
        v_succeeded := false;
    END;
    PERFORM set_config('test.inv03_succeeded', v_succeeded::text, true);
END$$;

SELECT ok(
    current_setting('test.inv03_succeeded') = 'true',
    'INV-03: accept_invite() succeeds for an invite with NULL expires_at'
);

-- ── INV-04: acceptance creates membership and marks invite accepted atomically ─
-- eve already accepted inv02 with roles=['viewer']. Verify both conditions hold.
SELECT ok(
    EXISTS (
        SELECT 1 FROM rbac.members
        WHERE group_id = '31000000-0000-0000-0000-000000000002'::uuid
          AND user_id  = '31000000-0000-0000-0000-000000000003'::uuid
          AND 'viewer' = ANY(roles)
    )
    AND
    (SELECT accepted_at IS NOT NULL
     FROM rbac.invites
     WHERE id = '31000002-0000-0000-0000-000000000001'::uuid),
    'INV-04: accept_invite() atomically creates membership and marks invite accepted'
);

-- ── INV-05: concurrent acceptance — carol tries to accept an invite already ────
--            taken by eve
-- Create a new invite and have eve accept it first, then carol tries the same invite.
INSERT INTO rbac.invites (id, group_id, roles, invited_by, expires_at)
VALUES (
    '31000005-0000-0000-0000-000000000001'::uuid,
    '31000000-0000-0000-0000-000000000002'::uuid,
    ARRAY['viewer'],
    '31000000-0000-0000-0000-000000000001'::uuid,
    NULL
);

-- Remove eve from group first so the acceptance is clean (she was added above)
DELETE FROM rbac.members
WHERE group_id = '31000000-0000-0000-0000-000000000002'::uuid
  AND user_id  = '31000000-0000-0000-0000-000000000003'::uuid;

DO $$
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"31000000-0000-0000-0000-000000000003","exp":9999999999}',
        true);
    PERFORM rbac.accept_invite('31000005-0000-0000-0000-000000000001'::uuid);
END$$;

-- Carol attempts the same invite — must fail (already accepted)
DO $$
DECLARE v_raised boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"31000000-0000-0000-0000-000000000004","exp":9999999999}',
        true);
    BEGIN
        PERFORM rbac.accept_invite('31000005-0000-0000-0000-000000000001'::uuid);
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
    END;
    PERFORM set_config('test.inv05_raised', v_raised::text, true);
END$$;

SELECT ok(
    current_setting('test.inv05_raised') = 'true',
    'INV-05: accept_invite() rejects a second user attempting the same invite'
);

-- ── INV-06: acceptance creates membership under the acceptor's user_id ─────────
-- carol accepted inv03. Verify the member row belongs to carol's UUID, not another.
SELECT ok(
    (SELECT user_id = '31000000-0000-0000-0000-000000000004'::uuid
     FROM rbac.members
     WHERE group_id = '31000000-0000-0000-0000-000000000002'::uuid
       AND user_id  = '31000000-0000-0000-0000-000000000004'::uuid),
    'INV-06: membership created on accept_invite() is bound to the acceptor''s user_id'
);

-- ── INV-07: acceptance fails when the invite's roles were deleted ──────────────
-- Create a temporary role, issue an invite with that role, delete the role,
-- then attempt acceptance — _validate_roles() inside accept_invite() should raise.
INSERT INTO rbac.roles (name, description)
VALUES ('inv-temp-role', 'Temporary role for INV-07 test')
ON CONFLICT DO NOTHING;

INSERT INTO rbac.invites (id, group_id, roles, invited_by, expires_at)
VALUES (
    '31000007-0000-0000-0000-000000000001'::uuid,
    '31000000-0000-0000-0000-000000000002'::uuid,
    ARRAY['inv-temp-role'],
    '31000000-0000-0000-0000-000000000001'::uuid,
    NULL
);

-- Delete the role (no members hold it yet, so delete_role() won't refuse)
SELECT rbac.delete_role('inv-temp-role');

-- Now carol tries to accept — should raise because inv-temp-role no longer exists
DO $$
DECLARE v_raised boolean := false;
BEGIN
    PERFORM set_config('request.jwt.claims',
        '{"role":"authenticated","sub":"31000000-0000-0000-0000-000000000004","exp":9999999999}',
        true);
    BEGIN
        PERFORM rbac.accept_invite('31000007-0000-0000-0000-000000000001'::uuid);
    EXCEPTION WHEN OTHERS THEN
        v_raised := true;
    END;
    PERFORM set_config('test.inv07_raised', v_raised::text, true);
END$$;

SELECT ok(
    current_setting('test.inv07_raised') = 'true',
    'INV-07: accept_invite() raises when the invite''s roles no longer exist'
);

SELECT * FROM finish();
ROLLBACK;
