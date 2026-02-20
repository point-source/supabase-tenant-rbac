-- Tests for invite expiration (v4.2.0 feature).
-- Verifies that the expires_at column exists, and that the accept-invite
-- UPDATE query (as executed by the edge function) correctly rejects expired
-- invites while accepting valid ones.
--
-- Because data-modifying CTEs cannot be used in subexpressions, the three
-- UPDATEs are run as top-level statements between the schema tests and the
-- state-verification tests.

BEGIN;
SELECT plan(7);

-- Setup: inviter user
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    'eeeeeeee-0000-0000-0000-000000000001'::uuid,
    'inviter@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

-- Setup: accepter user (simulates the user accepting the invite)
INSERT INTO auth.users (
    id, email, encrypted_password, email_confirmed_at,
    created_at, updated_at, raw_app_meta_data, raw_user_meta_data,
    is_super_admin, role
) VALUES (
    'eeeeeeee-0000-0000-0000-000000000002'::uuid,
    'accepter@example.local',
    crypt('testpassword', gen_salt('bf')),
    now(), now(), now(),
    '{}'::jsonb, '{}'::jsonb,
    false, 'authenticated'
);

-- Setup: test group
INSERT INTO public.groups (id, metadata)
VALUES ('eeeeeeee-0000-0000-0000-000000000003'::uuid, '{"name":"Expiry Test Group"}');

-- Setup: three invites with different expiry states
INSERT INTO public.group_invites (id, group_id, roles, invited_by, expires_at) VALUES
    -- null expiry: should always be accepted
    ('eeeeeeee-0000-0000-0000-000000000004'::uuid,
     'eeeeeeee-0000-0000-0000-000000000003'::uuid,
     ARRAY['viewer'],
     'eeeeeeee-0000-0000-0000-000000000001'::uuid,
     NULL),
    -- future expiry: should be accepted
    ('eeeeeeee-0000-0000-0000-000000000005'::uuid,
     'eeeeeeee-0000-0000-0000-000000000003'::uuid,
     ARRAY['viewer'],
     'eeeeeeee-0000-0000-0000-000000000001'::uuid,
     now() + interval '1 hour'),
    -- past expiry: should be rejected
    ('eeeeeeee-0000-0000-0000-000000000006'::uuid,
     'eeeeeeee-0000-0000-0000-000000000003'::uuid,
     ARRAY['viewer'],
     'eeeeeeee-0000-0000-0000-000000000001'::uuid,
     now() - interval '1 hour');

-- Test 1: expires_at column exists on group_invites
SELECT has_column(
    'group_invites',
    'expires_at',
    'group_invites has an expires_at column'
);

-- Test 2: expires_at accepts NULL (null means the invite never expires)
SELECT ok(
    (SELECT expires_at IS NULL
     FROM public.group_invites
     WHERE id = 'eeeeeeee-0000-0000-0000-000000000004'::uuid),
    'expires_at column accepts NULL (null means the invite never expires)'
);

-- Simulate the edge function accept UPDATE for all three invites.
-- WHERE clause mirrors the edge function:
--   user_id IS NULL AND accepted_at IS NULL
--   AND (expires_at IS NULL OR expires_at > now())
-- Data-modifying statements must be at the top level (not inside subexpressions).

UPDATE public.group_invites
SET user_id     = 'eeeeeeee-0000-0000-0000-000000000002'::uuid,
    accepted_at = now()
WHERE id = 'eeeeeeee-0000-0000-0000-000000000004'::uuid  -- null expiry
  AND user_id IS NULL
  AND accepted_at IS NULL
  AND (expires_at IS NULL OR expires_at > now());

UPDATE public.group_invites
SET user_id     = 'eeeeeeee-0000-0000-0000-000000000002'::uuid,
    accepted_at = now()
WHERE id = 'eeeeeeee-0000-0000-0000-000000000005'::uuid  -- future expiry
  AND user_id IS NULL
  AND accepted_at IS NULL
  AND (expires_at IS NULL OR expires_at > now());

UPDATE public.group_invites
SET user_id     = 'eeeeeeee-0000-0000-0000-000000000002'::uuid,
    accepted_at = now()
WHERE id = 'eeeeeeee-0000-0000-0000-000000000006'::uuid  -- past expiry (should not match)
  AND user_id IS NULL
  AND accepted_at IS NULL
  AND (expires_at IS NULL OR expires_at > now());

-- Test 3: null-expiry invite was accepted (accepted_at set)
SELECT ok(
    (SELECT accepted_at IS NOT NULL
     FROM public.group_invites
     WHERE id = 'eeeeeeee-0000-0000-0000-000000000004'::uuid),
    'invite with null expires_at is accepted'
);

-- Test 4: future-expiry invite was accepted (accepted_at set)
SELECT ok(
    (SELECT accepted_at IS NOT NULL
     FROM public.group_invites
     WHERE id = 'eeeeeeee-0000-0000-0000-000000000005'::uuid),
    'invite with future expires_at is accepted'
);

-- Test 5: expired invite was rejected (accepted_at still null)
SELECT ok(
    (SELECT accepted_at IS NULL
     FROM public.group_invites
     WHERE id = 'eeeeeeee-0000-0000-0000-000000000006'::uuid),
    'invite with past expires_at is rejected'
);

-- Test 6: null-expiry invite has user_id set (accepted by the right user)
SELECT ok(
    (SELECT user_id = 'eeeeeeee-0000-0000-0000-000000000002'::uuid
     FROM public.group_invites
     WHERE id = 'eeeeeeee-0000-0000-0000-000000000004'::uuid),
    'user_id is set on the accepted null-expiry invite'
);

-- Test 7: expired invite still has user_id null (was not accepted)
SELECT ok(
    (SELECT user_id IS NULL
     FROM public.group_invites
     WHERE id = 'eeeeeeee-0000-0000-0000-000000000006'::uuid),
    'user_id remains null on the rejected expired invite'
);

SELECT * FROM finish();
ROLLBACK;
