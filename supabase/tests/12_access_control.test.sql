-- Tests for function grant assignments on extension functions.
-- Verifies that the expected roles have EXECUTE on each function.
--
-- In v5.0.0, functions live in the rbac schema with public wrappers.
-- We test both the rbac.* originals and the public.* wrappers.

BEGIN;
SELECT plan(8);

-- ── Test 1: authenticator has EXECUTE on db_pre_request() ────────────────────
SELECT ok(
    has_function_privilege('authenticator', 'rbac.db_pre_request()', 'EXECUTE'),
    'authenticator role has EXECUTE on rbac.db_pre_request()'
);

-- ── Test 2: authenticated has EXECUTE on accept_invite() (rbac) ──────────────
SELECT ok(
    has_function_privilege('authenticated', 'rbac.accept_invite(uuid)', 'EXECUTE'),
    'authenticated role has EXECUTE on rbac.accept_invite(uuid)'
);

-- ── Test 3: authenticated has EXECUTE on has_role() (public wrapper) ─────────
SELECT ok(
    has_function_privilege('authenticated', 'public.has_role(uuid, text)', 'EXECUTE'),
    'authenticated role has EXECUTE on public.has_role(uuid, text)'
);

-- ── Test 4: authenticated has EXECUTE on is_member() (public wrapper) ────────
SELECT ok(
    has_function_privilege('authenticated', 'public.is_member(uuid)', 'EXECUTE'),
    'authenticated role has EXECUTE on public.is_member(uuid)'
);

-- ── Test 5: authenticated has EXECUTE on has_any_role() (public wrapper) ─────
SELECT ok(
    has_function_privilege('authenticated', 'public.has_any_role(uuid, text[])', 'EXECUTE'),
    'authenticated role has EXECUTE on public.has_any_role(uuid, text[])'
);

-- ── Test 6: authenticated has EXECUTE on create_group() (public wrapper) ─────
SELECT ok(
    has_function_privilege('authenticated', 'public.create_group(text, jsonb, text[])', 'EXECUTE'),
    'authenticated role has EXECUTE on public.create_group(text, jsonb, text[])'
);

-- ── Test 7: authenticated has EXECUTE on create_role() (public wrapper) ──────
SELECT ok(
    has_function_privilege('authenticated', 'public.create_role(text, text)', 'EXECUTE'),
    'authenticated role has EXECUTE on public.create_role(text, text)'
);

-- ── Test 8: supabase_auth_admin has EXECUTE on custom_access_token_hook() ─────
SELECT ok(
    has_function_privilege('supabase_auth_admin', 'public.custom_access_token_hook(jsonb)', 'EXECUTE'),
    'supabase_auth_admin role has EXECUTE on public.custom_access_token_hook(jsonb)'
);

SELECT * FROM finish();
ROLLBACK;
