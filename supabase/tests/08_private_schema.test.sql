-- Tests for private schema isolation (PS-01 through PS-04).
-- Verifies schema access privileges, that internal functions are locked down,
-- that public management RPCs are accessible to authenticated, and that
-- anon cannot access management RPCs.

BEGIN;
SELECT plan(4);

-- No data setup required — all tests are privilege/configuration checks.

-- ── PS-01: authenticated has USAGE on rbac schema ─────────────────────────────
-- The rbac schema is accessible to authenticated (USAGE granted by extension).
-- This is correct: authenticated calls schema-qualified RPCs like rbac.create_group().
SELECT ok(
    has_schema_privilege('authenticated', 'rbac', 'USAGE'),
    'PS-01: authenticated has USAGE on rbac schema — schema-qualified RPCs are callable'
);

-- ── PS-02: authenticated does NOT have EXECUTE on rbac._sync_member_metadata() ─
-- Internal trigger functions are locked down. v5.0.0 revokes EXECUTE from PUBLIC
-- and does not re-grant to authenticated for _sync_member_metadata.
SELECT ok(
    NOT has_function_privilege('authenticated', 'rbac._sync_member_metadata()', 'EXECUTE'),
    'PS-02: authenticated does not have EXECUTE on rbac._sync_member_metadata() — internal function locked'
);

-- ── PS-03: authenticated has EXECUTE on rbac.create_group(text, jsonb, text[]) ─
-- Management RPCs are granted to authenticated. create_group is the primary
-- entry-point for group creation — it must be callable by authenticated.
SELECT ok(
    has_function_privilege('authenticated', 'rbac.create_group(text, jsonb, text[])', 'EXECUTE'),
    'PS-03: authenticated has EXECUTE on rbac.create_group(text, jsonb, text[]) — management RPC accessible'
);

-- ── PS-04: anon does NOT have EXECUTE on rbac.create_group(text, jsonb, text[]) ─
-- anon is unauthenticated; management RPCs are restricted to authenticated only.
-- The extension GRANTs to authenticated, not PUBLIC, so anon is excluded.
SELECT ok(
    NOT has_function_privilege('anon', 'rbac.create_group(text, jsonb, text[])', 'EXECUTE'),
    'PS-04: anon does not have EXECUTE on rbac.create_group(text, jsonb, text[]) — unauthenticated excluded'
);

SELECT * FROM finish();
ROLLBACK;
