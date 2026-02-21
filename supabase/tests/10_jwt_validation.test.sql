-- Tests for jwt_is_expired() (lines 181–188 of the extension).
--
-- jwt_is_expired() implementation:
--   return extract(epoch from now()) > coalesce(auth.jwt()->>'exp', '0')::numeric;
--
-- Behaviour:
--   - exp in the past  → true  (expired)
--   - exp in the future → false (valid)
--   - empty JWT context → true  (coalesce('0') → epoch 0 < now())
--   - exp claim missing → true  (coalesce('0') → epoch 0 < now())
--
-- JWT claims are injected via set_config('request.jwt.claims', ...) —
-- the same pattern used in 08_storage_claims.test.sql.

BEGIN;
SELECT plan(4);

-- ── Test 1: Returns true when exp is in the past ──────────────────────────────
SELECT set_config('request.jwt.claims',
    format(
        '{"role":"authenticated","sub":"00000000-0000-0000-0000-000000000001","exp":%s}',
        (extract(epoch from now()) - 3600)::bigint
    ),
    true);
SELECT is(
    jwt_is_expired(),
    true,
    'jwt_is_expired() returns true when exp is in the past'
);

-- ── Test 2: Returns false when exp is in the future ───────────────────────────
SELECT set_config('request.jwt.claims',
    format(
        '{"role":"authenticated","sub":"00000000-0000-0000-0000-000000000001","exp":%s}',
        (extract(epoch from now()) + 3600)::bigint
    ),
    true);
SELECT is(
    jwt_is_expired(),
    false,
    'jwt_is_expired() returns false when exp is in the future'
);

-- ── Test 3: Returns true when JWT context is empty ────────────────────────────
-- auth.jwt() returns '{}' for an empty claims string; '{}' ->>'exp' is NULL;
-- coalesce(NULL, '0') → 0; now_epoch > 0 → true.
SELECT set_config('request.jwt.claims', '', true);
SELECT is(
    jwt_is_expired(),
    true,
    'jwt_is_expired() returns true when request.jwt.claims is empty (no session context)'
);

-- ── Test 4: Returns true when exp claim is missing from JWT ───────────────────
-- A JWT with no exp field is treated as expired (fail-safe).
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"00000000-0000-0000-0000-000000000001"}',
    true);
SELECT is(
    jwt_is_expired(),
    true,
    'jwt_is_expired() returns true when exp claim is absent from JWT'
);

SELECT * FROM finish();
ROLLBACK;
