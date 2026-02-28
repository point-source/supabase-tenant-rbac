-- Tests for _jwt_is_expired() (internal function, v5.0.0).
--
-- _jwt_is_expired() implementation:
--   return extract(epoch from now()) > coalesce(auth.jwt()->>'exp', '0')::numeric;
--
-- Behaviour:
--   - exp in the past  → true  (expired)
--   - exp in the future → false (valid)
--   - empty JWT context → true  (coalesce('0') → epoch 0 < now())
--   - exp claim missing → true  (coalesce('0') → epoch 0 < now())

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
    rbac._jwt_is_expired(),
    true,
    '_jwt_is_expired() returns true when exp is in the past'
);

-- ── Test 2: Returns false when exp is in the future ───────────────────────────
SELECT set_config('request.jwt.claims',
    format(
        '{"role":"authenticated","sub":"00000000-0000-0000-0000-000000000001","exp":%s}',
        (extract(epoch from now()) + 3600)::bigint
    ),
    true);
SELECT is(
    rbac._jwt_is_expired(),
    false,
    '_jwt_is_expired() returns false when exp is in the future'
);

-- ── Test 3: Returns true when JWT context is empty ────────────────────────────
SELECT set_config('request.jwt.claims', '', true);
SELECT is(
    rbac._jwt_is_expired(),
    true,
    '_jwt_is_expired() returns true when request.jwt.claims is empty (no session context)'
);

-- ── Test 4: Returns true when exp claim is missing from JWT ───────────────────
SELECT set_config('request.jwt.claims',
    '{"role":"authenticated","sub":"00000000-0000-0000-0000-000000000001"}',
    true);
SELECT is(
    rbac._jwt_is_expired(),
    true,
    '_jwt_is_expired() returns true when exp claim is absent from JWT'
);

SELECT * FROM finish();
ROLLBACK;
