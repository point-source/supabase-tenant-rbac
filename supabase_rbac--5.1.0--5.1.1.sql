-- Upgrade path: 5.1.0 → 5.1.1
-- Fixes db_pre_request() privilege gap: PostgREST calls it AFTER "SET LOCAL ROLE",
-- so authenticated and anon need EXECUTE — not just authenticator.
-- Replaces db_pre_request() body to short-circuit for anon/NULL-uid callers.
--
-- DATA SAFETY REVIEW:
--   Schema changes: db_pre_request() function body is replaced (CREATE OR REPLACE).
--     No tables, columns, or constraints are created, altered, or dropped.
--   Behavioral changes: authenticated and anon can now call db_pre_request().
--     db_pre_request now short-circuits with '{}' for anon or NULL auth.uid()
--     instead of attempting a SELECT on user_claims (which anon lacks access to).
--     Previously, all PostgREST requests from logged-in users on hosted Supabase
--     failed with "permission denied for function db_pre_request".
--   Data loss risk: none — all statements are GRANT or CREATE OR REPLACE.
--     No existing data, schema objects, or permissions are modified or removed.

-- Replace db_pre_request() to short-circuit for anon / NULL auth.uid()
CREATE OR REPLACE FUNCTION @extschema@.db_pre_request()
RETURNS void
LANGUAGE plpgsql
VOLATILE
SET search_path = @extschema@
AS $function$
DECLARE
    _uid   uuid := auth.uid();
    groups jsonb;
BEGIN
    -- anon and other no-user contexts: skip the user_claims SELECT entirely.
    -- anon lacks SELECT on user_claims and would never have claims anyway.
    -- Check current_user as defense-in-depth: auth.uid() reads JWT claims
    -- regardless of role, so a crafted JWT could produce a non-NULL uid for anon.
    IF _uid IS NULL OR current_user = 'anon' THEN
        PERFORM set_config('request.groups'::text, '{}'::text, true);
        RETURN;
    END IF;

    SELECT claims INTO groups FROM @extschema@.user_claims WHERE user_id = _uid;
    PERFORM set_config('request.groups'::text, coalesce(groups, '{}')::text, true);
END;
$function$;

-- PostgREST calls db_pre_request AFTER "SET LOCAL ROLE <role>", so the switched
-- role needs EXECUTE. authenticated and anon were missing in 5.1.0.
GRANT EXECUTE ON FUNCTION @extschema@.db_pre_request() TO authenticated, anon;
