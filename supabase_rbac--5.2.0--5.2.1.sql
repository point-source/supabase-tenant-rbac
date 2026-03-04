-- ═══════════════════════════════════════════════════════════════════════════════
-- supabase_rbac v5.2.0 → v5.2.1 upgrade path
-- ═══════════════════════════════════════════════════════════════════════════════
-- Security hardening patch:
--   F1. Revoke PUBLIC execute on internal _-prefixed helper functions
--   F6. Revoke SELECT on roles table from authenticated;
--       make _validate_roles() SECURITY DEFINER so INVOKER RPCs
--       (add_member, update_member_roles, create_invite) can still validate roles.

-- DATA SAFETY REVIEW:
--   Schema changes: none — no tables, columns, indexes, or constraints are altered.
--   Statements: CREATE OR REPLACE FUNCTION (×1), REVOKE (×6), GRANT (×2).
--   All statements are privilege or function-definition changes only.
--   No DROP, ALTER TABLE, TRUNCATE, or DELETE statements.
--
--   Data loss risk: none — no rows are read, written, or removed by any statement.
--
--   Behavioral changes for existing deployments:
--   1. REVOKE SELECT ON roles FROM authenticated: Any app that directly queries
--      rbac.roles as an authenticated user will start receiving insufficient_privilege.
--      The extension's own management RPCs are unaffected (_validate_roles is now
--      SECURITY DEFINER and reads roles as the function owner). App-authors who
--      need users to browse role definitions must re-add the grant explicitly:
--        GRANT SELECT ON rbac.roles TO authenticated;
--      plus an RLS policy (e.g. quickstart.sql opt-in comment).
--      Also drop the now-stale RLS policy if present:
--        DROP POLICY IF EXISTS "Authenticated can read roles" ON rbac.roles;
--   2. REVOKE EXECUTE FROM PUBLIC on internal helpers: Callers that were (mis)using
--      _build_user_claims, _validate_roles, or _set_updated_at directly will now
--      receive insufficient_privilege. These were never part of the public API.
--      _get_user_groups and _jwt_is_expired are re-granted to the roles that need
--      them (authenticated/anon/service_role), so no extension functionality regresses.

-- ─────────────────────────────────────────────────────────────────────────────
-- F6: Make _validate_roles() SECURITY DEFINER
-- ─────────────────────────────────────────────────────────────────────────────
-- _validate_roles reads rbac.roles. Authenticated no longer has SELECT on roles,
-- so we make this function DEFINER (runs as function owner = postgres) so INVOKER
-- management RPCs can still validate role names.
CREATE OR REPLACE FUNCTION @extschema@._validate_roles(p_roles text[])
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = @extschema@
AS $function$
DECLARE
    _undefined text[];
BEGIN
    IF p_roles IS NULL OR cardinality(p_roles) = 0 THEN
        RETURN;
    END IF;

    SELECT array_agg(r)
    INTO _undefined
    FROM unnest(p_roles) AS r
    WHERE r NOT IN (SELECT name FROM @extschema@.roles);

    IF _undefined IS NOT NULL THEN
        RAISE EXCEPTION 'Undefined roles: %', array_to_string(_undefined, ', ')
            USING HINT = 'Add these roles to the roles table first';
    END IF;
END;
$function$;

-- ─────────────────────────────────────────────────────────────────────────────
-- F6: Revoke SELECT on roles from authenticated
-- ─────────────────────────────────────────────────────────────────────────────
-- The roles table (names, descriptions, permissions[]) should not be discoverable
-- by end users. Role management is a service_role / admin operation.
-- App-authors who want users to browse roles can add:
--   GRANT SELECT ON rbac.roles TO authenticated; -- plus an RLS policy
REVOKE SELECT ON @extschema@.roles FROM authenticated;

-- ─────────────────────────────────────────────────────────────────────────────
-- F1: Revoke PUBLIC execute on internal helpers
-- ─────────────────────────────────────────────────────────────────────────────
-- These functions are internal implementation details, not part of the public
-- extension API. Previously they inherited PUBLIC execute from creation.
REVOKE EXECUTE ON FUNCTION @extschema@._build_user_claims(uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION @extschema@._get_user_groups() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION @extschema@._validate_roles(text[]) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION @extschema@._jwt_is_expired() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION @extschema@._set_updated_at() FROM PUBLIC;

-- Re-grant only where needed by extension internals:
-- _get_user_groups: called by get_claims() INVOKER (Storage RLS fallback path)
GRANT EXECUTE ON FUNCTION @extschema@._get_user_groups() TO authenticated, service_role;
-- _jwt_is_expired: called by RLS helpers (has_role, is_member, etc.) which are INVOKER
GRANT EXECUTE ON FUNCTION @extschema@._jwt_is_expired() TO authenticated, anon, service_role;
