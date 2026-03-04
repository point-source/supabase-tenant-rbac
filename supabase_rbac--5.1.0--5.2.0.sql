-- ═══════════════════════════════════════════════════════════════════════════════
-- supabase_rbac upgrade: 5.1.0 → 5.2.0
-- ═══════════════════════════════════════════════════════════════════════════════
-- Apply this script to upgrade an existing 5.1.0 installation to 5.2.0.
-- Run as the extension owner (postgres / superuser).

-- DATA SAFETY REVIEW:
--   Schema changes: none — no tables, columns, constraints, or indexes are
--     added, altered, or dropped.
--   Function changes:
--     - ALTER FUNCTION ... SECURITY DEFINER: changes security context of three
--       trigger functions. No data is read or written.
--     - CREATE OR REPLACE FUNCTION create_invite / delete_invite: new RPCs.
--       No data is written on install.
--     - CREATE OR REPLACE FUNCTION revoke_member_permission: replaces existing
--       function body to add empty-string validation before the existing DELETE.
--       No behavior change for valid calls; invalid calls now raise earlier.
--   Privilege changes: REVOKE INSERT, UPDATE on user_claims from authenticated;
--     GRANT INSERT, DELETE on invites to authenticated. No data changes.
--   DELETE FROM statements detected: both are inside function bodies
--     (delete_invite and revoke_member_permission). They execute only when an
--     end user explicitly calls those RPCs — NOT during script application.
--   Data loss risk: none — applying this script reads and writes zero rows.

-- ─────────────────────────────────────────────────────────────────────────────
-- P0: Make the three claims-writing trigger functions SECURITY DEFINER.
-- This closes the user_claims write attack surface: triggers now run as the
-- function owner (postgres) rather than the invoking role, so authenticated
-- users no longer need INSERT/UPDATE on user_claims.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER FUNCTION @extschema@._sync_member_metadata() SECURITY DEFINER;
ALTER FUNCTION @extschema@._sync_member_permission() SECURITY DEFINER;
ALTER FUNCTION @extschema@._on_role_permissions_change() SECURITY DEFINER;

-- ─────────────────────────────────────────────────────────────────────────────
-- P0: Revoke INSERT/UPDATE on user_claims from authenticated.
-- Existing SELECT grant is retained (needed by _get_user_groups fallback).
-- ─────────────────────────────────────────────────────────────────────────────

REVOKE INSERT, UPDATE ON @extschema@.user_claims FROM authenticated;

-- ─────────────────────────────────────────────────────────────────────────────
-- P1: Grant INSERT/DELETE on invites to authenticated.
-- These were missing, blocking the new create_invite / delete_invite RPCs.
-- ─────────────────────────────────────────────────────────────────────────────

GRANT INSERT, DELETE ON @extschema@.invites TO authenticated;

-- ─────────────────────────────────────────────────────────────────────────────
-- P1: Add create_invite() RPC.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION @extschema@.create_invite(
    p_group_id   uuid,
    p_roles      text[],
    p_expires_at timestamptz DEFAULT NULL
)
RETURNS uuid
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
DECLARE
    _user_id   uuid := auth.uid();
    _invite_id uuid;
BEGIN
    IF _user_id IS NULL THEN
        RAISE EXCEPTION 'Not authenticated';
    END IF;

    PERFORM _validate_roles(p_roles);

    INSERT INTO @extschema@.invites (group_id, roles, invited_by, expires_at)
    VALUES (p_group_id, p_roles, _user_id, p_expires_at)
    RETURNING id INTO _invite_id;

    RETURN _invite_id;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.create_invite(uuid, text[], timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.create_invite(uuid, text[], timestamptz) TO authenticated;

-- ─────────────────────────────────────────────────────────────────────────────
-- P1: Add delete_invite() RPC.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION @extschema@.delete_invite(p_invite_id uuid)
RETURNS void
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
BEGIN
    DELETE FROM @extschema@.invites WHERE id = p_invite_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invite not found or not authorized';
    END IF;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.delete_invite(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.delete_invite(uuid) TO authenticated;

-- ─────────────────────────────────────────────────────────────────────────────
-- P3: Add consistent REVOKE/GRANT on the five RLS helpers that were missing them.
-- ─────────────────────────────────────────────────────────────────────────────

REVOKE EXECUTE ON FUNCTION @extschema@.get_claims() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.get_claims() TO authenticated, anon, service_role;

REVOKE EXECUTE ON FUNCTION @extschema@.has_role(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.has_role(uuid, text) TO authenticated, anon, service_role;

REVOKE EXECUTE ON FUNCTION @extschema@.is_member(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.is_member(uuid) TO authenticated, anon, service_role;

REVOKE EXECUTE ON FUNCTION @extschema@.has_any_role(uuid, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.has_any_role(uuid, text[]) TO authenticated, anon, service_role;

REVOKE EXECUTE ON FUNCTION @extschema@.has_all_roles(uuid, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.has_all_roles(uuid, text[]) TO authenticated, anon, service_role;

-- ─────────────────────────────────────────────────────────────────────────────
-- P4: Add empty-string validation to revoke_member_permission().
-- ─────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION @extschema@.revoke_member_permission(
    p_group_id   uuid,
    p_user_id    uuid,
    p_permission text
)
RETURNS void
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
BEGIN
    -- Caller must be a member of the target group.
    IF NOT is_member(p_group_id) THEN
        RAISE EXCEPTION 'permission denied — caller is not a member of the target group'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Reject empty permission strings.
    IF trim(coalesce(p_permission, '')) = '' THEN
        RAISE EXCEPTION 'permission must not be empty'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    DELETE FROM @extschema@.member_permissions
    WHERE group_id = p_group_id AND user_id = p_user_id AND permission = p_permission;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Permission override not found for member';
    END IF;
END;
$function$;
