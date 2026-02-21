-- Upgrade path: v4.3.0 → v4.4.0
-- Adds accept_group_invite() — atomic invite acceptance as a SECURITY DEFINER RPC function.

-- DATA SAFETY REVIEW:
--   No existing row data is modified by this upgrade.
--   Schema changes: none — no new tables, columns, or constraints.
--   New objects: accept_group_invite(uuid) SECURITY DEFINER function.
--   Permission changes (two):
--     1. accept_group_invite(uuid): EXECUTE revoked from PUBLIC, granted to authenticated.
--        Anon callers can no longer attempt the RPC; they receive permission-denied immediately.
--     2. db_pre_request(): EXECUTE revoked from PUBLIC, granted to authenticator.
--        This function is only meant to be called by PostgREST's pre-request hook mechanism.
--        Any code calling /rest/v1/rpc/db_pre_request directly will receive permission-denied
--        after this upgrade. That endpoint was never intended for direct use.
--   Behavioral changes: accept_group_invite() replaces the edge function's non-atomic two-step
--     UPDATE+INSERT. Existing group_invites and group_users rows are unaffected.
--   Data loss risk: none — only objects are added and permissions are tightened.

-- Atomically accept a group invite and insert group membership(s) in a single transaction.
-- Uses auth.uid() (not a parameter) so each user can only accept invites as themselves.
-- SECURITY DEFINER runs as the function owner, bypassing RLS to perform the two writes
-- atomically; the WHERE clause enforces all invite validity checks.
CREATE OR REPLACE FUNCTION @extschema@.accept_group_invite(p_invite_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = @extschema@
AS $function$
DECLARE
  _user_id uuid := auth.uid();
  _invite record;
BEGIN
  IF _user_id IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;

  -- Lock the invite row to prevent concurrent acceptance races
  SELECT * INTO _invite FROM group_invites
  WHERE id = p_invite_id
    AND user_id IS NULL
    AND accepted_at IS NULL
    AND (expires_at IS NULL OR expires_at > now())
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Invite not found, already used, or expired';
  END IF;

  -- Mark invite as accepted (same transaction — atomic with the INSERT below)
  UPDATE group_invites
  SET user_id = _user_id, accepted_at = now()
  WHERE id = p_invite_id;

  -- Insert group membership for each role in the invite
  INSERT INTO group_users (user_id, group_id, role)
  SELECT _user_id, _invite.group_id, unnest(_invite.roles)
  ON CONFLICT (group_id, user_id, role) DO NOTHING;
END;
$function$;

-- Defense-in-depth: restrict direct RPC calls to authenticated users only.
-- Anon callers are rejected before the function body executes.
REVOKE EXECUTE ON FUNCTION @extschema@.accept_group_invite(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.accept_group_invite(uuid) TO authenticated;

-- db_pre_request() is invoked exclusively by PostgREST's pre-request hook
-- (registered via ALTER ROLE authenticator SET pgrst.db_pre_request).
-- It is not intended to be called by end users directly via RPC.
REVOKE EXECUTE ON FUNCTION @extschema@.db_pre_request() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.db_pre_request() TO authenticator;
