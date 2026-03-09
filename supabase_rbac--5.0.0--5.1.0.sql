-- Upgrade path: 5.0.0 → 5.1.0
-- Grants service_role EXECUTE on management RPCs and db_pre_request,
-- plus SELECT on user_claims for the db_pre_request INVOKER path.
--
-- DATA SAFETY REVIEW:
--   Schema changes: none — no tables, columns, constraints, or functions are created, altered, or dropped.
--   Behavioral changes: service_role can now call management RPCs and db_pre_request.
--     Previously these were denied at the PostgreSQL privilege level. Escalation
--     checks already bypass for non-authenticated roles, so this grants access
--     that was architecturally intended but not wired up.
--   Data loss risk: none — all statements are GRANT (additive privilege changes only).
--     No existing data, schema objects, or permissions are modified or removed.

-- Management RPCs: add service_role
GRANT EXECUTE ON FUNCTION @extschema@.create_group(text, jsonb, text[]) TO service_role;
GRANT EXECUTE ON FUNCTION @extschema@.delete_group(uuid) TO service_role;
GRANT EXECUTE ON FUNCTION @extschema@.add_member(uuid, uuid, text[]) TO service_role;
GRANT EXECUTE ON FUNCTION @extschema@.remove_member(uuid, uuid) TO service_role;
GRANT EXECUTE ON FUNCTION @extschema@.update_member_roles(uuid, uuid, text[]) TO service_role;
GRANT EXECUTE ON FUNCTION @extschema@.list_members(uuid) TO service_role;
GRANT EXECUTE ON FUNCTION @extschema@.accept_invite(uuid) TO service_role;
GRANT EXECUTE ON FUNCTION @extschema@.create_invite(uuid, text[], timestamptz) TO service_role;
GRANT EXECUTE ON FUNCTION @extschema@.delete_invite(uuid) TO service_role;
GRANT EXECUTE ON FUNCTION @extschema@.grant_member_permission(uuid, uuid, text) TO service_role;
GRANT EXECUTE ON FUNCTION @extschema@.revoke_member_permission(uuid, uuid, text) TO service_role;
GRANT EXECUTE ON FUNCTION @extschema@.list_member_permissions(uuid, uuid) TO service_role;

-- db_pre_request: service_role needs EXECUTE (PostgREST calls it after SET LOCAL ROLE)
GRANT EXECUTE ON FUNCTION @extschema@.db_pre_request() TO service_role;

-- user_claims: service_role needs SELECT (db_pre_request is INVOKER, reads user_claims)
GRANT SELECT ON @extschema@.user_claims TO service_role;
