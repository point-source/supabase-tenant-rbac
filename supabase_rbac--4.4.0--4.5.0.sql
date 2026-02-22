-- Upgrade script: 4.4.0 → 4.5.0
-- Adds two bulk role-check helper functions: user_has_any_group_role() and
-- user_has_all_group_roles(). No schema changes; backwards compatible.
--
-- DATA SAFETY REVIEW:
--   Schema changes: none — no tables, columns, indexes, or constraints are added,
--     altered, or removed.
--   Behavioral changes: none — existing functions are untouched. The two new
--     functions are purely additive read-only helpers (STABLE, no side effects).
--     Existing RLS policies that call user_has_group_role() / user_is_group_member()
--     continue to work identically; no policy expressions are modified by this upgrade.
--   Data loss risk: none — this upgrade only creates two new functions. No user
--     data (groups, group_users, group_invites, auth.users metadata) is read,
--     written, or affected in any way by applying this script.

-- Returns true if the user has ANY of the listed roles in the group.
-- Use instead of multiple user_has_group_role() calls joined with OR.
-- Example: user_has_any_group_role(group_id, ARRAY['owner', 'admin'])
-- Uses JSONB ?| operator to check array element membership in one call.
-- Same auth tier dispatch as user_has_group_role().
create
or replace function @extschema@.user_has_any_group_role (group_id uuid, group_roles text[]) returns boolean language plpgsql stable
set
  search_path = @extschema@ as $function$
declare
  auth_role text = auth.role();
  retval bool;
begin
    if auth_role = 'authenticated' then
        if jwt_is_expired() then
            raise exception 'invalid_jwt' using hint = 'jwt is expired or missing';
        end if;
        select coalesce(get_user_claims()->group_id::text ?| group_roles,
            false
          ) into retval;
        return retval;
    elsif auth_role = 'anon' then
        return false;
    else -- not a user session, probably being called from a trigger or something
      if session_user = 'postgres' or auth_role = 'service_role' then
        return true;
      else -- such as 'authenticator'
        return false;
      end if;
    end if;
end;
$function$;

-- Returns true if the user has ALL of the listed roles in the group.
-- Use when a policy requires simultaneous possession of multiple roles/permissions.
-- Example: user_has_all_group_roles(group_id, ARRAY['project.read', 'project.admin'])
-- Uses JSONB ?& operator to check all elements exist in the claims array.
-- Same auth tier dispatch as user_has_group_role().
-- Note: calling with an empty array returns true for any group member (vacuous truth).
create
or replace function @extschema@.user_has_all_group_roles (group_id uuid, group_roles text[]) returns boolean language plpgsql stable
set
  search_path = @extschema@ as $function$
declare
  auth_role text = auth.role();
  retval bool;
begin
    if auth_role = 'authenticated' then
        if jwt_is_expired() then
            raise exception 'invalid_jwt' using hint = 'jwt is expired or missing';
        end if;
        select coalesce(get_user_claims()->group_id::text ?& group_roles,
            false
          ) into retval;
        return retval;
    elsif auth_role = 'anon' then
        return false;
    else -- not a user session, probably being called from a trigger or something
      if session_user = 'postgres' or auth_role = 'service_role' then
        return true;
      else -- such as 'authenticator'
        return false;
      end if;
    end if;
end;
$function$;
