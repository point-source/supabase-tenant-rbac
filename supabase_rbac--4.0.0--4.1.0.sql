-- Upgrade from 4.0.0 to 4.1.0
--
-- Fixes:
--   #37 - Groupless users crash get_user_claims() with JSON parse error
--   #11 - Deleting a user causes update_user_roles trigger to error
--   #38 - Add ON DELETE CASCADE to foreign keys for automatic cleanup
--   #39 - user_has_group_role / user_is_group_member should return true for service_role
--   #29 - db_pre_request not found when extension installed in custom schema
--
-- DATA SAFETY NOTES:
--   - This script does NOT modify or delete any existing row data.
--   - The NOT VALID + VALIDATE CONSTRAINT pattern is used for the FK changes:
--       NOT VALID adds the constraint definition without a table scan.
--       VALIDATE CONSTRAINT verifies existing rows, which will always succeed
--       because 4.0.0 already enforced these FK columns (just without CASCADE).
--
-- BEHAVIORAL CHANGE — ON DELETE CASCADE (fix #38):
--   Before this upgrade: deleting a group or user was BLOCKED by FK if any
--   group_users or group_invites rows referenced it. You had to delete the
--   child rows first.
--   After this upgrade: deleting a group or user will automatically CASCADE-
--   delete all related group_users and group_invites rows, AND the
--   update_user_roles trigger will fire for each deleted group_users row to
--   clean up auth.users.raw_app_meta_data.
--   If your application code currently handles the "FK violation on group/user
--   delete" error to prompt the user to clean up first, that code path will no
--   longer be reached after this upgrade.

-- Fix #38: Drop and re-add group_users foreign keys with ON DELETE CASCADE
ALTER TABLE @extschema@.group_users DROP CONSTRAINT group_users_group_id_fkey;
ALTER TABLE @extschema@.group_users
  ADD CONSTRAINT group_users_group_id_fkey
  FOREIGN KEY (group_id) REFERENCES @extschema@.groups (id) ON DELETE CASCADE NOT VALID;
ALTER TABLE @extschema@.group_users VALIDATE CONSTRAINT group_users_group_id_fkey;

ALTER TABLE @extschema@.group_users DROP CONSTRAINT group_users_user_id_fkey;
ALTER TABLE @extschema@.group_users
  ADD CONSTRAINT group_users_user_id_fkey
  FOREIGN KEY (user_id) REFERENCES auth.users (id) ON DELETE CASCADE NOT VALID;
ALTER TABLE @extschema@.group_users VALIDATE CONSTRAINT group_users_user_id_fkey;

-- Fix #38: Drop and re-add group_invites foreign keys with ON DELETE CASCADE
ALTER TABLE @extschema@.group_invites DROP CONSTRAINT group_invites_invited_by_fkey;
ALTER TABLE @extschema@.group_invites
  ADD CONSTRAINT group_invites_invited_by_fkey
  FOREIGN KEY (invited_by) REFERENCES auth.users (id) ON DELETE CASCADE NOT VALID;
ALTER TABLE @extschema@.group_invites VALIDATE CONSTRAINT group_invites_invited_by_fkey;

ALTER TABLE @extschema@.group_invites DROP CONSTRAINT group_invites_group_id_fkey;
ALTER TABLE @extschema@.group_invites
  ADD CONSTRAINT group_invites_group_id_fkey
  FOREIGN KEY (group_id) REFERENCES @extschema@.groups (id) ON DELETE CASCADE NOT VALID;
ALTER TABLE @extschema@.group_invites VALIDATE CONSTRAINT group_invites_group_id_fkey;

ALTER TABLE @extschema@.group_invites DROP CONSTRAINT group_invites_user_id_fkey;
ALTER TABLE @extschema@.group_invites
  ADD CONSTRAINT group_invites_user_id_fkey
  FOREIGN KEY (user_id) REFERENCES auth.users (id) ON DELETE CASCADE NOT VALID;
ALTER TABLE @extschema@.group_invites VALIDATE CONSTRAINT group_invites_user_id_fkey;

-- Fix #29 + #37: schema-qualify function name; coalesce null groups to '{}'
CREATE OR REPLACE FUNCTION @extschema@.db_pre_request () RETURNS void LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = @extschema@ AS $function$
DECLARE
    groups jsonb;
BEGIN
    SELECT raw_app_meta_data->'groups' FROM auth.users INTO groups WHERE id = auth.uid();
    PERFORM set_config('request.groups'::text, coalesce(groups, '{}')::text, false);
END;
$function$;

-- Fix #37: nullif guards against empty string causing JSON parse error
CREATE OR REPLACE FUNCTION @extschema@.get_user_claims () RETURNS jsonb LANGUAGE sql STABLE
SET search_path = @extschema@ AS $function$
SELECT coalesce(nullif(current_setting('request.groups', true), '')::jsonb, auth.jwt()->'app_metadata'->'groups')::jsonb
$function$;

-- Fix #39: return true for service_role
CREATE OR REPLACE FUNCTION @extschema@.user_has_group_role (group_id uuid, group_role text) RETURNS boolean LANGUAGE plpgsql STABLE
SET search_path = @extschema@ AS $function$
DECLARE
  auth_role text = auth.role();
  retval bool;
BEGIN
    IF auth_role = 'authenticated' THEN
        IF jwt_is_expired() THEN
            RAISE EXCEPTION 'invalid_jwt' USING hint = 'jwt is expired or missing';
        END IF;
        SELECT coalesce(get_user_claims()->group_id::text ? group_role, false) INTO retval;
        RETURN retval;
    ELSIF auth_role = 'anon' THEN
        RETURN false;
    ELSE
      IF session_user = 'postgres' OR auth_role = 'service_role' THEN
        RETURN true;
      ELSE
        RETURN false;
      END IF;
    END IF;
END;
$function$;

-- Fix #39: return true for service_role
CREATE OR REPLACE FUNCTION @extschema@.user_is_group_member (group_id uuid) RETURNS boolean LANGUAGE plpgsql STABLE
SET search_path = @extschema@ AS $function$
DECLARE
  auth_role text = auth.role();
  retval bool;
BEGIN
    IF auth_role = 'authenticated' THEN
        IF jwt_is_expired() THEN
            RAISE EXCEPTION 'invalid_jwt' USING hint = 'jwt is expired or missing';
        END IF;
        SELECT coalesce(get_user_claims() ? group_id::text, false) INTO retval;
        RETURN retval;
    ELSIF auth_role = 'anon' THEN
        RETURN false;
    ELSE
      IF session_user = 'postgres' OR auth_role = 'service_role' THEN
        RETURN true;
      ELSE
        RETURN false;
      END IF;
    END IF;
END;
$function$;

-- Fix #11: skip metadata update when user no longer exists
CREATE OR REPLACE FUNCTION @extschema@.update_user_roles()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO @extschema@
AS $function$
DECLARE
  _group_id TEXT = COALESCE(new.group_id, old.group_id)::TEXT;
  _group_id_old TEXT = COALESCE(old.group_id, new.group_id)::TEXT;
  _user_id UUID = COALESCE(new.user_id, old.user_id);
  _user_id_old UUID = COALESCE(old.user_id, new.user_id);
  _role TEXT = COALESCE(new.role, old.role);
  _role_old TEXT = COALESCE(old.role, new.role);
  _raw_app_meta_data JSONB;
BEGIN
  IF _group_id IS DISTINCT FROM _group_id_old OR _user_id IS DISTINCT FROM _user_id_old THEN
      RAISE EXCEPTION 'Changing user_id or group_id is not allowed';
  END IF;

  -- Fix #11: skip if user was already deleted (e.g. cascaded from auth.users)
  IF NOT EXISTS (SELECT 1 FROM auth.users WHERE id = _user_id) THEN
      RETURN OLD;
  END IF;

  SELECT raw_app_meta_data INTO _raw_app_meta_data FROM auth.users WHERE id = _user_id;
  _raw_app_meta_data = coalesce(_raw_app_meta_data, '{}'::jsonb);

  IF (TG_OP = 'DELETE') OR (TG_OP = 'UPDATE' AND _role IS DISTINCT FROM _role_old) THEN
    _raw_app_meta_data = jsonb_set(
        _raw_app_meta_data,
        '{groups}',
        jsonb_strip_nulls(
            COALESCE(_raw_app_meta_data->'groups', '{}'::jsonb) ||
            jsonb_build_object(
                _group_id::text,
                (
                    SELECT jsonb_agg(val)
                    FROM jsonb_array_elements_text(COALESCE(_raw_app_meta_data->'groups'->(_group_id::text), '[]'::jsonb)) AS vals(val)
                    WHERE val <> _role_old
                )
            )
        )
    );
  END IF;

  IF (TG_OP = 'INSERT') OR (TG_OP = 'UPDATE' AND _role IS DISTINCT FROM _role_old) THEN
    _raw_app_meta_data = jsonb_set(
        _raw_app_meta_data,
        '{groups}',
        COALESCE(_raw_app_meta_data->'groups', '{}'::jsonb) ||
        jsonb_build_object(
            _group_id::text,
            (
                SELECT jsonb_agg(DISTINCT val)
                FROM (
                    SELECT val
                    FROM jsonb_array_elements_text(COALESCE(_raw_app_meta_data->'groups'->(_group_id::text), '[]'::jsonb)) AS vals(val)
                    UNION
                    SELECT _role
                ) AS combined_roles(val)
            )
        )
    );
  END IF;

  UPDATE auth.users
  SET raw_app_meta_data = _raw_app_meta_data
  WHERE id = _user_id;

  RETURN NEW;
END;
$function$;

-- Fix #29: schema-qualify so this resolves correctly in non-public schema installs
ALTER ROLE authenticator
SET
  pgrst.db_pre_request TO '@extschema@.db_pre_request';

NOTIFY pgrst,
'reload config';
