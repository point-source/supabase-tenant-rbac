SET check_function_bodies = off;

CREATE OR REPLACE FUNCTION public.update_user_roles()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $function$
DECLARE
  _group_id UUID = COALESCE(new.group_id, old.group_id);
  _group_id_old UUID = COALESCE(old.group_id, new.group_id);
  _user_id UUID = COALESCE(new.user_id, old.user_id);
  _user_id_old UUID = COALESCE(old.user_id, new.user_id);
BEGIN
  -- Check if user_id or group_id is changed
  IF _group_id IS DISTINCT FROM _group_id_old OR _user_id IS DISTINCT FROM _user_id_old THEN
    RAISE EXCEPTION 'Changing user_id or group_id is not allowed';
  END IF;

  -- Update raw_app_meta_data in auth.users
  UPDATE auth.users
  SET raw_app_meta_data = JSONB_SET(
      raw_app_meta_data,
      '{groups}',
      JSONB_STRIP_NULLS(
        JSONB_SET(
          COALESCE(raw_app_meta_data->'groups', '{}'::JSONB),
          ARRAY[_group_id::TEXT],
          COALESCE(
            (SELECT JSONB_AGG("role")
             FROM group_users gu
             WHERE gu.group_id = _group_id
               AND gu.user_id = _user_id
            ),
            'null'::JSONB
          )
        )
      )
    )
  WHERE id = _user_id;

  -- Return null (the trigger function requires a return value)
  RETURN NULL;
END;
$function$;
