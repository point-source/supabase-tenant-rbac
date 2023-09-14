set check_function_bodies = off;

CREATE OR REPLACE FUNCTION public.update_user_roles()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
declare _group_id uuid = coalesce(new.group_id, old.group_id);
_user_id uuid = coalesce(new.user_id, old.user_id);
begin
update auth.users
set raw_app_meta_data = jsonb_set(
    raw_app_meta_data,
    '{groups}',
    jsonb_strip_nulls(
      jsonb_set(
        coalesce(raw_app_meta_data->'groups', '{}'::jsonb),
        array [_group_id::text],
        coalesce(
          (select jsonb_agg("role")
            from group_users gu
            where gu.group_id = _group_id
              and gu.user_id = _user_id
          ),
          'null'::jsonb
        )
      )
    )
  )
where id = _user_id;
return null;
end;
$function$
;


