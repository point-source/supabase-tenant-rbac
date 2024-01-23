set check_function_bodies = off;

create
or replace function db_pre_request () returns void language plpgsql security definer as $function$
declare
    groups jsonb;
begin
    -- get current groups from auth.users
    select raw_app_meta_data->'groups' from auth.users into groups where id = auth.uid();
    -- store it in the request object
    perform set_config('request.groups'::text, groups::text, false /* applies to transaction if true, session if false */);
end;
$function$;

create
or replace function get_req_groups () returns jsonb language sql stable as $function$ 
select coalesce(current_setting('request.groups', true), '{}')::jsonb
$function$;

-- Enable the db_pre_request hook for the authenticator role
ALTER ROLE authenticator SET pgrst.db_pre_request TO 'public.db_pre_request';
NOTIFY pgrst, 'reload config';

create
or replace function jwt_has_group_role (group_id uuid, group_role text) returns boolean language plpgsql as $function$
declare retval bool;
begin
    if session_user = 'authenticator' then
        if jwt_is_expired() then
            raise exception 'invalid_jwt' using hint = 'jwt is expired or missing';
        end if;
        select coalesce(
            coalesce(get_req_groups(), auth.jwt()->'app_metadata'->'groups')->group_id::text ? group_role,
            false
          ) into retval;
        return retval;
    else -- not a user session, probably being called from a trigger or something
        return true;
    end if;
end;
$function$;

create
or replace function jwt_is_expired () returns boolean language plpgsql as $function$ begin
  return extract(epoch from now()) > coalesce(auth.jwt()->>'exp', '0')::numeric;
end;
$function$;

create
or replace function jwt_is_group_member (group_id uuid) returns boolean language plpgsql as $function$
declare retval bool;
begin
    if session_user = 'authenticator' then
        if jwt_is_expired() then
            raise exception 'invalid_jwt' using hint = 'jwt is expired or missing';
        end if;
        select coalesce(
            coalesce(get_req_groups(), auth.jwt()->'app_metadata'->'groups') ? group_id::text,
            false
          ) into retval;
        return retval;
    else -- not a user session, probably being called from a trigger or something
        return true;
    end if;
end;
$function$;
