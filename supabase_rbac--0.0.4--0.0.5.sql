create
or replace function public.user_has_group_role (group_id uuid, group_role text) returns boolean language plpgsql stable 
set
  search_path = public as $function$
declare 
  auth_role text = auth.role();
  retval bool;
begin
    if auth_role = 'service_role' then
        if jwt_is_expired() then
            raise exception 'invalid_jwt' using hint = 'jwt is expired or missing';
        else
            return true;
        end if;
    elsif auth_role = 'authenticated' then
        if jwt_is_expired() then
            raise exception 'invalid_jwt' using hint = 'jwt is expired or missing';
        end if;
        select coalesce(get_user_claims()->group_id::text ? group_role,
            false
          ) into retval;
        return retval;
    elsif auth_role = 'anon' then
        return false;
    else -- not a user session, probably being called from a trigger or something
      if session_user = 'postgres' then
        return true;
      else -- such as 'authenticator'
        return false;
      end if;
    end if;
end;
$function$;

create
or replace function public.user_is_group_member (group_id uuid) returns boolean language plpgsql stable 
set
  search_path = public as $function$
declare 
  auth_role text = auth.role();
  retval bool;
begin
    if auth_role = 'service_role' then
        if jwt_is_expired() then
            raise exception 'invalid_jwt' using hint = 'jwt is expired or missing';
        else
            return true;
        end if;
    elsif auth_role = 'authenticated' then
        if jwt_is_expired() then
            raise exception 'invalid_jwt' using hint = 'jwt is expired or missing';
        end if;
        select coalesce(get_user_claims() ? group_id::text,
            false
          ) into retval;
        return retval;
    elsif auth_role = 'anon' then
        return false;
    else -- not a user session, probably being called from a trigger or something
      if session_user = 'postgres' then
        return true;
      else -- such as 'authenticator'
        return false;
      end if;
    end if;
end;
$function$;