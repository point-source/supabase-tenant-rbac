create table if not exists
  "groups" (
    "id" uuid not null default gen_random_uuid (),
    "name" text not null default ''::text,
    "created_at" timestamp with time zone not null default now()
  );

create table if not exists
  "group_users" (
    "id" uuid not null default gen_random_uuid (),
    "group_id" uuid not null,
    "user_id" uuid not null,
    "role" text not null default ''::text,
    "created_at" timestamp with time zone default now()
  );

create unique index if not exists group_pkey on "groups" using btree (id);

create unique index if not exists group_users_group_id_idx on group_users using btree (group_id, user_id, role);

create unique index if not exists group_users_pkey on group_users using btree (id);

alter table "groups"
drop constraint if exists "group_pkey";

alter table "groups"
add constraint "group_pkey" primary key using index "group_pkey";

alter table "group_users"
drop constraint if exists "group_users_pkey";

alter table "group_users"
add constraint "group_users_pkey" primary key using index "group_users_pkey";

alter table "group_users"
drop constraint if exists "group_users_group_id_fkey";

alter table "group_users"
add constraint "group_users_group_id_fkey" foreign key (group_id) references "groups" (id) not valid;

alter table "group_users" validate constraint "group_users_group_id_fkey";

alter table "group_users"
drop constraint if exists "group_users_user_id_fkey";

alter table "group_users"
add constraint "group_users_user_id_fkey" foreign key (user_id) references auth.users (id) not valid;

alter table "group_users" validate constraint "group_users_user_id_fkey";

create or replace view
  "user_roles"
with
  (security_invoker) as
select
  gu.id,
  g.name as group_name,
  gu.role,
  u.email,
  gu.group_id,
  gu.user_id
from
  (
    (
      group_users gu
      join auth.users u on ((u.id = gu.user_id))
    )
    join "groups" g on ((g.id = gu.group_id))
  );

create
or replace function delete_group_users () returns trigger language plpgsql as $function$ begin
    delete from group_users where id = old.id;
    return null;
end;
$function$;

create
or replace function has_group_role (group_id uuid, group_role text) returns boolean language plpgsql security definer as $function$
declare retval bool;
begin 
    if session_user = 'authenticator' then 
        if jwt_is_expired() then 
            raise exception 'invalid_jwt' using hint = 'jwt is expired or missing';
        end if;
        select coalesce(
            raw_app_meta_data->'groups'->group_id::text ? group_role,
            false
          )
        from auth.users into retval
        where id = auth.uid();
        return retval;
    else -- not a user session, probably being called from a trigger or something
        return true;
    end if;
end;
$function$;

create
or replace function is_group_member (group_id uuid) returns boolean language plpgsql security definer as $function$
declare retval bool;
begin 
    if session_user = 'authenticator' then
        if jwt_is_expired() then 
            raise exception 'invalid_jwt' using hint = 'jwt is expired or missing';
        end if;
        select coalesce(
            raw_app_meta_data->'groups' ? group_id::text,
            false
          )
        from auth.users into retval
        where id = auth.uid();
        return retval;
    else
        return true;
    end if;
end;
$function$;

create
or replace function jwt_has_group_role (group_id uuid, group_role text) returns boolean language plpgsql as $function$
declare retval bool;
begin
    if session_user = 'authenticator' then
        if jwt_is_expired() then
            raise exception 'invalid_jwt' using hint = 'jwt is expired or missing';
        end if;
        select coalesce(
            coalesce(get_req_groups(), auth.jwt()->'app_metadata'->'groups')->'app_metadata'->'groups'->group_id::text ? group_role,
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
            coalesce(get_req_groups(), auth.jwt()->'app_metadata'->'groups')->'app_metadata'->'groups' ? group_id::text,
            false
          ) into retval;
        return retval;
    else -- not a user session, probably being called from a trigger or something
        return true;
    end if;
end;
$function$;

create
or replace function update_user_roles () returns trigger language plpgsql security definer as $function$
declare
  _group_id uuid = coalesce(new.group_id, old.group_id);
  _group_id_old uuid = coalesce(old.group_id, new.group_id);
  _user_id uuid = coalesce(new.user_id, old.user_id);
  _user_id_old uuid = coalesce(old.user_id, new.user_id);
begin
  -- check if user_id or group_id is changed
  if _group_id is distinct from _group_id_old or _user_id is distinct from _user_id_old then
      raise exception 'changing user_id or group_id is not allowed';
  end if;

  -- update raw_app_meta_data in auth.users
  update auth.users
  set raw_app_meta_data = jsonb_set(
      raw_app_meta_data,
      '{groups}',
      jsonb_strip_nulls(
        jsonb_set(
          coalesce(raw_app_meta_data->'groups', '{}'::jsonb),
          array[_group_id::text],
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

  -- return null (the trigger function requires a return value)
  return null;
end;
$function$;

create
or replace function set_group_owner () returns trigger language plpgsql security definer as $function$
	begin
		if auth.uid() is not null then 
		insert into group_users(group_id, user_id, role) values(new.id, auth.uid(), 'owner');
		end if;
		return new;
	end;
$function$;

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

create
or replace function add_group_user_by_email (user_email text, gid uuid, group_role text) returns text language plpgsql security definer as $function$
	declare
		uid uuid = auth.uid();
		recipient_id uuid;
		new_record_id uuid;
	begin
		if uid is null then
			raise exception 'not_authorized' using hint = 'you are are not authorized to perform this action';
		end if;
	
		if not exists(select id from group_users gu where gu.user_id = uid and gu.group_id = gid and gu.role = 'owner') then
			raise exception 'not_authorized' using hint = 'you are are not authorized to perform this action';
		end if;
	
		select u.id from auth.users u into recipient_id where u.email = user_email;
	
		if recipient_id is null then
			raise exception 'failed_to_add_user' using hint = 'user could not be added to group';
		end if;
	
		insert into group_users (group_id, user_id, role) values (gid, recipient_id, group_role) returning id into new_record_id;
	
		return new_record_id;
	exception
		when unique_violation then
			raise exception 'failed_to_add_user' using hint = 'user could not be added to group';
	end;
$function$;

create
or replace trigger on_change_update_user_metadata
after insert
or delete
or
update on group_users for each row
execute function update_user_roles ();

create
or replace trigger on_delete_user instead of delete on user_roles for each row
execute function delete_group_users ();

create
or replace trigger on_insert_set_group_owner
after insert on groups for each row
execute function set_group_owner ();

alter table "group_users" enable row level security;

alter table "groups" enable row level security;