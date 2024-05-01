create table
  "groups" (
    "id" uuid not null default gen_random_uuid (),
    "name" text not null default ''::text,
    "created_at" timestamp with time zone not null default now()
  );

create table
  "group_users" (
    "id" uuid not null default gen_random_uuid (),
    "group_id" uuid not null,
    "user_id" uuid not null,
    "role" text not null default ''::text,
    "created_at" timestamp with time zone default now()
  );

create table
  "group_invites" (
    "id" uuid not null default uuid_generate_v4 (),
    "group_id" uuid not null,
    "roles" text[] not null default '{}'::text[] check (cardinality(roles) > 0),
    "invited_by" uuid not null,
    "created_at" timestamp with time zone not null default now(),
    "user_id" uuid,
    "accepted_at" timestamp with time zone
  );

CREATE UNIQUE INDEX group_pkey ON "groups" USING btree (id);

CREATE UNIQUE INDEX group_users_group_id_idx ON group_users USING btree (group_id, user_id, role);

CREATE UNIQUE INDEX group_users_pkey ON group_users USING btree (id);

CREATE UNIQUE INDEX group_invites_pkey ON group_invites USING btree (id);

alter table "groups"
add constraint "group_pkey" PRIMARY KEY using index "group_pkey";

alter table "group_users"
add constraint "group_users_pkey" PRIMARY KEY using index "group_users_pkey";

alter table "group_users"
add constraint "group_users_group_id_fkey" FOREIGN KEY (group_id) REFERENCES "groups" (id) not valid;

alter table "group_users" validate constraint "group_users_group_id_fkey";

alter table "group_users"
add constraint "group_users_user_id_fkey" FOREIGN KEY (user_id) REFERENCES auth.users (id) not valid;

alter table "group_users" validate constraint "group_users_user_id_fkey";

alter table "group_invites"
add constraint "group_invites_pkey" PRIMARY KEY using index "group_invites_pkey";

alter table "group_invites"
add constraint "group_invites_invited_by_fkey" FOREIGN KEY ("invited_by") REFERENCES auth.users (id) not valid;

alter table "group_invites" validate constraint "group_invites_invited_by_fkey";

alter table "group_invites"
add constraint "group_invites_group_id_fkey" FOREIGN KEY ("group_id") REFERENCES groups (id) not valid;

alter table "group_invites" validate constraint "group_invites_group_id_fkey";

alter table "group_invites"
add constraint "group_invites_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES auth.users (id) not valid;

alter table "group_invites" validate constraint "group_invites_user_id_fkey";

alter table "group_invites" enable row level security;

create or replace view
  "user_roles"
WITH
  (security_invoker) as
SELECT
  gu.id,
  g.name AS group_name,
  gu.role,
  u.email,
  gu.group_id,
  gu.user_id
FROM
  (
    (
      group_users gu
      JOIN auth.users u ON ((u.id = gu.user_id))
    )
    JOIN "groups" g ON ((g.id = gu.group_id))
  );

CREATE
OR REPLACE FUNCTION delete_group_users () RETURNS trigger LANGUAGE plpgsql AS $function$ BEGIN
    DELETE from format('%I.group_users', current_schema()) WHERE id = OLD.id;
    RETURN NULL;
END;
$function$;

create
or replace function db_pre_request () returns void language plpgsql stable security definer as $function$
declare
    groups jsonb;
begin
    -- Set the search_path to the specific schema and 'public'
    EXECUTE 'SET search_path = ' || quote_ident(current_schema()) || ', public';

    -- get current groups from auth.users
    select raw_app_meta_data->'groups' from auth.users into groups where id = auth.uid();
    -- store it in the request object
    perform set_config('request.groups'::text, groups::text, false /* applies to transaction if true, session if false */);
end;
$function$;

create
or replace function get_user_claims () returns jsonb language sql stable as $function$ 
select coalesce(current_setting('request.groups', true)::jsonb, auth.jwt()->'app_metadata'->'groups')::jsonb
$function$;

create
or replace function user_has_group_role (group_id uuid, group_role text) returns boolean language plpgsql stable as $function$
declare retval bool;
begin
    if auth.role() = 'authenticated' then
        if jwt_is_expired() then
            raise exception 'invalid_jwt' using hint = 'jwt is expired or missing';
        end if;
        select coalesce(get_user_claims()->group_id::text ? group_role,
            false
          ) into retval;
        return retval;
    else -- not a user session, probably being called from a trigger or something
      if session_user = 'postgres' then
        return true;
      else
        return false;
      end if;
    end if;
end;
$function$;

create
or replace function user_is_group_member (group_id uuid) returns boolean language plpgsql stable as $function$
declare retval bool;
begin
    if auth.role() = 'authenticated' then
        if jwt_is_expired() then
            raise exception 'invalid_jwt' using hint = 'jwt is expired or missing';
        end if;
        select coalesce(get_user_claims() ? group_id::text,
            false
          ) into retval;
        return retval;
    else -- not a user session, probably being called from a trigger or something
      if session_user = 'postgres' then
        return true;
      else
        return false;
      end if;
    end if;
end;
$function$;

create
or replace function jwt_is_expired () returns boolean language plpgsql stable as $function$ begin
  return extract(epoch from now()) > coalesce(auth.jwt()->>'exp', '0')::numeric;
end;
$function$;

CREATE
OR REPLACE FUNCTION update_user_roles () RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $function$
DECLARE
  _group_id UUID = COALESCE(new.group_id, old.group_id);
  _group_id_old UUID = COALESCE(old.group_id, new.group_id);
  _user_id UUID = COALESCE(new.user_id, old.user_id);
  _user_id_old UUID = COALESCE(old.user_id, new.user_id);
BEGIN
  -- Set the search_path to the specific schema and 'public'
  EXECUTE 'SET search_path = ' || quote_ident(current_schema()) || ', public';

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
             FROM current_schema().group_users gu
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

CREATE
OR REPLACE FUNCTION set_group_owner () RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $function$
	begin
    -- Set the search_path to the specific schema and 'public'
    EXECUTE 'SET search_path = ' || quote_ident(current_schema()) || ', public';

		IF auth.uid() IS not NULL THEN 
		insert into current_schema().group_users(group_id, user_id, role) values(new.id, auth.uid(), 'owner');
		end if;
		return new;
	end;
$function$;

CREATE
OR REPLACE FUNCTION add_group_user_by_email (user_email text, gid uuid, group_role text) RETURNS text LANGUAGE plpgsql SECURITY DEFINER AS $function$
	declare
		uid uuid = auth.uid();
		recipient_id uuid;
		new_record_id uuid;
	BEGIN
    -- Set the search_path to the specific schema and 'public'
    EXECUTE 'SET search_path = ' || quote_ident(current_schema()) || ', public';

		if uid is null then
			raise exception 'not_authorized' using hint = 'You are are not authorized to perform this action';
		end if;
	
		if not exists(select id from current_schema().group_users gu where gu.user_id = uid AND gu.group_id = gid AND gu.role = 'owner') then
			raise exception 'not_authorized' using hint = 'You are are not authorized to perform this action';
		end if;
	
		select u.id from auth.users u into recipient_id where u.email = user_email;
	
		if recipient_id is null then
			raise exception 'failed_to_add_user' using hint = 'User could not be added to group';
		end if;
	
		INSERT INTO current_schema().group_users (group_id, user_id, role) VALUES (gid, recipient_id, group_role) returning id into new_record_id;
	
		return new_record_id;
	exception
		when unique_violation then
			raise exception 'failed_to_add_user' using hint = 'User could not be added to group';
	END;
$function$;

-- Enable the db_pre_request hook for the authenticator role
ALTER ROLE authenticator
SET
  pgrst.db_pre_request TO 'db_pre_request';

NOTIFY pgrst,
'reload config';

CREATE TRIGGER on_change_update_user_metadata
AFTER INSERT
OR DELETE
OR
UPDATE ON group_users FOR EACH ROW
EXECUTE FUNCTION update_user_roles ();

CREATE TRIGGER on_delete_user INSTEAD OF DELETE ON user_roles FOR EACH ROW
EXECUTE FUNCTION delete_group_users ();

CREATE TRIGGER on_insert_set_group_owner
AFTER INSERT ON groups FOR EACH ROW
EXECUTE FUNCTION set_group_owner ();

alter table "group_users" enable row level security;

alter table "groups" enable row level security;

alter table "group_invites" enable row level security;