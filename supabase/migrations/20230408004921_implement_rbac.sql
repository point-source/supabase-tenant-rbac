create table "public"."groups" (
  "id" uuid not null default uuid_generate_v4(),
  "name" text not null default ''::text,
  "created_at" timestamp with time zone not null default now()
);
create table "public"."group_users" (
  "id" uuid not null default uuid_generate_v4(),
  "group_id" uuid not null,
  "user_id" uuid not null,
  "role" text not null default ''::text,
  "created_at" timestamp with time zone default now()
);
CREATE UNIQUE INDEX group_pkey ON public."groups" USING btree (id);
CREATE UNIQUE INDEX group_users_group_id_idx ON public.group_users USING btree (group_id, user_id, role);
CREATE UNIQUE INDEX group_users_pkey ON public.group_users USING btree (id);
alter table "public"."groups"
add constraint "group_pkey" PRIMARY KEY using index "group_pkey";
alter table "public"."group_users"
add constraint "group_users_pkey" PRIMARY KEY using index "group_users_pkey";
alter table "public"."group_users"
add constraint "group_users_group_id_fkey" FOREIGN KEY (group_id) REFERENCES "groups"(id) not valid;
alter table "public"."group_users" validate constraint "group_users_group_id_fkey";
alter table "public"."group_users"
add constraint "group_users_user_id_fkey" FOREIGN KEY (user_id) REFERENCES auth.users(id) not valid;
alter table "public"."group_users" validate constraint "group_users_user_id_fkey";
set check_function_bodies = off;
CREATE OR REPLACE FUNCTION public.delete_group_users() RETURNS trigger LANGUAGE plpgsql AS $function$ BEGIN
DELETE from public.group_users
WHERE id = OLD.id;
RETURN NULL;
END;
$function$;
CREATE OR REPLACE FUNCTION public.has_group_role(group_id uuid, group_role text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER AS $function$
DECLARE retval bool;
BEGIN IF session_user = 'authenticator' THEN --------------------------------------------
-- To disallow any authenticated app users
-- from editing claims, delete the following
-- block of code and replace it with:
-- RETURN FALSE;
--------------------------------------------
if jwt_is_expired() then raise exception 'invalid_jwt' USING HINT = 'JWT is expired or missing';
end if;
select coalesce(
    raw_app_meta_data->'groups'->group_id::text ? group_role,
    false
  )
from auth.users into retval
where id = auth.uid();
return retval;
--------------------------------------------
-- End of block 
--------------------------------------------
ELSE -- not a user session, probably being called from a trigger or something
return true;
END IF;
END;
$function$;
CREATE OR REPLACE FUNCTION public.is_group_member(group_id uuid) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER AS $function$
DECLARE retval bool;
begin IF session_user = 'authenticator' THEN --------------------------------------------
-- To disallow any authenticated app users
-- from editing claims, delete the following
-- block of code and replace it with:
-- RETURN FALSE;
--------------------------------------------
if jwt_is_expired() then raise exception 'invalid_jwt' USING HINT = 'JWT is expired or missing';
end if;
select coalesce(
    raw_app_meta_data->'groups' ? group_id::text,
    false
  )
from auth.users into retval
where id = auth.uid();
return retval;
--------------------------------------------
-- End of block 
--------------------------------------------
ELSE -- not a user session, probably being called from a trigger or something
return true;
END IF;
END;
$function$;
CREATE OR REPLACE FUNCTION public.jwt_has_group_role(group_id uuid, group_role text) RETURNS boolean LANGUAGE plpgsql AS $function$
DECLARE retval bool;
BEGIN IF session_user = 'authenticator' THEN --------------------------------------------
-- To disallow any authenticated app users
-- from editing claims, delete the following
-- block of code and replace it with:
-- RETURN FALSE;
--------------------------------------------
if jwt_is_expired() then raise exception 'invalid_jwt' USING HINT = 'JWT is expired or missing';
end if;
select coalesce(
    auth.jwt()->'app_metadata'->'groups'->group_id::text ? group_role,
    false
  ) into retval;
return retval;
--------------------------------------------
-- End of block 
--------------------------------------------
ELSE -- not a user session, probably being called from a trigger or something
return true;
END IF;
END;
$function$;
CREATE OR REPLACE FUNCTION public.jwt_is_expired() RETURNS boolean LANGUAGE plpgsql AS $function$ BEGIN return extract(
    epoch
    from now()
  ) > coalesce(auth.jwt()->>'exp', '0')::numeric;
END;
$function$;
CREATE OR REPLACE FUNCTION public.jwt_is_group_member(group_id uuid) RETURNS boolean LANGUAGE plpgsql AS $function$
DECLARE retval bool;
BEGIN IF session_user = 'authenticator' THEN --------------------------------------------
-- To disallow any authenticated app users
-- from editing claims, delete the following
-- block of code and replace it with:
-- RETURN FALSE;
--------------------------------------------
if jwt_is_expired() then raise exception 'invalid_jwt' USING HINT = 'JWT is expired or missing';
end if;
select coalesce(
    auth.jwt()->'app_metadata'->'groups' ? group_id::text,
    false
  ) into retval;
return retval;
--------------------------------------------
-- End of block 
--------------------------------------------
ELSE -- not a user session, probably being called from a trigger or something
return true;
END IF;
END;
$function$;
CREATE OR REPLACE FUNCTION public.update_user_roles() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $function$
declare _group_id uuid = coalesce(new.group_id, old.group_id);
_user_id uuid = coalesce(new.user_id, old.user_id);
begin
update auth.users
set raw_app_meta_data = jsonb_set(
    raw_app_meta_data,
    '{groups}',
    jsonb_set(
      coalesce(raw_app_meta_data->'groups', '{}'::jsonb),
      array [_group_id::text],
      coalesce(
        (
          select jsonb_agg("role")
          from group_users gu
          where gu.group_id = _group_id
            and gu.user_id = _user_id
        ),
        '[]'::jsonb
      )
    )
  )
where id = _user_id;
return null;
end;
$function$;
create or replace view "public"."user_roles" WITH (security_invoker) as
SELECT gu.id,
  g.name AS group_name,
  gu.role,
  u.email,
  gu.group_id,
  gu.user_id
FROM (
    (
      group_users gu
      JOIN auth.users u ON ((u.id = gu.user_id))
    )
    JOIN "groups" g ON ((g.id = gu.group_id))
  );
CREATE TRIGGER on_change_update_user_metadata
AFTER
INSERT
  OR DELETE
  OR
UPDATE ON public.group_users FOR EACH ROW EXECUTE FUNCTION update_user_roles();
CREATE TRIGGER on_delete_user INSTEAD OF DELETE ON public.user_roles FOR EACH ROW EXECUTE FUNCTION delete_group_users();
alter table "public"."group_users" enable row level security;
alter table "public"."groups" enable row level security;