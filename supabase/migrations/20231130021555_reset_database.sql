drop trigger if exists "on_change_update_user_metadata" on "public"."group_users";

drop trigger if exists "on_insert_set_group_owner" on "public"."groups";

drop trigger if exists "on_delete_user" on "public"."user_roles";

alter table "public"."group_users" drop constraint "group_users_group_id_fkey";

alter table "public"."group_users" drop constraint "group_users_user_id_fkey";

drop function if exists "public"."add_group_user_by_email"(user_email text, gid uuid, group_role text);

drop function if exists "public"."delete_group_users"();

drop function if exists "public"."has_group_role"(group_id uuid, group_role text);

drop function if exists "public"."is_group_member"(group_id uuid);

drop function if exists "public"."jwt_has_group_role"(group_id uuid, group_role text);

drop function if exists "public"."jwt_is_expired"();

drop function if exists "public"."jwt_is_group_member"(group_id uuid);

drop function if exists "public"."set_group_owner"();

drop function if exists "public"."update_user_roles"();

drop view if exists "public"."user_roles";

alter table "public"."group_users" drop constraint "group_users_pkey";

alter table "public"."groups" drop constraint "group_pkey";

drop index if exists "public"."group_pkey";

drop index if exists "public"."group_users_group_id_idx";

drop index if exists "public"."group_users_pkey";

drop table "public"."group_users";

drop table "public"."groups";


