create table
    "public"."sensitive_data" (
        "id" uuid not null default gen_random_uuid (),
        "data" text not null default ''::text,
        "created_at" timestamp with time zone not null default now(),
        "owned_by_group" uuid not null
    );

alter table "public"."sensitive_data" enable row level security;

CREATE UNIQUE INDEX sensitive_data_pkey ON public.sensitive_data USING btree (id);

alter table "public"."sensitive_data"
add constraint "sensitive_data_pkey" PRIMARY KEY using index "sensitive_data_pkey";

grant delete on table "public"."sensitive_data" to "anon";

grant insert on table "public"."sensitive_data" to "anon";

grant references on table "public"."sensitive_data" to "anon";

grant
select
    on table "public"."sensitive_data" to "anon";

grant trigger on table "public"."sensitive_data" to "anon";

grant
truncate on table "public"."sensitive_data" to "anon";

grant
update on table "public"."sensitive_data" to "anon";

grant delete on table "public"."sensitive_data" to "authenticated";

grant insert on table "public"."sensitive_data" to "authenticated";

grant references on table "public"."sensitive_data" to "authenticated";

grant
select
    on table "public"."sensitive_data" to "authenticated";

grant trigger on table "public"."sensitive_data" to "authenticated";

grant
truncate on table "public"."sensitive_data" to "authenticated";

grant
update on table "public"."sensitive_data" to "authenticated";

grant delete on table "public"."sensitive_data" to "service_role";

grant insert on table "public"."sensitive_data" to "service_role";

grant references on table "public"."sensitive_data" to "service_role";

grant
select
    on table "public"."sensitive_data" to "service_role";

grant trigger on table "public"."sensitive_data" to "service_role";

grant
truncate on table "public"."sensitive_data" to "service_role";

grant
update on table "public"."sensitive_data" to "service_role";

create policy "Allow group admins to modify" on "public"."sensitive_data" as permissive for all to authenticated using (
    user_has_group_role (owned_by_group, 'admin'::text)
)
with
    check (
        user_has_group_role (owned_by_group, 'admin'::text)
    );

create policy "Allow group member to read" on "public"."sensitive_data" as permissive for
select
    to authenticated using (user_is_group_member (owned_by_group));

drop policy "Allow group admins to modify" on "sensitive_data";

drop policy "Allow group member to read" on "sensitive_data";

create policy "Has update permission" on "sensitive_data" as permissive for all to authenticated using (
    user_has_group_role (owned_by_group, 'group_data.update'::text)
)
with
    check (
        user_has_group_role (owned_by_group, 'group_data.update'::text)
    );

create policy "Allow group member to read" on "sensitive_data" as permissive for
select
    to authenticated using (user_is_group_member (owned_by_group));