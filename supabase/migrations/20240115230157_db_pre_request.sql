drop policy "Allow group admins to modify" on "public"."sensitive_data";

drop policy "Allow group member to read" on "public"."sensitive_data";

create policy "Allow group admins to modify" on "public"."sensitive_data" as permissive for all to authenticated using (
    jwt_has_group_role (owned_by_group, 'admin'::text)
)
with
    check (
        jwt_has_group_role (owned_by_group, 'admin'::text)
    );

create policy "Allow group member to read" on "public"."sensitive_data" as permissive for
select
    to authenticated using (jwt_is_group_member (owned_by_group));