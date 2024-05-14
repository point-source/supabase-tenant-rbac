create policy "Has invite permission"
on "public"."group_invites"
as permissive
for all
to authenticated
using (user_has_group_role(group_id, 'group_user.invite'::text))
with check (user_has_group_role(group_id, 'group_user.invite'::text));


create policy "Has create permission"
on "public"."group_users"
as permissive
for insert
to authenticated
with check (user_has_group_role(group_id, 'group_user.create'::text));


create policy "Has delete permission"
on "public"."group_users"
as permissive
for delete
to authenticated
using (user_has_group_role(group_id, 'group_user.delete'::text));


create policy "Has read permission"
on "public"."group_users"
as permissive
for select
to authenticated
using (user_has_group_role(group_id, 'group_user.read'::text));


create policy "Has update permission"
on "public"."group_users"
as permissive
for update
to authenticated
using (user_has_group_role(group_id, 'group_user.update'::text))
with check (user_has_group_role(group_id, 'group_user.update'::text));


create policy "Authenticated can create"
on "public"."groups"
as permissive
for insert
to authenticated
with check (true);


create policy "Has delete permission"
on "public"."groups"
as permissive
for delete
to authenticated
using (user_has_group_role(id, 'delete'::text));


create policy "Has update permission"
on "public"."groups"
as permissive
for update
to authenticated
using (user_has_group_role(id, 'group.update'::text))
with check (user_has_group_role(id, 'group.update'::text));


create policy "Members can read"
on "public"."groups"
as permissive
for select
to authenticated
using (user_is_group_member(id));