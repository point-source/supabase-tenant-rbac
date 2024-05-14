create policy "Has invite permission"
on "public"."group_invites"
as permissive
for all
to authenticated
using (user_has_group_role(group_id, 'group_user.invite'))
with check (user_has_group_role(group_id, 'group_user.invite'));


create policy "Has create permission"
on "public"."group_users"
as permissive
for insert
to authenticated
with check (user_has_group_role(group_id, 'group_user.create'));


create policy "Has delete permission"
on "public"."group_users"
as permissive
for delete
to authenticated
using (user_has_group_role(group_id, 'group_user.delete'));


create policy "Has read permission"
on "public"."group_users"
as permissive
for select
to authenticated
using (user_has_group_role(group_id, 'group_user.read'));


create policy "Has update permission"
on "public"."group_users"
as permissive
for update
to authenticated
using (user_has_group_role(group_id, 'group_user.update'))
with check (user_has_group_role(group_id, 'group_user.update'));


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
using (user_has_group_role(id, 'delete'));


create policy "Has update permission"
on "public"."groups"
as permissive
for update
to authenticated
using (user_has_group_role(id, 'group.update'))
with check (user_has_group_role(id, 'group.update'));


create policy "Members can read"
on "public"."groups"
as permissive
for select
to authenticated
using (user_is_group_member(id));