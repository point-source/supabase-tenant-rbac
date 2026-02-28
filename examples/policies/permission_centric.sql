-- Example: Permission-centric RLS policies using dot-notation permission strings
--
-- Assumes the extension is installed in the 'rbac' schema with public wrappers.

create policy "Has invite permission"
on rbac.invites
as permissive
for all
to authenticated
using (has_role(group_id, 'group_user.invite'))
with check (has_role(group_id, 'group_user.invite'));

create policy "Has create permission"
on rbac.members
as permissive
for insert
to authenticated
with check (has_role(group_id, 'group_user.create'));

create policy "Has delete permission"
on rbac.members
as permissive
for delete
to authenticated
using (has_role(group_id, 'group_user.delete'));

create policy "Has read permission"
on rbac.members
as permissive
for select
to authenticated
using (has_role(group_id, 'group_user.read'));

create policy "Has update permission"
on rbac.members
as permissive
for update
to authenticated
using (has_role(group_id, 'group_user.update'))
with check (has_role(group_id, 'group_user.update'));

create policy "Authenticated can create"
on rbac.groups
as permissive
for insert
to authenticated
with check (true);

create policy "Has delete permission"
on rbac.groups
as permissive
for delete
to authenticated
using (has_role(id, 'group.delete'));

create policy "Has update permission"
on rbac.groups
as permissive
for update
to authenticated
using (has_role(id, 'group.update'))
with check (has_role(id, 'group.update'));

create policy "Members can read"
on rbac.groups
as permissive
for select
to authenticated
using (is_member(id));
