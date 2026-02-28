-- Example: Role-centric RLS policies using named roles (owner, admin, viewer)
--
-- Assumes the extension is installed in the 'rbac' schema with public wrappers.
-- The unqualified function names (has_role, is_member) resolve to public wrappers.

-- Allow authenticated group members with the "admin" role to perform CRUD operations on invites
create policy "Admins can CRUD"
on rbac.invites
as permissive
for all
to authenticated
using (has_role(group_id, 'admin'::text))
with check (has_role(group_id, 'admin'::text));

-- Allow authenticated group members with the "admin" role to perform CRUD operations on members
create policy "Admins can CRUD"
on rbac.members
as permissive
for all
to authenticated
using (has_role(group_id, 'admin'::text))
with check (has_role(group_id, 'admin'::text));

-- Allow authenticated group members with any role to read members
create policy "Members can read"
on rbac.members
as permissive
for select
to authenticated
using (is_member(group_id));

-- Allow authenticated group members with the "admin" role to update groups
create policy "Admins can update"
on rbac.groups
as permissive
for update
to authenticated
using (has_role(id, 'admin'::text));

-- Allow authenticated users to create groups (no previous membership required)
create policy "Authenticated can insert"
on rbac.groups
as permissive
for insert
to authenticated
with check (true);

-- Allow authenticated group members with any role to read groups
create policy "Members can read"
on rbac.groups
as permissive
for select
to authenticated
using (is_member(id));

-- Allow authenticated group members with the "owner" role to delete groups
create policy "Owners can delete"
on rbac.groups
as permissive
for delete
to authenticated
using (has_role(id, 'owner'::text));
