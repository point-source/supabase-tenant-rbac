-- Allow authenticated group members with the "admin" role to perform CRUD operations on group_invites
create policy "Admins can CRUD"
on "public"."group_invites"
as permissive
for all
to authenticated
using (user_has_group_role(group_id, 'admin'::text))
with check (user_has_group_role(group_id, 'admin'::text));

-- Allow authenticated group members with the "admin" role to perform CRUD operations on group_users
create policy "Admins can CRUD"
on "public"."group_users"
as permissive
for all
to authenticated
using (user_has_group_role(group_id, 'admin'::text))
with check (user_has_group_role(group_id, 'admin'::text));

-- Allow authenticated group members with any role to read group_users
create policy "Members can read"
on "public"."group_users"
as permissive
for select
to authenticated
using (user_is_group_member(group_id));

-- Allow authenticated group members with the "admin" role to perform UPDATE operations on groups
create policy "Admins can update"
on "public"."groups"
as permissive
for update
to authenticated
using (user_has_group_role(id, 'admin'::text));

-- Allow authenticated users to perform INSERT operations on groups (no previous group membership required)
create policy "Authenticated can insert"
on "public"."groups"
as permissive
for insert
to authenticated
with check (true);

-- Allow authenticated group members with any role to read groups
create policy "Members can read"
on "public"."groups"
as permissive
for all
to authenticated
using (user_is_group_member(id));

-- Allow authenticated group members with the "owner" role to perform DELETE operations on groups
create policy "Owners can delete"
on "public"."groups"
as permissive
for delete
to authenticated
using (user_has_group_role(id, 'owner'::text));



