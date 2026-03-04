-- ─────────────────────────────────────────────────────────────────────────────
-- RLS policies for the RBAC extension tables (installed in the rbac schema).
-- These are the starter policies used by the local dev environment.
-- ─────────────────────────────────────────────────────────────────────────────

-- ── groups ──────────────────────────────────────────────────────────────────

create policy "Members can read"
on rbac.groups
as permissive
for select
to authenticated
using (rbac.is_member(id));

-- NOTE: No INSERT policy — group creation goes through create_group() RPC
-- (SECURITY DEFINER), which bypasses RLS. Direct INSERTs are not supported.

create policy "Has update permission"
on rbac.groups
as permissive
for update
to authenticated
using (rbac.has_permission(id, 'group.update'::text))
with check (rbac.has_permission(id, 'group.update'::text));

create policy "Has delete permission"
on rbac.groups
as permissive
for delete
to authenticated
using (rbac.has_permission(id, 'group.delete'::text));

-- ── members ─────────────────────────────────────────────────────────────────

create policy "Has read permission"
on rbac.members
as permissive
for select
to authenticated
using (rbac.has_permission(group_id, 'group_user.read'::text));

create policy "Has create permission"
on rbac.members
as permissive
for insert
to authenticated
with check (rbac.has_permission(group_id, 'group_user.create'::text));

create policy "Has update permission"
on rbac.members
as permissive
for update
to authenticated
using (rbac.has_permission(group_id, 'group_user.update'::text))
with check (rbac.has_permission(group_id, 'group_user.update'::text));

create policy "Has delete permission"
on rbac.members
as permissive
for delete
to authenticated
using (rbac.has_permission(group_id, 'group_user.delete'::text));

-- ── invites ─────────────────────────────────────────────────────────────────

create policy "Has invite permission"
on rbac.invites
as permissive
for all
to authenticated
using (rbac.has_permission(group_id, 'group_user.invite'::text))
with check (rbac.has_permission(group_id, 'group_user.invite'::text));

-- ── roles ───────────────────────────────────────────────────────────────────

create policy "Authenticated can read roles"
on rbac.roles
as permissive
for select
to authenticated
using (true);

create policy "Service role can manage roles"
on rbac.roles
as permissive
for all
to service_role
using (true)
with check (true);

-- ── member_permissions ──────────────────────────────────────────────────────

create policy "Has read permission"
on rbac.member_permissions
as permissive
for select
to authenticated
using (rbac.is_member(group_id));

create policy "Has manage_access permission"
on rbac.member_permissions
as permissive
for all
to authenticated
using (rbac.has_permission(group_id, 'group.manage_access'::text))
with check (rbac.has_permission(group_id, 'group.manage_access'::text));

create policy "Service role has full access"
on rbac.member_permissions
as permissive
for all
to service_role
using (true)
with check (true);

-- ── user_claims ─────────────────────────────────────────────────────────────
-- Claims are written exclusively by the three SECURITY DEFINER trigger functions
-- (_sync_member_metadata, _sync_member_permission, _on_role_permissions_change).
-- Those triggers run as the function owner (postgres), not the calling role, so
-- authenticated does NOT need INSERT/UPDATE on this table.
-- SELECT is needed for _get_user_groups() fallback (Storage RLS path).

create policy "Allow select for authenticator and auth admin"
on rbac.user_claims
as permissive
for select
to authenticator, supabase_auth_admin
using (true);

create policy "Allow all for service_role"
on rbac.user_claims
as permissive
for all
to service_role
using (true);

create policy "Allow users to read own claims"
on rbac.user_claims
as permissive
for select
to authenticated
using (user_id = auth.uid());
