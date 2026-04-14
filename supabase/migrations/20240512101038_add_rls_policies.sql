-- ─────────────────────────────────────────────────────────────────────────────
-- RLS policies for the RBAC extension tables (installed in the rbac schema).
-- These are the starter policies for the local dev environment.
--
-- STYLE NOTE — Permission-based policies:
-- These policies use has_permission() (e.g., has_permission(id, 'group.update'))
-- rather than has_role() (e.g., has_role(id, 'owner')).
-- Permission-based policies are more granular and support direct member_permissions
-- overrides. The quickstart example (examples/policies/quickstart.sql) shows the
-- simpler role-based style. Both are valid; choose the approach that fits your app.
-- ─────────────────────────────────────────────────────────────────────────────

-- ── groups ──────────────────────────────────────────────────────────────────

create policy "Members can read"
on rbac.groups
as permissive
for select
to authenticated
using (rbac.is_member(id));

-- create_group() is SECURITY INVOKER — an INSERT policy is required for group creation.
-- This policy allows any authenticated user to create groups (adjust for your app).
create policy "Authenticated users can create groups"
on rbac.groups as permissive for insert
to authenticated with check ((select auth.uid()) is not null);

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
using (rbac.is_member(group_id));

create policy "Has manage permission"
on rbac.members
as permissive
for insert
to authenticated
with check (rbac.has_permission(group_id, 'members.manage'::text));

create policy "Has update permission"
on rbac.members
as permissive
for update
to authenticated
using (rbac.has_permission(group_id, 'members.manage'::text))
with check (rbac.has_permission(group_id, 'members.manage'::text));

create policy "Has delete permission"
on rbac.members
as permissive
for delete
to authenticated
using (
    rbac.has_permission(group_id, 'members.manage'::text)
    OR user_id = (select auth.uid())
);

-- ── invites ─────────────────────────────────────────────────────────────────

create policy "Has manage permission"
on rbac.invites
as permissive
for all
to authenticated
using (rbac.has_permission(group_id, 'members.manage'::text))
with check (rbac.has_permission(group_id, 'members.manage'::text));

-- ── roles ───────────────────────────────────────────────────────────────────
-- Role definitions are hidden from authenticated users by default.
-- authenticated has no table-level SELECT on rbac.roles (revoked by extension).

create policy "Service role can manage roles"
on rbac.roles
as permissive
for all
to service_role
using (true)
with check (true);

-- ── permissions ─────────────────────────────────────────────────────────────
-- The permissions registry is managed exclusively by service_role.

create policy "Service role can manage permissions"
on rbac.permissions
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

-- Grant: caller must have the target permission in their grantable_permissions
create policy "Has grantable permission"
on rbac.member_permissions
as permissive
for insert
to authenticated
with check (
    (rbac.get_claims() -> group_id::text -> 'grantable_permissions') ? '*'
    OR (rbac.get_claims() -> group_id::text -> 'grantable_permissions') ? permission
);

-- Revoke: same scope check for delete
create policy "Has grantable permission for revoke"
on rbac.member_permissions
as permissive
for delete
to authenticated
using (
    (rbac.get_claims() -> group_id::text -> 'grantable_permissions') ? '*'
    OR (rbac.get_claims() -> group_id::text -> 'grantable_permissions') ? permission
);

create policy "Service role has full access"
on rbac.member_permissions
as permissive
for all
to service_role
using (true)
with check (true);

-- ── user_claims ─────────────────────────────────────────────────────────────
-- Claims are written exclusively by SECURITY DEFINER trigger functions.
-- authenticated does NOT need INSERT/UPDATE on this table.

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
using (user_id = (select auth.uid()));
