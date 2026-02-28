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
using (is_member(id));

create policy "Authenticated can create"
on rbac.groups
as permissive
for insert
to authenticated
with check (true);

create policy "Has update permission"
on rbac.groups
as permissive
for update
to authenticated
using (has_role(id, 'group.update'::text))
with check (has_role(id, 'group.update'::text));

create policy "Has delete permission"
on rbac.groups
as permissive
for delete
to authenticated
using (has_role(id, 'group.delete'::text));

-- ── members ─────────────────────────────────────────────────────────────────

create policy "Has read permission"
on rbac.members
as permissive
for select
to authenticated
using (has_role(group_id, 'group_user.read'::text));

create policy "Has create permission"
on rbac.members
as permissive
for insert
to authenticated
with check (has_role(group_id, 'group_user.create'::text));

create policy "Has update permission"
on rbac.members
as permissive
for update
to authenticated
using (has_role(group_id, 'group_user.update'::text))
with check (has_role(group_id, 'group_user.update'::text));

create policy "Has delete permission"
on rbac.members
as permissive
for delete
to authenticated
using (has_role(group_id, 'group_user.delete'::text));

-- ── invites ─────────────────────────────────────────────────────────────────

create policy "Has invite permission"
on rbac.invites
as permissive
for all
to authenticated
using (has_role(group_id, 'group_user.invite'::text))
with check (has_role(group_id, 'group_user.invite'::text));

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

-- ── user_claims ─────────────────────────────────────────────────────────────
-- The trigger (_sync_member_metadata) fires as `postgres` when called from
-- SECURITY DEFINER RPCs (create_group, accept_invite) and as `authenticated`
-- when called from SECURITY INVOKER RPCs (add_member, remove_member,
-- update_member_roles). The authenticated role needs INSERT/UPDATE to allow
-- the trigger to upsert claims for any user_id, not just auth.uid().
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

create policy "Allow authenticated to insert claims"
on rbac.user_claims
as permissive
for insert
to authenticated
with check (true);

create policy "Allow authenticated to update claims"
on rbac.user_claims
as permissive
for update
to authenticated
using (true)
with check (true);
