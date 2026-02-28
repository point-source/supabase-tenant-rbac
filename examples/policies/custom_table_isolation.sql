-- Example: Row-Level Security for a custom application table
--
-- The most common use case: you have an application table with a group_id
-- column and want to restrict access based on group membership or specific roles.
--
-- Assumes the extension is installed in the 'rbac' schema with public wrappers.

-- ──────────────────────────────────────────────────────────────────────────────
-- Table definition
-- ──────────────────────────────────────────────────────────────────────────────

create table "public"."projects" (
  "id"         uuid not null default gen_random_uuid(),
  "group_id"   uuid not null references rbac.groups(id) on delete cascade,
  "name"       text not null,
  "data"       jsonb not null default '{}'::jsonb,
  "created_at" timestamp with time zone not null default now(),
  "updated_at" timestamp with time zone not null default now()
);

alter table "public"."projects" enable row level security;

-- ──────────────────────────────────────────────────────────────────────────────
-- Option A: Role-centric policies
--
-- Use this when your app has a small set of named roles (owner / admin / viewer)
-- in the members.roles array.
-- ──────────────────────────────────────────────────────────────────────────────

create policy "Members can read projects"
on "public"."projects"
as permissive
for select
to authenticated
using (is_member(group_id));

-- has_any_role() replaces two separate has_role() calls with OR.
create policy "Admins can write projects"
on "public"."projects"
as permissive
for insert
to authenticated
with check (has_any_role(group_id, ARRAY['owner', 'admin']));

create policy "Admins can update projects"
on "public"."projects"
as permissive
for update
to authenticated
using (has_any_role(group_id, ARRAY['owner', 'admin']))
with check (has_any_role(group_id, ARRAY['owner', 'admin']));

create policy "Owners can delete projects"
on "public"."projects"
as permissive
for delete
to authenticated
using (has_role(group_id, 'owner'));

-- ──────────────────────────────────────────────────────────────────────────────
-- Option B: Permission-centric policies
--
-- Use this when you want fine-grained control via dot-notation permission strings
-- in the members.roles array.
-- ──────────────────────────────────────────────────────────────────────────────

create policy "Has project read permission"
on "public"."projects"
as permissive
for select
to authenticated
using (has_role(group_id, 'project.read'));

create policy "Has project write permission (insert)"
on "public"."projects"
as permissive
for insert
to authenticated
with check (has_role(group_id, 'project.write'));

create policy "Has project write permission (update)"
on "public"."projects"
as permissive
for update
to authenticated
using (has_role(group_id, 'project.write'))
with check (has_role(group_id, 'project.write'));

create policy "Has project delete permission"
on "public"."projects"
as permissive
for delete
to authenticated
using (has_role(group_id, 'project.delete'));
