-- Example: Row-Level Security for a custom application table
--
-- The most common use case: you have an application table with a group_id
-- column and want to restrict access based on group membership or specific roles.
--
-- This example uses a "projects" table, but the same pattern applies to any
-- table that belongs to a group (documents, records, resources, etc.).

-- ──────────────────────────────────────────────────────────────────────────────
-- Table definition
-- ──────────────────────────────────────────────────────────────────────────────

create table "public"."projects" (
  "id"         uuid not null default gen_random_uuid(),
  "group_id"   uuid not null references "public"."groups"(id) on delete cascade,
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
-- assigned directly in group_users.role.
-- ──────────────────────────────────────────────────────────────────────────────

-- Any group member can read projects belonging to their group
create policy "Members can read projects"
on "public"."projects"
as permissive
for select
to authenticated
using (user_is_group_member(group_id));

-- Admins and owners can create or update projects.
-- user_has_any_group_role() (v4.5.0) replaces two separate user_has_group_role()
-- calls in the policy expression, avoiding the OR chain.
create policy "Admins can write projects"
on "public"."projects"
as permissive
for insert
to authenticated
with check (user_has_any_group_role(group_id, ARRAY['owner', 'admin']));

create policy "Admins can update projects"
on "public"."projects"
as permissive
for update
to authenticated
using (user_has_any_group_role(group_id, ARRAY['owner', 'admin']))
with check (user_has_any_group_role(group_id, ARRAY['owner', 'admin']));

-- Only owners can delete projects
create policy "Owners can delete projects"
on "public"."projects"
as permissive
for delete
to authenticated
using (user_has_group_role(group_id, 'owner'));


-- ──────────────────────────────────────────────────────────────────────────────
-- Option B: Permission-centric policies
--
-- Use this when you want fine-grained control via dot-notation permission strings
-- (e.g. "project.read", "project.write", "project.delete") rather than broad
-- role names. Each permission is a separate row in group_users.
--
-- Drop the Option A policies above and use these instead if you prefer this model.
-- ──────────────────────────────────────────────────────────────────────────────

-- Users with the "project.read" permission can select projects
create policy "Has project read permission"
on "public"."projects"
as permissive
for select
to authenticated
using (user_has_group_role(group_id, 'project.read'));

-- Users with the "project.write" permission can insert and update projects
create policy "Has project write permission (insert)"
on "public"."projects"
as permissive
for insert
to authenticated
with check (user_has_group_role(group_id, 'project.write'));

create policy "Has project write permission (update)"
on "public"."projects"
as permissive
for update
to authenticated
using (user_has_group_role(group_id, 'project.write'))
with check (user_has_group_role(group_id, 'project.write'));

-- Users with the "project.delete" permission can delete projects
create policy "Has project delete permission"
on "public"."projects"
as permissive
for delete
to authenticated
using (user_has_group_role(group_id, 'project.delete'));
