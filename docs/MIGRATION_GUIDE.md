# Migration Guide: v4.x to v5.0.0

This guide covers migrating from any v4.x release of Supabase Tenant RBAC to v5.0.0. There is no automated upgrade path — the changes are too extensive. Migration requires data export, extension reinstall, and re-import.

## Table of Contents

1. [Breaking Changes Summary](#breaking-changes-summary)
2. [Key Differences](#key-differences)
3. [Migration Procedure](#migration-procedure)
4. [Permission Name Mapping](#permission-name-mapping)
5. [RLS Policy Updates](#rls-policy-updates)
6. [Common Issues](#common-issues)

---

## Breaking Changes Summary

| What changed | v4.x behavior | v5.0.0 behavior |
|-------------|---------------|-----------------|
| Schema | Tables in `public` | Tables in `rbac` (private, not REST-exposed) |
| Table name | `group_users` | `members` |
| Table name | `group_invites` | `invites` |
| Membership model | One row per user-group-**role** | One row per user-group; `roles text[]` |
| Claims storage | `auth.users.raw_app_meta_data` | `rbac.user_claims` table |
| Claims format | `{"groups": {"<uuid>": ["role1"]}}` | `{"<uuid>": {"roles": [...], "permissions": [...], "grantable_roles": [...], "grantable_permissions": [...]}}` |
| RLS helper | `user_has_group_role(uuid, text)` | `has_role(uuid, text)` |
| RLS helper | `user_is_group_member(uuid)` | `is_member(uuid)` |
| RLS helper | `user_has_any_group_role(uuid, text[])` | `has_any_role(uuid, text[])` |
| RLS helper | `user_has_all_group_roles(uuid, text[])` | `has_all_roles(uuid, text[])` |
| RLS helper | `get_user_claims()` | `get_claims()` |
| Group creation | Direct `INSERT` into `groups` + `group_users` | `create_group()` RPC |
| Invite acceptance | `accept_group_invite(uuid)` | `accept_invite(uuid)` |
| Role validation | No validation | All role names validated against `rbac.roles` |
| Permission validation | No validation | All permission strings validated against `rbac.permissions` |
| Privilege escalation | No built-in prevention | Enforced in `add_member`, `update_member_roles`, `create_invite`, `grant_member_permission` |
| Public wrappers | Auto-created | Opt-in via `examples/setup/create_public_wrappers.sql` |

---

## Key Differences

**Private schema architecture.** In v4.x, tables were in the `public` schema and directly accessible via the REST API. In v5.0.0, all tables are in the `rbac` schema, which should not be listed in `db_schemas`. All access goes through RPCs. This is the most significant behavioral change.

**New tables.** v5.0.0 adds two tables that do not exist in v4.x:
- `rbac.permissions` — canonical registry of all permission strings
- `rbac.member_permissions` — direct per-member permission overrides

**New claims format.** The v4.x claims format stored roles only: `{"groups": {"<uuid>": ["role1", "role2"]}}`. The v5.0.0 format is richer and nested differently: `{"<uuid>": {"roles": [...], "permissions": [...], "grantable_roles": [...], "grantable_permissions": [...]}}`. Any code that reads claims from the JWT or from the database must be updated.

**New permission model.** v5.0.0 introduces a first-class permission layer. Roles carry a `permissions text[]` column. RLS policies can check resolved permissions (`has_permission()`) rather than role names. All permission strings must be registered in `rbac.permissions` before use.

**Built-in escalation prevention.** v4.x had no mechanism to prevent a group member from assigning a role they didn't hold. In v5.0.0, `add_member()`, `update_member_roles()`, and `create_invite()` all check the caller's `grantable_roles` before proceeding. This requires defining `grantable_roles` on your roles when you create them.

---

## Migration Procedure

### Step 1: Export v4.x Data

Before doing anything else, export your existing data. Run these queries in your Supabase SQL editor or psql:

```sql
-- Export groups
COPY (
    SELECT id, name, metadata, created_at
    FROM public.groups
) TO '/tmp/groups_export.csv' CSV HEADER;

-- Export group_users (one row per user-group-role in v4.x)
-- We'll need to collapse these into arrays in Step 6
COPY (
    SELECT group_id, user_id, role, metadata, created_at
    FROM public.group_users
) TO '/tmp/group_users_export.csv' CSV HEADER;

-- Export invites
COPY (
    SELECT id, group_id, role, invited_by, user_id, accepted_at, expires_at, created_at
    FROM public.group_invites
) TO '/tmp/invites_export.csv' CSV HEADER;
```

Alternatively, use the Supabase dashboard to export each table as CSV.

### Step 2: Record Your Role Strings

Query the distinct roles in use:

```sql
SELECT DISTINCT role FROM public.group_users ORDER BY role;
```

Save this list. You will re-register these roles in v5.0.0's `rbac.roles` table in Step 5.

### Step 3: Drop v4.x Extension

```sql
DROP EXTENSION "pointsource-supabase_rbac" CASCADE;
```

The `CASCADE` removes all functions, triggers, and tables created by the extension. The data was exported in Step 1.

Verify the tables are gone:
```sql
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public'
AND table_name IN ('groups', 'group_users', 'group_invites');
-- Should return 0 rows
```

### Step 4: Install v5.x

```sql
-- Install dbdev if not already installed
SELECT dbdev.install('pointsource-supabase_rbac');

-- Create extension in private schema (use the latest 5.x version)
CREATE EXTENSION "pointsource-supabase_rbac"
    SCHEMA rbac
    VERSION '5.1.0';
```

### Step 5: Register Permissions and Define Roles

Before importing data, register your permissions and create your roles. This must happen before member data is imported because `add_member()` and the membership triggers validate against these tables.

```sql
-- Register permissions (use service_role or postgres)
SELECT rbac.create_permission('group.update', 'Update group metadata');
SELECT rbac.create_permission('group.delete', 'Delete the group');
SELECT rbac.create_permission('members.manage', 'Add, remove, and update members');
SELECT rbac.create_permission('members.invite', 'Create invites');
SELECT rbac.create_permission('data.read', 'Read group data');
SELECT rbac.create_permission('data.write', 'Create and modify group data');
-- Add all permissions your application uses

-- Create roles with permissions and grantable_roles
-- Adjust to match your application's role model
SELECT rbac.create_role(
    'owner',
    'Full control',
    ARRAY['group.update', 'group.delete', 'members.manage', 'members.invite', 'data.read', 'data.write'],
    ARRAY['*']  -- owners can grant any role
);

SELECT rbac.create_role(
    'admin',
    'Manage members and data',
    ARRAY['group.update', 'members.manage', 'members.invite', 'data.read', 'data.write'],
    ARRAY['editor', 'viewer']
);

SELECT rbac.create_role(
    'editor',
    'Create and edit content',
    ARRAY['data.read', 'data.write'],
    ARRAY['viewer']
);

SELECT rbac.create_role(
    'viewer',
    'Read-only access',
    ARRAY['data.read'],
    ARRAY[]::text[]
);
```

### Step 6: Import Groups

```sql
-- Import groups from export
-- Adjust the CSV path as needed
INSERT INTO rbac.groups (id, name, metadata, created_at)
SELECT
    id,
    -- v4.x stored name in metadata->>'name' if there was no name column
    -- adjust this depending on your v4.x schema
    COALESCE(metadata->>'name', 'Unnamed Group') AS name,
    metadata,
    created_at
FROM (VALUES
    -- paste your CSV data here as VALUES, or use a temp table
) AS t(id, metadata, created_at);
```

If importing from a temp table:

```sql
CREATE TEMP TABLE groups_import (
    id uuid,
    name text,
    metadata jsonb,
    created_at timestamptz
);

-- Load your CSV data into groups_import
-- Then:
INSERT INTO rbac.groups (id, name, metadata, created_at)
SELECT id, name, metadata, created_at FROM groups_import;
```

### Step 7: Import Members

v4.x had one row per user-group-role. v5.0.0 has one row per user-group with a `roles text[]` array. Collapse using `array_agg`:

```sql
CREATE TEMP TABLE group_users_import (
    group_id uuid,
    user_id uuid,
    role text,
    metadata jsonb,
    created_at timestamptz
);

-- Load your CSV data into group_users_import
-- Then collapse and import:
INSERT INTO rbac.members (group_id, user_id, roles, metadata, created_at)
SELECT
    group_id,
    user_id,
    array_agg(DISTINCT role) AS roles,
    -- use the most recent metadata row, or merge as needed
    (array_agg(metadata ORDER BY created_at DESC))[1] AS metadata,
    min(created_at) AS created_at
FROM group_users_import
GROUP BY group_id, user_id;
```

After import, verify the member counts match your expectations:

```sql
SELECT COUNT(*) FROM rbac.members;
SELECT COUNT(DISTINCT (group_id, user_id)) FROM group_users_import; -- should match
```

### Step 8: Import Invites (Optional)

Only import pending (unaccepted) invites. Accepted invites can be left behind.

```sql
INSERT INTO rbac.invites (id, group_id, roles, invited_by, user_id, accepted_at, expires_at, created_at)
SELECT
    id,
    group_id,
    ARRAY[role],  -- v4.x stored a single role per invite; wrap in array
    invited_by,
    user_id,
    accepted_at,
    expires_at,
    created_at
FROM group_invites_import
WHERE accepted_at IS NULL;  -- only pending invites
```

### Step 9: Add RLS Policies

Apply RLS policies for all rbac tables. The quickstart policies are a good starting point:

```sql
\i examples/policies/quickstart.sql
```

Then add RLS to your application tables (see [RLS Policy Updates](#rls-policy-updates) below).

### Step 10: Register db_pre_request

If not already done at extension install:

```sql
ALTER ROLE authenticator SET pgrst.db_pre_request TO 'rbac.db_pre_request';
NOTIFY pgrst, 'reload config';
```

Verify by making an API request and checking that `rbac.user_claims` has rows for users who have memberships.

---

## Permission Name Mapping

v4.x used role names directly in RLS policies. v5.0.0 separates roles from permissions. Here is a suggested mapping from common v4.x role names to v5.0.0 permissions:

| v4.x role name (used as permission) | Suggested v5.0.0 permission |
|-------------------------------------|------------------------------|
| `owner` | `group.delete` + `members.manage` + `data.write` |
| `admin` | `members.manage` + `data.write` |
| `editor` | `data.write` |
| `viewer` | `data.read` |
| `group.update` | `group.update` |
| `group.delete` | `group.delete` |
| `group_data.read` | `data.read` |
| `group_data.write` | `data.write` |
| `group_user.create` | `members.manage` |
| `group_user.update` | `members.manage` |
| `group_user.delete` | `members.manage` |
| `group_user.invite` | `members.invite` |

These are suggestions. The naming convention is yours to define — choose names that fit your application domain. The dot-notation is a useful organizing convention but is not interpreted by the extension.

---

## RLS Policy Updates

### Before (v4.x)

```sql
-- v4.x: functions in public schema, role-only checks
CREATE POLICY "admins can update"
ON public.projects
FOR UPDATE TO authenticated
USING (user_has_group_role(group_id, 'admin'));

CREATE POLICY "members can read"
ON public.projects
FOR SELECT TO authenticated
USING (user_is_group_member(group_id));
```

### After (v5.0.0)

```sql
-- v5.0.0: schema-qualified (or via public wrappers), permission-centric
CREATE POLICY "admins can update"
ON public.projects
FOR UPDATE TO authenticated
USING (rbac.has_permission(group_id, 'data.write'));

CREATE POLICY "members can read"
ON public.projects
FOR SELECT TO authenticated
USING (rbac.is_member(group_id));
```

Function name changes:

| v4.x | v5.0.0 |
|------|--------|
| `user_has_group_role(uuid, text)` | `rbac.has_role(uuid, text)` |
| `user_is_group_member(uuid)` | `rbac.is_member(uuid)` |
| `user_has_any_group_role(uuid, text[])` | `rbac.has_any_role(uuid, text[])` |
| `user_has_all_group_roles(uuid, text[])` | `rbac.has_all_roles(uuid, text[])` |
| `get_user_claims()` | `rbac.get_claims()` |

If you ran `examples/setup/create_public_wrappers.sql`, the `rbac.` prefix is optional — `has_role(...)`, `is_member(...)`, etc. resolve to the public wrappers.

**Recommended approach:** Migrate role-centric policies to permission-centric policies. Instead of checking whether a user is an `admin`, check whether they have the `data.write` permission. This decouples your RLS policies from your role names, making it easier to add new roles in the future without updating policies.

---

## Common Issues

**"role X does not exist" error when importing members.**
All role names in `members.roles[]` must exist in `rbac.roles` before importing. Ensure Step 5 is complete and covers all roles in your export.

**"permission X does not exist" error when creating roles.**
All permission strings in `roles.permissions[]` must exist in `rbac.permissions` before the role is created. Check that `create_permission()` was called for each permission in Step 5.

**`user_claims` is empty after member import.**
Each INSERT into `rbac.members` triggers `_sync_member_metadata()`, which upserts into `user_claims`. If `user_claims` is empty after import, check that the trigger exists:
```sql
SELECT trigger_name FROM information_schema.triggers
WHERE event_object_schema = 'rbac'
AND event_object_table = 'members';
-- Should show: on_change_sync_member_metadata
```

**REST API calls fail with 404 on rbac functions.**
The `rbac` schema is private by default. Either schema-qualify calls (`rbac.function_name`) or run `examples/setup/create_public_wrappers.sql` to create public wrappers and set `db_schemas` to include `public`.

**Claims in JWT do not match current memberships.**
JWT claims are frozen at token-creation time. Use `db_pre_request` for fresh server-side claims (it is registered automatically). The JWT claims from `custom_access_token_hook` are always one token-lifetime behind.

**Existing RLS policies using `current_setting('request.jwt.claims')` directly.**
v4.x code that read raw JWT claims directly must be rewritten to use `rbac.get_claims()` or the specific helpers. The claims format changed substantially between v4.x and v5.0.0.
