# API Reference

Complete reference for all functions in the Supabase Tenant RBAC extension. For conceptual background, see [docs/CONCEPTUAL_MODEL.md](CONCEPTUAL_MODEL.md).

## Table of Contents

1. [RLS Helpers](#rls-helpers)
2. [Group Management](#group-management)
3. [Member Management](#member-management)
4. [Invite System](#invite-system)
5. [Permission Overrides](#permission-overrides)
6. [Role Management (service_role)](#role-management-service_role)
7. [Permission Management (service_role)](#permission-management-service_role)
8. [Hooks](#hooks)

---

## RLS Helpers

These functions are used inside RLS policies on your application tables. They read claims from `request.groups` (set by `db_pre_request`) with a fallback to `user_claims` for Storage requests.

All helpers return `true` for `service_role` and `postgres` (superuser bypass), `false` for `anon`, and raise `invalid_jwt` for expired JWTs when called as `authenticated`.

---

### `get_claims()`

**Signature:** `get_claims() → jsonb`

**INVOKER/DEFINER:** INVOKER

**Required role:** `authenticated`, `service_role`, `anon` (anon always returns `{}`)

**Description:** Returns the full claims JSONB for the current user. The claims object is keyed by group UUID, with each value containing `roles`, `permissions`, `grantable_roles`, and `grantable_permissions` arrays.

**Returns:** JSONB in the format:
```json
{
  "<group-uuid>": {
    "roles": ["editor"],
    "permissions": ["data.read", "data.write"],
    "grantable_roles": ["viewer"],
    "grantable_permissions": ["data.read"]
  }
}
```
Returns `{}` for groupless users or `anon`.

**Escalation check:** No.

**Example:**
```sql
-- View your own claims
SELECT rbac.get_claims();

-- Use in a policy (rarely needed directly; prefer specific helpers)
CREATE POLICY "debug_policy" ON public.my_table
    FOR SELECT TO authenticated
    USING (rbac.get_claims() ? group_id::text);
```

---

### `is_member(group_id uuid)`

**Signature:** `is_member(group_id uuid) → boolean`

**INVOKER/DEFINER:** INVOKER

**Required role:** `authenticated`, `service_role`, `anon` (anon always returns `false`)

**Description:** Returns `true` if the current user has any membership in the specified group. Use this when all members — regardless of role — should have equivalent access.

**Parameters:**
- `group_id uuid` — the group to check membership in

**Returns:** `boolean`

**Escalation check:** No.

**Example:**
```sql
-- All group members can read documents
CREATE POLICY "members can read" ON public.documents
    FOR SELECT TO authenticated
    USING (rbac.is_member(group_id));
```

---

### `has_role(group_id uuid, role text)`

**Signature:** `has_role(group_id uuid, role text) → boolean`

**INVOKER/DEFINER:** INVOKER

**Required role:** `authenticated`, `service_role`, `anon`

**Description:** Returns `true` if the current user holds the specified role in the specified group.

**Parameters:**
- `group_id uuid` — the group to check
- `role text` — the role name to check for

**Returns:** `boolean`

**Escalation check:** No.

**Example:**
```sql
-- Only owners can delete the group
CREATE POLICY "owners can delete" ON rbac.groups
    FOR DELETE TO authenticated
    USING (rbac.has_role(id, 'owner'));
```

---

### `has_any_role(group_id uuid, roles text[])`

**Signature:** `has_any_role(group_id uuid, roles text[]) → boolean`

**INVOKER/DEFINER:** INVOKER

**Required role:** `authenticated`, `service_role`, `anon`

**Description:** Returns `true` if the current user holds at least one of the specified roles. More efficient than chaining multiple `OR has_role(...)` calls.

**Parameters:**
- `group_id uuid` — the group to check
- `roles text[]` — array of role names; true if user holds any one of them

**Returns:** `boolean`

**Escalation check:** No.

**Example:**
```sql
-- Owners or admins can manage members
CREATE POLICY "owners and admins can update members" ON rbac.members
    FOR UPDATE TO authenticated
    USING (rbac.has_any_role(group_id, ARRAY['owner', 'admin']));
```

---

### `has_all_roles(group_id uuid, roles text[])`

**Signature:** `has_all_roles(group_id uuid, roles text[]) → boolean`

**INVOKER/DEFINER:** INVOKER

**Required role:** `authenticated`, `service_role`, `anon`

**Description:** Returns `true` if the current user holds all of the specified roles.

**Parameters:**
- `group_id uuid` — the group to check
- `roles text[]` — array of role names; true only if user holds all of them

**Returns:** `boolean`

**Escalation check:** No.

**Example:**
```sql
-- Only users who are both verified and editor can publish
CREATE POLICY "verified editors can publish" ON public.posts
    FOR UPDATE TO authenticated
    USING (rbac.has_all_roles(group_id, ARRAY['verified', 'editor']));
```

---

### `has_permission(group_id uuid, permission text)`

**Signature:** `has_permission(group_id uuid, permission text) → boolean`

**INVOKER/DEFINER:** INVOKER

**Required role:** `authenticated`, `service_role`, `anon`

**Description:** Returns `true` if the current user holds the specified permission in the specified group. Permissions are pre-resolved into the claims cache — no extra database query at runtime.

**Parameters:**
- `group_id uuid` — the group to check
- `permission text` — the permission string to check

**Returns:** `boolean`

**Escalation check:** No.

**Example:**
```sql
-- Only users with data.write permission can insert
CREATE POLICY "writers can insert" ON public.documents
    FOR INSERT TO authenticated
    WITH CHECK (rbac.has_permission(group_id, 'data.write'));
```

---

### `has_any_permission(group_id uuid, permissions text[])`

**Signature:** `has_any_permission(group_id uuid, permissions text[]) → boolean`

**INVOKER/DEFINER:** INVOKER

**Required role:** `authenticated`, `service_role`, `anon`

**Description:** Returns `true` if the current user holds at least one of the specified permissions.

**Parameters:**
- `group_id uuid` — the group to check
- `permissions text[]` — array of permission strings

**Returns:** `boolean`

**Escalation check:** No.

**Example:**
```sql
-- Users with either read or admin permission can view
CREATE POLICY "readers can view" ON public.reports
    FOR SELECT TO authenticated
    USING (rbac.has_any_permission(group_id, ARRAY['reports.read', 'reports.admin']));
```

---

### `has_all_permissions(group_id uuid, permissions text[])`

**Signature:** `has_all_permissions(group_id uuid, permissions text[]) → boolean`

**INVOKER/DEFINER:** INVOKER

**Required role:** `authenticated`, `service_role`, `anon`

**Description:** Returns `true` if the current user holds all of the specified permissions.

**Parameters:**
- `group_id uuid` — the group to check
- `permissions text[]` — array of permission strings

**Returns:** `boolean`

**Escalation check:** No.

**Example:**
```sql
-- Must have both read and export permission to download
CREATE POLICY "can download" ON public.exports
    FOR SELECT TO authenticated
    USING (rbac.has_all_permissions(group_id, ARRAY['data.read', 'data.export']));
```

---

## Group Management

---

### `create_group(p_name, p_metadata, p_creator_roles)`

**Signature:** `create_group(p_name text, p_metadata jsonb DEFAULT '{}', p_creator_roles text[] DEFAULT ARRAY['owner']) → uuid`

**INVOKER/DEFINER:** INVOKER

**Required role:** `authenticated`

**Description:** Creates a new group and adds the calling user as a member with the specified roles. Returns the new group's UUID.

SECURITY INVOKER — the INSERT into `rbac.groups` is subject to RLS. An INSERT policy on `rbac.groups` is required (see `examples/policies/quickstart.sql`). The membership row is created by the `_on_group_created` AFTER INSERT trigger (SECURITY DEFINER), which uses `auth.uid()` to bind the caller.

**Parameters:**
- `p_name text` — display name for the group (required)
- `p_metadata jsonb` — arbitrary metadata (default: `{}`)
- `p_creator_roles text[]` — roles to assign to the creator (default: `ARRAY['owner']`); all must exist in `rbac.roles`

**Returns:** `uuid` — the new group's ID

**Escalation check:** No (creator becomes the initial member; no prior membership exists to validate against).

**Example:**
```sql
-- Create a group with default owner role
SELECT rbac.create_group('Acme Corp');

-- Create a group with metadata and custom creator role
SELECT rbac.create_group(
    'Acme Corp',
    '{"plan": "enterprise"}'::jsonb,
    ARRAY['owner', 'billing_admin']
);
```

---

### `delete_group(p_group_id)`

**Signature:** `delete_group(p_group_id uuid) → void`

**INVOKER/DEFINER:** INVOKER

**Required role:** `authenticated`

**Description:** Deletes a group. All members, invites, and member_permissions for this group are deleted via CASCADE. Requires an RLS DELETE policy on `rbac.groups` permitting the caller.

**Parameters:**
- `p_group_id uuid` — the group to delete

**Returns:** void

**Escalation check:** No (RLS enforced).

**Example:**
```sql
SELECT rbac.delete_group('c2aa61f5-d86b-45e8-9e6d-a5bae98cd530');
```

---

## Member Management

---

### `add_member(p_group_id, p_user_id, p_roles)`

**Signature:** `add_member(p_group_id uuid, p_user_id uuid, p_roles text[] DEFAULT '{}') → uuid`

**INVOKER/DEFINER:** INVOKER

**Required role:** `authenticated`

**Description:** Adds a user to a group with the specified roles. If the user is already a member, merges the new roles into their existing roles array (no duplicates). Returns the member row UUID.

Requires an RLS INSERT (or UPDATE) policy on `rbac.members` permitting the caller.

**Parameters:**
- `p_group_id uuid` — the group to add the user to
- `p_user_id uuid` — the user to add
- `p_roles text[]` — roles to assign (all must exist in `rbac.roles`)

**Returns:** `uuid` — the member row ID

**Escalation check:** Yes — all roles in `p_roles` must be within the caller's `grantable_roles` for this group. Raises `insufficient_privilege` if any role is outside the caller's grant scope.

**Example:**
```sql
SELECT rbac.add_member(
    'c2aa61f5-d86b-45e8-9e6d-a5bae98cd530',  -- group_id
    'f1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c',  -- user_id
    ARRAY['editor']
);
```

---

### `remove_member(p_group_id, p_user_id)`

**Signature:** `remove_member(p_group_id uuid, p_user_id uuid) → void`

**INVOKER/DEFINER:** INVOKER

**Required role:** `authenticated`

**Description:** Removes a user from a group. All `member_permissions` for this user in this group are also deleted via CASCADE. Requires an RLS DELETE policy on `rbac.members` permitting the caller.

**Parameters:**
- `p_group_id uuid` — the group
- `p_user_id uuid` — the user to remove

**Returns:** void

**Escalation check:** No (RLS enforced).

**Example:**
```sql
SELECT rbac.remove_member(
    'c2aa61f5-d86b-45e8-9e6d-a5bae98cd530',
    'f1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c'
);
```

---

### `update_member_roles(p_group_id, p_user_id, p_roles)`

**Signature:** `update_member_roles(p_group_id uuid, p_user_id uuid, p_roles text[]) → void`

**INVOKER/DEFINER:** INVOKER

**Required role:** `authenticated`

**Description:** Replaces a member's roles array entirely with the specified array. To add roles without removing existing ones, use `add_member()` instead. Requires an RLS UPDATE policy on `rbac.members` permitting the caller.

**Parameters:**
- `p_group_id uuid` — the group
- `p_user_id uuid` — the member whose roles to update
- `p_roles text[]` — the new roles array (replaces existing; all must exist in `rbac.roles`)

**Returns:** void

**Escalation check:** Yes — all roles in `p_roles` must be within the caller's `grantable_roles` for this group. Raises `insufficient_privilege` if any role is outside the caller's grant scope.

**Example:**
```sql
-- Demote a member from editor to viewer
SELECT rbac.update_member_roles(
    'c2aa61f5-d86b-45e8-9e6d-a5bae98cd530',
    'f1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c',
    ARRAY['viewer']
);
```

---

### `list_members(p_group_id)`

**Signature:** `list_members(p_group_id uuid) → TABLE(id uuid, user_id uuid, roles text[], metadata jsonb, created_at timestamptz)`

**INVOKER/DEFINER:** INVOKER

**Required role:** `authenticated`

**Description:** Returns all members of a group. Requires an RLS SELECT policy on `rbac.members` permitting the caller.

**Parameters:**
- `p_group_id uuid` — the group to list members of

**Returns:** Table with columns: `id`, `user_id`, `roles`, `metadata`, `created_at`

**Escalation check:** No (RLS enforced).

**Example:**
```sql
SELECT * FROM rbac.list_members('c2aa61f5-d86b-45e8-9e6d-a5bae98cd530');
```

---

## Invite System

---

### `create_invite(p_group_id, p_roles, p_expires_at)`

**Signature:** `create_invite(p_group_id uuid, p_roles text[], p_expires_at timestamptz DEFAULT NULL) → uuid`

**INVOKER/DEFINER:** INVOKER

**Required role:** `authenticated`

**Description:** Creates an invite for a group with the specified roles. The invite's `invited_by` is set to `auth.uid()`. Returns the invite UUID (which serves as the invite code).

Requires an RLS INSERT policy on `rbac.invites` permitting the caller.

Invites with `p_expires_at = NULL` never expire. Set a future timestamp to create a time-limited invite.

**Parameters:**
- `p_group_id uuid` — the group the invitee will join
- `p_roles text[]` — roles the invitee receives on acceptance (all must exist in `rbac.roles`)
- `p_expires_at timestamptz` — optional expiry timestamp (NULL = never expires)

**Returns:** `uuid` — the invite ID (use this as the invite code)

**Escalation check:** Yes — all roles in `p_roles` must be within the caller's `grantable_roles` for this group. Raises `insufficient_privilege` if any role is outside the caller's grant scope.

**Example:**
```sql
-- Create a viewer invite that expires in 7 days
SELECT rbac.create_invite(
    'c2aa61f5-d86b-45e8-9e6d-a5bae98cd530',
    ARRAY['viewer'],
    now() + interval '7 days'
);
```

---

### `delete_invite(p_invite_id)`

**Signature:** `delete_invite(p_invite_id uuid) → void`

**INVOKER/DEFINER:** INVOKER

**Required role:** `authenticated`

**Description:** Deletes an invite. Raises if the invite is not found or RLS prevents the delete. Requires an RLS DELETE policy on `rbac.invites` permitting the caller.

**Parameters:**
- `p_invite_id uuid` — the invite to delete

**Returns:** void

**Escalation check:** No (RLS enforced).

**Example:**
```sql
SELECT rbac.delete_invite('9a8b7c6d-5e4f-3a2b-1c0d-e9f8a7b6c5d4');
```

---

### `accept_invite(p_invite_id)`

**Signature:** `accept_invite(p_invite_id uuid) → void`

**INVOKER/DEFINER:** DEFINER

**Required role:** `authenticated`

**Description:** Accepts an invite. Validates the invite is not expired and not already accepted. Atomically marks the invite as used and upserts the calling user into the group with the invite's roles.

SECURITY DEFINER is required because the caller has no prior membership in the target group — without it, the upsert into `members` would fail RLS.

Uses `FOR UPDATE` row lock to prevent concurrent acceptance races.

**Parameters:**
- `p_invite_id uuid` — the invite to accept

**Returns:** void

**Escalation check:** No (roles are set at invite creation time by a user with appropriate grant scope).

**Example:**
```sql
-- Typically called via the edge function, but can be called directly:
SELECT rbac.accept_invite('9a8b7c6d-5e4f-3a2b-1c0d-e9f8a7b6c5d4');
```

The edge function at `supabase/functions/invite/index.ts` accepts HTTP POST requests:
```bash
curl --request POST \
  'https://<project>.supabase.co/functions/v1/invite?invite_code=<invite-id>' \
  --header 'Authorization: Bearer <user-jwt>'
```

---

## Permission Overrides

Direct per-member permission grants that do not require role assignment.

---

### `grant_member_permission(p_group_id, p_user_id, p_permission)`

**Signature:** `grant_member_permission(p_group_id uuid, p_user_id uuid, p_permission text) → void`

**INVOKER/DEFINER:** INVOKER

**Required role:** `authenticated`

**Description:** Grants a direct permission override to a specific member. Idempotent — calling again with the same arguments is a no-op. The override merges into the member's cached permissions immediately via trigger.

Requires an RLS INSERT policy on `rbac.member_permissions` permitting the caller.

The permission must exist in the `rbac.permissions` registry.

**Parameters:**
- `p_group_id uuid` — the group
- `p_user_id uuid` — the member to grant the permission to
- `p_permission text` — the permission string (must exist in `rbac.permissions`)

**Returns:** void

**Escalation check:** Yes — `p_permission` must be within the caller's `grantable_permissions` for this group. Raises `insufficient_privilege` if outside scope.

**Example:**
```sql
-- Grant a one-off export permission to a viewer
SELECT rbac.grant_member_permission(
    'c2aa61f5-d86b-45e8-9e6d-a5bae98cd530',
    'f1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c',
    'data.export'
);
```

---

### `revoke_member_permission(p_group_id, p_user_id, p_permission)`

**Signature:** `revoke_member_permission(p_group_id uuid, p_user_id uuid, p_permission text) → void`

**INVOKER/DEFINER:** INVOKER

**Required role:** `authenticated`

**Description:** Removes a direct permission override from a specific member. Raises if the override does not exist. Claims are updated immediately via trigger.

Requires an RLS DELETE policy on `rbac.member_permissions` permitting the caller.

**Parameters:**
- `p_group_id uuid` — the group
- `p_user_id uuid` — the member to revoke from
- `p_permission text` — the permission string to revoke

**Returns:** void

**Escalation check:** Yes — `p_permission` must be within the caller's `grantable_permissions` for this group. Same check as `grant_member_permission`.

**Example:**
```sql
SELECT rbac.revoke_member_permission(
    'c2aa61f5-d86b-45e8-9e6d-a5bae98cd530',
    'f1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c',
    'data.export'
);
```

---

### `list_member_permissions(p_group_id, p_user_id)`

**Signature:** `list_member_permissions(p_group_id uuid, p_user_id uuid DEFAULT NULL) → TABLE(user_id uuid, permission text, created_at timestamptz)`

**INVOKER/DEFINER:** INVOKER

**Required role:** `authenticated`

**Description:** Returns direct permission overrides for a group. Pass `p_user_id` to filter to a specific member, or omit to return all overrides in the group. Requires an RLS SELECT policy on `rbac.member_permissions` permitting the caller.

**Parameters:**
- `p_group_id uuid` — the group
- `p_user_id uuid` — (optional) filter to a specific member

**Returns:** Table with columns: `user_id`, `permission`, `created_at`

**Escalation check:** No (RLS enforced).

**Example:**
```sql
-- List all overrides in a group
SELECT * FROM rbac.list_member_permissions('c2aa61f5-d86b-45e8-9e6d-a5bae98cd530');

-- List overrides for a specific member
SELECT * FROM rbac.list_member_permissions(
    'c2aa61f5-d86b-45e8-9e6d-a5bae98cd530',
    'f1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c'
);
```

---

## Role Management (service_role)

These are app-author operations intended for use in migrations or admin tooling. All require `service_role` and are not exposed via public wrapper functions.

---

### `create_role(p_name, p_description, p_permissions, p_grantable_roles)`

**Signature:** `create_role(p_name text, p_description text DEFAULT NULL, p_permissions text[] DEFAULT '{}', p_grantable_roles text[] DEFAULT '{}') → void`

**INVOKER/DEFINER:** INVOKER

**Required role:** `service_role`

**Description:** Creates a new role definition. All permissions in `p_permissions` must exist in `rbac.permissions`. All role names in `p_grantable_roles` must exist in `rbac.roles` (or be `'*'`).

**Parameters:**
- `p_name text` — role name (unique)
- `p_description text` — human-readable description (optional)
- `p_permissions text[]` — permissions granted to holders of this role
- `p_grantable_roles text[]` — roles that holders of this role can assign; `'*'` for wildcard

**Returns:** void

**Escalation check:** No.

**Example:**
```sql
SELECT rbac.create_role(
    'editor',
    'Can read and write content',
    ARRAY['data.read', 'data.write'],
    ARRAY['viewer']
);
```

---

### `delete_role(p_name)`

**Signature:** `delete_role(p_name text) → void`

**INVOKER/DEFINER:** INVOKER

**Required role:** `service_role`

**Description:** Deletes a role definition. Raises if any member currently has this role assigned. Remove the role from all members before deleting.

**Parameters:**
- `p_name text` — role name to delete

**Returns:** void

**Escalation check:** No.

**Example:**
```sql
SELECT rbac.delete_role('legacy_admin');
```

---

### `list_roles()`

**Signature:** `list_roles() → TABLE(name text, description text, permissions text[], grantable_roles text[], created_at timestamptz)`

**INVOKER/DEFINER:** INVOKER

**Required role:** `service_role`

**Description:** Returns all defined roles with their permissions and grantable_roles.

**Returns:** Table with columns: `name`, `description`, `permissions`, `grantable_roles`, `created_at`

**Escalation check:** No.

**Example:**
```sql
SELECT * FROM rbac.list_roles();
```

---

### `set_role_permissions(p_role_name, p_permissions)`

**Signature:** `set_role_permissions(p_role_name text, p_permissions text[]) → void`

**INVOKER/DEFINER:** INVOKER

**Required role:** `service_role`

**Description:** Replaces the permissions array for a role entirely. Triggers a rebuild of `user_claims` for all users holding this role. All permissions in `p_permissions` must exist in `rbac.permissions`.

**Parameters:**
- `p_role_name text` — the role to update
- `p_permissions text[]` — the new permissions array (replaces existing)

**Returns:** void

**Escalation check:** No.

**Example:**
```sql
SELECT rbac.set_role_permissions('editor', ARRAY['data.read', 'data.write', 'data.export']);
```

---

### `grant_permission(p_role_name, p_permission)`

**Signature:** `grant_permission(p_role_name text, p_permission text) → void`

**INVOKER/DEFINER:** INVOKER

**Required role:** `service_role`

**Description:** Appends a single permission to a role's permissions array. No-op if already present. Triggers a claims rebuild for all users holding this role.

**Parameters:**
- `p_role_name text` — the role to add the permission to
- `p_permission text` — permission string (must exist in `rbac.permissions`)

**Returns:** void

**Escalation check:** No.

**Example:**
```sql
SELECT rbac.grant_permission('editor', 'data.export');
```

---

### `revoke_permission(p_role_name, p_permission)`

**Signature:** `revoke_permission(p_role_name text, p_permission text) → void`

**INVOKER/DEFINER:** INVOKER

**Required role:** `service_role`

**Description:** Removes a single permission from a role's permissions array. Triggers a claims rebuild for all users holding this role.

**Parameters:**
- `p_role_name text` — the role to remove the permission from
- `p_permission text` — permission string to remove

**Returns:** void

**Escalation check:** No.

**Example:**
```sql
SELECT rbac.revoke_permission('editor', 'data.export');
```

---

### `list_role_permissions(p_role_name)`

**Signature:** `list_role_permissions(p_role_name text DEFAULT NULL) → TABLE(role_name text, permission text)`

**INVOKER/DEFINER:** INVOKER

**Required role:** `service_role`

**Description:** Returns permission assignments for roles. Omit `p_role_name` to get all roles.

**Parameters:**
- `p_role_name text` — (optional) filter to a specific role

**Returns:** Table with columns: `role_name`, `permission`

**Escalation check:** No.

**Example:**
```sql
-- All permissions for all roles
SELECT * FROM rbac.list_role_permissions();

-- Permissions for a specific role
SELECT * FROM rbac.list_role_permissions('editor');
```

---

### `set_role_grantable_roles(p_role_name, p_grantable_roles)`

**Signature:** `set_role_grantable_roles(p_role_name text, p_grantable_roles text[]) → void`

**INVOKER/DEFINER:** INVOKER

**Required role:** `service_role`

**Description:** Replaces the `grantable_roles` array for a role. Triggers a claims rebuild for all users holding this role, recomputing their `grantable_roles` and `grantable_permissions` in `user_claims`.

This operation is prospective-only: existing memberships and permission overrides granted under the old scope are not revoked.

**Parameters:**
- `p_role_name text` — the role to update
- `p_grantable_roles text[]` — the new grantable_roles array; use `ARRAY['*']` for wildcard

**Returns:** void

**Escalation check:** No.

**Example:**
```sql
-- Restrict owner to only granting admin and below
SELECT rbac.set_role_grantable_roles('owner', ARRAY['admin', 'editor', 'viewer']);

-- Restore wildcard
SELECT rbac.set_role_grantable_roles('owner', ARRAY['*']);
```

---

## Permission Management (service_role)

Also service_role only. Manages the permissions registry that all role and override assignments are validated against.

---

### `create_permission(p_name, p_description)`

**Signature:** `create_permission(p_name text, p_description text DEFAULT NULL) → void`

**INVOKER/DEFINER:** INVOKER

**Required role:** `service_role`

**Description:** Registers a new permission string. Must be called before a permission can be assigned to a role or granted as a direct override.

**Parameters:**
- `p_name text` — the permission string (unique; e.g., `data.read`)
- `p_description text` — human-readable description (optional)

**Returns:** void

**Escalation check:** No.

**Example:**
```sql
SELECT rbac.create_permission('data.read', 'Read documents belonging to the group');
SELECT rbac.create_permission('data.write', 'Create and modify documents');
SELECT rbac.create_permission('data.export', 'Export documents as a file');
```

---

### `delete_permission(p_name)`

**Signature:** `delete_permission(p_name text) → void`

**INVOKER/DEFINER:** INVOKER

**Required role:** `service_role`

**Description:** Removes a permission from the registry. Raises if the permission is currently assigned to any role or used as a direct override on any member.

**Parameters:**
- `p_name text` — the permission string to delete

**Returns:** void

**Escalation check:** No.

**Example:**
```sql
SELECT rbac.delete_permission('data.export');
```

---

### `list_permissions()`

**Signature:** `list_permissions() → TABLE(name text, description text, created_at timestamptz)`

**INVOKER/DEFINER:** INVOKER

**Required role:** `service_role`

**Description:** Returns all registered permissions.

**Returns:** Table with columns: `name`, `description`, `created_at`

**Escalation check:** No.

**Example:**
```sql
SELECT * FROM rbac.list_permissions();
```

---

## Hooks

---

### `db_pre_request()`

**Signature:** `db_pre_request() → void`

**INVOKER/DEFINER:** INVOKER

**Required role:** `authenticator` (called by PostgREST, not directly by application code)

**Description:** PostgREST pre-request hook. Reads the current user's claims from `rbac.user_claims` and writes them to the `request.groups` session variable. All RLS helper functions read from this session variable.

This function is registered automatically at extension install time:
```sql
ALTER ROLE authenticator SET pgrst.db_pre_request TO 'rbac.db_pre_request';
NOTIFY pgrst, 'reload config';
```

Do not call this function directly. It is invoked once per PostgREST request before any RLS policy evaluation.

**Returns:** void

**Escalation check:** No.

---

### `custom_access_token_hook(event jsonb)`

**Signature:** `custom_access_token_hook(event jsonb) → jsonb`

**INVOKER/DEFINER:** INVOKER

**Required role:** `supabase_auth_admin` (called by Supabase Auth, not directly by application code)

**Description:** Optional Supabase Auth Hook that injects group claims into the JWT at token-creation time. When registered, the JWT's `app_metadata.groups` field contains the same claims structure as `user_claims.claims`.

This is complementary to `db_pre_request`, not a replacement. `db_pre_request` provides the freshness guarantee; the auth hook provides convenient client-side access to claims without a database round-trip.

**Registration in config.toml:**
```toml
[auth.hook.custom_access_token]
enabled = true
uri = "pg-functions://postgres/rbac/custom_access_token_hook"
```

**Returns:** Modified `event` jsonb with `app_metadata.groups` populated.

**Escalation check:** No.
