# Conceptual Model

This document explains the design of the Supabase Tenant RBAC extension — what the entities are, how they relate, and why the system is structured the way it is. If you are new to RBAC or new to this extension, read this first.

## Table of Contents

1. [The Three-Tier Authority Model](#the-three-tier-authority-model)
2. [Entity Relationships](#entity-relationships)
3. [The Permissions Vocabulary](#the-permissions-vocabulary)
4. [Grantable Roles and Escalation Prevention](#grantable-roles-and-escalation-prevention)
5. [Grantable Permissions](#grantable-permissions)
6. [Claims Caching Strategy](#claims-caching-strategy)
7. [ORBAC Alignment](#orbac-alignment)
8. [Comparison to JWT-Only Approaches](#comparison-to-jwt-only-approaches)

---

## The Three-Tier Authority Model

The system defines three distinct tiers of authority. Each tier has bounded responsibilities that cannot exceed what the tier above it permits.

| Tier | Actor | Capabilities | Mechanism |
|------|-------|-------------|-----------|
| **App Author** | `service_role` / `postgres` | Defines the vocabulary: creates roles, creates permissions, assigns permissions to roles, sets `grantable_roles` on each role | `create_role()`, `create_permission()`, `set_role_permissions()`, `set_role_grantable_roles()`, direct SQL |
| **Group Administrator** | Authenticated user with appropriate roles/permissions in a group | Manages membership within the boundaries set by the app author: adds/removes members, assigns roles (within grantable scope), grants permission overrides (within grantable scope) | `add_member()`, `remove_member()`, `update_member_roles()`, `grant_member_permission()` — all subject to RLS and escalation checks |
| **Member** | Authenticated user with membership in a group | Consumes permissions: can perform actions allowed by their roles and direct permission overrides | RLS policies using `has_role()`, `is_member()`, `has_permission()`, etc. |

This hierarchy is enforced structurally:

- The **app author** controls what exists — the vocabulary of roles and permissions is defined once and applies to all groups.
- **Group administrators** control who has what within their group, but only within the scope the app author has authorized.
- **Members** use what they have been given.

A Group Administrator is not a separate database role — it is any authenticated user who holds a role that grants sufficient `grantable_roles` for the operations they want to perform. The pre-seeded `owner` role has `grantable_roles = ['*']`, making group owners full administrators by default.

---

## Entity Relationships

```
permissions (registry)        roles (definitions)
    │                            │
    │  roles.permissions[] ──────┤  Each role bundles
    │  (permissions granted       │  a set of permissions
    │   to role holders)          │
    │                            │  roles.grantable_roles[]
    │                            │  (which roles can holders
    │                            │   of this role assign?)
    │                            │
    └──────────┬─────────────────┘
               │
               ▼
         groups (tenants / organizations)
               │
               ▼
     members (group_id, user_id, roles[])
               │
               ├── member_permissions (direct overrides per member)
               │
               ▼
     user_claims (cached per user:
                  roles[], permissions[],
                  grantable_roles[], grantable_permissions[])
```

**Entity descriptions:**

**`permissions`** — The canonical registry of all permission strings in the application. Managed exclusively by the app author. Every permission used anywhere in the system must first be registered here.

**`roles`** — Named bundles of permissions. Each role has a `permissions text[]` column (the permissions granted to holders of this role) and a `grantable_roles text[]` column (the roles that holders of this role are authorized to assign to others). Managed exclusively by the app author.

**`groups`** — Tenants or organizations. A group has an `id`, a `name`, optional `metadata`, and timestamps. Groups are the top-level container for membership.

**`members`** — One row per user-group pair. A member has a `roles text[]` array (their assigned roles in this group) and optional `metadata`. The `(group_id, user_id)` pair is unique — a user can only have one membership row per group, but that row can carry multiple roles.

**`member_permissions`** — Direct per-member permission overrides. A specific permission granted to a specific member without assigning a role. These merge additively into the member's cached permissions. The FK to `members(group_id, user_id)` means overrides are automatically deleted when the member is removed.

**`user_claims`** — The claims cache. One row per user, containing a JSONB object keyed by group UUID. The cache is maintained automatically by triggers and is never written to directly by application code. It stores four fields per group: `roles`, `permissions`, `grantable_roles`, and `grantable_permissions`.

---

## The Permissions Vocabulary

All permissions in the system come from a single authoritative source: the `permissions` table. This is the canonical registry.

**Why a separate table?**

Without a registry, permission strings are just arbitrary text in `roles.permissions[]` arrays and `member_permissions` rows. Typos silently create permissions that never match anything. Two roles might use `data.read` and `data_read` (with an underscore) and never grant the same access. The registry enforces consistency.

**How it works:**

- When the app author calls `create_permission('data.read', 'Read documents')`, the permission is registered.
- When `set_role_permissions()` or `grant_permission()` assigns permissions to a role, each permission string is validated against the registry. Unrecognized permissions are rejected with an error.
- When `grant_member_permission()` grants a direct override, the permission is similarly validated.

**Permission string conventions:**

The extension treats permission strings as opaque identifiers — `group_data.read` and `group_data.*` are two different strings with no implied relationship. However, dot-notation is a useful convention for organizing permissions into namespaces:

```
group.update          — Update group metadata
group.delete          — Delete the group
group_data.read       — Read data belonging to the group
group_data.write      — Create or modify data belonging to the group
members.invite        — Create invites
members.manage        — Add, remove, or change roles of members
```

The extension does not interpret dots or wildcards in permission strings. If you want hierarchical matching (e.g., `group_data.*` implying all `group_data.*` permissions), that is a future enhancement. For now, be explicit.

**The registry enables future features:**

Because permissions are first-class entities in their own table, a future version can add per-group custom roles (group administrators composing roles from the global permission vocabulary) without requiring any schema changes to existing tables.

---

## Grantable Roles and Escalation Prevention

Privilege escalation is a common vulnerability in access control systems: a user with limited authority elevates their own or another user's authority beyond what should be permitted.

**The problem without escalation prevention:**

If any group member with an UPDATE policy on `members` can call `update_member_roles()`, then a `viewer` could call `update_member_roles(group_id, their_own_user_id, ARRAY['owner'])` and grant themselves full control. Nothing in the RLS policy itself prevents this — the policy only checks whether the caller is a member, not what roles they are authorized to assign.

**The solution: `grantable_roles`**

Each role in the `roles` table has a `grantable_roles text[]` column. This declares the set of roles that holders of this role are authorized to assign to others. The escalation check is built into the management RPCs themselves — it is not left to the app author to implement via additional triggers.

When `add_member()` or `update_member_roles()` is called, the RPC:

1. Reads the caller's `grantable_roles` for the target group from the `user_claims` cache.
2. Checks whether every role in the target array is covered by the caller's grant scope.
3. If any role is not covered, raises an error and aborts.

**Example configuration:**

```sql
-- App author defines roles with explicit grant scope:
SELECT rbac.create_role('owner', 'Full control',
    ARRAY['group.delete', 'group.update', 'members.manage', 'members.invite', 'data.write', 'data.read'],
    ARRAY['*']      -- owner can grant any role
);

SELECT rbac.create_role('admin', 'Manage members and data',
    ARRAY['group.update', 'members.manage', 'members.invite', 'data.write', 'data.read'],
    ARRAY['editor', 'viewer']  -- admin can only grant editor or viewer
);

SELECT rbac.create_role('editor', 'Create and edit content',
    ARRAY['data.write', 'data.read'],
    ARRAY['viewer']  -- editor can only grant viewer
);

SELECT rbac.create_role('viewer', 'Read-only access',
    ARRAY['data.read'],
    ARRAY[]::text[]  -- viewer cannot grant any roles
);
```

With this configuration:

- An `owner` can assign any role (including `owner`) to any member.
- An `admin` can assign `editor` or `viewer`, but not `owner` or `admin`. If they try, the RPC raises an error.
- An `editor` can assign only `viewer`.
- A `viewer` cannot assign any roles.

**The wildcard `'*'`:**

A role with `grantable_roles = ARRAY['*']` can grant any role, including roles added in the future. The pre-seeded `owner` role ships with this wildcard, so group creators can manage membership fully without additional configuration.

The wildcard applies to `grantable_permissions` as well — a role that can grant any role can also directly grant any permission (see below).

**Prospective-only changes:**

Changing `grantable_roles` on a role definition affects future grant operations only. Existing memberships and permission overrides that were granted before the change are not retroactively revoked. If you tighten grant scope, existing overrides remain until `service_role` explicitly removes them or the member is removed and re-added. This is a documented limitation — see [docs/SECURITY.md](SECURITY.md).

---

## Grantable Permissions

The grant scope for direct permission overrides is derived from the grant scope for roles — you do not configure it separately.

When `_build_user_claims()` resolves the claims cache, it computes `grantable_permissions` as follows:

- Take the caller's `grantable_roles` set.
- For each role in that set, collect all permissions that role grants (from `roles.permissions[]`).
- The union of those permissions is `grantable_permissions`.
- If `grantable_roles` contains `'*'`, then `grantable_permissions` is also `['*']`.

This means: if you can grant the `editor` role, you can also directly grant any permission that `editor` holds — but no more.

**Example:**

An `admin` with `grantable_roles = ['editor', 'viewer']` gets:
- `editor` permissions: `['data.write', 'data.read']`
- `viewer` permissions: `['data.read']`
- `grantable_permissions`: `['data.write', 'data.read']` (deduplicated union)

The `admin` can call `grant_member_permission(group_id, user_id, 'data.write')` successfully.
The `admin` cannot call `grant_member_permission(group_id, user_id, 'group.delete')` — that permission is not in their grantable scope.

`revoke_member_permission()` applies the same check symmetrically. This is consistent with the design principle that revocation is also a privileged operation.

---

## Claims Caching Strategy

The claims cache is the performance and correctness backbone of the extension.

**What is cached:**

For each group the user is a member of, the cache stores four fields:

| Field | Source | Purpose |
|-------|--------|---------|
| `roles` | `members.roles[]` | The member's assigned roles in this group |
| `permissions` | Union of `roles.permissions[]` for held roles + `member_permissions` direct overrides | What the member can do |
| `grantable_roles` | Union of `roles.grantable_roles[]` for held roles; `['*']` if any role has wildcard | Which roles the member can assign |
| `grantable_permissions` | Derived from `grantable_roles` as described above | Which permissions the member can grant as direct overrides |

**Example claims structure:**

```json
{
  "c2aa61f5-d86b-45e8-9e6d-a5bae98cd530": {
    "roles": ["editor"],
    "permissions": ["data.read", "data.write"],
    "grantable_roles": ["viewer"],
    "grantable_permissions": ["data.read"]
  },
  "9f3b2e1a-4c5d-6e7f-8a9b-0c1d2e3f4a5b": {
    "roles": ["owner"],
    "permissions": ["data.read", "data.write", "group.delete", "group.update", "members.manage"],
    "grantable_roles": ["*"],
    "grantable_permissions": ["*"]
  }
}
```

**When the cache is rebuilt:**

The cache is always rebuilt from source tables — it is never incrementally updated. This means the cache is always consistent and there is no risk of incremental update bugs.

Rebuilds are triggered by:

- INSERT, UPDATE, or DELETE on `members` — rebuilds that user's claims.
- INSERT or DELETE on `member_permissions` — rebuilds the affected user's claims.
- UPDATE of `permissions[]` or `grantable_roles[]` on `roles` — rebuilds claims for all users who hold that role.

**Why write-time resolution?**

RLS policies evaluate per-row on every query. An application with thousands of rows in a table might call `has_permission()` or `is_member()` millions of times per minute. If those functions had to join against `roles` and `member_permissions` tables on every call, the performance impact would be severe.

Instead, all joins happen at write time — when memberships or role definitions change, which is infrequent. The runtime check is a JSONB key lookup against `request.groups` (a session variable), which is O(1) and performs no database I/O.

**How claims are consumed:**

- **PostgREST requests:** `db_pre_request()` reads the user's row from `user_claims` and stores it in the `request.groups` session variable. All RLS helpers read from that session variable.
- **Supabase Storage requests:** Storage bypasses `db_pre_request`. `get_claims()` falls back to reading `user_claims` directly.
- **Management RPCs:** Read `grantable_roles` and `grantable_permissions` from the cache to enforce escalation checks.
- **JWT (optional):** `custom_access_token_hook` reads `user_claims` at token-creation time and injects the claims into `app_metadata.groups` for client-side use.

---

## ORBAC Alignment

The extension is inspired by the Organization-Based Access Control (ORBAC) model but does not strictly implement it. The mapping is:

| ORBAC Concept | Extension Concept | Notes |
|---------------|-------------------|-------|
| Organization | Group | Direct mapping |
| Role | Role | Direct mapping; global definitions, per-group assignment |
| Activity | Permission | Permissions are the activities that can be performed |
| View | (Not implemented) | ORBAC views (data scope) are left to RLS policies |
| Context | (Not implemented) | Contextual constraints are left to RLS policies |

The extension provides the organizational and role layers. The app author implements view and context constraints through RLS policies on their application tables. This keeps the extension focused on the RBAC machinery and avoids dictating application-specific concerns.

---

## Comparison to JWT-Only Approaches

The [official Supabase RBAC approach](https://supabase.com/docs/guides/auth/row-level-security) stores role claims in the JWT at token-creation time via an auth hook. This is efficient — claims are immediately accessible client-side and server-side without a database query.

The drawback is **staleness**: claims in a JWT are frozen at token-creation time. If a user's role is revoked, the JWT continues to grant access until it expires. Depending on token lifetime, this can be minutes to hours.

This extension takes a different approach:

**Write-time caching, not JWT freezing.** When a membership changes, a trigger immediately writes the updated claims to `rbac.user_claims`. On the next API request, `db_pre_request()` reads the current state of `user_claims`. The RLS helpers read from that request context, not from the JWT.

**Role changes take effect on the next request** — typically under one second.

The two approaches are complementary, not mutually exclusive. This extension also includes `custom_access_token_hook`, which can inject claims into JWTs at token-creation time for convenient client-side access. The guarantee of freshness comes from `db_pre_request`, not from the JWT.

**Multi-tenant scope.** The official Supabase RBAC assigns database-level roles globally. This extension adds group-scoped roles: a user can be an `owner` in one organization and a `viewer` in another. The claims cache stores per-group state, and all RLS helpers take a `group_id` argument to scope the check.
