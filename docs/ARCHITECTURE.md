# Architecture

## Overview

`supabase-tenant-rbac` provides multi-tenant role-based access control (RBAC) as a PostgreSQL TLE. It stores group memberships in a relational table, propagates them into an extension-owned `user_claims` cache via trigger, and makes them available to RLS policies via a PostgREST pre-request hook — ensuring claims are always fresh on every API request. An optional Supabase Auth Hook injects claims into JWTs at token creation time.

As of v5.0.0, all tables live in a **private schema** (recommended: `rbac`) that is not exposed to PostgREST. All interaction goes through typed RPC functions. Public wrappers are **opt-in** — run `examples/setup/create_public_wrappers.sql` after installation to expose functions in the `public` schema for PostgREST discovery.

---

## Data Model

### Tables (in `@extschema@`, e.g. `rbac`)

#### `groups`
Represents a tenant, organization, team, or any logical grouping.

| Column | Type | Notes |
|--------|------|-------|
| `id` | `uuid` | Primary key, auto-generated |
| `name` | `text NOT NULL` | Group display name |
| `metadata` | `jsonb` | Arbitrary group data (settings, etc.) Default: `{}` |
| `created_at` | `timestamptz` | Auto-set on insert |
| `updated_at` | `timestamptz` | Auto-updated via `_set_updated_at()` trigger |

#### `members`
Maps users to groups. **One row per membership** with a `roles` array.

| Column | Type | Notes |
|--------|------|-------|
| `id` | `uuid` | Primary key, auto-generated |
| `group_id` | `uuid` | FK → `groups(id)` ON DELETE CASCADE |
| `user_id` | `uuid` | FK → `auth.users(id)` ON DELETE CASCADE |
| `roles` | `text[]` | Array of role strings. Default: `{}` |
| `metadata` | `jsonb` | Arbitrary user-in-group data. Default: `{}` |
| `created_at` | `timestamptz` | Auto-set on insert |
| `updated_at` | `timestamptz` | Auto-updated via `_set_updated_at()` trigger |

**Unique constraint:** `(group_id, user_id)` — one row per user-group pair. Use `add_member()` with ON CONFLICT to merge roles.

#### `invites`
An invite code allowing a user to join a group with pre-specified roles.

| Column | Type | Notes |
|--------|------|-------|
| `id` | `uuid` | Primary key AND invite code, auto-generated |
| `group_id` | `uuid` | FK → `groups(id)` ON DELETE CASCADE |
| `roles` | `text[]` | Roles to assign when accepted. Must have >= 1 role. |
| `invited_by` | `uuid` | FK → `auth.users(id)` ON DELETE CASCADE |
| `created_at` | `timestamptz` | Auto-set on insert |
| `user_id` | `uuid` | FK → `auth.users(id)` ON DELETE CASCADE. NULL until accepted. |
| `accepted_at` | `timestamptz` | NULL until accepted. |
| `expires_at` | `timestamptz` | Optional expiry. NULL = never expires. |

#### `roles`
Global role definitions. All management RPCs validate role assignments against this table. Roles can carry a `permissions[]` array that is resolved into the claims cache at write time.

| Column | Type | Notes |
|--------|------|-------|
| `name` | `text` | Primary key. The role string. |
| `description` | `text` | Optional human-readable description. |
| `permissions` | `text[]` | Permissions granted by this role. Default: `{}` |
| `created_at` | `timestamptz` | Auto-set on insert |

Pre-seeded with `'owner'` (default role for `create_group`).

#### `user_claims`
Claims cache. One row per user, auto-managed by the `_sync_member_metadata` and `_sync_member_permission` triggers.

| Column | Type | Notes |
|--------|------|-------|
| `user_id` | `uuid` | Primary key, FK → `auth.users(id)` ON DELETE CASCADE |
| `claims` | `jsonb` | Nested group/role/permission map — see format below |

**Never write to this table directly.** It is updated automatically whenever `members`, `roles.permissions`, or `member_permissions` changes.

#### `member_permissions`
Direct per-member permission overrides. One row per `(group_id, user_id, permission)` triple.

| Column | Type | Notes |
|--------|------|-------|
| `id` | `uuid` | Primary key, auto-generated |
| `group_id` | `uuid` | FK → `groups(id)` ON DELETE CASCADE |
| `user_id` | `uuid` | FK → `auth.users(id)` ON DELETE CASCADE |
| `permission` | `text` | The permission string being granted directly |
| `created_at` | `timestamptz` | Auto-set on insert |

**Unique constraint:** `(group_id, user_id, permission)` — prevents duplicate grants; enables idempotent `grant_member_permission()`.

**FK to `members(group_id, user_id)` ON DELETE CASCADE** — deleting a member automatically removes all their direct permission overrides in that group.

Permission overrides are merged into `user_claims.permissions[]` alongside role-derived permissions. The combined `permissions[]` is the flat, deduplicated, sorted union of both sources.

### Claims Storage Format

`rbac.user_claims` stores a nested structure with separate `roles` and `permissions` arrays per group:

```json
{
  "<group-uuid>": {
    "roles": ["role1", "role2"],
    "permissions": ["perm.a", "perm.b", "perm.c"]
  },
  "<other-group-uuid>": {
    "roles": ["viewer"],
    "permissions": ["data.read"]
  }
}
```

`roles` contains the raw role assignments from `members.roles[]`. `permissions` is the flat, deduplicated, alphabetically-sorted union of all permissions from `roles.permissions[]` for every role the user holds in that group, **plus** any direct overrides from `member_permissions` for that (group, user) pair. Both sources are resolved at write time by `_build_user_claims()` — zero runtime cost in RLS policies.

The `custom_access_token_hook` injects this structure into JWT `app_metadata.groups` at token creation:

```json
{
  "app_metadata": {
    "groups": {
      "<group-uuid>": {
        "roles": ["role1"],
        "permissions": ["perm.a"]
      }
    }
  }
}
```

---

## Claims Synchronization Flow

```
1a. Management RPC (add_member, create_group, etc.) modifies members table
         │
         ▼
2a. AFTER trigger fires: on_change_sync_member_metadata
         │
         ▼
3. _sync_member_metadata() [SECURITY INVOKER] runs
   - Calls _build_user_claims(user_id)
   - _build_user_claims() joins members with roles + member_permissions:
     SELECT jsonb_object_agg(group_id::text,
       jsonb_build_object('roles', roles, 'permissions',
         deduplicated_union_of_role_permissions_and_direct_overrides))
     FROM members WHERE user_id = p_user_id
   - Upserts result into rbac.user_claims

1b. Permission management RPC (set_role_permissions, grant_permission, etc.)
    modifies roles.permissions[]
         │
         ▼
2b. AFTER trigger fires: on_role_permissions_change
    (WHEN OLD.permissions IS DISTINCT FROM NEW.permissions)
         │
         ▼
3b. _on_role_permissions_change() [SECURITY INVOKER] runs
    - Finds all users holding the changed role (SELECT DISTINCT user_id FROM members)
    - Calls _build_user_claims() and upserts user_claims for each affected user

1c. grant_member_permission() / revoke_member_permission() modifies member_permissions
         │
         ▼
2c. AFTER trigger fires: on_member_permission_change
         │
         ▼
3c. _sync_member_permission() [SECURITY INVOKER] runs
    - Calls _build_user_claims(user_id)
    - Upserts result into rbac.user_claims
         │
         ▼
4. rbac.user_claims now reflects current memberships and permissions
         │
         ├─► On every PostgREST API request, BEFORE the query runs:
         │   db_pre_request() [SECURITY INVOKER] executes
         │   - Reads claims from rbac.user_claims for auth.uid()
         │   - Stores it in session config: request.groups
         │
         └─► On JWT creation (Supabase Auth Hook):
             custom_access_token_hook() [SECURITY INVOKER] executes
             - Reads claims from rbac.user_claims for event.user_id
             - Injects groups into JWT app_metadata.groups
         │
         ▼
5. RLS policies evaluate using has_role() / is_member() / has_any_role() / has_all_roles()
   - These call get_claims()
   - get_claims() reads request.groups (fresh, from step 4 PostgREST path)
   - Falls back to _get_user_groups() if request.groups is unset (Storage path)
   - _get_user_groups() reads rbac.user_claims directly [SECURITY INVOKER]
```

**Key insight:** Step 4 (db_pre_request) happens on *every* API request, so role changes take effect immediately — no waiting for JWT expiry or re-login.

**Storage path:** When `db_pre_request` does not run (Supabase Storage), `request.groups` is unset and `get_claims()` falls back to `_get_user_groups()`, which reads `rbac.user_claims` directly. Storage RLS policies therefore also always see fresh data.

**Auth Hook path:** `custom_access_token_hook` embeds claims in the JWT at token creation. Clients can read `app_metadata.groups` from the decoded JWT without a DB query, useful for client-side authorization decisions. Note: JWT claims reflect membership at the time of token issuance, not necessarily current membership. The db_pre_request path always reflects current membership.

---

## Schema Architecture

### Private Schema + Public Wrappers

```
@extschema@ (e.g. rbac) — NOT in PostgREST exposed schemas
├── Tables: groups, members, invites, roles (with permissions[]),
│           user_claims, member_permissions
├── Internal: db_pre_request [INVOKER], _get_user_groups [INVOKER],
│             _build_user_claims [STABLE], _sync_member_metadata [INVOKER],
│             _sync_member_permission [INVOKER],
│             _on_role_permissions_change [INVOKER], _set_updated_at,
│             _jwt_is_expired, _validate_roles
├── Auth Hook: custom_access_token_hook [INVOKER]
├── RLS helpers: get_claims, has_role, is_member, has_any_role, has_all_roles,
│               has_permission, has_any_permission, has_all_permissions
├── Member mgmt: create_group [DEFINER], delete_group [INVOKER],
│                add_member [INVOKER], remove_member [INVOKER],
│                update_member_roles [INVOKER], list_members [INVOKER],
│                accept_invite [DEFINER]
├── Override mgmt: grant_member_permission [INVOKER],
│                  revoke_member_permission [INVOKER],
│                  list_member_permissions [INVOKER]
├── Role mgmt:   create_role [service_role], delete_role [service_role],
│                list_roles [service_role]
└── Perm mgmt:   set_role_permissions [service_role], grant_permission [service_role],
                 revoke_permission [service_role], list_role_permissions [service_role]

public (opt-in wrappers — run examples/setup/create_public_wrappers.sql after install)
├── RLS helpers + member management RPCs + custom_access_token_hook
└── Thin pass-throughs to @extschema@.*
    NOTE: Permission management RPCs are NOT wrapped — service_role only.
```

**Why private schema?** Tables are NOT REST-accessible (schema not in PostgREST's `db_schemas`). All interaction goes through RPC functions, reducing the attack surface.

**Why opt-in public wrappers?** PostgREST discovers RPC functions in its exposed schemas (typically `public`). The wrappers enable `supabase.rpc('has_role', ...)` without extra configuration. They also allow unqualified function names in RLS policies: `USING (has_role(group_id, 'admin'))`. Wrappers are opt-in (not auto-created) so the default install has zero public surface area.

### Security Model for INVOKER RPCs

SECURITY INVOKER RPCs respect RLS on the `rbac.*` tables. The `authenticated` role has DML grants on all rbac tables, but RLS (deny-all, zero policies on install) controls row access. Consumers add RLS policies to define their authorization rules.

SECURITY DEFINER is reserved for bootstrap operations only:
- `create_group` — no prior membership exists for the caller to satisfy RLS
- `accept_invite` — user doesn't have group membership yet

---

## Functions

### Internal Functions

#### `db_pre_request()` → void
**SECURITY INVOKER** | Called automatically by PostgREST before each request.
Reads the current user's `claims` from `rbac.user_claims` and stores it in the `request.groups` session config variable. Runs as the `authenticator` role.

#### `_get_user_groups()` → jsonb
**SECURITY INVOKER** | Fallback in `get_claims()` for the Storage path.
Reads `claims` from `rbac.user_claims` for `auth.uid()`. Returns `'{}'` for unauthenticated/groupless users.

#### `_build_user_claims(p_user_id uuid)` → jsonb
**STABLE SQL** | Internal helper used by both sync triggers.
Builds the full claims object for a user by joining `members` with `roles`. Resolves and deduplicates permissions across all roles the user holds in each group. Returns `{}` if the user has no memberships.

#### `_sync_member_metadata()` → trigger
**SECURITY INVOKER** | AFTER INSERT OR DELETE OR UPDATE on `members`.
Calls `_build_user_claims()` and upserts the result into `rbac.user_claims`. Enforces immutability of `user_id`/`group_id` on UPDATE.

#### `_on_role_permissions_change()` → trigger
**SECURITY INVOKER** | AFTER UPDATE on `roles` (only when `permissions` actually changes).
Finds all users holding the changed role and rebuilds their claims via `_build_user_claims()`. Admin operation — cost is proportional to the number of users assigned the role.

#### `custom_access_token_hook(event jsonb)` → jsonb
**SECURITY INVOKER** | Supabase Auth Hook called at JWT creation time.
Reads `claims` from `rbac.user_claims` for `event.user_id` and injects them into `event.claims.app_metadata.groups`. Runs as `supabase_auth_admin`. Register in `config.toml`.

#### `_set_updated_at()` → trigger
Sets `NEW.updated_at = now()`. Replaces the `moddatetime` dependency.

#### `_jwt_is_expired()` → boolean
Returns `true` if the JWT `exp` claim is in the past or missing.

#### `_validate_roles(p_roles text[])` → void
Checks that every role in the array exists in the `roles` table. Raises a descriptive error listing undefined roles.

### RLS Helper Functions

| Function | Returns | Description |
|----------|---------|-------------|
| `get_claims()` | `jsonb` | Returns current user's full claims (nested roles + permissions) |
| `has_role(group_id, role)` | `boolean` | User has specific role in group |
| `is_member(group_id)` | `boolean` | User is a member of group (any role) |
| `has_any_role(group_id, roles[])` | `boolean` | User has any of the listed roles |
| `has_all_roles(group_id, roles[])` | `boolean` | User has all of the listed roles |
| `has_permission(group_id, permission)` | `boolean` | User has a specific resolved permission in group |
| `has_any_permission(group_id, permissions[])` | `boolean` | User has any of the listed permissions |
| `has_all_permissions(group_id, permissions[])` | `boolean` | User has all of the listed permissions |

Permissions are resolved from `roles.permissions[]` at write time (claims cache). Using `has_permission()` in RLS is as fast as `has_role()` — both are single JSONB key lookups against the cached claims.

**Auth tier logic** (applies to all helpers except `get_claims`):
- `authenticated`: validates JWT not expired, checks claims
- `anon`: always `false`
- `session_user = 'postgres'` or `service_role`: always `true`
- anything else: always `false`

### Management RPCs

| Function | Security | Description |
|----------|----------|-------------|
| `create_group(name, metadata, creator_roles)` → `uuid` | DEFINER | Create group + add caller as member. Default roles: `ARRAY['owner']` |
| `delete_group(p_group_id)` | INVOKER | Delete a group (RLS enforced) |
| `add_member(p_group_id, p_user_id, p_roles)` → `uuid` | INVOKER | Add member or merge roles on conflict |
| `remove_member(p_group_id, p_user_id)` | INVOKER | Remove a member (RLS enforced) |
| `update_member_roles(p_group_id, p_user_id, p_roles)` | INVOKER | Replace roles array (RLS enforced) |
| `list_members(p_group_id)` → `TABLE(...)` | INVOKER | List group members (RLS enforced) |
| `accept_invite(p_invite_id)` → `void` | DEFINER | Accept invite, upsert membership with role merge |
| `create_role(p_name, p_description)` → `void` | service_role only | Add a role definition |
| `delete_role(p_name)` → `void` | service_role only | Delete a role (blocked if in use) |
| `list_roles()` → `TABLE(name, description, permissions[], created_at)` | service_role only | List all role definitions |
| `set_role_permissions(p_role_name, p_permissions[])` → `void` | service_role only | Replace all permissions for a role |
| `grant_permission(p_role_name, p_permission)` → `void` | service_role only | Add one permission to a role (idempotent) |
| `revoke_permission(p_role_name, p_permission)` → `void` | service_role only | Remove one permission from a role |
| `list_role_permissions(p_role_name DEFAULT NULL)` → `TABLE(role_name, permission)` | service_role only | List permissions per role |
| `grant_member_permission(p_group_id, p_user_id, p_permission)` → `void` | INVOKER | Grant a direct permission override to a member (idempotent) |
| `revoke_member_permission(p_group_id, p_user_id, p_permission)` → `void` | INVOKER | Remove a direct permission override (raises if not found) |
| `list_member_permissions(p_group_id, p_user_id DEFAULT NULL)` → `TABLE(user_id, permission, created_at)` | INVOKER | List direct overrides in a group (all members or one) |

---

## Role Model Strategies

The extension validates roles against the `roles` table, but the naming convention is up to you.

### Role-Centric with Permissions
```
owner  → permissions: ['group.delete', 'group.update', 'member.add', ...]
admin  → permissions: ['member.add', 'member.remove', 'data.create', ...]
viewer → permissions: ['data.read']
```
RLS by role: `has_role(group_id, 'admin')`
RLS by permission: `has_permission(group_id, 'data.read')`

### Permission-Centric Roles (flat)
Name roles as permission strings and give each role a single matching permission:
```
group_data.read → permissions: ['group_data.read']
group_user.invite → permissions: ['group_user.invite']
```
RLS: `has_permission(group_id, 'group_data.read')`

**Hybrid:** Use coarse roles (owner/admin/viewer) for simple checks and fine-grained permissions for specific operations. `has_role()` for catch-alls, `has_permission()` for specific capabilities.

---

## Invite System Flow

```
1. An owner/admin creates an invite via direct INSERT (per RLS):
   INSERT INTO rbac.invites (group_id, roles, invited_by)
   VALUES ('<group-uuid>', ARRAY['viewer'], auth.uid());
   → id (invite code) is auto-generated

2. Inviter shares the invite code (UUID) with the target user

3. Target user calls the edge function or RPC directly:
   POST /functions/v1/invite?invite_code=<uuid>
   Authorization: Bearer <user-jwt>

4. accept_invite() [SECURITY DEFINER] runs:
   a. Locks invite row (SELECT FOR UPDATE)
   b. Validates: not accepted, not expired
   c. Marks invite as accepted (sets user_id and accepted_at)
   d. Upserts into members (merges roles on conflict)
   e. _sync_member_metadata trigger fires → updates auth.users

5. User now has group membership; next API request sees fresh claims
```

---

## Extension Packaging

The extension follows standard PostgreSQL TLE conventions:
- **Control file** (`supabase_rbac.control`): declares version, `superuser = true`
- **Full install scripts**: `supabase_rbac--X.Y.Z.sql` for fresh installs
- **Upgrade scripts**: `supabase_rbac--A--B.sql` for in-place upgrades
- Distributed on [database.dev](https://database.dev/pointsource/supabase_rbac)

### Migration Generator

`tools/generate_migration.sh` reads the version from the control file, wraps the extension SQL in `pgtle.install_extension()` boilerplate, and generates `CREATE SCHEMA IF NOT EXISTS rbac` + `CREATE EXTENSION ... SCHEMA rbac`.

---

## Local Dev Architecture

- **Migrations** run in order on `supabase start` or `supabase db reset`
- **Seed** (`seed.sql`) creates test users, groups, members, and role definitions
- The extension is installed via `pgtle.install_extension()` followed by `CREATE EXTENSION ... SCHEMA rbac`
- Local PostgreSQL runs at port `54322`, API at `54321`, Studio at `54323`
