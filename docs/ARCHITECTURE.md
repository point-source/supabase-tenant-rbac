# Architecture

## Overview

`supabase-tenant-rbac` provides multi-tenant role-based access control (RBAC) as a PostgreSQL TLE. It stores group memberships in a relational table, propagates them into an extension-owned `user_claims` cache via trigger, and makes them available to RLS policies via a PostgREST pre-request hook — ensuring claims are always fresh on every API request. An optional Supabase Auth Hook injects claims into JWTs at token creation time.

As of v5.0.0, all tables live in a **private schema** (recommended: `rbac`) that is not exposed to PostgREST. All interaction goes through typed RPC functions, with optional public wrappers auto-created for PostgREST discovery.

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
Global role definitions. All management RPCs validate role assignments against this table.

| Column | Type | Notes |
|--------|------|-------|
| `name` | `text` | Primary key. The role string. |
| `description` | `text` | Optional human-readable description. |
| `created_at` | `timestamptz` | Auto-set on insert |

Pre-seeded with `'owner'` (default role for `create_group`).

#### `user_claims`
Claims cache. One row per user, auto-managed by the `_sync_member_metadata` trigger.

| Column | Type | Notes |
|--------|------|-------|
| `user_id` | `uuid` | Primary key, FK → `auth.users(id)` ON DELETE CASCADE |
| `claims` | `jsonb` | Group/role map: `{"<group-uuid>": ["role1", "role2"], ...}` |

**Never write to this table directly.** It is updated automatically whenever `members` changes.

### Claims Storage Format

When roles are assigned, `rbac.user_claims` stores:

```json
{
  "<group-uuid>": ["role1", "role2"],
  "<other-group-uuid>": ["viewer"]
}
```

The `custom_access_token_hook` injects this into JWT `app_metadata.groups` at token creation:

```json
{
  "app_metadata": {
    "groups": {
      "<group-uuid>": ["role1", "role2"]
    }
  }
}
```

---

## Claims Synchronization Flow

```
1. Management RPC (add_member, create_group, etc.) modifies members table
         │
         ▼
2. AFTER trigger fires: on_change_sync_member_metadata
         │
         ▼
3. _sync_member_metadata() [SECURITY INVOKER] runs
   - Rebuilds the entire user's claims:
     SELECT jsonb_object_agg(group_id::text, to_jsonb(roles))
     FROM members WHERE user_id = _user_id
   - Upserts result into rbac.user_claims
         │
         ▼
4. rbac.user_claims now reflects current memberships
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
├── Tables: groups, members, invites, roles, user_claims
├── Internal: db_pre_request [INVOKER], _get_user_groups [INVOKER],
│             _sync_member_metadata [INVOKER], _set_updated_at,
│             _jwt_is_expired, _validate_roles
├── Auth Hook: custom_access_token_hook [INVOKER]
├── RLS helpers: get_claims, has_role, is_member, has_any_role, has_all_roles
├── Member mgmt: create_group [DEFINER], delete_group [INVOKER],
│                add_member [INVOKER], remove_member [INVOKER],
│                update_member_roles [INVOKER], list_members [INVOKER],
│                accept_invite [DEFINER]
└── Role mgmt:   create_role [INVOKER], delete_role [INVOKER], list_roles [INVOKER]

public (auto-created wrappers, conditional: only when @extschema@ != 'public')
├── All RLS helpers + management RPCs + role RPCs + custom_access_token_hook
└── Thin pass-throughs to @extschema@.* — tracked as extension members
```

**Why private schema?** Tables are NOT REST-accessible (schema not in PostgREST's `db_schemas`). All interaction goes through RPC functions, reducing the attack surface.

**Why public wrappers?** PostgREST discovers RPC functions in its exposed schemas (typically `public`). The wrappers enable `supabase.rpc('has_role', ...)` without extra configuration. They also allow unqualified function names in RLS policies: `USING (has_role(group_id, 'admin'))`.

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

#### `_sync_member_metadata()` → trigger
**SECURITY INVOKER** | AFTER INSERT OR DELETE OR UPDATE on `members`.
Rebuilds the entire user's claims via `jsonb_object_agg` and upserts into `rbac.user_claims`. Enforces immutability of `user_id`/`group_id` on UPDATE.

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
| `get_claims()` | `jsonb` | Returns current user's group/role claims |
| `has_role(group_id, role)` | `boolean` | User has specific role in group |
| `is_member(group_id)` | `boolean` | User is a member of group (any role) |
| `has_any_role(group_id, roles[])` | `boolean` | User has any of the listed roles |
| `has_all_roles(group_id, roles[])` | `boolean` | User has all of the listed roles |

**Auth tier logic** (applies to `has_role`, `is_member`, `has_any_role`, `has_all_roles`):
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
| `create_role(p_name, p_description)` → `void` | INVOKER | Add a role definition (RLS enforced) |
| `delete_role(p_name)` → `void` | INVOKER | Delete a role (blocked if in use) |
| `list_roles()` → `TABLE(...)` | INVOKER | List all role definitions (RLS enforced) |

---

## Role Model Strategies

The extension validates roles against the `roles` table, but the naming convention is up to you.

### Role-Centric
```
owner  →  full group control
admin  →  manage users, update group
viewer →  read-only access
```
RLS: `has_role(group_id, 'admin')`

### Permission-Centric
```
group.update        group.delete
group_data.create   group_data.read   group_data.update   group_data.delete
group_user.create   group_user.read   group_user.update   group_user.delete
```
RLS: `has_role(group_id, 'group_data.read')`

**Hybrid:** Combine both. Check catch-all roles first in OR chains for performance.

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
