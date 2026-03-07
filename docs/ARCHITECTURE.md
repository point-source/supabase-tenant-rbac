# Architecture

This document describes the internal structure of the Supabase Tenant RBAC extension — the tables, triggers, functions, and data flows that make the system work. Read [docs/CONCEPTUAL_MODEL.md](CONCEPTUAL_MODEL.md) first for the conceptual background.

## Table of Contents

1. [Table Schemas](#table-schemas)
2. [Trigger Flow](#trigger-flow)
3. [_build_user_claims() — The Resolution Algorithm](#_build_user_claims--the-resolution-algorithm)
4. [db_pre_request Hook](#db_pre_request-hook)
5. [Auth Hook](#auth-hook)
6. [Storage RLS Fallback](#storage-rls-fallback)
7. [File Relationships Diagram](#file-relationships-diagram)
8. [SECURITY DEFINER Functions](#security-definer-functions)

---

## Table Schemas

All tables live in the `rbac` schema (the extension schema, `@extschema@`). None are exposed via PostgREST directly.

### `permissions`

The canonical registry of all permission strings.

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `name` | `text` | PRIMARY KEY | The permission string, e.g. `data.read` |
| `description` | `text` | | Human-readable description |
| `created_at` | `timestamptz` | NOT NULL DEFAULT now() | |

RLS: enabled, deny-all on install. App author must add policies or use `service_role`.

### `roles`

Role definitions. The app author creates roles once; they apply to all groups.

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `name` | `text` | PRIMARY KEY | The role name, e.g. `editor` |
| `description` | `text` | | Human-readable description |
| `permissions` | `text[]` | NOT NULL DEFAULT `'{}'` | Permission strings granted to holders of this role. Each must exist in `permissions` table |
| `grantable_roles` | `text[]` | NOT NULL DEFAULT `'{}'` | Role names that holders of this role can assign. `'*'` wildcard means any role |
| `created_at` | `timestamptz` | NOT NULL DEFAULT now() | |
| `updated_at` | `timestamptz` | NOT NULL DEFAULT now() | Maintained by `_set_updated_at` trigger |

Pre-seeded: `owner` with `grantable_roles = ARRAY['*']`.

RLS: enabled, deny-all on install. `authenticated` has no SELECT by default. App authors who want users to browse role definitions must explicitly grant SELECT and add an RLS policy.

### `groups`

Tenants or organizations.

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `id` | `uuid` | PRIMARY KEY DEFAULT gen_random_uuid() | |
| `name` | `text` | NOT NULL | Display name |
| `metadata` | `jsonb` | NOT NULL DEFAULT `'{}'` | Arbitrary app-defined metadata |
| `created_at` | `timestamptz` | NOT NULL DEFAULT now() | |
| `updated_at` | `timestamptz` | NOT NULL DEFAULT now() | Maintained by `_set_updated_at` trigger |

RLS: enabled, deny-all on install.

### `members`

One row per user-group membership.

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `id` | `uuid` | PRIMARY KEY DEFAULT gen_random_uuid() | |
| `group_id` | `uuid` | NOT NULL REFERENCES groups(id) ON DELETE CASCADE | |
| `user_id` | `uuid` | NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE | |
| `roles` | `text[]` | NOT NULL DEFAULT `'{}'` | Assigned role names. Each must exist in `roles` table |
| `metadata` | `jsonb` | NOT NULL DEFAULT `'{}'` | Arbitrary app-defined metadata |
| `created_at` | `timestamptz` | NOT NULL DEFAULT now() | |
| `updated_at` | `timestamptz` | NOT NULL DEFAULT now() | Maintained by `_set_updated_at` trigger |

UNIQUE constraint: `(group_id, user_id)` — named `members_group_user_uq`. Required for the `member_permissions` FK reference.

RLS: enabled, deny-all on install.

### `member_permissions`

Direct per-member permission overrides. Grants a specific permission to a specific member without assigning a role.

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `id` | `uuid` | PRIMARY KEY DEFAULT gen_random_uuid() | |
| `group_id` | `uuid` | NOT NULL | Part of FK to members |
| `user_id` | `uuid` | NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE | |
| `permission` | `text` | NOT NULL | Must exist in `permissions` table |
| `created_at` | `timestamptz` | NOT NULL DEFAULT now() | |

UNIQUE constraint: `(group_id, user_id, permission)` — makes grants idempotent (INSERT ... ON CONFLICT DO NOTHING).

FK: `(group_id, user_id)` REFERENCES `members(group_id, user_id)` ON DELETE CASCADE — overrides are automatically deleted when the member is removed.

RLS: enabled, deny-all on install.

### `invites`

Invite codes for group membership.

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `id` | `uuid` | PRIMARY KEY DEFAULT gen_random_uuid() | The invite code |
| `group_id` | `uuid` | NOT NULL REFERENCES groups(id) ON DELETE CASCADE | |
| `roles` | `text[]` | NOT NULL DEFAULT `'{}'` | Roles the invitee receives on acceptance |
| `invited_by` | `uuid` | NOT NULL REFERENCES auth.users(id) | Set to `auth.uid()` at creation |
| `user_id` | `uuid` | REFERENCES auth.users(id) | Populated on acceptance |
| `accepted_at` | `timestamptz` | | Populated on acceptance |
| `expires_at` | `timestamptz` | | NULL means never expires |
| `created_at` | `timestamptz` | NOT NULL DEFAULT now() | |

RLS: enabled, deny-all on install.

### `user_claims`

The claims cache. One row per user. Never written to directly — maintained exclusively by trigger functions.

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| `user_id` | `uuid` | PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE | |
| `claims` | `jsonb` | NOT NULL DEFAULT `'{}'` | Keyed by group UUID. See format below |

**Claims format:**

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

RLS: enabled. `authenticated` has SELECT on own row only. `authenticator` has SELECT (for `db_pre_request`). `supabase_auth_admin` has SELECT (for auth hook). `service_role` has ALL. No INSERT or UPDATE for `authenticated` — writes are exclusively via DEFINER trigger functions.

---

## Trigger Flow

Three triggers maintain the claims cache automatically. A fourth trigger bootstraps group creator membership.

```
groups table
    INSERT
        │
        └── trigger: on_group_created
            (AFTER INSERT, FOR EACH ROW)
                │
                └── calls: _on_group_created() [SECURITY DEFINER]
                        │
                        └── reads auth.uid() — skips if NULL (service_role/migration)
                        └── reads rbac.creator_roles session var (set by create_group)
                        └── validates roles via _validate_roles()
                        └── INSERT into rbac.members (bootstraps creator membership)

members table
    INSERT / UPDATE / DELETE
        │
        └── trigger: on_change_sync_member_metadata
            (AFTER INSERT OR UPDATE OR DELETE, FOR EACH ROW)
                │
                └── calls: _sync_member_metadata() [SECURITY DEFINER]
                        │
                        └── calls: _build_user_claims(affected_user_id)
                        └── UPSERT into rbac.user_claims

member_permissions table
    INSERT / DELETE
        │
        └── trigger: on_member_permission_change
            (AFTER INSERT OR DELETE, FOR EACH ROW)
                │
                └── calls: _sync_member_permission() [SECURITY DEFINER]
                        │
                        └── calls: _build_user_claims(affected_user_id)
                        └── UPSERT into rbac.user_claims

roles table
    UPDATE (WHEN permissions[] changed OR grantable_roles[] changed)
        │
        └── trigger: on_role_definition_change
            (AFTER UPDATE, FOR EACH ROW,
             WHEN OLD.permissions <> NEW.permissions
               OR OLD.grantable_roles <> NEW.grantable_roles)
                │
                └── calls: _on_role_definition_change() [SECURITY DEFINER]
                        │
                        └── for each member holding the updated role:
                            └── calls: _build_user_claims(member_user_id)
                            └── UPSERT into rbac.user_claims
```

All three trigger functions are SECURITY DEFINER so they can write to `user_claims` without requiring INSERT/UPDATE grants for `authenticated`. The trigger functions (`RETURNS trigger`) cannot be called directly via RPC or REST — DEFINER on trigger functions does not expand the API surface.

---

## Index-Aware Role Lookups

The `members.roles` column has a GIN index (`members_roles_gin_idx`) to support fast role-membership lookups on large datasets.

Internal role lookups that can touch many rows use array containment syntax:

- `members.roles @> ARRAY[role_name]`

instead of:

- `role_name = ANY(members.roles)`

This operator choice matters because the containment form is GIN-friendly, while the `ANY(...)` form is often planned as a sequential scan.

The two main internal paths that rely on this are:

- `delete_role()` "role in use" guard
- `_on_role_definition_change()` affected-user selection

---

## `_build_user_claims()` — The Resolution Algorithm

`_build_user_claims(p_user_id uuid)` is the internal function that computes the full claims object for a user. It is called by all three trigger functions and is never called directly by application code.

**Algorithm:**

```
1. Query all memberships for p_user_id from rbac.members.
   For each membership (group_id, roles[]):

   a. Resolve permissions:
      - For each role name in members.roles[]:
          collect roles.permissions[] from rbac.roles
      - SELECT permission FROM rbac.member_permissions
          WHERE group_id = <group_id> AND user_id = p_user_id
      - UNION ALL of role permissions + direct overrides
      - SELECT DISTINCT to deduplicate
      → result: permissions[]

   b. Resolve grantable_roles:
      - For each role name in members.roles[]:
          collect roles.grantable_roles[] from rbac.roles
      - If any collected array contains '*', result is ['*']
      - Otherwise, UNION ALL + DISTINCT
      → result: grantable_roles[]

   c. Resolve grantable_permissions:
      - If grantable_roles = ['*']: result is ['*']
      - Otherwise, for each role name in grantable_roles:
          collect roles.permissions[] from rbac.roles
      - UNION ALL + DISTINCT
      → result: grantable_permissions[]

   d. Build the group entry:
      {
        "roles": members.roles[],
        "permissions": permissions[],
        "grantable_roles": grantable_roles[],
        "grantable_permissions": grantable_permissions[]
      }

2. Construct the full claims object:
   {
     "<group-uuid-1>": { ... },
     "<group-uuid-2>": { ... }
   }
   (one entry per group the user is a member of)

3. UPSERT into rbac.user_claims:
   INSERT INTO rbac.user_claims (user_id, claims)
   VALUES (p_user_id, <claims_object>)
   ON CONFLICT (user_id) DO UPDATE SET claims = <claims_object>

   If the user has no memberships, upserts with claims = '{}'.
```

**Why full rebuild instead of incremental update?**

A full rebuild from source tables is simpler and safer than incremental updates. There is no risk of incremental update bugs, no need to track what changed, and the result is always consistent with the source tables. The write path (membership and role definition changes) is infrequent enough that the full rebuild cost is acceptable.

---

## `db_pre_request` Hook

`db_pre_request()` is a SECURITY INVOKER function registered as the PostgREST `pgrst.db_pre_request` hook on the `authenticator` role.

**When it runs:** Before every PostgREST API request. It does not run for Supabase Storage requests.

**What it does:**

```
1. Read auth.uid() from the current JWT.
2. If auth.role() = 'anon' or auth.uid() is NULL:
     set_config('request.groups', '{}', true)
     return
3. SELECT claims FROM rbac.user_claims WHERE user_id = auth.uid()
4. set_config('request.groups', claims::text, true)
   (session-local: true — resets at transaction end)
```

**What it provides:**

All RLS helper functions (`has_role`, `is_member`, `has_permission`, etc.) call `get_claims()` internally. `get_claims()` reads the `request.groups` session variable set by `db_pre_request`. This means:

- The database read from `user_claims` happens once per request, not once per row in a query.
- Role changes take effect on the next request — not on the next token refresh.
- The session variable is transaction-local, so it cannot leak between requests.

**Registration:**

```sql
ALTER ROLE authenticator SET pgrst.db_pre_request TO 'rbac.db_pre_request';
NOTIFY pgrst, 'reload config';
```

This is done automatically at extension install time.

---

## Auth Hook

`custom_access_token_hook(event jsonb)` is an optional Supabase Auth Hook that injects group claims into JWTs at token-creation time.

**Purpose:** Provides convenient client-side access to claims without a database round-trip. The JWT's `app_metadata.groups` field contains the same structure as `user_claims.claims`.

**How it works:**

```
1. Extract user_id from event.user_id.
2. SELECT claims FROM rbac.user_claims WHERE user_id = <user_id>
3. Merge claims into event.claims.app_metadata.groups
4. Return the modified event
```

**Important:** The auth hook runs at token-creation time. Claims in the JWT may become stale if group memberships change before the token expires. `db_pre_request` provides the freshness guarantee — the auth hook is complementary, not a replacement.

**Registration in config.toml:**

```toml
[auth.hook.custom_access_token]
enabled = true
uri = "pg-functions://postgres/rbac/custom_access_token_hook"
```

Or if using public wrappers:
```toml
uri = "pg-functions://postgres/public/custom_access_token_hook"
```

**Grants required:**

```sql
GRANT USAGE ON SCHEMA rbac TO supabase_auth_admin;
GRANT SELECT ON rbac.user_claims TO supabase_auth_admin;
GRANT EXECUTE ON FUNCTION rbac.custom_access_token_hook TO supabase_auth_admin;
```

These are set at install time.

---

## Storage RLS Fallback

Supabase Storage routes requests through a separate code path that does not invoke the PostgREST `db_pre_request` hook. As a result, `request.groups` is not set for Storage requests.

`get_claims()` handles this with a fallback:

```sql
-- Pseudocode for get_claims()
DECLARE
  v_groups text := current_setting('request.groups', true);
BEGIN
  -- PostgREST path: request.groups was set by db_pre_request
  IF v_groups IS NOT NULL AND v_groups != '' THEN
    RETURN v_groups::jsonb;
  END IF;

  -- Storage path: read user_claims directly
  RETURN coalesce(
    (SELECT claims FROM rbac.user_claims WHERE user_id = auth.uid()),
    '{}'::jsonb
  );
END;
```

All RLS helper functions call `get_claims()`, so they work correctly in both PostgREST and Storage contexts without any changes to RLS policies.

`_get_user_groups()` is the internal function that performs the direct `user_claims` read for the Storage fallback. It is SECURITY INVOKER and has EXECUTE granted to `authenticated` and `service_role`.

---

## File Relationships Diagram

```
members (INSERT/UPDATE/DELETE)
    └── trigger: on_change_sync_member_metadata
        └── calls: _sync_member_metadata()  [SECURITY DEFINER]
            └── calls: _build_user_claims(user_id)
                └── resolves permissions from roles.permissions[]
                └── resolves grantable_roles from roles.grantable_roles[]
                └── resolves grantable_permissions from grantable_roles
                └── + direct overrides from member_permissions
            └── upserts: rbac.user_claims

member_permissions (INSERT/DELETE)
    └── trigger: on_member_permission_change
        └── calls: _sync_member_permission()  [SECURITY DEFINER]
            └── calls: _build_user_claims(user_id)
            └── upserts: rbac.user_claims

roles (UPDATE permissions[] OR grantable_roles[])
    └── trigger: on_role_definition_change
        (WHEN OLD.permissions <> NEW.permissions
          OR OLD.grantable_roles <> NEW.grantable_roles)
        └── calls: _on_role_definition_change()  [SECURITY DEFINER]
            └── for each user holding the role:
                └── calls: _build_user_claims(user_id)
                └── upserts: rbac.user_claims

Every PostgREST API request:
    └── db_pre_request()  [SECURITY INVOKER, registered on authenticator role]
        └── reads: rbac.user_claims
        └── writes: request.groups (session config)

Token creation (Supabase Auth Hook):
    └── custom_access_token_hook()  [SECURITY INVOKER, supabase_auth_admin]
        └── reads: rbac.user_claims
        └── injects: claims.app_metadata.groups into JWT

RLS policies call:
    └── has_role / has_any_role / has_all_roles
    │   has_permission / has_any_permission / has_all_permissions
    │   is_member
        └── calls: get_claims()
            └── reads: request.groups (PostgREST path, from db_pre_request)
            └── fallback: _get_user_groups() [SECURITY INVOKER] (Storage path)
                └── reads: rbac.user_claims directly

Management RPCs (add_member, update_member_roles, create_invite,
                 grant_member_permission, revoke_member_permission):
    └── reads: request.groups (grantable_roles, grantable_permissions)
    └── enforces escalation check before write
    └── calls: _check_role_escalation() / _check_permission_escalation()
    └── calls: _validate_roles() [SECURITY DEFINER] to check role names
    └── calls: _validate_permissions() [SECURITY DEFINER] to check permission names
    └── calls: _validate_grantable_roles() [SECURITY DEFINER] for role-definition validation
```

---

## SECURITY DEFINER Functions

The extension minimizes SECURITY DEFINER surface. Only 8 functions have this property, each with a documented justification.

| Function | Type | Why DEFINER | What it does | What it does NOT do |
|----------|------|-------------|-------------|---------------------|
| `_on_group_created()` | Trigger function | AFTER INSERT on `groups`. Caller has no prior membership to satisfy RLS on `members` at creation time | Reads `auth.uid()`, validates creator roles, inserts caller as member. Skips when `auth.uid()` is NULL (service_role/migration inserts) | Cannot be called directly via RPC or REST (trigger-only) |
| `accept_invite()` | Management RPC | Caller has no prior membership in the target group | Validates invite, marks it used, upserts caller as member | Does not bypass membership validation or expiry check |
| `_sync_member_metadata()` | Trigger function | Must write to `user_claims` without requiring INSERT/UPDATE grants for `authenticated` | Calls `_build_user_claims()`, upserts to `user_claims` | Cannot be called directly via RPC or REST (trigger-only) |
| `_sync_member_permission()` | Trigger function | Must write to `user_claims` without requiring INSERT/UPDATE grants for `authenticated` | Calls `_build_user_claims()`, upserts to `user_claims` | Cannot be called directly via RPC or REST (trigger-only) |
| `_on_role_definition_change()` | Trigger function | Must write to `user_claims` for all affected users without requiring broad grants | Iterates affected members, calls `_build_user_claims()` per user | Cannot be called directly via RPC or REST (trigger-only) |
| `_validate_roles()` | Internal helper | INVOKER RPCs need to validate role names against `rbac.roles`, but `authenticated` has no SELECT on that table | Reads `roles.name`, raises if any name is unrecognized | No writes; no user-controllable output beyond the exception message |
| `_validate_permissions()` | Internal helper | INVOKER RPCs need to validate permission names against `rbac.permissions`, but `authenticated` has no SELECT on that table | Reads `permissions.name`, raises if any name is unrecognized | No writes; no user-controllable output beyond the exception message |
| `_validate_grantable_roles()` | Internal helper | INVOKER role-management RPCs need to validate that `grantable_roles[]` entries exist in `rbac.roles` (or are `'*'`) | Reads `roles.name`, raises for undefined role names | No writes; no caller-scope escalation logic |

All other internal helper functions (`_build_user_claims`, `_get_user_groups`, `_jwt_is_expired`, `_set_updated_at`) are SECURITY INVOKER.

All `_`-prefixed functions have `REVOKE EXECUTE FROM PUBLIC`. Selective re-grants:
- `_get_user_groups`: re-granted to `authenticated, service_role` (called by `get_claims()` Storage fallback)
- `_jwt_is_expired`: re-granted to `authenticated, anon, service_role` (called by all RLS helpers)
- `_build_user_claims`, `_on_group_created`, `_validate_roles`, `_validate_permissions`, `_validate_grantable_roles`, `_set_updated_at`: no re-grant (DEFINER callers or trigger mechanism only)
