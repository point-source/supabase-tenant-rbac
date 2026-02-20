# Architecture

## Overview

`supabase-tenant-rbac` provides multi-tenant role-based access control (RBAC) as a PostgreSQL TLE. It stores group memberships in a relational table, propagates them into `auth.users` metadata via trigger, and makes them available to RLS policies via a PostgREST pre-request hook — ensuring claims are always fresh on every API request.

---

## Data Model

### Tables

#### `groups`
Represents a tenant, organization, team, or any logical grouping.

| Column | Type | Notes |
|--------|------|-------|
| `id` | `uuid` | Primary key, auto-generated |
| `metadata` | `jsonb` | Arbitrary group data (name, settings, etc.) Default: `{}` |
| `created_at` | `timestamptz` | Auto-set on insert |
| `updated_at` | `timestamptz` | Auto-updated via `moddatetime` trigger |

#### `group_users`
Maps users to groups with a specific role. One row per user-group-role combination.

| Column | Type | Notes |
|--------|------|-------|
| `id` | `uuid` | Primary key, auto-generated |
| `group_id` | `uuid` | FK → `groups(id)` |
| `user_id` | `uuid` | FK → `auth.users(id)` |
| `role` | `text` | Role or permission string (unconstrained, app-defined) |
| `metadata` | `jsonb` | Arbitrary user-in-group data. Default: `{}` |
| `created_at` | `timestamptz` | Auto-set on insert |
| `updated_at` | `timestamptz` | Auto-updated via `moddatetime` trigger |

**Unique constraint:** `(group_id, user_id, role)` — prevents duplicate role assignments.

A user can have **multiple roles** in a single group (each is a separate row). A user can be in **multiple groups** simultaneously.

#### `group_invites`
An invite code allowing a user to join a group with pre-specified roles.

| Column | Type | Notes |
|--------|------|-------|
| `id` | `uuid` | Primary key AND invite code, auto-generated |
| `group_id` | `uuid` | FK → `groups(id)` |
| `roles` | `text[]` | Roles to assign when invite is accepted. Must have ≥1 role. |
| `invited_by` | `uuid` | FK → `auth.users(id)` |
| `created_at` | `timestamptz` | Auto-set on insert |
| `user_id` | `uuid` | FK → `auth.users(id)`. NULL until accepted. |
| `accepted_at` | `timestamptz` | NULL until accepted. |

### Claims Storage Format

When roles are assigned, `auth.users.raw_app_meta_data` is updated to contain:

```json
{
  "groups": {
    "<group-uuid>": ["role1", "role2"],
    "<other-group-uuid>": ["viewer"]
  },
  "provider": "email",
  "providers": ["email"]
}
```

The `groups` key is managed entirely by this extension. The `provider`/`providers` keys are standard Supabase fields and are preserved.

---

## Claims Synchronization Flow

```
1. Admin/user inserts/updates/deletes a row in group_users
         │
         ▼
2. AFTER trigger fires: on_change_update_user_metadata
         │
         ▼
3. update_user_roles() [SECURITY DEFINER] runs
   - Reads current raw_app_meta_data from auth.users
   - On DELETE or role change: removes old role from the JSONB array
   - On INSERT or role change: adds new role to the JSONB array (DISTINCT)
   - Writes updated raw_app_meta_data back to auth.users
         │
         ▼
4. auth.users.raw_app_meta_data now reflects current memberships
   (This is included in the JWT on the NEXT session creation)
         │
         ▼
5. On every PostgREST API request, BEFORE the query runs:
   db_pre_request() [SECURITY DEFINER] executes
   - Reads raw_app_meta_data->'groups' from auth.users for auth.uid()
   - Stores it in session config: request.groups
         │
         ▼
6. RLS policies evaluate using user_has_group_role() / user_is_group_member()
   - These call get_user_claims()
   - get_user_claims() reads request.groups (fresh, from step 5)
   - Falls back to auth.jwt()->'app_metadata'->'groups' if request.groups is null
```

**Key insight:** Step 5 happens on *every* API request, so role changes take effect immediately — no waiting for JWT expiry or re-login.

---

## Functions

### `db_pre_request()` → void
**SECURITY DEFINER** | Called automatically by PostgREST before each request.

Reads the current user's `raw_app_meta_data->'groups'` from `auth.users` and stores it in the `request.groups` session config variable. This ensures RLS policies always see the latest group/role data, not potentially stale JWT data.

Registered via:
```sql
ALTER ROLE authenticator SET pgrst.db_pre_request TO 'db_pre_request';
```

### `get_user_claims()` → jsonb
Returns the current user's group/role claims as a JSONB object. Precedence:
1. `request.groups` (set by `db_pre_request` — freshest, per-request)
2. `auth.jwt()->'app_metadata'->'groups'` (from JWT — may be stale)

Returns `null` if neither is available (e.g., groupless user, anon user).

### `user_has_group_role(group_id uuid, group_role text)` → boolean
Checks whether the current user has a specific role in a specific group. Used in RLS policies.

**Auth tier logic:**
- `authenticated` role: validates JWT not expired, checks claims
- `anon` role: always `false`
- `session_user = 'postgres'` (triggers, superuser): always `true`
- anything else (e.g., `authenticator`): always `false`

### `user_is_group_member(group_id uuid)` → boolean
Checks whether the current user is a member of a group (any role). Same auth tier logic as above. More performant than `user_has_group_role` when any role grants access.

### `jwt_is_expired()` → boolean
Returns `true` if the JWT `exp` claim is in the past or missing. Called internally before any claims check.

### `update_user_roles()` → trigger
**SECURITY DEFINER** | AFTER INSERT OR DELETE OR UPDATE on `group_users`.

Incrementally updates `auth.users.raw_app_meta_data` when group membership changes:
- **INSERT**: adds new role to the group's array
- **DELETE**: removes old role from the group's array
- **UPDATE**: removes old role, adds new role (role change)

Enforces that `user_id` and `group_id` cannot be changed on existing rows (raises exception).

---

## Role Model Strategies

The extension is role-string-agnostic. Two common patterns:

### Role-Centric
Use descriptive role names for user types:
```
owner  →  can delete group, inherits admin
admin  →  can manage users, update group
viewer →  can read
```
RLS checks: `user_has_group_role(group_id, 'admin')`

**Pros:** Simple, fewer rows per user, intuitive
**Cons:** Less granular, harder to audit specific capabilities

### Permission-Centric
Use dot-notation permission strings:
```
group.update        group.delete
group_data.create   group_data.read   group_data.update   group_data.delete
group_user.create   group_user.read   group_user.update   group_user.delete
group_user.invite
```
RLS checks: `user_has_group_role(group_id, 'group_data.read')`

**Pros:** Granular, explicit, easy to audit
**Cons:** More rows per user, slightly more verbose policies

**Hybrid tip:** Combine both. Use `group_data.all` as a catch-all alongside specific permissions. Check catch-all first in OR chains for performance.

---

## Invite System Flow

```
1. An admin/authorized user creates a group_invites row:
   INSERT INTO group_invites (group_id, roles, invited_by)
   VALUES ('<group-uuid>', ARRAY['viewer'], auth.uid());
   → id (invite code) is auto-generated

2. Inviter shares the invite code (the row's id UUID) with the target user

3. Target user calls the edge function:
   POST /functions/v1/invite/accept?invite_code=<uuid>
   Authorization: Bearer <user-jwt>

4. Edge function (supabase/functions/invite/index.ts):
   a. Verifies JWT using SB_JWT_SECRET
   b. Updates group_invites: sets user_id and accepted_at (only if both are NULL)
   c. Inserts rows into group_users for each role in the invite
   d. Returns 201 Created

5. The update_user_roles trigger fires for each group_users insert,
   propagating the new roles into auth.users.raw_app_meta_data
```

**Notes:**
- An invite can only be accepted once (`user_id IS NULL AND accepted_at IS NULL` check)
- Invites do not expire (no expiration column currently — see KNOWN_ISSUES.md)
- Any authenticated user who obtains a valid invite code UUID can accept it

---

## Local Dev Architecture

The `supabase/` directory contains a full local development setup:

- **Migrations** run in order on `supabase start` or `supabase db reset`
- **Seed** (`seed.sql`) creates test users, groups, and role assignments
- The extension is installed via `pgtle.install_extension()` followed by `CREATE EXTENSION`
- Local PostgreSQL runs at port `54322`, API at `54321`, Studio at `54323`
- JWT expiry is 1 hour (configurable in `config.toml`)

---

## Extension Packaging

The extension follows standard PostgreSQL TLE conventions:
- **Control file** (`supabase_rbac.control`): declares version, requires `moddatetime`, `superuser = true`
- **Full install scripts**: `supabase_rbac--X.Y.Z.sql` for fresh installs
- **Upgrade scripts**: `supabase_rbac--A--B.sql` for in-place upgrades via `ALTER EXTENSION ... UPDATE TO`
- Distributed on [database.dev](https://database.dev/pointsource/supabase_rbac)
