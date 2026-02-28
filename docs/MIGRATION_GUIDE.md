# Migration Guide: v4.x to v5.0.0

This document compares the latest v4.x release (v4.5.0) against v5.0.0 to help you decide whether to migrate and understand what changes.

There is **no automated upgrade path**. Migrating requires exporting data, dropping the extension, reinstalling, and re-importing. This guide explains what you gain (and what breaks) so you can make an informed decision.

---

## Quick Comparison

| | v4.5.0 | v5.0.0 |
|---|---|---|
| Schema | Public (or custom) | Private `rbac` schema + public wrappers |
| Membership model | One row per user-group-**role** | One row per user-group, `roles text[]` |
| Claims cache | `auth.users.raw_app_meta_data` | Extension-owned `user_claims` table |
| SECURITY DEFINER functions | 5 | 2 |
| Group name | Stored in `metadata->>'name'` | Dedicated `name text NOT NULL` column |
| Role validation | None (free-text strings) | Validated against `roles` table |
| Management API | Direct table INSERTs/UPDATEs | Typed RPC functions |
| moddatetime dependency | Required | Removed (inline trigger) |
| Auth Hook (JWT injection) | Not available | Built-in `custom_access_token_hook` |
| Bulk role checks | `user_has_any_group_role`, `user_has_all_group_roles` | `has_any_role`, `has_all_roles` |
| Test coverage | 12 files, ~70 assertions | 16 files, ~115 assertions |

---

## What You Gain by Migrating

### 1. Reduced Privileged Surface Area

v4.5.0 has **5 SECURITY DEFINER functions** that read or write `auth.users`:
- `db_pre_request()` — reads `raw_app_meta_data` on every request
- `_get_user_groups()` — reads `raw_app_meta_data` for Storage fallback
- `update_user_roles()` — reads and writes `raw_app_meta_data` on every membership change
- `accept_group_invite()` — writes to `group_users` and `group_invites`
- No `create_group` equivalent (users INSERT directly)

v5.0.0 has **2 SECURITY DEFINER functions**:
- `create_group()` — bootstrap operation (no prior membership for RLS)
- `accept_invite()` — atomic acceptance (no prior membership for RLS)

The other three dropped DEFINER because they no longer touch `auth.users`. The claims cache moved to `rbac.user_claims`, which the extension owns, so no elevated privileges are needed to read or write it.

### 2. No More Writing to `auth.users`

In v4.x, every membership change triggers `update_user_roles()`, which does a SECURITY DEFINER read + write to `auth.users.raw_app_meta_data`. This has several downsides:
- Writing to `auth.users` can conflict with Supabase Auth's own updates
- `raw_app_meta_data` is a shared field — other tools may also write to it
- Requires DEFINER to access a table the extension doesn't own

In v5.0.0, the trigger writes to `rbac.user_claims` instead — an extension-owned table with a dedicated purpose. `auth.users` is never read or written by the extension.

### 3. Simpler Membership Model

v4.5.0 stores **one row per user-group-role**:
```
group_users: (group_id, user_id, role='owner')
group_users: (group_id, user_id, role='admin')
```

Adding 3 roles to a user creates 3 rows. The `update_user_roles()` trigger does incremental jsonb manipulation (add/remove individual role strings) on every row change.

v5.0.0 stores **one row per user-group** with a `roles text[]` array:
```
members: (group_id, user_id, roles=['owner', 'admin'])
```

The trigger does a full rebuild via `jsonb_object_agg` — simpler, no incremental bookkeeping. The unique index is `(group_id, user_id)` instead of `(group_id, user_id, role)`.

### 4. Management RPCs

v4.5.0 requires direct table access for all management operations:
```sql
-- v4.5.0: Adding a member
INSERT INTO group_users (group_id, user_id, role)
VALUES ('...', '...', 'viewer');

-- v4.5.0: Creating a group
INSERT INTO groups (metadata)
VALUES ('{"name": "My Group"}'::jsonb);
-- Then separately add yourself as owner
INSERT INTO group_users (group_id, user_id, role)
VALUES ('...', auth.uid(), 'owner');
```

v5.0.0 provides typed RPCs with validation:
```sql
-- v5.0.0: Adding a member (validates roles, merges on conflict)
SELECT add_member('group-uuid', 'user-uuid', ARRAY['viewer']);

-- v5.0.0: Creating a group (auto-adds caller as owner)
SELECT create_group('My Group');
```

RPCs validate roles against the `roles` table, handle edge cases (ON CONFLICT merge), and have consistent error messages.

### 5. Role Definitions

v4.5.0 uses **free-text role strings** — any string is accepted. A typo like `'ownr'` silently creates a meaningless role.

v5.0.0 adds a **`roles` table** with `create_role()` / `delete_role()` / `list_roles()` RPCs. All role assignments are validated. `delete_role()` refuses to delete a role that's in use.

### 6. Private Schema Isolation

v4.5.0 tables can be installed in any schema, and if installed in `public` (common), they're directly accessible via the REST API.

v5.0.0 installs tables in a private schema (e.g. `rbac`) that is **not** in PostgREST's `db_schemas`. Tables cannot be accessed via REST — all interaction goes through RPC functions. Thin public wrappers are auto-created for PostgREST RPC discovery and are cleaned up automatically on `DROP EXTENSION`.

### 7. Auth Hook for JWT Claims

v5.0.0 includes `custom_access_token_hook()`, a Supabase Auth Hook that injects group claims into JWTs at token creation. Clients can read `app_metadata.groups` from the decoded token for client-side authorization decisions without a DB round-trip.

This is optional and **complementary** to `db_pre_request` — the hook provides convenience, while `db_pre_request` ensures freshness on every API request regardless of JWT age.

### 8. Dedicated Group Name Column

v4.5.0 stores the group name in `metadata->>'name'`. v5.0.0 adds a proper `name text NOT NULL` column, making queries and display simpler.

### 9. No External Dependencies

v4.5.0 requires the `moddatetime` extension for `updated_at` triggers. v5.0.0 replaces it with an inline `_set_updated_at()` trigger function — one fewer extension to manage.

---

## What Breaks

### Table Renames
| v4.5.0 | v5.0.0 |
|--------|--------|
| `group_users` | `members` |
| `group_invites` | `invites` |

### Function Renames
| v4.5.0 | v5.0.0 |
|--------|--------|
| `user_has_group_role(uuid, text)` | `has_role(uuid, text)` |
| `user_is_group_member(uuid)` | `is_member(uuid)` |
| `user_has_any_group_role(uuid, text[])` | `has_any_role(uuid, text[])` |
| `user_has_all_group_roles(uuid, text[])` | `has_all_roles(uuid, text[])` |
| `get_user_claims()` | `get_claims()` |
| `jwt_is_expired()` | `_jwt_is_expired()` (internal) |
| `accept_group_invite(uuid)` | `accept_invite(uuid)` |
| `update_user_roles()` (trigger) | `_sync_member_metadata()` (trigger) |

### Schema Change

All tables move from the install schema to a private schema. RLS policies referencing table columns directly need to use schema-qualified names or go through RPCs.

### Membership Data Structure

`group_users` has one row per role:
```
id | group_id | user_id | role
---+----------+---------+------
1  | G1       | U1      | owner
2  | G1       | U1      | admin
```

`members` has one row with an array:
```
id | group_id | user_id | roles
---+----------+---------+-----------
1  | G1       | U1      | {owner,admin}
```

### Unique Index Change

v4.5.0: `UNIQUE(group_id, user_id, role)` — allows multiple rows per user-group pair.
v5.0.0: `UNIQUE(group_id, user_id)` — enforces one row per user-group pair.

### RLS Policies Must Be Rewritten

Every RLS policy referencing v4.x function names needs updating:
```sql
-- v4.5.0
USING (user_has_group_role(group_id, 'admin'))

-- v5.0.0
USING (has_role(group_id, 'admin'))
```

You also need to add RLS policies on the `rbac.*` tables themselves (v5.0.0 ships with zero policies — deny-all by default). See `examples/policies/quickstart.sql`.

---

## When to Stay on v4.x

- **Stable production system with no security concerns.** If your DEFINER surface is acceptable and you don't need role validation or the auth hook, v4.x continues to work.
- **Cannot afford downtime for data migration.** The migration requires dropping and recreating the extension. Plan for a maintenance window.
- **Heavy reliance on the `group_users` multi-row model.** If you query `group_users` directly (joins, aggregations by individual role rows), the array model requires query changes.
- **Existing code reads `raw_app_meta_data.groups` directly.** v5.0.0 no longer writes to `raw_app_meta_data`. If you have application code or external systems that read `auth.users.raw_app_meta_data->'groups'`, those need to change (use the auth hook JWT claims or query `rbac.user_claims` instead).

---

## When to Migrate

- **You want fewer SECURITY DEFINER functions.** Going from 5 to 2 meaningfully reduces the privileged attack surface.
- **You want the extension to stop writing to `auth.users`.** Eliminates conflicts with Supabase Auth and other tools that use `raw_app_meta_data`.
- **You want role validation.** Prevents typos and enforces a defined role vocabulary.
- **You want management RPCs.** Typed functions with validation instead of raw INSERTs.
- **You want the auth hook.** JWT-embedded claims for client-side authorization.
- **You're starting a new project.** No migration cost — start with v5.0.0.

---

## Migration Steps

1. **Export data** from `groups`, `group_users`, and `group_invites`
2. **Drop** the existing extension: `DROP EXTENSION "pointsource-supabase_rbac"`
3. **Install** v5.0.0: `CREATE EXTENSION "pointsource-supabase_rbac" SCHEMA rbac`
4. **Re-import data**:
   - `rbac.groups`: add the `name` column (extract from `metadata->>'name'` if stored there)
   - `rbac.members`: collapse `group_users` rows into one row per `(group_id, user_id)` with `roles` as a text array:
     ```sql
     INSERT INTO rbac.members (group_id, user_id, roles, metadata)
     SELECT group_id, user_id, array_agg(DISTINCT role ORDER BY role), max(metadata)
     FROM exported_group_users
     GROUP BY group_id, user_id;
     ```
   - `rbac.invites`: rename columns as needed
5. **Add role definitions** to `rbac.roles` for every role string you use:
   ```sql
   INSERT INTO rbac.roles (name) VALUES ('admin'), ('viewer'), ('editor')
   ON CONFLICT DO NOTHING;
   ```
6. **Update RLS policies** to use new function names
7. **Add RLS policies on `rbac.*` tables** — see `examples/policies/quickstart.sql`
8. **Optionally enable the auth hook** in `config.toml`:
   ```toml
   [auth.hook.custom_access_token]
   enabled = true
   uri = "pg-functions://postgres/public/custom_access_token_hook"
   ```
9. **Update application code** that reads `raw_app_meta_data.groups` — use JWT `app_metadata.groups` (via the auth hook) or query `rbac.user_claims` instead
