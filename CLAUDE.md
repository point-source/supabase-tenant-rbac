# CLAUDE.md — Developer & Agent Quick Reference

## What This Project Is

A PostgreSQL TLE (Trusted Language Extension) that provides multi-tenant RBAC for Supabase projects. Distributed via [database.dev](https://database.dev/pointsource/supabase_rbac) as `pointsource-supabase_rbac`. Current version: **4.5.0**.

## Repository Layout

```
supabase_rbac--4.0.0.sql       # Current extension full install script (READ THIS FIRST)
supabase_rbac--X.Y.Z.sql       # Prior version install scripts (keep for upgrade paths)
supabase_rbac--A--B.sql        # Upgrade path scripts between versions
supabase_rbac.control          # Extension metadata (default_version lives here)
CHANGELOG.md                   # Version history

examples/
  policies/
    role_centric.sql           # Example RLS using role names (owner/admin/viewer)
    permission_centric.sql     # Example RLS using dot-notation permissions
  triggers/
    auto_group_owner.sql       # Auto-assign owner+admin when user creates a group
    auto_group_permissions.sql # Auto-assign granular permissions on group create
    sync_user_into_group_role.sql  # Keep user email/name synced into group_users.metadata
    on_delete_user_roles.sql   # Cascade deletes via user_roles view
  views/
    user_roles.sql             # Replacement for built-in user_roles view (removed in 4.0.0)
  functions/
    add_user_by_email.sql      # Add a user to a group by email (owner-only)

supabase/
  config.toml                  # Local dev config (Postgres 15, port 54321)
  migrations/
    20240502214827_install_pre_reqs.sql   # Installs pg_tle and moddatetime
    20240502214828_install_4.0.0.sql      # Installs the extension
    20240502214829_add_dummy_data.sql     # Test sensitive_data table
    20240512101038_add_rls_policies.sql   # Permission-centric RLS on core tables
  seed.sql                     # 2 test users, 3 groups, role assignments
  functions/invite/index.ts    # Deno edge function for invite acceptance

docs/
  ARCHITECTURE.md              # End-to-end system design
  SECURITY.md                  # Security model and known limitations
  KNOWN_ISSUES.md              # All open GitHub issues with context
  IMPROVEMENT_PLAN.md          # Phased roadmap for future improvements

tools/get_jwt.sh               # Script to get a JWT for local dev testing
```

## Local Development

```bash
# Start local Supabase (Docker required)
supabase start

# Applies migrations + seed.sql automatically
# Studio available at http://localhost:54323
# API at http://localhost:54321
# DB at postgresql://postgres:postgres@localhost:54322/postgres

# Stop
supabase stop

# Reset (re-runs migrations + seed)
supabase db reset

# Get a JWT for a test user (for curl testing)
./tools/get_jwt.sh
```

### Test Users (from seed.sql)
| Email | Password | Notes |
|-------|----------|-------|
| `devuser@email.local` | `password` | Has full permissions in RED group, read-only in BLUE |
| `invited@email.local` | `password` | Has full permissions in BLUE group, read-only in GREEN |

## Extension Versioning

When making changes to the core extension:

1. Create `supabase_rbac--<new-version>.sql` — full install script for fresh installs
2. Create `supabase_rbac--<old>--<new>.sql` — upgrade path (ALTER/REPLACE only the changed objects)
3. Update `default_version` in `supabase_rbac.control`
4. Update `supabase/migrations/20240502214828_install_4.0.0.sql` (or create a new migration)
5. Add entry to `CHANGELOG.md`

**Version bump rules:**
- `patch` (4.0.x): Bug fixes only, fully backwards compatible
- `minor` (4.x.0): New features, backwards compatible
- `major` (x.0.0): Breaking changes (table schema changes, function signature changes, removed objects)

## Key Design Principles

- **Deny-all by default**: All tables have RLS enabled with no policies. Consumers must explicitly add policies.
- **Fresh claims on every request**: `db_pre_request` reads `auth.users` on each API call, bypassing stale JWT data.
- **Schema-agnostic**: Uses `@extschema@` everywhere (never hardcoded `public`). Install in any schema.
- **Minimal core**: The extension ships only tables, functions, and triggers. Examples are in `examples/`.
- **Role strings are flexible**: No built-in role names. Use whatever strings fit your app (roles, permissions, or both).

## Common Gotchas

- **Custom schema installs**: When installed in a non-`public` schema, the `pgrst.db_pre_request` value in `ALTER ROLE authenticator SET ...` must be schema-qualified (e.g., `rbac.db_pre_request`). See [Issue #29](https://github.com/point-source/supabase-tenant-rbac/issues/29).
- **Groupless users crash**: Users with no group memberships cause `get_user_claims()` to fail with a JSON parsing error. See [Issue #37](https://github.com/point-source/supabase-tenant-rbac/issues/37).
- **User deletion crashes trigger**: Deleting a user cascades to `group_users`, causing the trigger to fail when it tries to update the now-deleted user. See [Issue #11](https://github.com/point-source/supabase-tenant-rbac/issues/11).
- **Storage requests bypass db_pre_request**: The hook only runs for PostgREST (API) requests, not Supabase Storage. RLS policies on storage objects cannot use the RBAC functions reliably. See [Issue #34](https://github.com/point-source/supabase-tenant-rbac/issues/34).
- **No ON DELETE CASCADE**: Deleting a group does NOT automatically clean up `group_users` or remove roles from `auth.users.raw_app_meta_data`. Manual cleanup is required.
- **TLE backup/restore issues**: Supabase logical backups may fail to restore if `auth.users` isn't available when the extension is installed. See [Issue #41](https://github.com/point-source/supabase-tenant-rbac/issues/41).

## File Relationships

```
group_users (INSERT/UPDATE/DELETE)
    └── triggers: on_change_update_user_metadata
        └── calls: update_user_roles()  [SECURITY DEFINER]
            └── updates: auth.users.raw_app_meta_data

Every PostgREST API request:
    └── db_pre_request()  [SECURITY DEFINER, registered on authenticator role]
        └── reads: auth.users.raw_app_meta_data
        └── writes: request.groups (session config)

RLS policies call:
    └── user_has_group_role(group_id, role)
    │   user_has_any_group_role(group_id, roles[])  ← v4.5.0, uses ?| operator
    │   user_has_all_group_roles(group_id, roles[]) ← v4.5.0, uses ?& operator
    │   user_is_group_member(group_id)
        └── calls: get_user_claims()
            └── reads: request.groups (from db_pre_request) OR auth.jwt()
```
