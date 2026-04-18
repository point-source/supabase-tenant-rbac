# Supabase Tenant RBAC

Multi-tenant, role-based access control for Supabase.

**Current version: 5.2.1**

## What Is This?

A PostgreSQL extension that gives your Supabase project:

- **Groups** (tenants/organizations) with **members** assigned **roles**
- **Permissions** derived from roles and cached for fast RLS policy checks
- **Privilege escalation prevention** — members can only assign roles they're authorized to grant
- **Immediate freshness** — role changes take effect on the next request, no JWT expiry wait

## Install

From your Supabase project directory:

```bash
curl -sL https://raw.githubusercontent.com/point-source/supabase-tenant-rbac/main/tools/install.sh | bash
```

This creates a timestamped migration file in `supabase/migrations/`. Then apply it:

```bash
supabase migration up
# or: supabase db reset
```

Then add RLS policies. See [Quickstart](#quickstart).

### Options

```bash
# Use a custom schema name (default: rbac)
curl -sL .../tools/install.sh | bash -s -- --schema my_rbac

# Install a specific version
curl -sL .../tools/install.sh | bash -s -- --version 5.2.0

# Upgrade from a previous version
curl -sL .../tools/install.sh | bash -s -- --from 5.0.0

# Custom output directory
curl -sL .../tools/install.sh | bash -s -- --output-dir ./migrations

# Preview without writing
curl -sL .../tools/install.sh | bash -s -- --dry-run
```

> In the examples above, `...` is shorthand for `https://raw.githubusercontent.com/point-source/supabase-tenant-rbac/main`.

### Alternative: dbdev

If you prefer using the [dbdev](https://database.dev) package manager:

**Prerequisite:** `pg_tle` must be enabled in your Supabase project.

```bash
# Install
dbdev add -o "./supabase/migrations/" -s rbac package -n pointsource@supabase_rbac

# Upgrade (generates a new migration with the update)
dbdev add -o "./supabase/migrations/" -s rbac package -n pointsource@supabase_rbac
```

Then apply with `supabase migration up` or `supabase db reset`.

**Known limitations:** dbdev installs via pg_tle, which registers objects as extension members. This causes `pg_dump`, `supabase db diff`, `supabase db pull`, and logical backup/restore to miss RBAC objects ([#23](https://github.com/point-source/supabase-tenant-rbac/issues/23), [#41](https://github.com/point-source/supabase-tenant-rbac/issues/41)). The curl installer above avoids these issues by generating plain SQL.

> **Do not mix installation methods.** If you installed via dbdev, continue upgrading via dbdev. If you installed via the curl installer or plain SQL, continue upgrading that way. Mixing methods leaves the database in an inconsistent state. To switch from dbdev to plain SQL, perform a fresh plain SQL install on a new database and migrate your data.

### Alternative: manual

Clone the repo and generate a migration directly:

```bash
git clone https://github.com/point-source/supabase-tenant-rbac.git
cd supabase-tenant-rbac
tools/install.sh
# Copy supabase/migrations/20240502214828_install_rbac.sql into your project
```

## Quickstart

**1. Create a group (as an authenticated user):**
```sql
SELECT rbac.create_group('My Organization');
```

**2. Add a member:**
```sql
SELECT rbac.add_member('<group-id>', '<user-id>', ARRAY['viewer']);
```

**3. Write RLS policies using helpers:**
```sql
-- Any group member can read
CREATE POLICY "members can read" ON public.documents
    FOR SELECT TO authenticated
    USING (rbac.is_member(group_id));

-- Only users with data.write permission can insert
CREATE POLICY "writers can insert" ON public.documents
    FOR INSERT TO authenticated
    WITH CHECK (rbac.has_permission(group_id, 'data.write'));
```

**4. Register your permissions and define roles (in a migration, as service_role):**
```sql
SELECT rbac.create_permission('data.read', 'Read documents');
SELECT rbac.create_permission('data.write', 'Create and edit documents');

SELECT rbac.create_role('editor', 'Can read and write',
    ARRAY['data.read', 'data.write'], -- permissions
    ARRAY['viewer']                    -- can grant: viewer role
);
SELECT rbac.create_role('viewer', 'Read-only', ARRAY['data.read'], ARRAY[]::text[]);
```

## RLS Helpers

| Function | Purpose |
|----------|---------|
| `is_member(group_id)` | Is the user a member of this group? |
| `has_role(group_id, role)` | Does the user hold this role? |
| `has_permission(group_id, permission)` | Does the user hold this permission? |
| `has_any_role(group_id, roles[])` | Holds at least one of these roles? |
| `has_any_permission(group_id, permissions[])` | Holds at least one of these permissions? |
| `has_all_permissions(group_id, permissions[])` | Holds all of these permissions? |

## Documentation

- [Conceptual Model](docs/CONCEPTUAL_MODEL.md) — groups, roles, permissions, escalation prevention
- [Architecture](docs/ARCHITECTURE.md) — tables, triggers, claims resolution, hooks
- [Security](docs/SECURITY.md) — threat model, escalation prevention, DEFINER audit
- [API Reference](docs/API_REFERENCE.md) — every RPC and helper with signatures and examples
- [Migration Guide](docs/MIGRATION_GUIDE.md) — upgrading from v4.x

## Examples

```
examples/
  policies/
    quickstart.sql           — Starter RLS policies for all rbac tables
    storage_rls.sql          — Storage bucket RLS examples
    custom_table_isolation.sql — RLS for your app tables
    hardened_setup.sql       — REVOKE ALL + targeted GRANT defense-in-depth
  setup/
    create_public_wrappers.sql — Expose functions to PostgREST (opt-in)
    remove_public_wrappers.sql — Remove those wrappers
```

### Optional Edge Function Examples

The repo includes opt-in edge function examples under `supabase/functions/`:

- `invite/` — HTTP wrapper for `accept_invite`
- `add-member/` — server-side `add_member` wrapper using `service_role`

These are optional and not required to use the extension's SQL API.

For setup/auth details, see the "Optional Edge Function Examples" section in [docs/API_REFERENCE.md](docs/API_REFERENCE.md).  
If you deploy `add-member`, run `examples/setup/create_service_role_wrapper.sql` so `public.add_member` is exposed to PostgREST with service-role-only EXECUTE.

## Local Development

```bash
supabase start    # starts Docker + applies migrations + seed
supabase test db  # runs test suite
supabase db reset # re-runs migrations + seed
```

Test users: alice@example.local (owner), bob@example.local (admin), carol@example.local (editor), dave@example.local (viewer). Password: `password`.

## vs. Official Supabase RBAC

The [official Supabase RBAC](https://supabase.com/docs/guides/auth/row-level-security) assigns database roles globally. This extension adds **multi-tenant** RBAC: a user can be an `owner` in one organization and a `viewer` in another, with permissions scoped per group. See the [Conceptual Model](docs/CONCEPTUAL_MODEL.md) for a detailed comparison.
