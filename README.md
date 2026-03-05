# Supabase Tenant RBAC

Multi-tenant, role-based access control for Supabase. Distributed as a PostgreSQL TLE via [database.dev](https://database.dev/pointsource/supabase_rbac).

**Current version: 5.0.0**

## What Is This?

A PostgreSQL extension that gives your Supabase project:

- **Groups** (tenants/organizations) with **members** assigned **roles**
- **Permissions** derived from roles and cached for fast RLS policy checks
- **Privilege escalation prevention** — members can only assign roles they're authorized to grant
- **Immediate freshness** — role changes take effect on the next request, no JWT expiry wait

## Install

```sql
-- In a Supabase migration:
select dbdev.install('pointsource-supabase_rbac');
create extension "pointsource-supabase_rbac"
    schema rbac
    version '5.0.0';
```

Then add RLS policies. See [Quickstart](#quickstart).

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

## Local Development

```bash
supabase start    # starts Docker + applies migrations + seed
supabase test db  # runs test suite
supabase db reset # re-runs migrations + seed
```

Test users: alice@example.local (owner), bob@example.local (admin), carol@example.local (editor), dave@example.local (viewer). Password: `password`.

## vs. Official Supabase RBAC

The [official Supabase RBAC](https://supabase.com/docs/guides/auth/row-level-security) assigns database roles globally. This extension adds **multi-tenant** RBAC: a user can be an `owner` in one organization and a `viewer` in another, with permissions scoped per group. See the [Conceptual Model](docs/CONCEPTUAL_MODEL.md) for a detailed comparison.
