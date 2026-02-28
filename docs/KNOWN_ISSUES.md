# Known Issues

This document catalogs GitHub issues and their current status. Issues are grouped by type.

---

## Open Bugs / Limitations

### #41 — TLE restoration fails after project pause/upgrade
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/41

Supabase logical backups do not correctly capture the dependency between the TLE extension and `auth.users`. When a paused or upgraded project is restored, the extension may be installed before `auth.users` exists.

**Impact:** Projects may fail to restore after being paused or after a Supabase version upgrade.

**Workaround:** Contact Supabase support. This is an upstream platform issue.

**Status:** Open. Requires a Supabase platform fix.

---

## Feature Requests

### #19 — Adopt the Supabase Auth Hooks approach
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/19

**Status: Implemented in v5.0.0.** The `custom_access_token_hook()` function injects group claims into JWTs at token creation time by reading from `rbac.user_claims`. Register it in `config.toml`:

```toml
[auth.hook.custom_access_token]
enabled = true
uri = "pg-functions://postgres/public/custom_access_token_hook"
```

The `db_pre_request` approach (instant revocation on every request) is retained alongside the hook. The hook provides JWT-embedded claims for clients that read `app_metadata.groups` directly from their tokens.

---

## Support / Usage Questions

### #33 — RLS policies for custom tables with `group_id` FK
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/33

```sql
-- v5.0.0 syntax:
CREATE POLICY "Group members can read"
ON my_data FOR SELECT TO authenticated
USING (is_member(group_id));

CREATE POLICY "Admins can write"
ON my_data FOR INSERT TO authenticated
WITH CHECK (has_role(group_id, 'admin'));
```

See `examples/policies/custom_table_isolation.sql` for complete examples.

---

### #32 — Hierarchical organizations
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/32

The extension does not natively support nested group hierarchies. Use groups as top-level orgs, store parent references in `metadata`, or create a separate hierarchy layer.

---

### #30 — Mapping multi-tenancy concepts
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/30

**Tenant = Group.** Each `groups` row is one tenant. The `name` column (v5.0.0) stores the display name; `metadata` stores tenant-specific settings.

---

### #27 — Nested groups and RLS performance
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/27

Not natively supported. Flatten hierarchies by assigning users to leaf-level groups with role naming to express hierarchy.

---

### #26 — Type generation fails with RBAC installed
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/26

**Workaround:** Exclude the RBAC schema from type generation. In v5.0.0, the `rbac` schema is already separate from `public`, which may reduce conflicts.

---

### #23 — `supabase pull` omits RBAC tables
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/23

TLE-managed tables don't appear in schema dumps. The extension is managed via `pgtle.install_extension()` + `CREATE EXTENSION` in migration files.

---

### #22 — Upgrading fails in CI/CD
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/22

Ensure `pgtle.install_extension()` runs before `CREATE EXTENSION` in migrations.
