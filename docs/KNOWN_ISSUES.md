# Known Issues

This document catalogs GitHub issues and their current status. Issues are grouped by type. See [IMPROVEMENT_PLAN.md](./IMPROVEMENT_PLAN.md) for the phased roadmap.

---

## Fixed Bugs

These bugs have been resolved in extension releases. Listed for historical reference and to help users on older versions understand what to upgrade for.

### #37 — Groupless users crash `get_user_claims()` ✅ Fixed in v4.1.0
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/37

When a user signs up and has never been added to any group, `db_pre_request` stored `NULL` in `request.groups`. `get_user_claims()` cast an empty string to `jsonb`, causing a parse error. Every API request by a groupless user returned 500.

**Fix:** `db_pre_request` now stores `'{}'` via `coalesce`. `get_user_claims()` uses `NULLIF(..., '')` to guard against stale empty strings left by older versions.

---

### #11 — User deletion crashes `update_user_roles` trigger ✅ Fixed in v4.1.0
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/11

Deleting a user cascaded to `group_users`, which fired the `update_user_roles` trigger. The trigger then tried to update `auth.users` for a user that no longer existed.

**Fix:** The trigger now checks for user existence and returns early if the user is gone.

---

### #38 — Deleting a group or user blocked by FK constraints ✅ Fixed in v4.1.0
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/38

Previously, deleting a group or user with existing `group_users` / `group_invites` rows was blocked by FK violations. Users had to manually clean up child rows first.

**Fix:** All foreign keys on `group_users` and `group_invites` now have `ON DELETE CASCADE`. **Behavioral change:** deletes now cascade automatically. See CHANGELOG for full details.

---

### #29 — `db_pre_request` not found when installed in a custom schema ✅ Fixed in v4.1.0
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/29

The `pgrst.db_pre_request` role setting was registered without a schema prefix, so PostgREST could not find the function when the extension was in a non-`public` schema.

**Fix:** Registration now uses `@extschema@.db_pre_request` to always resolve correctly.

---

### #35 — Role-centric example uses `FOR ALL` instead of `FOR SELECT` ✅ Fixed in Phase 1
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/35

The "Members can read" policy in `examples/policies/role_centric.sql` incorrectly used `FOR ALL`. Fixed to `FOR SELECT`.

---

### #39 — Permission functions should return `true` for `service_role` ✅ Fixed in v4.1.0
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/39

`user_has_group_role` and `user_is_group_member` returned `false` for `service_role` callers, which was inconsistent with service_role bypassing RLS entirely.

**Fix:** Both functions now return `true` when `auth.role() = 'service_role'`, in addition to the existing `session_user = 'postgres'` check.

---

### #1 — No automated tests ✅ Completed in Phase 4
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/1

There were no automated tests. pgTAP tests have been added in `supabase/tests/` — 7 test files, 46 assertions — and a GitHub Actions CI workflow runs them on every push and PR to `main`.

---

## Open Bugs / Limitations

### #41 — TLE restoration fails after project pause/upgrade
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/41

Supabase logical backups do not correctly capture the dependency between the TLE extension and `auth.users`. When a paused or upgraded project is restored, the extension may be installed before `auth.users` exists.

**Impact:** Projects may fail to restore after being paused or after a Supabase version upgrade.

**Workaround:** Contact Supabase support. This is an upstream platform issue.

**Status:** Open. Requires a Supabase platform fix or a change to how TLE dependencies are declared.

---

### #34 — `db_pre_request` does not fire for Storage requests
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/34

The `db_pre_request` hook only runs in the PostgREST pipeline. Supabase Storage goes through a separate code path and does not invoke it. Storage RLS policies fall back to (potentially stale) JWT claims.

**Impact:** Role changes take effect in Storage only when the user's JWT refreshes (default: up to 1 hour).

**Workaround:** Accept the JWT staleness window for storage policies, or use signed URLs / server-side access checks for operations requiring immediate revocation.

**Status:** Open. Fundamental architectural limitation of Supabase. Cannot be fixed within this extension.

---

## Open PRs (Ready to Merge to upstream)

### PR #36 — Fix `role_centric.sql` example (fixes #35)
**Link:** https://github.com/point-source/supabase-tenant-rbac/pull/36
**Status:** Applied locally in Phase 1. Pending merge to upstream `main`.

### PR #40 — Permission functions should return `true` for `service_role` (fixes #39)
**Link:** https://github.com/point-source/supabase-tenant-rbac/pull/40
**Status:** Applied and tested in v4.1.0. Pending merge to upstream `main`.

---

## Feature Requests

### #19 — Consider adopting the new Supabase Auth Hooks approach
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/19
**Opened by:** Supabase team member

The official Supabase guide uses Auth Hooks to inject claims into JWTs at generation time, rather than the `db_pre_request` per-request approach.

**Trade-offs:**
- Auth Hooks: claims in JWT (client-visible, no per-request DB query), but stale until refresh
- `db_pre_request`: always fresh (per-request DB query), but only PostgREST (not Storage)

**Decision:** Not pursuing Auth Hooks migration. The `db_pre_request` approach provides instant revocation and is the core architectural differentiator of this extension.

---

## Support / Usage Questions

These issues represent gaps in documentation or common points of confusion.

### #33 — How to write RLS policies for a custom table with a `group_id` FK
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/33

See the "Custom Data Table (End-to-End Example)" section in the README for a complete walkthrough.

---

### #32 — Hierarchical organizations (Org → Group → Users)
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/32

This extension does not natively support nested group hierarchies. Options:
1. **Use groups as orgs**: one group per org, roles like `org_member`, `org_admin`.
2. **Store parent org in metadata**: `groups.metadata->>'parent_org_id'`, write custom RLS.
3. **Separate `orgs` table**: replicate the RBAC pattern at a higher level.

---

### #30 — Mapping multi-tenancy concepts to groups/roles
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/30

**Tenant = Group.** Each row in `groups` represents one tenant/organization. The `metadata` column stores tenant-specific data (name, plan, settings). Sub-groups or departments can be modeled as additional group rows with role naming conventions (e.g., `dept:engineering`).

---

### #27 — Nested groups and RLS performance
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/27

Nested groups are not natively supported. Recursive group membership in RLS policies would incur per-row query costs. Recommended alternative: flatten hierarchies and use role naming (e.g., `team:alpha:member`).

---

### #26 — `supabase generate-types` fails with RBAC installed
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/26

Type generation tools may produce schemas with missing dependencies for TLE functions. Workaround: exclude the RBAC schema from type generation, or manually add the missing types.

---

### #23 — `supabase pull` / schema dump omits RBAC tables
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/23

The Supabase CLI schema dump does not include objects created by TLE extensions. This is expected: the extension is managed via `pgtle.install_extension()` and `CREATE EXTENSION` in your migration files. The tables are recreated when the migration runs.

---

### #22 — Upgrading to 4.0.0 fails in CI/CD
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/22

`CREATE EXTENSION "pointsource-supabase_rbac" version "4.0.0"` fails with "no installation script nor update path for version 4.0.0" because the CI environment does not have `dbdev` installed.

**Cause:** The `pgtle.install_extension()` migration must run before `CREATE EXTENSION`. Ensure migration timestamps are ordered so the install script precedes the create-extension step.

---

## Support / Usage Questions

These issues represent gaps in documentation or common points of confusion. The answers are captured here for reference.

### #33 — How to write RLS policies for a custom table with a `group_id` FK
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/33

For a custom table like:
```sql
CREATE TABLE my_data (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id uuid REFERENCES groups(id),
    content text
);
```

A basic RLS policy allowing group members to read:
```sql
CREATE POLICY "Group members can read"
ON my_data
FOR SELECT
TO authenticated
USING (user_is_group_member(group_id));
```

For writes (requires a specific role):
```sql
CREATE POLICY "Group data creators can insert"
ON my_data
FOR INSERT
TO authenticated
WITH CHECK (user_has_group_role(group_id, 'group_data.create'));
```

See `examples/policies/` for complete examples.

---

### #32 — Hierarchical organizations (Org → Group → Users)
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/32

This extension does not natively support nested group hierarchies. For an org-level concept, options:
1. **Use groups as orgs**: Create one "group" per org. Create roles like `org_member`, `org_admin`. Create sub-groups (separate rows) with their own memberships.
2. **Add an `org_id` to `groups.metadata`**: Store the parent org UUID in metadata. Write custom RLS policies that check org membership.
3. **Create a separate `orgs` table**: Manually replicate the RBAC pattern for a higher-level entity.

The extension is deliberately minimal to support diverse use cases.

---

### #30 — Mapping multi-tenancy concepts to groups/roles
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/30

**Tenant = Group.** Each row in `groups` represents one tenant/organization. Users belong to a tenant via `group_users`. The `metadata` column stores tenant-specific data (name, plan, settings).

**Department within tenant**: Use a role like `dept:engineering` or create a sub-group row in `groups` with `metadata->>'parent_group_id'`.

---

### #27 — Nested groups and RLS performance
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/27

Nested groups (parent-child relationships) are not natively supported. Implementing recursive group membership would require custom functions and could have significant performance implications in RLS policies (which run per-row).

**Alternative**: Flatten hierarchies — assign users directly to leaf-level groups and use role naming to express hierarchy (e.g., roles like `team:alpha:member`, `org:acme:admin`).

---

### #26 — Supabase `generate-types` / `supabase-to-zod` fails with RBAC installed
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/26

Type generation tools may produce schemas with missing dependencies for the RBAC functions (`dbPreRequestArgsSchema`, etc.). This is a limitation of how TLE functions appear in the introspection schema.

**Workaround:** Exclude the RBAC schema from type generation, or manually add the missing types to the generated output.

---

### #23 — `supabase pull` / schema dump omits RBAC tables
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/23

The Supabase CLI `supabase pull` command and schema dump do not include objects created by TLE extensions. The `groups`, `group_users`, and `group_invites` tables will not appear in the dumped schema.

**Workaround:** The extension is managed via `pgtle.install_extension()` and `CREATE EXTENSION`. These commands are in your migration files and do not need to be in the schema dump. The tables are recreated when the extension is installed.

---

### #22 — Upgrading to 4.0.0 fails in CI/CD
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/22

`DROP EXTENSION` + `CREATE EXTENSION "pointsource-supabase_rbac" version "4.0.0"` works locally but fails in GitHub Actions with "no installation script nor update path for version 4.0.0".

**Cause:** The CI environment does not have `dbdev` installed or the dbdev package cache is not available. The `pgtle.install_extension()` step (which registers the extension scripts) must run before `CREATE EXTENSION`.

**Workaround:** Ensure the migration that calls `pgtle.install_extension()` runs before the migration that calls `CREATE EXTENSION`. If using `supabase db push`, migrations run in order by timestamp — the install script must have an earlier timestamp than the create extension step.
