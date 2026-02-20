# Known Issues

This document catalogs all open GitHub issues as of 2025. Issues are grouped by type. See [IMPROVEMENT_PLAN.md](./IMPROVEMENT_PLAN.md) for the phased roadmap that addresses these.

---

## Bugs

### #37 — Groupless users crash `get_user_claims()` (CRITICAL)
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/37

When a user signs up via Supabase's standard flow and has never been added to any group, `db_pre_request` stores an empty string in `request.groups` (since `raw_app_meta_data->'groups'` is NULL). `get_user_claims()` then tries to cast this empty string as `jsonb`, causing a `invalid input syntax for type json` error. Every API request by a groupless authenticated user returns a 500 error.

**Impact:** Any Supabase app using standard signup will break for new users until they are added to at least one group.

**Workaround:** Ensure all users are added to at least one group immediately after signup (e.g., via a trigger on `auth.users`).

**Fix (v4.1.0):**
- In `db_pre_request()`: `coalesce(groups, '{}')` before calling `set_config`
- In `get_user_claims()`: use `NULLIF(..., '')` before casting to `jsonb`

---

### #11 — User deletion crashes `update_user_roles` trigger
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/11

Deleting a row from `auth.users` cascades to `group_users` (FK constraint). The `update_user_roles` trigger fires for each deleted `group_users` row, then tries to `UPDATE auth.users WHERE id = _user_id` — but the user was just deleted. This raises an error.

**Impact:** Cannot delete users from Supabase without first manually removing all their `group_users` rows.

**Workaround:** Before deleting a user, manually delete all their `group_users` rows:
```sql
DELETE FROM group_users WHERE user_id = '<user-uuid>';
-- Now safe to delete the user
```

**Fix (v4.1.0):** Add an existence check in `update_user_roles()`:
```sql
IF NOT EXISTS (SELECT 1 FROM auth.users WHERE id = _user_id) THEN
    RETURN OLD;
END IF;
```

---

### #41 — TLE restoration fails after project pause/upgrade
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/41

Supabase logical backups do not correctly capture the dependency between the TLE extension and `auth.users`. When a paused or upgraded project is restored, the extension may be installed before `auth.users` exists, causing the restoration to fail.

**Impact:** Projects using this extension may fail to restore after being paused or after a Supabase version upgrade.

**Workaround:** Not well-established. May require manual restoration steps or Supabase support intervention.

**Status:** Upstream issue with how Supabase handles TLE restoration ordering. A long-term fix may require changes to how the extension declares its `auth.users` dependency, or a Supabase platform fix.

---

### #29 — `db_pre_request` not found when installed in custom schema
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/29

When the extension is installed in a non-`public` schema (e.g., `CREATE EXTENSION ... schema rbac`), the `ALTER ROLE authenticator SET pgrst.db_pre_request TO 'db_pre_request'` line registers an unqualified function name. PostgREST cannot find the function and every API request fails.

**Workaround:** After installing in a custom schema, manually run:
```sql
ALTER ROLE authenticator SET pgrst.db_pre_request TO 'your_schema.db_pre_request';
NOTIFY pgrst, 'reload config';
```

**Fix (v4.1.0):** Change the registration to use `@extschema@.db_pre_request` instead of `db_pre_request`.

---

### #35 / PR #36 — Role-centric example uses `FOR ALL` instead of `FOR SELECT`
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/35

In `examples/policies/role_centric.sql`, the "Members can read" policy on the `groups` table uses `FOR ALL` instead of `FOR SELECT`. The comment says "read" but the policy grants all operations.

**Impact:** Example-only. Does not affect the core extension. Misleading for developers copying the example.

**Fix:** PR #36 is open and ready to merge — changes `for all` to `for select`.

---

### #34 — `db_pre_request` does not fire for Storage requests
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/34

The `db_pre_request` hook only runs in the PostgREST pipeline. Supabase Storage upload/download requests go through a different code path and do not trigger the hook. During storage operations, `request.groups` is NULL, and `get_user_claims()` falls back to (potentially stale) JWT claims.

**Impact:** RLS policies on storage objects that use `user_has_group_role()` or `user_is_group_member()` will use outdated claims if a user's roles changed since their JWT was issued.

**Workaround:** For storage-specific RLS, accept a staleness window equal to the JWT lifetime (default: 1 hour). Role changes for storage access take effect on the user's next token refresh.

**Status:** This is a fundamental limitation of Supabase's architecture. Cannot be fixed within this extension.

---

## Open PRs (Ready to Merge)

### PR #36 — Fix `role_centric.sql` example (fixes #35)
**Link:** https://github.com/point-source/supabase-tenant-rbac/pull/36
- 1-line fix: `for all` → `for select`
- No test required, example-only change

### PR #40 — `user_is_group_member` and `user_has_group_role` should return `true` for `service_role` (fixes #39)
**Link:** https://github.com/point-source/supabase-tenant-rbac/pull/40
- When these functions are used in views or application functions (not just RLS), they currently only short-circuit for `session_user = 'postgres'`. Calls made with the Supabase service_role key should also return `true` to be consistent with how service_role bypasses RLS.
- Needs review and testing before merge

---

## Feature Requests

### #39 — `user_is_group_member` / `user_has_group_role` should return `true` for service role
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/39
**PR:** #40 is open

When these functions are used in views or application functions (not just RLS policies), service_role requests currently return `false` unless `session_user = 'postgres'`. This is surprising because service_role requests already bypass RLS. PR #40 proposes a fix.

---

### #38 — Auto-delete orphaned invites and user associations
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/38

Suggests adding `ON DELETE CASCADE` to the foreign key constraints so that:
- Deleting a group automatically removes all `group_users` and `group_invites` rows
- Deleting a user automatically removes all their `group_users` and `group_invites` rows

This would also resolve #11 (user deletion crash) by triggering the `update_user_roles` cleanup before the user is gone.

**Targeted for v4.1.0.**

---

### #19 — Consider adopting the new Supabase Auth Hooks approach
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/19
**Opened by:** Supabase team member

The official Supabase [custom claims & RBAC guide](https://supabase.com/docs/guides/auth/custom-claims-and-role-based-access-control-rbac) uses Auth Hooks to inject custom claims into JWTs at generation time. This is different from the `db_pre_request` approach used here.

**Trade-offs:**
- Auth Hooks: claims are in the JWT (client-visible, no per-request DB query), but stale until JWT refresh
- `db_pre_request`: claims are always fresh (per-request DB query), but only works for PostgREST (not Storage)

**Decision:** Not pursuing Auth Hooks migration at this time. The `db_pre_request` approach provides better security (instant revocation) and is the core architectural differentiator of this extension.

---

### #1 — Add pgTAP tests
**Link:** https://github.com/point-source/supabase-tenant-rbac/issues/1
**Opened by:** Supabase team member

There are currently no automated tests for any functionality. pgTAP is the standard PostgreSQL testing framework and is supported in the Supabase CLI.

**Targeted for Phase 4 of the improvement plan.**

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
