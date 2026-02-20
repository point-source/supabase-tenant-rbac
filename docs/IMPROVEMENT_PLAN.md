# Improvement Plan

This document tracks the phased improvement roadmap for `supabase-tenant-rbac`. Update this document as phases are completed and mark items with their completion status.

---

## Phase 1: Immediate Fixes (No Extension Version Bump)

These changes apply to examples, docs, and the edge function only.

### 1.1 Merge PR #36 — Fix role_centric.sql example
- [x] **File:** `examples/policies/role_centric.sql:43-49`
- [x] **Change:** `for all` → `for select` on the "Members can read" groups policy
- [x] **PR:** [#36](https://github.com/point-source/supabase-tenant-rbac/pull/36) is ready to merge

### 1.2 Fix JWT logging in edge function
- [x] **File:** `supabase/functions/invite/index.ts:56`
- [x] **Change:** Remove `${token}` from console.log — raw JWTs must never be logged

### 1.3 Update edge function dependency versions
- [x] **File:** `supabase/functions/invite/index.ts:5-7`
- [x] `opine` — already at latest (2.3.4), no change needed
- [x] `@supabase/supabase-js` — updated 2.39.3 → 2.97.0
- [x] `djwt` — updated v2.8 → v3.0.2 (major version; verify API compatibility before deploying)

---

## Phase 2: Extension Bug Fixes → v4.1.0

Requires creating `supabase_rbac--4.1.0.sql` (full install), `supabase_rbac--4.0.0--4.1.0.sql` (upgrade path), and updating `supabase_rbac.control`.

### 2.1 Fix groupless user crash (Issue #37) — CRITICAL
- [x] `db_pre_request()`: `coalesce(groups, '{}')` stores empty object instead of NULL
- [x] `get_user_claims()`: `NULLIF(..., '')` prevents empty-string-to-jsonb cast error

### 2.2 Fix user deletion trigger crash (Issue #11)
- [x] `update_user_roles()`: early return when user no longer exists in `auth.users`

### 2.3 Add ON DELETE CASCADE to foreign keys (Issue #38)
- [x] `group_users.group_id` → `groups(id)` ON DELETE CASCADE
- [x] `group_users.user_id` → `auth.users(id)` ON DELETE CASCADE
- [x] `group_invites.group_id` → `groups(id)` ON DELETE CASCADE
- [x] `group_invites.invited_by` → `auth.users(id)` ON DELETE CASCADE
- [x] `group_invites.user_id` → `auth.users(id)` ON DELETE CASCADE

### 2.4 Add service_role support (Issue #39 / PR #40)
- [x] `user_has_group_role()`: returns `true` when `auth_role = 'service_role'`
- [x] `user_is_group_member()`: returns `true` when `auth_role = 'service_role'`

### 2.5 Fix custom schema `db_pre_request` registration (Issue #29)
- [x] `ALTER ROLE authenticator SET pgrst.db_pre_request TO '@extschema@.db_pre_request'`

### 2.6 Version bookkeeping
- [x] Created `supabase_rbac--4.1.0.sql` — full install script
- [x] Created `supabase_rbac--4.0.0--4.1.0.sql` — upgrade path script
- [x] Updated `supabase_rbac.control`: `default_version = '4.1.0'`
- [x] Renamed `supabase/migrations/20240502214828_install_rbac.sql` (dropped version from filename)
- [x] Added v4.1.0 entry to `CHANGELOG.md`
- [x] Added pgTAP regression tests (5 files, 30 assertions) in `supabase/tests/`

---

## Phase 3: Security Hardening & Invite Improvements → v4.1.0 (same release)

### 3.1 Add invite expiration support
- [ ] **File:** New extension version — add column to `group_invites`
  ```sql
  ALTER TABLE group_invites ADD COLUMN "expires_at" timestamptz;
  ```
- [ ] **File:** `supabase/functions/invite/index.ts` — check expiry before accepting:
  ```typescript
  .is("expires_at", null) // not expired (null = no expiry set)
  // OR check: .gt("expires_at", new Date().toISOString())
  ```
  Add: `.or('expires_at.is.null,expires_at.gt.' + new Date().toISOString())`

### 3.2 Document privilege escalation risk
- [ ] **File:** `docs/SECURITY.md` — already documented (see Role Assignment is Unconstrained section)
- [ ] **File:** `README.md` — add a "Security Considerations" callout section

---

## Phase 4: Testing Infrastructure (Issue #1)

### 4.1 Add pgTAP tests
- [ ] Install pgTAP via migration: `supabase/migrations/YYYYMMDD_install_pgtap.sql`
- [ ] Create `tests/` directory
- [ ] Write test files:
  - [ ] `tests/test_group_crud.sql` — group creation, metadata, deletion
  - [ ] `tests/test_role_assignment.sql` — trigger fires, claims updated in auth.users
  - [ ] `tests/test_permission_checks.sql` — all four auth tier behaviors
  - [ ] `tests/test_groupless_user.sql` — regression for #37
  - [ ] `tests/test_user_deletion.sql` — regression for #11
  - [ ] `tests/test_cascade_delete.sql` — group/user deletion cascades
  - [ ] `tests/test_invites.sql` — invite creation, acceptance, expiry, duplicate prevention

### 4.2 Add GitHub Actions CI
- [ ] Create `.github/workflows/test.yml`
- [ ] Setup: Supabase CLI + local Postgres, run `pg_prove`
- [ ] Trigger on push to `main` and on PRs targeting `main`

---

## Phase 5: Documentation Refresh

### 5.1 Improve README
- [ ] Add "Security Considerations" section (role escalation, invite expiry, custom schema)
- [ ] Add "Troubleshooting" section covering issues #29, #34, #37, #41
- [ ] Add "Custom Table RLS" example (complete end-to-end for a user-data table)
- [ ] Fix outdated function references in README (still mentions jwt_has_group_role, is_group_member which were removed in v1.0.0)
- [ ] Fix example policy in "Securing the invitation system" section (uses old API signature)

### 5.2 Keep `docs/` up to date
- [ ] Update `docs/KNOWN_ISSUES.md` as issues are closed
- [ ] Update this `docs/IMPROVEMENT_PLAN.md` as phases complete
- [ ] Update `docs/ARCHITECTURE.md` when extension changes are made

---

## Completion Tracking

| Phase | Status | Version |
|-------|--------|---------|
| Phase 1: Immediate fixes | Complete | No version bump |
| Phase 2: Extension bug fixes | Complete | v4.1.0 |
| Phase 3: Security hardening | Pending | v4.1.0 |
| Phase 4: Testing | Pending | N/A |
| Phase 5: Documentation | In progress (initial docs created) | N/A |
