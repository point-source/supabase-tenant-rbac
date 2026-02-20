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

## Phase 3: Security Hardening & Invite Improvements → v4.2.0

### 3.1 Add invite expiration support
- [x] **File:** `supabase_rbac--4.2.0.sql` — added nullable `expires_at timestamptz` column to `group_invites`
- [x] **File:** `supabase_rbac--4.1.0--4.2.0.sql` — upgrade script (`ALTER TABLE ... ADD COLUMN IF NOT EXISTS`)
- [x] **File:** `supabase_rbac.control` — version bumped to `4.2.0`
- [x] **File:** `supabase/functions/invite/index.ts` — added `.or('expires_at.is.null,expires_at.gt.<now>')` filter
- [x] **File:** `supabase/tests/06_invite_expiration.test.sql` — 7 pgTAP regression tests

### 3.2 Document privilege escalation risk
- [x] **File:** `docs/SECURITY.md` — already documented (see Role Assignment is Unconstrained section)
- [x] **File:** `README.md` — added "Security Considerations" section covering privilege escalation, invite expiry, and Storage claims gap
- [x] **File:** `README.md` — fixed stale function names (`is_group_member` → `user_is_group_member`, removed deleted `jwt_*` methods)
- [x] **File:** `README.md` — fixed wrong function signature in invite policy example

---

## Phase 4: Testing Infrastructure (Issue #1)

### 4.1 Add pgTAP tests
- [x] pgTAP is provided automatically by `supabase test db` — no migration needed
- [x] `supabase/tests/` directory created in Phase 2
- [x] Test files (46 assertions across 7 files):
  - [x] `01_groupless_user.test.sql` — regression for #37 (5 tests)
  - [x] `02_user_deletion.test.sql` — regression for #11 (4 tests)
  - [x] `03_cascade_delete.test.sql` — group/user deletion cascades, #38 (7 tests)
  - [x] `04_service_role.test.sql` — all four auth tier behaviors, #39 (6 tests)
  - [x] `05_role_sync.test.sql` — trigger fires, claims updated in auth.users (8 tests)
  - [x] `06_invite_expiration.test.sql` — invite expiry and acceptance logic (7 tests)
  - [x] `07_group_crud.test.sql` — group creation, metadata, moddatetime trigger,
        deletion, duplicate-invite-acceptance prevention, upsert idempotency (9 tests)

### 4.2 Add GitHub Actions CI
- [x] Created `.github/workflows/test.yml`
- [x] Setup: `supabase/setup-cli@v1` + `supabase start` + `supabase test db`
- [x] Triggers on push to `main` and on PRs targeting `main`
- [x] Excludes heavy services not needed for DB tests (studio, imgproxy, edge-runtime, vector, inbucket)

---

## Phase 5: Documentation Refresh

### 5.1 Improve README
- [x] Add "Security Considerations" section *(Phase 3)*
- [x] Add "Troubleshooting" section covering issues #29, #34, #37, #41
- [x] Add "Custom Data Table (End-to-End Example)" under RLS Policy Examples
- [x] Fix outdated function references *(Phase 3)*
- [x] Fix example policy in "Securing the invitation system" section *(Phase 3)*

### 5.2 Keep `docs/` up to date
- [x] `docs/KNOWN_ISSUES.md` — restructured into Fixed / Open / Feature Requests / Support sections; all resolved issues marked with version and ✅
- [x] `docs/IMPROVEMENT_PLAN.md` — updated throughout all phases
- [x] `docs/ARCHITECTURE.md` — updated for v4.1.0 (CASCADE FKs, service_role tier, groupless user fix, schema-qualified registration, update_user_roles existence check) and v4.2.0 (expires_at column, invite flow note); added Migration Generator section

---

## Completion Tracking

| Phase | Status | Version |
|-------|--------|---------|
| Phase 1: Immediate fixes | Complete | No version bump |
| Phase 2: Extension bug fixes | Complete | v4.1.0 |
| Phase 3: Security hardening | Complete | v4.2.0 |
| Phase 4: Testing | Complete | N/A |
| Phase 5: Documentation | Complete | N/A |
