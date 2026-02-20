# Improvement Plan

This document tracks the phased improvement roadmap for `supabase-tenant-rbac`. Update this document as phases are completed and mark items with their completion status.

---

## Phase 1: Immediate Fixes (No Extension Version Bump)

These changes apply to examples, docs, and the edge function only.

### 1.1 Merge PR #36 — Fix role_centric.sql example
- [ ] **File:** `examples/policies/role_centric.sql:43-49`
- [ ] **Change:** `for all` → `for select` on the "Members can read" groups policy
- [ ] **PR:** [#36](https://github.com/point-source/supabase-tenant-rbac/pull/36) is ready to merge

### 1.2 Fix JWT logging in edge function
- [ ] **File:** `supabase/functions/invite/index.ts:56`
- [ ] **Change:** Remove `${token}` from console.log — raw JWTs must never be logged
- [ ] **Before:** `console.log(\`User ID could not be retrieved from token: ${token}.\`);`
- [ ] **After:** `console.log("User ID could not be retrieved from token.");`

### 1.3 Update edge function dependency versions
- [ ] **File:** `supabase/functions/invite/index.ts:5-7`
- [ ] **Change:** Update pinned versions of `opine`, `supabase-js`, and `djwt` to latest stable
- [ ] Current versions are ~2 years old (opine 2.3.4, supabase-js 2.39.3, djwt v2.8)

---

## Phase 2: Extension Bug Fixes → v4.1.0

Requires creating `supabase_rbac--4.1.0.sql` (full install), `supabase_rbac--4.0.0--4.1.0.sql` (upgrade path), and updating `supabase_rbac.control`.

### 2.1 Fix groupless user crash (Issue #37) — CRITICAL
- [ ] **File:** `update_user_roles()` / `get_user_claims()` in new extension version
- [ ] **Fix in `db_pre_request()`:** Handle NULL groups gracefully:
  ```sql
  perform set_config('request.groups'::text, coalesce(groups, '{}')::text, false);
  ```
- [ ] **Fix in `get_user_claims()`:** Handle empty string before casting:
  ```sql
  select coalesce(nullif(current_setting('request.groups', true), '')::jsonb,
      auth.jwt()->'app_metadata'->'groups')::jsonb
  ```

### 2.2 Fix user deletion trigger crash (Issue #11)
- [ ] **File:** `update_user_roles()` in new extension version
- [ ] **Fix:** Early return when the target user no longer exists:
  ```sql
  IF NOT EXISTS (SELECT 1 FROM auth.users WHERE id = _user_id) THEN
      RETURN OLD;
  END IF;
  ```

### 2.3 Add ON DELETE CASCADE to foreign keys (Issue #38)
- [ ] **File:** New extension version — alter foreign key constraints
- [ ] Add `ON DELETE CASCADE` to:
  - `group_users.group_id` → `groups(id)`
  - `group_users.user_id` → `auth.users(id)`
  - `group_invites.group_id` → `groups(id)`
  - `group_invites.invited_by` → `auth.users(id)`
  - `group_invites.user_id` → `auth.users(id)`
- [ ] Note: CASCADE on `group_users.user_id` triggers `update_user_roles`, which will clean up `raw_app_meta_data` — this combined with fix 2.2 handles user deletion cleanly.

### 2.4 Add service_role support (Issue #39 / PR #40)
- [ ] **File:** `user_has_group_role()` and `user_is_group_member()` in new extension version
- [ ] **Fix:** Add service_role check alongside postgres check:
  ```sql
  if session_user = 'postgres' OR auth.role() = 'service_role' then
      return true;
  end if;
  ```
- [ ] **PR:** [#40](https://github.com/point-source/supabase-tenant-rbac/pull/40) is open — review before incorporating

### 2.5 Fix custom schema `db_pre_request` registration (Issue #29)
- [ ] **File:** Extension SQL — the `ALTER ROLE authenticator SET pgrst.db_pre_request` line
- [ ] **Change:** Use schema-qualified name:
  ```sql
  ALTER ROLE authenticator SET pgrst.db_pre_request TO '@extschema@.db_pre_request';
  ```

### 2.6 Version bookkeeping
- [ ] Create `supabase_rbac--4.1.0.sql` — full install script incorporating all fixes
- [ ] Create `supabase_rbac--4.0.0--4.1.0.sql` — upgrade script with ALTER/REPLACE for changed objects
- [ ] Update `supabase_rbac.control`: `default_version = '4.1.0'`
- [ ] Update `supabase/migrations/20240502214828_install_4.0.0.sql` to install 4.1.0
- [ ] Add v4.1.0 entry to `CHANGELOG.md`

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
| Phase 1: Immediate fixes | Pending | No version bump |
| Phase 2: Extension bug fixes | Pending | v4.1.0 |
| Phase 3: Security hardening | Pending | v4.1.0 |
| Phase 4: Testing | Pending | N/A |
| Phase 5: Documentation | In progress (initial docs created) | N/A |
