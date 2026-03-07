# Changelog

## 5.0.0

### Breaking Changes from v4.x

There is no automated upgrade from v4.x to v5.0.0. See `docs/MIGRATION_GUIDE.md`.

- **Data model changes require migration work:**
  - `group_users` (one row per user-group-role) is replaced by `members` (one row per user-group with `roles text[]`).
  - `group_invites` is replaced by `invites`.
  - Claims are no longer stored in `auth.users.raw_app_meta_data->groups`; they are stored in `rbac.user_claims`.
- **Helper and RPC API surface changed:**
  - v4 helpers (`user_has_group_role`, `user_is_group_member`, `get_user_claims`, etc.) are replaced by v5 helpers (`has_role`, `is_member`, `get_claims`, `has_permission`, etc.).
  - `accept_group_invite()` is replaced by `accept_invite()`.
- **Upgrade path is manual** from 4.x to 5.0.0 (export/reinstall/reimport + policy rewrite).

### New in 5.0.0 (vs 4.5.0)

- **Private-schema architecture by default** (`rbac`), with opt-in public wrappers. This removes direct REST exposure of internal extension tables.
- **Permission-centric RBAC model**:
  - New `permissions` registry table.
  - New `roles` definition table with `permissions[]` and `grantable_roles[]`.
  - New `member_permissions` table for direct per-member permission overrides.
- **Built-in privilege escalation prevention**:
  - Role-assignment checks in `add_member()` / `update_member_roles()` / `create_invite()`.
  - Permission-scope checks in `grant_member_permission()` / `revoke_member_permission()`.
  - Wildcard grant scopes via `grantable_roles = ['*']`.
- **Trigger-maintained claims cache** in `rbac.user_claims`, with write-time resolution of:
  - `roles`
  - `permissions`
  - `grantable_roles`
  - `grantable_permissions`
- **Fresh-claims request flow**:
  - `db_pre_request()` populates `request.groups` for PostgREST requests.
  - `get_claims()` falls back to `user_claims` for Storage requests (where pre-request hooks are not invoked).
  - Optional `custom_access_token_hook` injects claims into JWTs at issue time.
- **Expanded management RPC surface**:
  - Group/member/invite operations (`create_group`, `add_member`, `create_invite`, `accept_invite`, etc.).
  - Role/permission administration (`create_role`, `set_role_permissions`, `set_role_grantable_roles`, `create_permission`, etc.).
- **Consistency and hardening improvements included in 5.0.0 final**:
  - Role arrays are canonicalized (dedupe/sort) on write paths.
  - Internal role-membership lookups use GIN-friendly containment operators on `members.roles`.
- **Operational simplification**:
  - Removed dependency on `moddatetime` by replacing it with an internal `_set_updated_at` trigger function.
- **Edge-function/API ergonomics improvements**:
  - Invite edge function accepts `invite_code` in JSON request body, applies stricter Bearer-token parsing, and fails fast on missing environment configuration.
- **Examples and docs cleanup for v5 usage**:
  - Removed deprecated examples superseded by built-in v5 RPCs.
  - Updated policy examples to use explicit `rbac.`-qualified helper calls so they work without public wrapper functions.
- **Release validation coverage expansion**:
  - Test suite expanded to 25 SQL test files / 151 checks, plus dedicated edge-function unit tests for invite acceptance request handling.

### Security posture in 5.0.0

- Deny-all RLS default (tables start with RLS enabled and no policies).
- Minimal SECURITY DEFINER surface (8 functions, each with documented rationale).
- Internal helper functions are locked down (`REVOKE EXECUTE FROM PUBLIC`).
- `user_claims` write path is restricted to internal trigger functions; authenticated users have read-only access.
