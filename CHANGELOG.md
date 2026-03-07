# Changelog

## 5.0.0

### Breaking Changes from v4.x

There is no automated upgrade from v4.x to v5.0.0. See `docs/MIGRATION_GUIDE.md`.

### New Features

- **`permissions` table** — Canonical registry of all permission strings. All role permissions and member permission overrides are validated against this table at write time. Managed exclusively via `service_role` RPCs.

- **`grantable_roles` on roles** — Each role definition now declares which other roles its holders can assign (`grantable_roles text[]`). The pre-seeded `owner` role has `grantable_roles = ['*']` (can grant any role). Used to prevent privilege escalation.

- **Expanded claims cache** — `user_claims.claims` now stores four fields per group: `roles`, `permissions`, `grantable_roles`, `grantable_permissions`. All four are resolved at write time by `_build_user_claims()`.

- **Wildcard `'*'` in `grantable_roles`** — A role with `grantable_roles = ['*']` can assign any role and any permission, including roles added in the future.

- **Privilege escalation prevention** — `add_member()`, `update_member_roles()`, `create_invite()`, `grant_member_permission()`, and `revoke_member_permission()` now enforce that the caller's cached grant scope covers the target roles/permissions. Built-in, not left to app author policy.

- **New RPCs: `create_permission()`, `delete_permission()`, `list_permissions()`** — service_role management of the permissions registry.

- **New RPC: `set_role_grantable_roles()`** — service_role management of a role's grant scope.

- **Extended `create_role()` signature** — Now accepts `p_permissions text[]` and `p_grantable_roles text[]` for creating fully-configured roles in one call.

- **`list_roles()` returns `grantable_roles`** — The `grantable_roles` column is included in the output.

- **Private schema architecture** — All tables in `rbac` schema, not exposed via PostgREST. Public wrappers are opt-in.

- **Trigger-based claims cache** — Three triggers maintain the `user_claims` cache automatically. Cache is rebuilt on membership changes, permission override changes, and role definition changes.

- **Auth hook** — Optional `custom_access_token_hook` injects claims into JWTs at token creation time.

- **Invite RPCs** — `create_invite()` (with escalation check) and `delete_invite()`.

- **Direct permission overrides** — `grant_member_permission()`, `revoke_member_permission()`, `list_member_permissions()`.

### Security Architecture

- 8 SECURITY DEFINER functions (down from broad defaults in v4): `_on_group_created`, `accept_invite`, `_sync_member_metadata`, `_sync_member_permission`, `_on_role_definition_change`, `_validate_roles`, `_validate_permissions`, `_validate_grantable_roles`.
- Deny-all RLS by default on all tables.
- Internal helpers locked down: `REVOKE EXECUTE FROM PUBLIC` on all `_`-prefixed functions.
- `rbac.roles` and `rbac.permissions` tables hidden from `authenticated` by default.
- `user_claims` write access restricted to DEFINER trigger functions.
