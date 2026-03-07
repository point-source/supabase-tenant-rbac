# Security Model

This document describes the security model of the Supabase Tenant RBAC extension — what attacks it defends against, how the defenses work, and what the known limitations are.

## Table of Contents

1. [Threat Model](#threat-model)
2. [Privilege Escalation Prevention](#privilege-escalation-prevention)
3. [SECURITY DEFINER Audit](#security-definer-audit)
4. [Deny-All by Default](#deny-all-by-default)
5. [Private Schema Architecture](#private-schema-architecture)
6. [Claims Forgery Prevention](#claims-forgery-prevention)
7. [Storage RLS Freshness](#storage-rls-freshness)
8. [Known Limitations and Documented Risks](#known-limitations-and-documented-risks)

---

## Threat Model

The extension is designed to defend against the following classes of attack from authenticated users:

**Privilege escalation via role assignment.** A user with limited authority attempts to assign a role they are not authorized to grant — either to themselves or to another member.

**Privilege escalation via permission override.** A user attempts to grant a direct permission override that is outside their authorized grant scope.

**Invite escalation.** A user creates an invite with roles beyond their authorized grant scope, allowing a new user to join with elevated privileges.

**Claims forgery.** An authenticated user attempts to directly write to `user_claims` to inject false claims.

**Direct table access.** A user attempts to read or write internal RBAC tables directly via the REST API, bypassing RPCs.

**Cross-group data access.** A user attempts to read or modify data belonging to a group they are not a member of.

The extension does not defend against:

**Malicious service_role users.** `service_role` bypasses all RLS and can perform any operation. This is a Supabase platform property, not specific to this extension.

**Application-level bugs.** If an app author writes an RLS policy that is too permissive, or forgets to add a policy, the extension cannot prevent that.

**Audit logging.** The extension does not provide built-in audit trails. App authors who need audit logging should add triggers on `members` and `member_permissions`.

---

## Privilege Escalation Prevention

Privilege escalation prevention is built into the management RPCs. It is not left to the app author to implement.

### Role Assignment Escalation

**Affected RPCs:** `add_member()`, `update_member_roles()`

**Check:** Before performing the write, the RPC calls `_check_role_escalation()`, which reads the caller's `grantable_roles` from the `user_claims` cache and verifies that every role in the target `p_roles` array is within the caller's grant scope.

**Example:** An `admin` with `grantable_roles = ['editor', 'viewer']` tries to call `add_member(group_id, user_id, ARRAY['owner'])`. The check reads `'owner'` is not in `['editor', 'viewer']` and raises an error. The INSERT never happens.

**Wildcard:** If the caller's `grantable_roles` contains `'*'`, all role assignments are permitted, including roles added after the caller's membership was established.

### Permission Override Escalation

**Affected RPCs:** `grant_member_permission()`, `revoke_member_permission()`

**Check:** The RPC reads the caller's `grantable_permissions` from the `user_claims` cache and verifies that the target permission is within the caller's grantable scope.

**Derivation:** `grantable_permissions` is computed at write time by `_build_user_claims()`. It is the union of `roles.permissions[]` for all roles in the caller's `grantable_roles` set. If `grantable_roles` contains `'*'`, then `grantable_permissions` is also `['*']`.

**Symmetry:** `revoke_member_permission()` applies the same check as `grant_member_permission()`. Revocation is also a privileged operation. If an app author tightens `grantable_roles` and existing overrides become unrevocable by normal members, `service_role` can clean them up.

### Invite Escalation

**Affected RPC:** `create_invite()`

**Check:** Before inserting the invite, the RPC validates the `p_roles` array against the caller's `grantable_roles`, using the same mechanism as `add_member()`. A member cannot create an invite that would grant roles beyond their own grant scope.

**Rationale:** Without this check, a `viewer` could create an invite with `roles = ['owner']`. The invite would sit in the database and the first user to accept it would become an owner — even though the creator never had authority to grant that role.

### Wildcard Scope

A role with `grantable_roles = ['*']` has unlimited grant scope:

- Can assign any role that exists in the `roles` table.
- Can directly grant any permission that exists in the `permissions` table.
- The wildcard is evaluated at enforcement time against the current set of roles and permissions — it does cover roles added after the caller's membership was established.

The pre-seeded `owner` role ships with `grantable_roles = ['*']`. This makes group owners full administrators by default. App authors can change this by calling `set_role_grantable_roles('owner', ARRAY['admin', 'editor', 'viewer'])` to restrict what owners can grant.

### Prospective-Only Changes

**Important limitation:** Changes to `grantable_roles` on a role definition are prospective only.

When `grantable_roles` is updated on a role, `_on_role_definition_change()` rebuilds the claims cache for all users holding that role. Their cached `grantable_permissions` is recomputed based on the new scope.

However, existing memberships and permission overrides that were granted before the change are not revoked. If an `admin` previously granted an `editor` role to a member, and you subsequently remove `editor` from the `admin` role's `grantable_roles`, the existing `editor` membership remains. Future attempts by that `admin` to grant `editor` will be blocked, but the existing grants stand.

App authors are responsible for cleanup when they tighten grant scope. `service_role` can always perform direct revocations.

---

## SECURITY DEFINER Audit

The extension minimizes SECURITY DEFINER surface. Only 8 functions are SECURITY DEFINER. Each has a documented justification and documented trust boundary.

| Function | Why DEFINER | Trust Boundary |
|----------|-------------|----------------|
| `_on_group_created()` | AFTER INSERT trigger on `groups`. The caller has no prior membership, so the INSERT into `members` would fail RLS if done in user context. | Fires only as a trigger (cannot be called via RPC or REST). Reads `auth.uid()` to bind membership. Skips when `auth.uid()` is NULL (service_role/migration inserts). Role names are validated against `rbac.roles`. |
| `accept_invite(p_invite_id)` | Caller has no prior membership in the target group. Without DEFINER, the upsert into `members` would fail RLS. | Validates invite expiry and unused status. Uses `auth.uid()` (not a caller-supplied parameter) to bind the membership. Cannot accept an invite on behalf of another user. |
| `_sync_member_metadata()` | Trigger function. Must write to `user_claims` without requiring INSERT/UPDATE grants for `authenticated`. | Cannot be called directly via RPC or REST. Only fires as the `on_change_sync_member_metadata` trigger on the `members` table. Writes only to `user_claims` for the affected user. |
| `_sync_member_permission()` | Trigger function. Must write to `user_claims` without requiring INSERT/UPDATE grants for `authenticated`. | Cannot be called directly via RPC or REST. Only fires as the `on_member_permission_change` trigger on `member_permissions`. Writes only to `user_claims` for the affected user. |
| `_on_role_definition_change()` | Trigger function. Must write to `user_claims` for multiple users (all holders of the changed role) without requiring broad grants. | Cannot be called directly via RPC or REST. Only fires as the `on_role_definition_change` trigger on `roles`. Writes only to `user_claims`. |
| `_validate_roles(p_roles text[])` | INVOKER management RPCs need to validate role names against `rbac.roles`, but `authenticated` has no SELECT on that table by default. | Reads only `roles.name`. No writes. Output is limited to an exception message that names the invalid role — no other data is exposed. Cannot be called with a role that `authenticated` does not know about already (they supplied the role name as a parameter). |
| `_validate_permissions(p_permissions text[])` | INVOKER management RPCs need to validate permission names against `rbac.permissions`, but `authenticated` has no SELECT on that table by default. | Reads only `permissions.name`. No writes. Same information-exposure rationale as `_validate_roles`. |
| `_validate_grantable_roles(p_roles text[])` | INVOKER role-management RPCs need to validate that role names listed in `grantable_roles` exist in `rbac.roles` (or are `'*'`). | Reads only `roles.name`. No writes. Does not enforce caller grant scope. |

---

## Deny-All by Default

All extension tables have Row Level Security enabled with zero policies on install. This means:

- No `authenticated` user can SELECT, INSERT, UPDATE, or DELETE from any `rbac.*` table after install.
- Nothing works until the app author explicitly adds RLS policies.
- This includes group creation — `create_group()` is SECURITY INVOKER, so without an INSERT policy on `rbac.groups`, it is blocked by RLS. Single-tenant apps can omit this policy to prevent users from creating additional groups.

This is the safest default: a misconfigured system fails closed (access denied) rather than open.

The recommended starting point for RLS policies is `examples/policies/quickstart.sql`. This file provides sensible policies for all six extension tables using the pre-seeded `owner` role.

---

## Private Schema Architecture

All extension tables live in the `rbac` schema (the extension schema specified at `CREATE EXTENSION` time). This schema is intentionally not exposed via PostgREST.

PostgREST exposes schemas listed in `db_schemas` in your `config.toml` or project settings. The `rbac` schema should not be in that list. As long as it is not exposed:

- No user can issue a REST GET/POST/PATCH/DELETE against `rbac.*` tables, even if they have table-level privileges.
- All interaction goes through RPCs in the `rbac` schema (or public wrappers, if created).

**Public wrappers are opt-in.** The default install has zero public surface. To expose RPCs to PostgREST for use in the REST API (e.g., via `supabase.functions.invoke` or direct HTTP calls), run `examples/setup/create_public_wrappers.sql`. These are thin pass-through functions in the `public` schema that delegate to the `rbac` originals. The `rbac` originals retain their security properties.

**`anon` has no grants.** The `anon` role has no EXECUTE on any extension function and no SELECT on any extension table. Unauthenticated requests cannot call any extension function.

---

## Claims Forgery Prevention

The `user_claims` table is the authoritative source for all authorization decisions. An attacker who could write to this table could grant themselves arbitrary permissions.

**Why authenticated users cannot write to user_claims:**

1. **Privilege level:** `authenticated` has only SELECT on `user_claims` (for the `db_pre_request` path). No INSERT or UPDATE is granted.

2. **RLS level:** Even if a privilege were granted, RLS on `user_claims` has no INSERT or UPDATE policies for `authenticated`. A `WITH CHECK (true)` policy is not present.

3. **Write mechanism:** The three trigger functions that write to `user_claims` (`_sync_member_metadata`, `_sync_member_permission`, `_on_role_definition_change`) are SECURITY DEFINER and run as `postgres`. They are the only write path. Trigger functions (`RETURNS trigger`) cannot be invoked directly via RPC or REST.

The two-layer defense (privilege + RLS) means that even a misconfigured RLS policy cannot open the write path to `authenticated`, because the privilege is not granted.

---

## Storage RLS Freshness

Supabase Storage routes requests through a separate code path that does not invoke the PostgREST `db_pre_request` hook. A naive implementation would leave Storage RLS policies using stale claims from the JWT.

The extension addresses this in `get_claims()`:

- If `request.groups` is set (PostgREST path), return it — this is the fresh value written by `db_pre_request`.
- If `request.groups` is not set (Storage path), fall back to reading `user_claims` directly via `_get_user_groups()`.

The fallback reads from the same `user_claims` table that `db_pre_request` reads from. Both paths reflect the same claims state, rebuilt by triggers whenever memberships change. Storage RLS policies using `has_role()`, `is_member()`, `has_permission()`, etc., always reflect the current membership state.

---

## Known Limitations and Documented Risks

### Invite UUID as a Bearer Token

Invite codes are UUIDs generated by `gen_random_uuid()`, which provides 122 bits of entropy. This is cryptographically strong enough to prevent brute-force guessing. However, invite codes should be treated as bearer tokens:

- **Set a short `expires_at`:** An unexpired, unused invite is permanently valid. Set `expires_at` to the shortest acceptable window (e.g., 7 days for email invites, 15 minutes for one-click links).
- **Single-use enforcement:** `accept_invite()` atomically marks the invite as used (`user_id IS NOT NULL`, `accepted_at IS NOT NULL`) and refuses to reuse it. There is no secondary share-link mechanism — each invite is consumed exactly once.
- **Revocation:** Use `delete_invite()` to invalidate an outstanding invite before it is accepted.

### `create_group()` Resource Exhaustion

`create_group()` is a SECURITY INVOKER function. An INSERT policy on `rbac.groups` is required for it to succeed — without one, RLS blocks group creation (deny-all default). However, if an INSERT policy is present, any authenticated user matching that policy can create groups with no built-in rate limit or quota. Mitigations:

- Add an application-level rate limit (e.g., at the API gateway or in a PostgREST pre-request hook).
- Add an RLS-equivalent BEFORE trigger on `rbac.groups` that counts existing groups per user and raises an exception above a threshold.
- Restrict or omit the INSERT policy on `rbac.groups` (e.g., single-tenant apps can omit it entirely to prevent users from creating new groups).

### Empty `members.roles` Is Intentional

A `members` row may have `roles = '{}'` (an empty array). This represents a member with no roles — they are in the group (so `is_member()` returns true) but have no permissions from roles. This is a valid state used to represent group membership without role-based authority.

This differs from `invites.roles`, which has a `CHECK (cardinality(roles) > 0)` constraint — invites must specify at least one role to be meaningful.

### No Automated Upgrade from v4.x

There is no automated upgrade path from v4.x to v5.0.0. The schema changes are too extensive. Migration requires data export, extension drop, reinstall, and re-import. See [docs/MIGRATION_GUIDE.md](MIGRATION_GUIDE.md).

### Supabase Logical Backup Limitations

Supabase logical backups may fail to restore correctly if `auth.users` is not available when the extension is being restored. This is an upstream Supabase platform issue (see GitHub Issue #41) with no workaround within this extension. Contact Supabase support if you encounter this.

### Role Definitions Are Global

All groups share the same role vocabulary. There is no way to define roles that exist only for one group. If your application needs different role names for different groups, the current system requires all of those role names to be registered globally in `rbac.roles`.

Per-group custom roles are a planned future enhancement. The `permissions` table being a separate, canonical registry (rather than permissions being embedded only in `roles.permissions[]`) is designed to enable this without schema changes.

### Permission Strings Are Opaque

The extension does not interpret dot-notation or other structure in permission strings. `group_data.read` and `group_data.*` are two independent strings. There is no wildcard matching within permission strings. If you want a broad grant (e.g., all `group_data.*` permissions), you must list each permission explicitly in the role definition.

### Prospective-Only Changes

Tightening `grantable_roles` on a role definition does not retroactively revoke existing memberships or permission overrides. Only future grant operations are affected. This is documented above in [Privilege Escalation Prevention](#privilege-escalation-prevention) and is a documented design decision, not a bug. App authors must perform explicit cleanup via `service_role` if they need to revoke existing grants after tightening scope.

### Self-Removal Risk

An `owner` can remove themselves from the group using `remove_member()` (subject to RLS). If there are no other owners, the group becomes orphaned — no member has the authority to perform owner-level operations. The extension does not prevent this.

Mitigation: add an RLS DELETE policy on `members` that prevents deleting the last owner, or add an `AFTER DELETE` trigger that checks for at least one remaining owner.

### Audit Logging

The extension does not provide built-in audit trails. If you need to track who added whom to a group, or who changed a member's roles, add triggers on `members` and `member_permissions`. The `_sync_member_metadata` trigger fires AFTER the write, so a custom BEFORE trigger could capture the pre-change state.
