# Supabase Tenant RBAC v5.x.x — Security Test Specification

## Table of Contents

1. [Test Infrastructure](#test-infrastructure)
2. [Privilege Escalation Prevention](#privilege-escalation-prevention)
   - [Role Assignment Escalation](#role-assignment-escalation)
   - [Permission Override Escalation](#permission-override-escalation)
   - [Invite Escalation](#invite-escalation)
   - [Revocation Scope](#revocation-scope)
   - [Wildcard Grantable Roles](#wildcard-grantable-roles)
3. [Deny-All Default Enforcement](#deny-all-default-enforcement)
4. [SECURITY DEFINER Function Isolation](#security-definer-function-isolation)
5. [Private Schema Isolation](#private-schema-isolation)
6. [Claims Cache Integrity](#claims-cache-integrity)
   - [Trigger-Based Sync](#trigger-based-sync)
   - [Role Definition Changes](#role-definition-changes)
   - [Grantable Scope Cache](#grantable-scope-cache)
7. [Claims Freshness](#claims-freshness)
   - [db_pre_request Hook](#db_pre_request-hook)
   - [Storage RLS Fallback](#storage-rls-fallback)
8. [Permission Validation](#permission-validation)
9. [Invite System Security](#invite-system-security)
10. [Auth Hook Security](#auth-hook-security)
11. [Edge Cases & Boundary Conditions](#edge-cases--boundary-conditions)
12. [Role-Based Bypass Behavior](#role-based-bypass-behavior)

---

## Test Infrastructure

### Assumed Test Roles

All tests should operate under clearly defined database roles to verify behavior at each privilege level:

| Test Actor  | Database Role   | Description                                                                    |
| ----------- | --------------- | ------------------------------------------------------------------------------ |
| `superuser` | `postgres`      | Full superuser; represents app author during migrations                        |
| `service`   | `service_role`  | Service role; represents backend/server operations                             |
| `alice`     | `authenticated` | Group owner (holds `owner` role with `grantable_roles = ['*']`)                |
| `bob`       | `authenticated` | Group admin (holds `admin` role with `grantable_roles = ['editor', 'viewer']`) |
| `carol`     | `authenticated` | Group editor (holds `editor` role with `grantable_roles = ['viewer']`)         |
| `dave`      | `authenticated` | Group viewer (holds `viewer` role with `grantable_roles = []`)                 |
| `eve`       | `authenticated` | Non-member (no group membership)                                               |
| `anon_user` | `anon`          | Unauthenticated user                                                           |

### Assumed Role Definitions

| Role     | Permissions                                                                 | Grantable Roles        |
| -------- | --------------------------------------------------------------------------- | ---------------------- |
| `owner`  | `group.update`, `group.delete`, `members.manage`, `data.read`, `data.write` | `['*']`                |
| `admin`  | `group.update`, `members.manage`, `data.read`, `data.write`                 | `['editor', 'viewer']` |
| `editor` | `data.read`, `data.write`                                                   | `['viewer']`           |
| `viewer` | `data.read`                                                                 | `[]`                   |

### Assumed Permissions Registry

All of the following exist in the `permissions` table:

`group.update`, `group.delete`, `members.manage`, `data.read`, `data.write`, `data.export`

Note: `data.export` is intentionally not assigned to any role — it exists in the registry for testing override scenarios.

### Test Notation

Each test is written as:

- **Given:** preconditions
- **When:** the action under test
- **Then:** expected outcome (ALLOW or DENY, with specific error where relevant)

---

## Privilege Escalation Prevention

### Role Assignment Escalation

**ESC-R-01: Admin cannot assign a role outside their grantable set**

- Given: `bob` is `admin` in group G (`grantable_roles = ['editor', 'viewer']`)
- When: `bob` calls `add_member(G, eve, ['owner'])`
- Then: DENY — error indicating `owner` is not in caller's grantable roles

**ESC-R-02: Admin can assign a role within their grantable set**

- Given: `bob` is `admin` in group G
- When: `bob` calls `add_member(G, eve, ['editor'])`
- Then: ALLOW — `eve` is added with `editor` role

**ESC-R-03: Admin cannot assign multiple roles if any is outside grantable set**

- Given: `bob` is `admin` in group G
- When: `bob` calls `add_member(G, eve, ['viewer', 'owner'])`
- Then: DENY — `owner` is not in caller's grantable roles; entire operation rejected (no partial assignment)

**ESC-R-04: Admin cannot escalate via update_member_roles**

- Given: `bob` is `admin` in group G; `dave` is `viewer` in group G
- When: `bob` calls `update_member_roles(G, dave, ['owner'])`
- Then: DENY — `owner` is not in caller's grantable roles

**ESC-R-05: Admin can update roles within grantable set**

- Given: `bob` is `admin` in group G; `dave` is `viewer` in group G
- When: `bob` calls `update_member_roles(G, dave, ['editor', 'viewer'])`
- Then: ALLOW — `dave` now has `['editor', 'viewer']`

**ESC-R-06: Member with empty grantable_roles cannot assign any role**

- Given: `dave` is `viewer` in group G (`grantable_roles = []`)
- When: `dave` calls `add_member(G, eve, ['viewer'])`
- Then: DENY — caller has no grantable roles

**ESC-R-07: Escalation check uses union of caller's roles' grantable sets**

- Given: `bob` holds both `admin` (`grantable_roles = ['editor', 'viewer']`) and `editor` (`grantable_roles = ['viewer']`) in group G
- When: `bob` calls `add_member(G, eve, ['editor'])`
- Then: ALLOW — `editor` is in the union of caller's grantable roles

**ESC-R-08: Member cannot assign roles in a group they don't belong to**

- Given: `bob` is `admin` in group G1 but not a member of group G2
- When: `bob` calls `add_member(G2, eve, ['viewer'])`
- Then: DENY — caller has no claims in G2

**ESC-R-09: add_member role merge does not bypass escalation check**

- Given: `carol` is `editor` in group G (`grantable_roles = ['viewer']`); `dave` is already `viewer` in group G
- When: `carol` calls `add_member(G, dave, ['admin'])`
- Then: DENY — `admin` is not in caller's grantable roles; existing `viewer` role is unchanged

### Permission Override Escalation

**ESC-P-01: Member cannot grant a permission outside their grantable set**

- Given: `carol` is `editor` in group G; `carol`'s `grantable_permissions` = `['data.read']` (derived from grantable_roles = `['viewer']`)
- When: `carol` calls `grant_member_permission(G, dave, 'data.write')`
- Then: DENY — `data.write` is not in caller's grantable permissions

**ESC-P-02: Member can grant a permission within their grantable set**

- Given: `carol` is `editor` in group G; `carol`'s `grantable_permissions` includes `data.read`
- When: `carol` calls `grant_member_permission(G, dave, 'data.read')`
- Then: ALLOW — override is created

**ESC-P-03: Permission override must exist in permissions registry**

- Given: `alice` is `owner` in group G (`grantable_roles = ['*']`)
- When: `alice` calls `grant_member_permission(G, dave, 'nonexistent.perm')`
- Then: DENY — permission does not exist in `permissions` table

**ESC-P-04: Override for an unassigned-but-registered permission works**

- Given: `alice` is `owner` in group G; `data.export` exists in `permissions` table but is not assigned to any role
- When: `alice` calls `grant_member_permission(G, dave, 'data.export')`
- Then: ALLOW — the permission exists in the registry and `alice` has `grantable_roles = ['*']`

**ESC-P-05: Grantable permissions are derived from grantable roles correctly**

- Given: `bob` is `admin` in group G with `grantable_roles = ['editor', 'viewer']`; `editor` has `['data.read', 'data.write']`; `viewer` has `['data.read']`
- When: checking `bob`'s cached `grantable_permissions`
- Then: `grantable_permissions` = `['data.read', 'data.write']` (deduplicated union)

### Invite Escalation

**ESC-I-01: Invite creator cannot set roles outside their grantable set**

- Given: `bob` is `admin` in group G (`grantable_roles = ['editor', 'viewer']`)
- When: `bob` calls `create_invite(G, ['owner'])`
- Then: DENY — `owner` is not in caller's grantable roles

**ESC-I-02: Invite creator can set roles within their grantable set**

- Given: `bob` is `admin` in group G
- When: `bob` calls `create_invite(G, ['editor', 'viewer'])`
- Then: ALLOW — invite is created

**ESC-I-03: Non-member cannot create invite**

- Given: `eve` is not a member of group G
- When: `eve` calls `create_invite(G, ['viewer'])`
- Then: DENY — caller has no claims in G

### Revocation Scope

**REV-01: Member can revoke a permission within their grantable set**

- Given: `bob` is `admin` in group G; `dave` has direct override `data.read`
- When: `bob` calls `revoke_member_permission(G, dave, 'data.read')`
- Then: ALLOW — override is removed

**REV-02: Member cannot revoke a permission outside their grantable set**

- Given: `carol` is `editor` in group G (`grantable_permissions` derived from `['viewer']`); `dave` has direct override `data.write`
- When: `carol` calls `revoke_member_permission(G, dave, 'data.write')`
- Then: DENY — `data.write` is not in caller's grantable permissions

**REV-03: service_role can revoke any permission (escape hatch)**

- Given: `dave` has direct override `group.delete` in group G
- When: `service` calls `revoke_member_permission(G, dave, 'group.delete')`
- Then: ALLOW — service_role bypasses escalation checks

**REV-04: Dangling permission survives grantable_roles change**

- Given: `bob` is `admin` and previously granted `dave` the override `data.write`; app author then changes `admin.grantable_roles` to `['viewer']` only
- When: `bob` calls `revoke_member_permission(G, dave, 'data.write')`
- Then: DENY — `data.write` is no longer in `bob`'s grantable permissions
- And: `dave` still has the override (prospective-only change)
- And: `service` can revoke it

### Wildcard Grantable Roles

**WC-01: Wildcard allows granting any role**

- Given: `alice` is `owner` in group G (`grantable_roles = ['*']`)
- When: `alice` calls `add_member(G, eve, ['admin'])`
- Then: ALLOW

**WC-02: Wildcard allows granting any permission override**

- Given: `alice` is `owner` in group G (`grantable_permissions = ['*']`)
- When: `alice` calls `grant_member_permission(G, dave, 'group.delete')`
- Then: ALLOW

**WC-03: Wildcard propagates from grantable_roles to grantable_permissions**

- Given: `alice` is `owner` with `grantable_roles = ['*']`
- When: checking `alice`'s cached `grantable_permissions`
- Then: `grantable_permissions = ['*']`

**WC-04: Wildcard covers roles added after the cache was built**

- Given: `alice` is `owner` with `grantable_roles = ['*']`; app author creates new role `moderator`
- When: `alice` calls `add_member(G, eve, ['moderator'])`
- Then: ALLOW — `'*'` matches any role, including newly created ones

**WC-05: Non-wildcard does not cover newly added roles**

- Given: `bob` is `admin` with `grantable_roles = ['editor', 'viewer']`; app author creates new role `moderator`
- When: `bob` calls `add_member(G, eve, ['moderator'])`
- Then: DENY — `moderator` is not in `['editor', 'viewer']`

---

## Deny-All Default Enforcement

**DA-01: No operations succeed on groups without policies**

- Given: fresh installation, no RLS policies added
- When: `alice` (authenticated) attempts SELECT, INSERT, UPDATE, DELETE on `rbac.groups`
- Then: DENY on all four operations

**DA-02: No operations succeed on members without policies**

- Given: fresh installation, no RLS policies added
- When: `alice` (authenticated) attempts SELECT, INSERT, UPDATE, DELETE on `rbac.members`
- Then: DENY on all four operations

**DA-03: No operations succeed on invites without policies**

- Given: fresh installation, no RLS policies added
- When: `alice` (authenticated) attempts any operation on `rbac.invites`
- Then: DENY

**DA-04: No operations succeed on member_permissions without policies**

- Given: fresh installation, no RLS policies added
- When: `alice` (authenticated) attempts any operation on `rbac.member_permissions`
- Then: DENY

**DA-05: roles table is inaccessible to authenticated users**

- Given: fresh installation
- When: `alice` (authenticated) attempts SELECT on `rbac.roles`
- Then: DENY (managed via service_role RPCs only)

**DA-06: permissions table is inaccessible to authenticated users**

- Given: fresh installation
- When: `alice` (authenticated) attempts SELECT on `rbac.permissions`
- Then: DENY (managed via service_role RPCs only)

**DA-07: user_claims table is inaccessible to authenticated users**

- Given: fresh installation
- When: `alice` (authenticated) attempts SELECT, INSERT, UPDATE, DELETE on `rbac.user_claims`
- Then: DENY on all operations

**DA-08: create_group works despite deny-all (SECURITY DEFINER bypass)**

- Given: fresh installation, no RLS policies added
- When: `alice` (authenticated) calls `create_group('Test Group')`
- Then: ALLOW — `create_group` is SECURITY DEFINER and bypasses RLS for the INSERT

---

## SECURITY DEFINER Function Isolation

**SD-01: create_group only creates one group and one membership**

- Given: `alice` (authenticated) calls `create_group('Test')`
- When: inspecting database state after the call
- Then: exactly one new row in `groups`, exactly one new row in `members` with `alice`'s user_id and `['owner']` roles; no other side effects

**SD-02: create_group uses caller's auth.uid(), not a spoofable parameter**

- Given: `alice` calls `create_group('Test')`
- When: inspecting the created membership
- Then: `members.user_id = auth.uid()` of the caller, not a parameter

**SD-03: accept_invite only processes the specified invite**

- Given: two pending invites exist (invite_1 for group G1, invite_2 for group G2)
- When: `eve` calls `accept_invite(invite_1)`
- Then: `eve` is added to G1 only; invite_2 is unaffected

**SD-04: accept_invite cannot be called twice on the same invite**

- Given: `eve` has already accepted invite_1
- When: `eve` calls `accept_invite(invite_1)` again
- Then: DENY — invite is already accepted

**SD-05: Internal trigger functions are not callable by authenticated users**

- Given: `alice` (authenticated)
- When: `alice` calls `rbac._sync_member_metadata()` directly
- Then: DENY — function is not accessible to the `authenticated` role

**SD-06: Internal trigger functions are not callable by anon**

- Given: `anon_user`
- When: `anon_user` calls `rbac._build_user_claims()` directly
- Then: DENY

---

## Private Schema Isolation

**PS-01: Extension tables are not accessible via PostgREST REST API**

- Given: extension installed in `rbac` schema; `rbac` is not in PostgREST `schemas` config
- When: HTTP GET request to `/rest/v1/groups` (or `/rest/v1/members`, etc.)
- Then: 404 or empty — tables are not discoverable

**PS-02: Extension functions in rbac schema are not callable via PostgREST RPC**

- Given: no public wrapper functions created
- When: HTTP POST to `/rest/v1/rpc/create_group`
- Then: 404 — function is not discoverable

**PS-03: Public wrapper functions are accessible via PostgREST RPC when created**

- Given: `examples/setup/create_public_wrappers.sql` has been applied
- When: HTTP POST to `/rest/v1/rpc/create_group` with valid JWT
- Then: function executes successfully

**PS-04: Removing public wrappers restores isolation**

- Given: public wrappers were created, then `examples/setup/remove_public_wrappers.sql` is applied
- When: HTTP POST to `/rest/v1/rpc/create_group`
- Then: 404 — function is no longer discoverable

---

## Claims Cache Integrity

### Trigger-Based Sync

**CC-01: Adding a member updates user_claims**

- Given: `alice` calls `add_member(G, eve, ['viewer'])`
- When: inspecting `rbac.user_claims` for `eve`
- Then: claims contain group G with `roles = ['viewer']`, `permissions` matching viewer's permissions, and appropriate `grantable_roles`/`grantable_permissions`

**CC-02: Removing a member removes the group from user_claims**

- Given: `eve` is a member of group G
- When: `alice` calls `remove_member(G, eve)`
- Then: group G is no longer present in `eve`'s claims; if `eve` has no other groups, claims = `{}`

**CC-03: Updating member roles updates all four cache fields**

- Given: `eve` is `viewer` in group G
- When: `alice` calls `update_member_roles(G, eve, ['editor'])`
- Then: `eve`'s claims for G reflect `roles = ['editor']`, permissions matching editor, and grantable_roles/grantable_permissions matching editor's grant scope

**CC-04: Adding a member_permission override updates cached permissions**

- Given: `eve` is `viewer` in group G with `permissions = ['data.read']`
- When: `alice` calls `grant_member_permission(G, eve, 'data.write')`
- Then: `eve`'s cached permissions for G = `['data.read', 'data.write']`

**CC-05: Removing a member_permission override updates cached permissions**

- Given: `eve` has override `data.write` plus role-derived `data.read` in group G
- When: `alice` calls `revoke_member_permission(G, eve, 'data.write')`
- Then: `eve`'s cached permissions for G = `['data.read']` (role-derived only)

**CC-06: Multi-group user has independent claims per group**

- Given: `eve` is `viewer` in G1 and `editor` in G2
- When: inspecting `rbac.user_claims` for `eve`
- Then: claims contain two keys (G1 and G2) with independent roles/permissions/grantable sets

**CC-07: Deleting a group cascades and cleans up user_claims**

- Given: `eve` is a member of group G
- When: group G is deleted
- Then: G is removed from `eve`'s claims

### Role Definition Changes

**CC-08: Changing a role's permissions rebuilds claims for holders**

- Given: `eve` has role `editor` in group G; `editor.permissions = ['data.read', 'data.write']`
- When: app author calls `revoke_permission('editor', 'data.write')`
- Then: `eve`'s cached `permissions` for G no longer includes `data.write`

**CC-09: Changing a role's permissions rebuilds grantable_permissions for granters**

- Given: `bob` is `admin` with `grantable_roles = ['editor', 'viewer']`; `editor.permissions = ['data.read', 'data.write']`
- When: app author calls `revoke_permission('editor', 'data.write')`
- Then: `bob`'s cached `grantable_permissions` no longer includes `data.write` (assuming `data.write` is not also held by `viewer`)

**CC-10: Adding a new permission to a role rebuilds claims**

- Given: `eve` has role `viewer`; `viewer.permissions = ['data.read']`
- When: app author calls `grant_permission('viewer', 'data.export')`
- Then: `eve`'s cached `permissions` includes `data.export`

### Grantable Scope Cache

**CC-11: Grantable roles are cached correctly**

- Given: `bob` holds `admin` (`grantable_roles = ['editor', 'viewer']`) in group G
- When: inspecting `bob`'s claims
- Then: `grantable_roles = ['editor', 'viewer']`

**CC-12: Grantable roles union across multiple held roles**

- Given: `bob` holds both `admin` (`grantable_roles = ['editor', 'viewer']`) and `editor` (`grantable_roles = ['viewer']`) in group G
- When: inspecting `bob`'s claims
- Then: `grantable_roles = ['editor', 'viewer']` (deduplicated union)

**CC-13: Wildcard in any held role collapses grantable_roles to ['*']**

- Given: `alice` holds `owner` (`grantable_roles = ['*']`) and `admin` (`grantable_roles = ['editor', 'viewer']`) in group G
- When: inspecting `alice`'s claims
- Then: `grantable_roles = ['*']`

**CC-14: Wildcard grantable_roles produces wildcard grantable_permissions**

- Given: `alice` has `grantable_roles = ['*']`
- When: inspecting `alice`'s claims
- Then: `grantable_permissions = ['*']`

**CC-15: Changing grantable_roles on a role definition rebuilds affected users' claims**

- Given: `bob` holds `admin` in group G; `admin.grantable_roles = ['editor', 'viewer']`
- When: app author changes `admin.grantable_roles` to `['viewer']`
- Then: `bob`'s cached `grantable_roles` becomes `['viewer']`; `grantable_permissions` is recomputed accordingly

---

## Claims Freshness

### db_pre_request Hook

**CF-01: Claims are available in request context after db_pre_request**

- Given: `alice` is `owner` in group G; `db_pre_request` is registered
- When: `alice` makes a PostgREST API request
- Then: `current_setting('request.groups', true)` returns `alice`'s claims JSON

**CF-02: Role change takes effect on the next API request**

- Given: `eve` is `viewer` in group G
- When: `alice` calls `update_member_roles(G, eve, ['editor'])`, then `eve` makes an API request
- Then: `eve`'s request context contains `roles = ['editor']`

**CF-03: Removed member gets empty claims on next request**

- Given: `eve` is a member of group G
- When: `alice` calls `remove_member(G, eve)`, then `eve` makes an API request
- Then: `eve`'s request context contains `{}` (or group G is absent)

**CF-04: Groupless user gets empty claims, not an error**

- Given: `eve` has never been added to any group
- When: `eve` makes a PostgREST API request
- Then: `current_setting('request.groups', true)` returns `'{}'`; no 500 error

### Storage RLS Fallback

**CF-05: get_claims() works in Storage context (no request.groups set)**

- Given: `alice` is `owner` in group G; request is via Supabase Storage (db_pre_request not invoked)
- When: an RLS policy calls `get_claims()`
- Then: returns `alice`'s claims read directly from `rbac.user_claims`

**CF-06: Role change takes effect in Storage RLS immediately**

- Given: `eve` is `viewer` in group G
- When: `alice` calls `update_member_roles(G, eve, ['editor'])`, then `eve` makes a Storage request
- Then: `has_role(G, 'editor')` returns true in the Storage RLS policy

---

## Permission Validation

**PV-01: Role cannot be assigned a permission that doesn't exist in the registry**

- Given: `permissions` table does not contain `fake.perm`
- When: app author calls `grant_permission('editor', 'fake.perm')`
- Then: DENY — permission not found in registry

**PV-02: set_role_permissions rejects any unknown permission**

- Given: `permissions` table contains `data.read`, `data.write` but not `fake.perm`
- When: app author calls `set_role_permissions('editor', ['data.read', 'fake.perm'])`
- Then: DENY — entire operation rejected; `editor` permissions unchanged

**PV-03: member_permission override rejects unknown permission**

- Given: `permissions` table does not contain `fake.perm`
- When: `alice` calls `grant_member_permission(G, dave, 'fake.perm')`
- Then: DENY — permission not found in registry

**PV-04: Role names are validated against the roles table**

- Given: `roles` table does not contain `superadmin`
- When: `alice` calls `add_member(G, eve, ['superadmin'])`
- Then: DENY — role not found in roles table

**PV-05: update_member_roles validates all roles in the array**

- Given: `roles` table contains `editor`, `viewer` but not `superadmin`
- When: `alice` calls `update_member_roles(G, eve, ['editor', 'superadmin'])`
- Then: DENY — entire operation rejected

**PV-06: grantable_roles values are validated against roles table**

- Given: `roles` table does not contain `moderator`
- When: app author calls sets `admin.grantable_roles = ['editor', 'moderator']`
- Then: DENY — `moderator` is not a defined role (note: `'*'` is a special value and should be allowed)

**PV-07: Wildcard '\*' is accepted in grantable_roles**

- Given: app author sets `owner.grantable_roles = ['*']`
- Then: ALLOW — `'*'` is a recognized special value

---

## Invite System Security

**INV-01: Expired invite cannot be accepted**

- Given: invite with `expires_at = now() - interval '1 hour'`
- When: `eve` calls `accept_invite(invite_id)`
- Then: DENY — invite has expired

**INV-02: Already-accepted invite cannot be reused**

- Given: invite that `eve` already accepted
- When: `carol` calls `accept_invite(invite_id)`
- Then: DENY — invite already accepted

**INV-03: Invite with NULL expires_at never expires**

- Given: invite with `expires_at = NULL` created 1 year ago
- When: `eve` calls `accept_invite(invite_id)`
- Then: ALLOW

**INV-04: Invite acceptance is atomic (no partial state)**

- Given: valid invite for group G with `roles = ['editor', 'viewer']`
- When: `eve` calls `accept_invite(invite_id)`
- Then: `eve` is a member of G with exactly `['editor', 'viewer']`; invite is marked accepted; this happens in one transaction

**INV-05: Concurrent invite acceptance is race-condition safe**

- Given: valid invite for group G
- When: `eve` and `carol` both call `accept_invite(invite_id)` concurrently
- Then: exactly one succeeds; the other gets a "already accepted" error

**INV-06: accept_invite uses caller's auth.uid()**

- Given: valid invite
- When: `eve` calls `accept_invite(invite_id)`
- Then: the membership is created for `eve`'s user_id, not a spoofable parameter

**INV-07: Invite roles are validated against roles table at acceptance time**

- Given: invite created with `roles = ['editor']`; app author deletes `editor` role before acceptance
- When: `eve` calls `accept_invite(invite_id)`
- Then: DENY — `editor` no longer exists in roles table

---

## Auth Hook Security

**AH-01: Auth hook reads from user_claims, not from members directly**

- Given: `custom_access_token_hook` is registered
- When: `alice` authenticates and a token is created
- Then: JWT `app_metadata.groups` matches `rbac.user_claims` content for `alice`

**AH-02: Auth hook returns empty groups for groupless user**

- Given: `eve` has no group memberships
- When: `eve` authenticates
- Then: JWT `app_metadata.groups` is `{}` or absent; no error

**AH-03: Auth hook does not crash on malformed claims**

- Given: `rbac.user_claims` for `alice` is somehow corrupted (e.g., NULL claims)
- When: `alice` authenticates
- Then: JWT is issued with empty/absent groups; no 500 error

---

## Edge Cases & Boundary Conditions

**EC-01: User removed from all groups has empty claims**

- Given: `eve` was a member of G1 and G2; removed from both
- When: inspecting `rbac.user_claims` for `eve`
- Then: claims = `{}`

**EC-02: Adding a member with empty roles array**

- Given: `alice` calls `add_member(G, eve, '{}')`
- When: inspecting `eve`'s membership
- Then: `eve` is a member with `roles = []`, `is_member(G)` returns true, `has_role(G, anything)` returns false

**EC-03: Self-removal from a group**

- Given: `alice` is `owner` of group G; RLS allows members to remove themselves
- When: `alice` calls `remove_member(G, alice)`
- Then: depends on RLS policy; if allowed, `alice` is removed and group may become ownerless (this is a documented risk, not prevented by the extension)

**EC-04: create_group with custom creator roles**

- Given: `alice` calls `create_group('Test', '{}', ['admin', 'viewer'])` instead of default `['owner']`
- When: inspecting the created membership
- Then: `alice` has `roles = ['admin', 'viewer']` (not `owner`); all specified roles must exist and the creator role set is not subject to escalation checks (the caller is creating a new group they own)

**EC-05: Duplicate role in assignment array is deduplicated**

- Given: `alice` calls `add_member(G, eve, ['viewer', 'viewer'])`
- Then: `eve` has `roles = ['viewer']` (deduplicated)

**EC-06: grant_member_permission is idempotent**

- Given: `eve` already has override `data.read` in group G
- When: `alice` calls `grant_member_permission(G, eve, 'data.read')`
- Then: no error; no duplicate row; override still exists

**EC-07: Very large number of groups per user**

- Given: `alice` is a member of 100 groups
- When: inspecting `rbac.user_claims` for `alice`
- Then: claims contain 100 group entries; `db_pre_request` and `get_claims()` function correctly

**EC-08: Very large number of members per group**

- Given: group G has 1000 members
- When: role definition change triggers claims rebuild for all 1000 members
- Then: all claims are rebuilt correctly (may be slow, but not incorrect)

---

## Role-Based Bypass Behavior

**RB-01: service_role bypasses all escalation checks**

- Given: `service` role
- When: `service` calls `add_member(G, eve, ['owner'])`
- Then: ALLOW — service_role is not subject to grantable_roles checks

**RB-02: service_role bypasses RLS**

- Given: deny-all RLS on all tables
- When: `service` performs direct SELECT on `rbac.members`
- Then: ALLOW — service_role bypasses RLS

**RB-03: postgres superuser bypasses everything**

- Given: `superuser` role
- When: `superuser` performs any operation
- Then: ALLOW

**RB-04: anon gets false from all RLS helpers**

- Given: `anon_user`
- When: calling `is_member(G)`, `has_role(G, 'owner')`, `has_permission(G, 'data.read')`
- Then: all return false

**RB-05: Expired JWT raises invalid_jwt from RLS helpers**

- Given: authenticated user with an expired JWT
- When: calling `has_role(G, 'owner')`
- Then: raises `invalid_jwt` error

**RB-06: RLS helpers return true for service_role regardless of membership**

- Given: `service` role, not a member of group G
- When: calling `has_role(G, 'owner')`
- Then: returns true (superuser bypass)
