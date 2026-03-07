# Supabase Tenant RBAC v5.x.x — Design Goals & Specification

## Table of Contents

1. [Executive Summary](#executive-summary)
   - [Product Overview](#product-overview)
   - [Target Audience](#target-audience)
   - [Core Value Proposition](#core-value-proposition)
   - [Motivation for v5](#motivation-for-v5)
   - [Design Philosophy](#design-philosophy)
2. [Conceptual Model](#conceptual-model)
   - [Three-Tier Authority Model](#three-tier-authority-model)
   - [Entity Relationships](#entity-relationships)
   - [ORBAC Alignment](#orbac-alignment)
   - [The Permissions Vocabulary](#the-permissions-vocabulary)
   - [Grantable Roles & Escalation Prevention](#grantable-roles--escalation-prevention)
   - [Claims Caching Strategy](#claims-caching-strategy)
3. [Functional Requirements](#functional-requirements)
   - [Core Entities (Tables)](#core-entities-tables)
   - [Management RPCs](#management-rpcs)
   - [RLS Helper Functions](#rls-helper-functions)
   - [Invite System](#invite-system)
   - [Auth Hook (Optional)](#auth-hook-optional)
   - [db_pre_request Hook](#db_pre_request-hook)
4. [Security Requirements](#security-requirements)
   - [Privilege Escalation Prevention](#privilege-escalation-prevention)
   - [SECURITY DEFINER Audit](#security-definer-audit)
   - [Deny-All by Default](#deny-all-by-default)
   - [Private Schema Architecture](#private-schema-architecture)
   - [Storage RLS Freshness](#storage-rls-freshness)
   - [Known Limitations & Documented Risks](#known-limitations--documented-risks)
5. [Architecture Decisions](#architecture-decisions)
   - [Claims in user_claims vs. raw_app_meta_data](#claims-in-user_claims-vs-raw_app_meta_data)
   - [Write-Time Resolution](#write-time-resolution)
   - [Global Roles and Permissions](#global-roles-and-permissions)
   - [Future: Per-Group Custom Roles](#future-per-group-custom-roles)
6. [Distribution & Installation](#distribution--installation)
   - [Primary: dbdev Migrations](#primary-dbdev-migrations)
   - [Secondary: Manual SQL Migrations](#secondary-manual-sql-migrations)
   - [Upgrade Path from v4.x](#upgrade-path-from-v4x)
7. [Documentation Plan](#documentation-plan)
   - [Document Structure](#document-structure)
   - [Target Reader](#target-reader)
   - [README Scope](#readme-scope)
8. [Implementation Roadmap](#implementation-roadmap)
   - [v5.0.0: Must-Have](#v500-must-have)
   - [v5.x.x: Near-Term Enhancements](#v5xx-near-term-enhancements)
   - [Future: Beyond v5](#future-beyond-v5)
9. [Resolved Design Decisions](#resolved-design-decisions)

---

## Executive Summary

### Product Overview

Supabase Tenant RBAC is a PostgreSQL TLE (Trusted Language Extension) that provides role-based access control for single- and multi-tenant Supabase projects. It allows application authors to define groups (tenants/organizations), roles, and permissions, and provides the machinery for managing membership, enforcing access policies via RLS, and keeping authorization state fresh across all request types.

### Target Audience

**Primary:** The author (point-source), for use in personal Supabase projects.

**Secondary:** The growing community of Supabase developers building single- or multi-tenant applications who need RBAC beyond what Supabase provides natively. These users range from RBAC-experienced developers who need a Supabase-native solution to developers new to RBAC who need guidance on the concepts alongside the tooling.

### Core Value Proposition

1. **Group-scoped RBAC that Supabase doesn't provide out of the box.** The official Supabase RBAC docs cover single-tenant role assignment but not the tenant → role → permission hierarchy that SaaS applications need. Works for single-tenant apps (one group, restrict creation via deny-all RLS) and multi-tenant apps (many groups, opt-in INSERT policy on `rbac.groups`).
2. **Immediate claim freshness.** Unlike JWT-only approaches where revoked access persists until token expiry, claim changes take effect on the next API request.
3. **Secure by default.** Deny-all RLS, private schema, minimal SECURITY DEFINER surface, and built-in privilege escalation prevention.
4. **Mechanism, not policy.** The extension provides the RBAC engine and helpers; the app author writes the policies that fit their application.

### Motivation for v5

The v5 rewrite was triggered by the convergence of several pressures:

1. **Community confusion** about the conceptual model — users struggled to understand the relationship between groups, roles, and permissions in a tenant → role → permission architecture.
2. **Security realization** that defaulting to the `public` schema exposed internal tables to the PostgREST API.
3. **Supabase platform changes** — the addition of auth hooks and tightening of security on `auth.users`, discouraging direct metadata manipulation.
4. **ORBAC discovery** — awareness of the Organization-Based Access Control model provided a formal framework to align the extension's architecture with.
5. **dbdev/TLE tooling changes** shifting toward generating migrations rather than an in-database package manager.
6. **Accumulated technical debt** from incremental v4.x patches that made a clean-slate rethink more productive than further iteration.

### Design Philosophy

- **Security over convenience.** When a design choice involves a tradeoff between security and ease of use, security wins. The extension should be hard to misconfigure into an insecure state.
- **Mechanism, not policy.** The extension provides the RBAC engine (tables, triggers, caching, helper functions). The app author provides the policy (RLS policies, role definitions, permission assignments). The extension does not dictate _what_ roles or permissions exist — it provides the infrastructure for defining and enforcing them.
- **Write-time resolution, read-time simplicity.** Expensive operations (permission resolution, grant scope computation) happen when memberships or role definitions change. RLS policy checks at query time are pure cache reads with no joins.
- **Deny-all by default.** Nothing works until the app author explicitly allows it. This is safer than shipping permissive defaults that users forget to tighten.
- **Minimal SECURITY DEFINER surface.** Only functions that _must_ bypass RLS (because the caller has no prior state to satisfy a policy) are SECURITY DEFINER. The only user-facing DEFINER function is `accept_invite`; `create_group` is INVOKER with an AFTER INSERT trigger (`_on_group_created`, DEFINER) handling the membership bootstrap. Everything else is SECURITY INVOKER.

---

## Conceptual Model

### Three-Tier Authority Model

The system defines three tiers of authority, each with distinct responsibilities:

| Tier                    | Actor                                                            | Capabilities                                                                                                                                                                       | Mechanism                                                                                                                          |
| ----------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| **App Author**          | `service_role` / `postgres`                                      | Defines the vocabulary: creates roles, creates permissions, assigns permissions to roles, sets `grantable_roles` on each role                                                      | `create_role()`, `create_permission()`, `set_role_permissions()`, direct SQL                                                       |
| **Group Administrator** | Authenticated user with appropriate roles/permissions in a group | Manages membership within the boundaries set by the app author: adds/removes members, assigns roles (within grantable scope), grants permission overrides (within grantable scope) | `add_member()`, `remove_member()`, `update_member_roles()`, `grant_member_permission()` — all subject to RLS and escalation checks |
| **Member**              | Authenticated user with membership in a group                    | Consumes permissions: can perform actions allowed by their roles and direct permission overrides                                                                                   | RLS policies using `has_role()`, `is_member()`, `has_permission()`, etc.                                                           |

This hierarchy is enforced structurally: the app author controls what exists (roles, permissions), group administrators control who has what (within the grantable scope), and members use what they've been given.

### Entity Relationships

```
permissions (registry)        roles (definitions)
    │                            │
    │  roles.permissions[] ──────┤
    │  (which perms a role       │  roles.grantable_roles[]
    │   grants its holders)      │  (which roles holders of
    │                            │   this role can assign)
    │                            │
    └──────────┬─────────────────┘
               │
               ▼
         groups (tenants)
               │
               ▼
     members (group_id, user_id, roles[])
               │
               ├── member_permissions (direct overrides)
               │
               ▼
     user_claims (cached: roles, permissions,
                  grantable_roles, grantable_permissions)
```

**Key relationships:**

- A **permission** is a string (e.g., `group_data.read`) registered in the `permissions` table by the app author. This is the canonical registry.
- A **role** is a named bundle of permissions, defined in the `roles` table by the app author. Roles also declare which other roles their holders can grant (`grantable_roles`).
- A **group** is a tenant/organization. Groups contain members.
- A **member** is a user's presence in a group, with one or more roles assigned.
- A **member_permission** is a direct permission override — granting a specific permission to a specific member without assigning a role. The permission must exist in the `permissions` table.
- **user_claims** is a cache table, automatically maintained by triggers. It contains the resolved state for each user: their roles, permissions, grantable_roles, and grantable_permissions per group. All RLS helpers and management RPCs read from this cache.

### ORBAC Alignment

The extension is inspired by the Organization-Based Access Control (ORBAC) model but does not strictly implement it. The mapping is:

| ORBAC Concept | Extension Concept | Notes                                                    |
| ------------- | ----------------- | -------------------------------------------------------- |
| Organization  | Group             | Direct mapping                                           |
| Role          | Role              | Direct mapping; global definitions, per-group assignment |
| Activity      | Permission        | Permissions are the actions that can be performed        |
| View          | (Not implemented) | ORBAC views (data scope) are left to RLS policies        |
| Context       | (Not implemented) | Contextual constraints are left to RLS policies          |

This is documented as "ORBAC-inspired" rather than "ORBAC-compliant." The extension provides the organizational and role layers; the app author implements view and context constraints through RLS policies on their application tables.

### The Permissions Vocabulary

All permissions in the system come from a single, authoritative source: the `permissions` table. This table is managed exclusively by the app author via `service_role`.

- **Roles** reference permissions from this table via `roles.permissions[]`. When a role is assigned to a member, the member gains those permissions.
- **Direct overrides** (`member_permissions`) also reference this table. An override grants a specific permission to a specific member without assigning a role.
- **Validation** is enforced at write time: assigning a permission (whether to a role or as an override) that does not exist in the `permissions` table is rejected.
- **Permission strings** follow a dot-notation convention (e.g., `group_data.read`, `members.assign_role`) but this is a convention, not a constraint. The extension treats permission strings as opaque identifiers.

### Grantable Roles & Escalation Prevention

Privilege escalation prevention is built into the extension, not left to the app author to implement.

**How it works:**

Each role in the `roles` table has a `grantable_roles text[]` column. This declares which other roles holders of this role are authorized to assign to other members. A special wildcard value `'*'` means "can grant any role, including roles added in the future."

When a member attempts to assign a role (via `add_member()` or `update_member_roles()`), the RPC checks the caller's cached `grantable_roles` for the target group. If the target role is not in the caller's grantable set, the operation is rejected.

**Cache fields:**

| Field                   | Source                                                                                                       | Purpose                                                    |
| ----------------------- | ------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------- |
| `roles`                 | `members.roles[]`                                                                                            | The member's assigned roles                                |
| `permissions`           | Union of `roles.permissions[]` for held roles + `member_permissions`                                         | What the member can do                                     |
| `grantable_roles`       | Union of `roles.grantable_roles[]` for held roles; `['*']` if any role has `'*'`                             | Which roles the member can assign                          |
| `grantable_permissions` | Union of `roles.permissions[]` for all roles in `grantable_roles`; `['*']` if grantable_roles contains `'*'` | Which permissions the member can grant as direct overrides |

All four fields are resolved at write time by `_build_user_claims()` and cached in `user_claims.claims`. The management RPCs read from the cache — no joins at enforcement time.

**For direct permission overrides:** `grant_member_permission()` checks the caller's `grantable_permissions`. If the target permission is not in the caller's grantable set, the operation is rejected. This means the grant scope for permissions is derived from the grant scope for roles — if you can grant the `editor` role, you can also directly grant any permission that `editor` holds.

**Pre-seeded default:** The `owner` role ships with `grantable_roles = ['*']`, so group creators can manage membership fully without additional configuration.

### Claims Caching Strategy

The claims cache (`user_claims` table) is the performance and correctness backbone of the extension.

**When the cache is rebuilt:**

- A row is inserted, updated, or deleted in `members` → `_sync_member_metadata()` trigger fires → `_build_user_claims()` rebuilds that user's claims
- A row is inserted, updated, or deleted in `member_permissions` → trigger fires → rebuilds affected user's claims
- `set_role_permissions()`, `grant_permission()`, or `revoke_permission()` modifies a role's permissions → rebuilds claims for all users holding that role
- `grantable_roles` is modified on a role → rebuilds claims for all users holding that role

**How claims are consumed:**

- **PostgREST requests:** `db_pre_request()` reads the user's row from `user_claims` and stores it in `request.groups`. All RLS helpers read from `request.groups`.
- **Supabase Storage requests:** `get_claims()` falls back to reading `user_claims` directly when `request.groups` is not set (because Storage bypasses `db_pre_request`).
- **Management RPCs:** Read `grantable_roles` and `grantable_permissions` from the cache to enforce escalation checks.
- **JWT (optional):** `custom_access_token_hook` reads `user_claims` at token-creation time and injects claims into `app_metadata.groups` for client-side use.

---

## Functional Requirements

### Core Entities (Tables)

All tables live in a private schema (e.g., `rbac`) not exposed via PostgREST. All access is via RPCs.

| Table                | Key Columns                                                                | Managed By                      | Purpose                                                  |
| -------------------- | -------------------------------------------------------------------------- | ------------------------------- | -------------------------------------------------------- |
| `permissions`        | `name` (PK), `description`                                                 | App author (`service_role`)     | Canonical registry of all permission strings             |
| `roles`              | `name` (PK), `description`, `permissions text[]`, `grantable_roles text[]` | App author (`service_role`)     | Role definitions with permission bundles and grant scope |
| `groups`             | `id`, `name`, `metadata`                                                   | `create_group()` RPC            | Tenants / organizations                                  |
| `members`            | `group_id`, `user_id`, `roles text[]`, `metadata`                          | Management RPCs                 | One row per user-group membership                        |
| `member_permissions` | `group_id`, `user_id`, `permission`                                        | `grant_member_permission()` RPC | Direct per-member permission overrides                   |
| `invites`            | `group_id`, `roles text[]`, `invited_by`, `expires_at`                     | RLS policies on invites table   | Invite codes for group membership                        |
| `user_claims`        | `user_id` (PK), `claims jsonb`                                             | Triggers (never write directly) | Cached resolved state per user                           |

### Management RPCs

| Function                     | DEFINER/INVOKER   | Escalation Check                                                    | Purpose                               |
| ---------------------------- | ----------------- | ------------------------------------------------------------------- | ------------------------------------- |
| `create_group()`             | INVOKER           | N/A (RLS INSERT policy on `groups` controls creation)               | Create group, add caller as owner     |
| `delete_group()`             | INVOKER           | N/A (RLS enforced)                                                  | Delete group and cascade              |
| `add_member()`               | INVOKER           | Yes — target roles must be in caller's `grantable_roles`            | Add user to group with roles          |
| `remove_member()`            | INVOKER           | N/A (RLS enforced)                                                  | Remove user from group                |
| `update_member_roles()`      | INVOKER           | Yes — target roles must be in caller's `grantable_roles`            | Replace a member's roles              |
| `list_members()`             | INVOKER           | N/A (RLS enforced)                                                  | List group members                    |
| `grant_member_permission()`  | INVOKER           | Yes — target permission must be in caller's `grantable_permissions` | Grant direct permission override      |
| `revoke_member_permission()` | INVOKER           | N/A (RLS enforced)                                                  | Revoke direct permission override     |
| `create_invite()`            | INVOKER           | Yes — invite roles must be in caller's `grantable_roles`            | Create an invite with specified roles |
| `accept_invite()`            | DEFINER           | N/A (invite roles set at creation)                                  | Accept invite, join group             |
| `create_role()`              | service_role only | N/A                                                                 | Define a new role                     |
| `delete_role()`              | service_role only | N/A                                                                 | Delete a role (fails if in use)       |
| `create_permission()`        | service_role only | N/A                                                                 | Register a new permission             |
| `delete_permission()`        | service_role only | N/A                                                                 | Delete a permission (fails if in use) |
| `set_role_permissions()`     | service_role only | N/A                                                                 | Replace a role's permissions          |
| `grant_permission()`         | service_role only | N/A                                                                 | Add a permission to a role            |
| `revoke_permission()`        | service_role only | N/A                                                                 | Remove a permission from a role       |

### RLS Helper Functions

All helpers return `true` for `service_role` and `postgres`, `false` for `anon`, and raise `invalid_jwt` for expired JWTs.

| Function                                       | Purpose                                            |
| ---------------------------------------------- | -------------------------------------------------- |
| `is_member(group_id)`                          | Is the user a member of this group?                |
| `has_role(group_id, role)`                     | Does the user hold this role in this group?        |
| `has_any_role(group_id, roles[])`              | Does the user hold at least one of these roles?    |
| `has_all_roles(group_id, roles[])`             | Does the user hold all of these roles?             |
| `has_permission(group_id, permission)`         | Does the user hold this permission?                |
| `has_any_permission(group_id, permissions[])`  | Does the user hold at least one?                   |
| `has_all_permissions(group_id, permissions[])` | Does the user hold all?                            |
| `get_claims()`                                 | Returns the full claims JSONB for the current user |

### Invite System

- Invites are rows in the `invites` table with a `group_id`, `roles[]`, optional `expires_at`, and `invited_by`.
- Invites are created by members with appropriate RLS policies (e.g., owners or users with an `invites.create` permission).
- Acceptance happens via `accept_invite()` RPC, which is SECURITY DEFINER (the acceptor has no prior membership).
- The RPC validates expiry, checks the invite hasn't been used, and atomically upserts the user into the group with the invite's roles.
- An edge function wrapper is provided for HTTP-based acceptance.

### Auth Hook (Optional)

`custom_access_token_hook` injects group claims from `user_claims` into `app_metadata.groups` in the JWT at token-creation time. This is **complementary** to `db_pre_request` — the hook provides convenient client-side access to claims, while `db_pre_request` guarantees freshness on every server-side API request.

### db_pre_request Hook

On every PostgREST API request, `db_pre_request()` reads the current user's row from `user_claims` and stores it in `request.groups`. All RLS helpers read from this request context. This ensures claim changes take effect immediately without waiting for JWT expiry.

---

## Security Requirements

### Privilege Escalation Prevention

**Requirement:** A member cannot assign a role they are not authorized to grant, and cannot grant a permission they are not authorized to delegate.

**Implementation:** Enforced in the management RPCs (`add_member`, `update_member_roles`, `grant_member_permission`) by checking the caller's cached `grantable_roles` and `grantable_permissions`. The grantable scope is defined by the app author on the `roles` table and resolved into the claims cache at write time.

**Wildcard:** Roles with `grantable_roles = ['*']` can grant any role and any permission. The pre-seeded `owner` role has this by default.

### SECURITY DEFINER Audit

Only 8 functions are SECURITY DEFINER:

1. `_on_group_created()` — AFTER INSERT trigger on `groups`; bootstraps creator membership (caller has no prior membership to satisfy RLS on `members`)
2. `accept_invite()` — caller has no prior membership to satisfy RLS
3. `_sync_member_metadata()` — internal trigger, not callable by users
4. `_sync_member_permission()` — internal trigger, not callable by users
5. `_on_role_definition_change()` — internal trigger, not callable by users
6. `_validate_roles()` — internal validation, DEFINER so INVOKER RPCs can check names without authenticated having SELECT on rbac.roles
7. `_validate_permissions()` — same rationale for rbac.permissions
8. `_validate_grantable_roles()` — same rationale for rbac.roles

All user-facing management RPCs (except `accept_invite`) are SECURITY INVOKER with RLS enforced. `create_group()` is also INVOKER — the `_on_group_created` trigger handles the bootstrap membership insert.

### Deny-All by Default

All extension tables have RLS enabled with zero policies. Nothing works until the app author adds policies. This includes group creation — `create_group()` is SECURITY INVOKER, so without an INSERT policy on `rbac.groups`, it is blocked by RLS. Single-tenant apps can omit this policy to prevent users from creating additional groups. The `examples/policies/quickstart.sql` provides a recommended starting point.

### Private Schema Architecture

All tables are created in a dedicated schema (e.g., `rbac`) that is not exposed via PostgREST. This prevents direct REST API access to internal tables. All interaction happens through RPCs, which can be optionally exposed to PostgREST via public wrapper functions.

### Storage RLS Freshness

Supabase Storage bypasses `db_pre_request`. The `get_claims()` function falls back to reading `user_claims` directly when `request.groups` is not set. This ensures Storage RLS policies using `has_role()`, `is_member()`, etc., always reflect the current state.

### Known Limitations & Documented Risks

- **No automated upgrade from v4.x.** Migration requires data export, extension drop, reinstall, and re-import.
- **Supabase logical backups** may not correctly restore the extension due to dependency ordering on `auth.users`. This is an upstream platform issue.
- **Role definitions are global, not per-group.** All groups share the same role vocabulary. Per-group custom roles are a future enhancement.
- **Permission strings are opaque.** The extension does not interpret dot-notation or hierarchies in permission strings — `group_data.read` and `group_data.*` are treated as independent strings.

---

## Architecture Decisions

### Claims in user_claims vs. raw_app_meta_data

**Decision:** Store claims in a dedicated `rbac.user_claims` table, not in `auth.users.raw_app_meta_data`.

**Rationale:**

- Supabase is tightening security on `auth.users` and discouraging direct metadata manipulation by extensions.
- A dedicated table gives the extension full control over the schema and lifecycle of claims data.
- Avoids conflicts with other extensions or application code that may also use `raw_app_meta_data`.
- Enables richer cache structure (roles, permissions, grantable_roles, grantable_permissions) without polluting the auth schema.

### Write-Time Resolution

**Decision:** Resolve permissions, grantable_roles, and grantable_permissions at write time (when memberships or role definitions change) and cache the results.

**Rationale:**

- RLS policy checks execute per-row and must be fast. Cache reads (JSONB key lookup) are O(1); joins against role and permission tables would be O(n) per check.
- The write path (membership changes, role definition changes) is infrequent relative to the read path (every API request, every row).
- The trigger-based rebuild ensures the cache is always consistent with the source tables.

### Global Roles and Permissions

**Decision:** Roles and permissions are global — shared across all groups. All groups use the same vocabulary.

**Rationale:**

- Simplicity: the app author defines the vocabulary once, and it applies everywhere.
- Security: the vocabulary is controlled by `service_role`, not by end users.
- Sufficient for the primary use case (personal projects and typical SaaS multi-tenancy).

### Future: Per-Group Custom Roles

**Decision:** Defer to a future version, but design the current schema to avoid blocking it.

**Planned approach:** A future `group_roles` table would allow group administrators to compose custom roles from the global `permissions` registry. These would sit alongside the global `roles` table, not replace it. The `permissions` table being a separate, canonical registry (rather than permissions being embedded only in `roles.permissions[]`) enables this without schema changes to existing tables.

**Constraint:** The v5.x schema must not require manual migration, significant RLS policy changes by users, or data loss when this feature is added.

---

## Distribution & Installation

### Primary: dbdev Migrations

dbdev now generates migrations for users outside the database. v5 targets this as the primary installation method. Users run `dbdev.install()` and create the extension in a dedicated schema.

### Secondary: Manual SQL Migrations

For users who prefer direct SQL, the versioned `.sql` files in the repository serve as standalone migrations.

### Upgrade Path from v4.x

There is no automated upgrade path from v4.x to v5.0.0. The changes are too extensive. Migration requires:

1. Exporting group/membership data from v4.x tables
2. Dropping the v4.x extension
3. Installing v5.0.0
4. Re-importing data into the new schema
5. Rewriting RLS policies to use new function names

A detailed migration guide is provided in `docs/MIGRATION_GUIDE.md`.

---

## Documentation Plan

### Document Structure

| Document                     | Purpose                                                                                     | Reader                                                    |
| ---------------------------- | ------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| **README.md**                | Concise entry point: what it is, install, quickstart, links to docs                         | Everyone                                                  |
| **docs/CONCEPTUAL_MODEL.md** | The "why": three-tier model, how roles/permissions/groups relate, grantable_roles, caching  | Developers new to RBAC or new to this extension           |
| **docs/ARCHITECTURE.md**     | The "how": tables, triggers, claims resolution, db_pre_request, auth hook, Storage fallback | Developers who want to understand internals or contribute |
| **docs/SECURITY.md**         | Threat model, escalation prevention, SECURITY DEFINER audit, known limitations              | Security-conscious developers, auditors                   |
| **docs/API_REFERENCE.md**    | Every RPC and helper with signatures, return types, required role, examples                 | Developers integrating the extension                      |
| **docs/MIGRATION_GUIDE.md**  | v4 → v5 migration procedure, breaking changes, data export/import                           | Existing v4 users upgrading                               |

### Target Reader

A Supabase developer who understands SQL and RLS basics but is not necessarily an RBAC expert. The conceptual model doc bridges the knowledge gap; the README gets them running without requiring it.

### README Scope

The README should be focused and scannable:

- What is this? (2-3 sentences)
- Install (copy-paste commands)
- Quickstart (create group, add member, write first policy)
- Links to detailed docs
- Comparison to official Supabase RBAC (brief, link to full doc)
- Examples index

The current README contains architectural explanations, full API reference, and extended examples that belong in the separate docs.

---

## Implementation Roadmap

### v5.0.0: Must-Have

| Feature                                                      | Status         | Notes                                                                             |
| ------------------------------------------------------------ | -------------- | --------------------------------------------------------------------------------- |
| Private schema architecture                                  | ✅ Implemented | Tables in `rbac` schema                                                           |
| Typed management RPCs                                        | ✅ Implemented | SECURITY INVOKER where possible                                                   |
| `user_claims` cache table                                    | ✅ Implemented | Replaces `raw_app_meta_data`                                                      |
| `db_pre_request` hook                                        | ✅ Implemented | Ensures freshness                                                                 |
| Storage RLS fallback                                         | ✅ Implemented | `get_claims()` reads `user_claims` directly                                       |
| `custom_access_token_hook`                                   | ✅ Implemented | Optional JWT injection                                                            |
| Invite system                                                | ✅ Implemented | With edge function wrapper                                                        |
| **`permissions` table**                                      | ✅ Implemented | Canonical registry with `_validate_permissions()` enforcement                     |
| **`grantable_roles` column on `roles`**                      | ✅ Implemented | Escalation prevention for role assignment                                         |
| **`grantable_roles` cached in `user_claims`**                | ✅ Implemented | Write-time resolution of grant scope                                              |
| **`grantable_permissions` cached in `user_claims`**          | ✅ Implemented | Derived from grantable_roles for override grants                                  |
| **Escalation checks in `add_member`, `update_member_roles`** | ✅ Implemented | Reject role assignments outside grantable scope                                   |
| **Escalation checks in `grant_member_permission`**           | ✅ Implemented | Reject permission grants outside grantable scope                                  |
| **Wildcard `'*'` support**                                   | ✅ Implemented | In grantable_roles; propagates to grantable_permissions                           |
| **Pre-seed `owner` with `grantable_roles = ['*']`**          | ✅ Implemented | Default for group creators                                                        |
| **Permission validation on `member_permissions`**            | ✅ Implemented | Override permissions must exist in `permissions` table                            |
| **Permission validation on `roles.permissions[]`**           | ✅ Implemented | Role permissions must exist in `permissions` table                                |
| **`create_invite()` RPC with escalation check**              | ✅ Implemented | Validate invite roles against creator's `grantable_roles`                         |
| **Symmetrical revocation checks**                            | ✅ Implemented | `revoke_member_permission()` checks `grantable_permissions`                       |
| **Documentation rewrite**                                    | ✅ Implemented | Split README into focused docs per documentation plan                             |

### v5.0.0: Also Implemented (promoted from near-term)

| Feature                                            | Status         | Notes                                               |
| -------------------------------------------------- | -------------- | --------------------------------------------------- |
| `create_permission()` / `delete_permission()` RPCs | ✅ Implemented | Service_role management of the permissions registry |
| CI test suite for escalation scenarios             | ✅ Implemented | 19 test files, 129 tests                            |

### v5.x.x: Near-Term Enhancements

| Feature                                       | Notes                       |
| --------------------------------------------- | --------------------------- |
| Per-operation example policies for all tables | Expand `quickstart.sql`     |

### Future: Beyond v5

| Feature                                                | Notes                                                                   |
| ------------------------------------------------------ | ----------------------------------------------------------------------- |
| Per-group custom roles                                 | Group admins compose roles from global permissions; `group_roles` table |
| Docs site                                              | If user base warrants it                                                |
| Permission hierarchy / wildcards in permission strings | e.g., `group_data.*` matching `group_data.read`                         |

---

## Resolved Design Decisions

The following questions were evaluated during the design review and resolved as follows:

### 1. Permission string wildcards

**Decision:** No wildcards. Permission strings are opaque for v5.

**Rationale:** Keeps the system simple and avoids edge cases around matching semantics. Users who want broad grants can assign all permissions explicitly to a role, or use the `'*'` wildcard on `grantable_roles` (which is a separate, well-scoped concept). Wildcard permission matching may be considered for a future version if demand warrants it.

### 2. Invite role escalation

**Decision:** Add a `create_invite()` RPC with escalation checks, consistent with the `add_member()` pattern.

**Rationale:** Without this, a member could create an invite with `roles = ['owner']` even if their `grantable_roles` only includes `['viewer']`. The `create_invite()` RPC validates the invite's roles against the creator's cached `grantable_roles` before inserting. This is consistent with all other write operations that involve role assignment going through managed RPCs with escalation checks. Direct INSERTs to the `invites` table remain blocked by deny-all RLS unless the app author explicitly allows them.

### 3. Cascading permission changes

**Decision:** No cascading. Changes to `grantable_roles` on a role definition are prospective only.

**Rationale:** Retroactive revocation would be surprising, potentially destructive, and would require tracking grant provenance (who assigned what). The app author is responsible for cleanup when they tighten grant scope. `service_role` can always perform direct revocations as needed. This must be clearly documented in the security documentation: "Changing `grantable_roles` on a role definition affects future grant operations only. Existing memberships and permission overrides are not retroactively revoked."

### 4. Revocation scope

**Decision:** Symmetrical with granting. `revoke_member_permission()` checks the caller's `grantable_permissions`, same as `grant_member_permission()`. `service_role` serves as the escape hatch for dangling permissions.

**Rationale:** Symmetry is cleaner and less surprising than allowing anyone with member-management RLS to revoke arbitrary permissions. If the app author tightens `grantable_roles` and existing overrides become unrevocable by normal members, `service_role` can clean them up. This is consistent with the "changes are prospective only" decision — the app author owns cleanup after policy changes.

### 5. Audit logging

**Decision:** Out of scope for v5. The security documentation will briefly mention `pgaudit` and note that triggers on `members` and `member_permissions` are the appropriate hook points for custom audit logging. No maintained example or guide will be provided.

**Rationale:** Audit logging adds a table, triggers on every write path, and ongoing maintenance burden. Enterprise users who need audit trails are well-resourced and can implement this themselves using standard PostgreSQL tooling.
