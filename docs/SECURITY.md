# Security Model

## Design Principles

### 1. Deny-All by Default
All four tables (`groups`, `members`, `invites`, `roles`) have RLS enabled with **no policies** on install. Every operation is rejected until the database administrator explicitly adds policies. This means a misconfigured install fails closed (too restrictive) rather than open (too permissive).

### 2. Fresh Claims on Every Request
Rather than trusting potentially stale JWT claims, `db_pre_request()` reads `rbac.user_claims` directly on every PostgREST API request. This means:
- Role changes take effect immediately (no waiting for JWT expiry)
- Revoked access cannot be bypassed with an old JWT
- There is a small per-request DB query cost (typically negligible)

This freshness guarantee also applies to Supabase Storage. `get_claims()` falls back to `_get_user_groups()` (which reads `rbac.user_claims` directly) rather than the JWT, so Storage RLS policies always see current data.

The `custom_access_token_hook` provides a complementary path: it embeds claims in JWTs at token creation. JWT claims may become stale if membership changes without a new token, but the db_pre_request path always prevails for API requests.

### 3. Private Schema Isolation
Tables live in a private schema (e.g. `rbac`) that is NOT in PostgREST's `db_schemas`. This means:
- Tables cannot be accessed directly via REST API
- All interaction goes through RPC functions
- Reduces attack surface from direct table manipulation

All functions use `SET search_path = @extschema@` to prevent search_path injection.

### 4. Role Validation
All management RPCs (`create_group`, `add_member`, `update_member_roles`, `accept_invite`) validate role assignments against the `roles` table. Free-text role strings from v4.x are replaced by a validated vocabulary.

### 5. Minimal SECURITY DEFINER Surface
Six functions are `SECURITY DEFINER`:
- `create_group()` — bootstraps membership when no prior RLS-satisfying row exists
- `accept_invite()` — writes invites + members atomically, bypassing RLS
- `_sync_member_metadata()` — trigger function that writes `rbac.user_claims`; runs as function owner (postgres) to avoid requiring `authenticated` INSERT/UPDATE on user_claims
- `_sync_member_permission()` — trigger function that writes `rbac.user_claims`; same rationale
- `_on_role_permissions_change()` — trigger function that writes `rbac.user_claims` for all affected users; same rationale
- `_validate_roles()` — internal helper that reads `rbac.roles.name` to validate a role array; made DEFINER (v5.2.1) so INVOKER management RPCs can validate roles without the caller needing SELECT on `rbac.roles`

The three trigger functions (`RETURNS trigger`) cannot be called directly via RPC or REST — only the database trigger mechanism can invoke them. SECURITY DEFINER on trigger functions does not expand the callable API surface. Similarly, `_validate_roles` has `REVOKE EXECUTE FROM PUBLIC` — no external caller has EXECUTE on it.

All other functions are `SECURITY INVOKER`:
- `db_pre_request()` — reads `rbac.user_claims` (extension-owned, not privileged)
- `_get_user_groups()` — reads `rbac.user_claims` for the Storage fallback path
- `_build_user_claims()` — reads `members` + `roles`, builds claims JSONB (trigger helper; EXECUTE revoked from PUBLIC)
- `custom_access_token_hook()` — reads `rbac.user_claims` for JWT injection
- All RLS helpers (`has_role`, `is_member`, `has_any_role`, `has_all_roles`, `get_claims`, `has_permission`, `has_any_permission`, `has_all_permissions`)
- All management RPCs (`delete_group`, `add_member`, `remove_member`, `update_member_roles`, `list_members`, `create_invite`, `delete_invite`)

By moving the claims cache from `auth.users` to `rbac.user_claims` (v5.0.0) and making the three write triggers SECURITY DEFINER (v5.2.0), the `authenticated` role no longer needs INSERT/UPDATE on `user_claims`.

### 6. Internal Helpers Locked Down (v5.2.1)
All five `_`-prefixed internal helper functions have `REVOKE EXECUTE FROM PUBLIC`. Selective re-grants:
- `_get_user_groups()` → `authenticated, service_role` (Storage RLS fallback via `get_claims()`)
- `_jwt_is_expired()` → `authenticated, anon, service_role` (called by all RLS helpers)
- `_build_user_claims(uuid)` — no re-grant (DEFINER trigger functions only)
- `_validate_roles(text[])` — no re-grant (DEFINER itself; trigger-like internal use)
- `_set_updated_at()` — no re-grant (trigger mechanism only, returns `trigger`)

### 7. Role Definitions Hidden from Authenticated (v5.2.1)
`authenticated` has no table-level `SELECT` on `rbac.roles`. The role vocabulary (names, descriptions, `permissions[]` arrays) is an admin/migration concern, not end-user data. App-authors who want users to browse role definitions must explicitly opt in:
```sql
GRANT SELECT ON rbac.roles TO authenticated;
CREATE POLICY "Authenticated users can read roles"
    ON rbac.roles FOR SELECT TO authenticated USING (true);
```

---

## Auth Role Tiers

The permission-checking functions (`has_role`, `is_member`, `has_any_role`, `has_all_roles`, `has_permission`, `has_any_permission`, `has_all_permissions`) handle four distinct execution contexts:

| Context | `auth.role()` | `session_user` | Behavior |
|---------|---------------|----------------|----------|
| Authenticated user via API | `authenticated` | `authenticator` | Checks JWT expiry, then checks claims |
| Anonymous user via API | `anon` | `authenticator` | Always `false` |
| Trigger / superuser context | varies | `postgres` | Always `true` |
| Service role | `service_role` | varies | Always `true` |
| Other (e.g., `authenticator` direct) | other | other | Always `false` |

The `session_user = 'postgres'` and `service_role` bypasses allow triggers and server-side functions to operate without RBAC checks.

### JWT Expiry Check
Every claims-checking function calls `_jwt_is_expired()` first. If the JWT is expired or missing, an `invalid_jwt` exception is raised.

---

## SECURITY DEFINER Function Analysis (6 Functions)

### `db_pre_request()` — SECURITY INVOKER
- Runs as `authenticator` (the PostgREST session role).
- Reads `claims` from `rbac.user_claims` for `auth.uid()`.
- No privileged access needed — `rbac.user_claims` is an extension-owned table.
- **RPC access restricted**: EXECUTE revoked from PUBLIC, granted only to `authenticator`.

### `_sync_member_metadata()` — SECURITY DEFINER
- **Trigger-only**: Returns `trigger` type — cannot be called directly via API.
- Writes to `rbac.user_claims` (upsert). No `auth.users` access required.
- Runs as the function owner (`postgres`) regardless of which role fired the triggering DML.
- **Immutability enforcement**: Raises exception if `user_id` or `group_id` is changed on UPDATE.
- **Why DEFINER**: Allows the authenticated role to be stripped of INSERT/UPDATE on `user_claims`, closing the claims forgery vector (any authenticated user could previously forge claims for any `user_id`).

### `_validate_roles()` — SECURITY DEFINER (v5.2.1)
- Reads `roles.name` from `rbac.roles` to validate a role name array.
- **Why DEFINER**: `authenticated` no longer has `SELECT` on `rbac.roles` (v5.2.1). DEFINER allows INVOKER management RPCs (`add_member`, `update_member_roles`, `create_invite`) to validate role names without requiring the caller to have table access.
- **EXECUTE revoked from PUBLIC**: No external caller has EXECUTE. Only DEFINER callers (the management RPCs, which call `_validate_roles` from within their bodies) can invoke it.
- **No side effects**: Reads only `roles.name`; no writes, no user-controllable output beyond the exception message listing undefined role names (which the caller already supplied).

### `_get_user_groups()` — SECURITY INVOKER
- Reads `claims` from `rbac.user_claims` for `auth.uid()`. Returns `'{}'` for unauthenticated/groupless users.
- Called by `get_claims()` when `request.groups` is not set (Storage fallback path).

### `custom_access_token_hook()` — SECURITY INVOKER
- Called by Supabase Auth at JWT creation time, runs as `supabase_auth_admin`.
- Reads `claims` from `rbac.user_claims` for `event.user_id`.
- Injects `app_metadata.groups` into the JWT claims.
- Per Supabase docs, auth hooks should not be SECURITY DEFINER.

### `create_group()`
- **Why DEFINER**: The caller has no existing membership, so no RLS policy on `members` can grant INSERT permission for the initial membership row.
- **Scope**: Creates one `groups` row and one `members` row for `auth.uid()`.
- **Identity binding**: Uses `auth.uid()` — cannot create groups on behalf of others.
- **Validates roles**: All roles in `creator_roles` must exist in the `roles` table.

### `accept_invite()`
- **Why DEFINER**: Must write to `invites` (update accepted status) and `members` (upsert membership) atomically. The user doesn't have group membership yet, so RLS on `members` would block the INSERT.
- **Identity binding**: Uses `auth.uid()` — cannot accept on behalf of others.
- **Atomicity**: `SELECT FOR UPDATE` locks the invite row; UPDATE + INSERT in same transaction.
- **RPC access restricted**: EXECUTE revoked from PUBLIC, granted only to `authenticated`.

---

## SECURITY INVOKER RPC Model

Member management RPCs (`delete_group`, `add_member`, `remove_member`, `update_member_roles`, `list_members`) are SECURITY INVOKER. They execute DML against `rbac.*` tables as the calling role (`authenticated`).

Role and permission management RPCs (`create_role`, `delete_role`, `list_roles`, `set_role_permissions`, `grant_permission`, `revoke_permission`, `list_role_permissions`) are **service_role only** — app-author operations intended for migrations and admin tooling, not end-user API calls.

This means:
- The `authenticated` role needs DML grants on `rbac.*` tables (shipped by the extension)
- RLS policies on `rbac.*` tables control which rows are accessible
- Consumers define their authorization model via RLS policies

Example: An `add_member()` call succeeds only if the caller satisfies the INSERT policy on `rbac.members` (e.g., must be an owner of the group).

---

## Claims Cache Write Protection

### Why `authenticated` does not write to `user_claims` (v5.2.0+)

Prior to v5.2.0, the three trigger functions that maintain `user_claims` were SECURITY INVOKER. When fired by `add_member()` or other INVOKER RPCs, the trigger ran as `authenticated`. This meant `authenticated` needed INSERT/UPDATE on `user_claims` — and those table-level grants, combined with the required RLS policies (`WITH CHECK (true)`), allowed **any authenticated user to forge claims for any `user_id`** by directly calling `INSERT INTO rbac.user_claims ...`.

As of v5.2.0, all three trigger functions are SECURITY DEFINER:
- `_sync_member_metadata()`
- `_sync_member_permission()`
- `_on_role_permissions_change()`

They run as the function owner (`postgres`) regardless of which role triggers the DML on `members`, `member_permissions`, or `roles`. The `authenticated` table grant is reduced to SELECT-only. No INSERT/UPDATE RLS policies on `user_claims` are needed or recommended.

**Trigger functions cannot be called via REST or RPC** — only the database trigger mechanism can invoke them. Making them SECURITY DEFINER does not expand the callable API surface.

### Migration steps for existing deployments (5.1.0 → 5.2.0)

1. Apply the upgrade script: `supabase_rbac--5.1.0--5.2.0.sql`
2. Drop the no-longer-needed RLS policies:
   ```sql
   DROP POLICY IF EXISTS "authenticated can insert claims (trigger)" ON rbac.user_claims;
   DROP POLICY IF EXISTS "Allow authenticated to insert claims" ON rbac.user_claims;
   DROP POLICY IF EXISTS "authenticated can update claims (trigger)" ON rbac.user_claims;
   DROP POLICY IF EXISTS "Allow authenticated to update claims" ON rbac.user_claims;
   ```
3. Verify no INSERT/UPDATE policies remain on `rbac.user_claims` for `authenticated`.

---

## PostgREST Schema Exposure

**Never add `rbac` (or whatever schema you installed the extension in) to PostgREST's `db_schemas`.**

If `rbac` is listed in `db_schemas`, PostgREST will expose all `rbac.*` tables directly as REST endpoints, bypassing the RPC-only access model. Even with RLS enabled, direct table access via REST is a significantly larger attack surface than the RPC model.

The extension's management RPCs (`create_group`, `add_member`, etc.) and RLS helpers (`has_role`, `has_permission`, etc.) are the intended API surface. If you need PostgREST to discover these functions, use the opt-in public wrappers (`examples/setup/create_public_wrappers.sql`), which live in `public` (or another exposed schema) and delegate to the private `rbac.*` originals.

---

## Known Security Considerations

### Direct Member Permission Override Escalation

**Risk level: Low — same as role assignment; mitigated by RLS**

`grant_member_permission()` is SECURITY INVOKER and relies on RLS policies on `member_permissions` to enforce who can grant overrides. If you create a policy that allows group admins to write to `member_permissions`, **nothing in the extension prevents an admin from granting a permission they do not hold themselves** (e.g., granting `data.export` without having that permission).

**Mitigation**: Scope your write policy to users who have a specific management permission (e.g., `group.manage_access`). If escalation prevention is critical, add a `BEFORE INSERT` trigger on `member_permissions` that validates the granted permission against the granting user's own permissions.

### Cross-Group Permission Grant

**Risk level: None — blocked at two independent layers**

An authenticated user with `group.manage_access` in Group A **cannot** use `grant_member_permission()` or `revoke_member_permission()` to write permission overrides in Group B.

**Layer 1 — in-function guard**: Both RPCs call `is_member(p_group_id)` before any DML. If the caller is not a member of the target group, an `insufficient_privilege` exception is raised immediately — before RLS is evaluated and before the INSERT/DELETE is attempted. `is_member()` returns `true` for `postgres` and `service_role` so backend callers are unaffected.

**Layer 2 — RLS WITH CHECK**: Even if the in-function guard were bypassed (e.g., via a future `CREATE OR REPLACE`), the consumer's write policy (`has_permission(group_id, 'group.manage_access')`) checks the target group's `group_id` column, not the caller's home group. A cross-group write would fail the WITH CHECK constraint.

**FK as join-guard**: `member_permissions` has a composite FK to `members(group_id, user_id)`. A permission cannot be granted to a `(group_id, user_id)` pair that does not exist in `members` — so this table cannot be used to create memberships.

### `request.groups` is a Trusted Session Variable

**Risk level: Low — requires a consumer to create a vulnerable function**

`get_claims()` reads the `request.groups` session config key, which is set by `db_pre_request()`. Any PostgreSQL function can overwrite this key using `set_config('request.groups', ...)`. If a consumer creates an RPC function that writes user-controlled input to `request.groups`, an end user could spoof their group membership.

**Mitigation**: Never write a function that passes user input to `set_config('request.groups', ...)`.

### Role Permissions Change Trigger Cost

**Risk level: Informational — no security impact**

When `set_role_permissions()`, `grant_permission()`, or `revoke_permission()` changes a role's `permissions[]`, the `on_role_permissions_change` trigger rebuilds claims for every user holding that role. For widely-assigned roles (e.g., a `viewer` role held by thousands of users), this is an O(N) write operation.

**Mitigation**: Permission changes are admin/migration operations, not per-request operations. Run them during low-traffic windows for large deployments. The WHEN condition (`OLD.permissions IS DISTINCT FROM NEW.permissions`) ensures the trigger only fires when permissions actually change, not on every role UPDATE.

### Inviter Permission Not Re-Checked at Acceptance

**Risk level: Low**

Once an invite is created, `accept_invite()` validates the invite itself but does not re-verify the inviter's current permissions. If the inviter's access is revoked after creating an invite, the invite remains valid.

**Mitigation**: Set `expires_at` on sensitive invites. Delete invites when revoking access.

---

## Edge Function Security (`supabase/functions/invite/index.ts`)

The edge function is a thin HTTP wrapper. All invite validation, atomicity, and identity enforcement live in the `accept_invite()` database function.

| Aspect | Status | Notes |
|--------|--------|-------|
| JWT verification | Delegated to database | User's JWT forwarded to RPC; PostgREST verifies it |
| User identity | Enforced by `auth.uid()` | From verified JWT, not caller-supplied |
| Invite reuse prevention | Implemented | `SELECT FOR UPDATE` + `user_id IS NULL AND accepted_at IS NULL` |
| Atomicity | Implemented | UPDATE invite + UPSERT member in single transaction |
| Service role usage | Not required | Edge function uses user's own JWT |
| Invite expiry | Implemented | `expires_at` checked; null means no expiry |
| Role validation | Implemented | Invite roles validated against `roles` table on acceptance |
