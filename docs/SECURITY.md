# Security Model

## Design Principles

### 1. Deny-All by Default
All three core tables (`groups`, `group_users`, `group_invites`) have RLS enabled with **no policies** on install. Every operation is rejected until the database administrator explicitly adds policies. This means a misconfigured or half-configured install fails closed (too restrictive) rather than open (too permissive).

### 2. Fresh Claims on Every Request
Rather than trusting potentially stale JWT claims, `db_pre_request()` reads `auth.users.raw_app_meta_data` directly on every PostgREST API request. This means:
- Role changes take effect immediately (no waiting for JWT expiry)
- Revoked access cannot be bypassed with an old JWT
- There is a small per-request DB query cost (typically negligible)

As of v4.3.0, this freshness guarantee also applies to Supabase Storage. `get_user_claims()` falls back to `_get_user_groups()` (a SECURITY DEFINER helper that reads `auth.users` directly) rather than the JWT, so Storage RLS policies using `user_has_group_role()` or `user_is_group_member()` always see current data.

### 3. Schema Isolation
All functions use `SET search_path = @extschema@` (never hardcoded `public`). This prevents search_path injection attacks where a malicious user creates a same-named function in a publicly-writable schema.

### 4. Minimal SECURITY DEFINER Surface
Four functions are `SECURITY DEFINER`:
- `db_pre_request()` — needs to read `auth.users` (privileged table)
- `update_user_roles()` — needs to write `auth.users.raw_app_meta_data` (privileged table)
- `_get_user_groups()` *(v4.3.0)* — needs to read `auth.users` for the Storage fallback path
- `accept_group_invite()` *(v4.4.0)* — needs to write `group_invites` and `group_users` atomically, bypassing RLS

All other functions (`user_has_group_role`, `user_is_group_member`, `get_user_claims`, `jwt_is_expired`) are `SECURITY INVOKER` and run with the calling user's permissions.

---

## Auth Role Tiers

The permission-checking functions (`user_has_group_role`, `user_is_group_member`) handle four distinct execution contexts:

| Context | `auth.role()` | `session_user` | Behavior |
|---------|---------------|----------------|----------|
| Authenticated user via API | `authenticated` | `authenticator` | Checks JWT expiry, then checks claims |
| Anonymous user via API | `anon` | `authenticator` | Always `false` |
| Trigger / superuser context | varies | `postgres` | Always `true` |
| Other (e.g., `authenticator` direct) | other | other | Always `false` |

The `session_user = 'postgres'` bypass allows triggers and server-side functions that run with superuser privileges to perform operations without RBAC checks blocking them. This is intentional and expected.

### JWT Expiry Check
Every claims-checking function calls `jwt_is_expired()` first. If the JWT is expired or missing, an `invalid_jwt` exception is raised. This prevents expired tokens from being used to access resources.

---

## SECURITY DEFINER Function Analysis

### `db_pre_request()`
```sql
CREATE FUNCTION db_pre_request() RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = @extschema@
```

- **Why SECURITY DEFINER**: Must read `auth.users` which is only accessible to privileged roles.
- **Scope of elevated privilege**: Only reads `raw_app_meta_data->'groups'` for `auth.uid()` (the calling user's own data).
- **Cannot be abused to read other users' data** since `auth.uid()` is always the authenticated user's ID.
- **`set_config` scope**: Uses `false` for `is_local`, meaning the config persists for the session rather than just the transaction. In Supabase's PostgREST setup, sessions are reset between requests, so this is safe in practice.
- **RPC access restricted** *(v4.4.0)*: `EXECUTE` is revoked from `PUBLIC` and granted only to `authenticator`. End users (anon/authenticated) receive a permission-denied error if they attempt to call this via `/rest/v1/rpc/db_pre_request`. The PostgREST pre-request hook, which runs as `authenticator`, is unaffected.

### `update_user_roles()`
```sql
CREATE FUNCTION update_user_roles() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path TO @extschema@
```

- **Why SECURITY DEFINER**: Must write to `auth.users.raw_app_meta_data` which requires elevated privileges.
- **Trigger-only**: Returns `trigger` type — cannot be called directly via the API.
- **Bounded by RLS on `group_users`**: The trigger only fires when `group_users` is modified. Since `group_users` has RLS enabled, only authorized mutations reach this trigger.
- **Immutability enforcement**: Raises an exception if `user_id` or `group_id` is changed on an existing row, preventing indirect privilege manipulation.

### `_get_user_groups()` *(v4.3.0)*
```sql
CREATE FUNCTION _get_user_groups() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = @extschema@
```

- **Why SECURITY DEFINER**: Must read `auth.users` which is only accessible to privileged roles.
- **Scope of elevated privilege**: Only reads `raw_app_meta_data->'groups'` for `auth.uid()` (the calling user's own data). Returns `'{}'` for unauthenticated/groupless users.
- **Used exclusively as a fallback** in `get_user_claims()` when `request.groups` is not set (Storage path). PostgREST requests continue to use `db_pre_request`-populated session config.
- **Leading underscore naming** (`_get_user_groups`) signals this is an internal implementation detail, not a public API.

### `accept_group_invite(p_invite_id uuid)` *(v4.4.0)*
```sql
CREATE FUNCTION accept_group_invite(p_invite_id uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = @extschema@
```

- **Why SECURITY DEFINER**: Must write to `group_invites` and `group_users` atomically in a single transaction, bypassing RLS on those tables. RLS on `group_invites` would otherwise prevent the user from updating a row they don't own.
- **Identity binding**: Uses `auth.uid()` (not a caller-supplied parameter) to identify the accepting user. A caller cannot accept an invite on behalf of another user.
- **Atomicity**: `SELECT FOR UPDATE` locks the invite row, then `UPDATE` and `INSERT` execute in the same transaction. If either write fails, both are rolled back.
- **RPC access restricted**: `EXECUTE` is revoked from `PUBLIC` and granted only to `authenticated`. Anon callers receive a permission-denied error before the function body executes.

---

## Known Security Limitations

### Role Assignment is Unconstrained

**Risk level: Medium-High (design trade-off)**

The `role` column in `group_users` is free-text with no constraints. Any user who can write to `group_users` (per RLS policy) can assign any role string — including roles they do not themselves possess, and including assigning roles to themselves.

**Example scenario**: A user with `group_user.create` permission can INSERT:
```sql
INSERT INTO group_users (group_id, user_id, role)
VALUES ('<group-id>', auth.uid(), 'group.delete');
```

This self-assigns a `group.delete` permission they weren't supposed to have.

**Mitigation options** (for consumers to implement in their RLS `WITH CHECK` clauses):
```sql
-- Example: restrict which roles can be assigned in a WITH CHECK clause
-- Only allow assigning roles that the inserting user also holds
WITH CHECK (
    user_has_group_role(group_id, role)  -- must have the role yourself to assign it
)
```

Or use an allowlist of valid role strings enforced via a CHECK constraint or trigger.

The core extension intentionally does NOT impose restrictions here because role naming is application-specific. This is a documented responsibility of the consumer.

### `request.groups` is a Trusted Session Variable

**Risk level: Low — requires a consumer to create a vulnerable function**

`get_user_claims()` reads the `request.groups` session config key, which is set by `db_pre_request()` at the start of each PostgREST request. Any PostgreSQL function — including ones written by consumers — can overwrite this key using `set_config('request.groups', ...)`. If a consumer creates an RPC function that writes user-controlled input to `request.groups`, an end user could spoof their own group membership for the duration of that request and bypass RBAC.

In a standard Supabase/PostgREST deployment, end users **cannot exploit this directly**: `set_config` lives in `pg_catalog` (not the `public` schema), so it is not exposed as an RPC endpoint, and PostgREST parameterizes all table-endpoint input. The risk materialises only if a consumer writes a vulnerable function.

**Mitigation**: Never write an RPC function (or any function reachable by end users) that accepts user-supplied input and passes it to `set_config('request.groups', ...)`. Treat `request.groups` as an internal variable owned exclusively by `db_pre_request()`.

A future major version may remove the `request.groups` fast path in favour of always calling `_get_user_groups()` directly, which would eliminate this concern entirely.

### Inviter Permission Not Re-Checked at Acceptance

**Risk level: Low**

RLS controls who can create invites. However, once created, the invite is accepted via the `accept_group_invite()` SECURITY DEFINER function (which bypasses RLS). If the inviter's permissions are revoked after creating an invite, the invite remains valid until it is manually deleted or expires.

**Mitigation**: `accept_group_invite()` checks `user_id IS NULL AND accepted_at IS NULL` to prevent reuse, but does not re-verify the inviter's current permissions. Set an `expires_at` on sensitive invites and delete them explicitly when access is revoked.

---

## Edge Function Security (`supabase/functions/invite/index.ts`)

As of v4.4.0, the edge function is a thin HTTP wrapper. All invite validation, atomicity, and identity enforcement live in the `accept_group_invite()` database function.

| Aspect | Status | Notes |
|--------|--------|-------|
| JWT verification | Delegated to database | User's JWT is forwarded to the RPC call; PostgREST verifies it and `auth.uid()` binds identity |
| User identity | Enforced by `auth.uid()` | Identity comes from the verified JWT, not a caller-supplied parameter — users cannot accept on behalf of others |
| Invite reuse prevention | Implemented | `SELECT FOR UPDATE` + `user_id IS NULL AND accepted_at IS NULL` check inside `accept_group_invite()` |
| Atomicity | Implemented *(v4.4.0)* | `UPDATE group_invites` and `INSERT group_users` execute in a single transaction; partial failure is impossible |
| Service role usage | Removed *(v4.4.0)* | Edge function now uses the user's own JWT; no service role key required |
| Invite expiry | Implemented *(v4.2.0)* | `expires_at` checked inside `accept_group_invite()`; null means no expiry |
| Inviter re-verification | Not implemented | Does not re-check inviter's permissions at acceptance time |

---

## Example Security-Hardened RLS

For consumers who want to mitigate the role escalation risk:

```sql
-- Restrict group_user.create to only assign roles the creator already holds
CREATE POLICY "Users can only assign roles they possess"
ON group_users
FOR INSERT
TO authenticated
WITH CHECK (
    user_has_group_role(group_id, role)
    AND user_has_group_role(group_id, 'group_user.create')
);
```

This ensures a user cannot grant roles they don't already have.
