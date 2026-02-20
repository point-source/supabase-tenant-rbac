# Security Model

## Design Principles

### 1. Deny-All by Default
All three core tables (`groups`, `group_users`, `group_invites`) have RLS enabled with **no policies** on install. Every operation is rejected until the database administrator explicitly adds policies. This means a misconfigured or half-configured install fails closed (too restrictive) rather than open (too permissive).

### 2. Fresh Claims on Every Request
Rather than trusting potentially stale JWT claims, `db_pre_request()` reads `auth.users.raw_app_meta_data` directly on every PostgREST API request. This means:
- Role changes take effect immediately (no waiting for JWT expiry)
- Revoked access cannot be bypassed with an old JWT
- There is a small per-request DB query cost (typically negligible)

### 3. Schema Isolation
All functions use `SET search_path = @extschema@` (never hardcoded `public`). This prevents search_path injection attacks where a malicious user creates a same-named function in a publicly-writable schema.

### 4. Minimal SECURITY DEFINER Surface
Only two functions are `SECURITY DEFINER`:
- `db_pre_request()` — needs to read `auth.users` (privileged table)
- `update_user_roles()` — needs to write `auth.users.raw_app_meta_data` (privileged table)

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

### No ON DELETE CASCADE

**Risk level: Medium**

Foreign keys from `group_users` and `group_invites` to `groups` do not cascade deletes. Deleting a group:
- Does NOT delete `group_users` rows → orphaned memberships remain
- Does NOT trigger `update_user_roles` → roles persist in `auth.users.raw_app_meta_data`
- Users retain claims for the deleted group until their `group_users` rows are manually cleaned up

**Workaround**: Manually delete `group_users` rows before deleting a group, or use a trigger/function to cascade the cleanup.

### Invite Codes Never Expire

**Risk level: Medium**

The `group_invites` table has no expiration column. Once created, an invite code remains valid indefinitely until it is accepted. A leaked invite code (e.g., sent via insecure email, logged accidentally) can be claimed by any authenticated user at any time in the future.

**Workaround**: Periodically audit and delete unused invite rows, or implement an application-layer expiry check.

### Inviter Permission Not Re-Checked at Acceptance

**Risk level: Low**

RLS controls who can create invites. However, once created, the invite is accepted by the edge function using the `service_role` key (bypasses RLS). If the inviter's permissions are revoked after creating an invite, the invite remains valid.

**Mitigation**: The edge function checks `user_id IS NULL AND accepted_at IS NULL` to prevent reuse, but does not re-verify inviter permissions.

### db_pre_request Does Not Cover Storage

**Risk level: Low-Medium (scope limitation)**

The `db_pre_request` hook runs in the PostgREST request pipeline only. Supabase Storage requests do not trigger this hook. This means:
- `request.groups` will be NULL during storage operations
- `get_user_claims()` falls back to the JWT claims (which may be stale)
- RLS policies on storage objects that use `user_has_group_role()` or `user_is_group_member()` will use potentially outdated claims

**Workaround**: For storage, rely on JWT-based claims (which are updated in `raw_app_meta_data` and included in new JWTs) rather than the fresh per-request approach. Accept a window of staleness equal to the JWT lifetime (default: 1 hour).

### Custom Schema Requires Manual Configuration

**Risk level: Low (configuration issue)**

When installed in a non-`public` schema (e.g., `CREATE EXTENSION ... schema rbac`), the `db_pre_request` hook registration uses an unqualified function name:
```sql
ALTER ROLE authenticator SET pgrst.db_pre_request TO 'db_pre_request';
```

PostgREST resolves this without a schema qualifier and may fail to find the function, causing every API request to fail. See [Issue #29](https://github.com/point-source/supabase-tenant-rbac/issues/29).

**Workaround**: After installing in a custom schema, manually run:
```sql
ALTER ROLE authenticator SET pgrst.db_pre_request TO 'your_schema.db_pre_request';
NOTIFY pgrst, 'reload config';
```

### Groupless User Crash

**Risk level: Medium (bug)**

Users who register via Supabase's standard signup flow (and have never been added to a group) have no `groups` key in their `raw_app_meta_data`. When `db_pre_request` runs for these users, it stores an empty value in `request.groups`. `get_user_claims()` then attempts to cast this as `jsonb` and fails with `invalid input syntax for type json`.

This means **any groupless authenticated user will receive a 500 error on every API request** if they hit a route where `db_pre_request` fires. See [Issue #37](https://github.com/point-source/supabase-tenant-rbac/issues/37) — targeted for fix in v4.1.0.

### User Deletion Trigger Crash

**Risk level: Medium (bug)**

Deleting a user in `auth.users` cascades to `group_users` (FK constraint). The `update_user_roles` trigger fires for each deleted `group_users` row and attempts to `UPDATE auth.users WHERE id = _user_id` — but the user no longer exists. This currently raises an error. See [Issue #11](https://github.com/point-source/supabase-tenant-rbac/issues/11) — targeted for fix in v4.1.0.

---

## Edge Function Security (`supabase/functions/invite/index.ts`)

| Aspect | Status | Notes |
|--------|--------|-------|
| JWT verification | Verified | Uses `djwt` with HMAC-SHA256 and `SB_JWT_SECRET` |
| Invite reuse prevention | Implemented | Checks `user_id IS NULL AND accepted_at IS NULL` |
| User identity | Verified | Extracts `user.sub` from the verified JWT |
| Service role usage | Expected | Uses service_role key to bypass RLS for the write operations |
| Invite expiry | **Not implemented** | Invites never expire — see limitation above |
| JWT logging on failure | **Bug** | Line 56 logs the raw token on verification failure (targeted for fix) |
| Inviter re-verification | **Not implemented** | Does not re-check inviter's permissions at acceptance time |

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
