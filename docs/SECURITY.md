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
Only two functions are `SECURITY DEFINER`:
- `create_group()` — bootstraps membership when no prior RLS-satisfying row exists
- `accept_invite()` — writes invites + members atomically, bypassing RLS

All other functions are `SECURITY INVOKER`:
- `db_pre_request()` — reads `rbac.user_claims` (extension-owned, not privileged)
- `_get_user_groups()` — reads `rbac.user_claims` for the Storage fallback path
- `_sync_member_metadata()` — writes `rbac.user_claims` (trigger-only)
- `custom_access_token_hook()` — reads `rbac.user_claims` for JWT injection
- All RLS helpers (`has_role`, `is_member`, `has_any_role`, `has_all_roles`, `get_claims`)
- All management RPCs (`delete_group`, `add_member`, `remove_member`, `update_member_roles`, `list_members`)

By moving the claims cache from `auth.users` to `rbac.user_claims`, the three previously DEFINER functions no longer need elevated privileges to read or write `auth.users`.

---

## Auth Role Tiers

The permission-checking functions (`has_role`, `is_member`, `has_any_role`, `has_all_roles`) handle four distinct execution contexts:

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

## SECURITY DEFINER Function Analysis

### `db_pre_request()` — SECURITY INVOKER
- Runs as `authenticator` (the PostgREST session role).
- Reads `claims` from `rbac.user_claims` for `auth.uid()`.
- No privileged access needed — `rbac.user_claims` is an extension-owned table.
- **RPC access restricted**: EXECUTE revoked from PUBLIC, granted only to `authenticator`.

### `_sync_member_metadata()` — SECURITY INVOKER
- **Trigger-only**: Returns `trigger` type — cannot be called directly via API.
- Writes to `rbac.user_claims` (upsert). No `auth.users` access required.
- When fired by SECURITY DEFINER RPCs (`create_group`, `accept_invite`), runs as `postgres`.
- When fired by SECURITY INVOKER RPCs (`add_member`, etc.), runs as `authenticated`.
- **Immutability enforcement**: Raises exception if `user_id` or `group_id` is changed on UPDATE.

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

Management RPCs (`delete_group`, `add_member`, `remove_member`, `update_member_roles`, `list_members`, `create_role`, `delete_role`, `list_roles`) are SECURITY INVOKER. They execute DML against `rbac.*` tables as the calling role (`authenticated`).

This means:
- The `authenticated` role needs DML grants on `rbac.*` tables (shipped by the extension)
- RLS policies on `rbac.*` tables control which rows are accessible
- Consumers define their authorization model via RLS policies

Example: An `add_member()` call succeeds only if the caller satisfies the INSERT policy on `rbac.members` (e.g., must be an owner of the group).

---

## Known Security Considerations

### `request.groups` is a Trusted Session Variable

**Risk level: Low — requires a consumer to create a vulnerable function**

`get_claims()` reads the `request.groups` session config key, which is set by `db_pre_request()`. Any PostgreSQL function can overwrite this key using `set_config('request.groups', ...)`. If a consumer creates an RPC function that writes user-controlled input to `request.groups`, an end user could spoof their group membership.

**Mitigation**: Never write a function that passes user input to `set_config('request.groups', ...)`.

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
