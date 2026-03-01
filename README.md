# Supabase Multi-Tenant Role-based Access Control

This is a [PostgreSQL TLE](https://github.com/aws/pg_tle) (extension) which provides a group and role system for Supabase projects. v5.0.0 features a private schema architecture, typed management RPCs, validated role definitions, and an optional auth hook for JWT-embedded claims. You can add it to your database by using the [database.dev](https://database.dev/) tool. It is based off the supabase community [custom claims work done here](https://github.com/supabase-community/supabase-custom-claims).

To install, [visit database.dev](https://database.dev/pointsource/supabase_rbac).

## Disclaimer

I built this for my own personal use. It has not been audited by an independent security agency nor has it been thouroughly tested beyond my own project. It has been slightly modified for public release so there may be bugs and other pitfalls. I highly encourage users to perform their own inspection of the security of this template. Please submit any issues you find and I will do my best to promptly resolve them. Use at your own risk

## Features

- Create groups of users (tenants/organizations)
- Users can be in multiple groups at once
- Users can have multiple roles in a single group (stored as `roles text[]`)
- Typed management RPCs: `create_group`, `add_member`, `remove_member`, `update_member_roles`, and more
- Role definitions validated against a `roles` table — typos rejected at write time
- Private schema architecture: tables live in a dedicated schema (e.g., `rbac`) not exposed via REST; all access via RPCs
- Auto-managed claims cache (`user_claims` table) kept in sync by a trigger on every membership change
- PostgREST `db_pre_request` hook ensures every API request uses up-to-date claims, not stale JWT data
- Optional `custom_access_token_hook` injects group claims into JWTs at token-creation time
- Only 2 SECURITY DEFINER functions (`create_group`, `accept_invite`) — all other RPCs are SECURITY INVOKER
- RLS helpers for writing policies: `has_role`, `is_member`, `has_any_role`, `has_all_roles`, `get_claims`
- Invite system: create invite codes with specific roles; accept atomically via RPC
- Deny-all RLS by default — you add policies that fit your application

## Compared to [Supabase Custom Claims & RBAC](https://supabase.com/docs/guides/database/postgres/custom-claims-and-role-based-access-control-rbac)

The official Supabase solution stores claims in the JWT at token-creation time via an auth hook. This is great for performance — claims are immediately accessible both server-side and client-side without a database query. The drawback is that claims are stale until the JWT expires: revoking access takes effect only after the next login.

This package takes a different approach. When group membership changes, a trigger writes the user's updated claims to `rbac.user_claims` — an extension-owned table. The PostgREST `db_pre_request` hook then reads `user_claims` on every API request and injects the current state into the request context. The included RLS helper functions (`has_role`, `is_member`, etc.) read from this request context, not from the JWT. This means **claim changes take effect immediately** for all users, with no need to wait for JWT expiry.

As of v5.0.0, this package also includes `custom_access_token_hook`, which injects group claims into JWTs at token-creation time (identical in concept to the official solution). This is **complementary** to `db_pre_request` — the hook provides convenient client-side access to claims, while `db_pre_request` guarantees freshness on every server-side API request.

Finally, the official docs guide you on implementing RBAC, but not Multi-Tenant RBAC (as of this writing). This means that while you can assign roles and permissions, it isn't obvious how to have multiple teams/organizations of users that each manage their own roles/permissions within their team/org. My library supports this natively by using groups to organize collections of users and then any number of roles per user, per group. You can use the same dot notation from the official docs to add permissions to this as well. This is documented at the end of this readme and includes [real code examples](https://github.com/point-source/supabase-tenant-rbac?tab=readme-ov-file#rls-policy-examples-continued).

In summary, my package should accomplish everything the official solution does while also adding security, instant application of changes, more convenient methods to call in RLS policies, and multi-tenant support. I hope that in the future, some of this functionality might be added to the official solution.

## Security Considerations

> **Note:** A full security analysis is in [`docs/SECURITY.md`](docs/SECURITY.md). The highlights below are the most important things to understand before deploying.

### Unconstrained role assignment (privilege escalation risk)

By default, RLS on `members` is set to deny-all, so only the service role or `postgres` can assign roles. If you create policies that allow group admins to write to `members`, be aware that **nothing in the extension prevents an admin from assigning a role they do not hold themselves** (though `_validate_roles()` does prevent assigning undefined roles). If privilege escalation is a concern, add a `BEFORE INSERT/UPDATE` trigger on `members` that validates the role being assigned against the caller's own roles.

### Invite expiration

The `invites` table has an optional `expires_at` column. Invites with `expires_at = NULL` never expire. Set `expires_at` to a future timestamp when creating an invite to ensure it cannot be used after that point. The edge function and `accept_invite()` RPC both enforce this at acceptance time.

### Claims freshness and Supabase Storage

This extension uses the `db_pre_request` hook to ensure PostgREST always uses fresh claims from `rbac.user_claims` rather than the JWT cache. Supabase Storage requests bypass `db_pre_request`, but `get_claims()` falls back to `_get_user_groups()` which reads `rbac.user_claims` directly when `request.groups` is not set. Role changes take effect immediately for both PostgREST and Storage requests.

## Compared to [custom-claims](https://github.com/supabase-community/supabase-custom-claims)

The custom-claims project provides built-in functions for adding and removing generic claims to/from the `raw_app_meta_data` field of the `auth.users` records. This is highly flexible but is not opinionated about the way groups and roles should be handled.

Additionally, the custom-claims project requires the use of functions for all changes and does not provide the table-based interface or trigger-driven sync that this project uses to maintain the `user_claims` cache. It also does not include an invitation system.

Finally, this project makes use of [pre-request hooks](https://postgrest.org/en/stable/references/api/preferences.html) to ensure that claims are always up to date. This is a more secure solution than storing claims only in the JWT, which may be out of date.

Nonetheless, these projects share many similarities and this one is built on top of the work that was done on the custom-claims project. This is merely an attempt to provide a more opinionated, streamlined, and secure-by-default solution that can be used by people who are not as familiar with RBAC or SQL functions.

## Under the hood

All group and role administration happens through the management RPCs (`create_group`, `add_member`, `update_member_roles`, etc.). When a record is inserted, updated, or deleted in the `members` table, the `_sync_member_metadata()` trigger fires and rebuilds the user's claims from scratch, then upserts them into `rbac.user_claims`. The claims format is:

```json
{
  "c2aa61f5-d86b-45e8-9e6d-a5bae98cd530": ["admin", "owner"]
}
```

The top-level keys are group UUIDs; the values are arrays of role strings. This is stored in `rbac.user_claims.claims` — **not** in `auth.users`.

On every PostgREST API request, `db_pre_request()` reads the current user's row from `user_claims` and stores it in `request.groups`. The RLS helper functions (`has_role`, `is_member`, etc.) read from this request context, so they always reflect the current state of `user_claims`, not stale JWT data.

For Supabase Storage requests (which bypass `db_pre_request`), `get_claims()` falls back to `_get_user_groups()`, which reads `user_claims` directly.

Optionally, `custom_access_token_hook` can be registered as a Supabase Auth Hook. When enabled, it reads `user_claims` at token-creation time and injects the groups into `app_metadata.groups` in the JWT — giving clients access to claims without a database round-trip.

For full architectural details, see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Installation

### Pre-check

- Requires PostgreSQL 15.x or later
- This creates the following tables in the extension schema (`rbac` by default). Make sure they do not collide with existing objects:
  - `groups`
  - `members`
  - `invites`
  - `roles`
  - `user_claims`
- This creates the following public-facing functions. Check for collisions:
  - `has_role`, `is_member`, `has_any_role`, `has_all_roles`, `get_claims` (RLS helpers)
  - `create_group`, `delete_group`, `add_member`, `remove_member`, `update_member_roles`, `list_members` (group management)
  - `accept_invite` (invite acceptance)
  - `create_role`, `delete_role`, `list_roles` (role management)
  - `custom_access_token_hook` (auth hook)
  - `db_pre_request` (PostgREST hook — called automatically)

### Installation via dbdev

1. Make sure you have [dbdev package manager](https://supabase.github.io/dbdev/install-in-db-client/#use) installed
2. Run `select dbdev.install('pointsource-supabase_rbac');` in your SQL console to install the package
3. Create the extension by running one of the following:

```sql
create extension "pointsource-supabase_rbac";
```

It is strongly recommended to install in a dedicated private schema (not `public`), so the tables are not directly accessible via the REST API:

```sql
create extension "pointsource-supabase_rbac" schema rbac version "5.0.0";
```

When installed in a non-`public` schema, thin public wrapper functions are created automatically so that PostgREST can discover the RPCs and RLS policies can use unqualified names (e.g., `has_role(...)` rather than `rbac.has_role(...)`).

### Security / RLS

Out of the box, all tables created by this extension have RLS enabled with **zero policies** (deny-all). This means nothing works until you add your own policies. The recommended starting point is:

```
examples/policies/quickstart.sql
```

This file contains ready-to-use policies for all five extension tables using the `owner` role (pre-seeded in `rbac.roles`).

For a minimal working setup:

1. Apply the quickstart policies (or write your own)
2. Use `create_group()` to create a group — the caller is automatically added as the `owner`
3. Use `add_member()` to add other users

The `create_group()` RPC is SECURITY DEFINER and bypasses RLS for the INSERT into `groups` and `members`, so you do **not** need an INSERT policy on those tables for normal group creation.

If you would like to see [more RLS policy examples](https://github.com/point-source/supabase-tenant-rbac?tab=readme-ov-file#rls-policy-examples-continued), check the bottom of this readme.

## Core Tables

All tables are created in the extension schema (e.g., `rbac`). They are **not** directly accessible via the REST API. Use management RPCs for all write operations.

| Table | Key Columns | Purpose |
|-------|-------------|---------|
| `groups` | `id`, `name`, `metadata` | Tenants / organizations |
| `members` | `group_id`, `user_id`, `roles text[]`, `metadata` | One row per user-group membership; `roles` is an array of role strings |
| `invites` | `group_id`, `roles text[]`, `invited_by`, `expires_at` | Invite codes; `user_id` and `accepted_at` are populated on acceptance |
| `roles` | `name` (PK), `description` | Role definitions; pre-seeded with `'owner'`; all role assignments are validated against this table |
| `user_claims` | `user_id` (PK), `claims jsonb` | Auto-managed claims cache; **never write to this table directly** |

> **Note:** `user_claims` is automatically kept in sync by a trigger on `members`. Writing to it directly will cause incorrect behavior.

## How to use

1. **Define your roles** — add custom roles using `create_role()`. The `'owner'` role is pre-seeded and used as the default for `create_group()`.
2. **Create a group** — call `create_group('My Group')`. The caller is automatically added as a member with the `owner` role.
3. **Add members** — call `add_member(group_id, user_id, ARRAY['viewer'])` to add a user with one or more roles.
4. **Write RLS policies** — use the built-in helpers (`has_role`, `is_member`, `has_any_role`) in your policies on application tables.
5. **(Optional) Enable the auth hook** — register `custom_access_token_hook` in your Supabase config to inject group claims into JWTs for client-side use.

### Core Functions

#### RLS Helpers

These are the functions you use in RLS policies. They read claims from `request.groups` (set by `db_pre_request`) and fall back to reading `rbac.user_claims` directly for Supabase Storage requests.

##### `get_claims() → jsonb`

Returns the current user's group/role claims as a jsonb object (`{ "group-uuid": ["role1", "role2"] }`). Returns `{}` for unauthenticated or groupless users.

##### `is_member(group_id uuid) → boolean`

Returns `true` if the current user is a member of the group (has any role). Preferred over `has_role` when all roles grant equivalent access, as it avoids iterating through role strings.

##### `has_role(group_id uuid, role text) → boolean`

Returns `true` if the current user has the specified role in the group.

##### `has_any_role(group_id uuid, roles text[]) → boolean`

Returns `true` if the current user has **at least one** of the specified roles. More efficient than chaining multiple `OR has_role(...)` calls.

##### `has_all_roles(group_id uuid, roles text[]) → boolean`

Returns `true` if the current user has **all** of the specified roles.

All four functions return `true` for `service_role` and `postgres` (superuser bypass), `false` for `anon`, and raise `invalid_jwt` for expired JWTs when called as `authenticated`.

#### Management RPCs

These are called by application code or from the Supabase dashboard. All are SECURITY INVOKER (RLS enforced) except `create_group` and `accept_invite`.

##### `create_group(p_name text, p_metadata jsonb DEFAULT '{}', p_creator_roles text[] DEFAULT ARRAY['owner']) → uuid`

Creates a new group and adds the caller as a member with `p_creator_roles`. Returns the new group UUID. **SECURITY DEFINER** (required because the caller has no prior membership to pass RLS).

##### `delete_group(p_group_id uuid)`

Deletes a group and all its members and invites (via CASCADE). Requires an RLS DELETE policy on `groups` allowing the caller.

##### `add_member(p_group_id uuid, p_user_id uuid, p_roles text[] DEFAULT '{}') → uuid`

Adds a user to a group with the specified roles. If the user is already a member, **merges** the new roles into their existing roles array (no duplicates). Returns the member UUID.

##### `remove_member(p_group_id uuid, p_user_id uuid)`

Removes a user from a group. Requires an RLS DELETE policy on `members` allowing the caller.

##### `update_member_roles(p_group_id uuid, p_user_id uuid, p_roles text[])`

Replaces the user's roles array entirely. Requires an RLS UPDATE policy on `members` allowing the caller.

##### `list_members(p_group_id uuid) → table`

Returns `(id, user_id, roles, metadata, created_at)` for all members of the group. Requires an RLS SELECT policy on `members`.

##### `accept_invite(p_invite_id uuid)`

Marks the invite as accepted, validates it is not expired or already used, then upserts the caller into the group with the invite's roles. **SECURITY DEFINER** (caller has no prior membership). Race-condition safe via `FOR UPDATE` row lock.

#### Role Management RPCs

##### `create_role(p_name text, p_description text DEFAULT NULL)`

Inserts a new role into the `roles` table. Requires an RLS INSERT policy on `roles`.

##### `delete_role(p_name text)`

Deletes a role. Refuses if any member currently has this role assigned. Requires an RLS DELETE policy on `roles`.

##### `list_roles() → table`

Returns `(name, description, created_at)` for all defined roles. Requires an RLS SELECT policy on `roles`.

#### Auth Hook

##### `custom_access_token_hook(event jsonb) → jsonb`

Supabase Auth Hook that injects group claims from `rbac.user_claims` into the `app_metadata.groups` field of the JWT at token-creation time. Register in `config.toml`:

```toml
[auth.hook.custom_access_token]
enabled = true
uri = "pg-functions://postgres/public/custom_access_token_hook"
```

This is **optional and complementary** to `db_pre_request`. Clients can read `app_metadata.groups` from the decoded JWT for authorization decisions without a DB round-trip.

## Setting up the Invitation System

### Initializing the Supabase CLI

If you already have a local dev instance of supabase or if you have already installed, authenticated, and linked the supabase cli for your project, you can skip this section.

1. Install the Supabase CLI by following the [getting started guide](https://supabase.com/docs/guides/cli/getting-started)
1. Set your terminal's current directory to that of your project: `cd /path/to/your/project`
1. Initialize the CLI by running `supabase init` and following the prompts
1. Authenticate the CLI by running `supabase login` and following the prompts
1. Link the CLI to your project by running `supabase link` and selecting your project

### Create & deploy the edge function

1. Run `supabase functions new invite` to create an empty function named "invite"
1. Copy the contents of [`supabase/functions/invite/index.ts`](https://github.com/point-source/supabase-tenant-rbac/blob/main/supabase/functions/invite/index.ts) into the newly created function
1. Run `supabase functions deploy invite` to deploy the function to your Supabase project

The function uses `SUPABASE_URL` and `SUPABASE_ANON_KEY` from the automatically injected Supabase edge function environment — no manual secret configuration is required.

### Using the invitation system

1. Create a new row in the `invites` table (via an RLS policy that allows the caller, or directly via the Supabase dashboard). Leave `user_id` and `accepted_at` blank. Set `roles` to the roles the invited user should receive.
1. Copy the `id` field from the newly created row. This is the invite code.
1. Send the invite code to the user you wish to invite.
1. When the user accepts the invite, they should send a POST request to your edge function. Here is an example curl request (replace the invite code in the query parameter and provide a valid JWT for the Authorization header):

```bash
curl --request POST 'http://localhost:54321/functions/v1/invite?invite_code=<your_invite_code>' \
  --header 'Authorization: Bearer USER_JWT_GOES_HERE'
```

The function is a thin wrapper: it extracts the invite code from the query string and calls the `accept_invite(p_invite_id)` RPC using the caller's JWT. All validation (expiry, already-used check, role validation) and the atomic membership upsert happen inside the database function.

### Securing the invitation system

Without RLS, anyone can create an invite to any group. The extension ships with zero policies on `invites` (deny-all). You must add policies to allow invite creation. Here is an example policy that allows users with the `owner` role to create, read, update, and delete invites for their groups:

```sql
create policy "Owners can manage invites"
on rbac.invites
as permissive
for all
to authenticated
using (has_role(group_id, 'owner'))
with check (has_role(group_id, 'owner'));
```

See [`examples/policies/quickstart.sql`](examples/policies/quickstart.sql) for the recommended invite policies with separate per-operation granularity.

## RLS Policy Examples (continued)

Below are two different strategies for implementing RLS policies based on the user's group and role memberships. They both achieve the same thing from the user's perspective but use different methods to do so from the developer perspective. You may find one more flexible or easier to work with than the other or more suitable for your use case.

### Role-centric Policies

These are policies based around predefined roles or "types of users" rather than permissions. These policies verify _who you are_ rather than _what you have been allowed to do_ in order to determine what is permitted. In this case, we are using the roles `owner`, `admin`, and `viewer`.

- Users with the `owner` role are automatically added to the user that creates the group via the `create_group()` RPC. The only additional ability that owners are granted in this example is to delete the group itself. This check is achieved by using the `has_role(id, 'owner')` function in the RLS policy.

- Users with the `admin` role are granted the ability to add and remove users from the group by assigning roles to them. This check is achieved by using the `has_role(id, 'admin')` function in the RLS policy.

- Finally, users with the `viewer` role are granted the ability to view the group and its members but are not allowed to make changes. It is important to note that rather than using a check like `has_role(id, 'viewer')`, we are instead using `is_member(id)` since all roles that might be assigned would, at the very least, have viewer permissions. By using this less restrictive check, we can ensure that all users who are members of the group can view the group without incurring the performance penalty of checking for each possible role.

You can [view the full policies here](https://github.com/point-source/supabase-tenant-rbac/tree/main/examples/policies/role_centric.sql).

### Permission-centric Policies

These are policies based around specific permissions that users have been granted. This is often more flexible and granular than the role-centric policies but also may come with a performance disadvantage since the database function has to iterate through more roles in order to verify permissions. This check is run for each row being accessed. With larger queries, this can become significant. In this example, we are using these permissions:

- `group.update` - Allows users to update a group
- `group.delete` - Allows users to delete a group

- `group_data.create` - Allows users to create data belonging to the group
- `group_data.read` - Allows users to view data belonging to the group
- `group_data.update` - Allows users to update data belonging to the group
- `group_data.delete` - Allows users to delete data belonging to the group

- `group_user.create` - Allows users to add a user to a group
- `group_user.read` - Allows users to view the members of a group
- `group_user.update` - Allows users to update the roles of a user in a group
- `group_user.delete` - Allows users to remove a user from a group
- `group_user.invite`\* - Allows users to create an invite for a group

Notice that while most of these permissions seem to follow a naming convention of `{table}.{operation}`, the `group_user.invite` permission does not follow this convention. This is because while there is an invites table, this permission ultimately permits users to add group members to a group, albeit via indirect (invite) means. By naming it the way we have, it is more descriptive about what this permission ultimately accomplishes. This is a matter of personal preference and you may choose to name it differently.

Furthermore, the `group_data.*` permissions do not reference any table and are there to serve as general-purpose permissions for RLS policies across multiple tables of data that might be generated or consumed by group members. It is not necessary to create general-purpose permissions like this, but it can be useful if you have a lot of tables that you want to apply the same permissions to.

To improve performance, you can also combine some of these permissions into a single role, or check multiple at once using `has_any_role()`:

```sql
-- Check if user has any write permission for group data
using (has_any_role(group_id, ARRAY['group_data.create', 'group_data.all']))
```

This is more efficient than chaining multiple `has_role()` checks. Make sure to check for combined permissions first, since they are more likely to shortcut the search.

You can [view the full policies here](https://github.com/point-source/supabase-tenant-rbac/tree/main/examples/policies/permission_centric.sql).

### Custom Data Table (End-to-End Example)

The most common real-world use case: you have a table that belongs to a group and you want different access levels for members vs. admins. Here is a complete example for a `posts` table.

**Step 1: Create the table with a `group_id` foreign key**

```sql
create table "public"."posts" (
  "id"         uuid not null default gen_random_uuid(),
  "group_id"   uuid not null references rbac.groups(id) on delete cascade,
  "title"      text not null,
  "body"       text not null default '',
  "created_at" timestamptz not null default now()
);

alter table "public"."posts" enable row level security;
grant select, insert, update, delete on "public"."posts" to authenticated;
```

**Step 2: Add RLS policies**

```sql
-- Any group member can read posts belonging to their group.
-- is_member is preferred here over has_role because all
-- roles (viewer, editor, admin, …) grant at minimum read access.
create policy "Group members can read"
on "public"."posts" as permissive for select to authenticated
using (is_member(group_id));

-- Only members with the editor role can create posts.
create policy "Editors can create"
on "public"."posts" as permissive for insert to authenticated
with check (has_role(group_id, 'editor'));

-- Only members with the editor role can update posts.
create policy "Editors can update"
on "public"."posts" as permissive for update to authenticated
using  (has_role(group_id, 'editor'))
with check (has_role(group_id, 'editor'));

-- Only group admins can delete posts.
create policy "Admins can delete"
on "public"."posts" as permissive for delete to authenticated
using (has_role(group_id, 'admin'));
```

The key pattern: pass the row's `group_id` column directly to `is_member` or `has_role`. The function reads the current user's claims from the request context and checks whether they have membership/the specified role in that group.

If you are using permission-centric roles (e.g. `post.create`, `post.delete`), substitute those strings for `'editor'` and `'admin'` above. See [#33](https://github.com/point-source/supabase-tenant-rbac/issues/33) for more discussion.

### Storage RLS

Supabase Storage requests bypass `db_pre_request`, but `get_claims()` falls back to reading `rbac.user_claims` directly — so `has_role()` and `is_member()` work correctly in Storage RLS policies too. Role changes take effect immediately without waiting for JWT refresh.

See [`examples/policies/storage_rls.sql`](examples/policies/storage_rls.sql) for complete Storage RLS examples using two patterns: group_id embedded in the object path, and group_id stored in object metadata.

### Hardened Setup

For defense-in-depth, consider revoking all default grants and re-granting only what your application needs. See [`examples/policies/hardened_setup.sql`](examples/policies/hardened_setup.sql) for a complete example using `REVOKE ALL` + targeted `GRANT` statements.

## Upgrading from v4.x

**There is no automated upgrade path from v4.x to v5.0.0.** The changes are too extensive for a simple `ALTER EXTENSION ... UPDATE`. Migration requires exporting data, dropping the extension, reinstalling v5.0.0, and re-importing.

### Key breaking changes

| What changed | v4.x | v5.0.0 |
|---|---|---|
| Table name | `group_users` | `members` |
| Table name | `group_invites` | `invites` |
| Membership model | One row per user-group-**role** | One row per user-group, `roles text[]` |
| Claims storage | `auth.users.raw_app_meta_data` | `rbac.user_claims` table |
| RLS helper | `user_has_group_role(uuid, text)` | `has_role(uuid, text)` |
| RLS helper | `user_is_group_member(uuid)` | `is_member(uuid)` |
| RLS helper | `get_user_claims()` | `get_claims()` |
| Invite acceptance | `accept_group_invite(uuid)` | `accept_invite(uuid)` |
| Group creation | Direct `INSERT` into `groups` + `group_users` | `create_group()` RPC |

For the complete migration procedure and a full comparison of what you gain, see [`docs/MIGRATION_GUIDE.md`](docs/MIGRATION_GUIDE.md).

## Troubleshooting

### Groupless users receive a 500 error on every API request

**Symptom:** Newly signed-up users who have not been added to any group receive a 500 error for every PostgREST API request. Supabase logs show `invalid input syntax for type json`.

**Cause:** Bug in versions before v4.1.0. See [issue #37](https://github.com/point-source/supabase-tenant-rbac/issues/37). When a user has no group memberships, `db_pre_request` stored an empty string in `request.groups`, which `get_claims()` then tried to cast as `jsonb`. This is fixed in v5.0.0 — `db_pre_request` writes `{}` when the user has no memberships.

**Fix:** Upgrade to v5.0.0.

---

### `db_pre_request` not found when installed in a custom schema

**Symptom:** After installing with `create extension "pointsource-supabase_rbac" schema my_schema`, every PostgREST request fails with a function-not-found error.

**Cause:** Bug in versions before v4.1.0. See [issue #29](https://github.com/point-source/supabase-tenant-rbac/issues/29). The `pgrst.db_pre_request` role setting was registered without a schema prefix, so PostgREST could not locate the function in a non-`public` schema. In v5.0.0, this is handled correctly at install time and public wrapper functions are auto-created — this is a non-issue.

**Fix for v4.x:** Upgrade to v5.0.0. If upgrading is not immediately possible, run this manually after installation:

```sql
alter role authenticator set pgrst.db_pre_request to 'my_schema.db_pre_request';
notify pgrst, 'reload config';
```

---

### Storage RLS policies use stale claims after a role change

**Symptom:** RLS policies on Supabase Storage objects that call `has_role()` or `is_member()` appear to use outdated group memberships after a role change.

**Cause:** The `db_pre_request` hook only fires in the PostgREST pipeline. Supabase Storage routes requests through a separate code path that does not invoke the hook. See [issue #34](https://github.com/point-source/supabase-tenant-rbac/issues/34).

**Fix:** In v5.0.0, `get_claims()` falls back to reading `rbac.user_claims` directly via `_get_user_groups()` when `request.groups` is not set, giving Storage RLS policies the same freshness guarantee as PostgREST requests. No changes to existing RLS policies are required.

See `examples/policies/storage_rls.sql` for Storage-specific RLS policy examples.

---

### Project fails to restore after being paused or upgraded

**Symptom:** After a Supabase project is paused and unpaused, or after a Supabase platform upgrade, the project fails to start with an error about `auth.users` not existing when the extension is being installed.

**Cause:** Supabase logical backups do not correctly capture the dependency between the TLE extension and `auth.users`. The extension may be restored before the `auth` schema exists. See [issue #41](https://github.com/point-source/supabase-tenant-rbac/issues/41).

**Workaround:** Contact Supabase support. This is an upstream platform issue; no workaround exists within this extension.

## Examples Index

| File | Description |
|------|-------------|
| [`examples/policies/quickstart.sql`](examples/policies/quickstart.sql) | **Start here.** Recommended RLS policies for all five extension tables |
| [`examples/policies/role_centric.sql`](examples/policies/role_centric.sql) | RLS using named roles (owner/admin/viewer) |
| [`examples/policies/permission_centric.sql`](examples/policies/permission_centric.sql) | RLS using dot-notation permissions (e.g. `group_data.read`) |
| [`examples/policies/storage_rls.sql`](examples/policies/storage_rls.sql) | RLS for Supabase Storage objects |
| [`examples/policies/custom_table_isolation.sql`](examples/policies/custom_table_isolation.sql) | RLS for application tables with a `group_id` FK |
| [`examples/policies/hardened_setup.sql`](examples/policies/hardened_setup.sql) | Defense-in-depth: `REVOKE ALL` + targeted grants |
| [`examples/triggers/sync_user_into_group_role.sql`](examples/triggers/sync_user_into_group_role.sql) | Keep user email/name synced into `members.metadata` |
| [`examples/triggers/on_delete_user_roles.sql`](examples/triggers/on_delete_user_roles.sql) | Cascade deletes via user_roles view |
| [`examples/views/user_roles.sql`](examples/views/user_roles.sql) | Flattened view: one row per user-group-role |
| [`examples/setup/remove_public_wrappers.sql`](examples/setup/remove_public_wrappers.sql) | How to drop the auto-created `public.*` wrapper functions |
| [`examples/triggers/auto_group_owner.sql`](examples/triggers/auto_group_owner.sql) | _(Superseded by `create_group()` RPC)_ Auto-assign owner on group create |
| [`examples/functions/add_user_by_email.sql`](examples/functions/add_user_by_email.sql) | _(Superseded by `add_member()` RPC)_ Add user by email |
