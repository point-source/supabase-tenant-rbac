# Supabase Multi-Tenant Role-based Access Control

This is a [PostgreSQL TLE](https://github.com/aws/pg_tle) (extension) which attempts to provide a group and role system for supabase projects. You can add it to your database by using the [database.dev](https://database.dev/) tool. It is based off the supabase community [custom claims work done here](https://github.com/supabase-community/supabase-custom-claims).

To install, [visit database.dev](https://database.dev/pointsource/supabase_rbac).

## Disclaimer

I built this for my own personal use. It has not been audited by an independent security agency nor has it been thouroughly tested beyond my own project. It has been slightly modified for public release so there may be bugs and other pitfalls. I highly encourage users to perform their own inspection of the security of this template. Please submit any issues you find and I will do my best to promptly resolve them. Use at your own risk

## Features

- Create groups of users
- Assign a user to a group
- Users can be in multiple groups at once
- Assign a role to the user within a group
- Users can have multiple roles in a single group
- Manage group and role assignments through a table
- Group and role memberships are stored in the group_user table, auth.users table, and JWT
- Create RLS policies based on the user's assigned group or role
- (Optionally) Users can create their own groups
- Group owners can add other users to their groups and assign roles
- Invite system which allows users to create an invite code which can be used to join a group with specific roles

## Compared to [Supabase Custom Claims & RBAC](https://supabase.com/docs/guides/database/postgres/custom-claims-and-role-based-access-control-rbac)

The official supabase solution, using auth hooks, is actually very similar to the way this package used to work prior to version 1.0.0. By storing the claims in the jwt upon jwt generation, the claims are made accessible both server-side and client-side without requiring additional queries just to fetch them per request.

This is great for performance. Unfortunately, it also means that if the claims change after a JWT has been issued, they won't take effect until the active JWT with the old claims expires and gets renewed. This means that if you are trying to revoke someone's access, you can't do it instantly. If you are trying to grant additional permission, the user won't be able to use it until they log out and log back in or until the JWT expires.

This package takes the approach of caching the claims in the user's raw_app_meta_data each time the claims are updated. This field is included in the JWT so it provides the same functionality as the official solution (albeit with a slightly different data structure).

The difference comes in when a query is performed. This library uses the postgrest [db_pre_request](https://github.com/burggraf/postgrest-request-processing) hook to trigger on all incoming api calls to postgrest, fetch the current state of the claims cache (not from the JWT), and inject it into the request context. The included RLS policy convenience functions check this request context first, before falling back to the JWT method.

This means that as long as you are making queries via postgrest or the supabase sdk, you are more secure than the officially provided solution since it will always use the most up-to-date claims. It also means that claim changes take immediate effect for all users of the app. There is a minimal performance impact to this approach because it fetches the claim cache for each request (but not for each row). I have found this impact to be negligible and worth the added security and real-time functionality for my application.

Finally, the official docs guide you on implementing RBAC, but not Multi-Tenant RBAC (as of this writing). This means that while you can assign roles and permissions, it isn't obvious how to have multiple teams/organizations of users that each manage their own roles/permissions within their team/org. My library supports this natively by using groups to organize collections of users and then any number of roles per user, per group. You can use the same dot notation from the official docs to add permissions to this as well. This is documented at the end of this readme and includes [real code examples](https://github.com/point-source/supabase-tenant-rbac?tab=readme-ov-file#rls-policy-examples-continued).

In summary, my package should accomplish everything the official solution does while also adding security, instant applicaiton of changes, more convenient methods to call in RLS policies, and multi-tenant support. I hope that in the future, some of this functionality might be added to the official solution.

## Security Considerations

> **Note:** A full security analysis is in [`docs/SECURITY.md`](docs/SECURITY.md). The highlights below are the most important things to understand before deploying.

### Unconstrained role assignment (privilege escalation risk)

By default, RLS on `group_users` is set to deny-all, so only the service role or `postgres` can assign roles. If you create policies that allow group admins to write to `group_users`, be aware that **nothing in the extension prevents an admin from assigning any role string, including a role they do not hold themselves.** If privilege escalation is a concern, add a check constraint or a `BEFORE INSERT/UPDATE` trigger on `group_users` that validates the role being assigned against an allowlist.

### Invite expiration

As of v4.2.0, `group_invites` has an optional `expires_at` column. Invites with `expires_at = NULL` never expire. Set `expires_at` to a future timestamp when creating an invite to ensure it cannot be used after that point. The edge function enforces this at acceptance time.

Prior to v4.2.0, invites were valid indefinitely once created. If you are upgrading, consider auditing your open invites and setting an `expires_at` on any that should have been time-limited.

### Claims freshness and Supabase Storage

This extension uses the `db_pre_request` hook to ensure PostgREST always uses fresh claims from `auth.users` rather than the JWT cache. However, `db_pre_request` is a PostgREST-only mechanism — **Supabase Storage bypasses it and uses JWT-based claims only.** If your application uses Storage with RBAC policies, be aware that role changes will not take effect in Storage until the user's JWT refreshes (typically up to one hour).

## Compared to [custom-claims](https://github.com/supabase-community/supabase-custom-claims)

The custom-claims project provides built-in functions for adding and removing generic claims to/from the `raw_app_meta_data` field of the auth.users records. This is highly flexible but is not opinionated about the way groups and roles should be handled.

Additionally, the custom-claims project requires the use of functions for all changes and does not provide the table-based interface that this project employs to maintain claims via trigger. It also does not include an invitation system.

Finally, this project makes use of [pre-request hooks](https://github.com/burggraf/postgrest-request-processing) to ensure that claims are always up to date. This is a more secure solution than the custom-claims project which uses claims cached in the JWT which may be out of date.

Nonetheless, these projects share many similarities and this one is built on top of the work that was done on the custom-claims project. This is merely an attempt to provide a more opinionated, streamlined, and secure-by-default solution that can be used by people who are not as familiar with RBAC or SQL functions.

## Under the hood

All group and role administration happens in the `groups` and `group_users` tables. When a record is inserted or changed in the `group_users` table, a function is triggered which detects the change and updates the corresponding `auth.users` record. Specifically, the `raw_app_meta_data` field is updated with data such as:

```json
{
  "groups": {
    "c2aa61f5-d86b-45e8-9e6d-a5bae98cd530": ["admin"]
  },
  "provider": "email",
  "providers": ["email"]
}
```

Notice that the `groups` key has been added by the trigger function and has been populated with a new subkey matching the uuid of the group that the user was added to. Finally, the value is an array of roles as strings. So the structure is `raw_app_meta_data -> groups -> group_id -> roles[]`

In this example, the `provider` and `providers` keys are a normal part of the supabase backend and are irrelevant to this project.

As a security note, `raw_app_meta_data` is stored within the JWTs when a session is created. This field is not editable by the user under normal circumstances.

## Installation

### Pre-check

- Requires PostgreSQL 15.x (due to use of "security_invoker" on the user_role view)
- This creates the following tables / views. Make sure they do not collide with existing tables. (alternatively, specify an alternate schema during creation of the extension):
  - groups
  - group_users
- This creates the following functions. Please check for collisions:
  - user_has_group_role
  - user_is_group_member
  - get_user_claims
  - jwt_is_expired
  - update_user_roles

### Installation via dbdev

1. Make sure you have [dbdev package manager](https://supabase.github.io/dbdev/install-in-db-client/#use) installed
2. Run `select dbdev.install('pointsource-supabase_rbac');` in your SQL console to install the rbac plugin
3. Create the extension by running one of the following:

```sql
create extension "pointsource-supabase_rbac";
```

or, if you want to specify a schema or version:

```sql
create extension "pointsource-supabase_rbac" schema my_schema version "4.0.0";
```

### Security / RLS

Out of the box, the tables created by this project have RLS enabled and set to reject all operations. This means that group membership and roles can only be assigned and administered by the database administrator/superuser. You may want to modify the RLS policies on the `groups` and `group_users` tables to enable users (such as users with an "admin" role) to modify certain group and role memberships based on their own membership.

One idea is to make use of [a trigger to allow any user who creates a group to automatically become the owner/admin of that group](https://github.com/point-source/supabase-tenant-rbac/tree/main/examples/triggers/auto_group_owner.sql). Then, via their owner role, they can [add additional users/roles by email](https://github.com/point-source/supabase-tenant-rbac/tree/main/examples/functions/add_user_by_email.sql). Note that in order for these to work, you will need to:

1. Modify the examples to match your schema (replace `my_schema_name` with your schema name. If you don't know, it is likely `public`)
1. Create an RLS policy that allows users to create groups (insert rows into the `groups` table). Here is an example of one such policy which allows any authenticated user to create a new group:

```sql
create policy "Allow authenticated users to insert"
on "public"."groups"
as permissive
for insert
to authenticated
with check (true);
```

If you would like to see [more RLS policy examples](https://github.com/point-source/supabase-tenant-rbac?tab=readme-ov-file#rls-policy-examples-continued), check the bottom of this readme.

## How to use

1. Create a record in the "groups" table
1. Create a record in the "group_users" table which links to the group and the user via the foreign key columns ("group_id" and "user_id", respectively)
1. Observe that the respective user record in auth.users has an updated `raw_app_meta_data` field which contains group and role information
1. (Optional) Use the built-in role checking functions for RLS
   - user_is_group_member
   - user_has_group_role
1. (Optional) Check the JWT signature and contents to determine roles on the client-side

### Built-in functions

#### user_is_group_member(group_id uuid)

Required inputs: `group_id` as a uuid
Returns: boolean

This will return true if the `group_id` exists within the `raw_app_meta_data->groups` field of the user's record in the auth.users table. Executing this function will perform a query against the auth.users table each time it is run.

#### user_has_group_role(group_id uuid, group_role text)

Required inputs: `group_id` as a uuid, `group_role` as text
Returns: boolean

This will return true if the `group_role` exists within the `raw_app_meta_data->groups->group_id` array of the user's record in the auth.users table. Executing this function will perform a query against the auth.users table each time it is run.

#### get_user_claims()

Required inputs: none
Returns: jsonb

This will attempt to return the contents of `request.groups` (populated by the db_pre_request hook) which contains the user's group and role information. If `request.groups` is null, it will fallback to returning the contents of `app_meta_data->>groups` from the JWT. If neither are available, it will return an empty jsonb object.

## Setting up the Invitation system

### Initializing the Supabase CLI

If you already have a local dev instance of supabase or if you have already installed, authenticated, and linked the supabase cli for your project, you can skip this section.

1. Install the supabase by following the [getting started guide](https://supabase.com/docs/guides/cli/getting-started)
1. Set your terminal's current directory to that of your project by running `cd /path/to/your/project`
1. Initialize the cli by running `supabase init` and following the prompts
1. Authenticate the cli by running `supabase login` and following the prompts
1. Link the cli to your project by running `supabase link` and selecting your project

### Create & deploy the edge function

1. Run `supabase functions new invite` to create an empty function named "invite"
1. Copy the contents of [supabase/functions/invite.js](https://github.com/point-source/supabase-tenant-rbac/blob/main/supabase/functions/invite/index.ts) into the newly created function
1. Since the invite function validates the user's JWT, you will need to add the JWT secret to the function's environment variables. To do this, run `supabase secrets set SB_JWT_SECRET=<your_supabase_jwt_secret>`. (this can be found in your project settings)
1. Run `supabase functions deploy invite` to deploy the function to your supabase project

### Using the invitation system

1. Create a new row in the `group_invites` table. You should leave the `user_id` and `accepted_at` fields blank for now.
1. Copy the `id` field from the newly created row. This is the invite code.
1. Send the invite code to the user you wish to invite.
1. When the user accepts the invite, they should send a POST request to `https://<your_supabase_url>/functions/v1/invite/accept`. Here is an example of an equivalent curl request (you should replace the invite code in the query parameter and provide a valid JWT for the Authorization header):

```bash
curl --request POST 'http://localhost:54321/functions/v1/invite/accept?invite_code=<your_invite_code>' \
  --header 'Authorization: Bearer USER_JWT_GOES_HERE'
```

When the function runs, it will validate the JWT of the user calling it and will then update the `user_id` and `accepted_at` fields of the invite record. It will also add the user to the group with the roles specified as an array in the `roles` field of the invite record.

### Securing the invitation system

Without RLS, anyone can create an invite to a group, even people who are not members of that group. This means people could potentially abuse the invite system to gain access to groups they are not supposed to be in. To prevent this, this package automatically enables a strict RLS policy which prevents all users from creating invites.

In order to enable users to create invites, you can create an RLS policy on the `group_invites` table which only allows users to create invites for groups that they are a member of. Here is an example of a policy which only allows users who have the `admin` role to create/read/update/delete invites for groups that they are a member of:

```sql
create policy "Enable CRUD for group admins"
on "group_invites"
as permissive
for all
to public
using (user_has_group_role(group_id, 'admin'))
with check (user_has_group_role(group_id, 'admin'));
```

## RLS Policy Examples (continued)

Below are two different strategies for implementing RLS policies based on the user's group and role memberships. They both achieve the same thing from the user's perspective but use different methods to do so from the developer perspective. You may find one more flexible or easier to work with than the other or more suitable for your use case.

### Role-centric Policies

These are policies based around predefined roles or "types of users" rather than permissions. These policies verify _who you are_ rather than _what you have been allowed to do_ in order to determine what is permitted. In this case, we are using the roles `owner`, `admin`, and `viewer`.

- Users with the `owner` role are automatically added to the user that creates the group via a [trigger function](https://github.com/point-source/supabase-tenant-rbac/tree/main/examples/triggers/auto_group_owner.sql). The only additional ability that owners are granted in this example is to delete the group itself. This check is achieved by using the `user_has_group_role(id, 'owner')` function in the RLS policy.

- Users with the `admin` role are granted the ability to add and remove users from the group by assigning roles to them. This role is also automatically assigned to the owner via the [trigger function](https://github.com/point-source/supabase-tenant-rbac/tree/main/examples/triggers/auto_group_owner.sql). This check is achieved by using the `user_has_group_role(id, 'admin')` function in the RLS policy.

- Finally, users with the `viewer` role are granted the ability to view the group and its members but are not allowed to make changes. It is important to note that rather than using a check like `user_has_group_role(id, 'viewer')`, we are instead using `user_is_group_member(id)` since all roles that might be assigned would, at the very least, have viewer permissions. By using this less restrictive check, we can ensure that all users who are members of the group can view the group without incurring the performance penalty of checking for each possible role.

You can [view the full policies here](https://github.com/point-source/supabase-tenant-rbac/tree/main/examples/policies/role_centric.sql).

### Permission-centric Policies

These are policies based around specific permissions that users have been granted. This is often more flexible and granualar than the role-centric policies but also may come with a performance disadvantage since the database function has to iterate through more roles in order to verify permissions. This check is run for each row being accessed. With larger queries, this can become significant. In this example, we are using these permissions:

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

Notice that while most of these permissions seem to follow a naming convention of `{table}.{operation}`, the `group_user.invite` permission does not follow this convention. This is because while there is a group_invite table, this permission ultimately permits users to add group members to a group, albeit via indirect (invite) means. By naming it the way we have, it is more descriptive about what this permission ultimately accomplishes. This is a matter of personal preference and you may choose to name it differently.

Futhermore, the `group_data.*` permissions do not reference any table and are there to serve as general-purpose permissions for RLS policies across multiple tables of data that might be generated or consumed by group members. It is not necessary to create general-purpose permissions like this, but it can be useful if you have a lot of tables that you want to apply the same permissions to.

To improve performance, you can also combine some of these permissions into a single role. For example, if you know that you are frequently assigning all permissions for a certain category to certain users, you can use something like `group_data.all` to represent all of the data permissions at once. This reduces the size of the permissions array for the user who has it. Then, in the RLS policy, you would use something like `user_has_group_role(group_id, 'group_user.all') OR user_has_group_role(group_id, 'group_user.create')` to check for the permission. Make sure to check for combined permissions first, since they are more likely to shortcut the search.

In a future version of this package, I may modify the permissions checking functions to accept multiple roles at once and search more efficiently.

You can [view the full policies here](https://github.com/point-source/supabase-tenant-rbac/tree/main/examples/policies/permission_centric.sql).

### Custom Data Table (End-to-End Example)

The most common real-world use case: you have a table that belongs to a group and you want different access levels for members vs. admins. Here is a complete example for a `posts` table.

**Step 1: Create the table with a `group_id` foreign key**

```sql
create table "public"."posts" (
  "id"         uuid not null default gen_random_uuid(),
  "group_id"   uuid not null references "groups"(id) on delete cascade,
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
-- user_is_group_member is preferred here over user_has_group_role because all
-- roles (viewer, editor, admin, …) grant at minimum read access.
create policy "Group members can read"
on "public"."posts" as permissive for select to authenticated
using (user_is_group_member(group_id));

-- Only members with the editor role can create posts.
create policy "Editors can create"
on "public"."posts" as permissive for insert to authenticated
with check (user_has_group_role(group_id, 'editor'));

-- Only members with the editor role can update posts.
create policy "Editors can update"
on "public"."posts" as permissive for update to authenticated
using  (user_has_group_role(group_id, 'editor'))
with check (user_has_group_role(group_id, 'editor'));

-- Only group admins can delete posts.
create policy "Admins can delete"
on "public"."posts" as permissive for delete to authenticated
using (user_has_group_role(group_id, 'admin'));
```

The key pattern: pass the row's `group_id` column directly to `user_is_group_member` or `user_has_group_role`. The function reads the current user's claims from the request context and checks whether they have membership/the specified role in that group.

If you are using permission-centric roles (e.g. `post.create`, `post.delete`), substitute those strings for `'editor'` and `'admin'` above. See [#33](https://github.com/point-source/supabase-tenant-rbac/issues/33) for more discussion.

## Troubleshooting

### Groupless users receive a 500 error on every API request

**Symptom:** Newly signed-up users who have not been added to any group receive a 500 error for every PostgREST API request. Supabase logs show `invalid input syntax for type json`.

**Cause:** Bug in versions before v4.1.0. See [issue #37](https://github.com/point-source/supabase-tenant-rbac/issues/37). When a user has no group memberships, `db_pre_request` stored an empty string in `request.groups`, which `get_user_claims()` then tried to cast as `jsonb`.

**Fix:** Upgrade to v4.1.0 or later:

```sql
alter extension "pointsource-supabase_rbac" update to '4.1.0';
```

If you cannot upgrade immediately, ensure all users are added to at least one group right after signup — for example via a trigger on `auth.users`.

---

### `db_pre_request` not found when installed in a custom schema

**Symptom:** After installing with `create extension "pointsource-supabase_rbac" schema my_schema`, every PostgREST request fails with a function-not-found error.

**Cause:** Bug in versions before v4.1.0. See [issue #29](https://github.com/point-source/supabase-tenant-rbac/issues/29). The `pgrst.db_pre_request` role setting was registered without a schema prefix, so PostgREST could not locate the function in a non-`public` schema.

**Fix:** Upgrade to v4.1.0 or later. If upgrading is not immediately possible, run this manually after installation:

```sql
alter role authenticator set pgrst.db_pre_request to 'my_schema.db_pre_request';
notify pgrst, 'reload config';
```

---

### Storage RLS policies use stale claims after a role change

**Symptom:** RLS policies on Supabase Storage objects that call `user_has_group_role()` or `user_is_group_member()` appear to use outdated group memberships for up to an hour after a role change.

**Cause:** The `db_pre_request` hook only fires in the PostgREST pipeline. Supabase Storage routes requests through a separate code path that does not invoke the hook. Storage therefore falls back to JWT claims, which are only refreshed when the user's session token is renewed (default: 1 hour). See [issue #34](https://github.com/point-source/supabase-tenant-rbac/issues/34).

**Workaround:** This is an architectural limitation that cannot be fixed within this extension. For storage access control, accept a staleness window equal to the JWT lifetime. If immediate revocation is critical, use server-side signed URLs or a separate access check rather than storage-level RLS based on group roles.

---

### Project fails to restore after being paused or upgraded

**Symptom:** After a Supabase project is paused and unpaused, or after a Supabase platform upgrade, the project fails to start with an error about `auth.users` not existing when the extension is being installed.

**Cause:** Supabase logical backups do not correctly capture the dependency between the TLE extension and `auth.users`. The extension may be restored before the `auth` schema exists. See [issue #41](https://github.com/point-source/supabase-tenant-rbac/issues/41).

**Workaround:** Contact Supabase support. This is an upstream platform issue; no workaround exists within this extension.
