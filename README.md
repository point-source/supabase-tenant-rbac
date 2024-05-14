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
- Includes a user_role view which allows easy reference of which users have which roles
- user_role view can be used to delete roles via trigger
- (Optionally) Users can create their own groups
- Group owners can add other users to their groups and assign roles
- Invite system which allows users to create an invite code which can be used to join a group with specific roles

## Compared to [custom-claims](https://github.com/supabase-community/supabase-custom-claims)

The custom-claims project provides built-in functions for adding and removing generic claims to/from the `raw_app_meta_data` field of the auth.users records. This is highly flexible but is not opinionated about the way groups and roles should be handled.

Additionally, the custom-claims project requires the use of functions for all changes and does not provide the table-based interface that this project employs to maintain claims via trigger. It also does not include an invitation system.

Finally, this project makes use of [pre-request hooks](https://github.com/burggraf/postgrest-request-processing) to ensure that claims are always up to date. This is a more secure solution than the custom-claims project which uses claims cached in the JWT which may be out of date.

Nonetheless, these projects share many similarities and this one is built on top of the work that was done on the custom-claims project. This is merely an attempt to provide a more opinionated, streamlined, and secure-by-default solution that can be used by people who are not as familiar with RBAC or SQL functions.

## Under the hood

All group and role administration happens in the `groups` and `group_users` tables. The only exception is user role deletion, which can be performed through the `user_roles` view. When a record is inserted or changed in the `group_users` table, a function is triggered which detects the change and updates the corresponding `auth.users` record. Specifically, the `raw_app_meta_data` field is updated with data such as:

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
  - user_roles (view)
- This creates the following functions. Please check for collisions:
  - user_has_group_role
  - user_is_group_member
  - get_user_claims
  - jwt_is_expired
  - update_user_roles
  - delete_group_users

### Installation via dbdev

1. Make sure you have [dbdev package manager](https://supabase.github.io/dbdev/install-in-db-client/#use) installed
2. Run `select dbdev.install('pointsource-supabase_rbac');` in your SQL console to install the rbac plugin
3. Create the extension by running one of the following:

```sql
create extension "pointsource-supabase_rbac";
```

or, if you want to specify a schema or version:

```sql
create extension "pointsource-supabase_rbac" schema my_schema version "1.0.0";
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

If you would like to see more RLS policy examples, check the bottom of this readme.

## How to use

1. Create a record in the "groups" table
1. Create a record in the "group_users" table which links to the group and the user via the foreign key columns ("group_id" and "user_id", respectively)
1. Observe that the respective user record in auth.users has an updated `raw_app_meta_data` field which contains group and role information
1. (Optional) Use the built-in role checking functions for RLS
   - is_group_member
   - has_group_role
   - jwt_is_group_member
   - jwt_has_group_role
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
using (user_has_group_role(auth.uid(), "groupId", 'admin'))
with check (user_has_group_role(auth.uid(), "groupId", 'admin'));
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
