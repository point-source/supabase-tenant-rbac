# Changelog

## 3.0.0

- BREAKING: Remove "name" column from groups table
- BREAKING: user_roles view now properly adheres to RLS policies via security invoker (requires Postgres 15+)
- Add "metadata" column to groups table
- Add "metadata" column to group_users table
- Add trigger to keep metadata columns updated when a user record is updated
- Modify user_roles view to reference metadata columns instead of auth.users table
- Improve `update_user_roles` performance by eliminating subqueries, updating only the affected roles, and adding the ability to update the record's metadata with the user's email
- Reorganize example files
- Update readme links so they work on database.dev
- Add RLS policy examples to readme

## 2.0.2

- Remove references to "public" schema

## 2.0.1

- Fixed an issue where impersonating an anonymous user in the supabase studio would appear to grant access to data otherwise restricted by RLS. This issue did not affect real requests in production.

## 2.0.0

- BREAKING: Requires the "moddatetime" extension to be installed prior to installing this extension
- BREAKING: "created_at" column in groups table is now non-nullable
- Adds "updated_at" column to groups and group_users tables
- Adds trigger to automatically update "updated_at" column when a group or group_user record is updated
- Update control file to specify this as the default version

## 1.0.0

- BREAKING: Replace get_req_groups with get_user_claims
- BREAKING: Rename is_group_member to user_is_group_member
- BREAKING: Rename has_group_role to user_has_group_role
- BREAKING: Remove jwt methods (primary methods are now performant enough)
- BREAKING: Invite system now accepts multiple roles in a single invite (fixes #20)
- BREAKING: Remove set_group_owner and instead provide an example of how to implement it
- BREAKING: Remove add_group_user_by_email and instead provide an example of how to implement it
- Mark remaining read-only methods as stable
- Use auth.role() to determine authentication type (fixes #15)
- Set search paths for security definer functions (fixes #18)
- Use user-specified schema to determine search paths at time of extension creation (fixes #16)

## 0.0.4

- Add invite feature (fixes #7)

## 0.0.3

- Implement db_pre_request hook to populate request.groups context
- Add get_req_groups method to get group claims from request.groups context
- Modify jwt methods to use get_req_groups method

## 0.0.2

- Updated README.md

## 0.0.1

- Initial release
