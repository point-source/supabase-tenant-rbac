# Changelog

## 4.3.0

- Fix #34: Storage RLS policies now get fresh claims instead of stale JWT data — `get_user_claims()` falls back to a new `_get_user_groups()` SECURITY DEFINER helper that reads `auth.users` directly, giving Supabase Storage the same freshness guarantee as PostgREST requests. Existing RLS policies require no changes.
- Add pgTAP regression tests for Storage claims path (8 assertions in `supabase/tests/08_storage_claims.test.sql`)
- Add `examples/policies/storage_rls.sql` — two patterns for Storage RLS (group_id in path vs. group_id in object metadata)

## 4.2.0

- Add invite expiration support — new nullable `expires_at` column on `group_invites`. Invites with `expires_at = NULL` never expire (backwards compatible; all existing invites get `NULL`). The invite acceptance edge function now rejects invites whose `expires_at` is set and in the past.
- Add pgTAP regression test for invite expiration (7 assertions)
- Add "Security Considerations" section to README covering privilege escalation risk, invite expiration, and Storage claims freshness
- Fix outdated function names in README (`is_group_member` / `has_group_role` → `user_is_group_member` / `user_has_group_role`; removed `jwt_*` methods were removed in v1.0.0)
- Fix incorrect function signature in README invite policy example (`user_has_group_role(group_id, 'admin')` — no `auth.uid()` argument)

## 4.1.0

- Fix #37: Groupless users no longer crash `get_user_claims()` — `db_pre_request` now stores `'{}'` instead of NULL for users with no group memberships, and `get_user_claims()` handles empty string gracefully via `NULLIF`
- Fix #11: Deleting a user no longer crashes the `update_user_roles` trigger — the trigger now skips the `auth.users` update when the user no longer exists
- Fix #38: Added `ON DELETE CASCADE` to all foreign keys on `group_users` and `group_invites` — deleting a group or user now automatically cleans up related rows and propagates metadata cleanup via the existing trigger. **Behavioral change**: previously, deleting a group or user with existing memberships was blocked by a FK violation; after this upgrade, those deletes will cascade automatically. No existing row data is modified by this upgrade.
- Fix #39: `user_has_group_role` and `user_is_group_member` now return `true` when `auth.role() = 'service_role'`, consistent with service_role bypassing RLS
- Fix #29: `db_pre_request` is now registered with a schema-qualified name (`@extschema@.db_pre_request`) so custom schema installs resolve the function correctly
- Add pgTAP regression tests for all fixed bugs (30 tests across 5 test files)

## 4.0.0

- BREAKING: Remove user_roles view
- BREAKING: Remove delete_group_users function (and trigger on_delete_user)
- BREAKING: Remove update_group_users_email function (and trigger update_group_users_email)
- BREAKING: Modify update_user_roles function to remove the ability to update the user's email in metadata
- Add example view to replace user_roles
- Add example trigger functions to help keep user data synchronized into the group_users metadata
- Updated readme and added a section comparing it to the official supabase RBAC solution

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
