# Changelog

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
