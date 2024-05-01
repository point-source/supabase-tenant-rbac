# Changelog

## 1.0.0

- BREAKING: Replace get_req_groups with get_user_claims
- BREAKING: Rename is_group_member to user_is_group_member
- BREAKING: Rename has_group_role to user_has_group_role
- BREAKING: Remove jwt methods (primary methods are now performant enough)
- BREAKING: Invite system now accepts multiple roles in a single invite (fixes #20)
- Mark remaining read-only methods as stable
- Use auth.role() to determine authentication type (fixes #15)
- Set search paths for security definer functions to "public" (fixes #18)

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