-- This view is used to get the user role information. 
-- It adds a view convenience fields by joining the group_users and groups tables and eleveting the metadata fields to the top level.
-- In order to keep the metadata fields populated and up to date, the triggers in the examples/triggers directory should be used.
create or replace view my_schema_name.user_roles with (security_invoker) as  SELECT gu.id,
    COALESCE(g.metadata ->> 'name', NULL) AS "name",
    gu.role,
    COALESCE(gu.metadata ->> 'first_name', NULL) AS "first_name",
    COALESCE(gu.metadata ->> 'last_name', NULL) AS "last_name",
    COALESCE(gu.metadata ->> 'email', NULL)::varchar(255) AS email,
    COALESCE((gu.metadata -> 'user_is_deleted')::bool, false) AS "is_deleted",
    gu.group_id,
    gu.user_id
   FROM (my_schema_name.group_users gu JOIN my_schema_name.groups g ON (g.id = gu.group_id));