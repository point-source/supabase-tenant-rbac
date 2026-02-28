-- This view provides user role information by joining members and groups.
-- Updated for v5.0.0: uses members table with roles[] array and groups.name column.
-- Uses unnest(roles) to expand the roles array into individual rows.
CREATE OR REPLACE VIEW my_schema_name.user_roles WITH (security_invoker) AS
SELECT
    m.id,
    g.name,
    unnest(m.roles) AS role,
    COALESCE(m.metadata ->> 'first_name', NULL) AS first_name,
    COALESCE(m.metadata ->> 'last_name', NULL) AS last_name,
    COALESCE(m.metadata ->> 'email', NULL)::varchar(255) AS email,
    COALESCE((m.metadata -> 'user_is_deleted')::bool, false) AS is_deleted,
    m.group_id,
    m.user_id
FROM my_schema_name.members m
JOIN my_schema_name.groups g ON g.id = m.group_id;
