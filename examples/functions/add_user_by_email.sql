-- NOTE: In v5.0.0, the add_member() RPC function largely supersedes this.
-- Use add_member() with a user UUID instead. This example remains for cases
-- where you need to look up a user by email and add them to a group.

CREATE OR REPLACE FUNCTION my_schema_name.add_member_by_email(
    user_email text,
    gid uuid,
    group_roles text[] DEFAULT ARRAY['viewer']
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = my_schema_name
AS $function$
DECLARE
    uid uuid = auth.uid();
    recipient_id uuid;
    new_record_id uuid;
BEGIN
    IF uid IS NULL THEN
        RAISE EXCEPTION 'not_authorized'
            USING HINT = 'You are not authorized to perform this action';
    END IF;

    IF NOT EXISTS(
        SELECT 1 FROM members m
        WHERE m.user_id = uid AND m.group_id = gid AND 'owner' = ANY(m.roles)
    ) THEN
        RAISE EXCEPTION 'not_authorized'
            USING HINT = 'You are not authorized to perform this action';
    END IF;

    SELECT u.id FROM auth.users u INTO recipient_id WHERE u.email = user_email;

    IF recipient_id IS NULL THEN
        RAISE EXCEPTION 'failed_to_add_user'
            USING HINT = 'User could not be added to group';
    END IF;

    INSERT INTO members (group_id, user_id, roles)
    VALUES (gid, recipient_id, group_roles)
    ON CONFLICT (group_id, user_id)
    DO UPDATE SET roles = (
        SELECT array_agg(DISTINCT r ORDER BY r)
        FROM unnest(members.roles || EXCLUDED.roles) AS r
    )
    RETURNING id INTO new_record_id;

    RETURN new_record_id;
EXCEPTION
    WHEN unique_violation THEN
        RAISE EXCEPTION 'failed_to_add_user'
            USING HINT = 'User could not be added to group';
END;
$function$;
