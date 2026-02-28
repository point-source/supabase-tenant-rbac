-- NOTE: In v5.0.0, the create_group() RPC function automatically adds the caller
-- as a member with specified roles. This trigger is largely superseded by that RPC.
-- Use this only if you need to handle group creation via direct INSERT rather than RPC.

CREATE OR REPLACE FUNCTION my_schema_name.set_group_owner()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = my_schema_name
AS $function$
BEGIN
    IF auth.uid() IS NOT NULL THEN
        INSERT INTO my_schema_name.members (group_id, user_id, roles)
        VALUES (NEW.id, auth.uid(), ARRAY[
            'group.update', 'group.delete',
            'group_data.create', 'group_data.read', 'group_data.update', 'group_data.delete',
            'group_user.create', 'group_user.read', 'group_user.update', 'group_user.delete',
            'group_user.invite'
        ]);
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER on_insert_set_group_owner
AFTER INSERT ON my_schema_name.groups FOR EACH ROW
EXECUTE FUNCTION my_schema_name.set_group_owner();
