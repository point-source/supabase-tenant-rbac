-- INSTEAD OF DELETE trigger for the user_roles view.
-- Updated for v5.0.0: references members instead of group_users.
CREATE OR REPLACE FUNCTION my_schema_name.delete_member()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = my_schema_name
AS $function$
BEGIN
    DELETE FROM my_schema_name.members WHERE id = OLD.id;
    RETURN NULL;
END;
$function$;

CREATE TRIGGER on_delete_user_roles INSTEAD OF DELETE ON my_schema_name.user_roles FOR EACH ROW
EXECUTE FUNCTION my_schema_name.delete_member();
