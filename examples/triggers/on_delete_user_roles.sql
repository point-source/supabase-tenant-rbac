CREATE
OR REPLACE FUNCTION my_schema_name.delete_group_users () RETURNS trigger LANGUAGE plpgsql 
set
  search_path = my_schema_name as $function$
BEGIN
    DELETE from my_schema_name.group_users WHERE id = OLD.id;
    RETURN NULL;
END;
$function$;

CREATE TRIGGER on_delete_user_roles INSTEAD OF DELETE ON my_schema_name.user_roles FOR EACH ROW
EXECUTE FUNCTION my_schema_name.delete_group_users();