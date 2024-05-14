CREATE
OR REPLACE FUNCTION my_schema_name.set_group_owner () RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET
	search_path = my_schema_name AS $function$
	begin
		IF auth.uid() IS not NULL THEN 
			insert into group_users(group_id, user_id, role) 
			values
				(new.id, auth.uid(), 'owner'),
				(new.id, auth.uid(), 'admin');
		end if;
		return new;
	end;
$function$;

CREATE TRIGGER on_insert_set_group_owner
AFTER INSERT ON groups FOR EACH ROW
EXECUTE FUNCTION set_group_owner ();