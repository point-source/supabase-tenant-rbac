CREATE
OR REPLACE FUNCTION my_schema_name.add_group_user_by_email (user_email text, gid uuid, group_role text) RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET
    search_path = my_schema_name AS $function$
	declare
		uid uuid = auth.uid();
		recipient_id uuid;
		new_record_id uuid;
	BEGIN
		if uid is null then
			raise exception 'not_authorized' using hint = 'You are are not authorized to perform this action';
		end if;
	
		if not exists(select id from group_users gu where gu.user_id = uid AND gu.group_id = gid AND gu.role = 'owner') then
			raise exception 'not_authorized' using hint = 'You are are not authorized to perform this action';
		end if;
	
		select u.id from auth.users u into recipient_id where u.email = user_email;
	
		if recipient_id is null then
			raise exception 'failed_to_add_user' using hint = 'User could not be added to group';
		end if;
	
		INSERT INTO group_users (group_id, user_id, role) VALUES (gid, recipient_id, group_role) returning id into new_record_id;
	
		return new_record_id;
	exception
		when unique_violation then
			raise exception 'failed_to_add_user' using hint = 'User could not be added to group';
	END;
$function$;