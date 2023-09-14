set check_function_bodies = off;

CREATE OR REPLACE FUNCTION public.set_group_owner()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
	begin
		IF auth.uid() IS not NULL THEN 
		insert into public.group_users(group_id, user_id, role) values(new.id, auth.uid(), 'owner');
		end if;
		return new;
	end;
$function$
;

CREATE TRIGGER on_insert_set_group_owner AFTER INSERT ON public.groups FOR EACH ROW EXECUTE FUNCTION set_group_owner();


