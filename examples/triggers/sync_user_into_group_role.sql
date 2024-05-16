-- This function syncs user data into a group role metadata field when a group user is inserted or updated.
CREATE OR REPLACE FUNCTION my_schema_name.pull_user_data_into_group_user()
 RETURNS trigger
 SECURITY DEFINER
 SET search_path TO my_schema_name
AS $$
DECLARE
    user_email text;
    user_meta_data jsonb;
    user_deleted_at timestamptz;
    group_user_metadata jsonb;
BEGIN
    -- Retrieve the 'raw_user_meta_data' JSON from the 'auth.users' table
    SELECT email, raw_user_meta_data, deleted_at INTO user_email, user_meta_data, user_deleted_at
    FROM auth.users
    WHERE id = NEW.user_id;

    -- Merge existing metadata with new 'first_name' and 'last_name' keys
    -- Ensure existing metadata is not overwritten, but updated with the new keys
    group_user_metadata := jsonb_set(
        coalesce(NEW.metadata, '{}'::jsonb), -- use existing metadata, or initialize it as an empty JSON object if NULL
        '{email}', -- path to set 'email'
        to_jsonb(user_email)
    );
    group_user_metadata := jsonb_set(
        group_user_metadata, -- start with the updated metadata from above
        '{first_name}', -- path to set 'first_name'
        to_jsonb(user_meta_data ->> 'firstName') -- value to set for 'first_name'
    );
    group_user_metadata := jsonb_set(
        group_user_metadata, -- start with the updated metadata from above
        '{last_name}', -- path to set 'last_name'
        to_jsonb(user_meta_data ->> 'lastName') -- value to set for 'last_name'
    );

    -- Check if 'deleted_at' is not null and if so, mark the user as deleted
    IF user_deleted_at IS NOT NULL THEN
        group_user_metadata := jsonb_set(
            group_user_metadata,
            '{user_is_deleted}',
            'true'
        );
    END IF;

    NEW.metadata := coalesce(group_user_metadata, NEW.metadata);

    -- Return the modified NEW row to continue with the insert operation
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_before_insert_group_users
BEFORE INSERT ON my_schema_name.group_users
FOR EACH ROW
EXECUTE PROCEDURE my_schema_name.pull_user_data_into_group_user();

-- This function syncs user data into a group role metadata field when a user is inserted or updated.
CREATE OR REPLACE FUNCTION my_schema_name.push_user_data_into_group_users()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO my_schema_name
AS $function$
DECLARE
  _email text = new.email;
  _email_old text = old.email;
  _first_name text = new.raw_user_meta_data->'firstName';
  _first_name_old text = old.raw_user_meta_data->'firstName';
  _last_name text = new.raw_user_meta_data->'lastName';
  _last_name_old text = old.raw_user_meta_data->'lastName';
BEGIN
    -- Check if the email was changed or it is a new insertion
    IF (TG_OP = 'INSERT') OR (TG_OP = 'UPDATE' AND 
        (
            _email IS DISTINCT FROM _email_old
            OR _first_name IS DISTINCT FROM _first_name_old 
            OR _last_name IS DISTINCT FROM _last_name_old
            OR new.deleted_at IS DISTINCT FROM old.deleted_at

        )) THEN
        -- Update the names in the metadata of group_users
        UPDATE group_users
        SET metadata = jsonb_set(
            jsonb_set(
                jsonb_set(
                    jsonb_set(
                        metadata, 
                        '{email}', 
                        to_jsonb(_email)
                    ), 
                    '{first_name}', 
                    _first_name::jsonb
                ), 
                '{last_name}', 
                _last_name::jsonb
            ), 
            '{user_is_deleted}', 
            to_jsonb(new.deleted_at IS NOT NULL)
        )
        WHERE user_id = NEW.id;
    END IF;

    RETURN NEW;
END;
$function$
;

CREATE TRIGGER update_group_users_name
AFTER INSERT OR UPDATE
ON auth.users
FOR EACH ROW
EXECUTE FUNCTION my_schema_name.push_user_data_into_group_users();
