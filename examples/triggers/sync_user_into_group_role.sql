-- This function syncs user data into a member's metadata field when a member is inserted or updated.
-- Updated for v5.0.0: uses rbac.members instead of group_users.
CREATE OR REPLACE FUNCTION my_schema_name.pull_user_data_into_member()
 RETURNS trigger
 SECURITY DEFINER
 SET search_path TO my_schema_name
AS $$
DECLARE
    user_email text;
    user_meta_data jsonb;
    user_deleted_at timestamptz;
    member_metadata jsonb;
BEGIN
    SELECT email, raw_user_meta_data, deleted_at INTO user_email, user_meta_data, user_deleted_at
    FROM auth.users
    WHERE id = NEW.user_id;

    member_metadata := jsonb_set(
        coalesce(NEW.metadata, '{}'::jsonb),
        '{email}',
        to_jsonb(user_email)
    );
    member_metadata := jsonb_set(
        member_metadata,
        '{first_name}',
        to_jsonb(user_meta_data ->> 'firstName')
    );
    member_metadata := jsonb_set(
        member_metadata,
        '{last_name}',
        to_jsonb(user_meta_data ->> 'lastName')
    );

    IF user_deleted_at IS NOT NULL THEN
        member_metadata := jsonb_set(
            member_metadata,
            '{user_is_deleted}',
            'true'
        );
    END IF;

    NEW.metadata := coalesce(member_metadata, NEW.metadata);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_before_insert_members
BEFORE INSERT ON my_schema_name.members
FOR EACH ROW
EXECUTE PROCEDURE my_schema_name.pull_user_data_into_member();

-- This function syncs user data into member metadata when a user is inserted or updated.
CREATE OR REPLACE FUNCTION my_schema_name.push_user_data_into_members()
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
    IF (TG_OP = 'INSERT') OR (TG_OP = 'UPDATE' AND
        (
            _email IS DISTINCT FROM _email_old
            OR _first_name IS DISTINCT FROM _first_name_old
            OR _last_name IS DISTINCT FROM _last_name_old
            OR new.deleted_at IS DISTINCT FROM old.deleted_at
        )) THEN
        UPDATE members
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
$function$;

CREATE TRIGGER update_members_name
AFTER INSERT OR UPDATE
ON auth.users
FOR EACH ROW
EXECUTE FUNCTION my_schema_name.push_user_data_into_members();
