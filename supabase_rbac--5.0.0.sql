-- ═══════════════════════════════════════════════════════════════════════════════
-- supabase_rbac v5.0.0 — Multi-Tenant RBAC for Supabase
-- ═══════════════════════════════════════════════════════════════════════════════
-- Install in a dedicated schema (e.g. rbac) that is NOT in PostgREST's exposed
-- schemas. Tables are accessed exclusively through RPC functions. Public wrapper
-- functions are auto-created at the end of this file when @extschema@ != 'public'.

-- ─────────────────────────────────────────────────────────────────────────────
-- TABLES
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE @extschema@.groups (
    id         uuid        NOT NULL DEFAULT gen_random_uuid(),
    name       text        NOT NULL,
    metadata   jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE @extschema@.members (
    id         uuid        NOT NULL DEFAULT gen_random_uuid(),
    group_id   uuid        NOT NULL,
    user_id    uuid        NOT NULL,
    roles      text[]      NOT NULL DEFAULT '{}'::text[],
    metadata   jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE @extschema@.invites (
    id          uuid        NOT NULL DEFAULT gen_random_uuid(),
    group_id    uuid        NOT NULL,
    roles       text[]      NOT NULL DEFAULT '{}'::text[] CHECK (cardinality(roles) > 0),
    invited_by  uuid        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    user_id     uuid,
    accepted_at timestamptz,
    expires_at  timestamptz
);

CREATE TABLE @extschema@.roles (
    name        text        PRIMARY KEY,
    description text,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Pre-seed the 'owner' role (used as the default in create_group)
INSERT INTO @extschema@.roles (name, description)
VALUES ('owner', 'Group creator with full administrative permissions');

-- Claims cache: one row per user, auto-managed by _sync_member_metadata trigger.
-- ON DELETE CASCADE handles cleanup when a user is deleted from auth.users.
CREATE TABLE @extschema@.user_claims (
    user_id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    claims  jsonb NOT NULL DEFAULT '{}'::jsonb
);

-- ─────────────────────────────────────────────────────────────────────────────
-- INDEXES & CONSTRAINTS
-- ─────────────────────────────────────────────────────────────────────────────

-- groups
CREATE UNIQUE INDEX groups_pkey ON @extschema@.groups USING btree (id);
ALTER TABLE @extschema@.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY USING INDEX groups_pkey;

-- members
CREATE UNIQUE INDEX members_pkey ON @extschema@.members USING btree (id);
ALTER TABLE @extschema@.members
    ADD CONSTRAINT members_pkey PRIMARY KEY USING INDEX members_pkey;

CREATE UNIQUE INDEX members_group_user_idx ON @extschema@.members USING btree (group_id, user_id);
CREATE INDEX members_user_id_idx ON @extschema@.members USING btree (user_id);

ALTER TABLE @extschema@.members
    ADD CONSTRAINT members_group_id_fkey FOREIGN KEY (group_id)
    REFERENCES @extschema@.groups (id) ON DELETE CASCADE NOT VALID;
ALTER TABLE @extschema@.members VALIDATE CONSTRAINT members_group_id_fkey;

ALTER TABLE @extschema@.members
    ADD CONSTRAINT members_user_id_fkey FOREIGN KEY (user_id)
    REFERENCES auth.users (id) ON DELETE CASCADE NOT VALID;
ALTER TABLE @extschema@.members VALIDATE CONSTRAINT members_user_id_fkey;

-- invites
CREATE UNIQUE INDEX invites_pkey ON @extschema@.invites USING btree (id);
ALTER TABLE @extschema@.invites
    ADD CONSTRAINT invites_pkey PRIMARY KEY USING INDEX invites_pkey;

ALTER TABLE @extschema@.invites
    ADD CONSTRAINT invites_group_id_fkey FOREIGN KEY (group_id)
    REFERENCES @extschema@.groups (id) ON DELETE CASCADE NOT VALID;
ALTER TABLE @extschema@.invites VALIDATE CONSTRAINT invites_group_id_fkey;

ALTER TABLE @extschema@.invites
    ADD CONSTRAINT invites_invited_by_fkey FOREIGN KEY (invited_by)
    REFERENCES auth.users (id) ON DELETE CASCADE NOT VALID;
ALTER TABLE @extschema@.invites VALIDATE CONSTRAINT invites_invited_by_fkey;

ALTER TABLE @extschema@.invites
    ADD CONSTRAINT invites_user_id_fkey FOREIGN KEY (user_id)
    REFERENCES auth.users (id) ON DELETE CASCADE NOT VALID;
ALTER TABLE @extschema@.invites VALIDATE CONSTRAINT invites_user_id_fkey;

-- ─────────────────────────────────────────────────────────────────────────────
-- ROW LEVEL SECURITY (deny-all by default — consumers add policies)
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE @extschema@.groups      ENABLE ROW LEVEL SECURITY;
ALTER TABLE @extschema@.members     ENABLE ROW LEVEL SECURITY;
ALTER TABLE @extschema@.invites     ENABLE ROW LEVEL SECURITY;
ALTER TABLE @extschema@.roles       ENABLE ROW LEVEL SECURITY;
ALTER TABLE @extschema@.user_claims ENABLE ROW LEVEL SECURITY;

-- ─────────────────────────────────────────────────────────────────────────────
-- INTERNAL FUNCTIONS
-- ─────────────────────────────────────────────────────────────────────────────

-- Replaces moddatetime dependency — inline updated_at trigger
CREATE OR REPLACE FUNCTION @extschema@._set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$function$;

-- JWT expiry check (internal, underscore-prefixed)
CREATE OR REPLACE FUNCTION @extschema@._jwt_is_expired()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SET search_path = @extschema@
AS $function$
BEGIN
    RETURN extract(epoch FROM now()) > coalesce(auth.jwt()->>'exp', '0')::numeric;
END;
$function$;

-- Direct DB read of user claims — reads extension-owned user_claims table.
-- Wraps the subquery so NULL auth.uid() returns '{}' instead of NULL.
CREATE OR REPLACE FUNCTION @extschema@._get_user_groups()
RETURNS jsonb
LANGUAGE sql
STABLE
-- No SECURITY DEFINER — reads extension-owned user_claims table
SET search_path = @extschema@
AS $function$
    SELECT coalesce(
        (SELECT claims FROM @extschema@.user_claims WHERE user_id = auth.uid()),
        '{}'
    )
$function$;

-- PostgREST pre-request hook — reads user_claims on every API request
CREATE OR REPLACE FUNCTION @extschema@.db_pre_request()
RETURNS void
LANGUAGE plpgsql
STABLE
-- No SECURITY DEFINER — reads extension-owned user_claims table
SET search_path = @extschema@
AS $function$
DECLARE
    groups jsonb;
BEGIN
    SELECT claims INTO groups FROM @extschema@.user_claims WHERE user_id = auth.uid();
    PERFORM set_config('request.groups'::text, coalesce(groups, '{}')::text, false);
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.db_pre_request() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.db_pre_request() TO authenticator;

-- Validate that all roles in an array exist in the roles table.
-- Raises a descriptive error listing any undefined roles.
CREATE OR REPLACE FUNCTION @extschema@._validate_roles(p_roles text[])
RETURNS void
LANGUAGE plpgsql
STABLE
SET search_path = @extschema@
AS $function$
DECLARE
    _undefined text[];
BEGIN
    IF p_roles IS NULL OR cardinality(p_roles) = 0 THEN
        RETURN;
    END IF;

    SELECT array_agg(r)
    INTO _undefined
    FROM unnest(p_roles) AS r
    WHERE r NOT IN (SELECT name FROM @extschema@.roles);

    IF _undefined IS NOT NULL THEN
        RAISE EXCEPTION 'Undefined roles: %', array_to_string(_undefined, ', ')
            USING HINT = 'Add these roles to the roles table first';
    END IF;
END;
$function$;

-- Trigger function: rebuild user's entire claims from members table
-- Fires on INSERT/UPDATE/DELETE on members
CREATE OR REPLACE FUNCTION @extschema@._sync_member_metadata()
RETURNS trigger
LANGUAGE plpgsql
-- No SECURITY DEFINER — writes to extension-owned user_claims table
SET search_path = @extschema@
AS $function$
DECLARE
    _user_id     uuid;
    _user_id_old uuid;
    _group_id     uuid;
    _group_id_old uuid;
    _new_groups  jsonb;
BEGIN
    _user_id     := coalesce(NEW.user_id, OLD.user_id);
    _user_id_old := coalesce(OLD.user_id, NEW.user_id);
    _group_id     := coalesce(NEW.group_id, OLD.group_id);
    _group_id_old := coalesce(OLD.group_id, NEW.group_id);

    -- Block changing user_id or group_id
    IF TG_OP = 'UPDATE' THEN
        IF _user_id IS DISTINCT FROM _user_id_old OR _group_id IS DISTINCT FROM _group_id_old THEN
            RAISE EXCEPTION 'Changing user_id or group_id is not allowed';
        END IF;
    END IF;

    -- Rebuild full claims for this user from the members table
    SELECT coalesce(
        jsonb_object_agg(m.group_id::text, to_jsonb(m.roles)),
        '{}'::jsonb
    )
    INTO _new_groups
    FROM @extschema@.members m
    WHERE m.user_id = _user_id;

    -- Upsert into user_claims (ON DELETE CASCADE handles deleted users automatically)
    INSERT INTO @extschema@.user_claims (user_id, claims)
    VALUES (_user_id, _new_groups)
    ON CONFLICT (user_id) DO UPDATE SET claims = EXCLUDED.claims;

    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;

EXCEPTION WHEN foreign_key_violation THEN
    -- user_id no longer exists in auth.users (deleted concurrently) — skip silently
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$function$;

-- ─────────────────────────────────────────────────────────────────────────────
-- RLS / CLAIMS HELPERS
-- ─────────────────────────────────────────────────────────────────────────────

-- Returns current user's group/role claims
CREATE OR REPLACE FUNCTION @extschema@.get_claims()
RETURNS jsonb
LANGUAGE sql
STABLE
SET search_path = @extschema@
AS $function$
    SELECT coalesce(
        nullif(current_setting('request.groups', true), '')::jsonb,
        _get_user_groups()
    )::jsonb
$function$;

-- Check if user has a specific role in a group
CREATE OR REPLACE FUNCTION @extschema@.has_role(group_id uuid, role text)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SET search_path = @extschema@
AS $function$
DECLARE
    auth_role text := auth.role();
    retval bool;
BEGIN
    IF auth_role = 'authenticated' THEN
        IF _jwt_is_expired() THEN
            RAISE EXCEPTION 'invalid_jwt' USING HINT = 'jwt is expired or missing';
        END IF;
        SELECT coalesce(get_claims()->group_id::text ? role, false) INTO retval;
        RETURN retval;
    ELSIF auth_role = 'anon' THEN
        RETURN false;
    ELSE
        IF session_user = 'postgres' OR auth_role = 'service_role' THEN
            RETURN true;
        ELSE
            RETURN false;
        END IF;
    END IF;
END;
$function$;

-- Check if user is a member of a group (any role)
CREATE OR REPLACE FUNCTION @extschema@.is_member(group_id uuid)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SET search_path = @extschema@
AS $function$
DECLARE
    auth_role text := auth.role();
    retval bool;
BEGIN
    IF auth_role = 'authenticated' THEN
        IF _jwt_is_expired() THEN
            RAISE EXCEPTION 'invalid_jwt' USING HINT = 'jwt is expired or missing';
        END IF;
        SELECT coalesce(get_claims() ? group_id::text, false) INTO retval;
        RETURN retval;
    ELSIF auth_role = 'anon' THEN
        RETURN false;
    ELSE
        IF session_user = 'postgres' OR auth_role = 'service_role' THEN
            RETURN true;
        ELSE
            RETURN false;
        END IF;
    END IF;
END;
$function$;

-- Check if user has ANY of the listed roles in a group
CREATE OR REPLACE FUNCTION @extschema@.has_any_role(group_id uuid, roles text[])
RETURNS boolean
LANGUAGE plpgsql
STABLE
SET search_path = @extschema@
AS $function$
DECLARE
    auth_role text := auth.role();
    retval bool;
BEGIN
    IF auth_role = 'authenticated' THEN
        IF _jwt_is_expired() THEN
            RAISE EXCEPTION 'invalid_jwt' USING HINT = 'jwt is expired or missing';
        END IF;
        SELECT coalesce(get_claims()->group_id::text ?| roles, false) INTO retval;
        RETURN retval;
    ELSIF auth_role = 'anon' THEN
        RETURN false;
    ELSE
        IF session_user = 'postgres' OR auth_role = 'service_role' THEN
            RETURN true;
        ELSE
            RETURN false;
        END IF;
    END IF;
END;
$function$;

-- Check if user has ALL of the listed roles in a group
CREATE OR REPLACE FUNCTION @extschema@.has_all_roles(group_id uuid, roles text[])
RETURNS boolean
LANGUAGE plpgsql
STABLE
SET search_path = @extschema@
AS $function$
DECLARE
    auth_role text := auth.role();
    retval bool;
BEGIN
    IF auth_role = 'authenticated' THEN
        IF _jwt_is_expired() THEN
            RAISE EXCEPTION 'invalid_jwt' USING HINT = 'jwt is expired or missing';
        END IF;
        SELECT coalesce(get_claims()->group_id::text ?& roles, false) INTO retval;
        RETURN retval;
    ELSIF auth_role = 'anon' THEN
        RETURN false;
    ELSE
        IF session_user = 'postgres' OR auth_role = 'service_role' THEN
            RETURN true;
        ELSE
            RETURN false;
        END IF;
    END IF;
END;
$function$;

-- ─────────────────────────────────────────────────────────────────────────────
-- MANAGEMENT RPCs
-- ─────────────────────────────────────────────────────────────────────────────

-- Create a group and add the caller as a member with creator_roles.
-- SECURITY DEFINER because the caller has no prior membership (cannot pass RLS).
CREATE OR REPLACE FUNCTION @extschema@.create_group(
    p_name          text,
    p_metadata      jsonb  DEFAULT '{}'::jsonb,
    p_creator_roles text[] DEFAULT ARRAY['owner']
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = @extschema@
AS $function$
DECLARE
    _user_id  uuid := auth.uid();
    _group_id uuid;
BEGIN
    IF _user_id IS NULL THEN
        RAISE EXCEPTION 'Not authenticated';
    END IF;

    PERFORM _validate_roles(p_creator_roles);

    INSERT INTO @extschema@.groups (name, metadata)
    VALUES (p_name, p_metadata)
    RETURNING id INTO _group_id;

    INSERT INTO @extschema@.members (group_id, user_id, roles)
    VALUES (_group_id, _user_id, p_creator_roles);

    RETURN _group_id;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.create_group(text, jsonb, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.create_group(text, jsonb, text[]) TO authenticated;

-- Delete a group. SECURITY INVOKER — RLS enforced.
CREATE OR REPLACE FUNCTION @extschema@.delete_group(p_group_id uuid)
RETURNS void
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
BEGIN
    DELETE FROM @extschema@.groups WHERE id = p_group_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Group not found or not authorized';
    END IF;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.delete_group(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.delete_group(uuid) TO authenticated;

-- Add a member to a group (or merge roles if already a member).
-- SECURITY INVOKER — RLS on members enforced.
CREATE OR REPLACE FUNCTION @extschema@.add_member(
    p_group_id uuid,
    p_user_id  uuid,
    p_roles    text[] DEFAULT '{}'::text[]
)
RETURNS uuid
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
DECLARE
    _member_id uuid;
BEGIN
    PERFORM _validate_roles(p_roles);

    INSERT INTO @extschema@.members (group_id, user_id, roles)
    VALUES (p_group_id, p_user_id, p_roles)
    ON CONFLICT (group_id, user_id)
    DO UPDATE SET roles = (
        SELECT array_agg(DISTINCT r ORDER BY r)
        FROM unnest(members.roles || EXCLUDED.roles) AS r
    )
    RETURNING id INTO _member_id;

    RETURN _member_id;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.add_member(uuid, uuid, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.add_member(uuid, uuid, text[]) TO authenticated;

-- Remove a member from a group. SECURITY INVOKER — RLS enforced.
CREATE OR REPLACE FUNCTION @extschema@.remove_member(p_group_id uuid, p_user_id uuid)
RETURNS void
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
BEGIN
    DELETE FROM @extschema@.members
    WHERE group_id = p_group_id AND user_id = p_user_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Member not found or not authorized';
    END IF;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.remove_member(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.remove_member(uuid, uuid) TO authenticated;

-- Replace the roles array for a member. SECURITY INVOKER — RLS enforced.
CREATE OR REPLACE FUNCTION @extschema@.update_member_roles(
    p_group_id uuid,
    p_user_id  uuid,
    p_roles    text[]
)
RETURNS void
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
BEGIN
    PERFORM _validate_roles(p_roles);

    UPDATE @extschema@.members
    SET roles = p_roles
    WHERE group_id = p_group_id AND user_id = p_user_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Member not found or not authorized';
    END IF;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.update_member_roles(uuid, uuid, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.update_member_roles(uuid, uuid, text[]) TO authenticated;

-- List members of a group. SECURITY INVOKER — RLS enforced.
CREATE OR REPLACE FUNCTION @extschema@.list_members(p_group_id uuid)
RETURNS TABLE(id uuid, user_id uuid, roles text[], metadata jsonb, created_at timestamptz)
LANGUAGE plpgsql
STABLE
SET search_path = @extschema@
AS $function$
BEGIN
    RETURN QUERY
    SELECT m.id, m.user_id, m.roles, m.metadata, m.created_at
    FROM @extschema@.members m
    WHERE m.group_id = p_group_id;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.list_members(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.list_members(uuid) TO authenticated;

-- Accept an invite. SECURITY DEFINER — bypasses RLS for atomic acceptance.
CREATE OR REPLACE FUNCTION @extschema@.accept_invite(p_invite_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = @extschema@
AS $function$
DECLARE
    _user_id uuid := auth.uid();
    _invite  record;
BEGIN
    IF _user_id IS NULL THEN
        RAISE EXCEPTION 'Not authenticated';
    END IF;

    -- Lock the invite row to prevent concurrent acceptance races
    SELECT * INTO _invite FROM @extschema@.invites
    WHERE id = p_invite_id
      AND user_id IS NULL
      AND accepted_at IS NULL
      AND (expires_at IS NULL OR expires_at > now())
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invite not found, already used, or expired';
    END IF;

    -- Validate that the roles on this invite still exist
    PERFORM _validate_roles(_invite.roles);

    -- Mark invite as accepted
    UPDATE @extschema@.invites
    SET user_id = _user_id, accepted_at = now()
    WHERE id = p_invite_id;

    -- Upsert membership — merge roles if already a member
    INSERT INTO @extschema@.members (group_id, user_id, roles)
    VALUES (_invite.group_id, _user_id, _invite.roles)
    ON CONFLICT (group_id, user_id)
    DO UPDATE SET roles = (
        SELECT array_agg(DISTINCT r ORDER BY r)
        FROM unnest(members.roles || EXCLUDED.roles) AS r
    );
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.accept_invite(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.accept_invite(uuid) TO authenticated;

-- Create a role definition. SECURITY INVOKER — RLS on roles table enforced.
CREATE OR REPLACE FUNCTION @extschema@.create_role(p_name text, p_description text DEFAULT NULL)
RETURNS void
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
BEGIN
    INSERT INTO @extschema@.roles (name, description)
    VALUES (p_name, p_description);
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.create_role(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.create_role(text, text) TO authenticated;

-- Delete a role definition. Refuses if any member uses this role.
-- SECURITY INVOKER — RLS on roles table enforced.
CREATE OR REPLACE FUNCTION @extschema@.delete_role(p_name text)
RETURNS void
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
BEGIN
    -- Check if any member has this role
    IF EXISTS (
        SELECT 1 FROM @extschema@.members WHERE p_name = ANY(roles)
    ) THEN
        RAISE EXCEPTION 'Role "%" is in use by one or more members', p_name
            USING HINT = 'Remove this role from all members before deleting it';
    END IF;

    DELETE FROM @extschema@.roles WHERE name = p_name;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Role "%" not found or not authorized', p_name;
    END IF;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.delete_role(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.delete_role(text) TO authenticated;

-- List all role definitions. SECURITY INVOKER — RLS on roles table enforced.
CREATE OR REPLACE FUNCTION @extschema@.list_roles()
RETURNS TABLE(name text, description text, created_at timestamptz)
LANGUAGE plpgsql
STABLE
SET search_path = @extschema@
AS $function$
BEGIN
    RETURN QUERY
    SELECT r.name, r.description, r.created_at
    FROM @extschema@.roles r
    ORDER BY r.name;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.list_roles() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.list_roles() TO authenticated;

-- Supabase Auth Hook: injects group claims into JWT at token creation time.
-- Register in config.toml: [auth.hook.custom_access_token]
-- uri = "pg-functions://postgres/public/custom_access_token_hook"
CREATE OR REPLACE FUNCTION @extschema@.custom_access_token_hook(event jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
-- No SECURITY DEFINER — reads extension-owned user_claims table
SET search_path = @extschema@
AS $function$
DECLARE
    claims      jsonb;
    user_groups jsonb;
BEGIN
    claims := event->'claims';

    SELECT uc.claims INTO user_groups
    FROM @extschema@.user_claims uc
    WHERE uc.user_id = (event->>'user_id')::uuid;

    -- Merge groups into app_metadata in the JWT claims
    claims := jsonb_set(
        claims,
        '{app_metadata}',
        coalesce(claims->'app_metadata', '{}'::jsonb)
            || jsonb_build_object('groups', coalesce(user_groups, '{}'::jsonb))
    );

    event := jsonb_set(event, '{claims}', claims);
    RETURN event;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.custom_access_token_hook(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.custom_access_token_hook(jsonb) TO supabase_auth_admin;

-- ─────────────────────────────────────────────────────────────────────────────
-- GRANTS
-- ─────────────────────────────────────────────────────────────────────────────

-- Schema access for SECURITY INVOKER RPCs
GRANT USAGE ON SCHEMA @extschema@ TO authenticated, anon, service_role;
-- authenticator needs schema access for db_pre_request() (now SECURITY INVOKER)
-- supabase_auth_admin needs schema access for custom_access_token_hook()
GRANT USAGE ON SCHEMA @extschema@ TO authenticator, supabase_auth_admin;

-- Table DML grants (RLS controls which rows)
GRANT SELECT, INSERT, UPDATE, DELETE ON @extschema@.groups  TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON @extschema@.members TO authenticated;
GRANT SELECT, UPDATE ON @extschema@.invites TO authenticated;
GRANT SELECT, INSERT, DELETE ON @extschema@.roles TO authenticated;

-- user_claims: authenticated needs INSERT/UPDATE for the trigger (runs as authenticated
-- when fired by SECURITY INVOKER RPCs like add_member/remove_member/update_member_roles).
-- SELECT is needed for _get_user_groups() fallback (Storage RLS path).
GRANT SELECT, INSERT, UPDATE ON @extschema@.user_claims TO authenticated;
-- authenticator needs SELECT for db_pre_request() (SECURITY INVOKER, runs as authenticator)
GRANT SELECT ON @extschema@.user_claims TO authenticator;
-- supabase_auth_admin needs SELECT for custom_access_token_hook()
GRANT SELECT ON @extschema@.user_claims TO supabase_auth_admin;

GRANT ALL ON ALL TABLES IN SCHEMA @extschema@ TO service_role;

-- ─────────────────────────────────────────────────────────────────────────────
-- TRIGGERS
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TRIGGER handle_updated_at
    BEFORE UPDATE ON @extschema@.groups
    FOR EACH ROW EXECUTE FUNCTION @extschema@._set_updated_at();

CREATE TRIGGER handle_updated_at
    BEFORE UPDATE ON @extschema@.members
    FOR EACH ROW EXECUTE FUNCTION @extschema@._set_updated_at();

CREATE TRIGGER on_change_sync_member_metadata
    AFTER INSERT OR DELETE OR UPDATE ON @extschema@.members
    FOR EACH ROW EXECUTE FUNCTION @extschema@._sync_member_metadata();

-- ─────────────────────────────────────────────────────────────────────────────
-- POSTGREST HOOK
-- ─────────────────────────────────────────────────────────────────────────────

ALTER ROLE authenticator SET pgrst.db_pre_request TO '@extschema@.db_pre_request';
NOTIFY pgrst, 'reload config';

-- ═══════════════════════════════════════════════════════════════════════════════
-- PUBLIC API WRAPPERS
-- When this extension is installed in a non-public schema (e.g. rbac), these
-- thin wrapper functions are created in the public schema so that:
--   1. PostgREST can discover them for RPC calls (supabase.rpc('has_role',...))
--   2. RLS policies can use unqualified names: USING (has_role(group_id, 'admin'))
--
-- These wrappers are tracked as extension members — DROP EXTENSION removes them.
-- To remove individual wrappers: DROP FUNCTION public.<name>(<signature>);
-- To remove all wrappers, see: examples/setup/remove_public_wrappers.sql
-- ═══════════════════════════════════════════════════════════════════════════════

DO $wrapper$ BEGIN
IF '@extschema@' <> 'public' THEN

    -- ── RLS / Claims helpers ────────────────────────────────────────────────

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.get_claims()
        RETURNS jsonb LANGUAGE sql STABLE
        SET search_path = @extschema@
        AS $f$ SELECT @extschema@.get_claims() $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.has_role(group_id uuid, role text)
        RETURNS boolean LANGUAGE sql STABLE
        SET search_path = @extschema@
        AS $f$ SELECT @extschema@.has_role($1, $2) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.is_member(group_id uuid)
        RETURNS boolean LANGUAGE sql STABLE
        SET search_path = @extschema@
        AS $f$ SELECT @extschema@.is_member($1) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.has_any_role(group_id uuid, roles text[])
        RETURNS boolean LANGUAGE sql STABLE
        SET search_path = @extschema@
        AS $f$ SELECT @extschema@.has_any_role($1, $2) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.has_all_roles(group_id uuid, roles text[])
        RETURNS boolean LANGUAGE sql STABLE
        SET search_path = @extschema@
        AS $f$ SELECT @extschema@.has_all_roles($1, $2) $f$
    $sql$;

    -- ── Management RPCs ─────────────────────────────────────────────────────

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.create_group(
            p_name text, p_metadata jsonb DEFAULT '{}'::jsonb, p_creator_roles text[] DEFAULT ARRAY['owner']
        )
        RETURNS uuid LANGUAGE sql SECURITY DEFINER
        SET search_path = @extschema@
        AS $f$ SELECT @extschema@.create_group($1, $2, $3) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.delete_group(p_group_id uuid)
        RETURNS void LANGUAGE sql
        SET search_path = @extschema@
        AS $f$ SELECT @extschema@.delete_group($1) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.add_member(
            p_group_id uuid, p_user_id uuid, p_roles text[] DEFAULT '{}'::text[]
        )
        RETURNS uuid LANGUAGE sql
        SET search_path = @extschema@
        AS $f$ SELECT @extschema@.add_member($1, $2, $3) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.remove_member(p_group_id uuid, p_user_id uuid)
        RETURNS void LANGUAGE sql
        SET search_path = @extschema@
        AS $f$ SELECT @extschema@.remove_member($1, $2) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.update_member_roles(
            p_group_id uuid, p_user_id uuid, p_roles text[]
        )
        RETURNS void LANGUAGE sql
        SET search_path = @extschema@
        AS $f$ SELECT @extschema@.update_member_roles($1, $2, $3) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.list_members(p_group_id uuid)
        RETURNS TABLE(id uuid, user_id uuid, roles text[], metadata jsonb, created_at timestamptz)
        LANGUAGE sql STABLE
        SET search_path = @extschema@
        AS $f$ SELECT * FROM @extschema@.list_members($1) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.accept_invite(p_invite_id uuid)
        RETURNS void LANGUAGE sql SECURITY DEFINER
        SET search_path = @extschema@
        AS $f$ SELECT @extschema@.accept_invite($1) $f$
    $sql$;

    -- ── Role management RPCs ────────────────────────────────────────────────

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.create_role(p_name text, p_description text DEFAULT NULL)
        RETURNS void LANGUAGE sql
        SET search_path = @extschema@
        AS $f$ SELECT @extschema@.create_role($1, $2) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.delete_role(p_name text)
        RETURNS void LANGUAGE sql
        SET search_path = @extschema@
        AS $f$ SELECT @extschema@.delete_role($1) $f$
    $sql$;

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.list_roles()
        RETURNS TABLE(name text, description text, created_at timestamptz)
        LANGUAGE sql STABLE
        SET search_path = @extschema@
        AS $f$ SELECT * FROM @extschema@.list_roles() $f$
    $sql$;

    -- ── Auth Hook wrapper ────────────────────────────────────────────────────

    EXECUTE $sql$
        CREATE OR REPLACE FUNCTION public.custom_access_token_hook(event jsonb)
        RETURNS jsonb LANGUAGE sql STABLE
        SET search_path = @extschema@
        AS $f$ SELECT @extschema@.custom_access_token_hook($1) $f$
    $sql$;

    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.custom_access_token_hook(jsonb) FROM PUBLIC';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.custom_access_token_hook(jsonb) TO supabase_auth_admin';

    -- ── REVOKE / GRANT on public wrappers ───────────────────────────────────

    -- RLS helpers: accessible to authenticated (Supabase also grants to anon/service_role
    -- on all public functions, which is fine — the functions handle auth tiers internally)
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.get_claims() FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.has_role(uuid, text) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.is_member(uuid) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.has_any_role(uuid, text[]) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.has_all_roles(uuid, text[]) FROM PUBLIC';

    EXECUTE 'GRANT EXECUTE ON FUNCTION public.get_claims() TO authenticated, anon, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.has_role(uuid, text) TO authenticated, anon, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.is_member(uuid) TO authenticated, anon, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.has_any_role(uuid, text[]) TO authenticated, anon, service_role';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.has_all_roles(uuid, text[]) TO authenticated, anon, service_role';

    -- Management RPCs: authenticated only
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.create_group(text, jsonb, text[]) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.delete_group(uuid) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.add_member(uuid, uuid, text[]) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.remove_member(uuid, uuid) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.update_member_roles(uuid, uuid, text[]) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.list_members(uuid) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.accept_invite(uuid) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.create_role(text, text) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.delete_role(text) FROM PUBLIC';
    EXECUTE 'REVOKE EXECUTE ON FUNCTION public.list_roles() FROM PUBLIC';

    EXECUTE 'GRANT EXECUTE ON FUNCTION public.create_group(text, jsonb, text[]) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.delete_group(uuid) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.add_member(uuid, uuid, text[]) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.remove_member(uuid, uuid) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.update_member_roles(uuid, uuid, text[]) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.list_members(uuid) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.accept_invite(uuid) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.create_role(text, text) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.delete_role(text) TO authenticated';
    EXECUTE 'GRANT EXECUTE ON FUNCTION public.list_roles() TO authenticated';

END IF;
END $wrapper$;
