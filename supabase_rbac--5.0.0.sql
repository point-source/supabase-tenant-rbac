-- ═══════════════════════════════════════════════════════════════════════════════
-- supabase_rbac v5.0.0 — Multi-Tenant RBAC for Supabase
-- ═══════════════════════════════════════════════════════════════════════════════
-- Install in a dedicated schema (e.g. rbac) that is NOT in PostgREST's exposed
-- schemas. Tables are accessed exclusively through RPC functions. Public wrapper
-- functions are opt-in only — run examples/setup/create_public_wrappers.sql after
-- installation to expose them in the public schema for PostgREST RPC discovery.
--
-- SECURITY DEFINER functions (8 total):
--   1. _on_group_created         — trigger: auto-creates membership for group creator (bootstrap)
--   2. accept_invite             — bootstrap: atomically adds membership without prior RLS
--   3. _sync_member_metadata     — trigger, writes user_claims without authenticated INSERT
--   4. _sync_member_permission   — trigger, writes user_claims without authenticated INSERT
--   5. _on_role_definition_change — trigger, writes user_claims without authenticated INSERT
--   6. _validate_roles           — reads rbac.roles (authenticated has no SELECT on roles)
--   7. _validate_permissions     — reads rbac.permissions (authenticated has no SELECT)
--   8. _validate_grantable_roles — reads rbac.roles (authenticated has no SELECT)

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
    name            text        PRIMARY KEY,
    description     text,
    permissions     text[]      NOT NULL DEFAULT '{}'::text[],
    grantable_roles text[]      NOT NULL DEFAULT '{}'::text[],
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- Pre-seed the 'owner' role (used as the default in create_group)
INSERT INTO @extschema@.roles (name, description, grantable_roles)
VALUES ('owner', 'Group creator with full administrative permissions', ARRAY['*']);

-- Claims cache: one row per user, auto-managed by _sync_member_metadata trigger.
-- ON DELETE CASCADE handles cleanup when a user is deleted from auth.users.
CREATE TABLE @extschema@.user_claims (
    user_id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    claims  jsonb NOT NULL DEFAULT '{}'::jsonb
);

-- Direct per-member permission overrides. These merge into the claims cache
-- alongside permissions resolved from roles. Additive only — no UPDATE needed.
CREATE TABLE @extschema@.member_permissions (
    id          uuid        NOT NULL DEFAULT gen_random_uuid(),
    group_id    uuid        NOT NULL,
    user_id     uuid        NOT NULL,
    permission  text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Global permission definitions. Validated by _validate_permissions before use.
CREATE TABLE @extschema@.permissions (
    name        text        PRIMARY KEY,
    description text,
    created_at  timestamptz NOT NULL DEFAULT now()
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

-- Promote unique index to a named constraint so member_permissions can FK-reference it.
CREATE UNIQUE INDEX members_group_user_idx ON @extschema@.members USING btree (group_id, user_id);
ALTER TABLE @extschema@.members
    ADD CONSTRAINT members_group_user_uq UNIQUE USING INDEX members_group_user_idx;

CREATE INDEX members_user_id_idx ON @extschema@.members USING btree (user_id);

-- GIN index for efficient role-membership lookups (WHERE roles @> ARRAY[name]).
-- Critical for _on_role_definition_change() and delete_role() on large member tables.
CREATE INDEX members_roles_gin_idx ON @extschema@.members USING gin (roles);

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

CREATE INDEX invites_group_id_idx ON @extschema@.invites USING btree (group_id);

ALTER TABLE @extschema@.invites
    ADD CONSTRAINT invites_invited_by_fkey FOREIGN KEY (invited_by)
    REFERENCES auth.users (id) ON DELETE CASCADE NOT VALID;
ALTER TABLE @extschema@.invites VALIDATE CONSTRAINT invites_invited_by_fkey;

ALTER TABLE @extschema@.invites
    ADD CONSTRAINT invites_user_id_fkey FOREIGN KEY (user_id)
    REFERENCES auth.users (id) ON DELETE CASCADE NOT VALID;
ALTER TABLE @extschema@.invites VALIDATE CONSTRAINT invites_user_id_fkey;

-- member_permissions
CREATE UNIQUE INDEX member_permissions_pkey ON @extschema@.member_permissions USING btree (id);
ALTER TABLE @extschema@.member_permissions
    ADD CONSTRAINT member_permissions_pkey PRIMARY KEY USING INDEX member_permissions_pkey;

-- Enforce uniqueness of (group_id, user_id, permission) — enables idempotent grants
CREATE UNIQUE INDEX member_permissions_group_user_perm_idx
    ON @extschema@.member_permissions USING btree (group_id, user_id, permission);

-- Index on user_id for efficient claims rebuild lookups
CREATE INDEX member_permissions_user_id_idx
    ON @extschema@.member_permissions USING btree (user_id);

ALTER TABLE @extschema@.member_permissions
    ADD CONSTRAINT member_permissions_group_id_fkey FOREIGN KEY (group_id)
    REFERENCES @extschema@.groups (id) ON DELETE CASCADE NOT VALID;
ALTER TABLE @extschema@.member_permissions VALIDATE CONSTRAINT member_permissions_group_id_fkey;

ALTER TABLE @extschema@.member_permissions
    ADD CONSTRAINT member_permissions_user_id_fkey FOREIGN KEY (user_id)
    REFERENCES auth.users (id) ON DELETE CASCADE NOT VALID;
ALTER TABLE @extschema@.member_permissions VALIDATE CONSTRAINT member_permissions_user_id_fkey;

-- FK to members (group_id, user_id): CASCADE ensures permission overrides are
-- removed when a member is removed from a group.
ALTER TABLE @extschema@.member_permissions
    ADD CONSTRAINT member_permissions_member_fkey FOREIGN KEY (group_id, user_id)
    REFERENCES @extschema@.members (group_id, user_id) ON DELETE CASCADE NOT VALID;
ALTER TABLE @extschema@.member_permissions VALIDATE CONSTRAINT member_permissions_member_fkey;

-- ─────────────────────────────────────────────────────────────────────────────
-- ROW LEVEL SECURITY (deny-all by default — consumers add policies)
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE @extschema@.groups             ENABLE ROW LEVEL SECURITY;
ALTER TABLE @extschema@.members            ENABLE ROW LEVEL SECURITY;
ALTER TABLE @extschema@.invites            ENABLE ROW LEVEL SECURITY;
ALTER TABLE @extschema@.roles              ENABLE ROW LEVEL SECURITY;
ALTER TABLE @extschema@.user_claims        ENABLE ROW LEVEL SECURITY;
ALTER TABLE @extschema@.member_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE @extschema@.permissions        ENABLE ROW LEVEL SECURITY;

-- ─────────────────────────────────────────────────────────────────────────────
-- INTERNAL FUNCTIONS
-- ─────────────────────────────────────────────────────────────────────────────

-- Replaces moddatetime dependency — inline updated_at trigger
CREATE OR REPLACE FUNCTION @extschema@._set_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = @extschema@
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
VOLATILE
-- No SECURITY DEFINER — reads extension-owned user_claims table
SET search_path = @extschema@
AS $function$
DECLARE
    groups jsonb;
BEGIN
    SELECT claims INTO groups FROM @extschema@.user_claims WHERE user_id = auth.uid();
    PERFORM set_config('request.groups'::text, coalesce(groups, '{}')::text, true);
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
SECURITY DEFINER
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

-- Validate that all permission names in an array exist in the permissions table.
-- Raises a descriptive error listing any undefined permissions.
CREATE OR REPLACE FUNCTION @extschema@._validate_permissions(p_permissions text[])
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = @extschema@
AS $function$
DECLARE
    _undefined text[];
BEGIN
    IF p_permissions IS NULL OR cardinality(p_permissions) = 0 THEN
        RETURN;
    END IF;

    SELECT array_agg(p)
    INTO _undefined
    FROM unnest(p_permissions) AS p
    WHERE p NOT IN (SELECT name FROM @extschema@.permissions);

    IF _undefined IS NOT NULL THEN
        RAISE EXCEPTION 'Undefined permissions: %', array_to_string(_undefined, ', ')
            USING HINT = 'Add these permissions to the permissions table first';
    END IF;
END;
$function$;

-- Validate that all role names in grantable_roles exist in the roles table.
-- The wildcard '*' is always valid and skipped during validation.
CREATE OR REPLACE FUNCTION @extschema@._validate_grantable_roles(p_roles text[])
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
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
    WHERE r <> '*' AND r NOT IN (SELECT name FROM @extschema@.roles);

    IF _undefined IS NOT NULL THEN
        RAISE EXCEPTION 'Undefined roles in grantable_roles: %', array_to_string(_undefined, ', ')
            USING HINT = 'Add these roles to the roles table first';
    END IF;
END;
$function$;

-- Check whether the caller is allowed to assign the requested roles to another
-- member. Prevents privilege escalation — a caller can only grant roles that
-- appear in their own grantable_roles claim for the target group.
-- Bypassed for service_role and postgres session users.
CREATE OR REPLACE FUNCTION @extschema@._check_role_escalation(p_group_id uuid, p_roles text[])
RETURNS void
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
DECLARE
    caller_grantable jsonb;
    bad_roles        text[];
BEGIN
    -- Only enforce when the effective role is 'authenticated'.
    -- Checking both auth.role() and current_user prevents stale JWT context
    -- (e.g. postgres top-level calls after a DO block that set request.jwt.claims)
    -- from triggering enforcement. In production, both are 'authenticated' for
    -- real user requests; service_role and postgres bypass automatically.
    IF auth.role() IS DISTINCT FROM 'authenticated'
       OR current_user IS DISTINCT FROM 'authenticated' THEN
        RETURN;
    END IF;

    IF p_roles IS NULL OR cardinality(p_roles) = 0 THEN
        RETURN;
    END IF;

    caller_grantable := get_claims()->p_group_id::text->'grantable_roles';

    IF caller_grantable IS NULL THEN
        RAISE EXCEPTION 'permission denied — caller is not a member of this group'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Wildcard: caller can grant any role
    IF caller_grantable ? '*' THEN
        RETURN;
    END IF;

    -- Find roles the caller is not permitted to grant
    SELECT array_agg(r)
    INTO bad_roles
    FROM unnest(p_roles) AS r
    WHERE NOT (caller_grantable ? r);

    IF bad_roles IS NOT NULL THEN
        RAISE EXCEPTION 'permission denied — role(s) not in caller''s grantable set: %',
            array_to_string(bad_roles, ', ')
            USING ERRCODE = 'insufficient_privilege';
    END IF;
END;
$function$;

-- Check whether the caller is allowed to grant or revoke the specified
-- permission for a member. Prevents permission escalation.
-- Bypassed for service_role and postgres session users.
CREATE OR REPLACE FUNCTION @extschema@._check_permission_escalation(p_group_id uuid, p_permission text)
RETURNS void
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
DECLARE
    caller_grantable_perms jsonb;
BEGIN
    -- Only enforce when the effective role is 'authenticated'.
    -- Checking both auth.role() and current_user prevents stale JWT context
    -- from triggering enforcement on postgres top-level calls.
    IF auth.role() IS DISTINCT FROM 'authenticated'
       OR current_user IS DISTINCT FROM 'authenticated' THEN
        RETURN;
    END IF;

    caller_grantable_perms := get_claims()->p_group_id::text->'grantable_permissions';

    IF caller_grantable_perms IS NULL THEN
        RAISE EXCEPTION 'permission denied — caller is not a member of this group'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Wildcard: caller can grant any permission
    IF caller_grantable_perms ? '*' THEN
        RETURN;
    END IF;

    IF NOT (caller_grantable_perms ? p_permission) THEN
        RAISE EXCEPTION 'permission denied — permission "%" not in caller''s grantable set',
            p_permission
            USING ERRCODE = 'insufficient_privilege';
    END IF;
END;
$function$;

-- Build the complete claims JSONB for a user.
-- Returns {"group-uuid": {"roles": [...], "permissions": [...], "grantable_roles": [...], "grantable_permissions": [...]}, ...}
-- Permissions are resolved from roles.permissions[] and member_permissions,
-- deduplicated and sorted. Direct permission overrides merge with role permissions.
-- grantable_roles and grantable_permissions are derived from roles.grantable_roles[].
CREATE OR REPLACE FUNCTION @extschema@._build_user_claims(p_user_id uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SET search_path = @extschema@
AS $function$
    SELECT coalesce(
        jsonb_object_agg(
            sub.gid,
            jsonb_build_object(
                'roles', sub.roles_arr,
                'permissions', sub.perms_arr,
                'grantable_roles', sub.grantable_roles_arr,
                'grantable_permissions', sub.grantable_perms_arr
            )
        ),
        '{}'::jsonb
    )
    FROM (
        SELECT
            m.group_id::text AS gid,
            to_jsonb(m.roles) AS roles_arr,
            -- permissions: union of role permissions + direct overrides, deduplicated
            coalesce(
                to_jsonb(
                    (SELECT array_agg(DISTINCT perm ORDER BY perm)
                     FROM (
                         SELECT unnest(r.permissions) AS perm
                         FROM @extschema@.roles r
                         WHERE r.name = ANY(m.roles)
                         UNION ALL
                         SELECT mp.permission
                         FROM @extschema@.member_permissions mp
                         WHERE mp.group_id = m.group_id AND mp.user_id = m.user_id
                     ) AS all_perms)
                ),
                '[]'::jsonb
            ) AS perms_arr,
            -- grantable_roles: union of roles.grantable_roles[] for held roles
            -- if any held role has '*', collapse entire result to ['*']
            -- The EXISTS wildcard check is intentionally duplicated for grantable_roles
            -- and grantable_permissions below — the optimizer deduplicates identical
            -- subqueries; explicit duplication keeps each CASE branch self-contained.
            CASE
                WHEN EXISTS (
                    SELECT 1 FROM @extschema@.roles r
                    WHERE r.name = ANY(m.roles)
                      AND '*' = ANY(r.grantable_roles)
                ) THEN '["*"]'::jsonb
                ELSE coalesce(
                    to_jsonb(
                        (SELECT array_agg(DISTINCT gr ORDER BY gr)
                         FROM (
                             SELECT unnest(r.grantable_roles) AS gr
                             FROM @extschema@.roles r
                             WHERE r.name = ANY(m.roles)
                         ) t
                         WHERE gr <> '*')
                    ),
                    '[]'::jsonb
                )
            END AS grantable_roles_arr,
            -- grantable_permissions: if wildcard, return ['*']
            -- else union of permissions[] for all roles named in grantable_roles
            CASE
                WHEN EXISTS (
                    SELECT 1 FROM @extschema@.roles r
                    WHERE r.name = ANY(m.roles)
                      AND '*' = ANY(r.grantable_roles)
                ) THEN '["*"]'::jsonb
                ELSE coalesce(
                    to_jsonb(
                        (SELECT array_agg(DISTINCT gp ORDER BY gp)
                         FROM (
                             SELECT unnest(r2.permissions) AS gp
                             FROM @extschema@.roles r
                             JOIN @extschema@.roles r2
                                 ON r2.name = ANY(r.grantable_roles)
                                 AND r2.name <> '*'
                             WHERE r.name = ANY(m.roles)
                         ) AS grantable_perms)
                    ),
                    '[]'::jsonb
                )
            END AS grantable_perms_arr
        FROM @extschema@.members m
        WHERE m.user_id = p_user_id
    ) sub
$function$;

-- Trigger function: rebuild user's entire claims from members table
-- Fires on INSERT/UPDATE/DELETE on members.
-- SECURITY DEFINER so it can write to user_claims regardless of the calling role.
-- Trigger functions (RETURNS trigger) cannot be called directly via RPC or REST.
CREATE OR REPLACE FUNCTION @extschema@._sync_member_metadata()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
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

    -- Rebuild full claims for this user
    SELECT _build_user_claims(_user_id) INTO _new_groups;

    -- Upsert into user_claims. Nested block catches only the expected FK violation
    -- (concurrent auth.users deletion during upsert), not unexpected errors elsewhere.
    BEGIN
        INSERT INTO @extschema@.user_claims (user_id, claims)
        VALUES (_user_id, _new_groups)
        ON CONFLICT (user_id) DO UPDATE SET claims = EXCLUDED.claims;
    EXCEPTION WHEN foreign_key_violation THEN
        -- user_id no longer exists in auth.users (deleted concurrently) — skip silently
        NULL;
    END;

    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$function$;

-- Trigger function: rebuild claims when a direct member permission is added or removed.
-- Fires on INSERT/DELETE on member_permissions.
-- SECURITY DEFINER so it can write to user_claims regardless of the calling role.
-- Trigger functions (RETURNS trigger) cannot be called directly via RPC or REST.
CREATE OR REPLACE FUNCTION @extschema@._sync_member_permission()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = @extschema@
AS $function$
DECLARE
    _user_id    uuid;
    _new_groups jsonb;
BEGIN
    _user_id := coalesce(NEW.user_id, OLD.user_id);

    -- Rebuild full claims for this user (includes remaining direct overrides)
    SELECT _build_user_claims(_user_id) INTO _new_groups;

    -- Nested block catches only the expected FK violation (concurrent user deletion).
    BEGIN
        INSERT INTO @extschema@.user_claims (user_id, claims)
        VALUES (_user_id, _new_groups)
        ON CONFLICT (user_id) DO UPDATE SET claims = EXCLUDED.claims;
    EXCEPTION WHEN foreign_key_violation THEN
        -- user_id no longer exists in auth.users (deleted concurrently) — skip silently
        NULL;
    END;

    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$function$;

-- Trigger function: rebuild claims for all users holding a role whose
-- permissions or grantable_roles column was changed, and for users who hold
-- roles that reference the changed role in their own grantable_roles.
-- Fires on UPDATE of roles.
-- SECURITY DEFINER so it can write to user_claims regardless of the calling role.
-- Trigger functions (RETURNS trigger) cannot be called directly via RPC or REST.
CREATE OR REPLACE FUNCTION @extschema@._on_role_definition_change()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = @extschema@
AS $function$
BEGIN
    -- Batch rebuild: single INSERT...ON CONFLICT replaces the previous per-row loop,
    -- reducing lock hold time for large membership tables. Pre-filtering on auth.users
    -- avoids FK violations from concurrent user deletions without needing an exception
    -- handler that could inadvertently swallow unexpected errors.
    INSERT INTO @extschema@.user_claims (user_id, claims)
    SELECT u.user_id, _build_user_claims(u.user_id)
    FROM (
        SELECT DISTINCT m.user_id
        FROM @extschema@.members m
        WHERE m.roles @> ARRAY[NEW.name]           -- direct holders of changed role
           OR EXISTS (
               SELECT 1 FROM @extschema@.roles r2
               WHERE m.roles @> ARRAY[r2.name]
                 AND NEW.name = ANY(r2.grantable_roles)
           )                                       -- indirect: holds a role whose grantable_roles lists the changed role
    ) u
    WHERE EXISTS (SELECT 1 FROM auth.users WHERE id = u.user_id)
    ON CONFLICT (user_id) DO UPDATE SET claims = EXCLUDED.claims;

    RETURN NEW;
END;
$function$;

-- Trigger function: auto-create membership row for group creator after INSERT on groups.
-- SECURITY DEFINER so it can INSERT into members even though the caller has no prior
-- membership (and therefore cannot pass the members INSERT RLS policy).
-- Trigger functions (RETURNS trigger) cannot be called directly via RPC or REST.
-- Skips when auth.uid() is NULL (service_role / migration INSERTs).
CREATE OR REPLACE FUNCTION @extschema@._on_group_created()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = @extschema@
AS $function$
DECLARE
    _user_id uuid;
    _roles   text[];
BEGIN
    _user_id := auth.uid();
    IF _user_id IS NULL THEN
        RETURN NEW;  -- service_role / migration insert — skip
    END IF;

    BEGIN
        _roles := current_setting('rbac.creator_roles')::text[];
    EXCEPTION WHEN OTHERS THEN
        _roles := ARRAY['owner'];
    END;

    -- Validate roles exist (guards direct INSERT path where create_group didn't run)
    PERFORM _validate_roles(_roles);

    INSERT INTO @extschema@.members (group_id, user_id, roles)
    VALUES (NEW.id, _user_id, ARRAY(SELECT DISTINCT unnest(_roles) ORDER BY 1));

    RETURN NEW;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@._on_group_created() FROM PUBLIC;

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

REVOKE EXECUTE ON FUNCTION @extschema@.get_claims() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.get_claims() TO authenticated, anon, service_role;

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
        SELECT coalesce(get_claims()->group_id::text->'roles' ? role, false) INTO retval;
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

REVOKE EXECUTE ON FUNCTION @extschema@.has_role(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.has_role(uuid, text) TO authenticated, anon, service_role;

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

REVOKE EXECUTE ON FUNCTION @extschema@.is_member(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.is_member(uuid) TO authenticated, anon, service_role;

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
        SELECT coalesce(get_claims()->group_id::text->'roles' ?| roles, false) INTO retval;
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

REVOKE EXECUTE ON FUNCTION @extschema@.has_any_role(uuid, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.has_any_role(uuid, text[]) TO authenticated, anon, service_role;

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
        SELECT coalesce(get_claims()->group_id::text->'roles' ?& roles, false) INTO retval;
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

REVOKE EXECUTE ON FUNCTION @extschema@.has_all_roles(uuid, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.has_all_roles(uuid, text[]) TO authenticated, anon, service_role;

-- Check if user has a specific resolved permission in a group
CREATE OR REPLACE FUNCTION @extschema@.has_permission(group_id uuid, permission text)
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
        SELECT coalesce(get_claims()->group_id::text->'permissions' ? permission, false) INTO retval;
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

REVOKE EXECUTE ON FUNCTION @extschema@.has_permission(uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.has_permission(uuid, text) TO authenticated, anon, service_role;

-- Check if user has ANY of the listed permissions in a group
CREATE OR REPLACE FUNCTION @extschema@.has_any_permission(group_id uuid, permissions text[])
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
        SELECT coalesce(get_claims()->group_id::text->'permissions' ?| permissions, false) INTO retval;
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

REVOKE EXECUTE ON FUNCTION @extschema@.has_any_permission(uuid, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.has_any_permission(uuid, text[]) TO authenticated, anon, service_role;

-- Check if user has ALL of the listed permissions in a group
CREATE OR REPLACE FUNCTION @extschema@.has_all_permissions(group_id uuid, permissions text[])
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
        SELECT coalesce(get_claims()->group_id::text->'permissions' ?& permissions, false) INTO retval;
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

REVOKE EXECUTE ON FUNCTION @extschema@.has_all_permissions(uuid, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.has_all_permissions(uuid, text[]) TO authenticated, anon, service_role;

-- ─────────────────────────────────────────────────────────────────────────────
-- MANAGEMENT RPCs
-- ─────────────────────────────────────────────────────────────────────────────

-- Create a group and add the caller as a member with creator_roles.
-- SECURITY INVOKER — INSERT into groups is subject to RLS. Add an INSERT policy on
-- rbac.groups to allow group creation (see examples/policies/quickstart.sql).
-- The _on_group_created AFTER INSERT trigger (SECURITY DEFINER) handles membership.
CREATE OR REPLACE FUNCTION @extschema@.create_group(
    p_name          text,
    p_metadata      jsonb  DEFAULT '{}'::jsonb,
    p_creator_roles text[] DEFAULT ARRAY['owner']
)
RETURNS uuid
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
DECLARE
    _user_id  uuid := auth.uid();
    _group_id uuid := gen_random_uuid();
BEGIN
    IF _user_id IS NULL THEN
        RAISE EXCEPTION 'Not authenticated';
    END IF;

    PERFORM _validate_roles(p_creator_roles);

    -- Store creator roles for the _on_group_created trigger.
    PERFORM set_config('rbac.creator_roles',
        ARRAY(SELECT DISTINCT unnest(p_creator_roles) ORDER BY 1)::text,
        true);

    -- Pre-generate the UUID to avoid RETURNING, which would require passing the
    -- SELECT policy (is_member check) before the trigger creates the membership.
    INSERT INTO @extschema@.groups (id, name, metadata)
    VALUES (_group_id, p_name, p_metadata);

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
    PERFORM _check_role_escalation(p_group_id, p_roles);

    INSERT INTO @extschema@.members (group_id, user_id, roles)
    VALUES (p_group_id, p_user_id, ARRAY(SELECT DISTINCT unnest(p_roles) ORDER BY 1))
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
    PERFORM _check_role_escalation(p_group_id, p_roles);

    UPDATE @extschema@.members
    SET roles = ARRAY(
        SELECT DISTINCT r
        FROM unnest(coalesce(p_roles, '{}'::text[])) AS r
        ORDER BY 1
    )
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
    VALUES (
        _invite.group_id,
        _user_id,
        ARRAY(
            SELECT DISTINCT r
            FROM unnest(_invite.roles) AS r
            ORDER BY 1
        )
    )
    ON CONFLICT (group_id, user_id)
    DO UPDATE SET roles = (
        SELECT array_agg(DISTINCT r ORDER BY r)
        FROM unnest(members.roles || EXCLUDED.roles) AS r
    );
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.accept_invite(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.accept_invite(uuid) TO authenticated;

-- Create an invite for a group. SECURITY INVOKER — RLS enforced.
-- The INSERT is subject to the app-author's RLS policy on invites, which controls
-- who may create invites (e.g. must have a specific role or permission in the group).
CREATE OR REPLACE FUNCTION @extschema@.create_invite(
    p_group_id   uuid,
    p_roles      text[],
    p_expires_at timestamptz DEFAULT NULL
)
RETURNS uuid
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
DECLARE
    _user_id   uuid := auth.uid();
    _invite_id uuid;
BEGIN
    IF _user_id IS NULL THEN
        RAISE EXCEPTION 'Not authenticated';
    END IF;

    PERFORM _validate_roles(p_roles);
    PERFORM _check_role_escalation(p_group_id, p_roles);

    INSERT INTO @extschema@.invites (group_id, roles, invited_by, expires_at)
    VALUES (
        p_group_id,
        ARRAY(
            SELECT DISTINCT r
            FROM unnest(coalesce(p_roles, '{}'::text[])) AS r
            ORDER BY 1
        ),
        _user_id,
        p_expires_at
    )
    RETURNING id INTO _invite_id;

    RETURN _invite_id;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.create_invite(uuid, text[], timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.create_invite(uuid, text[], timestamptz) TO authenticated;

-- Delete an invite. SECURITY INVOKER — RLS enforced.
-- Raises if the invite is not found or not authorized.
CREATE OR REPLACE FUNCTION @extschema@.delete_invite(p_invite_id uuid)
RETURNS void
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
BEGIN
    DELETE FROM @extschema@.invites WHERE id = p_invite_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Invite not found or not authorized';
    END IF;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.delete_invite(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.delete_invite(uuid) TO authenticated;

-- Grant a direct permission override to a member. SECURITY INVOKER — RLS enforced.
-- Idempotent: ON CONFLICT DO NOTHING prevents duplicates.
--
-- Defense-in-depth: is_member() guard runs before RLS, ensuring authenticated callers
-- cannot write to a group they are not members of even if a consumer RLS policy is
-- misconfigured. is_member() returns true for postgres/service_role so backend callers
-- are unaffected. The downstream FK (member_permissions → members) also prevents
-- granting permissions to users who are not members of the target group.
CREATE OR REPLACE FUNCTION @extschema@.grant_member_permission(
    p_group_id   uuid,
    p_user_id    uuid,
    p_permission text
)
RETURNS void
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
BEGIN
    -- Caller must be a member of the target group.
    IF NOT is_member(p_group_id) THEN
        RAISE EXCEPTION 'permission denied — caller is not a member of the target group'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Reject empty permission strings.
    IF trim(coalesce(p_permission, '')) = '' THEN
        RAISE EXCEPTION 'permission must not be empty'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    PERFORM _validate_permissions(ARRAY[p_permission]);
    PERFORM _check_permission_escalation(p_group_id, p_permission);

    INSERT INTO @extschema@.member_permissions (group_id, user_id, permission)
    VALUES (p_group_id, p_user_id, p_permission)
    ON CONFLICT (group_id, user_id, permission) DO NOTHING;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.grant_member_permission(uuid, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.grant_member_permission(uuid, uuid, text) TO authenticated;

-- Revoke a direct permission override from a member. SECURITY INVOKER — RLS enforced.
-- Raises if the override does not exist.
CREATE OR REPLACE FUNCTION @extschema@.revoke_member_permission(
    p_group_id   uuid,
    p_user_id    uuid,
    p_permission text
)
RETURNS void
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
BEGIN
    -- Caller must be a member of the target group.
    IF NOT is_member(p_group_id) THEN
        RAISE EXCEPTION 'permission denied — caller is not a member of the target group'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    -- Reject empty permission strings.
    IF trim(coalesce(p_permission, '')) = '' THEN
        RAISE EXCEPTION 'permission must not be empty'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    PERFORM _check_permission_escalation(p_group_id, p_permission);

    DELETE FROM @extschema@.member_permissions
    WHERE group_id = p_group_id AND user_id = p_user_id AND permission = p_permission;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Permission override not found for member';
    END IF;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.revoke_member_permission(uuid, uuid, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.revoke_member_permission(uuid, uuid, text) TO authenticated;

-- List direct permission overrides for a group, optionally filtered by user.
-- SECURITY INVOKER — RLS enforced.
CREATE OR REPLACE FUNCTION @extschema@.list_member_permissions(
    p_group_id uuid,
    p_user_id  uuid DEFAULT NULL
)
RETURNS TABLE(user_id uuid, permission text, created_at timestamptz)
LANGUAGE plpgsql
STABLE
SET search_path = @extschema@
AS $function$
BEGIN
    RETURN QUERY
    SELECT mp.user_id, mp.permission, mp.created_at
    FROM @extschema@.member_permissions mp
    WHERE mp.group_id = p_group_id
      AND (p_user_id IS NULL OR mp.user_id = p_user_id)
    ORDER BY mp.user_id, mp.permission;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.list_member_permissions(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.list_member_permissions(uuid, uuid) TO authenticated;

-- Create a role definition. SECURITY INVOKER — service_role only (app-author operation).
CREATE OR REPLACE FUNCTION @extschema@.create_role(
    p_name            text,
    p_description     text   DEFAULT NULL,
    p_permissions     text[] DEFAULT '{}'::text[],
    p_grantable_roles text[] DEFAULT '{}'::text[]
)
RETURNS void
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
BEGIN
    PERFORM _validate_permissions(p_permissions);
    PERFORM _validate_grantable_roles(p_grantable_roles);
    INSERT INTO @extschema@.roles (name, description, permissions, grantable_roles)
    VALUES (p_name, p_description, coalesce(p_permissions, '{}'::text[]), coalesce(p_grantable_roles, '{}'::text[]));
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.create_role(text, text, text[], text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.create_role(text, text, text[], text[]) TO service_role;

-- Delete a role definition. Refuses if any member uses this role or if other
-- roles reference it in their grantable_roles.
-- SECURITY INVOKER — service_role only (app-author operation).
CREATE OR REPLACE FUNCTION @extschema@.delete_role(p_name text)
RETURNS void
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
BEGIN
    -- Check if any member has this role
    IF EXISTS (
        SELECT 1 FROM @extschema@.members WHERE roles @> ARRAY[p_name]
    ) THEN
        RAISE EXCEPTION 'Role "%" is in use by one or more members', p_name
            USING HINT = 'Remove this role from all members before deleting it';
    END IF;

    -- Check if any other role references this role in grantable_roles
    IF EXISTS (
        SELECT 1 FROM @extschema@.roles WHERE p_name = ANY(grantable_roles)
    ) THEN
        RAISE EXCEPTION 'Role "%" is referenced in grantable_roles by other roles', p_name
            USING HINT = 'Remove this role from grantable_roles of other roles before deleting it';
    END IF;

    DELETE FROM @extschema@.roles WHERE name = p_name;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Role "%" not found or not authorized', p_name;
    END IF;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.delete_role(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.delete_role(text) TO service_role;

-- List all role definitions. SECURITY INVOKER — service_role only.
CREATE OR REPLACE FUNCTION @extschema@.list_roles()
RETURNS TABLE(name text, description text, permissions text[], grantable_roles text[], created_at timestamptz)
LANGUAGE plpgsql
STABLE
SET search_path = @extschema@
AS $function$
BEGIN
    RETURN QUERY
    SELECT r.name, r.description, r.permissions, r.grantable_roles, r.created_at
    FROM @extschema@.roles r
    ORDER BY r.name;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.list_roles() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.list_roles() TO service_role;

-- Replace all permissions for a role. service_role only (app-author operation).
-- Trigger on roles handles claims cache rebuild for all affected members.
CREATE OR REPLACE FUNCTION @extschema@.set_role_permissions(
    p_role_name   text,
    p_permissions text[]
)
RETURNS void
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM @extschema@.roles WHERE name = p_role_name) THEN
        RAISE EXCEPTION 'Role "%" not found', p_role_name;
    END IF;

    PERFORM _validate_permissions(p_permissions);

    UPDATE @extschema@.roles
    SET permissions = coalesce(p_permissions, '{}'::text[])
    WHERE name = p_role_name;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.set_role_permissions(text, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.set_role_permissions(text, text[]) TO service_role;

-- Add a single permission to a role (idempotent). service_role only.
CREATE OR REPLACE FUNCTION @extschema@.grant_permission(
    p_role_name  text,
    p_permission text
)
RETURNS void
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
BEGIN
    PERFORM _validate_permissions(ARRAY[p_permission]);

    UPDATE @extschema@.roles
    SET permissions = (
        SELECT array_agg(DISTINCT p ORDER BY p)
        FROM unnest(permissions || ARRAY[p_permission]) AS p
    )
    WHERE name = p_role_name;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Role "%" not found', p_role_name;
    END IF;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.grant_permission(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.grant_permission(text, text) TO service_role;

-- Remove a single permission from a role (no-op if not present). service_role only.
CREATE OR REPLACE FUNCTION @extschema@.revoke_permission(
    p_role_name  text,
    p_permission text
)
RETURNS void
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
BEGIN
    UPDATE @extschema@.roles
    SET permissions = array_remove(permissions, p_permission)
    WHERE name = p_role_name;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Role "%" not found', p_role_name;
    END IF;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.revoke_permission(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.revoke_permission(text, text) TO service_role;

-- List permissions for one or all roles. service_role only.
CREATE OR REPLACE FUNCTION @extschema@.list_role_permissions(p_role_name text DEFAULT NULL)
RETURNS TABLE(role_name text, permission text)
LANGUAGE plpgsql
STABLE
SET search_path = @extschema@
AS $function$
BEGIN
    RETURN QUERY
    SELECT r.name AS role_name, perm AS permission
    FROM @extschema@.roles r,
         unnest(r.permissions) AS perm
    WHERE p_role_name IS NULL OR r.name = p_role_name
    ORDER BY r.name, perm;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.list_role_permissions(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.list_role_permissions(text) TO service_role;

-- Replace the grantable_roles for a role. service_role only (app-author operation).
-- Trigger on roles handles claims cache rebuild for all affected members.
CREATE OR REPLACE FUNCTION @extschema@.set_role_grantable_roles(
    p_role_name       text,
    p_grantable_roles text[]
)
RETURNS void
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM @extschema@.roles WHERE name = p_role_name) THEN
        RAISE EXCEPTION 'Role "%" not found', p_role_name;
    END IF;

    PERFORM _validate_grantable_roles(p_grantable_roles);

    UPDATE @extschema@.roles
    SET grantable_roles = coalesce(p_grantable_roles, '{}'::text[])
    WHERE name = p_role_name;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.set_role_grantable_roles(text, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.set_role_grantable_roles(text, text[]) TO service_role;

-- Create a permission definition. service_role only (app-author operation).
CREATE OR REPLACE FUNCTION @extschema@.create_permission(
    p_name        text,
    p_description text DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
BEGIN
    INSERT INTO @extschema@.permissions (name, description) VALUES (p_name, p_description);
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.create_permission(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.create_permission(text, text) TO service_role;

-- Delete a permission definition. Refuses if any role or member uses this permission.
-- service_role only (app-author operation).
CREATE OR REPLACE FUNCTION @extschema@.delete_permission(p_name text)
RETURNS void
LANGUAGE plpgsql
SET search_path = @extschema@
AS $function$
BEGIN
    -- Check if any role has this permission
    IF EXISTS (
        SELECT 1 FROM @extschema@.roles WHERE p_name = ANY(permissions)
    ) THEN
        RAISE EXCEPTION 'Permission "%" is in use by one or more roles', p_name
            USING HINT = 'Remove this permission from all roles before deleting it';
    END IF;

    -- Check if any member has this direct permission override
    IF EXISTS (
        SELECT 1 FROM @extschema@.member_permissions WHERE permission = p_name
    ) THEN
        RAISE EXCEPTION 'Permission "%" is in use by one or more member permission overrides', p_name
            USING HINT = 'Revoke this permission from all members before deleting it';
    END IF;

    DELETE FROM @extschema@.permissions WHERE name = p_name;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Permission "%" not found', p_name;
    END IF;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.delete_permission(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.delete_permission(text) TO service_role;

-- List all permission definitions. service_role only.
CREATE OR REPLACE FUNCTION @extschema@.list_permissions()
RETURNS TABLE(name text, description text, created_at timestamptz)
LANGUAGE plpgsql
STABLE
SET search_path = @extschema@
AS $function$
BEGIN
    RETURN QUERY
    SELECT p.name, p.description, p.created_at
    FROM @extschema@.permissions p
    ORDER BY p.name;
END;
$function$;

REVOKE EXECUTE ON FUNCTION @extschema@.list_permissions() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION @extschema@.list_permissions() TO service_role;

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
GRANT SELECT, INSERT, UPDATE, DELETE ON @extschema@.invites TO authenticated;
-- user_claims: SELECT is needed for _get_user_groups() fallback (Storage RLS path).
-- No INSERT/UPDATE for authenticated — the three trigger functions that write to
-- user_claims are now SECURITY DEFINER and run as the function owner (postgres),
-- not as the calling role. Removing INSERT/UPDATE closes the claims forgery vector.
GRANT SELECT ON @extschema@.user_claims TO authenticated;
-- authenticator needs SELECT for db_pre_request() (SECURITY INVOKER, runs as authenticator)
GRANT SELECT ON @extschema@.user_claims TO authenticator;
-- supabase_auth_admin needs SELECT for custom_access_token_hook()
GRANT SELECT ON @extschema@.user_claims TO supabase_auth_admin;

-- member_permissions: authenticated can read, insert, and delete overrides.
-- No UPDATE needed — rows are inserted or deleted, not modified.
GRANT SELECT, INSERT, DELETE ON @extschema@.member_permissions TO authenticated;

-- permissions table: service_role only — permission definitions are admin-only
GRANT ALL ON @extschema@.permissions TO service_role;

GRANT ALL ON ALL TABLES IN SCHEMA @extschema@ TO service_role;

-- ─────────────────────────────────────────────────────────────────────────────
-- INTERNAL HELPER FUNCTION LOCKS
-- ─────────────────────────────────────────────────────────────────────────────
-- Revoke PUBLIC execute on all internal _-prefixed helpers. These are not part
-- of the public API and should only be called from within the extension itself.

REVOKE EXECUTE ON FUNCTION @extschema@._build_user_claims(uuid) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION @extschema@._get_user_groups() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION @extschema@._validate_roles(text[]) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION @extschema@._validate_permissions(text[]) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION @extschema@._validate_grantable_roles(text[]) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION @extschema@._check_role_escalation(uuid, text[]) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION @extschema@._check_permission_escalation(uuid, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION @extschema@._jwt_is_expired() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION @extschema@._set_updated_at() FROM PUBLIC;
-- Trigger-only functions: no EXECUTE for any non-superuser role
REVOKE EXECUTE ON FUNCTION @extschema@._on_group_created() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION @extschema@._sync_member_metadata() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION @extschema@._sync_member_permission() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION @extschema@._on_role_definition_change() FROM PUBLIC;

-- _get_user_groups: called by get_claims() INVOKER (Storage RLS fallback path)
GRANT EXECUTE ON FUNCTION @extschema@._get_user_groups() TO authenticated, service_role;
-- _jwt_is_expired: called by RLS helpers (has_role, is_member, etc.) which are INVOKER
GRANT EXECUTE ON FUNCTION @extschema@._jwt_is_expired() TO authenticated, anon, service_role;
-- _check_role_escalation/_check_permission_escalation: called by INVOKER management RPCs
GRANT EXECUTE ON FUNCTION @extschema@._check_role_escalation(uuid, text[]) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION @extschema@._check_permission_escalation(uuid, text) TO authenticated, service_role;
-- _validate_roles/_validate_permissions/_validate_grantable_roles are SECURITY DEFINER
-- (they read rbac.roles/rbac.permissions which authenticated cannot SELECT directly).
-- authenticated still needs EXECUTE to call them from INVOKER management RPCs.
GRANT EXECUTE ON FUNCTION @extschema@._validate_roles(text[]) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION @extschema@._validate_permissions(text[]) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION @extschema@._validate_grantable_roles(text[]) TO authenticated, service_role;

-- ─────────────────────────────────────────────────────────────────────────────
-- TRIGGERS
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TRIGGER handle_updated_at
    BEFORE UPDATE ON @extschema@.groups
    FOR EACH ROW EXECUTE FUNCTION @extschema@._set_updated_at();

CREATE TRIGGER on_group_created
    AFTER INSERT ON @extschema@.groups
    FOR EACH ROW EXECUTE FUNCTION @extschema@._on_group_created();

CREATE TRIGGER handle_updated_at
    BEFORE UPDATE ON @extschema@.members
    FOR EACH ROW EXECUTE FUNCTION @extschema@._set_updated_at();

CREATE TRIGGER on_change_sync_member_metadata
    AFTER INSERT OR DELETE OR UPDATE ON @extschema@.members
    FOR EACH ROW EXECUTE FUNCTION @extschema@._sync_member_metadata();

CREATE TRIGGER on_role_definition_change
    AFTER UPDATE ON @extschema@.roles
    FOR EACH ROW
    WHEN (OLD.permissions IS DISTINCT FROM NEW.permissions
       OR OLD.grantable_roles IS DISTINCT FROM NEW.grantable_roles)
    EXECUTE FUNCTION @extschema@._on_role_definition_change();

CREATE TRIGGER on_member_permission_change
    AFTER INSERT OR DELETE ON @extschema@.member_permissions
    FOR EACH ROW EXECUTE FUNCTION @extschema@._sync_member_permission();

-- ─────────────────────────────────────────────────────────────────────────────
-- POSTGREST HOOK
-- ─────────────────────────────────────────────────────────────────────────────

ALTER ROLE authenticator SET pgrst.db_pre_request TO '@extschema@.db_pre_request';
NOTIFY pgrst, 'reload config';

-- ═══════════════════════════════════════════════════════════════════════════════
-- PUBLIC API WRAPPERS (OPT-IN)
-- Public wrappers are NOT created automatically. To expose functions in the
-- public schema for PostgREST RPC discovery or unqualified RLS policy calls,
-- run the opt-in script after installation:
--
--   examples/setup/create_public_wrappers.sql
--
-- Without wrappers, use schema-qualified calls everywhere:
--   • RLS policies:  USING (rbac.has_role(group_id, 'owner'))
--   • Client SDK:    supabase.schema('rbac').rpc('create_group', {...})
--   • Auth hook URI: pg-functions://postgres/rbac/custom_access_token_hook
--
-- To remove previously created wrappers, see:
--   examples/setup/remove_public_wrappers.sql
-- ═══════════════════════════════════════════════════════════════════════════════
