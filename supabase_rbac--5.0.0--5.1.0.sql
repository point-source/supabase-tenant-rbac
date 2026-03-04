-- ═══════════════════════════════════════════════════════════════════════════════
-- supabase_rbac upgrade: 5.0.0 → 5.1.0
-- ═══════════════════════════════════════════════════════════════════════════════
-- Adds direct per-member permission overrides via the new member_permissions table.
-- Permissions from overrides merge with role-derived permissions in the claims cache.
-- Backwards compatible: existing claims format and all helper functions are unchanged.

-- DATA SAFETY REVIEW:
--   Schema changes:
--     - Promotes existing UNIQUE INDEX members_group_user_idx to a named UNIQUE
--       CONSTRAINT (members_group_user_uq). Non-destructive: reuses the index,
--       no rebuild, no data touched.
--     - Creates new table member_permissions (additive only — no existing table altered).
--     - Replaces _build_user_claims() via CREATE OR REPLACE (additive UNION ALL branch;
--       existing data unchanged, output is a superset of the prior function's output).
--     - Creates new trigger function _sync_member_permission() and trigger
--       on_member_permission_change (no impact until rows are written to the new table).
--     - Creates 3 new RPCs (grant_member_permission, revoke_member_permission,
--       list_member_permissions). Additive only. grant_member_permission and
--       revoke_member_permission now include an in-function is_member() guard
--       (cross-group escalation defense-in-depth) and empty-permission validation.
--       These are purely additive runtime checks — no schema or data change.
--   Potentially destructive operations detected:
--     - DELETE FROM @extschema@.member_permissions inside revoke_member_permission():
--       This is a single-row targeted delete (WHERE group_id = $1 AND user_id = $2
--       AND permission = $3). It operates only on the newly created table. There are
--       no rows in this table at upgrade time, and the function is only called by
--       callers explicitly revoking a specific override they previously granted.
--       The function additionally checks is_member(p_group_id) before executing the
--       DELETE, so callers not in the target group are rejected before DML runs.
--       Not a bulk operation; raises if no row is found (IF NOT FOUND THEN RAISE).
--   Behavioral changes:
--     - _build_user_claims now includes direct overrides from member_permissions in
--       the permissions[] array. Before upgrade the table is empty, so no claims
--       change at upgrade time. Claims only change when a caller explicitly grants
--       an override after upgrade.
--   Data loss risk: none — no existing table is dropped, truncated, or modified.
--     All existing rows in groups, members, invites, roles, and user_claims are
--     untouched. The constraint promotion reuses the existing index with no rebuild.

-- ─────────────────────────────────────────────────────────────────────────────
-- STEP 1: Promote unique index on members(group_id, user_id) to a named
-- constraint so member_permissions can reference it via FK.
-- Non-destructive: reuses the existing index, no index rebuild required.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE @extschema@.members
    ADD CONSTRAINT members_group_user_uq UNIQUE USING INDEX members_group_user_idx;

-- ─────────────────────────────────────────────────────────────────────────────
-- STEP 2: Create the member_permissions table
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE @extschema@.member_permissions (
    id          uuid        NOT NULL DEFAULT gen_random_uuid(),
    group_id    uuid        NOT NULL,
    user_id     uuid        NOT NULL,
    permission  text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Primary key
CREATE UNIQUE INDEX member_permissions_pkey ON @extschema@.member_permissions USING btree (id);
ALTER TABLE @extschema@.member_permissions
    ADD CONSTRAINT member_permissions_pkey PRIMARY KEY USING INDEX member_permissions_pkey;

-- Enforce uniqueness of (group_id, user_id, permission) — enables idempotent grants
CREATE UNIQUE INDEX member_permissions_group_user_perm_idx
    ON @extschema@.member_permissions USING btree (group_id, user_id, permission);

-- Index on user_id for efficient claims rebuild lookups
CREATE INDEX member_permissions_user_id_idx
    ON @extschema@.member_permissions USING btree (user_id);

-- FK → groups(id)
ALTER TABLE @extschema@.member_permissions
    ADD CONSTRAINT member_permissions_group_id_fkey FOREIGN KEY (group_id)
    REFERENCES @extschema@.groups (id) ON DELETE CASCADE NOT VALID;
ALTER TABLE @extschema@.member_permissions VALIDATE CONSTRAINT member_permissions_group_id_fkey;

-- FK → auth.users(id)
ALTER TABLE @extschema@.member_permissions
    ADD CONSTRAINT member_permissions_user_id_fkey FOREIGN KEY (user_id)
    REFERENCES auth.users (id) ON DELETE CASCADE NOT VALID;
ALTER TABLE @extschema@.member_permissions VALIDATE CONSTRAINT member_permissions_user_id_fkey;

-- FK → members(group_id, user_id): CASCADE ensures overrides are removed when
-- the underlying membership is removed.
ALTER TABLE @extschema@.member_permissions
    ADD CONSTRAINT member_permissions_member_fkey FOREIGN KEY (group_id, user_id)
    REFERENCES @extschema@.members (group_id, user_id) ON DELETE CASCADE NOT VALID;
ALTER TABLE @extschema@.member_permissions VALIDATE CONSTRAINT member_permissions_member_fkey;

-- Enable RLS (deny-all by default — consumers add policies)
ALTER TABLE @extschema@.member_permissions ENABLE ROW LEVEL SECURITY;

-- ─────────────────────────────────────────────────────────────────────────────
-- STEP 3: Grant DML on the new table
-- ─────────────────────────────────────────────────────────────────────────────

GRANT SELECT, INSERT, DELETE ON @extschema@.member_permissions TO authenticated;
GRANT ALL ON @extschema@.member_permissions TO service_role;

-- ─────────────────────────────────────────────────────────────────────────────
-- STEP 4: Update _build_user_claims to include direct permission overrides
-- ─────────────────────────────────────────────────────────────────────────────

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
                'permissions', sub.perms_arr
            )
        ),
        '{}'::jsonb
    )
    FROM (
        SELECT
            m.group_id::text AS gid,
            to_jsonb(m.roles) AS roles_arr,
            coalesce(
                to_jsonb(
                    (SELECT array_agg(DISTINCT perm ORDER BY perm)
                     FROM (
                         -- Permissions from global role definitions
                         SELECT unnest(r.permissions) AS perm
                         FROM @extschema@.roles r
                         WHERE r.name = ANY(m.roles)
                         UNION ALL
                         -- Direct per-member permission overrides
                         SELECT mp.permission
                         FROM @extschema@.member_permissions mp
                         WHERE mp.group_id = m.group_id AND mp.user_id = m.user_id
                     ) AS all_perms)
                ),
                '[]'::jsonb
            ) AS perms_arr
        FROM @extschema@.members m
        WHERE m.user_id = p_user_id
    ) sub
$function$;

-- ─────────────────────────────────────────────────────────────────────────────
-- STEP 5: Create the trigger function and trigger for member_permissions
-- ─────────────────────────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION @extschema@._sync_member_permission()
RETURNS trigger
LANGUAGE plpgsql
-- No SECURITY DEFINER — writes to extension-owned user_claims table
SET search_path = @extschema@
AS $function$
DECLARE
    _user_id    uuid;
    _new_groups jsonb;
BEGIN
    _user_id := coalesce(NEW.user_id, OLD.user_id);

    -- Rebuild full claims for this user (includes remaining direct overrides)
    SELECT _build_user_claims(_user_id) INTO _new_groups;

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

CREATE TRIGGER on_member_permission_change
    AFTER INSERT OR DELETE ON @extschema@.member_permissions
    FOR EACH ROW EXECUTE FUNCTION @extschema@._sync_member_permission();

-- ─────────────────────────────────────────────────────────────────────────────
-- STEP 6: Create the 3 new management RPCs
-- ─────────────────────────────────────────────────────────────────────────────

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
