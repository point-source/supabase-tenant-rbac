-- ═══════════════════════════════════════════════════════════════════════════
-- Quickstart RLS Policies for supabase_rbac v5.2.0
-- ═══════════════════════════════════════════════════════════════════════════
-- These are recommended starter policies for the rbac extension tables.
-- The extension ships with RLS enabled and ZERO policies (deny-all default).
-- You MUST add policies or no one can interact with the extension.
--
-- Adjust the schema name below if you installed the extension in a schema
-- other than 'rbac'.
--
-- These policies use the 'owner' role (pre-seeded in rbac.roles) for
-- management operations. Add more roles to rbac.roles and adjust these
-- policies to fit your application's needs.
-- ═══════════════════════════════════════════════════════════════════════════

-- ─────────────────────────────────────────────────────────────────────────
-- rbac.groups
-- ─────────────────────────────────────────────────────────────────────────

-- Any member of a group can read that group
CREATE POLICY "Members can read their groups"
    ON rbac.groups FOR SELECT
    TO authenticated
    USING (is_member(id));

-- Owners can update group name/metadata
CREATE POLICY "Owners can update their groups"
    ON rbac.groups FOR UPDATE
    TO authenticated
    USING (has_role(id, 'owner'))
    WITH CHECK (has_role(id, 'owner'));

-- Owners can delete groups they own
CREATE POLICY "Owners can delete their groups"
    ON rbac.groups FOR DELETE
    TO authenticated
    USING (has_role(id, 'owner'));

-- NOTE: Group creation is handled by the create_group() RPC (SECURITY DEFINER),
-- which bypasses RLS. No INSERT policy is needed for normal use.
-- If you allow direct INSERTs (not recommended), add an INSERT policy here.

-- ─────────────────────────────────────────────────────────────────────────
-- rbac.members
-- ─────────────────────────────────────────────────────────────────────────

-- Members can see other members in their groups
CREATE POLICY "Members can read group memberships"
    ON rbac.members FOR SELECT
    TO authenticated
    USING (is_member(group_id));

-- Owners can add members to their groups
CREATE POLICY "Owners can add members"
    ON rbac.members FOR INSERT
    TO authenticated
    WITH CHECK (has_role(group_id, 'owner'));

-- Owners can update member roles in their groups
CREATE POLICY "Owners can update member roles"
    ON rbac.members FOR UPDATE
    TO authenticated
    USING (has_role(group_id, 'owner'))
    WITH CHECK (has_role(group_id, 'owner'));

-- Owners can remove members, and members can remove themselves
CREATE POLICY "Owners can remove members or self-remove"
    ON rbac.members FOR DELETE
    TO authenticated
    USING (
        has_role(group_id, 'owner')
        OR user_id = auth.uid()
    );

-- ─────────────────────────────────────────────────────────────────────────
-- rbac.invites
-- ─────────────────────────────────────────────────────────────────────────

-- Members can see invites for their groups
CREATE POLICY "Members can read group invites"
    ON rbac.invites FOR SELECT
    TO authenticated
    USING (is_member(group_id));

-- Owners can create invites
CREATE POLICY "Owners can create invites"
    ON rbac.invites FOR INSERT
    TO authenticated
    WITH CHECK (has_role(group_id, 'owner'));

-- The accept_invite() RPC is SECURITY DEFINER and bypasses RLS.
-- This UPDATE policy allows owners to manually modify invites if needed.
CREATE POLICY "Owners can update invites"
    ON rbac.invites FOR UPDATE
    TO authenticated
    USING (has_role(group_id, 'owner'))
    WITH CHECK (has_role(group_id, 'owner'));

-- Owners can revoke invites
CREATE POLICY "Owners can delete invites"
    ON rbac.invites FOR DELETE
    TO authenticated
    USING (has_role(group_id, 'owner'));

-- ─────────────────────────────────────────────────────────────────────────
-- rbac.roles
-- ─────────────────────────────────────────────────────────────────────────

-- All authenticated users can read role definitions
CREATE POLICY "Authenticated users can read roles"
    ON rbac.roles FOR SELECT
    TO authenticated
    USING (true);

-- Only service_role can manage role definitions (via create_role/delete_role RPCs
-- called from server-side code or the Supabase dashboard).
-- If you want authenticated users to manage roles, replace 'service_role' below.
CREATE POLICY "Service role can manage roles"
    ON rbac.roles FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- ─────────────────────────────────────────────────────────────────────────
-- rbac.member_permissions
-- ─────────────────────────────────────────────────────────────────────────
-- Direct permission overrides per member. These merge into the claims cache
-- alongside permissions from roles.
--
-- The 'group.manage_access' permission below is a convention, not hard-coded.
-- Adjust to match your application's permission naming scheme.

-- Members can see permission overrides in their groups
CREATE POLICY "Members can read permission overrides"
    ON rbac.member_permissions FOR SELECT TO authenticated
    USING (rbac.is_member(group_id));

-- Users with the 'group.manage_access' permission can grant/revoke overrides
CREATE POLICY "Claims writers can manage permission overrides"
    ON rbac.member_permissions FOR ALL TO authenticated
    USING (rbac.has_permission(group_id, 'group.manage_access'))
    WITH CHECK (rbac.has_permission(group_id, 'group.manage_access'));

-- service_role has full access for admin operations
CREATE POLICY "Service role has full access to permission overrides"
    ON rbac.member_permissions FOR ALL TO service_role
    USING (true) WITH CHECK (true);

-- ─────────────────────────────────────────────────────────────────────────
-- rbac.user_claims
-- ─────────────────────────────────────────────────────────────────────────
-- This table is written exclusively by the three SECURITY DEFINER trigger
-- functions (_sync_member_metadata, _sync_member_permission,
-- _on_role_permissions_change). They run as the function owner (postgres),
-- not the calling role, so authenticated does NOT need INSERT/UPDATE here.
-- Do NOT add INSERT/UPDATE policies for authenticated — that would allow
-- any user to forge claims for any user_id.

-- PostgREST pre-request hook reads claims for the authenticated user
CREATE POLICY "authenticator can read all claims"
    ON rbac.user_claims FOR SELECT
    TO authenticator
    USING (true);

-- Supabase Auth Hook reads claims for the token being issued
CREATE POLICY "supabase_auth_admin can read all claims"
    ON rbac.user_claims FOR SELECT
    TO supabase_auth_admin
    USING (true);

-- service_role needs full access for admin operations
CREATE POLICY "service_role has full access to claims"
    ON rbac.user_claims FOR ALL
    TO service_role
    USING (true);

-- authenticated SELECT: needed by _get_user_groups() (Storage RLS fallback)
CREATE POLICY "Users can read own claims"
    ON rbac.user_claims FOR SELECT
    TO authenticated
    USING (user_id = auth.uid());
