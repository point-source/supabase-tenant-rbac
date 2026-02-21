-- Storage RLS Policy Examples
--
-- As of v4.3.0, get_user_claims() falls back to a SECURITY DEFINER helper that
-- reads auth.users directly instead of relying on potentially stale JWT claims.
-- This means user_has_group_role() and user_is_group_member() now work correctly
-- in Supabase Storage RLS policies — role changes take effect immediately without
-- waiting for JWT refresh.
--
-- Two patterns are shown below depending on how the group_id is associated with
-- each storage object.

-- ============================================================
-- Pattern 1: group_id embedded in the object path
-- ============================================================
-- Convention: objects are stored at "<group_id>/<filename>"
-- Example path: "c2aa61f5-d86b-45e8-9e6d-a5bae98cd530/report.pdf"
--
-- The group_id is extracted from the first path segment using string_to_array.

-- Allow any group member to read objects in their group's folder
CREATE POLICY "Group members can read objects"
ON storage.objects
FOR SELECT
TO authenticated
USING (
    bucket_id = 'group-files'
    AND user_is_group_member((string_to_array(name, '/'))[1]::uuid)
);

-- Allow group members with the 'uploader' role to insert objects
CREATE POLICY "Uploaders can insert objects"
ON storage.objects
FOR INSERT
TO authenticated
WITH CHECK (
    bucket_id = 'group-files'
    AND user_has_group_role((string_to_array(name, '/'))[1]::uuid, 'uploader')
);

-- Allow group members with the 'uploader' role to update their objects
CREATE POLICY "Uploaders can update objects"
ON storage.objects
FOR UPDATE
TO authenticated
USING (
    bucket_id = 'group-files'
    AND user_has_group_role((string_to_array(name, '/'))[1]::uuid, 'uploader')
)
WITH CHECK (
    bucket_id = 'group-files'
    AND user_has_group_role((string_to_array(name, '/'))[1]::uuid, 'uploader')
);

-- Allow group admins to delete objects
CREATE POLICY "Admins can delete objects"
ON storage.objects
FOR DELETE
TO authenticated
USING (
    bucket_id = 'group-files'
    AND user_has_group_role((string_to_array(name, '/'))[1]::uuid, 'admin')
);


-- ============================================================
-- Pattern 2: group_id stored in object metadata
-- ============================================================
-- Objects are stored with a custom metadata field: { "group_id": "<uuid>" }
-- This is set at upload time via the Supabase Storage client.
--
-- The group_id is extracted from the object's metadata column.

-- Allow any group member to read objects tagged with their group
CREATE POLICY "Group members can read tagged objects"
ON storage.objects
FOR SELECT
TO authenticated
USING (
    bucket_id = 'group-assets'
    AND user_is_group_member((metadata->>'group_id')::uuid)
);

-- Allow group members with the 'editor' role to insert tagged objects
CREATE POLICY "Editors can insert tagged objects"
ON storage.objects
FOR INSERT
TO authenticated
WITH CHECK (
    bucket_id = 'group-assets'
    AND user_has_group_role((metadata->>'group_id')::uuid, 'editor')
);

-- Allow group members with the 'editor' role to update tagged objects
CREATE POLICY "Editors can update tagged objects"
ON storage.objects
FOR UPDATE
TO authenticated
USING (
    bucket_id = 'group-assets'
    AND user_has_group_role((metadata->>'group_id')::uuid, 'editor')
)
WITH CHECK (
    bucket_id = 'group-assets'
    AND user_has_group_role((metadata->>'group_id')::uuid, 'editor')
);

-- Allow group admins to delete tagged objects
CREATE POLICY "Admins can delete tagged objects"
ON storage.objects
FOR DELETE
TO authenticated
USING (
    bucket_id = 'group-assets'
    AND user_has_group_role((metadata->>'group_id')::uuid, 'admin')
);
