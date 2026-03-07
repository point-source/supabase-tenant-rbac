-- Storage RLS Policy Examples
--
-- get_claims() falls back to reading rbac.user_claims directly instead of
-- relying on request.groups (which is only set by db_pre_request). This means
-- rbac.has_role() and rbac.is_member() work correctly in Supabase Storage RLS policies —
-- role changes take effect immediately without waiting for JWT refresh.
--
-- Two patterns are shown below depending on how the group_id is associated with
-- each storage object.

-- ============================================================
-- Pattern 1: group_id embedded in the object path
-- ============================================================
-- Convention: objects are stored at "<group_id>/<filename>"
-- Example path: "c2aa61f5-d86b-45e8-9e6d-a5bae98cd530/report.pdf"

CREATE POLICY "Group members can read objects"
ON storage.objects
FOR SELECT
TO authenticated
USING (
    bucket_id = 'group-files'
    AND rbac.is_member((string_to_array(name, '/'))[1]::uuid)
);

CREATE POLICY "Uploaders can insert objects"
ON storage.objects
FOR INSERT
TO authenticated
WITH CHECK (
    bucket_id = 'group-files'
    AND rbac.has_role((string_to_array(name, '/'))[1]::uuid, 'uploader')
);

CREATE POLICY "Uploaders can update objects"
ON storage.objects
FOR UPDATE
TO authenticated
USING (
    bucket_id = 'group-files'
    AND rbac.has_role((string_to_array(name, '/'))[1]::uuid, 'uploader')
)
WITH CHECK (
    bucket_id = 'group-files'
    AND rbac.has_role((string_to_array(name, '/'))[1]::uuid, 'uploader')
);

CREATE POLICY "Admins can delete objects"
ON storage.objects
FOR DELETE
TO authenticated
USING (
    bucket_id = 'group-files'
    AND rbac.has_role((string_to_array(name, '/'))[1]::uuid, 'admin')
);

-- ============================================================
-- Pattern 2: group_id stored in object metadata
-- ============================================================

CREATE POLICY "Group members can read tagged objects"
ON storage.objects
FOR SELECT
TO authenticated
USING (
    bucket_id = 'group-assets'
    AND rbac.is_member((metadata->>'group_id')::uuid)
);

CREATE POLICY "Editors can insert tagged objects"
ON storage.objects
FOR INSERT
TO authenticated
WITH CHECK (
    bucket_id = 'group-assets'
    AND rbac.has_role((metadata->>'group_id')::uuid, 'editor')
);

CREATE POLICY "Editors can update tagged objects"
ON storage.objects
FOR UPDATE
TO authenticated
USING (
    bucket_id = 'group-assets'
    AND rbac.has_role((metadata->>'group_id')::uuid, 'editor')
)
WITH CHECK (
    bucket_id = 'group-assets'
    AND rbac.has_role((metadata->>'group_id')::uuid, 'editor')
);

CREATE POLICY "Admins can delete tagged objects"
ON storage.objects
FOR DELETE
TO authenticated
USING (
    bucket_id = 'group-assets'
    AND rbac.has_role((metadata->>'group_id')::uuid, 'admin')
);
