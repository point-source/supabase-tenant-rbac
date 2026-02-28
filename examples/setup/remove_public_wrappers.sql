-- ═══════════════════════════════════════════════════════════════════════════
-- Remove Auto-Created Public Wrappers
-- ═══════════════════════════════════════════════════════════════════════════
-- When supabase_rbac is installed in a non-public schema (e.g. rbac), the
-- extension automatically creates thin wrapper functions in the public schema.
-- These wrappers enable:
--   1. PostgREST RPC discovery (supabase.rpc('has_role', ...))
--   2. Unqualified function calls in RLS policies (USING (has_role(...)))
--
-- If you prefer to use schema-qualified calls everywhere (rbac.has_role(...))
-- or want to control exactly which functions are publicly accessible, you can
-- drop some or all of these wrappers.
--
-- NOTE: DROP EXTENSION will automatically clean up all wrappers. This script
-- is only needed if you want to selectively remove wrappers while keeping
-- the extension installed.
-- ═══════════════════════════════════════════════════════════════════════════

-- ─────────────────────────────────────────────────────────────────────────
-- Remove ALL public wrappers
-- ─────────────────────────────────────────────────────────────────────────
-- Uncomment this entire block to remove all public wrappers at once.

-- RLS helpers
DROP FUNCTION IF EXISTS public.get_claims();
DROP FUNCTION IF EXISTS public.has_role(uuid, text);
DROP FUNCTION IF EXISTS public.is_member(uuid);
DROP FUNCTION IF EXISTS public.has_any_role(uuid, text[]);
DROP FUNCTION IF EXISTS public.has_all_roles(uuid, text[]);

-- Management RPCs
DROP FUNCTION IF EXISTS public.create_group(text, jsonb, text[]);
DROP FUNCTION IF EXISTS public.delete_group(uuid);
DROP FUNCTION IF EXISTS public.add_member(uuid, uuid, text[]);
DROP FUNCTION IF EXISTS public.remove_member(uuid, uuid);
DROP FUNCTION IF EXISTS public.update_member_roles(uuid, uuid, text[]);
DROP FUNCTION IF EXISTS public.list_members(uuid);
DROP FUNCTION IF EXISTS public.accept_invite(uuid);

-- Role management RPCs
DROP FUNCTION IF EXISTS public.create_role(text, text);
DROP FUNCTION IF EXISTS public.delete_role(text);
DROP FUNCTION IF EXISTS public.list_roles();

-- Auth Hook wrapper
-- NOTE: If you drop this wrapper, update config.toml to point the auth hook
-- directly at the rbac schema function instead of the public wrapper:
--   uri = "pg-functions://postgres/rbac/custom_access_token_hook"
DROP FUNCTION IF EXISTS public.custom_access_token_hook(jsonb);

-- ─────────────────────────────────────────────────────────────────────────
-- After removing wrappers
-- ─────────────────────────────────────────────────────────────────────────
-- If you removed the RLS helper wrappers, update your RLS policies to use
-- schema-qualified calls:
--
--   BEFORE: USING (has_role(group_id, 'owner'))
--   AFTER:  USING (rbac.has_role(group_id, 'owner'))
--
-- If you removed the management RPC wrappers, client-side calls must use
-- the schema-qualified name via PostgREST's schema header:
--
--   // Option A: Set the Accept-Profile header
--   const { data } = await supabase
--     .schema('rbac')
--     .rpc('create_group', { p_name: 'My Group' })
--
--   // Option B: Keep public wrappers for the functions you use most
--   //           and only drop the ones you don't need.
