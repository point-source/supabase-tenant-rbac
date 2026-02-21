-- Upgrade path: 4.2.0 → 4.3.0
-- Fix #34: Replace JWT fallback in get_user_claims() with a SECURITY DEFINER helper
-- that reads auth.users directly, giving Storage RLS the same freshness guarantee
-- as PostgREST requests.

-- DATA SAFETY REVIEW:
--   No existing row data is modified by this upgrade.
--   Schema changes: none — no tables, columns, indexes, or constraints are altered.
--   New objects: _get_user_groups() SECURITY DEFINER function (new internal helper).
--   Changed objects: get_user_claims() body updated (SECURITY INVOKER, same signature).
--   Behavioral changes: get_user_claims() fallback changes from stale JWT claims to a
--     fresh DB read via _get_user_groups(). PostgREST callers are unaffected (request.groups
--     takes precedence as before). Storage callers now get fresh data instead of stale JWT data.
--   Data loss risk: none — purely additive function additions/replacements.

-- New internal helper: reads auth.users directly for the Storage fallback path.
-- Leading underscore signals this is an internal function, not a public API.
create
or replace function @extschema@._get_user_groups () returns jsonb language sql stable security definer
set
  search_path = @extschema@ as $function$
    select coalesce(
        (select raw_app_meta_data->'groups' from auth.users where id = auth.uid()),
        '{}'
    )
$function$;

-- Updated fallback: DB read instead of potentially stale JWT claims.
-- PostgREST path unchanged: request.groups (from db_pre_request) still takes precedence.
-- Storage path: request.groups is unset → falls back to _get_user_groups() (fresh DB read).
create
or replace function @extschema@.get_user_claims () returns jsonb language sql stable
set
  search_path = @extschema@ as $function$
select coalesce(
    nullif(current_setting('request.groups', true), '')::jsonb,
    _get_user_groups()
)::jsonb
$function$;
