-- Upgrade path: 5.2.0 → 5.2.1
-- Adds covering indexes for two foreign keys on @extschema@.invites that
-- were previously unindexed. Resolves the Supabase linter warning
-- `unindexed_foreign_keys` and avoids seq scans when the referenced
-- auth.users rows are deleted (ON DELETE CASCADE).
--
-- The _version() function is replaced automatically by tools/install.sh and
-- picks up the SET search_path = '' hardening applied in 5.2.1.
--
-- DATA SAFETY REVIEW:
--   Schema changes: two new btree indexes on existing columns.
--   Behavioral changes: none — indexes are covering only; no query results change.
--   Data loss risk: none — CREATE INDEX IF NOT EXISTS is idempotent.

CREATE INDEX IF NOT EXISTS invites_invited_by_idx
    ON @extschema@.invites USING btree (invited_by);

CREATE INDEX IF NOT EXISTS invites_user_id_idx
    ON @extschema@.invites USING btree (user_id);
