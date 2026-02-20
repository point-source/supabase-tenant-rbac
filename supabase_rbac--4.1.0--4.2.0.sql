-- Upgrade from 4.1.0 to 4.2.0
--
-- Changes:
--   Add invite expiration support — new nullable "expires_at" column on group_invites.
--   Invites with expires_at = NULL never expire (same behavior as all 4.1.0 invites).
--   Invites with expires_at in the past are rejected by the edge function.
--
-- DATA SAFETY REVIEW:
--   No existing row data is modified or deleted by this upgrade.
--   Schema changes: adds a single nullable column "expires_at timestamptz" to group_invites.
--   Behavioral changes: the invite acceptance edge function now rejects invites whose
--     expires_at is set and is in the past. Existing invites all receive expires_at = NULL,
--     which the edge function treats as "no expiry" — they remain valid indefinitely,
--     identical to their behavior before this upgrade.
--   Data loss risk: none.

ALTER TABLE @extschema@.group_invites
  ADD COLUMN IF NOT EXISTS "expires_at" timestamp with time zone;
