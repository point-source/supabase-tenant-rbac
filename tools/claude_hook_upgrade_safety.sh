#!/usr/bin/env bash
# Claude Stop hook: ensure version upgrade SQL files have an explicit data safety review.
#
# When a file matching supabase_rbac--OLD--NEW.sql is new or modified in the
# working tree, this hook verifies it contains a "-- DATA SAFETY" comment block
# documenting that no user data will be lost. It also scans for destructive SQL
# operations (DROP TABLE, DROP COLUMN, TRUNCATE, DELETE FROM) as a secondary check.
#
# Exit codes:
#   0 — no upgrade files pending, or all have a DATA SAFETY comment (Claude may stop)
#   1 — upgrade file(s) found without a data safety review (blocks Claude stop;
#       the message below is fed back to Claude asking for an explicit review)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.."; pwd)"

# Find new or modified upgrade SQL files in the working tree.
# Upgrade files match: supabase_rbac--X.Y.Z--A.B.C.sql (two version segments)
UPGRADE_FILES=$(
    git -C "$REPO_ROOT" status --porcelain 2>/dev/null \
        | sed 's/^...//' \
        | grep -E '^supabase_rbac--[0-9]+\.[0-9]+\.[0-9]+--[0-9]+\.[0-9]+\.[0-9]+\.sql$' \
        || true
)

if [ -z "$UPGRADE_FILES" ]; then
    exit 0
fi

MISSING_REVIEW=""
DANGEROUS_OPS=""

while IFS= read -r FILE; do
    [ -z "$FILE" ] && continue
    FULL_PATH="$REPO_ROOT/$FILE"
    [ -f "$FULL_PATH" ] || continue

    # Check for a DATA SAFETY comment block (matches "-- DATA SAFETY REVIEW:",
    # "-- DATA SAFETY NOTES:", "-- DATA SAFETY:", etc.)
    if ! grep -qiE '^\s*--\s*DATA SAFETY' "$FULL_PATH"; then
        MISSING_REVIEW="${MISSING_REVIEW}  - ${FILE}\n"
    fi

    # Strip comment lines and scan for destructive SQL operations.
    NON_COMMENT=$(grep -viE '^\s*--' "$FULL_PATH" || true)
    FOUND_OPS=""
    if echo "$NON_COMMENT" | grep -qiE '\bDROP\s+TABLE\b'  2>/dev/null; then FOUND_OPS="${FOUND_OPS} DROP TABLE,";  fi
    if echo "$NON_COMMENT" | grep -qiE '\bDROP\s+COLUMN\b' 2>/dev/null; then FOUND_OPS="${FOUND_OPS} DROP COLUMN,"; fi
    if echo "$NON_COMMENT" | grep -qiE '\bTRUNCATE\b'       2>/dev/null; then FOUND_OPS="${FOUND_OPS} TRUNCATE,";    fi
    if echo "$NON_COMMENT" | grep -qiE '\bDELETE\s+FROM\b' 2>/dev/null; then FOUND_OPS="${FOUND_OPS} DELETE FROM,"; fi
    if [ -n "$FOUND_OPS" ]; then
        DANGEROUS_OPS="${DANGEROUS_OPS}  - ${FILE}:${FOUND_OPS%,}\n"
    fi
done <<< "$UPGRADE_FILES"

# All clear — every upgrade file has a data safety comment and no dangerous ops.
if [ -z "$MISSING_REVIEW" ] && [ -z "$DANGEROUS_OPS" ]; then
    exit 0
fi

# Build a feedback message that will be fed back to Claude to prompt a review.
cat <<'HEADER'
=== UPGRADE SAFETY REVIEW REQUIRED ===

A version upgrade SQL file (supabase_rbac--OLD--NEW.sql) is new or modified in
the working tree. Before this turn ends, please review it for data safety.
HEADER

if [ -n "$MISSING_REVIEW" ]; then
    echo ""
    echo "Files missing a DATA SAFETY comment block:"
    printf "%b" "$MISSING_REVIEW"
    cat <<'HINT'

Add a comment block near the top of each file, for example:

  -- DATA SAFETY REVIEW:
  --   No existing row data is modified by this upgrade.
  --   Schema changes: <describe what changes — new columns, new constraints, etc.>
  --   Behavioral changes: <describe any behavior changes, or "none">
  --   Data loss risk: none — <rationale>

If data loss IS possible (e.g. DROP COLUMN, type change, TRUNCATE), explain
exactly what will be lost and whether a migration guard or backup step is needed.
HINT
fi

if [ -n "$DANGEROUS_OPS" ]; then
    echo ""
    echo "Potentially destructive operations detected in non-comment lines:"
    printf "%b" "$DANGEROUS_OPS"
    echo ""
    echo "Please verify these are intentional and document them in the DATA SAFETY comment."
fi

cat <<'FOOTER'

Required steps:
  1. Read the flagged upgrade file(s) carefully.
  2. Check for any DROP, TRUNCATE, DELETE, type changes, or removed constraints.
  3. Add (or update) the -- DATA SAFETY REVIEW: comment block with your findings.
  4. If data loss is possible, document it explicitly and consider whether a
     pre-upgrade guard or backup recommendation is needed in the CHANGELOG.
FOOTER

exit 1
