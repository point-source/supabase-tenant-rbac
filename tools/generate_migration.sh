#!/usr/bin/env bash
# Generates supabase/migrations/20240502214828_install_rbac.sql from the
# current default extension version declared in supabase_rbac.control.
#
# Usage: tools/generate_migration.sh
#   Run from any directory in the repository — the script resolves the repo root.
#
# This script is the single source of truth mechanism: update default_version
# in supabase_rbac.control, create/update the corresponding supabase_rbac--X.Y.Z.sql,
# and this script will regenerate the migration to match.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTROL_FILE="$REPO_ROOT/supabase_rbac.control"
MIGRATION_FILE="$REPO_ROOT/supabase/migrations/20240502214828_install_rbac.sql"

# --- Read default_version from the control file ---
VERSION=$(grep "^default_version" "$CONTROL_FILE" | sed "s/default_version = '\\(.*\\)'/\\1/")

if [ -z "$VERSION" ]; then
    echo "ERROR: Could not read default_version from $CONTROL_FILE" >&2
    exit 1
fi

SQL_FILE="$REPO_ROOT/supabase_rbac--${VERSION}.sql"

if [ ! -f "$SQL_FILE" ]; then
    echo "ERROR: $SQL_FILE not found. Create it before updating default_version." >&2
    exit 1
fi

# --- Generate the migration ---
TEMP_FILE=$(mktemp)
trap 'rm -f "$TEMP_FILE"' EXIT

{
    printf "CREATE SCHEMA IF NOT EXISTS rbac;\n"
    printf "\n"
    printf "SELECT\n"
    printf "  pgtle.install_extension (\n"
    printf "    'pointsource-supabase_rbac',\n"
    printf "    '%s',\n" "$VERSION"
    printf "    'Supabase Multi-Tenant Role-based Access Control',\n"
    printf "    \$_pgtle_\$\n"
    cat "$SQL_FILE"
    printf "\$_pgtle_\$\n"
    printf "  );\n"
    printf "\n"
    printf "CREATE EXTENSION \"pointsource-supabase_rbac\" SCHEMA rbac VERSION '%s';\n" "$VERSION"
} > "$TEMP_FILE"

# Only write if content changed (avoid dirty git state on no-op runs)
if diff -q "$TEMP_FILE" "$MIGRATION_FILE" > /dev/null 2>&1; then
    echo "install_rbac migration is already up to date (v${VERSION})"
else
    cp "$TEMP_FILE" "$MIGRATION_FILE"
    echo "Generated $MIGRATION_FILE from supabase_rbac--${VERSION}.sql"
fi
