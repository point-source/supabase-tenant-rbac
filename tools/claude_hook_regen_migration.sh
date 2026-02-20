#!/usr/bin/env bash
# Claude Code PostToolUse hook: regenerate the install_rbac migration when
# the extension control file or a versioned extension SQL file is written or edited.
#
# Claude passes the tool call result as JSON to stdin. We extract the file_path
# and check if it matches the pattern of files that affect the migration.

set -euo pipefail

# Parse the file_path from Claude's tool input JSON
FILE_PATH=$(python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('tool_input', {}).get('file_path', ''))
except Exception:
    print('')
" 2>/dev/null || echo "")

# Only regenerate for extension SQL files and the control file
if echo "$FILE_PATH" | grep -qE 'supabase_rbac(--[0-9.]+)?\.sql$|supabase_rbac\.control$'; then
    REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    "$REPO_ROOT/tools/generate_migration.sh"
fi
