#!/usr/bin/env bash
# One-time setup: configure git to use the project's .githooks directory.
# Run this after cloning the repository.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

git -C "$REPO_ROOT" config core.hooksPath .githooks
chmod +x "$REPO_ROOT/.githooks/pre-commit"
echo "Git hooks configured. Pre-commit hook will auto-regenerate the install_rbac migration when extension files change."
