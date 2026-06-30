#!/usr/bin/env bash
# Push ai-security-reviewer to GitHub Pro Max repo.
# Requires GITHUB_TOKEN with Contents: Read and write on the target repo.
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/Mukeshj008/Ai-Security-Reviewer-Pro-Max-Skills.git}"
BRANCH="${BRANCH:-main}"
SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "Set GITHUB_TOKEN (fine-grained PAT with Contents: Read and write)." >&2
  exit 1
fi

export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS
GIT_ASKPASS="$(mktemp)"
chmod +x "$GIT_ASKPASS"
cat > "$GIT_ASKPASS" << 'EOF'
#!/bin/sh
case "$1" in
  *[Uu]sername*) echo "Mukeshj008" ;;
  *[Pp]assword*) echo "$GITHUB_TOKEN" ;;
  *) echo "$GITHUB_TOKEN" ;;
esac
EOF

cd "$SKILL_DIR"
git remote remove origin 2>/dev/null || true
git remote add origin "$REPO_URL"
git -c credential.helper= push -u origin "$BRANCH"
rm -f "$GIT_ASKPASS"
echo "Pushed to $REPO_URL ($BRANCH)"
