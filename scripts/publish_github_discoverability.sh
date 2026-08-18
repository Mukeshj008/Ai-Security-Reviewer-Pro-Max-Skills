#!/usr/bin/env bash
# Enable GitHub Pages (/docs) and set repo Topics + homepage.
# Requires GH_TOKEN or GITHUB_TOKEN with Administration + Contents on the repo.
set -euo pipefail

TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
if [[ -z "$TOKEN" ]]; then
  echo "Set GH_TOKEN or GITHUB_TOKEN first." >&2
  exit 1
fi

REPO="Mukeshj008/Ai-Security-Reviewer-Pro-Max-Skills"
API="https://api.github.com/repos/${REPO}"
AUTH=( -H "Authorization: Bearer ${TOKEN}" -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" )

curl -sS "${AUTH[@]}" -X PATCH "$API" \
  -d '{"homepage":"https://mukeshj008.github.io/Ai-Security-Reviewer-Pro-Max-Skills/"}' >/dev/null

curl -sS "${AUTH[@]}" -X PUT "$API/topics" \
  -d '{"names":["ai-security-reviewer","cursor-skill","claude-skill","sast","dast","owasp","appsec","security-review","false-positives"]}' >/dev/null

# Enable Pages from main /docs (201 if new, 409 if already on).
pages_code="$(curl -sS -o /tmp/gh-pages-enable.json -w '%{http_code}' "${AUTH[@]}" -X POST "$API/pages" \
  -d '{"source":{"branch":"main","path":"/docs"}}')"
if [[ "$pages_code" != "201" && "$pages_code" != "409" ]]; then
  echo "Pages enable returned HTTP ${pages_code}:" >&2
  cat /tmp/gh-pages-enable.json >&2
  exit 1
fi

echo "Homepage, topics, and GitHub Pages (main /docs) are set."
echo "Site: https://mukeshj008.github.io/Ai-Security-Reviewer-Pro-Max-Skills/"
echo "Repo: https://github.com/${REPO}"
