#!/usr/bin/env bash
# DEPRECATED for agent workflow — CI/human optional only. Agents: rg per references/burp-host-discovery.md
# Usage: bash scripts/discover_burp_hosts.sh [REPO_ROOT]
# Output: burp_hosts.txt

set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"
OUT="${ROOT}/burp_hosts.txt"
: > "$OUT"

echo "=== Burp Host Discovery (code-derived only) ===" | tee -a "$OUT"
echo "Root: $ROOT" | tee -a "$OUT"
echo "Rule: NEVER use localhost / 127.0.0.1 for Burp probes" | tee -a "$OUT"
echo "" | tee -a "$OUT"

if ! command -v rg >/dev/null 2>&1; then
  echo "ERROR: rg required" | tee -a "$OUT"
  exit 1
fi

echo "--- Hosts from config ---" | tee -a "$OUT"
rg -o "https?://[a-zA-Z0-9][-a-zA-Z0-9._]*\.[a-zA-Z]{2,}(:[0-9]+)?" src/configs/ --glob "config-*.js" 2>/dev/null \
  | sort -u | tee -a "$OUT" || true

echo "" | tee -a "$OUT"
echo "--- Hosts from src (https URLs) ---" | tee -a "$OUT"
rg -o "https?://[a-zA-Z0-9][-a-zA-Z0-9._]*\.[a-zA-Z]{2,}(:[0-9]+)?" src/ \
  --glob '!node_modules' --glob '!test' --glob '!tests' 2>/dev/null \
  | sort -u | head -40 | tee -a "$OUT" || true

echo "" | tee -a "$OUT"
echo "--- Filtered external hosts (no localhost) ---" | tee -a "$OUT"
{
  rg -o "https?://[a-zA-Z0-9][-a-zA-Z0-9._]*\.[a-zA-Z]{2,}(:[0-9]+)?" src/configs/ src/ \
    --glob '!node_modules' --glob '!test' --glob '!tests' 2>/dev/null || true
} | sed -E 's|https?://||; s|/.*||; s|:.*||' \
  | grep -viE '^(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|host\.docker\.internal)$' \
  | sort -u | tee -a "$OUT"

COUNT=$(grep -cE '^[a-zA-Z0-9]' "$OUT" 2>/dev/null || echo 0)
echo "" | tee -a "$OUT"
if [ "$COUNT" -eq 0 ]; then
  echo "RESULT: NO_EXTERNAL_HOST — skip Burp probes; use Not Verified (no target host in code)" | tee -a "$OUT"
else
  echo "RESULT: HOSTS_FOUND=$COUNT — use staging/dev host for Burp MCP" | tee -a "$OUT"
fi
