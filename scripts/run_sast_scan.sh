#!/usr/bin/env bash
# run_sast_scan.sh — agent-native SAST runner (OpenGrep class taxonomy, rg only)
# Usage: bash scripts/run_sast_scan.sh [REPO_ROOT]
# Output: sast_scan_results.txt

set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"

SRC_DIRS=""
for d in src lib app server api; do
  [ -d "$d" ] && SRC_DIRS="$SRC_DIRS $d"
done
[ -z "$SRC_DIRS" ] && SRC_DIRS="."

OUT="${ROOT}/sast_scan_results.txt"
: > "$OUT"

echo "=== AI Security Reviewer SAST Scan (OpenGrep taxonomy) ===" | tee -a "$OUT"
echo "Root: $ROOT | Source:$SRC_DIRS" | tee -a "$OUT"
echo "Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$OUT"
echo "" | tee -a "$OUT"

run_check() {
  local id="$1"
  local desc="$2"
  local pattern="$3"
  echo "--- [$id] $desc ---" | tee -a "$OUT"
  if command -v rg >/dev/null 2>&1; then
    rg -n --no-heading -S "$pattern" $SRC_DIRS \
      --glob '!node_modules' --glob '!test' --glob '!tests' --glob '!.foundry' \
      2>/dev/null | head -50 | tee -a "$OUT" || true
    local count
    count=$(rg -c --no-heading -S "$pattern" $SRC_DIRS \
      --glob '!node_modules' --glob '!test' --glob '!tests' --glob '!.foundry' \
      2>/dev/null | awk -F: '{s+=$2} END {print s+0}' || true)
    count=${count:-0}
    echo "MATCH_COUNT: $count" | tee -a "$OUT"
  else
    echo "SKIP: ripgrep (rg) not installed" | tee -a "$OUT"
  fi
  echo "" | tee -a "$OUT"
}

# OpenGrep vulnerability_class aligned checks (see opengrep-vulnerability-index.md)
run_check "SAST-OG-01" "Active Debug Code" 'debug\s*:\s*true|DEBUG\s*=\s*true'
run_check "SAST-OG-02" "Code Injection" 'eval\(|new Function\(|vm\.runInNewContext|setTimeout\s*\(\s*['\''"]'
run_check "SAST-OG-03" "Command Injection" 'exec\(|execSync|spawn\(|shell\s*:\s*true|git clone'
run_check "SAST-OG-04" "Cookie Security" 'res\.cookie\(|setCookie|secure\s*:\s*false|httpOnly\s*:\s*false'
run_check "SAST-OG-05" "CSRF / method override" 'method-override|methodOverride|X-HTTP-Method-Override'
run_check "SAST-OG-06" "XSS" 'innerHTML|dangerouslySetInnerHTML|document\.write|v-html|mustache\.escape'
run_check "SAST-OG-07" "Cryptographic Issues" 'md5|sha1|pseudoRandomBytes|Math\.random\(\)|ws://|rejectUnauthorized\s*:\s*false'
run_check "SAST-OG-08" "Dangerous methods" 'child_process|puppeteer\.|page\.evaluate\('
run_check "SAST-OG-09" "DoS patterns" 'new RegExp\(req\.|findAll\(\)'
run_check "SAST-OG-10" "Hard-coded Secrets" 'AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{36}|sk_live_|jwt\.sign\([^)]*['\''"][A-Za-z0-9+/=]{16,}'
run_check "SAST-OG-11" "HTTP routes" 'router\.(get|post|put|patch|delete)\(|app\.(get|post|put|patch|delete)\('
run_check "SAST-OG-12" "Improper Authorization" 'login_not_required|isSeller|skipAuth'
run_check "SAST-OG-13" "Improper Encoding" 'res\.send\([^)]*req\.|encodeURIComponent\('
run_check "SAST-OG-14" "Improper Validation / bus" 'JSON\.parse\(message\.|consumer\.run'
run_check "SAST-OG-15" "Insecure Deserialization" 'pickle\.loads|yaml\.load\(|unserialize|node-serialize'
run_check "SAST-OG-16" "Insecure Hashing" "createHash\\(['\"]md5|createHash\\(['\"]sha1"
run_check "SAST-OG-17" "Insufficient Logging" 'catch\s*\([^)]*\)\s*\{\s*\}'
run_check "SAST-OG-18" "LDAP Injection" 'ldap\.|createClient\(.*ldap|filter\s*=\s*['\''"].*\+'
run_check "SAST-OG-19" "Mass Assignment / PP" 'Object\.assign\([^)]*req\.(body|query)|__proto__|lodash\.(set|merge|defaultsDeep)'
run_check "SAST-OG-20" "Memory Issues" 'allocUnsafe\(|new Buffer\(|noAssert\s*:\s*true'
run_check "SAST-OG-21" "Mishandled Sensitive Info" 'err\.stack|res\.json\(\s*err\s*\)|logger\.(info|error).*(password|customer_id)'
run_check "SAST-OG-22" "Open Redirect" 'redirect\([^)]*req\.(query|body|params)|res\.redirect\([^)]*\+'
run_check "SAST-OG-23" "Other Security" 'cors\(\s*\)|Access-Control-Allow-Origin.*\*|bypassSecurityTrust'
run_check "SAST-OG-24" "Path Traversal" 'path\.join\([^)]*req\.|readFile\([^)]*req\.|\.\./'
run_check "SAST-OG-25" "SQL Injection" '\.query\(`|\.query\(['\''"].*\+|sequelize\.query\(['\''"].*\+'
run_check "SAST-OG-26" "SSRF" 'axios\(|require\(['\''"]request['\''"]\)|fetch\(|url:\s*(req\.|data\.|message\.)'
run_check "SAST-OG-27" "XML Injection / XXE" 'xml2json|libxmljs|DOMParser|DOCTYPE|ENTITY'
run_check "SAST-OG-28" "XPath Injection" 'xpath\.|selectNodes\(|evaluate\([^)]*\+'

# --- v3.7: Frontend stack trace leaks ---
run_check "SAST-LEAK-01" "Error in HTTP response" 'res\.(json|send)\([^)]*err|error:\s*err\.(stack|message)'
run_check "SAST-LEAK-02" "Stack trace fields" 'err\.stack|error\.stack|stackTrace|traceback\.format_exc'
run_check "SAST-LEAK-03" "GraphQL verbose errors" 'extensions\.stacktrace|formatError.*stack|debug\s*:\s*true'
run_check "SAST-LEAK-07" "Sensitive data in errors" 'res\.(json|send)\([^)]*(password|token|secret|sql)'

# --- v3.7: Expanded secrets ---
run_check "SAST-SECRET-01" "Cloud keys" 'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|xox[baprs]-'
run_check "SAST-SECRET-04" "DB URIs with creds" 'mongodb(\+srv)?://[^:]+:[^@]+@|postgres(ql)?://[^:]+:[^@]+@|redis://[^:]+:[^@]+@'
run_check "SAST-SECRET-05" "Private keys" 'BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY'
run_check "SAST-SECRET-06" "JWT/API secrets" '(jwt|session|api|hmac)[_-]?(secret|key)\s*[:=]\s*['\''"][^'\'']{8,}|secretOrKey\s*:'
run_check "SAST-SECRET-07" "Password literals" 'password\s*[:=]\s*['\''"][^'\'']{4,}['\''"]'
run_check "SAST-SECRET-09" "Env fallback secrets" 'process\.env\.\w+\s*\|\|\s*['\''"][^'\'']{8,}['\''"]'

# --- v3.7: Deep injection ---
run_check "SAST-INJ-XSS" "XSS sinks" 'innerHTML|dangerouslySetInnerHTML|v-html|<%-|insertAdjacentHTML|location\.hash.*innerHTML'
run_check "SAST-INJ-RCE" "RCE" 'eval\(|new Function\(|vm\.runInNewContext|node-serialize|unserialize\(|page\.evaluate\('
run_check "SAST-INJ-CMD" "Command injection" 'exec\(|execSync|spawn\(|shell\s*:\s*true|bash\s+-c|sh\s+-c'
run_check "SAST-INJ-XXE" "XXE" 'libxmljs|xml2json|fast-xml-parser|DOCTYPE|ENTITY|noent\s*:\s*true|processEntities\s*:\s*true'
run_check "SAST-INJ-XML" "XML injection" 'buildXml|xml\s*=\s*['\''"].*\+.*req\.|createElement\([^)]*\+'

echo "--- [DAST-HOST] burp host discovery ---" | tee -a "$OUT"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/discover_burp_hosts.sh" ]; then
  bash "$SCRIPT_DIR/discover_burp_hosts.sh" "$ROOT" 2>&1 | tail -15 | tee -a "$OUT" || true
else
  echo "SKIP: discover_burp_hosts.sh missing" | tee -a "$OUT"
fi
echo "" | tee -a "$OUT"
if [ -f package.json ] && command -v npm >/dev/null 2>&1; then
  npm audit --production 2>&1 | head -40 | tee -a "$OUT" || true
else
  echo "SKIP: no package.json or npm" | tee -a "$OUT"
fi
echo "" | tee -a "$OUT"

echo "Finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$OUT"
echo "Results: $OUT"
echo "Triage: AI-validate every MATCH_COUNT > 0 per sast_scan_manifest.md"
