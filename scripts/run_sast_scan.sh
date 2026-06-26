#!/usr/bin/env bash
# DEPRECATED for agent workflow — CI/human optional only. Agents: run rg per references/sast_scan_manifest.md
# run_sast_scan.sh — batch rg runner (OpenGrep taxonomy)
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

# --- v3.7+: Frontend stack trace leaks (SAST-LEAK-01..08) ---
run_check "SAST-LEAK-01" "Error in HTTP response" 'res\.(json|send)\([^)]*err|error:\s*err\.(stack|message)'
run_check "SAST-LEAK-02" "Stack trace fields" 'err\.stack|error\.stack|stackTrace|traceback\.format_exc'
run_check "SAST-LEAK-03" "GraphQL verbose errors" 'extensions\.stacktrace|formatError.*stack|debug\s*:\s*true'
run_check "SAST-LEAK-04" "Template/SSR error pages" 'res\.render\([^)]*error[^)]*err|showStack|detail:\s*err'
run_check "SAST-LEAK-05" "SPA client error leaks" 'dangerouslySetInnerHTML.*error|error\.stack|bypassSecurityTrust.*error'
run_check "SAST-LEAK-06" "Browser global error handlers" 'window\.onerror|unhandledrejection|postMessage\([^)]*stack'
run_check "SAST-LEAK-07" "Sensitive data in errors" 'res\.(json|send)\([^)]*(password|token|secret|sql)'
run_check "SAST-LEAK-08" "Debug flags to frontend" 'res\.locals\.debug|__DEBUG__|includeStack|detailedMessage'

# --- v3.7+: Full secrets catalog (SAST-SECRET-01..11) ---
run_check "SAST-SECRET-01" "Cloud keys" 'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|xox[baprs]-|dop_v1_|glpat-'
run_check "SAST-SECRET-02" "Git/CI tokens" 'gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_|npm_[A-Za-z0-9]{36}'
run_check "SAST-SECRET-03" "Payment/messaging SaaS" 'sk_live_|sk_test_|SG\.[a-zA-Z0-9_-]{22}\.|AC[a-f0-9]{32}'
run_check "SAST-SECRET-04" "DB URIs with creds" 'mongodb(\+srv)?://[^:]+:[^@]+@|postgres(ql)?://[^:]+:[^@]+@|redis://[^:]+:[^@]+@'
run_check "SAST-SECRET-05" "Private keys" 'BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY'
run_check "SAST-SECRET-06" "JWT/API secrets" '(jwt|session|api|hmac)[_-]?(secret|key)\s*[:=]\s*['\''"][^'\'']{8,}|secretOrKey\s*:'
run_check "SAST-SECRET-07" "Password literals" 'password\s*[:=]\s*['\''"][^'\'']{4,}['\''"]'
run_check "SAST-SECRET-08" "OAuth/OIDC secrets" 'client_secret\s*[:=]\s*['\''"][^'\'']+['\''"]|refresh_token\s*[:=]\s*['\''"]'
run_check "SAST-SECRET-09" "Env fallback secrets" 'process\.env\.\w+\s*\|\|\s*['\''"][^'\'']{8,}['\''"]'
run_check "SAST-SECRET-10" "Base64/hex secrets heuristic" '(secret|key|token|password)\s*[:=]\s*['\''"][A-Za-z0-9+/]{32,}'
run_check "SAST-SECRET-11" "Kafka/RMQ inline creds" 'sasl\.(username|password)\s*[:=]|connectionString\s*[:=]\s*['\''"]'

# --- v3.7+: Deep injection (SAST-INJ-*) ---
run_check "SAST-INJ-XSS" "XSS sinks" 'innerHTML|dangerouslySetInnerHTML|v-html|<%-|insertAdjacentHTML|location\.hash.*innerHTML'
run_check "SAST-INJ-RCE" "RCE" 'eval\(|new Function\(|vm\.runInNewContext|node-serialize|unserialize\(|page\.evaluate\('
run_check "SAST-INJ-CMD" "Command injection" 'exec\(|execSync|spawn\(|shell\s*:\s*true|bash\s+-c|sh\s+-c'
run_check "SAST-INJ-XXE" "XXE" 'libxmljs|xml2json|fast-xml-parser|DOCTYPE|ENTITY|noent\s*:\s*true|processEntities\s*:\s*true'
run_check "SAST-INJ-XML" "XML injection" 'buildXml|xml\s*=\s*['\''"].*\+.*req\.|createElement\([^)]*\+'

# --- v3.8: Extended classes (SAST-EXT-*) ---
run_check "SAST-EXT-01" "Trust boundary violation" 'session\.(set|put)\([^)]*req\.(query|body|params|headers)'
run_check "SAST-EXT-02" "Request smuggling signals" 'Transfer-Encoding|Content-Length.*chunked|proxy_pass'
run_check "SAST-EXT-03" "JNDI / Log4Shell" 'InitialContext\.lookup|jndi:|ldap://.*lookup|\$\{jndi:'
run_check "SAST-EXT-04" "Session fixation" 'session\.(save|regenerate)|changeSessionId|session\.setAttribute\([^)]*user'
run_check "SAST-EXT-05" "ReDoS" 'RegExp\([^)]*\+|new RegExp\(req\.|\.match\(/.*\(\.\+\)\+'
run_check "SAST-EXT-06" "XML bomb" 'DOCTYPE.*ENTITY|billion.*laughs|expandEntityReferences'
run_check "SAST-EXT-07" "Zip bomb" 'unzip|extractAll|adm-zip|yauzl|decompress.*without.*limit'

run_check "SAST-BUS-01" "Message bus boundary" 'JSON\.parse\(message\.|eachMessage|consumer\.run'

echo "--- [DEPS-01] npm audit ---" | tee -a "$OUT"
if [ -f package.json ] && command -v npm >/dev/null 2>&1; then
  npm audit --production 2>&1 | head -40 | tee -a "$OUT" || true
else
  echo "SKIP: no package.json or npm" | tee -a "$OUT"
fi
echo "" | tee -a "$OUT"

echo "--- [DAST-HOST-01] burp host discovery ---" | tee -a "$OUT"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/discover_burp_hosts.sh" ]; then
  bash "$SCRIPT_DIR/discover_burp_hosts.sh" "$ROOT" 2>&1 | tail -15 | tee -a "$OUT" || true
else
  echo "SKIP: discover_burp_hosts.sh missing" | tee -a "$OUT"
fi
echo "" | tee -a "$OUT"

echo "Finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$OUT"
echo "Results: $OUT"
echo "Triage: AI-validate every MATCH_COUNT > 0 per sast_scan_manifest.md"
echo "NOTE: Agents must NOT use this script — run manifest rg commands directly (agent-execution.md)"
