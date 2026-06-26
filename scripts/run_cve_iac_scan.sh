#!/usr/bin/env bash
# DEPRECATED for agent workflow — CI/human optional only. Agents: run rg per references/cve-exploitability.md + iac-misconfig-scan.md
# Usage: bash scripts/run_cve_iac_scan.sh [REPO_ROOT]
# Output: appends to cve_iac_scan_results.txt (or standalone if SAST not run)

set -euo pipefail

ROOT="${1:-.}"
cd "$ROOT"

OUT="${ROOT}/cve_iac_scan_results.txt"
: > "$OUT"

IAC_GLOBS=(
  --glob '**/Dockerfile*'
  --glob '**/docker-compose*'
  --glob '**/*.tf'
  --glob '**/infra/**'
  --glob '**/k8s/**'
  --glob '**/kubernetes/**'
  --glob '**/*.{yaml,yml}'
  --glob '**/nginx/**'
  --glob '**/*.conf'
  --glob 'bitbucket-pipelines.yml'
  --glob '.github/workflows/**'
)

SRC_DIRS=""
for d in . routes api lib app config infra; do
  [ -d "$d" ] && SRC_DIRS="$SRC_DIRS $d"
done
[ -z "$SRC_DIRS" ] && SRC_DIRS="."

echo "=== AI Security Reviewer CVE + IaC Scan ===" | tee -a "$OUT"
echo "Root: $ROOT" | tee -a "$OUT"
echo "Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$OUT"
echo "" | tee -a "$OUT"

run_check() {
  local id="$1"
  local desc="$2"
  local pattern="$3"
  local extra="${4:-}"
  echo "--- [$id] $desc ---" | tee -a "$OUT"
  if command -v rg >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    rg -n --no-heading -S "$pattern" $SRC_DIRS $extra \
      --glob '!node_modules' --glob '!.git' \
      2>/dev/null | head -40 | tee -a "$OUT" || true
    # shellcheck disable=SC2086
    local count
    count=$(rg -c --no-heading -S "$pattern" $SRC_DIRS $extra \
      --glob '!node_modules' --glob '!.git' \
      2>/dev/null | awk -F: '{s+=$2} END {print s+0}' || true)
    count=${count:-0}
    echo "MATCH_COUNT: $count" | tee -a "$OUT"
  else
    echo "SKIP: ripgrep (rg) not installed" | tee -a "$OUT"
  fi
  echo "" | tee -a "$OUT"
}

run_iac_check() {
  local id="$1"
  local desc="$2"
  local pattern="$3"
  echo "--- [$id] $desc ---" | tee -a "$OUT"
  if command -v rg >/dev/null 2>&1; then
    rg -n --no-heading -S "$pattern" . "${IAC_GLOBS[@]}" \
      --glob '!node_modules' \
      2>/dev/null | head -40 | tee -a "$OUT" || true
    local count
    count=$(rg -c --no-heading -S "$pattern" . "${IAC_GLOBS[@]}" \
      --glob '!node_modules' \
      2>/dev/null | awk -F: '{s+=$2} END {print s+0}' || true)
    count=${count:-0}
    echo "MATCH_COUNT: $count" | tee -a "$OUT"
  else
    echo "SKIP: ripgrep (rg) not installed" | tee -a "$OUT"
  fi
  echo "" | tee -a "$OUT"
}

echo "=== CVE DEPENDENCY AUDIT ===" | tee -a "$OUT"

echo "--- [CVE-DEPS-01] npm audit critical ---" | tee -a "$OUT"
if [ -f package.json ] && command -v npm >/dev/null 2>&1; then
  npm audit --audit-level=critical --json 2>/dev/null | head -80 | tee -a "$OUT" || \
    npm audit --audit-level=critical 2>&1 | head -30 | tee -a "$OUT" || true
else
  echo "SKIP: no package.json or npm" | tee -a "$OUT"
fi
echo "" | tee -a "$OUT"

echo "--- [CVE-DEPS-02] npm audit high ---" | tee -a "$OUT"
if [ -f package.json ] && command -v npm >/dev/null 2>&1; then
  npm audit --audit-level=high 2>&1 | head -40 | tee -a "$OUT" || true
else
  echo "SKIP: no package.json or npm" | tee -a "$OUT"
fi
echo "" | tee -a "$OUT"

run_check "CVE-DEPS-03" "Lockfile version pins" '"version":\s*"[0-9]' "" 
run_check "CVE-REACH-01" "require/import patterns (triage per advisory)" "require\(['\"]|from ['\"]" ""
run_check "CVE-CODE-01" "JNDI / Log4Shell patterns" 'jndi:|InitialContext\.lookup|\$\{jndi:|log4j' ""
run_check "CVE-CODE-02" "Insecure deserialization" 'node-serialize|serialize\.unserialize|pickle\.loads|ObjectInputStream' ""
run_check "CVE-CODE-03" "Prototype pollution chains" '__proto__|lodash\.(set|merge|defaultsDeep)' ""
run_check "CVE-CODE-04" "JWT algorithm issues" "algorithm\s*:\s*['\"]none['\"]|jwt\.verify\([^)]*algorithms" ""
run_check "CVE-CODE-05" "SSRF HTTP clients" 'url:\s*(req\.|params\.|body\.|query\.)' ""
run_check "CVE-CODE-06" "Path traversal file ops" 'path\.join\([^)]*req\.|sendFile\([^)]*req\.' ""
run_check "CVE-CODE-07" "Template SSTI" 'ejs\.render\(|pug\.render\(|handlebars\.compile\(' ""
run_check "CVE-CODE-08" "Shell via tooling" 'git clone|simple-git|imagemagick|graphicsmagick' ""

echo "=== IAC MISCONFIGURATION ===" | tee -a "$OUT"

run_iac_check "IAC-DOCKER-01" "Docker USER root/missing" '^USER\s+(root|0)|^FROM'
run_iac_check "IAC-DOCKER-02" "Secrets in ENV/ARG" 'ENV\s+.*(PASSWORD|SECRET|TOKEN|API_KEY)' 
run_iac_check "IAC-DOCKER-03" ":latest or unpinned FROM" '^FROM\s+[^:]+:latest|^FROM\s+[^:@]+$'
run_iac_check "IAC-DOCKER-04" "Remote ADD" '^ADD\s+https?://'
run_iac_check "IAC-DOCKER-05" "Privileged compose" 'privileged:\s*true|--privileged'

run_iac_check "IAC-K8S-01" "Privileged pods" 'privileged:\s*true|allowPrivilegeEscalation:\s*true'
run_iac_check "IAC-K8S-02" "hostNetwork/PID/IPC" 'hostNetwork:\s*true|hostPID:\s*true|hostIPC:\s*true'
run_iac_check "IAC-K8S-03" "runAsRoot" 'runAsNonRoot:\s*false|runAsUser:\s*0'
run_iac_check "IAC-K8S-04" "Plaintext secrets in env" 'value:\s*.*(password|AKIA|sk_live)' 
run_iac_check "IAC-K8S-05" "RBAC wildcard" "verbs:\s*\[?['\"]?\*['\"]?\]?|cluster-admin"

run_iac_check "IAC-TF-01" "Open ingress 0.0.0.0/0" '0\.0\.0\.0/0|::/0'
run_iac_check "IAC-TF-02" "Public storage ACL" 'public-read|block_public_acls\s*=\s*false'
run_iac_check "IAC-TF-03" "IAM wildcard" 'Action\s*=\s*\["?\*"?\]|Resource\s*=\s*\["?\*"?\]'
run_iac_check "IAC-TF-04" "Encryption disabled" 'encrypt.*=\s*false|storage_encrypted\s*=\s*false'
run_iac_check "IAC-TF-05" "TF hardcoded creds" "password\s*=\s*['\"][^'\"]+['\"]"

run_iac_check "IAC-NGINX-01" "Weak TLS" 'ssl_protocols.*TLSv1[^.]|ssl_protocols.*SSLv'
run_iac_check "IAC-NGINX-02" "Security headers" 'Strict-Transport-Security|X-Frame-Options|Content-Security-Policy'
run_iac_check "IAC-NGINX-03" "CORS wildcard" 'Access-Control-Allow-Origin\s+\*'

run_iac_check "IAC-CI-01" "Secrets in CI yaml" "(password|secret|token)\s*:\s*['\"][^'\"]{8,}"
run_iac_check "IAC-CI-02" "curl pipe bash" 'curl\s+[^|]+\|\s*(ba)?sh'
run_iac_check "IAC-CI-03" "Privileged docker CI" 'docker run.*--privileged|privileged:\s*true'

echo "Finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$OUT"
echo "Results: $OUT"
echo "Triage: cve-exploitability.md + iac-misconfig-scan.md + security-architect.md"
echo "AI-validate reachability before reporting CVE-NNN / IAC-NNN findings"
