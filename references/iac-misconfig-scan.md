# IaC & Platform Misconfiguration Scan (IAC-*)

**Goal:** Find **security-relevant misconfigurations** in infrastructure-as-code, containers, CI/CD, and edge configs — with architect-level impact notes.

**Scope paths:** `infra/`, `docker/`, `k8s/`, `kubernetes/`, `helm/`, `terraform/`, `*.tf`, `Dockerfile*`, `docker-compose*.yml`, `bitbucket-pipelines.yml`, `.github/workflows/`, `infra/nginx/`, `nginx.conf`, `Chart.yaml`

**Agent:** Run each `rg` block below on the repo. Do **not** use `run_cve_iac_scan.sh`.

---

## IAC-DOCKER-01 — Container runs as root

```bash
rg -n "^USER\s+root|^USER\s+0" --glob "**/Dockerfile*"
rg -n "USER" --glob "**/Dockerfile*" 
# Flag: no USER directive (defaults root) or USER root
```

**Read:** last `USER` before `CMD`/`ENTRYPOINT`. Missing `USER` non-root → FINDING.

---

## IAC-DOCKER-02 — Secrets in Dockerfile ARG/ENV

```bash
rg -n "ENV\s+.*(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE)" --glob "**/Dockerfile*" -i
rg -n "ARG\s+.*(PASSWORD|SECRET|TOKEN)" --glob "**/Dockerfile*" -i
```

---

## IAC-DOCKER-03 — Unpinned / :latest base images

```bash
rg -n "^FROM\s+[^:]+:latest|^FROM\s+[^:@]+$" --glob "**/Dockerfile*"
```

---

## IAC-DOCKER-04 — Remote ADD (supply chain)

```bash
rg -n "^ADD\s+https?://" --glob "**/Dockerfile*"
```

Prefer `COPY` + checksum verification.

---

## IAC-DOCKER-05 — Dangerous capabilities / privileged

```bash
rg -n "privileged:\s*true|cap_add:|--privileged" --glob "**/docker-compose*"
rg -n "security_opt:\s*seccomp:unconfined" .
```

---

## IAC-K8S-01 — Privileged pods / containers

```bash
rg -n "privileged:\s*true" --glob "**/*.{yaml,yml}"
rg -n "allowPrivilegeEscalation:\s*true" --glob "**/*.{yaml,yml}"
```

---

## IAC-K8S-02 — hostNetwork / hostPID / hostIPC

```bash
rg -n "hostNetwork:\s*true|hostPID:\s*true|hostIPC:\s*true" --glob "**/*.{yaml,yml}"
```

---

## IAC-K8S-03 — Missing runAsNonRoot / readOnlyRootFilesystem

```bash
rg -n "runAsNonRoot:\s*false|runAsUser:\s*0" --glob "**/*.{yaml,yml}"
rg -n "readOnlyRootFilesystem:\s*false" --glob "**/*.{yaml,yml}"
# Flag Deployment/StatefulSet without securityContext
```

---

## IAC-K8S-04 — Secrets in plain env (not secretKeyRef)

```bash
rg -n "value:\s*['\"]?(AKIA|sk_live|password|Bearer)" --glob "**/*.{yaml,yml}" -i
rg -n "- name:.*(PASSWORD|SECRET|TOKEN)" --glob "**/*.{yaml,yml}" -A2
```

---

## IAC-K8S-05 — Overly broad RBAC

```bash
rg -n "apiGroups:\s*\[?['\"]?\*['\"]?\]?|verbs:\s*\[?['\"]?\*['\"]?\]?" --glob "**/*.{yaml,yml}"
rg -n "cluster-admin|ClusterRoleBinding" --glob "**/*.{yaml,yml}"
```

---

## IAC-TF-01 — Open ingress (0.0.0.0/0)

```bash
rg -n "0\.0\.0\.0/0|::/0" --glob "**/*.tf"
rg -n "cidr_blocks\s*=\s*\[.*0\.0\.0\.0/0" --glob "**/*.tf"
```

---

## IAC-TF-02 — Public storage / ACL

```bash
rg -n "acl\s*=\s*['\"]public|public-read|block_public_acls\s*=\s*false" --glob "**/*.tf" -i
rg -n "storage_account.*allow_nested_public" --glob "**/*.tf"
```

---

## IAC-TF-03 — IAM wildcard permissions

```bash
rg -n 'Action\s*=\s*\["?\*"?\]|Resource\s*=\s*\["?\*"?\]' --glob "**/*.tf"
rg -n "Effect\s*=\s*['\"]Allow['\"]" --glob "**/*.tf" -A5 -B2
```

---

## IAC-TF-04 — Unencrypted storage / transit

```bash
rg -n "encrypt.*=\s*false|server_side_encryption.*false|tls_version\s*=\s*['\"]TLSv1['\"]" --glob "**/*.tf" -i
rg -n "storage_encrypted\s*=\s*false" --glob "**/*.tf"
```

---

## IAC-TF-05 — Hardcoded credentials in Terraform

```bash
rg -n "password\s*=\s*['\"][^'\"]+['\"]|access_key\s*=\s*['\"]" --glob "**/*.tf" -i
```

---

## IAC-NGINX-01 — Weak TLS protocols

```bash
rg -n "ssl_protocols.*TLSv1[^.]|ssl_protocols.*SSLv" infra/nginx nginx *.conf 2>/dev/null
rg -n "ssl_protocols" --glob "**/*.{conf,nginx}"
```

---

## IAC-NGINX-02 — Missing security headers at edge

```bash
rg -n "add_header\s+(Strict-Transport-Security|X-Frame-Options|X-Content-Type-Options|Content-Security-Policy)" infra/nginx nginx 2>/dev/null
# Flag: server block without HSTS / X-Frame-Options
rg -n "server\s*\{" --glob "**/*.{conf,nginx}" 
```

---

## IAC-NGINX-03 — Permissive CORS / proxy headers

```bash
rg -n "Access-Control-Allow-Origin\s+\*|add_header.*Access-Control-Allow-Origin\s+\*" infra/nginx nginx 2>/dev/null
rg -n "proxy_set_header\s+X-Forwarded" --glob "**/*.{conf,nginx}"
```

---

## IAC-CI-01 — Secrets in CI/CD pipelines

```bash
rg -n "(password|secret|token|api_key)\s*:\s*['\"][^'\"]{8,}" bitbucket-pipelines.yml .github/workflows .gitlab-ci.yml 2>/dev/null -i
rg -n "export\s+(AWS_|API_|SECRET_)" bitbucket-pipelines.yml .github/workflows 2>/dev/null
```

---

## IAC-CI-02 — curl | bash supply chain

```bash
rg -n "curl\s+[^|]+\|\s*(ba)?sh|wget\s+[^|]+\|\s*(ba)?sh" bitbucket-pipelines.yml .github/workflows scripts 2>/dev/null
```

---

## IAC-CI-03 — Privileged Docker in CI

```bash
rg -n "docker run.*--privileged|services:.*docker.*privileged" bitbucket-pipelines.yml .github/workflows 2>/dev/null
```

---

## AI validation (IaC)

1. **Environment:** staging vs production config — flag prod paths first.
2. **Compensating controls:** cloud WAF, private cluster, network policies.
3. **Blast radius:** internet-facing vs internal-only Service.
4. **Compliance:** PCI/SOC2 relevant controls (encryption, least privilege).

**Finding ID:** **IAC-NNN** — separate from VULN/CVE.

---

## Appendix E rows

| ID | Category |
|----|----------|
| IAC-DOCKER-01 … 05 | Container image & compose |
| IAC-K8S-01 … 05 | Kubernetes manifests |
| IAC-TF-01 … 05 | Terraform / OpenTofu |
| IAC-NGINX-01 … 03 | Nginx / ingress |
| IAC-CI-01 … 03 | CI/CD pipelines |
