# Pack: IaC, containers, CI/CD, web-server config

**Detect:** `Dockerfile*`, `docker-compose*.y*ml`, `*.tf`, `*.tfvars`, `k8s/`/`helm/`/`charts/`/`manifests/` YAML with `apiVersion:`, `kustomization.yaml`, `serverless.yml`, CloudFormation (`AWSTemplateFormatVersion`), `.github/workflows/*.yml`, `.gitlab-ci.yml`, `bitbucket-pipelines.yml`, `Jenkinsfile`, `.circleci/config.yml`, `azure-pipelines.yml`, `nginx*.conf`, `httpd.conf`, `.htaccess`, `ecosystem.config.js` / PM2.

**Also read:** `../extended-category-scans.md` (container & cloud sections). Kubernetes YAML is **not** Python/JS — G0 applies: only this pack's rules count for these files.

## Dockerfile

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| No `USER` (runs as root), `USER root` last | `USER 10001` / named non-root user | Multi-stage: only the **final** stage matters |
| `FROM image:latest` / no digest | pinned tag + `@sha256:` | |
| `ARG`/`ENV` with secrets (`ENV DB_PASSWORD=…`, `ARG NPM_TOKEN` then used in a layer) | BuildKit `--mount=type=secret` | `ARG` used only in a builder stage that is discarded still leaks via `docker history` for that stage image if pushed |
| `COPY . .` with no `.dockerignore` (copies `.env`, `.git`, keys) | `.dockerignore` | |
| `ADD http://…` (unverified remote), `curl … | sh` | `COPY` + checksum verify | |
| `chmod 777`, `--privileged` hints, SSH server in image | | |
| `EXPOSE` debug ports (9229 Node inspector, 5005 JDWP, 5678 debugpy) | | |
| `NODE_ENV=development`, `--inspect=0.0.0.0` in CMD | | |

## docker-compose

`privileged: true`, `network_mode: host`, `pid: host`, `cap_add: [SYS_ADMIN|ALL]`, `/var/run/docker.sock` mounted (container escape), secrets in `environment:` literals, DB ports published to `0.0.0.0` (`"5432:5432"`), `security_opt: [seccomp:unconfined, apparmor:unconfined]`.

## Kubernetes / Helm

| Vulnerable | Safe |
|-----------|------|
| `securityContext` missing or `privileged: true`, `allowPrivilegeEscalation: true`, `runAsUser: 0`, `runAsNonRoot` unset, `readOnlyRootFilesystem: false`, capabilities not dropped | `runAsNonRoot: true`, `drop: [ALL]`, `seccompProfile: RuntimeDefault` |
| `hostNetwork/hostPID/hostIPC: true`, `hostPath` volumes (esp. `/`, `/var/run/docker.sock`, `/etc`) | |
| Secrets as plain `env.value` or `kind: Secret` with `stringData` committed (base64 ≠ encryption) | External Secrets / sealed-secrets / CSI |
| `ClusterRoleBinding` to `cluster-admin`, Roles with `verbs: ["*"]` / `resources: ["*"]`, `secrets` get/list | least privilege |
| `automountServiceAccountToken` default true on pods that don't need the API | `false` |
| No `resources.limits` (noisy neighbor / DoS) | limits + requests |
| `Service` `type: LoadBalancer`/`NodePort` for internal components; Ingress without TLS; no `NetworkPolicy` | |
| `imagePullPolicy` with `:latest` | digests |

## Terraform / CloudFormation / serverless

- S3: `acl = "public-read"`, missing `aws_s3_bucket_public_access_block`, no encryption, no versioning on state buckets.
- Security groups: `0.0.0.0/0` (or `::/0`) on 22, 3389, DB ports (3306, 5432, 6379, 9200, 27017).
- IAM: `"Action": "*"` / `"Resource": "*"`, `iam:PassRole` on `*`, `sts:AssumeRole` trust policy with `"Principal": {"AWS": "*"}`.
- RDS `publicly_accessible = true`, `storage_encrypted = false`; ElastiCache without auth/TLS; EKS public endpoint without CIDR restriction.
- Secrets in `.tf` / `.tfvars` / `default =` values; `terraform.tfstate` committed (contains plaintext secrets).
- Lambda env vars with secrets; API Gateway routes with `authorization_type = "NONE"`.
- Logging disabled: CloudTrail, VPC flow logs, ALB access logs.

## CI/CD pipelines

| Risk | Vulnerable pattern | Safe |
|------|-------------------|------|
| Script injection | GitHub Actions `run: echo "${{ github.event.issue.title }}"` / `pull_request.head.ref` / `head_commit.message` interpolated into shell | pass via `env:` and quote `"$VAR"` |
| Untrusted code with secrets | `on: pull_request_target` + `actions/checkout` of `github.event.pull_request.head.sha` then build/test | `pull_request` trigger for untrusted code; separate privileged workflow |
| Unpinned actions | `uses: some/action@main` / `@v1` (third-party) | full commit SHA |
| Over-broad token | no `permissions:` block (defaults may be write-all), `permissions: write-all` | `permissions: contents: read` |
| Secret exposure | `echo $SECRET`, `set -x` with secrets, secrets passed to forked-PR jobs, artifacts containing `.env` | masking, OIDC to cloud instead of long-lived keys |
| Self-hosted runners on public repos | `runs-on: self-hosted` with fork PRs | ephemeral runners |
| Jenkins | `sh "… ${params.X}"` (Groovy interpolation into shell), `script { evaluate(...) }`, credentials echoed | `sh '… $X'` with `withEnv` |
| GitLab | `rules:` letting MR pipelines from forks access protected variables; `CI_JOB_TOKEN` scope wide | protected variables / branches |
| Supply chain | `curl … | bash` installers, `npm install` (not `npm ci`) without lockfile, `pip install` without hashes, caches shared across trust levels | lockfiles + `npm ci`, `--require-hashes` |
| Deployment | deploy jobs runnable from any branch; no environment protection / approvals | protected environments |

## Web server config (nginx / Apache)

- `alias /files/` with `location /files` (no trailing slash) → path traversal `/files../`.
- `merge_slashes off` + upstream path rules; `proxy_pass` with user-controlled `$host`/`$http_*` variables → SSRF; `resolver` + variable `proxy_pass`.
- `autoindex on`; `server_tokens on`; missing `add_header` for HSTS/CSP/X-Frame-Options/X-Content-Type-Options (`add_header` in a child `location` **drops** all parent headers).
- `ssl_protocols TLSv1 TLSv1.1`, weak `ssl_ciphers`.
- `client_max_body_size 0`; no `limit_req` on auth/OTP endpoints.
- Apache `.htaccess` `AllowOverride All` + upload dirs executing PHP; `Options +Indexes`.

## PM2 / process managers

`ecosystem.config.js` with literal secrets in `env:` / `env_production:`; `--inspect` in `node_args`; `watch: true` in prod.

## Hint rg

```bash
rg -n "^\s*(FROM|USER|ARG|ENV|ADD|COPY|EXPOSE|RUN .*curl[^|]*\|\s*(ba)?sh)" --glob "Dockerfile*" --glob "*.dockerfile"
rg -n "privileged:\s*true|network_mode:\s*host|pid:\s*host|docker\.sock|cap_add|seccomp:unconfined|\"0\.0\.0\.0:" --glob "docker-compose*.y*ml" --glob "compose*.y*ml"
rg -n "privileged:\s*true|allowPrivilegeEscalation:\s*true|runAsUser:\s*0|hostNetwork:\s*true|hostPID:\s*true|hostPath:|cluster-admin|verbs:\s*\[\s*\"\*\"|automountServiceAccountToken|stringData:|kind:\s*Secret" --glob "*.{yaml,yml}" -g '!node_modules/**' -g '!.github/**'
rg -n "public-read|0\.0\.0\.0/0|::/0|\"Action\"\s*:\s*\"\*\"|\"Resource\"\s*:\s*\"\*\"|publicly_accessible\s*=\s*true|storage_encrypted\s*=\s*false|authorization_type\s*=\s*\"NONE\"" --glob "*.{tf,tfvars,json,yaml,yml}" -g '!node_modules/**'
rg -n "\\\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|head_commit)|head_ref)|pull_request_target|uses:\s*[^@]+@(main|master|v\d+)\s*$|permissions:\s*write-all|runs-on:\s*self-hosted" --glob ".github/workflows/*.y*ml"
rg -n "sh\s+\"[^\"]*\\\$\{|evaluate\s*\(|withCredentials|echo\s+\\\$" --glob "Jenkinsfile*" --glob "*.groovy"
rg -n "curl[^|]*\|\s*(ba)?sh|npm install\b|pip install\b|set -x" --glob "{.gitlab-ci.yml,bitbucket-pipelines.yml,azure-pipelines.yml,.circleci/config.yml,.github/workflows/*.y*ml,Jenkinsfile}"
rg -n "alias\s+|proxy_pass\s+.*\\\$|autoindex\s+on|server_tokens\s+on|ssl_protocols|client_max_body_size\s+0|add_header" --glob "*.conf" --glob "nginx*"
rg -n "env(_production|_staging)?\s*:|--inspect|watch\s*:\s*true" --glob "ecosystem*.config.js" --glob "pm2*.json"
rg -n "shell:|command:|no_log|become:|validate_certs:\s*(no|false)|mode:\s*['\"]?0?777" --glob "**/{roles,playbooks,tasks,handlers}/**/*.y*ml"
```

## Class coverage index

Infrastructure files have no application sinks; rows map each class to its infrastructure form.

| ID | Infrastructure / CI form | Safe equivalent | FP trap / note |
|----|-------------------------|-----------------|----------------|
| L01 | nginx `add_header` missing CSP; `sub_filter` injecting user-controlled content; static error pages echoing `$request_uri` | CSP header at edge | XSS lives in app packs |
| L02 | Ansible/Jinja templates rendering **untrusted** variables into config (`{{ user_var }}` in nginx conf → config injection); Helm `tpl` on user values | quote/validate vars, avoid `tpl` on untrusted values | operator-controlled vars are trusted |
| L03 | CI `run:` with `${{ github.event.* }}` (script injection), Jenkins `evaluate()`, Groovy interpolation | env indirection, quoted vars | |
| L04 | N/A in IaC; DB init scripts with templated SQL from pipeline params | parameterized migrations | |
| L05 | N/A — check DB exposure instead (L25) | — | |
| L06 | Ansible `shell:` with `{{ var }}` from untrusted inventory/facts, Dockerfile `RUN` with build args from PRs, Makefile recipes with env input | `command:` module with args list, `quote` filter | |
| L07 | N/A — infra files build no LDAP/XPath queries; check LDAP servers exposed without TLS (389 open in SGs) under L24/L25 | LDAPS, private network | |
| L08 | nginx `proxy_set_header` passing client-controlled `X-Forwarded-*`/`Host` unchanged (spoofing), log format without escaping (`escape=json`) | overwrite forwarded headers at edge, `log_format … escape=json` | |
| L09 | nginx `proxy_pass` with variables from `$host`/`$arg_*`/`$http_*` (SSRF via proxy), cloud metadata reachable from pods (no IMDSv2 / NetworkPolicy) | fixed upstreams, IMDSv2 `http_tokens = "required"`, egress NetworkPolicy | |
| L10 | nginx `alias` without trailing slash (`/files../`), `root` inside `location` with user paths, K8s `hostPath` mounts | trailing slashes, avoid hostPath | |
| L11 | `client_max_body_size 0`; upload dirs served with script execution (Apache PHP handler) | size limits, `php_admin_flag engine off` for uploads | |
| L12 | N/A in config; message brokers exposed without auth (see L25) | — | |
| L13 | N/A — no XML parsing in infra config; SAML IdP metadata URLs over `http://` are an L24 issue | HTTPS metadata | |
| L14 | Helm values overriding security contexts from untrusted sources; Terraform modules from user input | pinned modules | |
| L15 | services exposed without auth (Redis, Elasticsearch, Mongo, RabbitMQ management, Kibana, Jenkins) in compose/K8s/SG rules | auth + private networking | |
| L16 | long-lived cloud keys in CI secrets instead of OIDC; K8s ServiceAccount token automount | OIDC federation, `automountServiceAccountToken: false` | |
| L17 | RBAC wildcards, `cluster-admin` bindings, IAM `*:*`, S3 bucket policies `Principal: *` | least privilege | |
| L18 | N/A — CSRF is an app concern; at the edge only cookie `SameSite` rewriting (`proxy_cookie_flags`) applies | `proxy_cookie_flags ~ secure samesite=lax` | |
| L19 | nginx `add_header Access-Control-Allow-Origin $http_origin` + credentials | map of allowed origins | |
| L20 | missing HSTS/CSP/XFO/nosniff at nginx/ingress; child `location` `add_header` drops parent headers | headers in every `location` or `always` include file | |
| L21 | nginx `return 302 $arg_next` / `rewrite … $arg_url` | fixed targets | |
| L22 | unencrypted volumes/buckets/RDS/EBS, KMS keys without rotation | encryption at rest + rotation | |
| L23 | N/A for config; generated passwords in Terraform (`random_password`) end up in state (L25); Ansible `lookup('password', …)` files committed | store state remotely encrypted | |
| L24 | `ssl_protocols TLSv1 TLSv1.1`, weak ciphers, Ingress without TLS, Ansible `validate_certs: no`, `curl -k` / `wget --no-check-certificate` in Dockerfiles/CI | TLS 1.2+, verified downloads | |
| L25 | § secrets in Dockerfile `ENV/ARG`, compose `environment:`, K8s `Secret` manifests committed, `.tfvars`/`tfstate`, Ansible vars without Vault, PM2 `env:` literals; debug ports exposed | secret managers, Ansible Vault, sealed-secrets | |
| L26 | `server_tokens on`, `autoindex on`, default error pages revealing versions | `server_tokens off` | |
| L27 | access logs capturing `Authorization`/query tokens; CI logs printing secrets (`set -x`); Ansible tasks without `no_log: true` on secrets | log formats excluding sensitive fields, `no_log` | |
| L28 | no `limit_req`/`limit_conn`, no K8s resource limits, no HPA ceilings, unlimited `client_max_body_size` | rate limits, quotas | |
| L29 | CI deploy jobs running concurrently on the same environment (no `concurrency:` group), Terraform without state locking | `concurrency:` groups, DynamoDB/remote state lock | |
| L30 | deploy pipelines skippable from any branch, missing environment approvals | protected environments | |
| L31 | `privileged: true`, `SYS_ADMIN`, `seccomp:unconfined`, docker.sock mounts (container escape surface) | drop capabilities, RuntimeDefault seccomp | |
| L32 | § CI supply chain: unpinned actions/images (`@main`, `:latest`), `curl | sh`, `npm install` vs `npm ci`, `pull_request_target` + checkout of PR head, self-hosted runners on public repos | SHA pins, digests, lockfiles, isolated runners | |
| L33 | gRPC/GraphQL/WebSocket endpoints exposed via Ingress without auth or WAF; `proxy_set_header Upgrade` on all paths | path-scoped upgrades, auth at gateway | |
| L34 | N/A — no reflection; analogue is CI loading actions/plugins by name from untrusted input (`uses: ${{ inputs.action }}`), Jenkins shared libraries from unpinned branches | pinned libraries/actions | |
| L35 | YAML anchors/merge keys hiding overrides; Helm `--set` overriding security values; Terraform `count`/`for_each` silently skipping security resources; Ansible `ignore_errors: yes` on security tasks | review rendered manifests (`helm template`, `terraform plan`) | |
