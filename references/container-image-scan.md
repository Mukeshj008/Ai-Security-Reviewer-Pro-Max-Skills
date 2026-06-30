# Container Image CVE Scan (additive)

**When:** `Dockerfile*`, `docker-compose*.yml`, K8s manifests, or image refs in CI.

**Extends** `iac-misconfig-scan.md` IAC-DOCKER-* — adds **image layer** CVE scan, not just Dockerfile USER/root.

---

## Detection

```bash
find . -name 'Dockerfile*' -o -name 'docker-compose*.yml' 2>/dev/null | head -10
rg -n "image:\s|FROM " Dockerfile* docker-compose*.yml k8s/ 2>/dev/null
```

---

## Scan tools (agent-run, install if missing)

```bash
# Trivy (preferred)
which trivy || brew install trivy 2>/dev/null

# Scan Dockerfile build context + base image
trivy config . 2>/dev/null | head -80
trivy image --severity HIGH,CRITICAL [registry/image:tag] 2>/dev/null | head -80

# Grype fallback
grype dir:. 2>/dev/null | head -50
```

If no image built locally: scan **FROM** line base image tag from Dockerfile.

---

## Reachability filter

Image CVE in base OS packages **unreachable from app** → filtered table (same philosophy as OSV SCA). App-layer packages in image → cross-check with Maven/npm SCA.

---

## Report

```markdown
### Container Image Scan (summary)

| Image / context | Tool | Critical/High | Finding refs |
|-----------------|------|---------------|--------------|
| FROM eclipse-temurin:21 | trivy image | 2 (filtered — base OS) | — |
| Dockerfile USER root | static | — | IAC-001 |
```

FINDING for **fixable app-reachable** image CVEs → **CVE-NNN** or note under SCA.

Log trivy command in Appendix F.
