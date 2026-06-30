# SBOM Export (optional additive deliverable)

**When:** User asks for supply-chain artifact or CI integration. **Optional** — does not replace SCA section.

---

## Maven (CycloneDX)

```bash
# Install plugin if project lacks it — document in Appendix F
mvn -q org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom \
  -Dcyclonedx.skipAttach=true \
  -DoutputFormat=json \
  -DoutputName=sbom 2>/dev/null

# Output: target/bom.json or similar
```

## npm (CycloneDX)

```bash
npx --yes @cyclonedx/cyclonedx-npm --output-file sbom.json 2>/dev/null
```

---

## Report mention

```markdown
## Software Composition Analysis (SCA)
...
**SBOM:** `sbom.json` generated (CycloneDX) — N packages; aligns with OSV inventory.
```

Deliver file alongside report when user requests SBOM. **Not mandatory** for standard reviews.

---

## SARIF (future / optional)

For CI gates, agents may note: *"SARIF export not generated — findings remain in security_report.md/html."* Full SARIF mapping is out of scope unless project adds converter.
