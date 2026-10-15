# Static SAST (scan mode `static`)

Publication contract for the **static** lane. `references/scan-modes.md` decides when this lane runs. This is the same class of issue a normal pattern/taint scanner reports from one file or one obvious helper.

The sink list is the active language pack (`lang-packs/<pack>.md`, rows marked vulnerable). Do not copy that list into the report, and do not hunt a sink the pack already marks safe.

## Publish

- **Direct injection and dangerous APIs** — XSS, SSRF, SQL injection, command injection, path traversal, XXE, SSTI, open redirect, deserialization, LDAP, header injection, and `eval` / dynamic execution, when attacker-controlled data reaches the sink in one function or one obvious helper and no control sits in front of that sink.
- **Secrets** — a standalone hardcoded password, key, token, or credential in source. Label it with `secret-type-labels.md`.
- **Weak cryptography and TLS** — a generic weak hash or cipher used for security, or TLS verification turned off, visible in that file.
- **Handler-local missing authentication** — a sensitive route whose own handler or route table has no authentication. Do not use this lane when the gap only appears after tracing middleware, a gateway, or a second route.
- **Single-file configuration** — insecure cookie flags, wildcard CORS with credentials, missing security headers, and one-file IaC or manifest issues (privileged container, host mount, public bucket, mutable image tag, secret in an image, exported component, cleartext traffic).

## Do not publish

Anything owned by `references/scanner-blind-spots.md`: business and financial invariants, object ownership and BFLA, second-order or wrong-context injection, a High or Critical bypass of a control that looks safe to a pattern scanner, cross-service races, and multi-file IAM, Kubernetes, or CI relationships.

If a control is present and a reachable path defeats it, that finding is logical, not static. If the control holds, use Appendix A. Dependency CVEs and quantum-only cryptography stay out of scope.
