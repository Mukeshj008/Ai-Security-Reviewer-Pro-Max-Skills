# Per-instance narrative (MANDATORY — v4.43)

When a finding has **more than one row** in `### Instances`, every instance must be actionable on its own: a developer can fix instance 3 without re-reading instances 1–2.

**Single instance (one row or no Instances table):** write one full Description, Impact, Remediation, and Vulnerable Code block — no `#### Instance 1` required.

---

## Section order (unchanged)

`Description → Instances → Affected endpoints → Burp PoC → Vulnerable Code → Data Flow → Impact → Remediation → Severity Rationale`

---

## Multi-instance rules (N ≥ 2)

| Section | Required shape |
|---------|----------------|
| **Description** | One short **shared** paragraph (root cause + who abuses it). Then **`#### Instance N`** (N = 1…N): 2–4 sentences — method/path or file, what is missing, what this specific sink does, attacker outcome. |
| **Vulnerable Code Snippet** | **`#### Instance N — `path:line`** + fenced verbatim code for **that** instance’s source/sink (Read ±15 lines). Repeat for every instance. Optional **`#### Shared root cause`** once if all instances share one config line (e.g. `permitAll`). |
| **Impact Assessment** | **`#### Instance N`**: 2–3 sentences naming **this** instance’s data/action harm (not generic CIA). Worst instance drives overall severity. |
| **Remediation** | **`#### Shared fix`** when one change covers all instances (middleware, global config). **`#### Instance N`** when a route/file needs an extra step (remove route, add guard, move secret). Each instance subsection must name **file + change**. |

**Forbidden for N ≥ 2:**

- One vague Description/Impact/Remediation for many endpoints with only the Instances table as detail
- One vulnerable snippet for instance 1 only while the table lists 5 routes
- “Same as instance 1” without at least file:line and sink difference stated

---

## Templates (copy structure)

### Description (multi-instance excerpt)

```markdown
### Description

Spring Security’s `SecurityFilterChain` leaves all `/api/**` requests permitted without authentication (shared root cause at `SecurityConfig.java:29`). Any anonymous client can invoke the business handlers below.

#### Instance 1 — POST `/api/v1/imsBook`

Unauthenticated callers reach `ImsBookController.book()` at line 47. The handler creates merchant inventory records with no session or API-key check, allowing arbitrary catalog writes.

#### Instance 2 — POST `/api/v1/merchantCancel`

The same `permitAll` matcher exposes `MerchantCancelController.cancel()` at line 74, letting anyone trigger cancellation workflows for merchant IDs supplied in the JSON body.
```

### Vulnerable Code (multi-instance excerpt)

Use headings `### Vulnerable Code Snippet`, then `#### Shared root cause — file:lines` with one fenced Java block, then `#### Instance N — file:lines` with a fenced block per instance (verbatim from repo). Each instance block must include SOURCE/SINK comments on the taint lines.

### Impact (multi-instance excerpt)

```markdown
### Impact Assessment

#### Instance 1

Attackers can create fraudulent inventory rows tied to arbitrary merchant IDs, corrupting storefront data and downstream settlement.

#### Instance 2

Attackers can cancel legitimate merchant bookings without owning the merchant account, causing revenue loss and support churn.
```

### Remediation (multi-instance excerpt)

```markdown
### Remediation

#### Shared fix

In `SecurityConfig.java`, replace `anyRequest().permitAll()` with authenticated matchers; use `requestMatchers("/api/v1/imsBook", "/api/v1/merchantCancel").authenticated()` or role-based rules.

#### Instance 1

Keep `ImsBookController.book` but add `@PreAuthorize("hasRole('MERCHANT')")` and server-side merchant-id binding from the JWT subject, not the body.

#### Instance 2

Add idempotency + ownership check in `CancelService`: `merchantId` must match `SecurityContext` before `cancel()` mutates state.
```

---

## LEAK / secrets (multi-file)

Same pattern: **Instances** = one row per `file:line`. Per instance:

- **Description**: which secret type, which file, which consumer service
- **Vulnerable Code**: literal line(s) redacted
- **Impact**: what that secret unlocks (bus, DB, partner API)
- **Remediation**: rotate + move to env/Vault for **that** file; shared rotation runbook in Shared fix if one key class

---

## Agent workflow

1. After merging instances (`finding-instances.md`), count rows **N**.
2. If N ≥ 2, draft all four sections using `#### Instance k` before moving to the next finding.
3. `Read` each instance sink file; paste snippet — no paraphrase.
4. `--strict` HTML export counts `#### Instance` headings in Vulnerable Code, Impact, and Remediation vs **N** (see `generate_html_report.py`).

---

## Token efficiency

- Shared root cause → **one** Shared paragraph + **one** shared code block; do not repeat identical config in every instance snippet.
- Instance subsections stay **short** but must include **path or file:line** and **distinct harm or sink**.
