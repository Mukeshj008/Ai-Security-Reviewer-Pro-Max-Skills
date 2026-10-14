# Authorization & Privilege Escalation Audit (MANDATORY for authenticated applications)

**Purpose:** systematically detect horizontal authorization failures (IDOR/BOLA), vertical privilege escalation (BFLA), cross-tenant access, and role/permission manipulation. This complements `idor-bola-audit.md` and `per-method-auth-audit.md`.

## 1. Build the principal and privilege model

Read authentication middleware, guards, policy code, role definitions, route registration, and persistence models. Record:

| Principal | Tenant scope | Roles/permissions | Identity source | Privileged actions |
|-----------|--------------|-------------------|-----------------|--------------------|

Trusted identity must come from a verified session/token/service credential. Headers, body fields, query parameters, unsigned JWT claims, and client-side UI state are attacker-controlled unless an in-repo trusted gateway strips and reissues them.

## 2. Build a route/action authorization matrix

For **every** HTTP method, GraphQL resolver, RPC method, WebSocket action, queue-triggered administrative action, and mutable business operation, record:

| Entry point | Required role/permission | Enforcement location | Object/tenant check | Sensitive action |
|-------------|--------------------------|----------------------|---------------------|------------------|

Do not infer authorization from authentication. `isAuthenticated()` proves identity, not permission.

## 3. Horizontal authorization (IDOR/BOLA)

Run `idor-bola-audit.md`. Enumerate references beyond names ending in `id`: UUID, slug, username, email, phone, PNR, order number, account number, invoice, token, filename/key, composite keys, and nested GraphQL/global IDs.

Require ownership or tenant scoping at the data operation, for example `{id, ownerId: principal.id}` or a policy decision over the loaded object. A hidden/unguessable identifier is not authorization.

## 4. Vertical privilege escalation / BFLA (PRIV-ADJ-01)

### Candidate patterns

- authenticated low-privilege user can call `/admin`, `/internal`, support, finance, refund, configuration, role-management, export, debug, or bulk-operation endpoints;
- route has authentication but no role/permission guard;
- only UI hides the action;
- client supplies `role`, `permissions`, `isAdmin`, `isStaff`, `accountType`, `tenantId`, `ownerId`, approval state, limits, or feature flags;
- mass assignment updates privileged fields;
- JWT/session role claims are decoded but not signature-verified, or request headers override verified claims;
- deny/allow policy has fail-open error/default branch;
- route ordering or wildcard matcher places privileged route under `permitAll` / generic-user middleware;
- method-level authorization is absent while peer methods are protected;
- service account/admin token is substituted server-side for an ordinary caller;
- low privilege can trigger a worker/webhook/cron that performs an administrator action.

### Mandatory questions

| Question | Finding when |
|----------|--------------|
| Is the caller authenticated as a lower role? | Yes, and the action requires a higher role |
| Is permission checked on this exact action/method? | No, or check is bypassable/fail-open |
| Is the role/tenant/owner derived only from verified principal state? | No; attacker input can replace or augment it |
| Does the sink execute a privileged read/write/approval/configuration operation? | Yes, with concrete file:line evidence |
| Is enforcement only in UI, documentation, naming, or an uncited gateway? | Yes; these are not controls |

### Effective controls (Appendix A G3)

- action-level policy/guard executes on the exact route and checks the required permission;
- server derives role and tenant exclusively from a verified principal and ignores attacker-provided privilege fields;
- repository query/write includes tenant/owner/role scope;
- DTO/serializer allowlist excludes privileged fields and the model does not copy unknown properties;
- in-repo gateway/mesh policy proves the specific route is restricted to the required service identity.

Class-level annotations count only after verifying framework/custom-interceptor inheritance. Role checks after the privileged side effect are ineffective.

## 5. DAST verification

When two authorized test identities exist:

- **Horizontal:** Session B requests Session A's object.
- **Vertical:** lowest-privilege session calls the exact admin/privileged action with a non-destructive request.

Use Burp MCP when available. Curl requires user permission. Never perform destructive refund, deletion, role grant, payment, or production configuration changes without explicit approval; publish a non-destructive Burp request and mark `Not Verified`/`Tentative`.

| Result | Verdict |
|--------|---------|
| low-role session receives privileged data or performs approved safe action | Confirmed vertical escalation |
| 401 | authentication rejected; retest with valid low-role session |
| 403 | authorization works for that request |
| 2xx validation response before authorization | inspect middleware/handler order; not automatically confirmed |
| UI blocks action but direct API succeeds | UI-only control; finding |

## 6. Reporting and completion gate

- Horizontal object access: VULN, usually CWE-639 / CWE-862.
- Vertical/BFLA: VULN or AUTH consistently, CWE-862 / CWE-863.
- Privileged-field mass assignment: CWE-915 plus authorization impact.
- Checklist Discovery is `Checklist` or `Researcher`; include exact required role and actual enforced role.

The authorization audit is incomplete until:

1. every entry point has an authorization row;
2. every sensitive action has an expected role/permission;
3. every object operation has owner/tenant disposition;
4. every candidate ends as Finding, Tentative, or Appendix A with `IDOR-ADJ-01` or `PRIV-ADJ-01`;
5. horizontal and vertical testing limitations appear in the Residual Register.
