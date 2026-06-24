# Frontend & API Stack Trace / Sensitive Error Disclosure (SAST-LEAK)

**Goal:** Find every path where errors, stacks, or internal details reach the **browser/client** or **HTTP response body**.

Run all `rg` sections on `[SRC]` (typically `src/`). AI-validate: does this response reach an end user?

---

## SAST-LEAK-01 — Node/Express error object in response

```bash
rg -n "res\.(json|send|status\([^)]*\)\.(json|send))\([^)]*err" [SRC]
rg -n "res\.(json|send)\(\s*\{[^}]*(stack|trace|exception|errorMessage)" [SRC]
rg -n "next\(err\)|app\.use\(\s*\(err" [SRC]
rg -n "errorHandler|handleError|onError" [SRC] --glob "**/*.{js,ts}"
```

**Flag:** `res.json(err)`, `res.json({ error: err.stack })`, `res.send(err.message)`, custom handlers returning `err.stack` / `err.toString()`.

---

## SAST-LEAK-02 — Stack trace fields explicitly

```bash
rg -n "err\.stack|error\.stack|e\.stack|exception\.stack|stackTrace|stack_trace" [SRC]
rg -n "traceback\.format_exc|printStackTrace|getStackTrace" [SRC]
rg -n "JSON\.stringify\(err\)|serializeError|formatError" [SRC]
```

---

## SAST-LEAK-03 — GraphQL / API verbose errors

```bash
rg -n "extensions\.(stacktrace|exception|code)|formatError|debug\s*:\s*true" [SRC]
rg -n "ApolloServer|graphqlHTTP|createHandler" [SRC]
```

**Flag:** GraphQL `extensions.stacktrace`, Apollo `debug: true` in production paths.

---

## SAST-LEAK-04 — Template / SSR error pages

```bash
rg -n "res\.render\([^)]*error[^)]*err" [SRC]
rg -n "detail:\s*err|message:\s*err\.(message|stack)" [SRC]
rg -n "NODE_ENV.*development.*stack|showStack" [SRC]
```

---

## SAST-LEAK-05 — React / Vue / Angular client leaks

```bash
rg -n "dangerouslySetInnerHTML.*error|error\.stack|componentDidCatch" [SRC]
rg -n "errorHandler.*stack|ErrorBoundary.*children" [SRC]
rg -n "enableProdMode|production:\s*false|__DEV__" [SRC]
rg -n "bypassSecurityTrust|trustAsHtml.*error" [SRC]
```

**Flag:** Error boundary renders `error.stack` to DOM; dev mode flags in production bundles.

---

## SAST-LEAK-06 — Browser global error handlers

```bash
rg -n "window\.onerror|addEventListener\(['\"]error|unhandledrejection" [SRC]
rg -n "postMessage\([^)]*stack|innerHTML.*error" [SRC]
```

---

## SAST-LEAK-07 — Sensitive fields in error payloads

```bash
rg -n "res\.(json|send)\([^)]*(password|token|secret|apiKey|authorization|cookie|session)" [SRC]
rg -n "error.*sql|query.*failed|ECONNREFUSED|ENOTFOUND|sequelize" [SRC] -i
```

**Flag:** SQL fragments, connection strings, file paths, env var names in user-visible errors.

---

## SAST-LEAK-08 — Debug / verbose flags shipped to frontend

```bash
rg -n "res\.locals\.debug|__DEBUG__|window\.__INITIAL_STATE__" [SRC]
rg -n "sourceMap|cheap-module-source-map" [SRC] --glob "**/webpack*"
rg -n "detailedMessage|verbose.*error|includeStack" [SRC]
```

---

## AI validation checklist (mandatory per hit)

1. Does the code path run in **production** (`NODE_ENV`, config)?
2. Is output sent in **HTTP response** or rendered in **HTML/JS** consumed by browser?
3. Does payload include **stack**, **file paths**, **SQL**, **secrets**, or **internal hostnames**?
4. Is there a generic error mapper (`{ error: 'Internal error' }`) that this bypasses?

**Verdict:** TRUE POSITIVE if any internal detail reaches client without auth-only/debug gating.
