# Pack: Frontend / browser (React, Vue, Angular, Svelte, jQuery, vanilla DOM)

**Detect:** `react`, `react-dom`, `next`, `vue`, `nuxt`, `@angular/core`, `svelte`, `jquery` in `package.json`; `*.jsx`, `*.tsx`, `*.vue`, `*.svelte`; static `*.html` with `<script>`.

This pack covers code that runs **in the browser**. Server-rendered templates belong to the server pack (`javascript-node.md`, `python.md`, …).

## Sources (DOM)

`location.href/search/hash/pathname`, `URLSearchParams`, `document.URL`, `document.referrer`, `window.name`, `postMessage` `event.data`, `localStorage`/`sessionStorage` (if written from another source), cookies via `document.cookie`, router params (`useParams`, `useSearchParams`, `this.$route.query`, `ActivatedRoute`), API responses that echo user-stored content (stored XSS via API).

## XSS sinks by framework

| Framework | Vulnerable | Safe equivalent | FP trap |
|-----------|-----------|-----------------|---------|
| React | `dangerouslySetInnerHTML={{ __html: x }}`; `href={x}` / `src={x}` with user URL (`javascript:` — React ≥ 16.9 only **warns**); `ref.current.innerHTML = x`; `createElement` from user tag names | JSX text `{x}` (escaped); `DOMPurify.sanitize(x)` before `dangerouslySetInnerHTML`; URL scheme allow-list | `{x}` in JSX is **not** XSS |
| Vue | `v-html="x"`; `:href="x"` with `javascript:`; `new Vue({ template: userString })` (template compile = SSTI-like) | `{{ x }}` / `v-text` (escaped) | `{{ }}` is escaped |
| Angular | `bypassSecurityTrustHtml/Url/ResourceUrl/Script/Style(x)`; `ElementRef.nativeElement.innerHTML = x`; `Renderer2.setProperty(el,'innerHTML',x)` | `[innerHTML]="x"` (Angular sanitizes) ; `{{ x }}` | `[innerHTML]` alone is sanitized — report only with `bypassSecurityTrust*` |
| Svelte | `{@html x}` | `{x}` | |
| jQuery | `$(x)` with user string (HTML parsing), `.html(x)`, `.append(x)`, `.before/.after/.prepend/.replaceWith(x)`, `$.parseHTML(x)` with scripts | `.text(x)`, `.attr('href', safeUrl)` | `$('#fixed-id')` is fine |
| Vanilla | `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write/writeln`, `eval`, `new Function`, `setTimeout/setInterval(string)`, `location = x` / `location.href = x` / `window.open(x)` with `javascript:`, `script.src = x`, `iframe.srcdoc = x` | `textContent`, `createElement` + `setAttribute` on allow-listed attrs, Trusted Types | `innerHTML = ''` / static strings |

**mXSS:** sanitizing then mutating (sanitize → re-parse via `innerHTML` in another context, or sanitizer config allowing `<svg>/<math>` + `<style>`) — Tentative unless the flow is obvious.

## postMessage

- `window.addEventListener('message', e => …)` without `e.origin` check → any frame can drive the handler. Handler sinks: DOM XSS, navigation, token storage.
- `postMessage(data, '*')` with tokens or PII → leaks to any embedding origin.

## Client-side trust (logic)

- Role/price/discount/feature flags enforced only in UI (`if (user.isAdmin)` hides a button but API has no check) → verify the **API** in the server pack; report the server gap, not the UI code.
- Amounts, fares, quantity computed client-side and sent to the server → check server recomputes.

## Secrets & data in the bundle

- API keys, OAuth client secrets, private keys, internal URLs, `process.env.*` inlined by bundlers (`NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*` are **public by design** — report only if the value is a real secret).
- Source maps shipped to production (`devtool: 'source-map'` in prod, `*.map` in `build/`).
- Tokens in `localStorage` (XSS-readable) vs `httpOnly` cookie — note risk, severity depends on XSS presence.
- PII / tokens in URLs (`?token=`, `?sso_token=`) → referrer and log leakage.

## Open redirect (client)

`location.href = params.get('next')`, `router.push(query.redirect)` without same-origin check — `new URL(x, location.origin).origin === location.origin`.

## CSP / Trusted Types

Inline `<script>`/`eval` usage forces `unsafe-inline`/`unsafe-eval`; check the CSP meta tag or server header (server pack / `iac-ci.md` nginx config).

## Hint rg

```bash
G='--glob *.{js,jsx,ts,tsx,vue,svelte,html} -g !node_modules/** -g !dist/** -g !build/** -g !*.min.js'
rg -n "dangerouslySetInnerHTML|v-html|\{@html|bypassSecurityTrust|nativeElement\.innerHTML|srcdoc" $G
rg -n "\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write" $G
rg -n "\.(html|append|prepend|before|after|replaceWith)\s*\(|\\\$\(\s*[a-zA-Z_]" $G
rg -n "eval\s*\(|new Function\s*\(|set(Timeout|Interval)\s*\(\s*['\"\`]" $G
rg -n "location(\.href)?\s*=|window\.open\s*\(|router\.push\s*\(" $G
rg -n "addEventListener\s*\(\s*['\"]message|postMessage\s*\(" $G
rg -n "localStorage\.setItem|sessionStorage\.setItem" $G
rg -n "(api[_-]?key|secret|private[_-]?key|client[_-]?secret)\s*[:=]" -i $G
rg -n "devtool\s*:\s*['\"](source-map|eval)" --glob "*.{js,ts,cjs,mjs}" -g '!node_modules/**'
rg -n "integrity=|crossorigin|<script[^>]+src=['\"]https?://" --glob "*.{html,jsx,tsx,vue}" -g '!node_modules/**'
```

## Class coverage index

| ID | Vulnerable in browser JS (React / Vue / Angular / Svelte / jQuery / DOM) | Safe equivalent | FP trap / note |
|----|-------------------------------------------------------------------------|-----------------|----------------|
| L01 | § XSS sinks: `dangerouslySetInnerHTML`, `v-html`, `{@html}`, `bypassSecurityTrust*`, `innerHTML`, jQuery `.html()`/`$(str)`, `href={x}` `javascript:` | JSX/`{{ }}` text, `DOMPurify`, `textContent`, scheme allow-list | Angular `[innerHTML]` is sanitized |
| L02 | client-side template injection: Vue `template: userString`, AngularJS (1.x) `{{ }}` in server-rendered HTML with user input (`{{constructor.constructor('…')()}}`), `ng-bind-html` + `$sce.trustAsHtml` | compile only static templates; `ng-non-bindable` around user content | Angular 2+ templates are AOT-compiled — not injectable at runtime |
| L03 | `eval`, `new Function`, `setTimeout(string)`, `script.src = userUrl`, dynamic `import(user)` | static imports, JSON | |
| L04 | N/A in browser — SQL runs server-side; report in backend pack. Exception: `sql.js`/WebSQL with string concat on local data (low) | backend pack | |
| L05 | N/A in browser — trace the API call to the backend pack (`find(req.body)`) | backend pack | client-built Mongo-style filter objects sent to API → check server accepts operators |
| L06 | N/A — no shell in browser. Electron: `child_process` via `nodeIntegration: true` / exposed preload API | `contextIsolation: true`, `nodeIntegration: false`, narrow `contextBridge` API | |
| L07 | N/A — `document.evaluate` XPath on own DOM is not a security boundary | — | |
| L08 | N/A for HTTP headers (browser controls them). Log injection into client telemetry is low | — | |
| L09 | N/A (browser has SOP). Client-side "SSRF": user-controlled `fetch(url)` with credentials to attacker origin leaks tokens in `Authorization` header | fixed API base; never attach tokens to user-supplied URLs | |
| L10 | client-side path traversal: `fetch('/api/files/' + userPath)` → `../admin` hits other endpoints (CSPT) | `encodeURIComponent` per segment | |
| L11 | client-only validation of file type/size | server-side validation (backend pack) | client checks are UX, not security |
| L12 | `JSON.parse` is safe; risk is `postMessage` data / `localStorage` objects trusted for logic | validate shape (Zod) | |
| L13 | `DOMParser` with `text/html` + insertion = XSS; attacker strings concatenated into XML/SVG markup before DOM insertion | sanitize before insertion; fixed-name DOM APIs + `textContent` | XXE N/A in browsers; serialized text values do not alter XML structure |
| L14 | client prototype pollution: `$.extend(true, {}, parsedQuery)`, `deparam`, `qs` in browser, `Object.assign` from `location.hash` → gadget XSS | `Object.create(null)`, key filtering | |
| L15 | tokens in `localStorage`/`sessionStorage` (XSS-stealable); auth decisions in UI only; logout without server invalidation | `httpOnly` cookies; server-side checks | |
| L16 | JWT decoded client-side to decide privileges; OAuth implicit flow, missing `state`/PKCE; tokens in URL fragments/query | auth code + PKCE, `state` check | decoding JWT for display is fine |
| L17 | hidden admin routes/buttons only; IDs in URL — real check is backend | report backend gap | UI hiding isn't a finding by itself |
| L18 | SPA sending cookie-auth state changes without CSRF header/token | custom header + server check, `SameSite` | |
| L19 | N/A client-side — CORS is enforced by server headers (backend pack) | — | |
| L20 | inline scripts force `unsafe-inline`; missing SRI on CDN scripts; `target=_blank` without `rel=noopener` (old browsers) | CSP nonces, `integrity=`, `rel="noopener noreferrer"` | modern browsers default `noopener` |
| L21 | § Open redirect: `location = params.get('next')`, `router.push(query.redirect)` | same-origin check | |
| L22 | crypto in JS with hardcoded keys "encrypting" API payloads (security theater); `crypto-js` AES with static key/IV | TLS + server-side crypto | |
| L23 | `Math.random()` for client nonces/state/PKCE verifier | `crypto.getRandomValues`, `crypto.randomUUID` | |
| L24 | N/A — browser validates TLS. Mixed content (`http://` subresources) | HTTPS everywhere, HSTS | |
| L25 | § Secrets in bundle: real secrets in `NEXT_PUBLIC_*`/`VITE_*`/`REACT_APP_*`, source maps in prod | server-side secrets | public keys / publishable keys are fine |
| L26 | verbose errors from API rendered to users; `console.error` with tokens | generic UI errors | see `../frontend-stacktrace-leaks.md` |
| L27 | PII/tokens in URLs (referrer leakage), analytics payloads with PII | POST bodies, redaction | |
| L28 | client ReDoS on user input (self-DoS only, low); unbounded rendering | — | usually Low/Info |
| L29 | double-submit of payment buttons (server must be idempotent) | idempotency keys server-side | client debounce isn't security |
| L30 | price/discount/quantity/role computed client-side and trusted by API | server recomputes | |
| L31 | N/A — no memory unsafety in JS. WebAssembly modules from C/C++ → `c-cpp.md` | — | |
| L32 | CDN scripts without SRI, third-party tags (GTM) with DOM access, `npm` deps (see Node L32) | SRI, CSP `script-src` allow-list | |
| L33 | GraphQL queries built by string concat client-side; WebSocket messages rendered via `innerHTML` | variables in GraphQL; text rendering | |
| L34 | `window[userKey]()`, dynamic component names from query (`<component :is="user">`) | allow-list map | |
| L35 | `postMessage` without `origin` check; `window.opener` access; Electron `nodeIntegration`; service-worker scope hijack | origin check, `contextIsolation` | |
