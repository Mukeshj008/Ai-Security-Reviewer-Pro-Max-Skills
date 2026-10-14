# Language packs — router (v4.40, MANDATORY)

The same vulnerability class has **different sources, sinks, and neutralizing controls in every language and framework**. A Jinja2 `|safe` pattern means nothing in a JSP; `<%= %>` is *escaped* in Rails ERB, *unescaped* in JSP and classic ASP.NET, and *escaped* in EJS while `<%- %>` is not. Searching one language's pattern in another language's file wastes tokens and produces both false positives and false negatives.

**Rule:** detect the stack first, load only the packs that match, and judge every sink by the rules of the language and framework it is written in.

---

## Step 1 — Detect stacks (before any pattern search)

Run `scripts/enumerate_inventory.py` (writes `languages`, `frameworks`, `lang_packs` into `.security-review/inventory.json`). If you cannot run it, detect by hand with this table. A pack is **active** when any trigger matches outside `node_modules/`, `vendor/`, `dist/`, `build/`, `target/`, `.venv/`.

| Pack file | Triggers (any) |
|-----------|----------------|
| `javascript-node.md` | `package.json` with `express` / `koa` / `fastify` / `@nestjs/*` / `hapi` / `next`, or server-side `*.js`/`*.ts` using `require('http')`, `app.listen`, `router.` |
| `frontend-browser.md` | `react`, `vue`, `@angular/core`, `svelte`, `jquery` in `package.json`; `*.jsx`/`*.tsx`/`*.vue`/`*.svelte`; `*.html` with `<script>` |
| `python.md` | `*.py` plus any of `requirements*.txt`, `pyproject.toml`, `Pipfile`, `setup.py`; frameworks `django`, `flask`, `fastapi`, `tornado`, `aiohttp` |
| `java-kotlin.md` | `pom.xml`, `build.gradle*`, `*.java`, `*.kt`, `*.jsp`, `web.xml` |
| `go.md` | `go.mod`, `*.go` |
| `php.md` | `composer.json`, `*.php`, `*.blade.php`, `*.twig` |
| `dotnet.md` | `*.csproj`, `*.sln`, `*.cs`, `*.cshtml`, `*.aspx`, `web.config` |
| `ruby.md` | `Gemfile`, `*.rb`, `*.erb`, `*.haml`, `*.slim` |
| `rust.md` | `Cargo.toml`, `*.rs` |
| `c-cpp.md` | `*.c`, `*.cc`, `*.cpp`, `*.h`, `CMakeLists.txt`, `Makefile` with native targets |
| `scala.md` | `build.sbt`, `*.scala`, `*.sc` (Play, Akka HTTP, http4s, Spark) |
| `elixir.md` | `mix.exs`, `*.ex`, `*.exs`, `*.heex`, `*.eex` (Phoenix, Plug, Ecto) |
| `shell.md` | `*.sh`, `*.bash`, `*.zsh`, `*.ps1`, `*.psm1`, shebang scripts, `Makefile` recipes |
| `mobile-native.md` | `*.swift`, `*.m`, `*.mm`, `AndroidManifest.xml` (+ module `*.kt`/`*.java`), `*.dart`, `pubspec.yaml`, `react-native` dep |
| `other-languages.md` | `*.pl`/`*.pm` (Perl), `*.lua` (Lua/OpenResty), `*.groovy` (Groovy/Grails, not Jenkinsfile), `*.sol` (Solidity) |
| `iac-ci.md` | `Dockerfile*`, `docker-compose*.yml`, K8s manifests (`kind:` + `apiVersion:`), `*.tf`, `Chart.yaml`, `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile*`, `azure-pipelines.yml`, `bitbucket-pipelines.yml`, Ansible playbooks |
| Mobile (existing) | `AndroidManifest.xml`, `*.swift`, `Info.plist`, `pubspec.yaml`, `react-native` → `../mobile-sast-audit.md` + `../deeplink-audit.md` |
| GraphQL / WS / gRPC (existing) | `*.graphql`, `graphql` deps, `*.proto`, `ws`/`socket.io` → `../protocol-scans-graphql-ws-grpc.md` |

Record the active packs in session memory under `## Language packs` (one line per pack: `active | files: N | frameworks: …`). Inactive packs: write `inactive — no triggers` once; never load them.

Packs marked `test/fixture only` (all triggers under `test/`, `tests/`, `spec/`, `fixtures/`, `docs/`, `examples/` …) are **not production attack surface**: review them only if the user asked for test code, and never let them inflate production severity. Ansible/Jinja `.j2` files under `roles/` / `playbooks/` belong to `iac-ci.md`, not `python.md`.

---

## Step 2 — Map each file to exactly one pack

When you open a file, the pack that applies is decided by **the file's language and the framework that renders or executes it**, not by the repo's main language:

| File | Pack |
|------|------|
| `views.py` returning HTML | `python.md` |
| `templates/*.html` rendered by Django/Jinja | `python.md` (template section) |
| `*.jsp`, Thymeleaf `templates/*.html` in a Spring app | `java-kotlin.md` |
| `*.ejs` / `*.pug` / `*.hbs` under an Express app | `javascript-node.md` (template section) |
| `src/components/*.tsx` | `frontend-browser.md` |
| `*.blade.php` | `php.md` |
| `*.cshtml` | `dotnet.md` |
| `Dockerfile`, workflow YAML | `iac-ci.md` |

A plain `.html` file is ambiguous: find what serves it (static file → frontend pack DOM rules only; server template engine → that engine's pack).

---

## Step 3 — G0 language-context gate (before G1–G5)

Every candidate must pass **G0** before it can become a Finding:

| G0 check | Fail → |
|----------|--------|
| The sink is a real sink **in this language/framework** (e.g. `{{ x }}` is escaped in Jinja2 *when autoescape is on*, Django, Twig, Blade, Razor, Angular, Vue, React text) | Appendix A — `G0: escaped by <engine> default` |
| The escaping/encoding default was **verified from config**, not assumed (Jinja2 `Environment()` autoescape is **off** unless set; Flask turns it on only for `.html/.htm/.xml/.xhtml`; JSP `${}` is **not** escaped; classic ASP.NET `<%= %>` is **not** escaped) | Keep as candidate; cite the config line |
| Response content type matches the class (JSON body with `application/json` is not reflected XSS; string/HTML body or missing content type can be) | Appendix A — `G0: non-HTML content type` |
| The pattern came from **this file's pack**, not another language's pack | Discard the hit; re-check with the correct pack |
| Framework-level protection was confirmed in this repo (CSRF middleware enabled, ORM bound params, `html/template` import) | Cite file:line in G3 |

Write `G0: <pack> — <rule>` in the finding's **Assumptions** section.

---

## Step 4 — Cross-language boundaries (where bugs hide)

Language packs stop at the file boundary; attackers do not. For each boundary below, trace data across the boundary with **both** packs:

| Boundary | What to check |
|----------|---------------|
| Backend JSON → frontend render | Backend pack: is the value attacker-controlled / stored? Frontend pack: is it rendered via `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrust*`, `href={x}`? (stored/DOM XSS) |
| Server injects data into `<script>` block | `JSON.stringify` / `json.dumps` / `tojson` inside `<script>` without `</script>` escaping — Django `json_script` and Jinja `|tojson` are safe |
| Backend builds shell / SQL in another language | e.g. Python calling `psql -c` or Node calling a Python script with string args |
| Queue / DB second-order | Value stored by service A (pack A), executed later by worker B (pack B) — `../async-second-order-audit.md` |
| CI pipeline runs repo scripts | `iac-ci.md` (untrusted PR input) → script language pack (`*.sh`, `*.py`) |
| Mobile WebView ↔ backend | `../mobile-sast-audit.md` + backend pack for the URL/token minting endpoint |

---

## Step 5 — Using hint `rg` correctly

Each pack ends with scoped hint commands. Rules:

1. Always pass the pack's `--glob` — never run a pack's patterns repo-wide.
2. Run hints **after** reading the routes/handlers for that module (`../exploration-first.md`); hints find what you missed, they do not define coverage.
3. A hit is a **candidate**, not a finding — it still needs G0–G5.
4. Zero hits from a pack is **not** a PASS for that class; the register row needs the files you actually read.

---

## Canonical vulnerability classes (v4.41 — every pack covers every class)

Every pack ends with a **`## Class coverage index`** table that has exactly one row per ID below. Each row gives, *for that language*, the vulnerable sink → safe equivalent → FP trap, or a pointer to the pack section that does, or `N/A — <language reason>` (e.g. memory corruption in safe Rust/Java, prototype pollution outside JS, ReDoS with RE2 engines). `scripts/check_lang_packs.py` fails if any pack misses an ID.

| ID | Class | ID | Class |
|----|-------|----|-------|
| L01 | XSS / output encoding | L19 | CORS |
| L02 | SSTI / template injection | L20 | Security headers & cookie flags |
| L03 | Code injection / eval / dynamic load | L21 | Open redirect / URL parsing |
| L04 | SQL injection (raw, ORM, identifiers) | L22 | Cryptography (algorithms, modes, keys) |
| L05 | NoSQL injection | L23 | Insecure randomness |
| L06 | OS command / argument injection | L24 | TLS / certificate validation |
| L07 | LDAP / XPath / EL / other query injection | L25 | Secrets & insecure configuration |
| L08 | Header / CRLF / log injection | L26 | Error handling & information disclosure |
| L09 | SSRF | L27 | Logging & privacy (PII) |
| L10 | Path traversal / file inclusion | L28 | DoS (ReDoS, limits, resource exhaustion) |
| L11 | File upload / archive extraction | L29 | Race conditions / TOCTOU / concurrency |
| L12 | Insecure deserialization | L30 | Business logic & numeric/type confusion |
| L13 | XML (XXE, entity expansion, structural injection) | L31 | Memory safety / unsafe / FFI |
| L14 | Mass assignment / prototype pollution / object injection | L32 | Supply chain (manifests, install hooks, lockfiles) |
| L15 | Authentication & session | L33 | API protocols (GraphQL, WebSocket, gRPC) |
| L16 | JWT / OAuth / SAML / tokens | L34 | Unsafe reflection / dynamic class or method loading |
| L17 | Authorization (IDOR/BOLA, BFLA, route order) | L35 | Language-specific pitfalls |
| L18 | CSRF | | |

Cross-language matrix view (one table per class, one row per language): `vuln-class-matrix.md` — **human reference only; never load it during a scan** (~28k tokens; each pack's index already has the row you need).

---

## Pack contents (shared structure)

Each pack has the same sections so agents can compare like for like:

1. Detect / frameworks
2. Sources (attacker-controlled input APIs for that framework)
3. Class tables — **vulnerable sink | safe equivalent | FP trap**: XSS & templates · SQL/ORM · NoSQL · Command · Code/EL/SSTI · SSRF · Path/file/upload · Deserialization · XML · Crypto/random/TLS · Auth/session/JWT · CSRF/CORS/headers/cookies · Redirect/header injection · Logging/errors · DoS/ReDoS · language-specific classes
4. Hint `rg` (scoped globs)

Taxonomy rollup across all packs: `../taxonomy-master-checklist.md`.

When any XML parser/builder/serializer/SOAP/SAML surface exists, also run `../xml-security-audit.md`. It is mandatory even for files covered by an active pack because it adds parser-instance XXE hardening, structural XML injection, XPath/XSLT construction, and signature-wrapping checks.
