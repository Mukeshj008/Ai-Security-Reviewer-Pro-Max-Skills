# Graphify Queries for Security Review

Use these before Read/Grep/Glob. Cap output with `--budget N` (default 2000).

## Bootstrap

**Native AI policy:** Security semantic work = **Cursor agent (you)**. Graph semantic on docs/images = **`/graphify .`** (IDE model). **Never Ollama** in this skill.

```bash
# Preferred — native Cursor AI for semantic extraction:
# /graphify .

# AST-only headless build (code dirs only; no LLM, no Ollama):
unset OLLAMA_BASE_URL
graphify extract src lib api --no-cluster    # substitute your source roots

# NOT recommended for security scans (pulls Assets/images/docs → may invoke Ollama):
# graphify extract . --no-cluster

graphify update .                            # after code changes, AST-only, no LLM
```

`--no-cluster` skips community clustering; it does **not** disable semantic LLM on docs/images. Scope `extract` to **code directories** for pure AST, or use `/graphify .` for full corpus with native AI.

## Attack surface & entry points

```bash
graphify query "HTTP routes API endpoints controllers request handlers" --budget 1500
graphify query "authentication authorization middleware filters guards" --budget 1500
graphify query "file upload multipart request body parsing" --budget 1200
graphify query "WebSocket socket.io real-time message handlers" --budget 1200
```

## Vulnerability-class discovery

```bash
graphify query "SQL database query execute raw string concatenation" --budget 1500
graphify query "shell command exec system subprocess os.popen Runtime.exec" --budget 1500
graphify query "dangerouslySetInnerHTML innerHTML template render unescaped" --budget 1500
graphify query "deserialization pickle yaml.load ObjectInputStream unserialize" --budget 1500
graphify query "SSRF HttpClient fetch axios request user-controlled URL" --budget 1500
graphify query "path traversal file read write open user filename" --budget 1500
graphify query "hardcoded secret password api key token credential" --budget 1200
graphify query "JNDI lookup InitialContext log4j logger user input" --budget 1200
graphify query "crypto encrypt decrypt hash password bcrypt md5 sha1" --budget 1200
graphify query "session cookie JWT token validation" --budget 1200
graphify query "public routes without authentication middleware unauthenticated endpoints" --budget 1500
graphify query "basicAuth router.use verifySsoToken login_not_required isSeller bypass" --budget 1500
```

## Source → sink tracing (replaces manual grep chains)

```bash
# After static match names a source symbol and sink symbol:
graphify path "request.getParameter" "executeQuery"
graphify path "req.body" "eval"
graphify path "upload.filename" "os.system"
graphify path "userInput" "dangerouslySetInnerHTML"

# Explain a suspicious symbol + neighbors:
graphify explain "UserController.getUser"
graphify explain "sanitizeBasic"

# Reverse impact — what breaks if this sink is vulnerable:
graphify affected "statement.executeQuery" --depth 3
graphify affected "exec" --relation calls --depth 2
```

## Framework-specific (adjust symbols to project)

```bash
graphify query "Spring RestController RequestMapping RequestParam" --budget 1500
graphify query "Flask route request.args render_template" --budget 1500
graphify query "Express app.get req.query res.send" --budget 1500
graphify query "Cordova plugin http advanced-http WebView" --budget 1500
graphify query "Django views HttpResponse ORM raw SQL" --budget 1500
```

## Token budget guide

| Phase | `--budget` | Purpose |
|-------|------------|---------|
| Recon (1–3 queries) | 1200–1500 each | Map attack surface |
| Per finding trace | path + explain (~2500 total) | Source→sink |
| Validation | Read 10–30 lines only | Confirm exploitability |
| Report | no graphify | Write findings |

## When Read/Grep is still OK

- `graphify-out/graph.json` does not exist and user declined building it
- Confirming exact line content after graphify identified file:line
- Scanning for regex secrets (`grep` on small result set from graphify query)
- Test files / configs not in graph

## CVE reachability (v3.9)

```bash
graphify query "require import package dependency node_modules vulnerable" --budget 1500
graphify path "router.post" "require('VULN_PACKAGE')"
graphify path "req.body" "unserialize"
graphify path "req.query" "eval"
graphify affected "require('lodash')" --depth 2
```

## Security architect recon (v3.9)

```bash
graphify query "webhook callback third party integration outbound HTTP" --budget 1500
graphify query "admin internal cron worker queue consumer kafka" --budget 1500
graphify query "session cookie redis vault secret encrypt decrypt" --budget 1500
```

## After fixing code

```bash
graphify update .
```
