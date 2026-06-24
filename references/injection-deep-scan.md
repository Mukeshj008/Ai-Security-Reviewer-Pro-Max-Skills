# Deep Injection Scan — XSS, RCE, Command Injection, XXE, XML (SAST-INJ)

Agent-native `rg` + `graphify path` + AI validation. Run **all** sections.

---

## SAST-INJ-XSS — Cross-Site Scripting (reflected, stored, DOM)

### Server-side / SSR sinks

```bash
rg -n "innerHTML|outerHTML|insertAdjacentHTML|document\.write" [SRC]
rg -n "dangerouslySetInnerHTML|v-html|ng-bind-html|bypassSecurityTrust" [SRC]
rg -n "res\.send\([^)]*<|res\.write\([^)]*<|\.html\([^)]*req\." [SRC]
rg -n "<%-|{{{|\{\{\{&|unescaped" [SRC]
rg -n "marked\(|markdown\.|showdown|DOMPurify\.sanitize" [SRC]
rg -n "Mustache\.escape\s*=\s*function|mustache\.escape\s*=\s*false" [SRC]
rg -n '\$\(`<|`\s*<[^`]*\$\{' [SRC]
```

### DOM-based XSS sources → sinks

```bash
rg -n "location\.(hash|search|href)|document\.URL|document\.referrer" [SRC]
rg -n "postMessage\(|addEventListener\(['\"]message" [SRC]
rg -n "jQuery\([^)]*\)\.html\(|\.append\([^)]*req\." [SRC]
rg -n "javascript:|data:text/html|on\w+\s*=" [SRC]
```

### AI trace

Source: `req.query`, `req.body`, `message.value`, `location.hash`  
Sink: any HTML sink above without encode/sanitize  
**graphify path:** `"req.query" "innerHTML"` or `"message.value" "res.send"`

---

## SAST-INJ-RCE — Remote Code Execution

```bash
rg -n "eval\s*\(|new Function\s*\(|vm\.(runInNewContext|runInThisContext|Script)" [SRC]
rg -n "require\(\s*req\.|require\(\s*[^'\"]+\)|import\(\s*req\." [SRC]
rg -n "node-serialize|serialize\.unserialize|unserialize\(" [SRC]
rg -n "child_process\.(exec|execSync|spawn|spawnSync)" [SRC]
rg -n "puppeteer\.|playwright\.|page\.evaluate\(" [SRC]
rg -n "render_template_string|compile\([^)]*req\.|ejs\.render\([^)]*\+.*req\." [SRC]
```

**RCE chain examples:** template injection → `Function`; deserialization → `require('child_process')`; `page.evaluate(userScript)`.

---

## SAST-INJ-CMD — Command Injection

```bash
rg -n "exec\(|execSync|spawn\(|spawnSync|execFile\(" [SRC]
rg -n "shell\s*:\s*true|shell\s*:\s*['\"]/" [SRC]
rg -n "`[^`]*\$\{[^}]*(req\.|params\.|query\.|body\.)" [SRC]
rg -n "os\.system|subprocess\.(call|Popen|run)|popen\(" [SRC]
rg -n "git clone|curl\s+|wget\s+|bash\s+-c|sh\s+-c" [SRC]
```

**AI validate:** user input in command string or `shell: true` argument array that includes tainted segment.

---

## SAST-INJ-XXE — XML External Entity

```bash
rg -n "libxmljs|parseXmlString|xml2js|fast-xml-parser|xml2json" [SRC]
rg -n "DOMParser|SAXParser|expat|lxml|DocumentBuilder" [SRC]
rg -n "DOCTYPE|ENTITY|SYSTEM\s+['\"]file:|SYSTEM\s+['\"]http" [SRC]
rg -n "noent\s*:\s*true|processEntities\s*:\s*true|expandEntityReferences" [SRC]
rg -n "setFeature.*external-general-entities|disallow-doctype-decl" [SRC]
```

**Flag:** XML parser without `DOCTYPE` disabled / external entities off.  
**Safe signals:** `disallow-doctype-decl: true`, `noent: false`, `processEntities: false`.

---

## SAST-INJ-XML — XML Injection (non-XXE)

```bash
rg -n "<\s*\$\{|`\s*<[^`]*\$\{|'\s*<[^']*'\s*\+.*req\." [SRC]
rg -n "buildXml|createElement\([^)]*\+|xml\s*=\s*['\"].*\+.*req\." [SRC]
rg -n "xpath\.|selectNodes\(|xmlbuilder|xml\.(create|ele)" [SRC]
```

User-controlled data concatenated into XML document structure (tag/attribute injection).

---

## Burp DAST payloads (when HTTP endpoint + host from code)

| Class | Probe param | Payload |
|-------|-------------|---------|
| XSS | `q`, `name`, `search` | `<script>alert(1)</script>` |
| XSS | reflected | `"><img src=x onerror=alert(1)>` |
| CMD | `filename`, `host` | `; id` or `\`id\`` |
| XXE | XML body | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>` |

Only send if host discovered per `burp-host-discovery.md`. Read-only GET/POST first.

---

## Appendix E rows

| ID | Class |
|----|-------|
| SAST-INJ-XSS | XSS |
| SAST-INJ-RCE | RCE |
| SAST-INJ-CMD | Command Injection |
| SAST-INJ-XXE | XXE |
| SAST-INJ-XML | XML Injection |
| SAST-LEAK-01…08 | Stack trace / error disclosure |
| SAST-SECRET-01…11 | Hardcoded secrets |
