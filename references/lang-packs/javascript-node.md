# Pack: JavaScript / TypeScript — server (Node.js)

**Detect:** `package.json` with `express`, `koa`, `fastify`, `@nestjs/core`, `@hapi/hapi`, `next` (API routes / server actions), `restify`; files calling `app.listen`, `http.createServer`, `router.get(…)`.
**Also read:** `../express-auth-audit.md` whenever `app.`/`router.` routing exists.

## Sources

`req.query`, `req.body`, `req.params`, `req.headers[...]` (incl. `x-forwarded-*`, `host`), `req.cookies`, `req.files` / multer, `ctx.request.*` (Koa), `request.query/body/params` (Fastify), NestJS `@Body() @Query() @Param() @Headers()`, Next `searchParams` / `formData()`, WebSocket `message`, Kafka/RabbitMQ consumer payloads, values read back from DB/Redis that a user wrote earlier.

Note `qs` parsing: `?a[b]=1` makes `req.query.a` an **object**; `?a=1&a=2` makes an **array**. Type confusion and NoSQL operator injection start here.

## XSS & server templates

| Vulnerable | Safe equivalent | FP trap |
|-----------|-----------------|---------|
| `res.send(str)` / `res.write(str)` / `res.end(str)` with user data and no JSON content type (Express defaults strings to `text/html`) | `res.json(obj)`; `res.type('text/plain')`; encode with `he`/`escape-html` | `res.send(object)` → JSON, not XSS |
| EJS `<%- user %>` | EJS `<%= user %>` (escaped) | Fixed template + `<%= %>` is **not** SSTI or XSS |
| Pug `!{user}`, `!=` | `#{user}`, `=` | |
| Handlebars `{{{user}}}`, `new SafeString(user)` | `{{user}}` | |
| Nunjucks `{{ x | safe }}`, `autoescape: false` | default `autoescape: true` | |
| JSONP `res.jsonp` with user `callback` name, or manual `callback + '(' + json + ')'` | fixed callback / CORS | |
| User string inside inline `<script>` via `JSON.stringify` without escaping `</` | `serialize-javascript`, escape `<` as `\u003c` | |

## SSTI / code injection

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `ejs.render(userTemplate)`, `pug.compile(user)`, `Handlebars.compile(user)`, `nunjucks.renderString(user)`, `_.template(user)` | Fixed templates; user data only as context | `ejs.render(fixedString, {name})` is safe |
| `eval(x)`, `new Function(x)`, `vm.runInNewContext(x)` (vm is **not** a sandbox), `setTimeout(string)`, `require(userPath)`, `import(userPath)` | Lookup table of allowed modules | `JSON.parse` is not code execution |

## SQL / ORM

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `` `SELECT … ${x}` ``, `'…' + x` into `query()` (mysql, pg, sqlite3, mssql) | `query('… $1', [x])`, `?` placeholders | Static strings with placeholders |
| Sequelize `sequelize.query(str)` with interpolation, `Sequelize.literal(user)`, `where: { [Op.like]: … }` built from raw strings | `replacements` / `bind` options | `Model.findAll({ where: { id: x } })` is parameterized |
| Knex `.raw(str)`, `whereRaw(str)` with interpolation | `.raw('?', [x])` | |
| TypeORM `.query(str)`, `createQueryBuilder().where(\`id = ${x}\`)` | `.where('id = :id', { id: x })` | |
| Prisma `$queryRawUnsafe(str)`, `$executeRawUnsafe` | `$queryRaw` tagged template (parameterized) | `$queryRaw\`… ${x}\`` is safe; `$queryRaw(Prisma.raw(x))` is not |
| `ORDER BY ${col}` / table names from input | allow-list of column names | |

## NoSQL (Mongo / Mongoose)

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `find(req.body)`, `findOne({ user: req.body.user })` where value can be `{ $ne: null }` | Cast: `String(x)`, Mongoose schema with `strictQuery` / `sanitizeFilter: true`, `mongo-sanitize`, Joi/Zod type check | Value typed by validator as string first |
| `$where` / `$function` / `mapReduce` with user strings | Avoid server-side JS | |
| `$regex` from user input (ReDoS + data leak) | escape with `_.escapeRegExp`, length cap | |
| Arbitrary `query` / `projection` objects passed through (admin/internal APIs) | allow-list keys and operators | Allow-listed top-level keys can still carry nested operators — check depth |

## Command execution

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `exec(str)`, `execSync(str)`, `spawn(cmd, { shell: true })` with input | `execFile(bin, [args])`, `spawn(bin, args)` without shell | `execFile` with user value as **arg** can still be option injection (`--output=/etc/…`) — check the binary |
| `shelljs.exec(str)`, `child_process.fork(userPath)` | | |

## SSRF

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `axios/got/fetch/request/needle/http.get(userUrl)` | Parse with `new URL`, allow-list host + scheme, resolve DNS and block private ranges, disable redirects or re-check per hop | Config base URL + user **path/query** segment → not host control (SSRF-ADJ-01); still check `..`, `@`, `//` concatenation |
| `request({ url: base + userInput })` where `base` has no trailing path → `@evil.com` | `new URL(path, base)` then assert `origin === base origin` | |
| Redirect follow (`maxRedirects` default 5 in axios/request) to internal hosts | `maxRedirects: 0` | |
| Webhook/callback URLs stored by users and called later | same allow-list at call time (second-order) | |

TLS: `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `https.Agent({ rejectUnauthorized: false })` → certificate validation disabled (CWE-295).

## Path / file / upload

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `path.join(base, user)` / `path.resolve(base, user)` then `fs.*` | `const p = path.resolve(base, user); if (!p.startsWith(path.resolve(base) + path.sep)) reject` | `path.join` does **not** stop `..` |
| `res.sendFile(user)`, `res.download(user)` without `root` option | `res.sendFile(name, { root: base })` + basename | `express.static` is safe for traversal |
| multer `storage` using `file.originalname` | generated names; check MIME by content | |
| `adm-zip` / `unzipper` / `tar` extract without entry path check (Zip Slip) | validate each entry's resolved path | `tar` ≥ 6 strips `..` by default — check version + options |

## Deserialization / prototype pollution

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `node-serialize` `unserialize`, `serialize-javascript` round-trip of user data, `funcster` | `JSON.parse` | `JSON.parse` alone is not RCE |
| `_.merge`, `_.defaultsDeep`, `$.extend(true, …)`, hand-written recursive merge, `_.set(obj, userPath, v)` with user keys → `__proto__` / `constructor.prototype` | `Object.create(null)`, key deny-list, `structuredClone`, lodash ≥ 4.17.21 still pollutes via `_.set` with user path | `Object.assign({}, body)` pollutes only own copy, not the prototype (but enables mass assignment) |
| `js-yaml` `load` with `DEFAULT_FULL_SCHEMA` (v3) | `js-yaml` v4 `load` (safe) | |

## XML

`libxmljs` `parseXml(x, { noent: true })`; `xml2js` is safe from XXE by default; `xmldom` + `xpath` with string-built XPath from input → XPath injection. Also trace string/template concatenation into XML/SOAP element names, attributes, raw fragments, CDATA boundaries, or namespaces; use builders/serializers with fixed names and escaped values. Run `../xml-security-audit.md`.

## Crypto / randomness

| Vulnerable | Safe |
|-----------|------|
| `Math.random()` for tokens, OTP, reset codes, session IDs | `crypto.randomBytes`, `crypto.randomInt`, `crypto.randomUUID` |
| `createHash('md5'|'sha1')` for passwords or signatures | `bcrypt`/`argon2`/`scrypt`; HMAC-SHA256 |
| `createCipher` (deprecated, no IV), `aes-*-ecb`, static IV, IV reused per key | `createCipheriv('aes-256-gcm', key, randomIV)` |
| `token === expected` for HMAC/signature | `crypto.timingSafeEqual` (equal-length buffers) |
| Hardcoded keys in `config*.js`, `.env` committed, `process.env.X || 'changeme'` fallback | env without fallback; fail at boot |

## Auth / session / JWT

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `jwt.decode()` used for authorization | `jwt.verify(token, key, { algorithms: ['RS256'] })` | `decode` only for logging/routing is fine |
| `jwt.verify` without `algorithms` and a key that could be a public key (alg confusion), `algorithms: ['none']` | pin algorithms, audience, issuer | jsonwebtoken ≥ 9 rejects `none` by default |
| Route registered **before** `app.use(auth)` / `router.use(auth)` | register after, or per-route middleware | Middleware mounted on a path prefix covers only that prefix |
| `express-session` with `secret: 'keyboard cat'`, `cookie: { secure: false }`, no `regenerate()` on login (fixation) | strong secret, `secure`, `httpOnly`, `sameSite`, `req.session.regenerate` | |
| `passport` strategy `verify` callback that returns `done(null, user)` on error paths | check every branch | |
| Basic-auth compare with `!==` | `timingSafeEqual` | |

## CSRF / CORS / headers / cookies

- `cors({ origin: true, credentials: true })` or manual `Access-Control-Allow-Origin: req.headers.origin` + `Allow-Credentials: true` → origin reflection with credentials.
- Regex origin checks: `/paytm\.com/` matches `evilpaytm.com` and `paytm.com.evil.io` — require anchored `^https://([a-z0-9-]+\.)?paytm\.com$`.
- `csurf` (deprecated) or no CSRF on cookie-authenticated state-changing routes. Header-token APIs (Authorization / custom header) are not CSRF-prone unless cookies also authenticate.
- No `helmet()` (or equivalent at nginx/CDN — verify before reporting; G3).
- `res.cookie(name, val)` without `httpOnly`, `secure`, `sameSite` for session/auth cookies.
- `app.set('trust proxy', true)` + `req.ip` for rate-limit / allow-listing → spoofable via `X-Forwarded-For`.

## Redirect / header injection

- `res.redirect(req.query.next)` → open redirect; `res.redirect('/' + x)` can still be `//evil.com`.
- `res.setHeader(name, userValue)` — Node ≥ 14 rejects CR/LF (throws), so classic CRLF needs an old Node or a raw socket write; report as header **injection of values** (e.g. `Content-Disposition` filename) rather than response splitting.

## Logging / errors

- `res.status(500).json({ error: err.message })` / `err.stack` → DB and path leakage.
- `log.info(req.body)` / `log.info(req.headers)` → tokens, OTP, passwords, PII. Check whether a masking layer exists and which keys it actually masks.
- `console.log` in production paths.

## DoS

- `new RegExp(userInput)`, regexes with nested quantifiers on user input (`/(a+)+$/`).
- `bodyParser.json({ limit })` missing or huge; `express.urlencoded({ extended: true, parameterLimit })`.
- Unbounded `limit`/`pageSize` from query into DB queries.
- Synchronous crypto/zlib/fs in request path (`*Sync`).

## Hint rg (run after reading routes)

```bash
G='--glob *.{js,cjs,mjs,ts} -g !node_modules/** -g !dist/** -g !build/**'
rg -n "res\.(send|write|end)\s*\(|\.type\s*\(\s*['\"](html|text/html)|text/html|\.(send|write|end)\s*\(\s*['\"\`]\s*<" $G
rg -n "<%-|!\{|\{\{\{|\|\s*safe|autoescape\s*:\s*false|SafeString" --glob "*.{ejs,pug,jade,hbs,handlebars,njk,html,js,ts}" -g '!node_modules/**'
rg -n "(ejs|pug|Handlebars|nunjucks)\.(render|compile|renderString)\s*\(|_\.template\s*\(" $G
rg -n "eval\s*\(|new Function\s*\(|vm\.run|setTimeout\s*\(\s*['\"\`]|require\s*\([^'\"\`]" $G
rg -n "(query|raw|whereRaw|\$queryRawUnsafe|\$executeRawUnsafe|literal)\s*\(\s*[\`'\"][^\`'\"]*(\$\{|\+)" $G
rg -n -i "\b(select|insert|update|delete|where|order by)\b[^;]*(['\"\`]\s*\+|\\\$\{)" $G   # SQL built in a variable first
rg -n "\b(db|conn|connection|pool|client|knex|sequelize)\.(all|get|run|each|exec|query|execute)\s*\(" $G
rg -n "\.(find|findOne|updateOne|updateMany|deleteMany|aggregate|countDocuments)\s*\(\s*req\.|\\\$where|\\\$regex" $G
rg -n "child_process|\bexec(Sync)?\s*\(|spawn\s*\([^)]*shell\s*:\s*true" $G
rg -n "(axios|got|fetch|needle|superagent|request)(\.(get|post|request))?\s*\(|http[s]?\.(get|request)\s*\(" $G
rg -n "rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED" $G
rg -n "path\.(join|resolve)\s*\([^)]*req\.|sendFile\s*\(|res\.download\s*\(|originalname" $G
rg -n "_\.(merge|defaultsDeep|set|setWith)\s*\(|extend\s*\(\s*true|__proto__|constructor\s*\[" $G
rg -n "Math\.random\s*\(|createHash\s*\(\s*['\"](md5|sha1)|createCipher\s*\(|-ecb['\"]|timingSafeEqual" $G
rg -n "jwt\.(decode|verify)\s*\(|algorithms\s*:" $G
rg -n "Access-Control-Allow-Origin|cors\s*\(|credentials\s*:\s*true|trust proxy|helmet\s*\(" $G
rg -n "res\.redirect\s*\(|setHeader\s*\(|res\.cookie\s*\(" $G
rg -n "err(or)?\.(message|stack)|log\.(info|debug|warn|error)\s*\(\s*req\.(body|headers)" $G
rg -n "new RegExp\s*\(|limit\s*:\s*['\"]?\d+mb" $G
rg -n "ldapjs|\.search\s*\(|xpath\.select|libxmljs|noent\s*:\s*true" $G
rg -n "graphql|introspection|ApolloServer|depthLimit|new WebSocket\.Server|io\.on\s*\(\s*['\"]connection|verifyClient" $G
rg -n "\"(preinstall|install|postinstall)\"\s*:" --glob "package.json" -g '!node_modules/**'
```

## Class coverage index

| ID | Vulnerable in Node.js / TypeScript | Safe equivalent | FP trap / note |
|----|-----------------------------------|-----------------|----------------|
| L01 | § XSS: `res.send(str)` HTML, EJS `<%-`, Pug `!{}`, HBS `{{{ }}}` | `res.json`, escaped template tags | `res.send(obj)` is JSON |
| L02 | § SSTI: `ejs.render(userTpl)`, `pug.compile(user)`, `_.template(user)` | fixed templates, user data as context | EJS `<%= %>` in fixed template is not SSTI |
| L03 | `eval`, `new Function`, `vm.run*` (not a sandbox), `vm2` (abandoned, escapes), `require(user)`, `import(user)` | lookup map of allowed modules | `JSON.parse` is not eval |
| L04 | § SQL/ORM: template-string SQL, `Sequelize.literal`, `knex.raw`, `$queryRawUnsafe`, `ORDER BY ${col}` | placeholders / `replacements` / tagged `$queryRaw` | Sequelize `where: {id}` is bound |
| L05 | § NoSQL: `find(req.body)`, `{ $ne: null }` via qs objects, `$where`, `$regex` from input | `String(x)`, `sanitizeFilter`, schema types | typed DTO validated first |
| L06 | § Command: `exec`, `execSync`, `spawn(...,{shell:true})` | `execFile`/`spawn(bin,[args])` | option injection still possible with arrays (`--` separator) |
| L07 | `ldapjs` filter `(uid=${u})`; `xpath.select("//u[@n='"+x+"']")` | `ldap-escape` / `ldapjs` `EqualityFilter`; parameterized XPath vars | JMESPath / lodash `get` are not LDAP |
| L08 | `res.setHeader('Content-Disposition', 'attachment; filename=' + name)`; logging raw `\n` input (Bunyan/winston JSON escapes newlines — log forging needs a text formatter) | `content-disposition` pkg; JSON log formatter | Node ≥14 throws on CR/LF in header values (no response splitting) |
| L09 | § SSRF: axios/got/fetch/request with user URL or `base + user` without slash; redirects followed | `new URL` + host allow-list + IP check + `maxRedirects:0` | config base + query param = SSRF-adjacent only |
| L10 | § Path: `path.join(base, user)` then `fs.*`; `res.sendFile(user)` | `path.resolve` + `startsWith(base + sep)`; `sendFile(name,{root})` | `express.static` is traversal-safe |
| L11 | multer `originalname`, MIME from client, `adm-zip`/`unzipper` entries unchecked | generated names, magic-byte check, per-entry path check | `tar` ≥6 strips `..` |
| L12 | `node-serialize`, `funcster`, `serialize-javascript` round-trip, js-yaml v3 `load` with full schema | `JSON.parse`, js-yaml v4 `load` | `JSON.parse` alone is safe |
| L13 | `libxmljs.parseXml(x,{noent:true})`; string-built XPath; concatenation into XML/SOAP markup, names, attributes, CDATA, or raw fragments | entity-disabled parser; fixed-name builder/serializer with escaped values; XPath variables | `xml2js`/`fast-xml-parser` don't resolve external entities; safe value serialization is not structural injection |
| L14 | prototype pollution: `_.merge/defaultsDeep/set`, recursive merge of `req.body`, `__proto__`/`constructor.prototype`; mass assignment: `Model.create(req.body)`, `Object.assign(user, req.body)` | key deny-list, `Object.create(null)`, explicit field picking (`_.pick`) | `Object.assign({}, body)` doesn't pollute prototype |
| L15 | § Auth: `express-session` weak secret, no `regenerate` on login, cookies not `secure`; OTP compared with `==`, no attempt limit | strong secret, `regenerate`, rate-limit (`express-rate-limit`) | header-token APIs have no session fixation |
| L16 | `jwt.decode` for authz; `verify` without `algorithms`; HS/RS confusion; long-lived tokens without revocation; OAuth `state` unchecked | `jwt.verify(t,k,{algorithms,audience,issuer})` | jsonwebtoken ≥9 rejects `none` |
| L17 | route registered before `router.use(auth)`; `findById(req.params.id)` without owner filter; uid from header/query | auth on every route; `{ _id, ownerId: req.user.id }` | prefix-mounted middleware covers only that prefix |
| L18 | cookie-session auth + state-changing POST without CSRF token / `SameSite` | `csrf-csrf`/`lusca`, `SameSite=Lax/Strict` | bearer-header APIs are not CSRF-prone |
| L19 | `cors({origin:true,credentials:true})`, reflected `Origin`, unanchored regex | explicit origin list | `origin:'*'` without credentials = low |
| L20 | no `helmet()`; `res.cookie` without `httpOnly/secure/sameSite`; `trust proxy` misuse | `helmet`, cookie flags | headers may be set at nginx/CDN (check before reporting) |
| L21 | `res.redirect(req.query.next)`; `'/'+x` → `//evil`; `url.parse` legacy quirks | same-origin check via `new URL(x, base).origin` | redirect to fixed path list |
| L22 | `createHash('md5'/'sha1')` for passwords, `createCipher`, ECB, static IV | `bcrypt`/`argon2`, `aes-256-gcm` + random IV | md5 for cache keys/ETags is fine |
| L23 | `Math.random()` for tokens/OTP/IDs; `uuid` v1 as secret | `crypto.randomBytes/randomInt/randomUUID` | `Math.random` for UI jitter is fine |
| L24 | `rejectUnauthorized:false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, custom `checkServerIdentity` returning undefined | default verification, pinned CA via `ca` | test-only agents (check path) |
| L25 | secrets in `config*.js`, `process.env.X || 'default'`, `.env` committed, `NODE_ENV` dev in prod | env without fallback, fail at boot | `.env.example` with placeholders |
| L26 | `res.json({error: err.message/stack})`; Express default handler in dev mode leaks stack | generic message + correlation id | stack only when `NODE_ENV=development` |
| L27 | `log.info(req.body/headers)`, logging OTP/token/PAN/Aadhaar | redaction/masking serializers | check which keys the masking layer covers |
| L28 | `new RegExp(user)`, nested quantifiers on input, no body limit, unbounded `limit` query, sync crypto/fs in handlers, `JSON.parse` of huge body | `re2`/`safe-regex`, body limits, pagination caps | constant regex on short bounded input |
| L29 | read-modify-write on balance/seat without transaction or atomic `$inc`/`findOneAndUpdate`; `await` between check and act; shared module-level state across requests | DB transactions, atomic operators, unique indexes, Redis `SET NX` locks | single-threaded JS still races across `await` and across PM2 workers |
| L30 | client-sent price/amount trusted; `parseInt` without radix/NaN check; float money math; qs array/object type confusion (`?amount[]=1`) | recompute server-side, integers in minor units, schema validation (Joi/Zod) | |
| L31 | native addons (`node-gyp`, N-API) buffer handling; `Buffer.allocUnsafe` exposed to clients; `new Buffer(n)` (deprecated, uninitialized) | `Buffer.alloc`; see `c-cpp.md` for addon source | pure JS has no memory corruption |
| L32 | `preinstall/postinstall` scripts in deps, unpinned `*`/`latest`, missing lockfile, `npm install` in CI instead of `npm ci`, typosquats, git-URL deps | lockfile + `npm ci`, `--ignore-scripts` where possible | SCA is opt-in (code-only default) |
| L33 | GraphQL introspection in prod, no depth/cost limit, per-resolver auth missing; `ws`/socket.io without auth on `connection`, no origin check | `graphql-depth-limit`, resolver auth, `verifyClient`/handshake auth | see `../protocol-scans-graphql-ws-grpc.md` |
| L34 | `obj[req.query.method]()` dynamic dispatch, `require(path)` from input, `global[name]` | allow-listed handler map | |
| L35 | `==` coercion in auth checks; `qs` deep objects; `async` errors unhandled crash the process (DoS); `setTimeout(string)`; `vm` sandbox assumption; Express 4 does not catch rejected promises | `===`, `express-async-errors` / try-catch, `process.on('unhandledRejection')` logging | |
