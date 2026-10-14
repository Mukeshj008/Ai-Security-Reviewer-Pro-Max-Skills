# Pack: Go (net/http, Gin, Echo, Fiber, Chi, gorilla/mux, gRPC)

**Detect:** `go.mod`, `*.go`.

## Sources

`r.URL.Query()`, `r.FormValue`, `r.PostForm`, `r.Header.Get`, `r.Body`, `mux.Vars(r)`, `chi.URLParam`, Gin `c.Query/Param/PostForm/ShouldBind*/GetHeader`, Echo `c.QueryParam/Param/Bind`, Fiber `c.Query/Params/BodyParser`, gRPC request messages.

## XSS & templates

| Vulnerable | Safe equivalent | FP trap |
|-----------|-----------------|---------|
| `text/template` rendering HTML (no escaping at all) | `html/template` (context-aware escaping) | Same API shape — **check the import**, not the call |
| `html/template` with `template.HTML(user)`, `template.JS(user)`, `template.URL(user)`, `template.HTMLAttr(user)` | pass plain `string` | Typed values from constants are fine |
| `fmt.Fprintf(w, "<p>%s</p>", user)`, `w.Write([]byte(user))`, `io.WriteString(w, user)` with HTML content type (Go sniffs `text/html` when no `Content-Type` is set) | `html.EscapeString`; set `Content-Type: application/json` / `text/plain`; `json.NewEncoder(w)` | `c.JSON(...)` (Gin/Echo) → JSON |
| Gin `c.Data(200, "text/html", []byte(user))`, `c.String` with HTML header | `c.HTML` with `html/template` | |

## SSTI / code

`template.New("").Parse(userString)` → template injection (with `text/template`, method calls on passed data objects are reachable — impact depends on what's in the data). `plugin.Open(user)`, `yaegi` eval of user code.

## SQL / ORM

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `db.Query("… " + x)`, `fmt.Sprintf("… %s", x)` into `Query/Exec/QueryRow` (database/sql, sqlx, pgx) | `db.Query("… $1", x)` / `?` | `Sprintf` with only `%d` of an `int` is not injectable |
| GORM `db.Raw(fmt.Sprintf(…))`, `db.Where(fmt.Sprintf("name = '%s'", x))`, `db.Where(userString)`, `Order(user)`, `Select(user)`, `Group(user)` | `db.Where("name = ?", x)`, allow-listed order columns | `db.Where(&User{Name: x})` is safe |
| `sqlx.In` misuse building strings | | |

## NoSQL

mongo-go-driver `bson.M{"user": input}` where `input` is decoded from JSON into `interface{}`/`map[string]interface{}` → operator injection; decode into typed structs.

## Command execution

`exec.Command("sh", "-c", x)`, `exec.Command("bash", "-c", …)` → injection. `exec.Command(bin, userArg)` → no shell, but option injection (`--upload-pack=` in git, `-o` for curl). Go does **not** invoke a shell by default.

## SSRF

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `http.Get(user)`, `http.NewRequest(method, user, …)`, `client.Do` with user URL, `resty` | parse with `url.Parse`, allow-list host/scheme, custom `DialContext` that checks resolved IP (`ip.IsPrivate()`, `IsLoopback`, `IsLinkLocalUnicast`) to beat DNS rebinding, `CheckRedirect` that re-validates | Base URL from config + `url.PathEscape(user)` → path only |
| `httputil.NewSingleHostReverseProxy(userURL)`, `ReverseProxy.Director` setting `req.URL.Host` from header | fixed target | |

TLS: `&tls.Config{InsecureSkipVerify: true}`, `MinVersion` unset with old servers (Go defaults are fine since 1.18 for clients).

## Path / file / upload

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `filepath.Join(base, user)` then `os.Open` — `Join` cleans `..` **but** keeps the result outside base | `filepath.Rel` check or `strings.HasPrefix(filepath.Clean(p), base+string(os.PathSeparator))`; Go 1.20+ `filepath.IsLocal(user)`; Go 1.24 `os.Root` | `http.FileServer(http.Dir(dir))` rejects `..` |
| `http.ServeFile(w, r, user)` | `http.Dir` + `FileServer` | `ServeFile` rejects `..` in `r.URL.Path` but **not** in the `name` arg |
| `archive/zip`, `archive/tar` extraction joining `hdr.Name` (Zip Slip) | `filepath.IsLocal(hdr.Name)` | |
| `multipart.FileHeader.Filename` as path | `filepath.Base` + generated name | |

## Deserialization

`encoding/gob` from untrusted input (DoS, type confusion), `yaml.Unmarshal` into `interface{}` (billion-laughs in older yaml.v2), `encoding/xml` is not XXE-prone (no external entities). JSON into `map[string]interface{}` then passed to DB → see NoSQL.

## Crypto / randomness

| Vulnerable | Safe |
|-----------|------|
| `math/rand` for tokens/OTP/keys | `crypto/rand` |
| `md5.Sum`, `sha1.Sum` for passwords | `golang.org/x/crypto/bcrypt`, `argon2` |
| `cipher.NewCBCEncrypter` with static IV; ECB via manual block loop; nonce reuse with `gcm.Seal` | random nonce per `Seal` |
| `==` / `bytes.Equal` on MACs | `hmac.Equal`, `subtle.ConstantTimeCompare` |

## Auth / session / JWT

- `golang-jwt` `jwt.Parse(t, keyFunc)` where `keyFunc` does not check `t.Method` (alg confusion) or returns the key for `none`; `ParseUnverified` used for authz. Use `jwt.WithValidMethods([]string{"RS256"})`.
- Middleware groups: Gin `r.Group("/admin", auth)` vs routes registered on `r` directly; Chi `r.With(auth)` scope; Echo `e.Group(..., middleware)` — routes registered before `Use()` in Echo/Gin are still covered (Gin applies `Use` to routes added **after** the call only). Verify order in Gin.
- `gorilla/sessions` with hardcoded key, `Secure: false`, `HttpOnly: false`.
- gRPC: missing auth interceptor (`grpc.UnaryInterceptor`) or reflection enabled in prod (`reflection.Register`).

## CSRF / CORS / headers

`rs/cors` `AllowedOrigins: []string{"*"}` + `AllowCredentials: true` (rs/cors refuses, but `AllowOriginFunc` returning true does reflect), gin-contrib/cors `AllowAllOrigins: true` + credentials; manual `w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))`. Cookie-auth forms without `gorilla/csrf`/`nosurf`.

## Redirect / header

`http.Redirect(w, r, r.URL.Query().Get("next"), 302)` → open redirect. Header values: net/http rejects CR/LF.

## Errors / logging / DoS

- `http.Error(w, err.Error(), 500)` leaking DB errors; `log.Printf("%+v", req)`.
- `http.Server{}` without `ReadHeaderTimeout`/`ReadTimeout` (Slowloris; gosec G112); `http.ListenAndServe` uses no timeouts.
- `io.ReadAll(r.Body)` without `http.MaxBytesReader`; `regexp` is RE2 (no catastrophic backtracking — ReDoS FP trap).
- Goroutine per request without bound; `pprof` imported in prod (`_ "net/http/pprof"` registers `/debug/pprof` on `DefaultServeMux`).

## Race conditions

Shared maps written from handlers without `sync.Mutex` (crashes: `concurrent map writes`); check-then-act on balances without DB transactions/`SELECT … FOR UPDATE`.

## Hint rg

```bash
G='--glob *.go -g !vendor/**'
rg -n "\"text/template\"|template\.(HTML|JS|URL|HTMLAttr|CSS)\s*\(|\.Parse\s*\(" $G
rg -n "fmt\.Fprint(f|ln)?\s*\(\s*w|w\.Write\s*\(|io\.WriteString\s*\(\s*w|c\.Data\s*\(" $G
rg -n "\.(Query|QueryRow|Exec|QueryContext|ExecContext|Raw|Where|Order|Select|Group)\s*\(\s*(fmt\.Sprintf|\"[^\"]*\"\s*\+)" $G
rg -n -i "Sprintf\s*\(\s*[\"\`][^\"\`]*\b(select|insert|update|delete|where)\b|[\"\`][^\"\`]*\b(select|insert|update|delete|where)\b[^\"\`]*[\"\`]\s*\+" $G   # SQL built in a variable first
rg -n "exec\.Command(Context)?\s*\(" $G
rg -n "http\.(Get|Post|NewRequest(WithContext)?)\s*\(|client\.Do\s*\(|NewSingleHostReverseProxy|resty\." $G
rg -n "InsecureSkipVerify\s*:\s*true" $G
rg -n "filepath\.Join\s*\(|http\.ServeFile\s*\(|os\.(Open|OpenFile|Create|ReadFile|WriteFile)\s*\(|zip\.OpenReader|tar\.NewReader|\.Filename" $G
rg -n "\"math/rand\"|md5\.|sha1\.|NewCBCEncrypter|bytes\.Equal\s*\(" $G
rg -n "jwt\.Parse\s*\(|ParseUnverified|WithValidMethods" $G
rg -n "Access-Control-Allow-Origin|AllowCredentials|AllowAllOrigins|AllowOriginFunc" $G
rg -n "http\.Redirect\s*\(|err\.Error\(\)|net/http/pprof|ListenAndServe\s*\(|ReadHeaderTimeout|io\.ReadAll\s*\(\s*r\.Body|MaxBytesReader" $G
rg -n "reflection\.Register|grpc\.(Unary|Stream)Interceptor" $G
rg -n "\"unsafe\"|unsafe\.Pointer|import \"C\"|//\s*#cgo" $G
rg -n "ldap\.NewSearchRequest|EscapeFilter|xpath\.|xmlquery" $G
rg -n "ShouldBind|BindJSON|c\.Bind\s*\(|json\.NewDecoder\s*\(\s*r\.Body\)\.Decode\s*\(\s*&" $G
rg -n "sync\.Mutex|go func\s*\(|FOR UPDATE|\.Clauses\s*\(\s*clause\.Locking" $G
rg -n "reflect\.ValueOf|MethodByName|plugin\.Open" $G
rg -n "^replace\s|=>\s*\.\./|GOFLAGS|GOINSECURE|GONOSUMDB|GOPRIVATE" --glob "{go.mod,*.env,Makefile,Dockerfile*}"
```

## Class coverage index

| ID | Vulnerable in Go | Safe equivalent | FP trap / note |
|----|-----------------|-----------------|----------------|
| L01 | § XSS: `text/template` for HTML, `template.HTML/JS/URL(user)`, `fmt.Fprintf(w, "<p>%s", x)`, `c.Data(…"text/html"…)` | `html/template`, `html.EscapeString`, `c.JSON` | check the import, not the call name |
| L02 | `template.New("").Parse(userString)` (text or html) — exposes methods on data objects | parse only constant templates | constant template + user data is fine |
| L03 | `plugin.Open(user)`, `yaegi`/`goja`/`otto` interpreters with user code, `go:generate` N/A at runtime | no runtime eval | Go has no `eval` |
| L04 | § SQL: `fmt.Sprintf`/`+` into `Query/Exec`, GORM `Raw(Sprintf)`, `Where(userString)`, `Order(user)` | `$1`/`?` placeholders, `Where("x = ?", v)`, allow-listed order | `Where(&Struct{})` is bound |
| L05 | mongo-go `bson.M` from `map[string]interface{}` decoded JSON → operator injection | decode into typed structs | |
| L06 | `exec.Command("sh","-c",x)` | `exec.Command(bin, args...)` | no shell by default; option injection still possible (use `--`) |
| L07 | go-ldap `NewSearchRequest(…, fmt.Sprintf("(uid=%s)", u), …)`; `xmlquery`/`xpath` with concatenated expressions | `ldap.EscapeFilter(u)`; compile fixed XPath, compare values in Go | |
| L08 | log injection with `log.Printf("%s", input)` in text logs; header values — net/http rejects CR/LF (no splitting) | `slog` JSON handler, `%q` | header splitting N/A on net/http |
| L09 | § SSRF: `http.Get(user)`, `NewRequest(user)`, `ReverseProxy` with user host | `url.Parse` + allow-list + `DialContext` IP check + `CheckRedirect` | `url.PathEscape(user)` on config base = path only |
| L10 | `filepath.Join(base, user)` then open; `http.ServeFile(w, r, user)` | `filepath.IsLocal`, `os.Root` (1.24), `http.FileServer(http.Dir)` | `Join` cleans `..` but result can escape base |
| L11 | zip/tar extraction with `hdr.Name`, `FileHeader.Filename` as path, no size limit (`MaxBytesReader`) | `filepath.IsLocal(hdr.Name)`, `filepath.Base`, size caps | |
| L12 | `encoding/gob` from untrusted peers, `yaml.v2` billion laughs into `interface{}`, `json` into `interface{}` passed to DB | typed structs, size limits | Go has no gadget-chain RCE deserialization in stdlib |
| L13 | `encoding/xml` has no external entities (safe from XXE); risk is libxml2 bindings (`lestrrat-go/libxml2`) with entity options | stdlib `encoding/xml` | XXE usually N/A in Go |
| L14 | binding request JSON directly into DB model structs (`IsAdmin`, `Balance` fields) via `ShouldBindJSON(&user)` / `Decode(&model)` then `db.Save` | separate input DTO, `json:"-"` on sensitive fields | GORM `Updates(map)` from request = mass assignment |
| L15 | `gorilla/sessions` hardcoded key, `Secure/HttpOnly` false, no session rotation on login, `==` password compare | random keys from env, `bcrypt.CompareHashAndPassword` | |
| L16 | golang-jwt `Parse` keyFunc ignoring `t.Method`, `ParseUnverified`, missing `exp` check (v4 `MapClaims` without `VerifyExpiresAt`), OAuth `state` unchecked | `jwt.WithValidMethods`, `WithExpirationRequired` (v5) | |
| L17 | Gin routes registered **before** `r.Use(auth)` (Gin applies `Use` only to later routes), handlers outside auth `Group`, `db.First(&o, id)` without owner | auth group, owner in `Where` | Echo `Use` covers all routes |
| L18 | cookie-session forms without `gorilla/csrf`/`nosurf`, `SameSite` unset | CSRF middleware | bearer APIs N/A |
| L19 | manual `Access-Control-Allow-Origin` = request `Origin` + credentials, `AllowOriginFunc` returning true | explicit allow-list | rs/cors refuses `*` + credentials |
| L20 | `http.Cookie{}` without `Secure/HttpOnly/SameSite`, no HSTS/CSP | set flags, `secure` middleware (unrolled/secure) | |
| L21 | `http.Redirect(w, r, r.FormValue("next"), …)` | relative-path allow-list | |
| L22 | `md5/sha1` for passwords, CBC with static IV, nonce reuse in `gcm.Seal`, `des`/`rc4` | bcrypt/argon2, random nonce | |
| L23 | `math/rand` (and `math/rand/v2` non-crypto sources) for secrets | `crypto/rand`, `rand.Text()` (1.24) | |
| L24 | `InsecureSkipVerify: true`, custom `VerifyPeerCertificate` returning nil | default verification, `RootCAs` | |
| L25 | secrets in `config.go`/YAML, `GIN_MODE=debug` in prod, `pprof` on public mux | env, separate admin mux | |
| L26 | `http.Error(w, err.Error(), 500)` with DB/internal errors, panics returning stack (`gin.Recovery` in debug) | generic message + log | |
| L27 | `log.Printf("%+v", req)` / logging tokens, request dumps (`httputil.DumpRequest`) | redaction | |
| L28 | no `ReadHeaderTimeout` (Slowloris), `io.ReadAll(r.Body)` unbounded, unbounded goroutines, `json.Decoder` without limits | timeouts, `MaxBytesReader`, worker pools | `regexp` is RE2 — ReDoS N/A |
| L29 | `concurrent map writes` (crash), shared state without `sync.Mutex`, check-then-act on balances without `SELECT … FOR UPDATE`/`clause.Locking`; run tests with `-race` | mutex/`sync.Map`, DB locks, atomic UPDATE | |
| L30 | integer overflow when converting `int64`→`int32`/`uint`, float money, negative quantities, `strconv.Atoi` without bounds | bounds checks, integer minor units | |
| L31 | `unsafe.Pointer` arithmetic, cgo (`import "C"`) buffer handling, `reflect.SliceHeader` misuse | avoid `unsafe`; see `c-cpp.md` for C code | safe Go is memory-safe (data races can still corrupt) |
| L32 | `replace` directives to forks/local paths, `GOINSECURE`/`GONOSUMDB`/`GOFLAGS=-insecure`, `go get` of unpinned `@latest` in CI | `go.sum` committed, `GOFLAGS=-mod=readonly`, `GOPROXY` + sumdb | SCA opt-in |
| L33 | gRPC without auth interceptor, `reflection.Register` in prod, gqlgen without complexity limit, `gorilla/websocket` `CheckOrigin: func(r) bool { return true }` | interceptors, `extension.FixedComplexityLimit`, origin check | |
| L34 | `reflect.ValueOf(obj).MethodByName(user).Call(...)`, `plugin.Open` | explicit switch/map | |
| L35 | ignored errors (`_ = err`) turning auth failures into success, nil-map writes / nil-pointer panics (DoS), loop-variable capture in goroutines (fixed in Go 1.22), `defer` in loops leaking fds, `time.After` leaks | handle every error, `errcheck` lint | |
