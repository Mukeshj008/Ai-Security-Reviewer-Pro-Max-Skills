# Pack: Scala (Play, Akka HTTP / Pekko, http4s, ZIO HTTP, Spark, Slick, Doobie)

**Detect:** `build.sbt`, `project/*.sbt`, `*.scala`, `*.sc`, Twirl `*.scala.html`.
**Also read:** `java-kotlin.md` for JVM-wide sinks (deserialization, XML parsers, `Runtime.exec`, TLS) — Scala code calls the same Java APIs.

## Sources

Play `request.queryString/body/headers/cookies`, form bindings (`Form(mapping(...))`), route params; Akka/Pekko HTTP `parameters(...)`, `entity(as[T])`, `headerValueByName`, path matchers; http4s `req.params`, `req.as[T]`, `QueryParamDecoderMatcher`; Spark job inputs from user-uploaded datasets; Kafka consumer records.

## Key language rules

- Twirl `@value` is HTML-escaped; `@Html(value)` is **raw**.
- Slick plain SQL: `sql"… $x"` interpolator **binds** `$x`; `#$x` splices raw text. Doobie `fr"… $x"`/`sql"…"` bind; `Fragment.const(x)` is raw.
- Quill `infix"…$x"` / `sql"…$x"` with `.pure` / `#$` is raw.
- `scala.sys.process`: `"cmd " + x !` tokenizes on spaces (no shell, but argument injection); `Seq("sh","-c",x).!` is shell injection.
- Spark: `spark.sql(s"… $x")` string interpolation is SQL injection; DataFrame API with `col("x") === lit(v)` is safe.

## Hint rg

```bash
G='--glob *.{scala,sc} -g !target/** -g !project/target/**'
rg -n "@Html\s*\(" --glob "*.scala.html"
rg -n "#\\\$|Fragment\.const|infix\"|\.pure|sql\s*\(\s*s\"|spark\.sql\s*\(\s*s\"|executeQuery\s*\(\s*s\"" $G
rg -n "sys\.process|\.!\s*$|\.!!|Process\s*\(|Runtime\.getRuntime" $G
rg -n "ObjectInputStream|readObject|enableDefaultTyping|JsonTypeInfo|Kryo|chill|java\.io\.Serializable" $G
rg -n "ws\.url\s*\(|Http\(\)\.singleRequest|Uri\s*\(\s*[a-z]|BlazeClient|EmberClient|sttp|basicRequest" $G
rg -n "Redirect\s*\(|addingToSession|withSession|CSRFFilter|play\.filters|allowedOrigins|SecurityHeadersFilter" $G
rg -n "scala\.util\.Random|new Random|MessageDigest\.getInstance\s*\(\s*\"(MD5|SHA-?1)|Cipher\.getInstance\s*\(\s*\"(AES|DES)" $G
rg -n "play\.http\.secret\.key|play\.filters\.(enabled|disabled)|akka\.http\.server|parsing\.max-content-length" --glob "*.conf"
rg -n "Pattern\.compile|\.r\b|new Regex" $G
rg -n "synchronized|AtomicReference|Ref\.|TVar|STM|FOR UPDATE" $G
```

## Class coverage index

| ID | Vulnerable in Scala | Safe equivalent | FP trap / note |
|----|--------------------|-----------------|----------------|
| L01 | Twirl `@Html(userValue)`, `Ok(s"<p>$x</p>").as(HTML)`, Akka `HttpEntity(ContentTypes.\`text/html(UTF-8)\`, s"…$x")` | Twirl `@value`, `Ok(Json.toJson(x))` | Twirl `@x` escapes by default |
| L02 | Twirl is compiled (not injectable); risk is Scalate/Mustache/Handlebars templates compiled from user strings | compile-time Twirl | |
| L03 | `scala.tools.reflect.ToolBox.eval`, `IMain`/REPL interpreter, `ScriptEngine` with user code | no runtime eval | |
| L04 | Slick `#$x`, Doobie `Fragment.const(x)`, Quill `infix` with raw splice, `spark.sql(s"…$x")`, JDBC `s"…$x"` | `sql"…$x"` binding, `fr"…$x"`, DataFrame API | Slick/Doobie `$x` (no `#`) is bound |
| L05 | ReactiveMongo/mongo-scala `BSONDocument` built from user JSON objects (operator injection) | typed case classes, scalar extraction | |
| L06 | `Seq("sh","-c",x).!`, `s"git clone $url".!` (argument injection, tokenized on spaces) | `Seq(bin, arg).!` with validated args, `--` separator | `"cmd".!` without shell |
| L07 | UnboundID/JNDI LDAP filters with `s"(uid=$u)"`, XPath via `javax.xml.xpath` concat | `Filter.createEqualityFilter`, XPath variables | |
| L08 | `Ok(...).withHeaders(name -> user)` (Play rejects invalid chars in recent versions), log forging in text appenders | Logback JSON encoder | |
| L09 | Play `ws.url(userUrl)`, Akka `Http().singleRequest(HttpRequest(uri = user))`, http4s/sttp clients with user `Uri` | host allow-list + IP check, redirects off | config base + path segment = adjacent |
| L10 | `new File(base, user)`, `Ok.sendFile(new File(user))`, `Paths.get(base, user)` | normalize + `startsWith(base)`, `Assets` controller | Play `Assets` is traversal-safe |
| L11 | `MultipartFormData.FilePart.filename` as path, Zip Slip in extraction helpers | `Paths.get(filename).getFileName`, entry path checks | |
| L12 | Java serialization in Akka remoting (`akka.actor.allow-java-serialization = on`), Kryo/Chill without registration, Jackson default typing, Spark reading user-provided serialized objects | Akka Jackson/Protobuf serializers, Kryo `registrationRequired` | Akka ≥2.6 disables Java serialization by default |
| L13 | `scala.xml.XML.loadString` (old versions use SAX with entity resolution), JVM parsers as in `java-kotlin.md` L13 | secure `SAXParserFactory` passed to `XML.withSAXParser` | scala-xml ≥2.0 disables DOCTYPE by default |
| L14 | Play JSON `Json.reads[UserEntity]` binding sensitive fields (`role`, `isAdmin`) straight from request | separate input case class | |
| L15 | Play session cookie (signed, not encrypted) holding sensitive data, `play.http.session.secure=false`, no rotation on login | server-side session store, `secure=true` | |
| L16 | `jwt-scala`/`pauldijou` decode without algorithm list (`JwtCirce.decode(t, key, JwtAlgorithm.allHmac())` accepting unexpected algs), `decodeRaw` without verification | pin single algorithm, verify `exp/aud/iss` | |
| L17 | Play actions without `Authenticated`/Silhouette `SecuredAction`, Akka routes outside `authenticateOAuth2` directive, repository lookups without owner | action builders on every route, owner filter | |
| L18 | Play `CSRFFilter` disabled or `play.filters.csrf.header.bypassHeaders` too broad; `+ nocsrf` route modifier on state-changing routes | default `CSRFFilter` | token-auth APIs N/A |
| L19 | `play.filters.cors.allowedOrigins = null` (all) + `supportsCredentials = true`; Akka `cors()` with `HttpOriginMatcher.*` + credentials | explicit origins | |
| L20 | `SecurityHeadersFilter` disabled, `play.filters.hosts.allowed = ["."]` (host header attacks) | default filters, explicit allowed hosts | |
| L21 | `Redirect(request.getQueryString("next").get)` | relative-path allow-list | |
| L22 | `Cipher.getInstance("AES")` (ECB), MD5/SHA1 passwords, static IV | AES-GCM, bcrypt/argon2 (`scala-bcrypt`) | |
| L23 | `scala.util.Random` for tokens | `java.security.SecureRandom` | |
| L24 | custom `X509TrustManager` accepting all, Play WS `ssl-config.loose.acceptAnyCertificate = true`, `disableHostnameVerification = true` | defaults | |
| L25 | `play.http.secret.key = "changeme"` committed, secrets in `application.conf`, `play.mode = Dev` in prod | `${?ENV_VAR}` substitution | |
| L26 | Play dev-mode error pages in prod, `InternalServerError(e.getMessage)` | `HttpErrorHandler` with generic output | |
| L27 | logging request bodies / `Authorization` headers, case class `toString` with secrets in logs | override `toString`, masking | |
| L28 | `.r` / `Pattern.compile` on user regex, backtracking regex on input, `parsing.max-content-length = infinite`, unbounded `Source` streams | bounded parsers, `withSizeLimit`, `take(n)` | |
| L29 | mutable `var` in actors accessed from `Future` callbacks (closing over actor state), check-then-act on DB without transactions, `Future` races on shared mutable maps | actor messages only, `TrieMap`, `Ref`/STM, DB locks | |
| L30 | `Double` money, `Int` overflow on `toInt`, negative quantities | `BigDecimal`, `Math.addExact`, refined types | |
| L31 | N/A for Scala code (JVM memory-safe); JNI / Scala Native `Ptr` / `unsafe` → `c-cpp.md` | — | |
| L32 | sbt plugins from untrusted resolvers, `resolvers += "…" at "http://…"`, SNAPSHOT/`latest.integration` versions | HTTPS resolvers, pinned versions, `sbt-dependency-lock` | SCA opt-in |
| L33 | Sangria/Caliban GraphQL without depth/complexity limits; Akka WebSocket `handleWebSocketMessages` without auth; gRPC (akka-grpc / fs2-grpc) without auth | `QueryReducer.rejectMaxDepth`, auth directives | |
| L34 | `Class.forName(user)`, Scala reflection `runtimeMirror.reflectModule(user)` | allow-list | |
| L35 | `Option.get` / `.head` on empty user input (exceptions → 500/DoS), implicit conversions hiding unsafe types, pattern matches non-exhaustive on security enums | `getOrElse`, `-Xfatal-warnings` with exhaustiveness | |
