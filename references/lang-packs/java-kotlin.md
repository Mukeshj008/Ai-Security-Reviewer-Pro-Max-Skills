# Pack: Java / Kotlin (Spring Boot/MVC/WebFlux, Jakarta EE/Servlets, JSP, Struts, Micronaut, Quarkus, Android backend libs)

**Detect:** `pom.xml`, `build.gradle(.kts)`, `*.java`, `*.kt`, `*.jsp`, `WEB-INF/web.xml`.
**Also read:** `../extended-category-scans.md` §19.1 (Spring), `../actuator-sensitive-endpoints-audit.md`, `../per-method-auth-audit.md`. Android apps → `../mobile-sast-audit.md`.

## Sources

`@RequestParam`, `@PathVariable`, `@RequestBody` (Jackson-bound object — every field is attacker-controlled), `@RequestHeader`, `@CookieValue`, `@ModelAttribute` (binds **any** matching field → mass assignment), `HttpServletRequest.getParameter/getHeader/getInputStream/getQueryString/getRequestURI`, `MultipartFile`, JAX-RS `@QueryParam/@PathParam/@FormParam`, Kafka `@KafkaListener` payloads, JMS messages, `ServerHttpRequest` (WebFlux).

## XSS & view templates

| Vulnerable | Safe equivalent | FP trap |
|-----------|-----------------|---------|
| JSP `<%= request.getParameter("x") %>`, JSP EL `${param.x}` / `${model.x}` in HTML body (EL is **not** escaped) | `<c:out value="${x}"/>`, `${fn:escapeXml(x)}` | `<c:out>` escapes by default (`escapeXml="false"` disables it) |
| Thymeleaf `th:utext="${x}"`, `[(${x})]` | `th:text`, `[[${x}]]` | `th:text` is escaped |
| FreeMarker `${x?no_esc}`, `<#noautoesc>`, or output format not HTML (`.ftl` without `.ftlh` / no `output_format`) | `.ftlh` templates / `HTMLOutputFormat` | Auto-escape only applies when output format is HTML |
| Velocity `$x` (no escaping by default) | `$esc.html($x)` / EscapeTool | |
| `response.getWriter().print/write(param)`; `@ResponseBody String` / `ResponseEntity<String>` with `produces = TEXT_HTML` or browser-sniffable type | return DTO → JSON; `HtmlUtils.htmlEscape`; OWASP Encoder `Encode.forHtml` | `@RestController` returning objects → `application/json`, not XSS |
| GWT/Vaadin `HTML` widgets with user strings | | |

## SSTI / EL / OGNL / script

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `new SpelExpressionParser().parseExpression(user).getValue(new StandardEvaluationContext())` | `SimpleEvaluationContext.forReadOnlyDataBinding()`; never parse user expressions | Fixed expression strings in `@Value`/`@PreAuthorize` are safe |
| `ExpressionFactory.createValueExpression(user)` (javax/jakarta EL), Struts OGNL from params | | |
| Thymeleaf view name from input: `return "user/" + request.getParameter("view")` (`__${…}__` preprocessing → SpEL RCE) | fixed view names; `@ResponseBody` | |
| FreeMarker `new Template(name, userString, cfg)`, Velocity `evaluate(user)`, `?new()` builtin allowed | `TemplateClassResolver.SAFER_RESOLVER` | |
| `ScriptEngineManager.getEngineByName("js").eval(user)`, Groovy `GroovyShell.evaluate(user)` | | |
| Log4j 2 < 2.17 `${jndi:…}` in logged input (CWE-917) | upgrade / `log4j2.formatMsgNoLookups` | CVE-override rule: never suppress if the logged value is user input |

## SQL / JPA / HQL

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `Statement.executeQuery("… " + x)`, `JdbcTemplate.query("…" + x)` | `PreparedStatement` + `setString`, `JdbcTemplate.query("… ?", args)`, `NamedParameterJdbcTemplate` | `PreparedStatement` built **from** a concatenated string is still SQLi |
| JPA `em.createQuery("… " + x)` (JPQL/HQL injection), `createNativeQuery("…" + x)` | `:param` + `setParameter` | Spring Data derived methods (`findByEmail`) are safe |
| `@Query("… #{…} …")` SpEL with user input, `@Query(nativeQuery=true, value="… ?#{[0]}")` | `:param` binding | |
| `ORDER BY` from `Sort.by(userField)` → Spring Data validates property names for JPA but **not** for native queries / `JpaSort.unsafe` | allow-list | |
| MyBatis `${x}` in mapper XML/annotations | `#{x}` | `#{}` is bound |
| jOOQ `DSL.field(userString)`, `DSL.condition(userString)` | typed fields, `DSL.val(x)` | |

## NoSQL / LDAP / XPath

- Spring Data Mongo `new BasicQuery(userJson)`, `mongoTemplate.find(new Query(Criteria.where(field)…))` with user field names, `$where`.
- LDAP: `ctx.search(base, "(uid=" + user + ")", …)` → LDAP injection; fix with `LdapEncoder.filterEncode` / Spring LDAP `LdapQueryBuilder`. JMESPath `.search()` is **not** LDAP (`../precision-false-positive-adjudication.md` LDAP-ADJ-01).
- XPath: `xpath.compile("//user[@name='" + x + "']")` → use `XPathVariableResolver`.

## Command execution

`Runtime.getRuntime().exec(String)` (tokenized, no shell — injection only if the string starts a shell or args are attacker-controlled), `exec(new String[]{"sh","-c", x})`, `ProcessBuilder("bash","-c", x)`. `ProcessBuilder(List.of(bin, userArg))` → option injection only.

## SSRF

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `new URL(user).openConnection()`, `RestTemplate.getForObject(userUrl)`, `WebClient.create(userUrl)`, `HttpClient.send(HttpRequest.newBuilder(URI.create(user)))`, OkHttp, Apache HttpClient, Feign `@Url URI` param, `ImageIO.read(new URL(user))` | allow-list host + scheme; block private IPs after resolution; disable redirects | `UriComponentsBuilder.fromHttpUrl(configBase).path(fixed).queryParam("q", user)` → query control only (SSRF-ADJ-01 G3) |
| `UriComponentsBuilder.fromHttpUrl(user)` / `.host(user)` | | `.path(user)` on config base: check `..`/`//` handling |
| `java.net.URL` supports `file:`, `jar:`, `netdoc:` | block schemes | |

TLS: `TrustAllStrategy`, `NoopHostnameVerifier`, custom `X509TrustManager` with empty `checkServerTrusted`, `HttpsURLConnection.setDefaultHostnameVerifier((h,s)->true)`, `SSLContext` with trust-all, `InsecureTrustManagerFactory` (Netty).

## Path / file / upload

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `new File(base, user)`, `Paths.get(base, user)`, `Path.resolve(user)` then read/write | `base.resolve(user).normalize().startsWith(base)` (after `toRealPath` for symlinks) | `normalize()` without `startsWith` check is not a fix |
| `MultipartFile.getOriginalFilename()` used as path; `transferTo(new File(dir + name))` | `FilenameUtils.getName` + generated name; content-type sniffing | |
| `ZipInputStream` / `ZipFile` entries written to `new File(dest, entry.getName())` (Zip Slip) | canonical path check per entry | |
| `ResourceLoader.getResource(user)` (`file:`, `classpath:`, `url:` prefixes) | | |
| Spring static resource mapping to filesystem dirs with user paths | | |

## Deserialization

| Vulnerable | Safe |
|-----------|------|
| `ObjectInputStream.readObject()` on network/cookie/queue/DB bytes | JSON DTOs; `ObjectInputFilter` allow-list (JEP 290) |
| Jackson `enableDefaultTyping()`, `activateDefaultTyping(…, NON_FINAL/EVERYTHING)`, `@JsonTypeInfo(use = Id.CLASS / MINIMAL_CLASS)` on fields of type `Object`/`Serializable` | `Id.NAME` + `@JsonSubTypes`; `PolymorphicTypeValidator` allow-list |
| Spring Kafka `spring.json.trusted.packages: "*"` with type headers | explicit packages, `USE_TYPE_INFO_HEADERS=false` |
| XStream `fromXML(user)` without allow-list, `XMLDecoder.readObject`, SnakeYAML `new Yaml().load(user)` (< 2.0 default constructor) | XStream `allowTypes`; SnakeYAML `SafeConstructor` / 2.x |
| Hessian/Kryo/Fastjson `autoType` | |
| Apache Commons `SerializationUtils.deserialize`, RMI/JMX exposed | |

## XML

`DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory`, `XMLReader`, `SAXBuilder` (JDOM), `SAXReader` (dom4j), JAXB `Unmarshaller` over a raw stream — vulnerable unless the exact parser instance has complete parser-specific hardening. `FEATURE_SECURE_PROCESSING` alone is not sufficient proof. Check the factory config **at the point of use**. Also trace string/template concatenation into XML/SOAP markup, element or attribute names, CDATA, namespaces, XPath, and XSLT; prefer fixed-name DOM/builders/serializers with escaped values. SAML/XML-DSig: signature verified on a different node than the one consumed (signature wrapping). Run `../xml-security-audit.md`.

## Crypto / randomness

| Vulnerable | Safe |
|-----------|------|
| `new Random()` / `Math.random()` / `ThreadLocalRandom` for tokens, OTP | `SecureRandom` |
| `MessageDigest.getInstance("MD5"/"SHA-1")` for passwords/signatures | `BCryptPasswordEncoder`, `Argon2PasswordEncoder`; HMAC-SHA256 |
| `Cipher.getInstance("AES")` (defaults to **ECB**), `"DES"`, `"DESede"`, `"AES/ECB/…"`, `"RC4"`, static `IvParameterSpec(new byte[16])` | `"AES/GCM/NoPadding"` + random 12-byte IV |
| `KeyPairGenerator` RSA < 2048 | ≥ 2048 |
| `String.equals` on MAC/tokens | `MessageDigest.isEqual` |
| `NoOpPasswordEncoder`, `{noop}` passwords | delegating encoder with bcrypt |

## Auth / authorization / session / JWT

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `SecurityFilterChain` with `.anyRequest().permitAll()`, overly broad `requestMatchers("/api/**").permitAll()`, `WebSecurityCustomizer.ignoring()` on API paths | explicit matchers, `authenticated()` default | Method security (`@PreAuthorize`) can still protect — verify `@EnableMethodSecurity` is on |
| Controller methods without `@PreAuthorize` where siblings have it (per-method walk) | | Class-level annotation covers all methods |
| `mvcMatchers` vs `antMatchers` path mismatch (`/admin` vs `/admin/` vs `/admin.json` suffix match in older Spring) | `requestMatchers` (Spring Security 6) | |
| Trusting `@RequestHeader("X-User-Id")` / `uid` header for identity | principal from token | Gateway-injected headers are safe **only** if the service is unreachable except via the gateway — needs evidence |
| JJWT `parse()` / `parseClaimsJwt` (unsigned) instead of `parseClaimsJws`; `Jwts.parser()` without `setSigningKey`; Auth0 `JWT.decode` used for authz | `parseSignedClaims` with key; `JWT.require(alg).withIssuer().build().verify()` | |
| Session fixation: `sessionManagement().sessionFixation().none()` | default `migrateSession` | |
| `@ModelAttribute`/`@RequestBody` entity binding (mass assignment of `role`, `owner`, `balance`) | DTOs; `@InitBinder setAllowedFields` | |

## CSRF / CORS / headers

- `http.csrf().disable()` / `csrf(c -> c.disable())` with session-cookie auth → CSRF. Stateless bearer-token APIs: not CSRF.
- `@CrossOrigin(origins = "*", allowCredentials = "true")` (rejected at runtime in Spring 5.3+, but `allowedOriginPatterns("*")` + credentials is allowed → reflection), `CorsConfiguration.addAllowedOriginPattern("*")`.
- `headers().frameOptions().disable()`, `contentSecurityPolicy` absent, `server.servlet.session.cookie.secure=false`, `http-only=false`.
- Actuator `management.endpoints.web.exposure.include=*`, `/heapdump`, `/env`, `/jolokia` exposed without auth.

## Redirect / header injection

`return "redirect:" + param`, `response.sendRedirect(param)` → open redirect; `response.setHeader(name, user)` — Tomcat rejects CR/LF in recent versions; older containers allow splitting.

## Logging / errors

`server.error.include-stacktrace=always`, `include-message=always`; `e.printStackTrace()` to response; logging `request.getParameterMap()`, passwords, `Authorization` header; Log4Shell (above).

## DoS

`Pattern.compile(user)`; regexes with nested quantifiers on input; `spring.servlet.multipart.max-file-size=-1`; unbounded `Pageable` size (`spring.data.web.pageable.max-page-size` unset); XML entity expansion (see XML).

## Hint rg

```bash
G='--glob *.{java,kt} -g !**/target/** -g !**/build/**'
rg -n "<%=|\\\$\{param\.|escapeXml\s*=\s*['\"]false|th:utext|\[\(\\\$\{|\?no_esc|noautoesc" --glob "*.{jsp,jspx,tag,html,ftl,ftlh,vm}"
rg -n "getWriter\(\)\.(print|write|println)|produces\s*=\s*.*TEXT_HTML|ResponseEntity<String>" $G
rg -n "SpelExpressionParser|StandardEvaluationContext|parseExpression|createValueExpression|ScriptEngineManager|GroovyShell|OgnlUtil" $G
rg -n "return\s+\"(redirect:|forward:)?[^\"]*\"\s*\+|sendRedirect\s*\(" $G
rg -n "(executeQuery|executeUpdate|execute|createQuery|createNativeQuery|prepareStatement|query|queryForList|update)\s*\(\s*\"[^\"]*\"\s*\+" $G
rg -n -i "\"[^\"]*\b(select|insert|update|delete|where|order by)\b[^\"]*\"\s*\+|String\.format\s*\(\s*\"[^\"]*\b(select|where)\b|\"\"\"[^\"]*\\\$\{" $G   # SQL built in a variable / Kotlin template
rg -n "\\\$\{[a-zA-Z_.]+\}" --glob "**/*Mapper*.xml" --glob "**/mapper/**/*.xml"
rg -n "@Query\s*\(.*(#\{|\+)|JpaSort\.unsafe|DSL\.(field|condition)\s*\(" $G
rg -n "new BasicQuery\s*\(|\.search\s*\([^)]*\"\s*\+|xpath\.(compile|evaluate)\s*\([^)]*\+" $G
rg -n "Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(" $G
rg -n "new URL\s*\(|openConnection\s*\(|RestTemplate|WebClient|HttpRequest\.newBuilder|OkHttpClient|@FeignClient|fromHttpUrl|ImageIO\.read" $G
rg -n "TrustAllStrategy|NoopHostnameVerifier|InsecureTrustManagerFactory|checkServerTrusted|setDefaultHostnameVerifier" $G
rg -n "getOriginalFilename|transferTo\s*\(|new File\s*\([^)]*,|Paths\.get\s*\(|ZipEntry|getNextEntry|getResource\s*\(" $G
rg -n "ObjectInputStream|readObject\s*\(|enableDefaultTyping|activateDefaultTyping|JsonTypeInfo|XStream|XMLDecoder|new Yaml\s*\(|SerializationUtils\.deserialize|autoType" $G
rg -n "trusted\.packages" --glob "*.{yml,yaml,properties}"
rg -n "DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|SAXBuilder|SAXReader|disallow-doctype-decl" $G
rg -n "new Random\s*\(|Math\.random|getInstance\s*\(\s*\"(MD5|SHA-?1|DES|DESede|AES|RC4|AES/ECB[^\"]*)\"|IvParameterSpec\s*\(\s*new byte|NoOpPasswordEncoder|\{noop\}" $G
rg -n "permitAll\s*\(|anyRequest\(\)|ignoring\(\)|csrf\s*\(.*disable|frameOptions\(\)\.disable|sessionFixation\(\)\.none|@PreAuthorize|@Secured|@RolesAllowed" $G
rg -n "@CrossOrigin|allowedOriginPatterns|addAllowedOriginPattern|setAllowCredentials\s*\(\s*true" $G
rg -n "getHeader\s*\(\s*\"(uid|userId|X-User|X-Tenant|customerId)|@RequestHeader\s*\(\s*\"(uid|userId|X-User)" -i $G
rg -n "parseClaimsJwt|Jwts\.parser\(\)|JWT\.decode\s*\(|\.parse\s*\(\s*token" $G
rg -n "include-stacktrace|include-message|exposure\.include|ddl-auto|h2\.console" --glob "*.{yml,yaml,properties}"
rg -n "printStackTrace|Pattern\.compile\s*\([^\"]" $G
rg -n "Class\.forName\s*\(|getMethod\s*\(|\.invoke\s*\(|newInstance\s*\(|URLClassLoader" $G
rg -n "synchronized|@Transactional|@Lock|LockModeType|@Version|ConcurrentHashMap" $G
rg -n "sun\.misc\.Unsafe|native\s+\w+\s*\(|System\.loadLibrary|ByteBuffer\.allocateDirect" $G
rg -n "@QueryMapping|@MutationMapping|GraphQL|@MessageMapping|WebSocketHandler|@GrpcService|introspection" $G
```

## Class coverage index

| ID | Vulnerable in Java / Kotlin | Safe equivalent | FP trap / note |
|----|----------------------------|-----------------|----------------|
| L01 | § XSS: JSP `<%= %>`/`${}`, Thymeleaf `th:utext`/`[( )]`, FreeMarker `?no_esc`/non-HTML output format, Velocity `$x`, `getWriter().print(param)` | `<c:out>`, `th:text`, `.ftlh`, `Encode.forHtml`, DTO → JSON | `@RestController` objects → JSON |
| L02 | § SSTI/EL: SpEL `parseExpression(user)` + `StandardEvaluationContext`, Thymeleaf view name from input (`__${}__`), FreeMarker `new Template(user)`/`?new`, Velocity `evaluate` | `SimpleEvaluationContext`, fixed view names, `SAFER_RESOLVER` | constant `@PreAuthorize` SpEL is fine |
| L03 | `ScriptEngine.eval(user)`, `GroovyShell.evaluate`, Nashorn/GraalJS with user code, Kotlin `ScriptEngine` | no dynamic eval | |
| L04 | § SQL: `Statement` concat, JPQL/HQL concat, `@Query` SpEL, `JpaSort.unsafe`, MyBatis `${}`, jOOQ `DSL.field(user)`, Kotlin string templates `"… $x"` in SQL | `PreparedStatement`, `:param`, `#{}`, derived queries | Spring Data derived methods are bound |
| L05 | `new BasicQuery(userJson)`, `Criteria.where(userField)`, `$where` | typed `Criteria` with fixed fields | |
| L06 | `Runtime.exec(String)` with shell, `ProcessBuilder("sh","-c",x)` | `ProcessBuilder(List)` without shell | `exec(String)` tokenizes, no shell by default |
| L07 | LDAP filter concat, XPath concat, javax/jakarta EL `createValueExpression(user)`, OGNL (Struts) | `LdapEncoder.filterEncode`, `XPathVariableResolver` | JMESPath is not LDAP (LDAP-ADJ-01) |
| L08 | `response.setHeader(name, user)` on old containers (CRLF), `Content-Disposition` filename injection; log forging via `log.info("user=" + input)` with text layout | `ContentDisposition.builder().filename()`, CR/LF stripping, JSON layout | Tomcat ≥8.5 rejects CR/LF in headers |
| L09 | § SSRF: `new URL(user)`, RestTemplate/WebClient/HttpClient/OkHttp/Feign `@Url`, `ImageIO.read(URL)`, `fromHttpUrl(user)` | host allow-list, IP check, no redirects | `.path()/.queryParam()` on config base = adjacent |
| L10 | `new File(base, user)`, `Paths.get(base,user)`, `ResourceLoader.getResource(user)` | `normalize().startsWith(base)` after `toRealPath` | |
| L11 | `getOriginalFilename()` as path, Zip Slip in `ZipInputStream`, content type from client | `FilenameUtils.getName`, canonical check per entry, Tika detection | |
| L12 | `ObjectInputStream.readObject`, Jackson default typing / `@JsonTypeInfo(Id.CLASS)`, XStream, XMLDecoder, SnakeYAML <2 `load`, Kryo/Hessian/Fastjson autoType, Kafka `trusted.packages=*` | JSON DTOs, `ObjectInputFilter`, `PolymorphicTypeValidator`, `SafeConstructor` | |
| L13 | unhardened XML factories/JAXB raw stream; concatenation into XML/SOAP markup or dynamic names; string-built XPath/XSLT; XML signature wrapping | complete parser-specific DTD/entity/external-access controls; fixed-name builder/serializer with escaped values; XPath variables | `FEATURE_SECURE_PROCESSING` alone is insufficient; JAXB from a hardened `Source` is fine |
| L14 | `@ModelAttribute`/`@RequestBody` binding JPA entities (`role`, `owner`), Spring4Shell-style class-loader binding on old Spring + JDK9 | DTOs, `@InitBinder setAllowedFields` | |
| L15 | `permitAll()` too broad, session fixation disabled, remember-me with static key, `NoOpPasswordEncoder` | `authenticated()` default, bcrypt encoder | method security may still protect |
| L16 | JJWT `parseClaimsJwt`/no key, Auth0 `JWT.decode` for authz, Nimbus without alg check, SAML signature on wrong element (wrapping), OAuth redirect-URI prefix match | `parseSignedClaims(key)`, `JWT.require(alg)…verify`, exact redirect match | |
| L17 | controller methods missing `@PreAuthorize` vs siblings, `findById(id)` without owner, trusting `X-User-Id` header, `mvcMatchers`/`antMatchers` path mismatch | per-method annotations, owner filter, principal from token | gateway-injected headers need evidence of non-reachability |
| L18 | `csrf().disable()` with session auth | default CSRF, `CookieCsrfTokenRepository` | stateless bearer APIs not CSRF-prone |
| L19 | `allowedOriginPatterns("*")` + credentials, `@CrossOrigin(origins="*")` | explicit origins | `*` + credentials is rejected at runtime in Spring ≥5.3 |
| L20 | `frameOptions().disable()`, cookie `secure/http-only=false`, no HSTS | Spring Security defaults | |
| L21 | `"redirect:" + param`, `sendRedirect(param)` | allow-list / relative paths only | |
| L22 | `Cipher.getInstance("AES")` (ECB default), DES/3DES/RC4, static IV, MD5/SHA1 passwords, RSA <2048 | `AES/GCM/NoPadding`, bcrypt/argon2 | |
| L23 | `new Random()`, `Math.random()`, `ThreadLocalRandom` for secrets; Kotlin `Random.Default` | `SecureRandom` | |
| L24 | trust-all `X509TrustManager`, `NoopHostnameVerifier`, `TrustAllStrategy`, `InsecureTrustManagerFactory` | default trust store, pinned CA | test-only clients |
| L25 | secrets in `application*.yml/properties`, Actuator `exposure.include=*`, `h2.console.enabled`, `ddl-auto=create` in prod | env/vault, minimal exposure | profile files not active in prod |
| L26 | `include-stacktrace=always`, `printStackTrace` to response, Whitelabel errors with messages | `include-message=never`, `@ControllerAdvice` | |
| L27 | logging `getParameterMap()`, `Authorization` headers, PII in MDC; Log4Shell (<2.17) with user input | masking layouts, upgrade | |
| L28 | `Pattern.compile(user)`, backtracking regex on input (Java regex backtracks), unbounded `Pageable`, `max-file-size=-1`, XML bombs | bounded regex/input, `max-page-size` | |
| L29 | check-then-act on balances without `@Lock(PESSIMISTIC_WRITE)`/`@Version`; `@Transactional` self-invocation (proxy bypass → no transaction); non-thread-safe singletons (`SimpleDateFormat`, mutable fields in `@Service`) | locking, atomic UPDATE, immutable beans | |
| L30 | `double` for money, `Integer.parseInt` overflow, negative quantities, client totals trusted | `BigDecimal`, `Math.addExact`, server recompute | |
| L31 | JNI (`native`, `System.loadLibrary` → `c-cpp.md`), `sun.misc.Unsafe`, `ByteBuffer.allocateDirect` misuse | — | managed Java/Kotlin is memory-safe |
| L32 | unpinned/`LATEST` Maven versions, HTTP repositories, Gradle plugins from untrusted repos, dependency confusion via mixed internal/public repos | pinned versions, HTTPS repos, dependency verification (`verification-metadata.xml`) | SCA opt-in (`../maven-sca-scan.md`) |
| L33 | Spring GraphQL without depth/complexity limits or field auth; STOMP `@MessageMapping` without auth/destination checks; gRPC services without `ServerInterceptor` auth, reflection service on | instrumentation limits, `@PreAuthorize` on resolvers, interceptors | |
| L34 | `Class.forName(user)`, `getMethod(user).invoke`, `URLClassLoader` with user URL, Spring `BeanWrapper` property paths from input | allow-list | |
| L35 | `==` on `String` (identity) in auth checks; Kotlin `!!` NPE DoS; `Optional.get()`; `equals` timing for secrets (`MessageDigest.isEqual`); Kotlin data class `copy()` exposing fields; Lombok `@Data` `toString` leaking secrets in logs | `.equals`, `isEqual`, `@ToString.Exclude` | |
