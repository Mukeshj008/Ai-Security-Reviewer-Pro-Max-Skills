# Pack: .NET (ASP.NET Core, ASP.NET MVC/WebForms, Blazor, minimal APIs)

**Detect:** `*.csproj`, `*.sln`, `*.cs`, `*.cshtml`, `*.razor`, `*.aspx`, `web.config`, `appsettings*.json`.

## Sources

`[FromQuery]`, `[FromRoute]`, `[FromBody]`, `[FromForm]`, `[FromHeader]`, action parameters (model binding — every public settable property is bindable), `Request.Query/Form/Headers/Cookies/Body`, `HttpContext.Request`, `IFormFile`, WebForms `Request.QueryString`, `Request.Params`, ViewState, SignalR hub method args.

## XSS & views

| Vulnerable | Safe equivalent | FP trap |
|-----------|-----------------|---------|
| Razor `@Html.Raw(x)`, `new HtmlString(x)`, `MarkupString` (Blazor) | `@x` (HTML-encoded) | `@x` inside `<script>` or event attributes is HTML-encoded, **not** JS-encoded → use `JavaScriptEncoder` / JSON |
| WebForms `<%= x %>`, `Response.Write(x)`, `Label.Text = x` (Label does not encode), `Literal` with `Mode="PassThrough"` | `<%: x %>`, `HttpUtility.HtmlEncode`, `Literal Mode="Encode"` | `<%: %>` encodes |
| `ContentResult { Content = x, ContentType = "text/html" }`, `return Content(x, "text/html")` | `Json(obj)`, `Ok(obj)` | `Ok(obj)`/`Json` → JSON |
| `validateRequest="false"`, `[ValidateInput(false)]`, `requestValidationMode="2.0"` | keep request validation (defense in depth only) | Request validation is not an XSS fix — report the sink, not the setting |

## Code / expression injection

`CSharpScript.EvaluateAsync(user)`, `Roslyn` compile of user code, `DataTable.Compute(user)`, `System.Linq.Dynamic.Core` `Where(userString)` (CVE-2023-32571 RCE in < 1.3.0), Razor `RazorEngine.Compile(userTemplate)`, `Process` from config strings. `Type.GetType(user)` + `Activator.CreateInstance` → arbitrary type instantiation.

## SQL / ORM

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `new SqlCommand("… " + x)`, `$"… {x}"` passed as `string` to `SqlCommand`/`ExecuteSqlRaw`/`FromSqlRaw` | `SqlParameter`, `cmd.Parameters.AddWithValue` | |
| EF Core `FromSqlRaw($"… {x}")`, `ExecuteSqlRaw($"…")` | `FromSqlInterpolated($"… {x}")` / `FromSql($"…")` (EF 7+) — interpolation becomes parameters | `FromSqlInterpolated` with `$""` is **safe**; `FromSqlRaw` with `$""` is **not** |
| Dapper `conn.Query("… " + x)` | `conn.Query("… @id", new { id = x })` | |
| `OrderBy(userString)` via Dynamic LINQ | allow-list | |

## Command execution

`Process.Start("cmd.exe", "/c " + x)`, `ProcessStartInfo { FileName = "/bin/sh", Arguments = "-c " + x }`, `UseShellExecute = true` with user file names. `ArgumentList` collection avoids quoting bugs.

## SSRF

`HttpClient.GetAsync(user)`, `WebRequest.Create(user)` (supports `file://`), `WebClient.DownloadString(user)`, `RestSharp`, `HttpClientFactory` named client with `BaseAddress` + user absolute URI (an absolute URI **overrides** `BaseAddress`). Fix: allow-list, `SocketsHttpHandler.ConnectCallback` IP check, `AllowAutoRedirect = false`. TLS: `ServerCertificateCustomValidationCallback = (…) => true`, `ServicePointManager.ServerCertificateValidationCallback += … true`, `HttpClientHandler.DangerousAcceptAnyServerCertificateValidator`.

## Path / file / upload

`Path.Combine(base, user)` — an absolute `user` **replaces** base; `File.ReadAllText/OpenRead/Delete`, `PhysicalFile(user)`, `IFormFile.FileName` as path, `ZipFile.ExtractToDirectory` (safe in .NET Core 2.0+ for `..`; `ZipArchiveEntry.ExtractToFile` with `FullName` joined manually is not). Fix: `Path.GetFullPath(Path.Combine(base, name)).StartsWith(Path.GetFullPath(base) + Path.DirectorySeparatorChar)`, `Path.GetFileName`, `PhysicalFileProvider`.

## Deserialization

| Vulnerable | Safe |
|-----------|------|
| `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `LosFormatter`, `ObjectStateFormatter`, `JavaScriptSerializer` with `SimpleTypeResolver` | `System.Text.Json`, `DataContractSerializer` with known types |
| Json.NET `TypeNameHandling` ≠ `None` (`Auto`/`Objects`/`All`) without `SerializationBinder` | `TypeNameHandling.None` (default) |
| ViewState with `EnableViewStateMac=false` or leaked `machineKey` in `web.config` → RCE | MAC on, keys out of source |
| `XmlSerializer(Type.GetType(user))` | fixed types |

## XML

`XmlDocument` with `XmlResolver` set (default null in .NET ≥ 4.5.2), `XmlTextReader` (.NET Framework < 4.5.2 `DtdProcessing.Parse` default), `XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() }`. `XPathNavigator.Select("…" + x)` → XPath injection.

## Crypto / randomness

| Vulnerable | Safe |
|-----------|------|
| `new Random()` for tokens/OTP | `RandomNumberGenerator.GetBytes/GetInt32` |
| `MD5.Create()`, `SHA1.Create()` for passwords; `Rfc2898DeriveBytes` with low iterations / SHA1 default | `PasswordHasher<T>`, `Rfc2898DeriveBytes.Pbkdf2(…, 600000, SHA256)` |
| `DESCryptoServiceProvider`, `TripleDES`, `RC2`, `Aes` with `CipherMode.ECB`, static IV | `AesGcm` |
| `==`/`SequenceEqual` on MACs | `CryptographicOperations.FixedTimeEquals` |

## Auth / authorization / session / JWT

- Controllers/actions missing `[Authorize]` where siblings have it; `[AllowAnonymous]` on sensitive actions (`AllowAnonymous` overrides `[Authorize]` at controller level). Check for a global `AuthorizeFilter` / `FallbackPolicy` (`RequireAuthenticatedUser`) before reporting.
- Minimal APIs: `app.MapGet(...)` without `.RequireAuthorization()` and no fallback policy.
- `TokenValidationParameters { ValidateIssuerSigningKey = false, ValidateLifetime = false, ValidateIssuer = false, ValidateAudience = false, RequireSignedTokens = false, SignatureValidator = (t, p) => new JwtSecurityToken(t) }`.
- IDOR: `_db.Orders.Find(id)` without owner filter or `IAuthorizationService.AuthorizeAsync(User, order, "Owner")`.
- Over-posting: binding EF entities directly (`[Bind]` missing, `TryUpdateModelAsync` without include list).
- Cookie auth: `CookieSecurePolicy.None`, `HttpOnly = false`, `SameSiteMode.None` without need.

## CSRF / CORS / headers

- MVC POST actions without `[ValidateAntiForgeryToken]` and no global `AutoValidateAntiforgeryTokenAttribute`; `[IgnoreAntiforgeryToken]`. Razor Pages validate by default.
- `policy.AllowAnyOrigin().AllowCredentials()` (throws at runtime) vs `SetIsOriginAllowed(_ => true).AllowCredentials()` (reflection — real bug).
- `app.UseDeveloperExceptionPage()` outside `IsDevelopment()`; `customErrors mode="Off"`; `<compilation debug="true">`; missing `UseHsts`/`UseHttpsRedirection`.

## Redirect

`return Redirect(returnUrl)` → open redirect; `LocalRedirect(returnUrl)` or `Url.IsLocalUrl` is the fix.

## Logging / DoS

Logging `Request.Headers["Authorization"]`, model objects with passwords; `Regex` with user pattern or without `matchTimeout` (`RegexOptions.NonBacktracking` in .NET 7+); `[RequestSizeLimit]`/`MaxRequestBodySize` disabled (`[DisableRequestSizeLimit]`).

## Hint rg

```bash
G='--glob *.{cs,cshtml,razor,aspx,ascx,master} -g !**/bin/** -g !**/obj/**'
rg -n "Html\.Raw\s*\(|new HtmlString\s*\(|MarkupString|<%=|Response\.Write\s*\(|ValidateInput\s*\(\s*false|validateRequest" $G
rg -n "Content\s*\([^)]*text/html|ContentType\s*=\s*\"text/html" $G
rg -n "CSharpScript|DataTable\(\)\.Compute|\.Compute\s*\(|Dynamic\.Core|Activator\.CreateInstance|Type\.GetType\s*\(" $G
rg -n "new SqlCommand\s*\(|FromSqlRaw|ExecuteSqlRaw|ExecuteSqlCommand|\.Query(<[^>]+>)?\s*\(\s*(\\\$\"|\"[^\"]*\"\s*\+)" $G
rg -n "Process\.Start|ProcessStartInfo|UseShellExecute" $G
rg -n "HttpClient|WebRequest\.Create|WebClient|RestClient|GetAsync\s*\(|ServerCertificateCustomValidationCallback|ServerCertificateValidationCallback|DangerousAcceptAnyServerCertificateValidator" $G
rg -n "Path\.Combine\s*\(|File\.(ReadAll|Open|Delete|WriteAll)|PhysicalFile\s*\(|\.FileName\b|ExtractToFile|ExtractToDirectory" $G
rg -n "BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter|SimpleTypeResolver|TypeNameHandling" $G
rg -n "machineKey|EnableViewStateMac|customErrors|debug=\"true\"" --glob "*.config"
rg -n "XmlResolver|DtdProcessing\.Parse|XmlTextReader|XmlUrlResolver" $G
rg -n "new Random\s*\(|MD5\.Create|SHA1\.Create|DESCryptoServiceProvider|TripleDES|CipherMode\.ECB|Rfc2898DeriveBytes" $G
rg -n "\[AllowAnonymous\]|\[Authorize|RequireAuthorization|FallbackPolicy|AuthorizeFilter" $G
rg -n "ValidateIssuerSigningKey\s*=\s*false|ValidateLifetime\s*=\s*false|RequireSignedTokens\s*=\s*false|SignatureValidator" $G
rg -n "ValidateAntiForgeryToken|IgnoreAntiforgeryToken|AllowAnyOrigin|SetIsOriginAllowed|AllowCredentials|UseDeveloperExceptionPage" $G
rg -n "\bRedirect\s*\(|LocalRedirect|IsLocalUrl|new Regex\s*\(|DisableRequestSizeLimit" $G
rg -n "DirectorySearcher|\.Filter\s*=|XPathNavigator|SelectNodes\s*\(|SelectSingleNode\s*\(" $G
rg -n "MongoDB\.Driver|BsonDocument\.Parse|Builders<" $G
rg -n "unsafe\s*\{|fixed\s*\(|Marshal\.|DllImport|LibraryImport|stackalloc" $G
rg -n "lock\s*\(|Interlocked|IsolationLevel|RowVersion|ConcurrencyCheck" $G
rg -n "HotChocolate|GraphQL|MapHub|Hub\b|Grpc\.AspNetCore|AddGrpc" $G
```

## Class coverage index

| ID | Vulnerable in C# / .NET | Safe equivalent | FP trap / note |
|----|------------------------|-----------------|----------------|
| L01 | § XSS: `@Html.Raw`, `HtmlString`, Blazor `MarkupString`, WebForms `<%= %>`/`Response.Write`/`Label.Text`, `Content(x,"text/html")` | `@x`, `<%: %>`, `HtmlEncoder`, `Json()` | `@x` inside `<script>` needs JS encoding |
| L02 | RazorEngine / RazorLight `CompileRenderStringAsync(user)`, Scriban/Fluid templates from user input with unsafe member access | fixed templates; Fluid `TemplateOptions` member allow-list | |
| L03 | `CSharpScript.EvaluateAsync`, Roslyn compile, `DataTable.Compute`, Dynamic LINQ `Where(userString)` (<1.3.0 RCE) | no runtime compilation of input | |
| L04 | § SQL: `SqlCommand` concat, `FromSqlRaw($"…")`, `ExecuteSqlRaw`, Dapper concat | `SqlParameter`, `FromSqlInterpolated`/`FromSql`, Dapper anonymous params | `FromSqlInterpolated($"")` is safe |
| L05 | `BsonDocument.Parse(userJson)` as filter, `$where` | `Builders<T>.Filter.Eq(x => x.F, v)` | |
| L06 | `Process.Start("cmd.exe", "/c " + x)`, `UseShellExecute=true` with user file | `ProcessStartInfo.ArgumentList` | |
| L07 | `DirectorySearcher.Filter = "(uid=" + u + ")"`, `XPathNavigator.Select(concat)`, `SelectNodes(concat)` | LDAP escaping (`\2a` etc.), `XsltArgumentList`/custom `XsltContext` variables | |
| L08 | `Response.Headers.Add(name, user)` (Kestrel rejects CR/LF), log forging with `Console`/text sinks | `ILogger` structured templates `{Value}` | header splitting N/A on Kestrel |
| L09 | § SSRF: `HttpClient.GetAsync(user)` (absolute URI overrides `BaseAddress`), `WebRequest.Create` (`file://`), `WebClient` | allow-list, `ConnectCallback` IP check, `AllowAutoRedirect=false` | |
| L10 | `Path.Combine(base, user)` (absolute replaces base), `PhysicalFile(user)`, `File.*` | `GetFullPath` + `StartsWith(base + sep)`, `PhysicalFileProvider` | |
| L11 | `IFormFile.FileName` as path, `ZipArchiveEntry.FullName` joined manually, content type from client | `Path.GetFileName`, `ExtractToDirectory` (safe in .NET Core), signature check | |
| L12 | `BinaryFormatter`/`SoapFormatter`/`NetDataContractSerializer`/`LosFormatter`/`ObjectStateFormatter`, Json.NET `TypeNameHandling` ≠ None, ViewState without MAC | `System.Text.Json`, `TypeNameHandling.None` | `BinaryFormatter` is removed in .NET 9 |
| L13 | `XmlDocument` with `XmlResolver` set, `DtdProcessing.Parse` + `XmlUrlResolver`, `XmlTextReader` on .NET Framework <4.5.2 | `XmlReaderSettings { DtdProcessing = Prohibit }` | .NET Core defaults are safe |
| L14 | binding EF entities directly in actions (over-posting `IsAdmin`), `TryUpdateModelAsync` without include list | view-model DTOs, `[Bind("A,B")]` | |
| L15 | cookie auth `SecurePolicy.None`, `HttpOnly=false`, no `SignInAsync` regeneration, Identity lockout disabled (`lockoutOnFailure: false`) | defaults, lockout enabled | |
| L16 | `TokenValidationParameters` with `ValidateIssuerSigningKey/Lifetime/Issuer/Audience=false`, `RequireSignedTokens=false`, custom `SignatureValidator`; OpenIdConnect without nonce/state validation | all validations on | |
| L17 | missing `[Authorize]`, `[AllowAnonymous]` on sensitive actions, minimal APIs without `.RequireAuthorization()`, `Find(id)` without owner check | `FallbackPolicy` requiring auth, resource-based `IAuthorizationService` | global `AuthorizeFilter` covers controllers |
| L18 | MVC POST without `[ValidateAntiForgeryToken]` and no global auto-validate, `[IgnoreAntiforgeryToken]` | `AutoValidateAntiforgeryTokenAttribute` | Razor Pages validate by default |
| L19 | `SetIsOriginAllowed(_ => true).AllowCredentials()` | `WithOrigins(...)` | `AllowAnyOrigin().AllowCredentials()` throws |
| L20 | no `UseHsts`/`UseHttpsRedirection`, cookie flags off, missing CSP | middleware + `NWebsec`/custom headers | |
| L21 | `Redirect(returnUrl)` | `LocalRedirect`, `Url.IsLocalUrl` | |
| L22 | DES/3DES/RC2, `CipherMode.ECB`, MD5/SHA1 passwords, `Rfc2898DeriveBytes` low iterations | `AesGcm`, `PasswordHasher<T>` | |
| L23 | `new Random()` / `Random.Shared` for tokens | `RandomNumberGenerator` | |
| L24 | `ServerCertificateCustomValidationCallback = … => true`, `DangerousAcceptAnyServerCertificateValidator`, `ServicePointManager` callback | default validation | |
| L25 | secrets in `appsettings*.json`/`web.config`, `machineKey` committed, `<compilation debug="true">` | User Secrets / Key Vault, config transforms | `appsettings.Development.json` not loaded in prod |
| L26 | `UseDeveloperExceptionPage` outside Development, `customErrors mode="Off"`, `ProblemDetails` with exception messages | `UseExceptionHandler` | |
| L27 | logging `Authorization` headers, model objects with passwords, `EnableSensitiveDataLogging()` in EF | redaction (`Microsoft.Extensions.Compliance.Redaction`) | |
| L28 | `new Regex(user)` / no `matchTimeout`, `[DisableRequestSizeLimit]`, unbounded `Take`, `MaxRequestBodySize = null` | `RegexOptions.NonBacktracking`, limits | |
| L29 | read-modify-write without `RowVersion`/`[ConcurrencyCheck]` or transaction isolation, `async void`, static mutable state in singletons | optimistic concurrency, `Interlocked`, scoped services | |
| L30 | `double` for money, unchecked arithmetic overflow (default unchecked), client totals trusted | `decimal`, `checked { }`, server recompute | |
| L31 | `unsafe` blocks, `fixed`, `stackalloc` with user size, `Marshal.*`, P/Invoke (`DllImport`) buffers | `Span<T>` with bounds, safe wrappers; native code → `c-cpp.md` | managed C# is memory-safe |
| L32 | NuGet without lock file (`packages.lock.json`), floating versions (`1.*`), multiple feeds without source mapping (dependency confusion), MSBuild targets in packages | `RestorePackagesWithLockFile`, package source mapping | SCA opt-in |
| L33 | HotChocolate without `MaxExecutionDepth`/cost analysis, introspection on; SignalR hubs without `[Authorize]`; gRPC services without auth | limits, hub/method authorization | |
| L34 | `Type.GetType(user)` + `Activator.CreateInstance`, `MethodInfo.Invoke` by user name, `Assembly.Load(user)` | allow-list | |
| L35 | `string.Equals` without `Ordinal` (culture issues in security checks, e.g. Turkish `i`), `async void` exceptions crash process, `ToString()` of entities leaking secrets | `StringComparison.Ordinal`, `CryptographicOperations.FixedTimeEquals` | |
