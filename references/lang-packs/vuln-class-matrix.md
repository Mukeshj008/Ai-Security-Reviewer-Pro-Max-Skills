# Vulnerability class × language matrix (generated — do not edit)

Regenerate with `python3 scripts/check_lang_packs.py --write-matrix`. Source of truth: each pack's
`## Class coverage index`. Use this file to compare how one class looks across languages; use the
pack itself when reviewing a file.

## L01 — XSS / output encoding

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | CGI / embedded web servers (`mongoose`, `civetweb`, Crow, Drogon, cpp-httplib) writing `printf("<p>%s</p>", query)` / `res.body = "<p>" + param` with `text/html` | HTML-encode helper, template engine with escaping (Inja/Crow mustache `{{ }}`) | Crow mustache `{{{ }}}` is raw |
| `dotnet.md` | § XSS: `@Html.Raw`, `HtmlString`, Blazor `MarkupString`, WebForms `<%= %>`/`Response.Write`/`Label.Text`, `Content(x,"text/html")` | `@x`, `<%: %>`, `HtmlEncoder`, `Json()` | `@x` inside `<script>` needs JS encoding |
| `elixir.md` | `raw(x)`, `{:safe, x}`, `html(conn, "<p>#{x}</p>")`, `send_resp(conn, 200, "<…#{x}…>")` with HTML content type | HEEx `<%= x %>` / `{x}`, `json(conn, map)` | HEEx escapes by default |
| `frontend-browser.md` | § XSS sinks: `dangerouslySetInnerHTML`, `v-html`, `{@html}`, `bypassSecurityTrust*`, `innerHTML`, jQuery `.html()`/`$(str)`, `href={x}` `javascript:` | JSX/`{{ }}` text, `DOMPurify`, `textContent`, scheme allow-list | Angular `[innerHTML]` is sanitized |
| `go.md` | § XSS: `text/template` for HTML, `template.HTML/JS/URL(user)`, `fmt.Fprintf(w, "<p>%s", x)`, `c.Data(…"text/html"…)` | `html/template`, `html.EscapeString`, `c.JSON` | check the import, not the call name |
| `iac-ci.md` | nginx `add_header` missing CSP; `sub_filter` injecting user-controlled content; static error pages echoing `$request_uri` | CSP header at edge | XSS lives in app packs |
| `java-kotlin.md` | § XSS: JSP `<%= %>`/`${}`, Thymeleaf `th:utext`/`[( )]`, FreeMarker `?no_esc`/non-HTML output format, Velocity `$x`, `getWriter().print(param)` | `<c:out>`, `th:text`, `.ftlh`, `Encode.forHtml`, DTO → JSON | `@RestController` objects → JSON |
| `javascript-node.md` | § XSS: `res.send(str)` HTML, EJS `<%-`, Pug `!{}`, HBS `{{{ }}}` | `res.json`, escaped template tags | `res.send(obj)` is JSON |
| `mobile-native.md` | WebView XSS: `loadHTMLString(user)`, `loadData(user, "text/html")`, `evaluateJavaScript("show('\(x)')")`, RN `injectJavaScript(\`…${x}\`)`, Flutter `runJavaScript("…$x")` | pass data via `postMessage`/JSON-encoded args, sanitize HTML | native `UILabel`/`TextView`/`Text` widgets are not XSS |
| `other-languages.md` | Perl CGI `print "<p>$q</p>"` · `ngx.say("<p>"..arg.."</p>")` · GSP `${x}` with `default.codec=none`, `<%= %>`, `raw()` · Solidity — (frontend dApp → `frontend-browser.md`) | `HTML::Entities::encode_entities` · `ngx.escape_uri`/HTML encoder · `codec=html`, `${x.encodeAsHTML()}` | Grails ≥2.3 defaults to HTML codec |
| `php.md` | § XSS: `echo`/`<?=`/`print` of input, Blade `{!! !!}`, Twig ` | raw`, `$_SERVER['PHP_SELF']`, WordPress output without `esc_*` | `htmlspecialchars($x, ENT_QUOTES, 'UTF-8')`, `{{ }}`, `esc_html/esc_attr/esc_url` |
| `python.md` | § XSS: ` | safe`, `mark_safe`, `Markup(user)`, `Environment()` without autoescape, `return f"<p>{x}"`, `HTMLResponse(f"...")` | autoescape, `format_html`, `escape` |
| `ruby.md` | § XSS: `raw`, `html_safe`, `<%==`, HAML `!=`, `render html:`/`inline:`, `link_to` with `javascript:` | `<%= %>` (Rails escapes), `sanitize` default allow-list | plain `ERB.new` outside Rails doesn't escape |
| `rust.md` | § XSS: `Html(format!(…user…))`, `content_type("text/html").body(format!)`, Tera/Askama ` | safe`, autoescape disabled | Askama/Maud/Tera auto-escape, `html_escape` |
| `scala.md` | Twirl `@Html(userValue)`, `Ok(s"<p>$x</p>").as(HTML)`, Akka `HttpEntity(ContentTypes.\`text/html(UTF-8)\`, s"…$x")` | Twirl `@value`, `Ok(Json.toJson(x))` | Twirl `@x` escapes by default |
| `shell.md` | CGI scripts `echo "<p>$QUERY_STRING</p>"`; scripts generating HTML reports from untrusted data | HTML-encode (`sed 's/&/\&amp;/g; s/</\&lt;/g…'`), generate reports in a real language |  |

## L02 — SSTI / template injection

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | Inja/mustache templates compiled from user strings (`env.render(user_tpl, data)`) | fixed templates |  |
| `dotnet.md` | RazorEngine / RazorLight `CompileRenderStringAsync(user)`, Scriban/Fluid templates from user input with unsafe member access | fixed templates; Fluid `TemplateOptions` member allow-list |  |
| `elixir.md` | `EEx.eval_string(user_template, assigns)`, Solid/Liquid with unsafe custom filters | compile-time templates (`~H`) | `~H` sigils are compiled |
| `frontend-browser.md` | client-side template injection: Vue `template: userString`, AngularJS (1.x) `{{ }}` in server-rendered HTML with user input (`{{constructor.constructor('…')()}}`), `ng-bind-html` + `$sce.trustAsHtml` | compile only static templates; `ng-non-bindable` around user content | Angular 2+ templates are AOT-compiled — not injectable at runtime |
| `go.md` | `template.New("").Parse(userString)` (text or html) — exposes methods on data objects | parse only constant templates | constant template + user data is fine |
| `iac-ci.md` | Ansible/Jinja templates rendering **untrusted** variables into config (`{{ user_var }}` in nginx conf → config injection); Helm `tpl` on user values | quote/validate vars, avoid `tpl` on untrusted values | operator-controlled vars are trusted |
| `java-kotlin.md` | § SSTI/EL: SpEL `parseExpression(user)` + `StandardEvaluationContext`, Thymeleaf view name from input (`__${}__`), FreeMarker `new Template(user)`/`?new`, Velocity `evaluate` | `SimpleEvaluationContext`, fixed view names, `SAFER_RESOLVER` | constant `@PreAuthorize` SpEL is fine |
| `javascript-node.md` | § SSTI: `ejs.render(userTpl)`, `pug.compile(user)`, `_.template(user)` | fixed templates, user data as context | EJS `<%= %>` in fixed template is not SSTI |
| `mobile-native.md` | server-driven UI templates compiled on device from untrusted sources | signed configs |  |
| `other-languages.md` | Template Toolkit / HTML::Template with user templates · `lua-resty-template` compiling user strings · `SimpleTemplateEngine().createTemplate(user)` · — | fixed templates |  |
| `php.md` | Twig `createTemplate($user)`, `Blade::render($user)`, Smarty `fetch('string:'.$user)` / `{php}` | fixed templates, Twig sandbox extension |  |
| `python.md` | § SSTI: `render_template_string(user)`, `Template(user)`, `from_string(user)`, Mako `Template(user)` | fixed templates; `SandboxedEnvironment` (still risky) | fixed template + context is not SSTI |
| `ruby.md` | `ERB.new(user).result`, `render inline: params[:x]`, Liquid with custom unsafe filters, Slim/HAML compiled from user strings | fixed templates; Liquid (safe by design) | Liquid templates from users are acceptable |
| `rust.md` | `Tera::one_off(user_template, …)`, `tera.add_raw_template(name, user)`, Handlebars `render_template(user)` | compile-time templates (Askama) | Askama templates are compiled — not injectable |
| `scala.md` | Twirl is compiled (not injectable); risk is Scalate/Mustache/Handlebars templates compiled from user strings | compile-time Twirl |  |
| `shell.md` | `envsubst` / `eval "cat <<EOF … EOF"` on untrusted template files (heredoc with `$(…)` executes) | quoted heredoc `<<'EOF'`, `envsubst '$ALLOWED'` with explicit var list |  |

## L03 — Code injection / eval / dynamic load

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | `dlopen(user_path)`, `system()` of user-built scripts, embedded Lua/Python interpreters running user code | allow-listed plugin paths |  |
| `dotnet.md` | `CSharpScript.EvaluateAsync`, Roslyn compile, `DataTable.Compute`, Dynamic LINQ `Where(userString)` (<1.3.0 RCE) | no runtime compilation of input |  |
| `elixir.md` | `Code.eval_string/eval_quoted(user)`, `apply(String.to_atom(mod), String.to_atom(fun), args)` | dispatch map |  |
| `frontend-browser.md` | `eval`, `new Function`, `setTimeout(string)`, `script.src = userUrl`, dynamic `import(user)` | static imports, JSON |  |
| `go.md` | `plugin.Open(user)`, `yaegi`/`goja`/`otto` interpreters with user code, `go:generate` N/A at runtime | no runtime eval | Go has no `eval` |
| `iac-ci.md` | CI `run:` with `${{ github.event.* }}` (script injection), Jenkins `evaluate()`, Groovy interpolation | env indirection, quoted vars |  |
| `java-kotlin.md` | `ScriptEngine.eval(user)`, `GroovyShell.evaluate`, Nashorn/GraalJS with user code, Kotlin `ScriptEngine` | no dynamic eval |  |
| `javascript-node.md` | `eval`, `new Function`, `vm.run*` (not a sandbox), `vm2` (abandoned, escapes), `require(user)`, `import(user)` | lookup map of allowed modules | `JSON.parse` is not eval |
| `mobile-native.md` | `addJavascriptInterface` + untrusted pages, `DexClassLoader`/`PathClassLoader` loading downloaded code, JSContext (`JavaScriptCore`) evaluating remote scripts, RN CodePush from unverified source | no JS bridges for untrusted origins, signed updates |  |
| `other-languages.md` | `eval $str`, `(?{ })` with `use re 'eval'` · `loadstring/load(user)` · `Eval.me`, `GroovyShell.evaluate` · `delegatecall` to user address | no runtime eval · sandboxed env tables · allow-listed addresses | Perl `eval { }` block is safe |
| `php.md` | `eval`, `assert($str)` (<8), `create_function`, `preg_replace /e` (<7), `call_user_func($user)`, `$func()`, `include($user)` | allow-listed callables |  |
| `python.md` | `eval`, `exec`, `compile`, `__import__(user)`, `importlib.import_module(user)`, `str.format` with user format string on objects | `ast.literal_eval`, dispatch dict | `literal_eval` is safe |
| `ruby.md` | `eval`, `instance_eval`, `class_eval`, `send(params[:m])`, `Kernel#open(" | cmd")` | `public_send` with allow-list |
| `rust.md` | embedded interpreters (`rhai`, `mlua`, `deno_core`, `boa`) running user scripts; `libloading` with user path | sandboxed engine config, no user code | Rust has no `eval` |
| `scala.md` | `scala.tools.reflect.ToolBox.eval`, `IMain`/REPL interpreter, `ScriptEngine` with user code | no runtime eval |  |
| `shell.md` | `eval "$x"`, `source "$userfile"`, PowerShell `iex`, `[ScriptBlock]::Create($x)`, `Add-Type -TypeDefinition $user` | case/allow-list dispatch |  |

## L04 — SQL injection

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | `sqlite3_exec(db, sprintf(...user...))`, `mysql_query` with concatenated `std::string`, libpq `PQexec` | `sqlite3_prepare_v2` + `sqlite3_bind_*`, `PQexecParams`, `mysql_stmt_*` |  |
| `dotnet.md` | § SQL: `SqlCommand` concat, `FromSqlRaw($"…")`, `ExecuteSqlRaw`, Dapper concat | `SqlParameter`, `FromSqlInterpolated`/`FromSql`, Dapper anonymous params | `FromSqlInterpolated($"")` is safe |
| `elixir.md` | `Ecto.Adapters.SQL.query(Repo, "… #{x}")`, `Repo.query("… #{x}")` | `Repo.query("… $1", [x])`, Ecto query bindings `^x` | `fragment` requires compile-time literal |
| `frontend-browser.md` | N/A in browser — SQL runs server-side; report in backend pack. Exception: `sql.js`/WebSQL with string concat on local data (low) | backend pack |  |
| `go.md` | § SQL: `fmt.Sprintf`/`+` into `Query/Exec`, GORM `Raw(Sprintf)`, `Where(userString)`, `Order(user)` | `$1`/`?` placeholders, `Where("x = ?", v)`, allow-listed order | `Where(&Struct{})` is bound |
| `iac-ci.md` | N/A in IaC; DB init scripts with templated SQL from pipeline params | parameterized migrations |  |
| `java-kotlin.md` | § SQL: `Statement` concat, JPQL/HQL concat, `@Query` SpEL, `JpaSort.unsafe`, MyBatis `${}`, jOOQ `DSL.field(user)`, Kotlin string templates `"… $x"` in SQL | `PreparedStatement`, `:param`, `#{}`, derived queries | Spring Data derived methods are bound |
| `javascript-node.md` | § SQL/ORM: template-string SQL, `Sequelize.literal`, `knex.raw`, `$queryRawUnsafe`, `ORDER BY ${col}` | placeholders / `replacements` / tagged `$queryRaw` | Sequelize `where: {id}` is bound |
| `mobile-native.md` | Android `rawQuery("… " + x)`/`execSQL`, ContentProvider `query()` concatenating `selection`; iOS `sqlite3_exec` with `stringWithFormat`; Flutter `sqflite` `rawQuery('… $x')` | `?` + `selectionArgs`, Room `@Query` binds, `sqlite3_bind_*`, sqflite `whereArgs` | Room DAO params are bound |
| `other-languages.md` | DBI `do/prepare("… $x")` · `ngx.quote_sql_str` missing in `resty.mysql` queries · `Sql.execute(str + x)` / `.toString()` · — | placeholders `?` · `ngx.quote_sql_str(x)` · GString `Sql.execute("… ${x}")` (auto-parameterized) | groovy.sql GString is bound |
| `php.md` | § SQL: `mysqli_query`/`->query` concat, `DB::raw`, `whereRaw/orderByRaw`, Doctrine DQL concat, `$wpdb->query` without `prepare` | PDO prepared statements, query builder bindings, `$wpdb->prepare` | `orderBy($col)` from input = column injection |
| `python.md` | § SQL: f-string / `%` / `.format` / `+` into `execute`, Django `.raw/.extra/RawSQL`, SQLAlchemy `text(f"")`, `order_by(user)` | `execute(sql, params)`, ORM filters, allow-listed columns | `execute("…%s", (x,))` is bound |
| `ruby.md` | § SQL: string interpolation in `where/order/pluck/select/group/joins/find_by_sql`, `Arel.sql(user)` | hash conditions, `?` placeholders, `sanitize_sql_*` | `find(params[:id])` is safe |
| `rust.md` | § SQL: `sqlx::query(&format!())`, Diesel `sql_query(format!)`, `dsl::sql(user)`, `rusqlite` `execute(&format!)` | `.bind()`, `query!` macros, `params![]` | `query!` is compile-time checked |
| `scala.md` | Slick `#$x`, Doobie `Fragment.const(x)`, Quill `infix` with raw splice, `spark.sql(s"…$x")`, JDBC `s"…$x"` | `sql"…$x"` binding, `fr"…$x"`, DataFrame API | Slick/Doobie `$x` (no `#`) is bound |
| `shell.md` | `mysql -e "SELECT … '$name'"`, `psql -c "… $x"`, `sqlite3 db "… $x"` | `psql -v name="$x" -c "… :'name'"`, parameterized via a real client |  |

## L05 — NoSQL injection

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | mongo-c-driver `bson_new_from_json(user)` used as filter (operator injection) | build BSON with typed appends |  |
| `dotnet.md` | `BsonDocument.Parse(userJson)` as filter, `$where` | `Builders<T>.Filter.Eq(x => x.F, v)` |  |
| `elixir.md` | MongoDB driver `Mongo.find(conn, coll, params)` with user maps (`%{"$ne" => …}`) | cast with Ecto changesets / explicit scalars |  |
| `frontend-browser.md` | N/A in browser — trace the API call to the backend pack (`find(req.body)`) | backend pack | client-built Mongo-style filter objects sent to API → check server accepts operators |
| `go.md` | mongo-go `bson.M` from `map[string]interface{}` decoded JSON → operator injection | decode into typed structs |  |
| `iac-ci.md` | N/A — check DB exposure instead (L25) | — |  |
| `java-kotlin.md` | `new BasicQuery(userJson)`, `Criteria.where(userField)`, `$where` | typed `Criteria` with fixed fields |  |
| `javascript-node.md` | § NoSQL: `find(req.body)`, `{ $ne: null }` via qs objects, `$where`, `$regex` from input | `String(x)`, `sanitizeFilter`, schema types | typed DTO validated first |
| `mobile-native.md` | Realm/NSPredicate: `NSPredicate(format: "name == '\(x)'")` (format injection) | `NSPredicate(format: "name == %@", x)` | `%@` placeholders are safe |
| `other-languages.md` | MongoDB driver with user hashrefs · `resty.mongol` with user tables · GORM `where` closures from maps · — | scalar casting |  |
| `php.md` | MongoDB `->find(['user' => $_POST['user']])` where PHP array params (`user[$ne]=x`) become operators | cast `(string)`, reject `$` keys | PHP auto-parses `a[b]=` into arrays |
| `python.md` | PyMongo `find(request.json)` / dict values (`{"$ne": None}`), `$where` | type-check scalars, reject `$` keys |  |
| `ruby.md` | Mongoid `where(params[:filter])` / `User.where(name: params[:name])` where name is a Hash (`name[$ne]=`) | `.to_s`, strong params with scalar types | Rack parses `a[b]=` into hashes |
| `rust.md` | mongodb crate `doc!{ "user": user_bson }` where value is `Bson` from user JSON (`{"$ne": …}`) | deserialize into typed struct, `Bson::String` only |  |
| `scala.md` | ReactiveMongo/mongo-scala `BSONDocument` built from user JSON objects (operator injection) | typed case classes, scalar extraction |  |
| `shell.md` | `mongo --eval "db.u.find({name:'$x'})"` (JS injection into the shell) | `mongosh` with `--eval` built from JSON-escaped values (`jq -Rs`) |  |

## L06 — OS command / argument injection

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | § Command: `system`, `popen`, `execl("/bin/sh","-c",…)` | `execve`/`posix_spawn` with argv array |  |
| `dotnet.md` | `Process.Start("cmd.exe", "/c " + x)`, `UseShellExecute=true` with user file | `ProcessStartInfo.ArgumentList` |  |
| `elixir.md` | `:os.cmd(String.to_charlist("ping " <> host))`, `System.cmd("sh", ["-c", x])` | `System.cmd(bin, [arg])` (no shell) | `System.cmd` with arg list is safe |
| `frontend-browser.md` | N/A — no shell in browser. Electron: `child_process` via `nodeIntegration: true` / exposed preload API | `contextIsolation: true`, `nodeIntegration: false`, narrow `contextBridge` API |  |
| `go.md` | `exec.Command("sh","-c",x)` | `exec.Command(bin, args...)` | no shell by default; option injection still possible (use `--`) |
| `iac-ci.md` | Ansible `shell:` with `{{ var }}` from untrusted inventory/facts, Dockerfile `RUN` with build args from PRs, Makefile recipes with env input | `command:` module with args list, `quote` filter |  |
| `java-kotlin.md` | `Runtime.exec(String)` with shell, `ProcessBuilder("sh","-c",x)` | `ProcessBuilder(List)` without shell | `exec(String)` tokenizes, no shell by default |
| `javascript-node.md` | § Command: `exec`, `execSync`, `spawn(...,{shell:true})` | `execFile`/`spawn(bin,[args])` | option injection still possible with arrays (`--` separator) |
| `mobile-native.md` | `Runtime.exec` on rooted-device helpers, `Process` (macOS Catalyst) | avoid shell | rarely reachable on mobile |
| `other-languages.md` | 2-arg `open($fh, $user)`, `system("…$x")`, backticks/`qx` · `os.execute("…"..x)`, `io.popen` · `["sh","-c",x].execute()` · — | 3-arg open, `system(LIST)` · avoid shell · `[bin, arg].execute()` | `"cmd $x".execute()` tokenizes (arg injection only) |
| `php.md` | `system/exec/shell_exec/passthru/popen/proc_open`, backticks, `mail()` 5th param | `escapeshellarg` per arg, `proc_open([...])` array form | `escapeshellcmd` on whole string is insufficient |
| `python.md` | `os.system`, `os.popen`, `subprocess(..., shell=True)` with input | list args, `shell=False`, `shlex.quote` | constant shell string is fine |
| `ruby.md` | `system("…#{x}")`, backticks, `%x()`, `IO.popen(str)`, `Open3.*(str)`, `Kernel#open(" | …")` | array form `system(bin, arg)` |
| `rust.md` | `Command::new("sh").arg("-c").arg(x)`; Windows `.bat` arg quoting (CVE-2024-24576, fixed 1.77.2) | `Command::new(bin).args([...])` | no shell by default |
| `scala.md` | `Seq("sh","-c",x).!`, `s"git clone $url".!` (argument injection, tokenized on spaces) | `Seq(bin, arg).!` with validated args, `--` separator | `"cmd".!` without shell |
| `shell.md` | unquoted `$var`, `bash -c "… $x"`, `ssh host "cmd $x"` (remote shell re-parses), `xargs` without `-0`, missing `--` before user args; PowerShell `& $cmd`, `Start-Process … "$x"` | `"$var"`, arrays `"${args[@]}"`, `--`, `printf '%q'` for remote ssh, `xargs -0` |  |

## L07 — LDAP / XPath / EL / other query injection

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | `ldap_search_ext_s` filter via `snprintf("(uid=%s)", u)`; libxml2 `xmlXPathEval` with concatenated expressions | RFC 4515 escaping of `*()\\\0`; XPath variables |  |
| `dotnet.md` | `DirectorySearcher.Filter = "(uid=" + u + ")"`, `XPathNavigator.Select(concat)`, `SelectNodes(concat)` | LDAP escaping (`\2a` etc.), `XsltArgumentList`/custom `XsltContext` variables |  |
| `elixir.md` | `:eldap.search` with filters built from strings (`:eldap.equalityMatch` is safe), XPath via `SweetXml` `~x` built with interpolation | `:eldap.equalityMatch/2`, fixed `~x` paths |  |
| `frontend-browser.md` | N/A — `document.evaluate` XPath on own DOM is not a security boundary | — |  |
| `go.md` | go-ldap `NewSearchRequest(…, fmt.Sprintf("(uid=%s)", u), …)`; `xmlquery`/`xpath` with concatenated expressions | `ldap.EscapeFilter(u)`; compile fixed XPath, compare values in Go |  |
| `iac-ci.md` | N/A — infra files build no LDAP/XPath queries; check LDAP servers exposed without TLS (389 open in SGs) under L24/L25 | LDAPS, private network |  |
| `java-kotlin.md` | LDAP filter concat, XPath concat, javax/jakarta EL `createValueExpression(user)`, OGNL (Struts) | `LdapEncoder.filterEncode`, `XPathVariableResolver` | JMESPath is not LDAP (LDAP-ADJ-01) |
| `javascript-node.md` | `ldapjs` filter `(uid=${u})`; `xpath.select("//u[@n='"+x+"']")` | `ldap-escape` / `ldapjs` `EqualityFilter`; parameterized XPath vars | JMESPath / lodash `get` are not LDAP |
| `mobile-native.md` | N/A — mobile apps rarely build LDAP/XPath queries; `NSXMLDocument` XPath on untrusted XML is the analogue | fixed XPath |  |
| `other-languages.md` | `Net::LDAP` filter strings · `lualdap` filters · LDAP/XPath concat as in Java · — | `Net::LDAP::Util::escape_filter_value` · escaping |  |
| `php.md` | `ldap_search($c, $dn, "(uid=$u)")`, `DOMXPath->query("//u[@n='$x']")` | `ldap_escape($u, '', LDAP_ESCAPE_FILTER)`; quote-safe XPath building |  |
| `python.md` | `ldap`/`ldap3` `search_s(base, scope, f"(uid={u})")`; lxml `xpath(f"//u[@n='{x}']")` | `ldap.filter.escape_filter_chars`, `ldap3.utils.conv.escape_filter_chars`; `xpath('…$n', n=x)` |  |
| `ruby.md` | `Net::LDAP::Filter.construct("(uid=#{u})")`; Nokogiri `xpath("//u[@n='#{x}']")` | `Net::LDAP::Filter.eq('uid', u)` (escapes); XPath variable bindings |  |
| `rust.md` | `ldap3` filter `format!("(uid={})", u)`; `sxd_xpath` with concatenated expressions | `ldap3::ldap_escape(u)`; fixed XPath + variables |  |
| `scala.md` | UnboundID/JNDI LDAP filters with `s"(uid=$u)"`, XPath via `javax.xml.xpath` concat | `Filter.createEqualityFilter`, XPath variables |  |
| `shell.md` | `ldapsearch … "(uid=$u)"` | escape filter chars (`* ( ) \ NUL`) before interpolation |  |

## L08 — Header / CRLF / log injection

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | § Format strings: `printf(user)`, `syslog(prio, user)`; CRLF in hand-built HTTP headers (`"Location: " + user + "\r\n"`) | `printf("%s", user)`, reject CR/LF |  |
| `dotnet.md` | `Response.Headers.Add(name, user)` (Kestrel rejects CR/LF), log forging with `Console`/text sinks | `ILogger` structured templates `{Value}` | header splitting N/A on Kestrel |
| `elixir.md` | `put_resp_header(conn, "x", user)` (Plug validates CR/LF), log injection with `Logger.info("… #{x}")` in text format | `Logger` metadata + JSON formatter | header splitting N/A on Plug |
| `frontend-browser.md` | N/A for HTTP headers (browser controls them). Log injection into client telemetry is low | — |  |
| `go.md` | log injection with `log.Printf("%s", input)` in text logs; header values — net/http rejects CR/LF (no splitting) | `slog` JSON handler, `%q` | header splitting N/A on net/http |
| `iac-ci.md` | nginx `proxy_set_header` passing client-controlled `X-Forwarded-*`/`Host` unchanged (spoofing), log format without escaping (`escape=json`) | overwrite forwarded headers at edge, `log_format … escape=json` |  |
| `java-kotlin.md` | `response.setHeader(name, user)` on old containers (CRLF), `Content-Disposition` filename injection; log forging via `log.info("user=" + input)` with text layout | `ContentDisposition.builder().filename()`, CR/LF stripping, JSON layout | Tomcat ≥8.5 rejects CR/LF in headers |
| `javascript-node.md` | `res.setHeader('Content-Disposition', 'attachment; filename=' + name)`; logging raw `\n` input (Bunyan/winston JSON escapes newlines — log forging needs a text formatter) | `content-disposition` pkg; JSON log formatter | Node ≥14 throws on CR/LF in header values (no response splitting) |
| `mobile-native.md` | log injection via `Log.d`/`NSLog`/`print` of untrusted data (also L27 leakage) | strip in release builds |  |
| `other-languages.md` | `print "Location: $x\n"` CRLF in CGI · `ngx.header[name] = user` (OpenResty rejects CR/LF in recent versions) · `response.setHeader` · — | strip CR/LF |  |
| `php.md` | `header("X: $user")` (rejects newlines since 5.1.2), log injection via `error_log($input)` | structured logs | response splitting N/A on modern PHP |
| `python.md` | header injection: Werkzeug/Django reject `\n` in headers (modern); log injection with `%s` of raw input into text logs | structured logging / strip CR-LF | `logging` with JSON formatter escapes |
| `ruby.md` | `response.headers[...] = user` (Rack rejects newlines in recent versions), log forging in text logs | `Logger` with formatter escaping, lograge JSON |  |
| `rust.md` | log injection with `info!("{}", input)` in text logs; `HeaderValue::from_str` rejects CR/LF | `tracing` JSON subscriber, `{:?}` debug quoting | header splitting N/A (http crate validates) |
| `scala.md` | `Ok(...).withHeaders(name -> user)` (Play rejects invalid chars in recent versions), log forging in text appenders | Logback JSON encoder |  |
| `shell.md` | `echo "user=$input" >> app.log` (newline injection in logs), building HTTP headers in `curl -H "X: $x"` with CR/LF | strip `\r\n` (`${x//[$'\r\n']/}`) |  |

## L09 — SSRF

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | libcurl `CURLOPT_URL` from user (+ `CURLOPT_PROTOCOLS` unset → `file://`, `gopher://`, `dict://`), `CURLOPT_FOLLOWLOCATION=1` | `CURLOPT_PROTOCOLS_STR "http,https"`, host allow-list, `CURLOPT_REDIR_PROTOCOLS_STR` |  |
| `dotnet.md` | § SSRF: `HttpClient.GetAsync(user)` (absolute URI overrides `BaseAddress`), `WebRequest.Create` (`file://`), `WebClient` | allow-list, `ConnectCallback` IP check, `AllowAutoRedirect=false` |  |
| `elixir.md` | `HTTPoison.get(user_url)`, `Req.get(user_url)`, `:httpc.request(user)`, Tesla with user base URL | allow-list + resolved-IP check, `redirect: false` |  |
| `frontend-browser.md` | N/A (browser has SOP). Client-side "SSRF": user-controlled `fetch(url)` with credentials to attacker origin leaks tokens in `Authorization` header | fixed API base; never attach tokens to user-supplied URLs |  |
| `go.md` | § SSRF: `http.Get(user)`, `NewRequest(user)`, `ReverseProxy` with user host | `url.Parse` + allow-list + `DialContext` IP check + `CheckRedirect` | `url.PathEscape(user)` on config base = path only |
| `iac-ci.md` | nginx `proxy_pass` with variables from `$host`/`$arg_*`/`$http_*` (SSRF via proxy), cloud metadata reachable from pods (no IMDSv2 / NetworkPolicy) | fixed upstreams, IMDSv2 `http_tokens = "required"`, egress NetworkPolicy |  |
| `java-kotlin.md` | § SSRF: `new URL(user)`, RestTemplate/WebClient/HttpClient/OkHttp/Feign `@Url`, `ImageIO.read(URL)`, `fromHttpUrl(user)` | host allow-list, IP check, no redirects | `.path()/.queryParam()` on config base = adjacent |
| `javascript-node.md` | § SSRF: axios/got/fetch/request with user URL or `base + user` without slash; redirects followed | `new URL` + host allow-list + IP check + `maxRedirects:0` | config base + query param = SSRF-adjacent only |
| `mobile-native.md` | app fetching URLs from deep-link params (`?url=`) with auth headers attached → token theft (mobile "SSRF") | allow-list hosts before attaching credentials | see `../deeplink-audit.md` |
| `other-languages.md` | `LWP::UserAgent->get($url)` · `ngx.location.capture(user)`, `resty.http:request_uri(user)` · `new URL(user).text` · — (oracles: trusting off-chain data feeds) | allow-list · fixed upstreams · allow-list · decentralized/verified oracles |  |
| `php.md` | § SSRF: `file_get_contents($url)`, curl, Guzzle, `getimagesize($url)`; wrappers `file://`, `php://filter`, `phar://`, `gopher://` | allow-list, `CURLOPT_PROTOCOLS`, disable redirects |  |
| `python.md` | § SSRF: `requests/httpx/urllib.urlopen(user_url)` (+`file://`), PDF renderers fetching remote resources | allow-list, IP check (`ipaddress.is_private`), `allow_redirects=False` | settings base + path param = adjacent |
| `ruby.md` | `Net::HTTP.get(URI(user))`, `URI.open(user)`, HTTParty/Faraday/RestClient with user URL | allow-list, `ssrf_filter` gem |  |
| `rust.md` | § SSRF: `reqwest::get(user)`, `Client::get(user)`, redirects default to 10 hops | allow-list + resolved-IP check (custom `dns_resolver`), `redirect::Policy::none()` |  |
| `scala.md` | Play `ws.url(userUrl)`, Akka `Http().singleRequest(HttpRequest(uri = user))`, http4s/sttp clients with user `Uri` | host allow-list + IP check, redirects off | config base + path segment = adjacent |
| `shell.md` | `curl "$url"` / `wget "$url"` / `Invoke-WebRequest $url` with user URLs in webhooks/CI | allow-list host, `--proto =https`, `--max-redirs 0` |  |

## L10 — Path traversal / file inclusion

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | § Command/file: `fopen(snprintf("%s/%s", base, user))`, `open()` without `realpath`/`O_NOFOLLOW` | `realpath` + prefix check, `openat` + `O_NOFOLLOW`/`RESOLVE_BENEATH` (`openat2`) |  |
| `dotnet.md` | `Path.Combine(base, user)` (absolute replaces base), `PhysicalFile(user)`, `File.*` | `GetFullPath` + `StartsWith(base + sep)`, `PhysicalFileProvider` |  |
| `elixir.md` | `File.read(Path.join(base, user))`, `send_file(conn, 200, user)` | `Path.safe_relative/2` (1.14+), `Plug.Static` | `Path.join` doesn't block `..` |
| `frontend-browser.md` | client-side path traversal: `fetch('/api/files/' + userPath)` → `../admin` hits other endpoints (CSPT) | `encodeURIComponent` per segment |  |
| `go.md` | `filepath.Join(base, user)` then open; `http.ServeFile(w, r, user)` | `filepath.IsLocal`, `os.Root` (1.24), `http.FileServer(http.Dir)` | `Join` cleans `..` but result can escape base |
| `iac-ci.md` | nginx `alias` without trailing slash (`/files../`), `root` inside `location` with user paths, K8s `hostPath` mounts | trailing slashes, avoid hostPath |  |
| `java-kotlin.md` | `new File(base, user)`, `Paths.get(base,user)`, `ResourceLoader.getResource(user)` | `normalize().startsWith(base)` after `toRealPath` |  |
| `javascript-node.md` | § Path: `path.join(base, user)` then `fs.*`; `res.sendFile(user)` | `path.resolve` + `startsWith(base + sep)`; `sendFile(name,{root})` | `express.static` is traversal-safe |
| `mobile-native.md` | ContentProvider `openFile(uri)` with `uri.getPath()` → `../` traversal; `FileProvider` with `<root-path>`; iOS file paths from URL params | canonical path check, narrow `file_paths.xml` |  |
| `other-languages.md` | `open(my $fh, '<', "$base/$name")` without check · `io.open(base..name)` · `new File(base, user)` · — | `File::Spec->canonpath` + prefix · prefix check · normalize + `startsWith` |  |
| `php.md` | `include/require($user)` LFI/RFI, `readfile/file_get_contents($base.$user)` | allow-list map, `basename`, `realpath` prefix check |  |
| `python.md` | `open(os.path.join(BASE, user))` (absolute user replaces BASE), `send_file(user)` | `Path.resolve().is_relative_to(BASE)`, `send_from_directory` | `os.path.basename` first is safe |
| `ruby.md` | `send_file(params[:path])`, `File.read(user)`, `Rails.root.join(user)` | `File.expand_path` + prefix check, `File.basename` |  |
| `rust.md` | `Path::new(base).join(user)` (absolute replaces base) then `fs::read` | `canonicalize` + `starts_with(base)`, `tower_http::ServeDir`, `actix_files` |  |
| `scala.md` | `new File(base, user)`, `Ok.sendFile(new File(user))`, `Paths.get(base, user)` | normalize + `startsWith(base)`, `Assets` controller | Play `Assets` is traversal-safe |
| `shell.md` | `cat "$BASE/$name"`, `rm -rf "$DIR/$name"` (with `name=../..`), `rm -rf "$UNSET_VAR/"` → `/` | `realpath -e` + prefix check, `set -u`, `${VAR:?}` |  |

## L11 — File upload / archive extraction

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | libarchive/minizip extraction with entry paths unchecked, symlink entries followed | `ARCHIVE_EXTRACT_SECURE_NODOTDOT`/`_SECURE_SYMLINKS`/`_SECURE_NOABSOLUTEPATHS` |  |
| `dotnet.md` | `IFormFile.FileName` as path, `ZipArchiveEntry.FullName` joined manually, content type from client | `Path.GetFileName`, `ExtractToDirectory` (safe in .NET Core), signature check |  |
| `elixir.md` | `%Plug.Upload{filename: name}` used as path, `:zip.unzip` / `:erl_tar.extract` without path checks | generated names, validate entries (`:zip.list_dir` first) |  |
| `frontend-browser.md` | client-only validation of file type/size | server-side validation (backend pack) | client checks are UX, not security |
| `go.md` | zip/tar extraction with `hdr.Name`, `FileHeader.Filename` as path, no size limit (`MaxBytesReader`) | `filepath.IsLocal(hdr.Name)`, `filepath.Base`, size caps |  |
| `iac-ci.md` | `client_max_body_size 0`; upload dirs served with script execution (Apache PHP handler) | size limits, `php_admin_flag engine off` for uploads |  |
| `java-kotlin.md` | `getOriginalFilename()` as path, Zip Slip in `ZipInputStream`, content type from client | `FilenameUtils.getName`, canonical check per entry, Tika detection |  |
| `javascript-node.md` | multer `originalname`, MIME from client, `adm-zip`/`unzipper` entries unchecked | generated names, magic-byte check, per-entry path check | `tar` ≥6 strips `..` |
| `mobile-native.md` | Zip extraction of downloaded content without entry checks (Android `ZipInputStream`, `SSZipArchive` old versions) | entry path validation |  |
| `other-languages.md` | `Archive::Zip` extraction · `lua-zip` · Grails `MultipartFile.originalFilename` · — | entry validation, generated names |  |
| `php.md` | `move_uploaded_file` into web root with client name/extension, trusting `$_FILES['type']`, `ZipArchive::extractTo` | random names outside web root, `finfo_file`, entry validation |  |
| `python.md` | `upload.name` as path, `tarfile.extractall` (symlinks/`..`), MIME from client | `extractall(filter='data')` (3.12+), generated names, `python-magic` | `zipfile` strips `..` since 3.6.2 |
| `ruby.md` | ActiveStorage/CarrierWave without content-type/extension allow-list, `Zip::File` extraction without path checks (rubyzip <1.3) | `extension_allowlist`, rubyzip ≥1.3 `on_exists_proc` + path validation |  |
| `rust.md` | `zip` `file.name()` / `mangled_name` misuse, `tar` manual `unpack(dest.join(path))`, multipart filename as path | `enclosed_name()`, `Entry::unpack_in`, generated names |  |
| `scala.md` | `MultipartFormData.FilePart.filename` as path, Zip Slip in extraction helpers | `Paths.get(filename).getFileName`, entry path checks |  |
| `shell.md` | `tar xf "$upload"` / `unzip "$upload"` without checking member paths (`../`, absolute, symlinks) | `tar --no-same-owner --no-absolute-filenames`, list then validate, extract into empty dir | GNU tar strips leading `/` by default |

## L12 — Insecure deserialization

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | Boost.Serialization / cereal / protobuf from untrusted input with polymorphic types; hand-written binary parsers trusting length fields | bounds-checked parsers, protobuf (no polymorphism), fuzzing |  |
| `dotnet.md` | `BinaryFormatter`/`SoapFormatter`/`NetDataContractSerializer`/`LosFormatter`/`ObjectStateFormatter`, Json.NET `TypeNameHandling` ≠ None, ViewState without MAC | `System.Text.Json`, `TypeNameHandling.None` | `BinaryFormatter` is removed in .NET 9 |
| `elixir.md` | `:erlang.binary_to_term(user)` (atom/fun creation), `Plug.Crypto.non_executable_binary_to_term` misuse | JSON (`Jason`), `binary_to_term(x, [:safe])` + `non_executable_binary_to_term` |  |
| `frontend-browser.md` | `JSON.parse` is safe; risk is `postMessage` data / `localStorage` objects trusted for logic | validate shape (Zod) |  |
| `go.md` | `encoding/gob` from untrusted peers, `yaml.v2` billion laughs into `interface{}`, `json` into `interface{}` passed to DB | typed structs, size limits | Go has no gadget-chain RCE deserialization in stdlib |
| `iac-ci.md` | N/A in config; message brokers exposed without auth (see L25) | — |  |
| `java-kotlin.md` | `ObjectInputStream.readObject`, Jackson default typing / `@JsonTypeInfo(Id.CLASS)`, XStream, XMLDecoder, SnakeYAML <2 `load`, Kryo/Hessian/Fastjson autoType, Kafka `trusted.packages=*` | JSON DTOs, `ObjectInputFilter`, `PolymorphicTypeValidator`, `SafeConstructor` |  |
| `javascript-node.md` | `node-serialize`, `funcster`, `serialize-javascript` round-trip, js-yaml v3 `load` with full schema | `JSON.parse`, js-yaml v4 `load` | `JSON.parse` alone is safe |
| `mobile-native.md` | Android `Serializable`/`Parcelable` from untrusted Intents (`getSerializableExtra`), iOS `NSKeyedUnarchiver.unarchiveObject` (non-secure coding) | `NSKeyedUnarchiver.unarchivedObject(ofClass:from:)` (secure coding), typed Parcelables, `getParcelableExtra(key, Class)` |  |
| `other-languages.md` | `Storable::thaw` / `YAML::Load` (code refs with `$YAML::LoadCode`) · `loadstring` of serialized tables · Java serialization, `XStream` · `abi.decode` of untrusted calldata into wrong types | JSON · `cjson.decode` · JSON · strict ABI types |  |
| `php.md` | `unserialize($user)` (POP chains), `phar://` triggers (<8), Laravel `decrypt()` with leaked `APP_KEY` | `json_decode`, `allowed_classes => false` |  |
| `python.md` | `pickle/cPickle/dill/joblib/torch.load/numpy allow_pickle`, `yaml.load` unsafe loaders, `jsonpickle`, `shelve`, `marshal` | `json`, `yaml.safe_load`, `torch.load(weights_only=True)` |  |
| `ruby.md` | `Marshal.load`, `YAML.load` (Psych <4), `YAML.unsafe_load`, `Oj.load(mode: :object)`, Marshal cookie serializer | `JSON.parse`, `YAML.safe_load`, `:json` cookies | Psych 4 `load` is safe |
| `rust.md` | `bincode`/`rmp-serde`/`serde_yaml` without size limits (memory DoS); `serde` with `#[serde(untagged)]` confusion | `bincode::options().with_limit`, body limits | no gadget-chain RCE in serde |
| `scala.md` | Java serialization in Akka remoting (`akka.actor.allow-java-serialization = on`), Kryo/Chill without registration, Jackson default typing, Spark reading user-provided serialized objects | Akka Jackson/Protobuf serializers, Kryo `registrationRequired` | Akka ≥2.6 disables Java serialization by default |
| `shell.md` | N/A as object deserialization; analogue: `source`-ing config files that users can write | parse key=value with `while IFS='=' read -r k v` |  |

## L13 — XML (XXE, entity expansion)

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | libxml2 `XML_PARSE_NOENT`, `XML_PARSE_DTDLOAD`, `xmlSubstituteEntitiesDefault(1)`; Xerces with external entities enabled; expat with entity expansion (billion laughs on old versions) | default libxml2 options (no NOENT), `XML_PARSE_NONET`, expat ≥2.4 |  |
| `dotnet.md` | `XmlDocument` with `XmlResolver` set, `DtdProcessing.Parse` + `XmlUrlResolver`, `XmlTextReader` on .NET Framework <4.5.2 | `XmlReaderSettings { DtdProcessing = Prohibit }` | .NET Core defaults are safe |
| `elixir.md` | `:xmerl_scan.string(user)` (entity expansion / external entities by default), SweetXml on untrusted XML | `SweetXml.parse(x, dtd: :none)`, `xmerl` with `{:fetch_fun, …}` denying |  |
| `frontend-browser.md` | `DOMParser` with `text/html` + insertion = XSS; browsers don't resolve external entities | sanitize before insertion | XXE N/A in browsers |
| `go.md` | `encoding/xml` has no external entities (safe from XXE); risk is libxml2 bindings (`lestrrat-go/libxml2`) with entity options | stdlib `encoding/xml` | XXE usually N/A in Go |
| `iac-ci.md` | N/A — no XML parsing in infra config; SAML IdP metadata URLs over `http://` are an L24 issue | HTTPS metadata |  |
| `java-kotlin.md` | `DocumentBuilderFactory`/`SAXParserFactory`/`XMLInputFactory`/`TransformerFactory`/`SchemaFactory`/JDOM/dom4j without `disallow-doctype-decl` | secure-processing features set at point of use | JAXB from `Source` parsed securely is fine |
| `javascript-node.md` | `libxmljs.parseXml(x,{noent:true})`, `xmldom` + string XPath | default libxmljs options; `xml2js` (no DTD) | `xml2js`/`fast-xml-parser` don't resolve external entities |
| `mobile-native.md` | `NSXMLParser` with `shouldResolveExternalEntities = true`, Android `DocumentBuilderFactory` defaults (see `java-kotlin.md` L13) | defaults off / secure features |  |
| `other-languages.md` | `XML::LibXML` with `expand_entities => 1`/`load_ext_dtd` · `lua-expat` entity expansion · `XmlSlurper` without `setFeature("…disallow-doctype-decl", true)` · — | `no_network => 1, expand_entities => 0` · disallow DOCTYPE |  |
| `php.md` | `LIBXML_NOENT`/`LIBXML_DTDLOAD` with `simplexml_load_string`/`DOMDocument::loadXML` | defaults on PHP ≥8 / libxml ≥2.9 | XXE needs those flags on modern stacks |
| `python.md` | `xml.etree`/`minidom`/`sax`/`lxml` with `resolve_entities=True`/`no_network=False` | `defusedxml` | stdlib `etree` doesn't fetch external entities but is vulnerable to entity expansion |
| `ruby.md` | Nokogiri `noent`/`dtdload` options, REXML old versions entity expansion | Nokogiri defaults |  |
| `rust.md` | `libxml` bindings with entity substitution; `quick-xml`/`roxmltree`/`xml-rs` don't resolve external entities | pure-Rust parsers | XXE usually N/A; `roxmltree` limits entity depth |
| `scala.md` | `scala.xml.XML.loadString` (old versions use SAX with entity resolution), JVM parsers as in `java-kotlin.md` L13 | secure `SAXParserFactory` passed to `XML.withSAXParser` | scala-xml ≥2.0 disables DOCTYPE by default |
| `shell.md` | `xmllint --noent` / `xsltproc` on untrusted XML | `xmllint --nonet` without `--noent` |  |

## L14 — Mass assignment / prototype pollution / object injection

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | N/A as mass assignment; object injection analogue = type confusion: `reinterpret_cast`/`static_cast` downcasts of attacker-chosen types, unions | `dynamic_cast`, `std::variant` |  |
| `dotnet.md` | binding EF entities directly in actions (over-posting `IsAdmin`), `TryUpdateModelAsync` without include list | view-model DTOs, `[Bind("A,B")]` |  |
| `elixir.md` | `Ecto.Changeset.cast(user, params, [:role, :is_admin])` exposing privileged fields; `struct(User, params)` | cast only user-editable fields; separate admin changesets |  |
| `frontend-browser.md` | client prototype pollution: `$.extend(true, {}, parsedQuery)`, `deparam`, `qs` in browser, `Object.assign` from `location.hash` → gadget XSS | `Object.create(null)`, key filtering |  |
| `go.md` | binding request JSON directly into DB model structs (`IsAdmin`, `Balance` fields) via `ShouldBindJSON(&user)` / `Decode(&model)` then `db.Save` | separate input DTO, `json:"-"` on sensitive fields | GORM `Updates(map)` from request = mass assignment |
| `iac-ci.md` | Helm values overriding security contexts from untrusted sources; Terraform modules from user input | pinned modules |  |
| `java-kotlin.md` | `@ModelAttribute`/`@RequestBody` binding JPA entities (`role`, `owner`), Spring4Shell-style class-loader binding on old Spring + JDK9 | DTOs, `@InitBinder setAllowedFields` |  |
| `javascript-node.md` | prototype pollution: `_.merge/defaultsDeep/set`, recursive merge of `req.body`, `__proto__`/`constructor.prototype`; mass assignment: `Model.create(req.body)`, `Object.assign(user, req.body)` | key deny-list, `Object.create(null)`, explicit field picking (`_.pick`) | `Object.assign({}, body)` doesn't pollute prototype |
| `mobile-native.md` | Intent extras overriding internal state (`intent.getBooleanExtra("isAdmin")`), Codable models decoding server-trust fields from deep links | ignore privileged fields from external inputs |  |
| `other-languages.md` | `%$self = (%$self, %$params)` hash merge · table merge from `get_uri_args()` · Grails data binding `new User(params)` / `user.properties = params` · — | explicit fields · `bindData(obj, params, [include: [...]])` |  |
| `php.md` | Laravel `$guarded = []`, `$fillable` with `is_admin`, `Model::create($request->all())`; `extract($_POST)`, `parse_str($q)` without result array (<8) | `$request->validated()`, explicit `$fillable` |  |
| `python.md` | DRF `ModelSerializer fields='__all__'`, Pydantic `extra='allow'` → `**data` into ORM, `setattr(obj, k, v)` loop over request keys, `Model(**request.json)` | explicit fields, `read_only_fields` |  |
| `ruby.md` | `params.permit!`, `permit(:role, :admin)`, `update(params[:user])` (pre-strong-params), `attr_accessible` | explicit `permit` lists |  |
| `rust.md` | `#[derive(Deserialize)]` on DB models with `is_admin`/`role` fields bound from request JSON → mass assignment | separate input DTO, `#[serde(skip_deserializing)]` |  |
| `scala.md` | Play JSON `Json.reads[UserEntity]` binding sensitive fields (`role`, `isAdmin`) straight from request | separate input case class |  |
| `shell.md` | `export $(cat .env)` / `declare "$k=$v"` from untrusted files overwriting `PATH`, `LD_PRELOAD`, `IFS` | explicit allow-list of keys |  |

## L15 — Authentication & session

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | hand-rolled auth: `strcmp(password, stored)` (timing), fixed session IDs, sessions without expiry | `CRYPTO_memcmp`, random IDs from `getrandom` |  |
| `dotnet.md` | cookie auth `SecurePolicy.None`, `HttpOnly=false`, no `SignInAsync` regeneration, Identity lockout disabled (`lockoutOnFailure: false`) | defaults, lockout enabled |  |
| `elixir.md` | session cookie `signing_salt` without `encryption_salt` storing sensitive data, `secure: false`, no `configure_session(renew: true)` on login | `encryption_salt`, `renew: true` |  |
| `frontend-browser.md` | tokens in `localStorage`/`sessionStorage` (XSS-stealable); auth decisions in UI only; logout without server invalidation | `httpOnly` cookies; server-side checks |  |
| `go.md` | `gorilla/sessions` hardcoded key, `Secure/HttpOnly` false, no session rotation on login, `==` password compare | random keys from env, `bcrypt.CompareHashAndPassword` |  |
| `iac-ci.md` | services exposed without auth (Redis, Elasticsearch, Mongo, RabbitMQ management, Kibana, Jenkins) in compose/K8s/SG rules | auth + private networking |  |
| `java-kotlin.md` | `permitAll()` too broad, session fixation disabled, remember-me with static key, `NoOpPasswordEncoder` | `authenticated()` default, bcrypt encoder | method security may still protect |
| `javascript-node.md` | § Auth: `express-session` weak secret, no `regenerate` on login, cookies not `secure`; OTP compared with `==`, no attempt limit | strong secret, `regenerate`, rate-limit (`express-rate-limit`) | header-token APIs have no session fixation |
| `mobile-native.md` | auth tokens in `UserDefaults`/`SharedPreferences`/`AsyncStorage`, biometric checks via `LocalAuthentication` boolean only (bypassable with hooks; no Keychain-bound key) | Keychain/Keystore, `kSecAccessControlBiometryCurrentSet`, `BiometricPrompt` + `CryptoObject` |  |
| `other-languages.md` | CGI::Session with predictable IDs · `lua-resty-session` with default secret · Spring Security plugin misconfig · Solidity: `tx.origin == owner` (phishing via intermediate contract) | random secrets · `msg.sender` checks |  |
| `php.md` | no `session_regenerate_id(true)` on login, cookie flags off, `session.use_strict_mode=0`, `==` password compare | `password_verify`, regenerate, strict mode |  |
| `python.md` | Django views without `@login_required`, DRF default `AllowAny`, Flask routes missing decorator, session cookie flags off, no `cycle_key` on login (Django does it in `login()`) | global permission class, `LoginRequiredMixin` | blueprint `before_request` covers routes |
| `ruby.md` | Devise `paranoid=false` (enumeration), no lockout (`:lockable`), session not reset on login (`reset_session`) | Devise lockable, `reset_session` | Devise resets session on sign-in |
| `rust.md` | `actix-session`/`tower-sessions` with hardcoded key, `cookie_secure(false)`, no rotation on login (`renew()`) | key from env, secure cookies, `session.renew()` |  |
| `scala.md` | Play session cookie (signed, not encrypted) holding sensitive data, `play.http.session.secure=false`, no rotation on login | server-side session store, `secure=true` |  |
| `shell.md` | CGI auth by checking `$REMOTE_USER` set by misconfigured proxy; `sudo` rules allowing scripts writable by users | root-owned scripts, `sudoers` with full paths |  |

## L16 — JWT / OAuth / SAML / tokens

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | JWT libs (`jwt-cpp`, `libjwt`) without algorithm pinning (`allow_algorithm`), skipping signature verification | `jwt::verify().allow_algorithm(rs256)` |  |
| `dotnet.md` | `TokenValidationParameters` with `ValidateIssuerSigningKey/Lifetime/Issuer/Audience=false`, `RequireSignedTokens=false`, custom `SignatureValidator`; OpenIdConnect without nonce/state validation | all validations on |  |
| `elixir.md` | `Joken` without signer/claims validation, Guardian `decode_and_verify` skipped (`peek_claims` used for authz), OAuth (Ueberauth) without state check | `Joken.verify_and_validate`, Guardian pipelines | `peek` for display only is fine |
| `frontend-browser.md` | JWT decoded client-side to decide privileges; OAuth implicit flow, missing `state`/PKCE; tokens in URL fragments/query | auth code + PKCE, `state` check | decoding JWT for display is fine |
| `go.md` | golang-jwt `Parse` keyFunc ignoring `t.Method`, `ParseUnverified`, missing `exp` check (v4 `MapClaims` without `VerifyExpiresAt`), OAuth `state` unchecked | `jwt.WithValidMethods`, `WithExpirationRequired` (v5) |  |
| `iac-ci.md` | long-lived cloud keys in CI secrets instead of OIDC; K8s ServiceAccount token automount | OIDC federation, `automountServiceAccountToken: false` |  |
| `java-kotlin.md` | JJWT `parseClaimsJwt`/no key, Auth0 `JWT.decode` for authz, Nimbus without alg check, SAML signature on wrong element (wrapping), OAuth redirect-URI prefix match | `parseSignedClaims(key)`, `JWT.require(alg)…verify`, exact redirect match |  |
| `javascript-node.md` | `jwt.decode` for authz; `verify` without `algorithms`; HS/RS confusion; long-lived tokens without revocation; OAuth `state` unchecked | `jwt.verify(t,k,{algorithms,audience,issuer})` | jsonwebtoken ≥9 rejects `none` |
| `mobile-native.md` | OAuth without PKCE, custom URL-scheme redirect hijack, tokens in deep links, JWT validated client-side only | PKCE + claimed HTTPS redirect (App Links / universal links), `ASWebAuthenticationSession` / AppAuth |  |
| `other-languages.md` | JWT modules without alg pinning (`Crypt::JWT` `accepted_alg`) · `lua-resty-jwt` `verify` with `alg` from header · same as Java · signature replay: `ecrecover` without nonce/chainId/EIP-712 domain, malleable signatures | pin algorithms · EIP-712 + nonces, OpenZeppelin `ECDSA` |  |
| `php.md` | `firebase/php-jwt` `JWT::decode` without `Key`+alg (old API `decode($t, $k, ['none'])`), OAuth `state` unchecked | `JWT::decode($t, new Key($k, 'RS256'))` | php-jwt ≥6 requires `Key` |
| `python.md` | `jwt.decode(..., options={"verify_signature": False})`, missing `algorithms`, `authlib`/`python-jose` alg confusion, OAuth `state` not verified | `jwt.decode(t, k, algorithms=[...], audience=...)` | PyJWT ≥2 requires `algorithms` |
| `ruby.md` | `JWT.decode(t, nil, false)`, algorithm not pinned, OmniAuth without CSRF protection (`omniauth-rails_csrf_protection`) | `JWT.decode(t, key, true, algorithm: 'RS256')` |  |
| `rust.md` | `jsonwebtoken` `insecure_disable_signature_validation()`, `dangerous_insecure_decode`, `Validation` with `validate_exp=false`, algorithms not pinned; `oauth2` crate without CSRF `state` check | `Validation::new(Algorithm::RS256)`, compare `CsrfToken` |  |
| `scala.md` | `jwt-scala`/`pauldijou` decode without algorithm list (`JwtCirce.decode(t, key, JwtAlgorithm.allHmac())` accepting unexpected algs), `decodeRaw` without verification | pin single algorithm, verify `exp/aud/iss` |  |
| `shell.md` | tokens passed as CLI args (`curl -H "Authorization: Bearer $T"` visible in `ps`), stored in world-readable files | `curl --config`/stdin, `chmod 600`, secret env vars |  |

## L17 — Authorization (IDOR/BOLA, BFLA, route order)

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | missing privilege checks in setuid binaries / daemons (UID from client message), `getuid` vs `geteuid` confusion | `SO_PEERCRED`, drop privileges early |  |
| `dotnet.md` | missing `[Authorize]`, `[AllowAnonymous]` on sensitive actions, minimal APIs without `.RequireAuthorization()`, `Find(id)` without owner check | `FallbackPolicy` requiring auth, resource-based `IAuthorizationService` | global `AuthorizeFilter` covers controllers |
| `elixir.md` | routes outside `pipe_through :require_authenticated_user`, LiveView `mount` without auth (`on_mount`), `Repo.get(Post, id)` without owner, channel `join` returning `{:ok, socket}` unconditionally | auth pipelines, `on_mount` hooks, scoped queries |  |
| `frontend-browser.md` | hidden admin routes/buttons only; IDs in URL — real check is backend | report backend gap | UI hiding isn't a finding by itself |
| `go.md` | Gin routes registered **before** `r.Use(auth)` (Gin applies `Use` only to later routes), handlers outside auth `Group`, `db.First(&o, id)` without owner | auth group, owner in `Where` | Echo `Use` covers all routes |
| `iac-ci.md` | RBAC wildcards, `cluster-admin` bindings, IAM `*:*`, S3 bucket policies `Principal: *` | least privilege |  |
| `java-kotlin.md` | controller methods missing `@PreAuthorize` vs siblings, `findById(id)` without owner, trusting `X-User-Id` header, `mvcMatchers`/`antMatchers` path mismatch | per-method annotations, owner filter, principal from token | gateway-injected headers need evidence of non-reachability |
| `javascript-node.md` | route registered before `router.use(auth)`; `findById(req.params.id)` without owner filter; uid from header/query | auth on every route; `{ _id, ownerId: req.user.id }` | prefix-mounted middleware covers only that prefix |
| `mobile-native.md` | exported Activities exposing privileged screens (`android:exported="true"` without `permission`), iOS URL handlers performing actions without confirmation | `exported=false`, signature permissions, user confirmation |  |
| `other-languages.md` | missing auth checks in CGI scripts · `access_by_lua` missing on some `location`s · Grails controllers without `@Secured` · Solidity functions missing `onlyOwner`/role modifiers, `public`/`external` visibility by mistake, unprotected `initialize()` on proxies | auth in every entry point · `initializer` modifier + `_disableInitializers()` |  |
| `php.md` | Laravel routes outside `auth` middleware, missing Policies/Gates (IDOR), WordPress `wp_ajax_nopriv_*` doing privileged work, REST `permission_callback => '__return_true'`, Symfony `access_control` order | middleware groups, `authorize()`, `current_user_can` |  |
| `python.md` | `Model.objects.get(pk=pk)` without owner filter, DRF `get_queryset` unfiltered, `has_object_permission` missing | `filter(owner=request.user)`, object permissions |  |
| `ruby.md` | `skip_before_action :authenticate_user!`, `Order.find(params[:id])` vs `current_user.orders.find`, Pundit/CanCan missing (`verify_authorized` absent) | scoped finders, `after_action :verify_authorized` |  |
| `rust.md` | Axum `route_layer(auth)` applied before later `.route()` calls (later routes unprotected); handlers loading by ID without owner check | layer after all routes / per-route extractor (`AuthUser`) | Axum `.layer` applies to routes registered before it |
| `scala.md` | Play actions without `Authenticated`/Silhouette `SecuredAction`, Akka routes outside `authenticateOAuth2` directive, repository lookups without owner | action builders on every route, owner filter |  |
| `shell.md` | `sudo` / setuid wrappers calling scripts that trust `$1`; scripts run as root reading user-writable paths | drop privileges, validate inputs |  |

## L18 — CSRF

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | embedded web UIs (routers/IoT) with cookie auth and no CSRF tokens | tokens + `SameSite` |  |
| `dotnet.md` | MVC POST without `[ValidateAntiForgeryToken]` and no global auto-validate, `[IgnoreAntiforgeryToken]` | `AutoValidateAntiforgeryTokenAttribute` | Razor Pages validate by default |
| `elixir.md` | browser pipeline missing `:protect_from_forgery`, LiveView without CSRF token in `connect_params` | Phoenix defaults | API pipelines with token auth N/A |
| `frontend-browser.md` | SPA sending cookie-auth state changes without CSRF header/token | custom header + server check, `SameSite` |  |
| `go.md` | cookie-session forms without `gorilla/csrf`/`nosurf`, `SameSite` unset | CSRF middleware | bearer APIs N/A |
| `iac-ci.md` | N/A — CSRF is an app concern; at the edge only cookie `SameSite` rewriting (`proxy_cookie_flags`) applies | `proxy_cookie_flags ~ secure samesite=lax` |  |
| `java-kotlin.md` | `csrf().disable()` with session auth | default CSRF, `CookieCsrfTokenRepository` | stateless bearer APIs not CSRF-prone |
| `javascript-node.md` | cookie-session auth + state-changing POST without CSRF token / `SameSite` | `csrf-csrf`/`lusca`, `SameSite=Lax/Strict` | bearer-header APIs are not CSRF-prone |
| `mobile-native.md` | WebView-based flows with cookie auth loading attacker pages | isolate WebView cookie stores | native API calls with bearer tokens N/A |
| `other-languages.md` | CGI forms without tokens · OpenResty-served forms · Grails `withForm`/`useToken` missing · — (no cookies) | tokens | Solidity N/A — transactions are signed |
| `php.md` | `VerifyCsrfToken::$except` wildcards, WordPress handlers without `check_admin_referer`/nonce, Symfony `csrf_protection: false` | CSRF tokens / nonces |  |
| `python.md` | `@csrf_exempt`, `CsrfViewMiddleware` removed, Flask without `CSRFProtect` on cookie auth | middleware on, tokens | DRF `TokenAuthentication` is not CSRF-prone; `SessionAuthentication` is |
| `ruby.md` | `skip_before_action :verify_authenticity_token`, `protect_from_forgery with: :null_session` on cookie-auth controllers | `protect_from_forgery with: :exception` | API-only controllers with token auth N/A |
| `rust.md` | cookie-auth forms without CSRF (`axum_csrf`, `actix-csrf`), `SameSite::None` | CSRF middleware, `SameSite::Lax` | bearer APIs N/A |
| `scala.md` | Play `CSRFFilter` disabled or `play.filters.csrf.header.bypassHeaders` too broad; `+ nocsrf` route modifier on state-changing routes | default `CSRFFilter` | token-auth APIs N/A |
| `shell.md` | N/A — shell scripts have no browser sessions; CGI handlers follow L18 of the serving server | — |  |

## L19 — CORS

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | embedded servers echoing `Origin` into `Access-Control-Allow-Origin` with credentials | allow-list |  |
| `dotnet.md` | `SetIsOriginAllowed(_ => true).AllowCredentials()` | `WithOrigins(...)` | `AllowAnyOrigin().AllowCredentials()` throws |
| `elixir.md` | `CORSPlug, origin: "*"` with credentials, `check_origin: false` on sockets | explicit origins |  |
| `frontend-browser.md` | N/A client-side — CORS is enforced by server headers (backend pack) | — |  |
| `go.md` | manual `Access-Control-Allow-Origin` = request `Origin` + credentials, `AllowOriginFunc` returning true | explicit allow-list | rs/cors refuses `*` + credentials |
| `iac-ci.md` | nginx `add_header Access-Control-Allow-Origin $http_origin` + credentials | map of allowed origins |  |
| `java-kotlin.md` | `allowedOriginPatterns("*")` + credentials, `@CrossOrigin(origins="*")` | explicit origins | `*` + credentials is rejected at runtime in Spring ≥5.3 |
| `javascript-node.md` | `cors({origin:true,credentials:true})`, reflected `Origin`, unanchored regex | explicit origin list | `origin:'*'` without credentials = low |
| `mobile-native.md` | N/A on device — CORS is server-side; WebView `setAllowUniversalAccessFromFileURLs(true)` is the analogue (file:// pages read any origin) | keep disabled |  |
| `other-languages.md` | — · `ngx.header["Access-Control-Allow-Origin"] = ngx.var.http_origin` + credentials · Grails CORS plugin `allowedOrigins: ['*']` + credentials · — | explicit list |  |
| `php.md` | `header("Access-Control-Allow-Origin: ".$_SERVER['HTTP_ORIGIN'])` + credentials; Laravel `cors.php` `allowed_origins => ['*']` + `supports_credentials` | explicit list |  |
| `python.md` | `CORS_ALLOW_ALL_ORIGINS + CORS_ALLOW_CREDENTIALS`, unanchored `CORS_ALLOWED_ORIGIN_REGEXES`, flask-cors `supports_credentials` with `*` | explicit origins |  |
| `ruby.md` | rack-cors `origins { true }` / regex unanchored + `credentials: true` | explicit list |  |
| `rust.md` | `CorsLayer::permissive()`/`very_permissive()`, `Cors::permissive()`, `AllowOrigin::mirror_request()` + credentials | explicit origins | `tower-http` panics on `Any` + credentials |
| `scala.md` | `play.filters.cors.allowedOrigins = null` (all) + `supportsCredentials = true`; Akka `cors()` with `HttpOriginMatcher.*` + credentials | explicit origins |  |
| `shell.md` | N/A — CORS headers belong to the web server config (`iac-ci.md`) | — |  |

## L20 — Security headers & cookie flags

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | embedded servers without security headers / cookie flags | set headers explicitly |  |
| `dotnet.md` | no `UseHsts`/`UseHttpsRedirection`, cookie flags off, missing CSP | middleware + `NWebsec`/custom headers |  |
| `elixir.md` | browser pipeline without `put_secure_browser_headers`, `force_ssl` missing | Phoenix defaults, `Plug.SSL` |  |
| `frontend-browser.md` | inline scripts force `unsafe-inline`; missing SRI on CDN scripts; `target=_blank` without `rel=noopener` (old browsers) | CSP nonces, `integrity=`, `rel="noopener noreferrer"` | modern browsers default `noopener` |
| `go.md` | `http.Cookie{}` without `Secure/HttpOnly/SameSite`, no HSTS/CSP | set flags, `secure` middleware (unrolled/secure) |  |
| `iac-ci.md` | missing HSTS/CSP/XFO/nosniff at nginx/ingress; child `location` `add_header` drops parent headers | headers in every `location` or `always` include file |  |
| `java-kotlin.md` | `frameOptions().disable()`, cookie `secure/http-only=false`, no HSTS | Spring Security defaults |  |
| `javascript-node.md` | no `helmet()`; `res.cookie` without `httpOnly/secure/sameSite`; `trust proxy` misuse | `helmet`, cookie flags | headers may be set at nginx/CDN (check before reporting) |
| `mobile-native.md` | `allowBackup="true"` (data extraction via adb backup), screenshots of sensitive screens (`FLAG_SECURE` missing), `debuggable=true` | `allowBackup=false`/`dataExtractionRules`, `FLAG_SECURE` |  |
| `other-languages.md` | CGI `Set-Cookie` without flags · `ngx.header["Set-Cookie"]` without `Secure; HttpOnly` · Grails cookie config · — | flags |  |
| `php.md` | `session.cookie_secure/httponly/samesite` off, `expose_php=On`, no security headers | php.ini hardening, middleware |  |
| `python.md` | `SESSION_COOKIE_SECURE/HTTPONLY=False`, no `SECURE_HSTS_SECONDS`, `X_FRAME_OPTIONS` unset, missing `SecurityMiddleware` | Django security settings, `flask-talisman` | proxy may add headers |
| `ruby.md` | `force_ssl=false`, cleared `default_headers`, cookies without `secure` | `config.force_ssl = true`, `secure_headers` gem |  |
| `rust.md` | missing security headers (`tower_http::set_header`), cookies without `secure/http_only` | `SetResponseHeaderLayer`, cookie builder flags |  |
| `scala.md` | `SecurityHeadersFilter` disabled, `play.filters.hosts.allowed = ["."]` (host header attacks) | default filters, explicit allowed hosts |  |
| `shell.md` | N/A — headers are set by the web server; CGI scripts printing `Set-Cookie` without `Secure; HttpOnly` | add flags |  |

## L21 — Open redirect / URL parsing

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | `Location:` built from user input in CGI | relative path allow-list |  |
| `dotnet.md` | `Redirect(returnUrl)` | `LocalRedirect`, `Url.IsLocalUrl` |  |
| `elixir.md` | `redirect(conn, external: params["next"])` | `redirect(conn, to: path)` (local only) | `to:` rejects external URLs |
| `frontend-browser.md` | § Open redirect: `location = params.get('next')`, `router.push(query.redirect)` | same-origin check |  |
| `go.md` | `http.Redirect(w, r, r.FormValue("next"), …)` | relative-path allow-list |  |
| `iac-ci.md` | nginx `return 302 $arg_next` / `rewrite … $arg_url` | fixed targets |  |
| `java-kotlin.md` | `"redirect:" + param`, `sendRedirect(param)` | allow-list / relative paths only |  |
| `javascript-node.md` | `res.redirect(req.query.next)`; `'/'+x` → `//evil`; `url.parse` legacy quirks | same-origin check via `new URL(x, base).origin` | redirect to fixed path list |
| `mobile-native.md` | deep-link handlers opening arbitrary URLs (`UIApplication.shared.open(url)` / `startActivity(Intent(ACTION_VIEW, uri))` from params) | allow-list |  |
| `other-languages.md` | `print $q->redirect($q->param('next'))` · `ngx.redirect(arg)` · `redirect(url: params.next)` · — | allow-list |  |
| `php.md` | `header("Location: ".$_GET['url'])`, Laravel `redirect($request->input('next'))` | `redirect()->intended()` with allow-list |  |
| `python.md` | `redirect(request.GET['next'])` | `url_has_allowed_host_and_scheme` |  |
| `ruby.md` | `redirect_to params[:url]`, `redirect_to(params.merge(host: …))` | `allow_other_host: false` / Rails 7 `raise_on_open_redirects` |  |
| `rust.md` | `Redirect::to(&query.next)` | allow-list / relative paths |  |
| `scala.md` | `Redirect(request.getQueryString("next").get)` | relative-path allow-list |  |
| `shell.md` | CGI `echo "Location: $next"` | allow-list |  |

## L22 — Cryptography

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | § Crypto: `EVP_*_ecb`, `DES_*`, `MD5()`/`SHA1()` passwords, static IVs, `RSA_PKCS1_PADDING` for encryption | `EVP_aes_256_gcm`, libsodium, `RSA_PKCS1_OAEP_PADDING` |  |
| `dotnet.md` | DES/3DES/RC2, `CipherMode.ECB`, MD5/SHA1 passwords, `Rfc2898DeriveBytes` low iterations | `AesGcm`, `PasswordHasher<T>` |  |
| `elixir.md` | `:crypto.hash(:md5/:sha, password)`, `:crypto.crypto_one_time(:aes_128_ecb, …)` | `Bcrypt`/`Argon2`, `:aes_256_gcm` |  |
| `frontend-browser.md` | crypto in JS with hardcoded keys "encrypting" API payloads (security theater); `crypto-js` AES with static key/IV | TLS + server-side crypto |  |
| `go.md` | `md5/sha1` for passwords, CBC with static IV, nonce reuse in `gcm.Seal`, `des`/`rc4` | bcrypt/argon2, random nonce |  |
| `iac-ci.md` | unencrypted volumes/buckets/RDS/EBS, KMS keys without rotation | encryption at rest + rotation |  |
| `java-kotlin.md` | `Cipher.getInstance("AES")` (ECB default), DES/3DES/RC4, static IV, MD5/SHA1 passwords, RSA <2048 | `AES/GCM/NoPadding`, bcrypt/argon2 |  |
| `javascript-node.md` | `createHash('md5'/'sha1')` for passwords, `createCipher`, ECB, static IV | `bcrypt`/`argon2`, `aes-256-gcm` + random IV | md5 for cache keys/ETags is fine |
| `mobile-native.md` | hardcoded AES keys in app, `CC_MD5`/`CC_SHA1` for passwords, `Cipher.getInstance("AES")` (ECB), static IVs | Keystore/Keychain-generated keys, CryptoKit `AES.GCM` |  |
| `other-languages.md` | `Digest::MD5` passwords, `Crypt::CBC` with static IV · `ngx.md5` for passwords · Java ciphers as in `java-kotlin.md` · — (hash collisions via `abi.encodePacked` of dynamic types) | bcrypt/argon2 · `abi.encode` |  |
| `php.md` | `md5/sha1` passwords, `crypt` DES, `openssl_encrypt(...'-ecb')`, `mcrypt_*` | `password_hash`, `sodium_*`, AES-GCM |  |
| `python.md` | `hashlib.md5/sha1(password)`, `AES.MODE_ECB`, static IV, PyCrypto (unmaintained) | `bcrypt`/`argon2`, `cryptography` AESGCM | md5 for checksums fine |
| `ruby.md` | `Digest::MD5/SHA1` passwords, `OpenSSL::Cipher` ECB / static IV | `bcrypt`, `has_secure_password`, AES-GCM via `ActiveSupport::MessageEncryptor` |  |
| `rust.md` | `md5`/`sha1` crates for passwords, raw `aes` block ECB, nonce reuse with `aes-gcm`, hand-rolled crypto | `argon2`, `aes-gcm` + `OsRng` nonces, `ring` |  |
| `scala.md` | `Cipher.getInstance("AES")` (ECB), MD5/SHA1 passwords, static IV | AES-GCM, bcrypt/argon2 (`scala-bcrypt`) |  |
| `shell.md` | `openssl enc -aes-256-cbc` without `-pbkdf2` (weak EVP_BytesToKey KDF), `-des`, `md5sum` for passwords | `openssl enc -aes-256-gcm`(where supported) / `age`/`gpg`, `-pbkdf2 -iter 600000` | md5sum for file integrity of non-adversarial data is fine |

## L23 — Insecure randomness

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | `rand()`, `srand(time(NULL))`, `std::mt19937`, `std::random_device` on old MinGW (deterministic) | `getrandom`, `arc4random_buf`, `RAND_bytes`, `BCryptGenRandom` |  |
| `dotnet.md` | `new Random()` / `Random.Shared` for tokens | `RandomNumberGenerator` |  |
| `elixir.md` | `:rand.uniform` / `Enum.random` for tokens | `:crypto.strong_rand_bytes/1` |  |
| `frontend-browser.md` | `Math.random()` for client nonces/state/PKCE verifier | `crypto.getRandomValues`, `crypto.randomUUID` |  |
| `go.md` | `math/rand` (and `math/rand/v2` non-crypto sources) for secrets | `crypto/rand`, `rand.Text()` (1.24) |  |
| `iac-ci.md` | N/A for config; generated passwords in Terraform (`random_password`) end up in state (L25); Ansible `lookup('password', …)` files committed | store state remotely encrypted |  |
| `java-kotlin.md` | `new Random()`, `Math.random()`, `ThreadLocalRandom` for secrets; Kotlin `Random.Default` | `SecureRandom` |  |
| `javascript-node.md` | `Math.random()` for tokens/OTP/IDs; `uuid` v1 as secret | `crypto.randomBytes/randomInt/randomUUID` | `Math.random` for UI jitter is fine |
| `mobile-native.md` | `arc4random` is fine; `java.util.Random`, Dart `Random()` (non-secure) for tokens | `SecureRandom`, `SecRandomCopyBytes`, `Random.secure()` |  |
| `other-languages.md` | `rand()` · `math.random` · `new Random()` · `block.timestamp`/`blockhash`/`prevrandao` for lotteries | `Crypt::URandom` · `resty.random.bytes(n, true)` · `SecureRandom` · Chainlink VRF / commit-reveal |  |
| `php.md` | `rand`, `mt_rand`, `uniqid`, `lcg_value`, `str_shuffle` for tokens | `random_bytes`, `random_int` |  |
| `python.md` | `random.*` for tokens | `secrets` module | `random` for sampling fine |
| `ruby.md` | `rand`, `Random.new`, `SecureRandom` misuse via `rand(…)` | `SecureRandom.hex/urlsafe_base64/uuid` |  |
| `rust.md` | `SmallRng`, `StdRng::seed_from_u64(const)`, `fastrand` for secrets | `OsRng`, `rand::thread_rng()` (CSPRNG) | `thread_rng` is cryptographically secure |
| `scala.md` | `scala.util.Random` for tokens | `java.security.SecureRandom` |  |
| `shell.md` | `$RANDOM`, `$$`, `date +%s` for temp names/tokens | `mktemp`, `openssl rand -hex 32`, `/dev/urandom` |  |

## L24 — TLS / certificate validation

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | `SSL_VERIFY_NONE`, no hostname check (`SSL_set1_host` missing), `CURLOPT_SSL_VERIFYPEER 0`/`VERIFYHOST 0`, ignoring `SSL_get_verify_result` | `SSL_VERIFY_PEER` + `SSL_set1_host`, curl defaults |  |
| `dotnet.md` | `ServerCertificateCustomValidationCallback = … => true`, `DangerousAcceptAnyServerCertificateValidator`, `ServicePointManager` callback | default validation |  |
| `elixir.md` | `:ssl` / `:httpc` with `verify: :verify_none` (Erlang/OTP <26 default for `:httpc`!), Hackney `insecure: true` | `verify: :verify_peer` + `cacerts: :public_key.cacerts_get()` | OTP 26+ verifies by default |
| `frontend-browser.md` | N/A — browser validates TLS. Mixed content (`http://` subresources) | HTTPS everywhere, HSTS |  |
| `go.md` | `InsecureSkipVerify: true`, custom `VerifyPeerCertificate` returning nil | default verification, `RootCAs` |  |
| `iac-ci.md` | `ssl_protocols TLSv1 TLSv1.1`, weak ciphers, Ingress without TLS, Ansible `validate_certs: no`, `curl -k` / `wget --no-check-certificate` in Dockerfiles/CI | TLS 1.2+, verified downloads |  |
| `java-kotlin.md` | trust-all `X509TrustManager`, `NoopHostnameVerifier`, `TrustAllStrategy`, `InsecureTrustManagerFactory` | default trust store, pinned CA | test-only clients |
| `javascript-node.md` | `rejectUnauthorized:false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, custom `checkServerIdentity` returning undefined | default verification, pinned CA via `ca` | test-only agents (check path) |
| `mobile-native.md` | ATS disabled, `usesCleartextTraffic`, trust-all `TrustManager`, `onReceivedSslError → handler.proceed()`, `URLSession` delegate accepting any `serverTrust`, Flutter `badCertificateCallback = (…) => true` | defaults + certificate pinning (`network_security_config.xml`, `TrustKit`) | debug-only configs (check build type) |
| `other-languages.md` | `LWP` with `verify_hostname => 0`, `SSL_verify_mode => SSL_VERIFY_NONE` · `lua_ssl_verify_depth` without `lua_ssl_trusted_certificate`, `ssl_verify=false` in `resty.http` · trust-all managers · — | verification on |  |
| `php.md` | `CURLOPT_SSL_VERIFYPEER false`, `VERIFYHOST 0`, Guzzle `verify => false`, stream context `verify_peer => false` | defaults |  |
| `python.md` | `verify=False`, `_create_unverified_context`, `CERT_NONE`, `check_hostname=False` | default verification, `certifi` | test code |
| `ruby.md` | `verify_mode = OpenSSL::SSL::VERIFY_NONE`, Faraday `ssl: { verify: false }` | defaults |  |
| `rust.md` | `danger_accept_invalid_certs(true)`, `danger_accept_invalid_hostnames`, rustls `dangerous().set_certificate_verifier(NoVerify)` | default verification |  |
| `scala.md` | custom `X509TrustManager` accepting all, Play WS `ssl-config.loose.acceptAnyCertificate = true`, `disableHostnameVerification = true` | defaults |  |
| `shell.md` | `curl -k`, `wget --no-check-certificate`, `git -c http.sslVerify=false`, PowerShell `-SkipCertificateCheck` / `ServerCertificateValidationCallback = {$true}` | defaults, `--cacert` |  |

## L25 — Secrets & insecure configuration

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | hardcoded keys/passwords in source or binaries (`strings` reveals them), debug backdoors behind `#ifdef DEBUG` shipped | external config, build flags audit |  |
| `dotnet.md` | secrets in `appsettings*.json`/`web.config`, `machineKey` committed, `<compilation debug="true">` | User Secrets / Key Vault, config transforms | `appsettings.Development.json` not loaded in prod |
| `elixir.md` | `secret_key_base`/DB passwords in `config/*.exs` committed, `debug_errors: true` in prod | `config/runtime.exs` with env vars | `dev.exs` not used in prod |
| `frontend-browser.md` | § Secrets in bundle: real secrets in `NEXT_PUBLIC_*`/`VITE_*`/`REACT_APP_*`, source maps in prod | server-side secrets | public keys / publishable keys are fine |
| `go.md` | secrets in `config.go`/YAML, `GIN_MODE=debug` in prod, `pprof` on public mux | env, separate admin mux |  |
| `iac-ci.md` | § secrets in Dockerfile `ENV/ARG`, compose `environment:`, K8s `Secret` manifests committed, `.tfvars`/`tfstate`, Ansible vars without Vault, PM2 `env:` literals; debug ports exposed | secret managers, Ansible Vault, sealed-secrets |  |
| `java-kotlin.md` | secrets in `application*.yml/properties`, Actuator `exposure.include=*`, `h2.console.enabled`, `ddl-auto=create` in prod | env/vault, minimal exposure | profile files not active in prod |
| `javascript-node.md` | secrets in `config*.js`, `process.env.X |  | 'default'`, `.env` committed, `NODE_ENV` dev in prod |
| `mobile-native.md` | API secrets/client secrets in source, `strings.xml`, `Info.plist`, `google-services.json` with unrestricted keys | backend-held secrets, key restrictions | Firebase/Maps keys are public by design if restricted |
| `other-languages.md` | credentials in `.pl`/`.conf` · secrets in `nginx.conf` Lua blocks · `application.yml`/`Config.groovy` secrets · private keys/mnemonics in `hardhat.config`/`.env` committed | env vars / secret stores |  |
| `php.md` | `APP_DEBUG=true`, `.env` committed, `wp-config.php` secrets, `display_errors=On` | env per environment | `.env.example` |
| `python.md` | `SECRET_KEY` committed, `DEBUG=True`, `ALLOWED_HOSTS=['*']`, Flask `debug=True` (Werkzeug console RCE) | env per environment | `settings/dev.py` not used in prod (check `DJANGO_SETTINGS_MODULE`) |
| `ruby.md` | `secret_key_base`/`master.key` committed, credentials in `database.yml` | Rails credentials (encrypted) + env key |  |
| `rust.md` | secrets in `config.toml`/`const`, `RUST_LOG=debug` in prod leaking bodies | env, `secrecy::Secret<String>` |  |
| `scala.md` | `play.http.secret.key = "changeme"` committed, secrets in `application.conf`, `play.mode = Dev` in prod | `${?ENV_VAR}` substitution |  |
| `shell.md` | hardcoded passwords/tokens in scripts, `ConvertTo-SecureString -AsPlainText` with literals, secrets in Makefiles | env/secret store, `Get-Secret` |  |

## L26 — Error handling & information disclosure

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | error messages exposing addresses (`%p`) / paths; core dumps enabled with secrets in memory | `prctl(PR_SET_DUMPABLE, 0)`, `RLIMIT_CORE=0` |  |
| `dotnet.md` | `UseDeveloperExceptionPage` outside Development, `customErrors mode="Off"`, `ProblemDetails` with exception messages | `UseExceptionHandler` |  |
| `elixir.md` | `debug_errors: true`, returning `inspect(error)` to clients | `ErrorView`/`ErrorJSON` |  |
| `frontend-browser.md` | verbose errors from API rendered to users; `console.error` with tokens | generic UI errors | see `../frontend-stacktrace-leaks.md` |
| `go.md` | `http.Error(w, err.Error(), 500)` with DB/internal errors, panics returning stack (`gin.Recovery` in debug) | generic message + log |  |
| `iac-ci.md` | `server_tokens on`, `autoindex on`, default error pages revealing versions | `server_tokens off` |  |
| `java-kotlin.md` | `include-stacktrace=always`, `printStackTrace` to response, Whitelabel errors with messages | `include-message=never`, `@ControllerAdvice` |  |
| `javascript-node.md` | `res.json({error: err.message/stack})`; Express default handler in dev mode leaks stack | generic message + correlation id | stack only when `NODE_ENV=development` |
| `mobile-native.md` | verbose crash/error dialogs with server responses; debug menus in release builds | strip in release |  |
| `other-languages.md` | `CGI::Carp qw(fatalsToBrowser)` · `ngx.say(err)` · Grails stack traces in prod · revert reasons leaking nothing sensitive (on-chain data is public anyway) | generic errors |  |
| `php.md` | Whoops/Ignition error pages in prod (Ignition RCE CVE-2021-3129 on old versions), `var_dump` to output | `APP_DEBUG=false`, generic errors |  |
| `python.md` | `traceback.format_exc()` in responses, `DEBUG=True` error pages, FastAPI `debug=True` | generic errors |  |
| `ruby.md` | `consider_all_requests_local = true` in prod, exception messages in JSON responses | `rescue_from` with generic messages |  |
| `rust.md` | returning `format!("{:?}", err)` to clients (DB/internal paths), `anyhow` chain in responses | map to generic error responses |  |
| `scala.md` | Play dev-mode error pages in prod, `InternalServerError(e.getMessage)` | `HttpErrorHandler` with generic output |  |
| `shell.md` | scripts echoing full command lines/env on failure (`env`, `printenv`) | targeted error messages |  |

## L27 — Logging & privacy (PII)

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | logging secrets/PII via `syslog`; secrets not wiped (`memset` optimized away) | `explicit_bzero`/`OPENSSL_cleanse`, redaction |  |
| `dotnet.md` | logging `Authorization` headers, model objects with passwords, `EnableSensitiveDataLogging()` in EF | redaction (`Microsoft.Extensions.Compliance.Redaction`) |  |
| `elixir.md` | `Logger.info(inspect(params))` with passwords; Phoenix `filter_parameters` missing custom keys | `config :phoenix, :filter_parameters, [...]` |  |
| `frontend-browser.md` | PII/tokens in URLs (referrer leakage), analytics payloads with PII | POST bodies, redaction |  |
| `go.md` | `log.Printf("%+v", req)` / logging tokens, request dumps (`httputil.DumpRequest`) | redaction |  |
| `iac-ci.md` | access logs capturing `Authorization`/query tokens; CI logs printing secrets (`set -x`); Ansible tasks without `no_log: true` on secrets | log formats excluding sensitive fields, `no_log` |  |
| `java-kotlin.md` | logging `getParameterMap()`, `Authorization` headers, PII in MDC; Log4Shell (<2.17) with user input | masking layouts, upgrade |  |
| `javascript-node.md` | `log.info(req.body/headers)`, logging OTP/token/PAN/Aadhaar | redaction/masking serializers | check which keys the masking layer covers |
| `mobile-native.md` | `Log.d`/`NSLog`/`print` of tokens/PII in release, analytics with PII, clipboard holding OTP/card data | `ProGuard` stripping, `os_log` privacy `%{private}` |  |
| `other-languages.md` | logging params/passwords · `ngx.log(ngx.ERR, ngx.req.get_body_data())` · logging params · — (all on-chain data is public: never store PII/secrets in contract storage, even `private`) | redaction · off-chain storage of PII | `private` Solidity variables are readable |
| `php.md` | logging `$_POST`/passwords, Monolog without processors for PII | redaction processors |  |
| `python.md` | `logger.info(request.data)`, logging passwords/tokens, Sentry `send_default_pii=True` | filters / scrubbing |  |
| `ruby.md` | logging params without `filter_parameters` (`password`, `token`, `otp`, `card`) | `config.filter_parameters += [...]` |  |
| `rust.md` | `Debug` derive on structs with passwords/tokens logged via `{:?}` | `secrecy` crate, manual `Debug` |  |
| `scala.md` | logging request bodies / `Authorization` headers, case class `toString` with secrets in logs | override `toString`, masking |  |
| `shell.md` | `set -x` with secrets, `history` files containing tokens, logging `$@` | `set +x` around secrets, `HISTCONTROL=ignorespace` |  |

## L28 — DoS (ReDoS, limits, exhaustion)

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | `std::regex` on user input (backtracking + stack overflow), unbounded `malloc` from length fields, recursion depth from input, fd/thread exhaustion | RE2, size caps, iterative parsing |  |
| `dotnet.md` | `new Regex(user)` / no `matchTimeout`, `[DisableRequestSizeLimit]`, unbounded `Take`, `MaxRequestBodySize = null` | `RegexOptions.NonBacktracking`, limits |  |
| `elixir.md` | `String.to_atom(user)` atom exhaustion, `Regex.compile(user)` (PCRE backtracking), unbounded `Plug.Parsers` `length`, mailbox flooding of a GenServer | `String.to_existing_atom`, length limits, back-pressure |  |
| `frontend-browser.md` | client ReDoS on user input (self-DoS only, low); unbounded rendering | — | usually Low/Info |
| `go.md` | no `ReadHeaderTimeout` (Slowloris), `io.ReadAll(r.Body)` unbounded, unbounded goroutines, `json.Decoder` without limits | timeouts, `MaxBytesReader`, worker pools | `regexp` is RE2 — ReDoS N/A |
| `iac-ci.md` | no `limit_req`/`limit_conn`, no K8s resource limits, no HPA ceilings, unlimited `client_max_body_size` | rate limits, quotas |  |
| `java-kotlin.md` | `Pattern.compile(user)`, backtracking regex on input (Java regex backtracks), unbounded `Pageable`, `max-file-size=-1`, XML bombs | bounded regex/input, `max-page-size` |  |
| `javascript-node.md` | `new RegExp(user)`, nested quantifiers on input, no body limit, unbounded `limit` query, sync crypto/fs in handlers, `JSON.parse` of huge body | `re2`/`safe-regex`, body limits, pagination caps | constant regex on short bounded input |
| `mobile-native.md` | N/A for server DoS; app crash loops from malformed deep links/intents (local DoS, low) | input validation | usually Low |
| `other-languages.md` | regex backtracking on input · `ngx.re` PCRE backtracking, unbounded `ngx.req.read_body` · regex/GORM unbounded queries · unbounded loops over user-growable arrays (gas DoS), push-payment DoS (revert in receiver) | bounded loops, pull-payment pattern |  |
| `php.md` | `preg_match` with user pattern / catastrophic regex (`pcre.backtrack_limit`), `max_input_vars`, hash-collision DoS (old PHP), unbounded `LIMIT` | `preg_quote`, limits |  |
| `python.md` | `re.compile(user)`, catastrophic regex on input (Python `re` backtracks), unbounded `page_size`, no upload size limits, `json.loads` on huge bodies, zip bombs | `re2`/`regex` with timeout, size caps |  |
| `ruby.md` | `Regexp.new(params[:q])`, backtracking regex (Ruby <3.2 no timeout), unbounded `per_page`, `JSON.parse` huge bodies | `Regexp.timeout` (3.2+), `Regexp.escape`, limits |  |
| `rust.md` | `unwrap()`/`expect()`/indexing on user input → panic (task dies; `panic="abort"` kills process); unbounded bodies (`DefaultBodyLimit::disable`); `fancy-regex` backtracking | `?` error propagation, body limits, `regex` crate | `regex` crate is linear-time — ReDoS N/A |
| `scala.md` | `.r` / `Pattern.compile` on user regex, backtracking regex on input, `parsing.max-content-length = infinite`, unbounded `Source` streams | bounded parsers, `withSizeLimit`, `take(n)` |  |
| `shell.md` | fork bombs from user-controlled loop counts, unbounded `find`/`grep` on user paths, `yes`-style output to logs | bounds, `timeout` command |  |

## L29 — Race conditions / TOCTOU / concurrency

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | § Command/file TOCTOU (`access`→`open`), data races on globals, signal-handler reentrancy, `std::shared_ptr` refcount OK but pointee not thread-safe | `O_EXCL`, mutexes/atomics, async-signal-safe handlers |  |
| `dotnet.md` | read-modify-write without `RowVersion`/`[ConcurrencyCheck]` or transaction isolation, `async void`, static mutable state in singletons | optimistic concurrency, `Interlocked`, scoped services |  |
| `elixir.md` | check-then-act across processes without DB locks, GenServer state races when callers bypass the server, Oban jobs without `unique` | `Repo.transaction` + `lock: "FOR UPDATE"`, single-writer GenServer, Oban `unique` | BEAM processes don't share memory |
| `frontend-browser.md` | double-submit of payment buttons (server must be idempotent) | idempotency keys server-side | client debounce isn't security |
| `go.md` | `concurrent map writes` (crash), shared state without `sync.Mutex`, check-then-act on balances without `SELECT … FOR UPDATE`/`clause.Locking`; run tests with `-race` | mutex/`sync.Map`, DB locks, atomic UPDATE |  |
| `iac-ci.md` | CI deploy jobs running concurrently on the same environment (no `concurrency:` group), Terraform without state locking | `concurrency:` groups, DynamoDB/remote state lock |  |
| `java-kotlin.md` | check-then-act on balances without `@Lock(PESSIMISTIC_WRITE)`/`@Version`; `@Transactional` self-invocation (proxy bypass → no transaction); non-thread-safe singletons (`SimpleDateFormat`, mutable fields in `@Service`) | locking, atomic UPDATE, immutable beans |  |
| `javascript-node.md` | read-modify-write on balance/seat without transaction or atomic `$inc`/`findOneAndUpdate`; `await` between check and act; shared module-level state across requests | DB transactions, atomic operators, unique indexes, Redis `SET NX` locks | single-threaded JS still races across `await` and across PM2 workers |
| `mobile-native.md` | double-tap payment submission (server must be idempotent), shared mutable state across threads (Swift `actor` misuse, Kotlin coroutines) | idempotency keys server-side |  |
| `other-languages.md` | file locking races in CGI · shared dict (`ngx.shared`) check-then-set races across workers · GORM without `lock: true` · **reentrancy** (external call before state update), front-running / transaction ordering | `flock` · `ngx.shared:add` (atomic) · pessimistic locks · checks-effects-interactions + `ReentrancyGuard`, commit-reveal |  |
| `php.md` | balance updates without `lockForUpdate()`/transactions, file-based counters without `flock` | `DB::transaction` + `lockForUpdate`, atomic `UPDATE … SET x = x - ?` |  |
| `python.md` | read-modify-write without `select_for_update()`/`F()` expressions; check-then-create without unique constraint; Celery task double-execution; GIL does not prevent races across processes | `transaction.atomic` + `select_for_update`, `F('balance') - x`, idempotency keys |  |
| `ruby.md` | balance updates without `with_lock`/`lock!`, `find_or_create_by` races without unique index, Sidekiq job double-run | `with_lock`, unique indexes, `update_counters`, idempotent jobs |  |
| `rust.md` | check-then-act across `.await` with separate lock acquisitions; DB read-modify-write without `FOR UPDATE`; `std::sync::Mutex` held across `.await` (deadlock) | single critical section, DB transactions, `tokio::sync::Mutex` | safe Rust prevents data races, not logic races |
| `scala.md` | mutable `var` in actors accessed from `Future` callbacks (closing over actor state), check-then-act on DB without transactions, `Future` races on shared mutable maps | actor messages only, `TrieMap`, `Ref`/STM, DB locks |  |
| `shell.md` | predictable `/tmp/name` (symlink attacks, TOCTOU), `[ -f x ] && cat x` races, concurrent cron runs without lock | `mktemp`, `flock`, `set -o noclobber` |  |

## L30 — Business logic & numeric/type confusion

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | integer overflow/underflow/signedness in size math, `size_t`↔`int` conversions, `atoi` (no error) | `strtol` + range checks, `__builtin_*_overflow`, `-ftrapv`/UBSan in tests |  |
| `dotnet.md` | `double` for money, unchecked arithmetic overflow (default unchecked), client totals trusted | `decimal`, `checked { }`, server recompute |  |
| `elixir.md` | float money, negative quantities, client totals trusted | `Decimal`, changeset validations |  |
| `frontend-browser.md` | price/discount/quantity/role computed client-side and trusted by API | server recomputes |  |
| `go.md` | integer overflow when converting `int64`→`int32`/`uint`, float money, negative quantities, `strconv.Atoi` without bounds | bounds checks, integer minor units |  |
| `iac-ci.md` | deploy pipelines skippable from any branch, missing environment approvals | protected environments |  |
| `java-kotlin.md` | `double` for money, `Integer.parseInt` overflow, negative quantities, client totals trusted | `BigDecimal`, `Math.addExact`, server recompute |  |
| `javascript-node.md` | client-sent price/amount trusted; `parseInt` without radix/NaN check; float money math; qs array/object type confusion (`?amount[]=1`) | recompute server-side, integers in minor units, schema validation (Joi/Zod) |  |
| `mobile-native.md` | client-side price/entitlement checks (in-app purchase validated only on device), jailbreak/root checks as the only control | server-side receipt validation |  |
| `other-languages.md` | numeric string comparisons (`==` vs `eq`) · Lua numbers are doubles (money precision) · `Double` money · integer overflow (<0.8 / `unchecked`), rounding/precision loss in division before multiplication, unchecked `call` return values | `eq` for strings · integer minor units · `BigDecimal` · Solidity ≥0.8 checked math, multiply-before-divide, check `(bool ok,) = …call` |  |
| `php.md` | type juggling: `==` with `"0e…"` magic hashes, `strcmp` with arrays (<8), `in_array` non-strict, `switch` loose, `intval` truncation, float money | `===`, `hash_equals`, `in_array(..., true)`, `bcmath` |  |
| `python.md` | float money (`float(amount)`), negative quantities, trusting client totals, `int()` of huge strings (CVE-2020-10735 DoS, limited since 3.11) | `Decimal`, server recompute, bounds |  |
| `ruby.md` | Float money, negative quantities, `to_i` silently returning 0 on bad input | `BigDecimal`, `Integer(x)` (raises), validations |  |
| `rust.md` | release builds wrap integer overflow silently (`overflow-checks=false`); `as` casts truncate (`u64 as u32`, `i64 as usize`); float money | `checked_*`/`try_into()`, `rust_decimal` |  |
| `scala.md` | `Double` money, `Int` overflow on `toInt`, negative quantities | `BigDecimal`, `Math.addExact`, refined types |  |
| `shell.md` | arithmetic `$(( $x ))` evaluating `x='a[$(cmd)]'` (bash arithmetic command injection), string vs number comparison (`[ "$a" \> "$b" ]`) | validate `[[ $x =~ ^[0-9]+$ ]]` before arithmetic |  |

## L31 — Memory safety / unsafe / FFI

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | § Memory corruption: overflow (`strcpy/sprintf/gets/memcpy`), off-by-one, UAF, double free, uninitialized reads, VLAs/`alloca`; C++ iterator invalidation, dangling `string_view`/`c_str()` | bounded APIs, RAII/smart pointers, `std::span`, ASan/MSan/UBSan + fuzzing, hardening flags | fixed-size literal copies into larger buffers are fine |
| `dotnet.md` | `unsafe` blocks, `fixed`, `stackalloc` with user size, `Marshal.*`, P/Invoke (`DllImport`) buffers | `Span<T>` with bounds, safe wrappers; native code → `c-cpp.md` | managed C# is memory-safe |
| `elixir.md` | NIFs (C/Rust via Rustler) can crash the whole VM → `c-cpp.md` / `rust.md` | dirty schedulers, safe Rustler code | pure Elixir is memory-safe |
| `frontend-browser.md` | N/A — no memory unsafety in JS. WebAssembly modules from C/C++ → `c-cpp.md` | — |  |
| `go.md` | `unsafe.Pointer` arithmetic, cgo (`import "C"`) buffer handling, `reflect.SliceHeader` misuse | avoid `unsafe`; see `c-cpp.md` for C code | safe Go is memory-safe (data races can still corrupt) |
| `iac-ci.md` | `privileged: true`, `SYS_ADMIN`, `seccomp:unconfined`, docker.sock mounts (container escape surface) | drop capabilities, RuntimeDefault seccomp |  |
| `java-kotlin.md` | JNI (`native`, `System.loadLibrary` → `c-cpp.md`), `sun.misc.Unsafe`, `ByteBuffer.allocateDirect` misuse | — | managed Java/Kotlin is memory-safe |
| `javascript-node.md` | native addons (`node-gyp`, N-API) buffer handling; `Buffer.allocUnsafe` exposed to clients; `new Buffer(n)` (deprecated, uninitialized) | `Buffer.alloc`; see `c-cpp.md` for addon source | pure JS has no memory corruption |
| `mobile-native.md` | Swift `UnsafePointer`/`UnsafeMutableRawPointer`, ObjC C buffers, JNI/NDK native code → `c-cpp.md` | safe Swift/Kotlin APIs |  |
| `other-languages.md` | XS modules → `c-cpp.md` · LuaJIT FFI (`ffi.cast`, `ffi.copy`) with user sizes · JNI → `c-cpp.md` · — (EVM is memory-safe; storage collisions in proxies are the analogue: unstructured storage slots) | bounds checks · EIP-1967 storage slots |  |
| `php.md` | N/A for PHP code; native extensions (`ext/*.c`) → `c-cpp.md`; FFI extension (`FFI::cdef`) with user data | disable FFI (`ffi.enable=0`) |  |
| `python.md` | `ctypes`/`cffi` pointer use, C extensions (→ `c-cpp.md`), `memoryview` of freed buffers in extensions | — | pure Python is memory-safe |
| `ruby.md` | N/A for Ruby code; C extensions (`ext/*.c`) → `c-cpp.md`; `Fiddle`/FFI with user data | — |  |
| `rust.md` | § Memory safety: `unsafe` blocks, `from_raw_parts`, `get_unchecked`, `set_len`, `transmute`, `static mut`, `unsafe impl Send/Sync`, FFI `CStr::from_ptr`, dangling `CString::as_ptr()` | safe abstractions, `miri` testing | memory bugs only in `unsafe`/FFI |
| `scala.md` | N/A for Scala code (JVM memory-safe); JNI / Scala Native `Ptr` / `unsafe` → `c-cpp.md` | — |  |
| `shell.md` | N/A — shell has no direct memory access; binaries invoked follow their own pack | — |  |

## L32 — Supply chain

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | vendored third-party sources without version tracking, `FetchContent`/`ExternalProject` from git branches without hash, Conan/vcpkg unpinned, `curl … | sh` in build scripts | pinned commits/hashes, `URL_HASH` |
| `dotnet.md` | NuGet without lock file (`packages.lock.json`), floating versions (`1.*`), multiple feeds without source mapping (dependency confusion), MSBuild targets in packages | `RestorePackagesWithLockFile`, package source mapping | SCA opt-in |
| `elixir.md` | `mix.exs` deps from git branches, Hex packages unpinned, `mix.lock` missing, compile-time code execution in deps | `mix.lock`, `mix hex.audit` | SCA opt-in |
| `frontend-browser.md` | CDN scripts without SRI, third-party tags (GTM) with DOM access, `npm` deps (see Node L32) | SRI, CSP `script-src` allow-list |  |
| `go.md` | `replace` directives to forks/local paths, `GOINSECURE`/`GONOSUMDB`/`GOFLAGS=-insecure`, `go get` of unpinned `@latest` in CI | `go.sum` committed, `GOFLAGS=-mod=readonly`, `GOPROXY` + sumdb | SCA opt-in |
| `iac-ci.md` | § CI supply chain: unpinned actions/images (`@main`, `:latest`), `curl | sh`, `npm install` vs `npm ci`, `pull_request_target` + checkout of PR head, self-hosted runners on public repos | SHA pins, digests, lockfiles, isolated runners |
| `java-kotlin.md` | unpinned/`LATEST` Maven versions, HTTP repositories, Gradle plugins from untrusted repos, dependency confusion via mixed internal/public repos | pinned versions, HTTPS repos, dependency verification (`verification-metadata.xml`) | SCA opt-in (`../maven-sca-scan.md`) |
| `javascript-node.md` | `preinstall/postinstall` scripts in deps, unpinned `*`/`latest`, missing lockfile, `npm install` in CI instead of `npm ci`, typosquats, git-URL deps | lockfile + `npm ci`, `--ignore-scripts` where possible | SCA is opt-in (code-only default) |
| `mobile-native.md` | CocoaPods/SPM/Gradle/pub deps unpinned, third-party SDKs with broad permissions, `Podfile` sources over HTTP | lockfiles (`Podfile.lock`, `Package.resolved`, `pubspec.lock`) | SCA opt-in |
| `other-languages.md` | CPAN deps unpinned (`cpanfile` without versions) · LuaRocks unpinned · Grails/Gradle deps unpinned · npm/forge libs unpinned, copied OpenZeppelin code modified | `cpanfile.snapshot` · pinned rocks · locks · pinned audited versions | SCA opt-in |
| `php.md` | `composer.json` scripts (`post-install-cmd`), unpinned `*`/`dev-master`, VCS repositories, `composer install` without lock | `composer.lock` + `--no-scripts` in CI where possible | SCA opt-in |
| `python.md` | unpinned `requirements.txt`, `pip install` without hashes, `setup.py` executing code at install, `--extra-index-url` dependency confusion, typosquats | pinned + `--require-hashes`, single index | SCA opt-in |
| `ruby.md` | `source 'http://…'`, `git:`/`github:` gems on branches, `Gemfile.lock` missing, gems with native extensions compiling at install | HTTPS source, lockfile, pinned refs | SCA opt-in |
| `rust.md` | `build.rs` running arbitrary code at build, git/path deps, `[patch]` overrides, proc-macro crates with network access, typosquats | `Cargo.lock` committed, `cargo vet`/`cargo deny` | SCA opt-in |
| `scala.md` | sbt plugins from untrusted resolvers, `resolvers += "…" at "http://…"`, SNAPSHOT/`latest.integration` versions | HTTPS resolvers, pinned versions, `sbt-dependency-lock` | SCA opt-in |
| `shell.md` | `curl … | bash` installers, downloading tools without checksum, `pip/npm install` without lockfiles in scripts | pinned versions + `sha256sum -c` |

## L33 — API protocols (GraphQL, WebSocket, gRPC)

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | gRPC C++ without auth (`InsecureServerCredentials`), WebSocket servers (Boost.Beast, uWebSockets) without origin/auth checks | `SslServerCredentials` + auth metadata processor |  |
| `dotnet.md` | HotChocolate without `MaxExecutionDepth`/cost analysis, introspection on; SignalR hubs without `[Authorize]`; gRPC services without auth | limits, hub/method authorization |  |
| `elixir.md` | Absinthe without `max_complexity`/depth, introspection on; Phoenix Channels `join` without auth; `check_origin: false` | `Absinthe.Plug` `analyze_complexity: true`, socket `connect/3` auth |  |
| `frontend-browser.md` | GraphQL queries built by string concat client-side; WebSocket messages rendered via `innerHTML` | variables in GraphQL; text rendering |  |
| `go.md` | gRPC without auth interceptor, `reflection.Register` in prod, gqlgen without complexity limit, `gorilla/websocket` `CheckOrigin: func(r) bool { return true }` | interceptors, `extension.FixedComplexityLimit`, origin check |  |
| `iac-ci.md` | gRPC/GraphQL/WebSocket endpoints exposed via Ingress without auth or WAF; `proxy_set_header Upgrade` on all paths | path-scoped upgrades, auth at gateway |  |
| `java-kotlin.md` | Spring GraphQL without depth/complexity limits or field auth; STOMP `@MessageMapping` without auth/destination checks; gRPC services without `ServerInterceptor` auth, reflection service on | instrumentation limits, `@PreAuthorize` on resolvers, interceptors |  |
| `javascript-node.md` | GraphQL introspection in prod, no depth/cost limit, per-resolver auth missing; `ws`/socket.io without auth on `connection`, no origin check | `graphql-depth-limit`, resolver auth, `verifyClient`/handshake auth | see `../protocol-scans-graphql-ws-grpc.md` |
| `mobile-native.md` | GraphQL/WebSocket clients without TLS pinning; gRPC with plaintext channels (`ManagedChannelBuilder.usePlaintext()`) | TLS channels |  |
| `other-languages.md` | — · OpenResty WebSocket (`resty.websocket.server`) without auth/origin check · Grails GraphQL plugin without limits · — | auth on upgrade |  |
| `php.md` | Lighthouse/webonyx GraphQL without depth/complexity limits or `@can` guards; Ratchet/Laravel WebSockets channels without auth (`routes/channels.php` returning true) | `QueryDepth`/`QueryComplexity` rules, channel auth callbacks |  |
| `python.md` | Graphene/Strawberry introspection on, no depth limit, resolver auth missing; Django Channels consumers without auth/origin (`AllowedHostsOriginValidator`); gRPC without interceptor auth | depth limit, `AuthMiddlewareStack`, origin validator |  |
| `ruby.md` | graphql-ruby without `max_depth`/`max_complexity`, field-level authorization missing; ActionCable channels without `reject` on unauthenticated `connect` | schema limits, `authorized?`, `identified_by` + reject |  |
| `rust.md` | `async-graphql` without `limit_depth`/`limit_complexity`, introspection on; `tonic` without interceptor auth; WebSocket upgrade without auth/origin check | schema limits, interceptors, origin validation |  |
| `scala.md` | Sangria/Caliban GraphQL without depth/complexity limits; Akka WebSocket `handleWebSocketMessages` without auth; gRPC (akka-grpc / fs2-grpc) without auth | `QueryReducer.rejectMaxDepth`, auth directives |  |
| `shell.md` | `websocat`/`grpcurl` usage with plaintext (`-plaintext`) in prod scripts | TLS |  |

## L34 — Unsafe reflection / dynamic dispatch

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | `dlsym(handle, user_symbol)`, function-pointer tables indexed by unchecked input | bounds-checked index, allow-list |  |
| `dotnet.md` | `Type.GetType(user)` + `Activator.CreateInstance`, `MethodInfo.Invoke` by user name, `Assembly.Load(user)` | allow-list |  |
| `elixir.md` | `apply(String.to_atom(mod), …)`, `Module.concat([user])` | dispatch map |  |
| `frontend-browser.md` | `window[userKey]()`, dynamic component names from query (`<component :is="user">`) | allow-list map |  |
| `go.md` | `reflect.ValueOf(obj).MethodByName(user).Call(...)`, `plugin.Open` | explicit switch/map |  |
| `iac-ci.md` | N/A — no reflection; analogue is CI loading actions/plugins by name from untrusted input (`uses: ${{ inputs.action }}`), Jenkins shared libraries from unpinned branches | pinned libraries/actions |  |
| `java-kotlin.md` | `Class.forName(user)`, `getMethod(user).invoke`, `URLClassLoader` with user URL, Spring `BeanWrapper` property paths from input | allow-list |  |
| `javascript-node.md` | `obj[req.query.method]()` dynamic dispatch, `require(path)` from input, `global[name]` | allow-listed handler map |  |
| `mobile-native.md` | `NSClassFromString(user)`/`performSelector(NSSelectorFromString(user))`, Android reflection `Class.forName(intentExtra)` | allow-list |  |
| `other-languages.md` | `&{"main::$name"}()` symbolic refs, `$obj->$method()` from input · `_G[name]()` · `obj."$method"()` dynamic dispatch, `Class.forName` · `delegatecall`/`call` with user-supplied selector | `use strict 'refs'`, dispatch tables · allow-list |  |
| `php.md` | `new $className()` from input, `call_user_func([$obj, $_GET['m']])`, `ReflectionClass($user)` | allow-list |  |
| `python.md` | `getattr(module, user)()`, `globals()[user]`, `importlib.import_module(user)`, `pickle` find_class | allow-list dispatch |  |
| `ruby.md` | `params[:type].constantize`, `Object.const_get(user)`, `send(user)` | allow-list hash |  |
| `rust.md` | `libloading::Library::new(user)`, dynamic dispatch by user string into function tables | static match |  |
| `scala.md` | `Class.forName(user)`, Scala reflection `runtimeMirror.reflectModule(user)` | allow-list |  |
| `shell.md` | dynamic function names `"$cmd"_handler` / `${!var}` indirect expansion from input | case statement |  |

## L35 — Language-specific pitfalls

| Pack | Vulnerable | Safe equivalent | FP trap / note |
|------|-----------|-----------------|----------------|
| `c-cpp.md` | undefined behaviour optimized into security bugs (null check removed after deref, signed overflow assumptions), `strncpy` non-termination, `scanf` without width, `gets` | compile with `-Wall -Wextra -Werror`, sanitizers |  |
| `dotnet.md` | `string.Equals` without `Ordinal` (culture issues in security checks, e.g. Turkish `i`), `async void` exceptions crash process, `ToString()` of entities leaking secrets | `StringComparison.Ordinal`, `CryptographicOperations.FixedTimeEquals` |  |
| `elixir.md` | `String.to_atom` from input, `==` vs `Plug.Crypto.secure_compare` for tokens, `with` clauses falling through on unexpected error tuples (fail-open) | `secure_compare`, explicit `else` in `with` |  |
| `frontend-browser.md` | `postMessage` without `origin` check; `window.opener` access; Electron `nodeIntegration`; service-worker scope hijack | origin check, `contextIsolation` |  |
| `go.md` | ignored errors (`_ = err`) turning auth failures into success, nil-map writes / nil-pointer panics (DoS), loop-variable capture in goroutines (fixed in Go 1.22), `defer` in loops leaking fds, `time.After` leaks | handle every error, `errcheck` lint |  |
| `iac-ci.md` | YAML anchors/merge keys hiding overrides; Helm `--set` overriding security values; Terraform `count`/`for_each` silently skipping security resources; Ansible `ignore_errors: yes` on security tasks | review rendered manifests (`helm template`, `terraform plan`) |  |
| `java-kotlin.md` | `==` on `String` (identity) in auth checks; Kotlin `!!` NPE DoS; `Optional.get()`; `equals` timing for secrets (`MessageDigest.isEqual`); Kotlin data class `copy()` exposing fields; Lombok `@Data` `toString` leaking secrets in logs | `.equals`, `isEqual`, `@ToString.Exclude` |  |
| `javascript-node.md` | `==` coercion in auth checks; `qs` deep objects; `async` errors unhandled crash the process (DoS); `setTimeout(string)`; `vm` sandbox assumption; Express 4 does not catch rejected promises | `===`, `express-async-errors` / try-catch, `process.on('unhandledRejection')` logging |  |
| `mobile-native.md` | `PendingIntent` mutable/implicit (hijack), sticky broadcasts, iOS pasteboard sharing (`UIPasteboard.general`), Flutter `MethodChannel` handlers trusting any caller, RN `originWhitelist={['*']}` | `FLAG_IMMUTABLE` explicit intents, local pasteboards, origin allow-lists |  |
| `other-languages.md` | missing `use strict; use warnings`; list vs scalar context bugs (`param()` returning lists → hash injection, CVE-2014-1572 style) · Lua 1-based indexes / `nil` holes; global variable leakage without `local` (shared across OpenResty requests) · Groovy truthiness (empty string/0 → false) in auth checks · Solidity: `msg.value` reused in loops, `transfer` 2300-gas stipend assumptions, `extcodesize` checks bypassed in constructors | `scalar($q->param('x'))` · `local` everywhere, `lua-releng` · explicit comparisons · audited patterns |  |
| `php.md` | register_globals-style `extract()`, `$$var` variable variables from input, `parse_str` overwriting vars, `null` from failed functions used in `==` checks | explicit assignment, strict types (`declare(strict_types=1)`) |  |
| `python.md` | `assert` used for auth checks (stripped with `-O`); mutable default args shared across requests; `is` vs `==` on strings; `tempfile.mktemp`; `zipfile` path trust; `format_map` attribute access | explicit `if … raise`, `mkstemp` |  |
| `ruby.md` | `respond_to?`-based dispatch, `method_missing` exposing internals, `==` vs `secure_compare` for tokens, symbol creation from input (DoS on Ruby <2.2) | `ActiveSupport::SecurityUtils.secure_compare` |  |
| `rust.md` | `unwrap` on `Option` from user input; `Rc<RefCell>` borrow panics; `mem::forget` leaks; `Drop` not running on `process::exit`; secrets not zeroized (`zeroize` crate) | `?`, `zeroize` |  |
| `scala.md` | `Option.get` / `.head` on empty user input (exceptions → 500/DoS), implicit conversions hiding unsafe types, pattern matches non-exhaustive on security enums | `getOrElse`, `-Xfatal-warnings` with exhaustiveness |  |
| `shell.md` | missing `set -euo pipefail` (failures ignored → fail-open), `IFS` manipulation, `[ $x = y ]` with empty `$x` errors, aliases/functions shadowing commands via sourced files, PowerShell `$null -eq` comparison order | `set -euo pipefail`, `[[ ]]`, `shellcheck` clean |  |
