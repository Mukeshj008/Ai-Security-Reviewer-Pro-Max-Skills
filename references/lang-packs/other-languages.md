# Pack: Other languages — Perl, Lua (incl. OpenResty), Groovy, Solidity

**Detect:** `*.pl`, `*.pm`, `*.cgi` with perl shebang, `cpanfile` (Perl) · `*.lua`, `nginx.conf` with `content_by_lua*` (Lua/OpenResty) · `*.groovy`, `*.gsp`, Grails `grails-app/` (Groovy — Jenkinsfiles go to `iac-ci.md`) · `*.sol`, `hardhat.config.*`, `foundry.toml` (Solidity).

Load only the sub-pack(s) the inventory detected. Each index cell is written as `Perl · Lua · Groovy · Solidity` where they differ; "—" means not applicable for that language.

## Perl essentials

Taint mode (`#!perl -T`) catches some flows; check it's on for CGI. `open(my $fh, $user)` (2-arg open) interprets `|cmd` / `>file` → command execution / file overwrite; use 3-arg `open($fh, '<', $path)`. `system("cmd $x")` uses a shell when given one string; `system('cmd', $x)` doesn't. DBI `$dbh->do("… $x")` vs placeholders `?`. `eval $string` executes code; `eval { }` block is exception handling (safe). Regex with `(?{ code })` from user input requires `use re 'eval'`.

## Lua / OpenResty essentials

`loadstring(user)`/`load(user)` executes code; `os.execute`, `io.popen` with concatenation → command injection. OpenResty: `ngx.var.arg_*`, `ngx.req.get_uri_args()` (returns tables for repeated keys — type confusion), `ngx.say(user)` with HTML → XSS, `ngx.redirect(user)`, `ngx.location.capture(user)` / `resty.http` with user URLs → SSRF. `ngx.re.match` with user patterns → ReDoS (PCRE). Lua string patterns are not regex but `string.rep`/`gsub` can still be abused for CPU.

## Groovy essentials

GString `"… ${x}"` passed to `Sql.execute` is **parameterized** by groovy.sql (it converts `${}` to `?`), but `Sql.execute(query.toString())` or string concatenation is not. `Eval.me(user)`, `GroovyShell().evaluate(user)`, `"cmd $x".execute()` (tokenized, no shell) vs `["sh","-c",x].execute()` (shell). GSP `${x}` escaping depends on `grails.views.default.codec` (`html` in modern Grails; `none` in old configs) — verify config. XML: `XmlSlurper`/`XmlParser` resolve DOCTYPE unless configured.

## Solidity essentials

Not a web stack; classes map to smart-contract bugs: reentrancy (external call before state update), access control (`onlyOwner` missing, `tx.origin` auth), unchecked external call return values, integer overflow (<0.8 without SafeMath; `unchecked {}` blocks in ≥0.8), `delegatecall` to user-controlled addresses, weak randomness (`block.timestamp`, `blockhash`), front-running, signature replay (no nonce/chainId), `selfdestruct`, uninitialized proxies.

## Hint rg

```bash
P='--glob *.{pl,pm,cgi,t}'; L='--glob *.lua --glob *nginx*.conf'; GR='--glob *.{groovy,gsp} -g !Jenkinsfile*'; S='--glob *.sol -g !node_modules/** -g !lib/**'
rg -n "open\s*\(\s*\w+\s*,\s*[\"\$]|open\s+\w+\s*,\s*\"|system\s*\(\s*\"|\`|qx\s*[\(\{/]|eval\s+\\\$|->do\s*\(\s*\"[^\"]*\\\$|->prepare\s*\(\s*\"[^\"]*\\\$" $P
rg -n "loadstring|load\s*\(|os\.execute|io\.popen|ngx\.say|ngx\.print|ngx\.redirect|ngx\.location\.capture|resty\.http|ngx\.re\.(match|find|gsub)|get_uri_args|ngx\.var\.arg_" $L
rg -n "Eval\.me|GroovyShell|\.execute\s*\(\s*\)|Sql\.(execute|rows|eachRow)\s*\([^)]*\+|\.toString\s*\(\s*\)\s*\)|XmlSlurper|XmlParser|default\.codec" $GR
rg -n "tx\.origin|delegatecall|\.call\{|\.call\.value|selfdestruct|block\.(timestamp|number|difficulty)|blockhash|unchecked\s*\{|ecrecover|onlyOwner|initializer" $S
```

## Class coverage index

| ID | Perl · Lua/OpenResty · Groovy · Solidity — vulnerable | Safe equivalent | FP trap / note |
|----|------------------------------------------------------|-----------------|----------------|
| L01 | Perl CGI `print "<p>$q</p>"` · `ngx.say("<p>"..arg.."</p>")` · GSP `${x}` with `default.codec=none`, `<%= %>`, `raw()` · Solidity — (frontend dApp → `frontend-browser.md`) | `HTML::Entities::encode_entities` · `ngx.escape_uri`/HTML encoder · `codec=html`, `${x.encodeAsHTML()}` | Grails ≥2.3 defaults to HTML codec |
| L02 | Template Toolkit / HTML::Template with user templates · `lua-resty-template` compiling user strings · `SimpleTemplateEngine().createTemplate(user)` · — | fixed templates | |
| L03 | `eval $str`, `(?{ })` with `use re 'eval'` · `loadstring/load(user)` · `Eval.me`, `GroovyShell.evaluate` · `delegatecall` to user address | no runtime eval · sandboxed env tables · allow-listed addresses | Perl `eval { }` block is safe |
| L04 | DBI `do/prepare("… $x")` · `ngx.quote_sql_str` missing in `resty.mysql` queries · `Sql.execute(str + x)` / `.toString()` · — | placeholders `?` · `ngx.quote_sql_str(x)` · GString `Sql.execute("… ${x}")` (auto-parameterized) | groovy.sql GString is bound |
| L05 | MongoDB driver with user hashrefs · `resty.mongol` with user tables · GORM `where` closures from maps · — | scalar casting | |
| L06 | 2-arg `open($fh, $user)`, `system("…$x")`, backticks/`qx` · `os.execute("…"..x)`, `io.popen` · `["sh","-c",x].execute()` · — | 3-arg open, `system(LIST)` · avoid shell · `[bin, arg].execute()` | `"cmd $x".execute()` tokenizes (arg injection only) |
| L07 | `Net::LDAP` filter strings · `lualdap` filters · LDAP/XPath concat as in Java · — | `Net::LDAP::Util::escape_filter_value` · escaping | |
| L08 | `print "Location: $x\n"` CRLF in CGI · `ngx.header[name] = user` (OpenResty rejects CR/LF in recent versions) · `response.setHeader` · — | strip CR/LF | |
| L09 | `LWP::UserAgent->get($url)` · `ngx.location.capture(user)`, `resty.http:request_uri(user)` · `new URL(user).text` · — (oracles: trusting off-chain data feeds) | allow-list · fixed upstreams · allow-list · decentralized/verified oracles | |
| L10 | `open(my $fh, '<', "$base/$name")` without check · `io.open(base..name)` · `new File(base, user)` · — | `File::Spec->canonpath` + prefix · prefix check · normalize + `startsWith` | |
| L11 | `Archive::Zip` extraction · `lua-zip` · Grails `MultipartFile.originalFilename` · — | entry validation, generated names | |
| L12 | `Storable::thaw` / `YAML::Load` (code refs with `$YAML::LoadCode`) · `loadstring` of serialized tables · Java serialization, `XStream` · `abi.decode` of untrusted calldata into wrong types | JSON · `cjson.decode` · JSON · strict ABI types | |
| L13 | `XML::LibXML` with `expand_entities => 1`/`load_ext_dtd` · `lua-expat` entity expansion · `XmlSlurper` without `setFeature("…disallow-doctype-decl", true)` · — | `no_network => 1, expand_entities => 0` · disallow DOCTYPE | |
| L14 | `%$self = (%$self, %$params)` hash merge · table merge from `get_uri_args()` · Grails data binding `new User(params)` / `user.properties = params` · — | explicit fields · `bindData(obj, params, [include: [...]])` | |
| L15 | CGI::Session with predictable IDs · `lua-resty-session` with default secret · Spring Security plugin misconfig · Solidity: `tx.origin == owner` (phishing via intermediate contract) | random secrets · `msg.sender` checks | |
| L16 | JWT modules without alg pinning (`Crypt::JWT` `accepted_alg`) · `lua-resty-jwt` `verify` with `alg` from header · same as Java · signature replay: `ecrecover` without nonce/chainId/EIP-712 domain, malleable signatures | pin algorithms · EIP-712 + nonces, OpenZeppelin `ECDSA` | |
| L17 | missing auth checks in CGI scripts · `access_by_lua` missing on some `location`s · Grails controllers without `@Secured` · Solidity functions missing `onlyOwner`/role modifiers, `public`/`external` visibility by mistake, unprotected `initialize()` on proxies | auth in every entry point · `initializer` modifier + `_disableInitializers()` | |
| L18 | CGI forms without tokens · OpenResty-served forms · Grails `withForm`/`useToken` missing · — (no cookies) | tokens | Solidity N/A — transactions are signed |
| L19 | — · `ngx.header["Access-Control-Allow-Origin"] = ngx.var.http_origin` + credentials · Grails CORS plugin `allowedOrigins: ['*']` + credentials · — | explicit list | |
| L20 | CGI `Set-Cookie` without flags · `ngx.header["Set-Cookie"]` without `Secure; HttpOnly` · Grails cookie config · — | flags | |
| L21 | `print $q->redirect($q->param('next'))` · `ngx.redirect(arg)` · `redirect(url: params.next)` · — | allow-list | |
| L22 | `Digest::MD5` passwords, `Crypt::CBC` with static IV · `ngx.md5` for passwords · Java ciphers as in `java-kotlin.md` · — (hash collisions via `abi.encodePacked` of dynamic types) | bcrypt/argon2 · `abi.encode` | |
| L23 | `rand()` · `math.random` · `new Random()` · `block.timestamp`/`blockhash`/`prevrandao` for lotteries | `Crypt::URandom` · `resty.random.bytes(n, true)` · `SecureRandom` · Chainlink VRF / commit-reveal | |
| L24 | `LWP` with `verify_hostname => 0`, `SSL_verify_mode => SSL_VERIFY_NONE` · `lua_ssl_verify_depth` without `lua_ssl_trusted_certificate`, `ssl_verify=false` in `resty.http` · trust-all managers · — | verification on | |
| L25 | credentials in `.pl`/`.conf` · secrets in `nginx.conf` Lua blocks · `application.yml`/`Config.groovy` secrets · private keys/mnemonics in `hardhat.config`/`.env` committed | env vars / secret stores | |
| L26 | `CGI::Carp qw(fatalsToBrowser)` · `ngx.say(err)` · Grails stack traces in prod · revert reasons leaking nothing sensitive (on-chain data is public anyway) | generic errors | |
| L27 | logging params/passwords · `ngx.log(ngx.ERR, ngx.req.get_body_data())` · logging params · — (all on-chain data is public: never store PII/secrets in contract storage, even `private`) | redaction · off-chain storage of PII | `private` Solidity variables are readable |
| L28 | regex backtracking on input · `ngx.re` PCRE backtracking, unbounded `ngx.req.read_body` · regex/GORM unbounded queries · unbounded loops over user-growable arrays (gas DoS), push-payment DoS (revert in receiver) | bounded loops, pull-payment pattern | |
| L29 | file locking races in CGI · shared dict (`ngx.shared`) check-then-set races across workers · GORM without `lock: true` · **reentrancy** (external call before state update), front-running / transaction ordering | `flock` · `ngx.shared:add` (atomic) · pessimistic locks · checks-effects-interactions + `ReentrancyGuard`, commit-reveal | |
| L30 | numeric string comparisons (`==` vs `eq`) · Lua numbers are doubles (money precision) · `Double` money · integer overflow (<0.8 / `unchecked`), rounding/precision loss in division before multiplication, unchecked `call` return values | `eq` for strings · integer minor units · `BigDecimal` · Solidity ≥0.8 checked math, multiply-before-divide, check `(bool ok,) = …call` | |
| L31 | XS modules → `c-cpp.md` · LuaJIT FFI (`ffi.cast`, `ffi.copy`) with user sizes · JNI → `c-cpp.md` · — (EVM is memory-safe; storage collisions in proxies are the analogue: unstructured storage slots) | bounds checks · EIP-1967 storage slots | |
| L32 | CPAN deps unpinned (`cpanfile` without versions) · LuaRocks unpinned · Grails/Gradle deps unpinned · npm/forge libs unpinned, copied OpenZeppelin code modified | `cpanfile.snapshot` · pinned rocks · locks · pinned audited versions | SCA opt-in |
| L33 | — · OpenResty WebSocket (`resty.websocket.server`) without auth/origin check · Grails GraphQL plugin without limits · — | auth on upgrade | |
| L34 | `&{"main::$name"}()` symbolic refs, `$obj->$method()` from input · `_G[name]()` · `obj."$method"()` dynamic dispatch, `Class.forName` · `delegatecall`/`call` with user-supplied selector | `use strict 'refs'`, dispatch tables · allow-list | |
| L35 | missing `use strict; use warnings`; list vs scalar context bugs (`param()` returning lists → hash injection, CVE-2014-1572 style) · Lua 1-based indexes / `nil` holes; global variable leakage without `local` (shared across OpenResty requests) · Groovy truthiness (empty string/0 → false) in auth checks · Solidity: `msg.value` reused in loops, `transfer` 2300-gas stipend assumptions, `extcodesize` checks bypassed in constructors | `scalar($q->param('x'))` · `local` everywhere, `lua-releng` · explicit comparisons · audited patterns | |
