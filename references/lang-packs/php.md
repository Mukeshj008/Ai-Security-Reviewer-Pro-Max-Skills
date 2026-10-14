# Pack: PHP (Laravel, Symfony, WordPress, CodeIgniter, Slim, plain PHP)

**Detect:** `composer.json`, `*.php`, `*.phtml`, `*.blade.php`, `*.twig`, `wp-config.php`.

## Sources

`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, `$_SERVER['HTTP_*' / 'REQUEST_URI' / 'PHP_SELF' / 'QUERY_STRING']`, `php://input`, `getallheaders()`; Laravel `$request->input/query/all/get/header/file`, route params; Symfony `$request->query/request/headers/attributes->get`; WordPress `$_GET` + `get_query_var`, REST `$request->get_param`.

## XSS & templates

| Vulnerable | Safe equivalent | FP trap |
|-----------|-----------------|---------|
| `echo $x`, `print $x`, `<?= $x ?>`, `printf` with user data (PHP never escapes) | `htmlspecialchars($x, ENT_QUOTES, 'UTF-8')` | `htmlspecialchars` without `ENT_QUOTES` (pre-8.1 default) leaves `'` → attribute XSS in single-quoted attrs |
| Blade `{!! $x !!}` | `{{ $x }}` (escaped) | |
| Twig `{{ x|raw }}`, `{% autoescape false %}` | `{{ x }}` | |
| WordPress `echo $_GET[...]`, `echo get_option(...)` from user-writable options | `esc_html`, `esc_attr`, `esc_url`, `wp_kses` | `esc_*` correct for the context only — `esc_html` inside `href` is wrong |
| `$_SERVER['PHP_SELF']` in form `action` | `htmlspecialchars($_SERVER['SCRIPT_NAME'])` | |

## SSTI / code injection

`eval($x)`, `assert($x)` (string, PHP < 8), `create_function`, `preg_replace('/…/e', …)` (PHP < 7), `call_user_func($user)`, `$func($args)` variable functions, `include/require($user)` (LFI/RFI — `allow_url_include`), Twig `createTemplate($user)`, Blade `Blade::render($user)`, Smarty `{php}`/`fetch('string:'.$user)`.

## SQL / ORM

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `mysqli_query($c, "… $x")`, `$pdo->query("… " . $x)`, `mysql_query` | `$pdo->prepare("… ?")->execute([$x])`, `mysqli_prepare` + `bind_param` | `PDO::quote` is acceptable but discouraged |
| `PDO::ATTR_EMULATE_PREPARES` true + non-UTF8 charset (GBK) | real prepares, `charset=utf8mb4` in DSN | |
| Laravel `DB::raw("… $x")`, `whereRaw("… $x")`, `orderByRaw($x)`, `selectRaw`, `DB::select("… $x")` | `whereRaw('id = ?', [$x])`, query builder | `where('id', $x)` is safe; `orderBy($userColumn)` → column injection (allow-list) |
| Doctrine `createQuery("… $x")` (DQL injection), `$conn->executeQuery("… $x")` | `setParameter`, `?` | |
| WordPress `$wpdb->query("… $x")`, `get_results("… $x")` | `$wpdb->prepare("… %s", $x)` | `prepare` with user-controlled format string is still unsafe |

## Command execution

`system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open`, backticks `` `…$x…` ``, `pcntl_exec`, `mail()` 5th parameter (sendmail arg injection). Fix: `escapeshellarg` per argument (not `escapeshellcmd` on whole string), or `proc_open` with array (PHP 7.4+).

## SSRF

`file_get_contents($url)`, `fopen($url)`, `curl_setopt($ch, CURLOPT_URL, $user)`, Guzzle `$client->get($user)`, `getimagesize($url)`, `simplexml_load_file($url)`. PHP wrappers widen impact: `file://`, `php://filter` (source disclosure), `phar://` (deserialization), `gopher://` (cURL), `data://`, `expect://`. Fix: scheme+host allow-list, `CURLOPT_PROTOCOLS` = HTTP|HTTPS, `CURLOPT_FOLLOWLOCATION` false or re-check. TLS: `CURLOPT_SSL_VERIFYPEER => false`, `CURLOPT_SSL_VERIFYHOST => 0`, Guzzle `'verify' => false`.

## Path / file / upload

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `include("pages/" . $_GET['p'] . ".php")` (LFI; null byte only < 5.3.4) | allow-list map | |
| `file_get_contents($base . $user)`, `readfile`, `unlink`, `fopen` | `realpath` + prefix check | `basename()` removes directories |
| `move_uploaded_file($_FILES['f']['tmp_name'], 'uploads/' . $_FILES['f']['name'])` in web root → `.php` upload = RCE; `$_FILES['type']` is client-controlled | random name, extension allow-list, store outside web root, `finfo_file` | |
| `ZipArchive::extractTo` without entry check | validate entries | |

## Deserialization

`unserialize($user)` (POP chains / `__wakeup`, `__destruct`), `phar://` paths reaching any filesystem function (`file_exists`, `is_file`, `getimagesize` trigger metadata deserialization in PHP < 8), Laravel `decrypt()` with leaked `APP_KEY` → RCE via cookie. Fix: `json_decode`; `unserialize($x, ['allowed_classes' => false])`.

## XML

`simplexml_load_string`, `DOMDocument::loadXML` with `LIBXML_NOENT` / `LIBXML_DTDLOAD`; PHP ≥ 8.0 + libxml ≥ 2.9 disable external entities by default — XXE requires those flags. `libxml_disable_entity_loader(true)` for older versions.

## Crypto / randomness

| Vulnerable | Safe |
|-----------|------|
| `rand()`, `mt_rand()`, `uniqid()`, `lcg_value()`, `str_shuffle` for tokens | `random_bytes`, `random_int`, `bin2hex(random_bytes(32))` |
| `md5($pass)`, `sha1($pass)`, `crypt` with DES | `password_hash`, `password_verify` |
| `openssl_encrypt(..., 'aes-128-ecb')`, static IV, `mcrypt_*` | `aes-256-gcm` with random IV, `sodium_crypto_secretbox` |
| `==` comparison of hashes/tokens (`"0e123" == "0e456"` magic hashes, type juggling) | `hash_equals`, `===` |

## Auth / session / type juggling

- `if ($_POST['password'] == $stored)` / `strcmp($a, $b) == 0` with array input (`strcmp` returns `null` → `== 0` true in PHP < 8).
- `in_array($x, $list)` without strict `true`; `switch` loose comparisons; `json_decode` giving `true` matching any string with `==`.
- `session_start()` without `session_regenerate_id(true)` on login; `session.cookie_secure/httponly/samesite` off; `session.use_strict_mode=0`.
- Laravel routes outside `auth` middleware group; `$guarded = []` / `$fillable` including `is_admin` (mass assignment via `Model::create($request->all())`); `Gate`/`Policy` missing on `show/update/destroy` (IDOR).
- WordPress: `wp_ajax_nopriv_*` actions doing privileged work; missing `current_user_can` and `check_ajax_referer` / `wp_verify_nonce`; REST routes with `permission_callback => '__return_true'`.
- Symfony `security.yaml` `access_control` order (first match wins), `IS_AUTHENTICATED_ANONYMOUSLY` / `PUBLIC_ACCESS` on sensitive paths.

## CSRF / CORS / headers

Laravel `VerifyCsrfToken::$except` with wildcards; Symfony forms with `csrf_protection: false`; `header("Access-Control-Allow-Origin: " . $_SERVER['HTTP_ORIGIN'])` + credentials; `APP_DEBUG=true` in prod `.env`; `display_errors=On`; `expose_php=On`.

## Redirect / header

`header("Location: " . $_GET['url'])` → open redirect; `header()` rejects multi-line values since PHP 5.1.2 (no response splitting).

## DoS

`preg_match` with user pattern (`preg_quote` missing); `pcre.backtrack_limit`; `max_input_vars`; XML billion laughs with `LIBXML_PARSEHUGE`.

## Hint rg

```bash
G='--glob *.{php,phtml,inc} -g !vendor/**'
rg -n "(echo|print)\s+[^;]*\\\$_(GET|POST|REQUEST|COOKIE|SERVER)|<\?=\s*\\\$" $G
rg -n "\{!!|\|\s*raw|autoescape\s+false" --glob "*.{blade.php,twig,php}" -g '!vendor/**'
rg -n "\b(eval|assert|create_function|call_user_func(_array)?)\s*\(|preg_replace\s*\(\s*['\"].*/e|\b(include|require)(_once)?\s*\(?\s*\\\$" $G
rg -n "(mysqli_query|->query|->exec|DB::(raw|select|statement)|whereRaw|orderByRaw|selectRaw|havingRaw|createQuery|executeQuery|get_results|get_var|get_row)\s*\([^)]*(\\\$|\.)" $G
rg -n "\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(|\`[^\`]*\\\$|\bmail\s*\(" $G
rg -n "file_get_contents\s*\(|fopen\s*\(|curl_setopt|CURLOPT_SSL_VERIFY(PEER|HOST)|getimagesize\s*\(|['\"]verify['\"]\s*=>\s*false" $G
rg -n "move_uploaded_file|\\\$_FILES|extractTo|readfile\s*\(|unlink\s*\(" $G
rg -n "unserialize\s*\(|phar://|LIBXML_NOENT|LIBXML_DTDLOAD|loadXML|simplexml_load" $G
rg -n "\b(rand|mt_rand|uniqid|lcg_value|str_shuffle)\s*\(|\b(md5|sha1)\s*\(|aes-\d+-ecb|mcrypt_" $G
rg -n "==\s*\\\$|strcmp\s*\(|in_array\s*\([^,]+,[^,]+\)\s*\)" $G
rg -n "wp_ajax_nopriv_|permission_callback|__return_true|current_user_can|check_ajax_referer|wp_verify_nonce" $G
rg -n "\\\$guarded\s*=\s*\[\s*\]|\\\$fillable|->all\(\)\)|session_regenerate_id|VerifyCsrfToken|\\\$except" $G
rg -n "header\s*\(\s*['\"](Location|Access-Control-Allow-Origin)" $G
rg -n "APP_DEBUG\s*=\s*true|display_errors" --glob "*.{env,ini,php}" -g '!vendor/**'
rg -n "ldap_search|ldap_escape|->xpath\s*\(|DOMXPath" $G
rg -n -e "->find\s*\(|MongoDB\\\\|\\\$where" $G
rg -n "lockForUpdate|sharedLock|DB::transaction|flock\s*\(" $G
rg -n "\"(post-install-cmd|post-update-cmd|pre-install-cmd)\"" --glob "composer.json"
```

## Class coverage index

| ID | Vulnerable in PHP | Safe equivalent | FP trap / note |
|----|------------------|-----------------|----------------|
| L01 | § XSS: `echo`/`<?=`/`print` of input, Blade `{!! !!}`, Twig `|raw`, `$_SERVER['PHP_SELF']`, WordPress output without `esc_*` | `htmlspecialchars($x, ENT_QUOTES, 'UTF-8')`, `{{ }}`, `esc_html/esc_attr/esc_url` | pre-8.1 `htmlspecialchars` default lacks `ENT_QUOTES` |
| L02 | Twig `createTemplate($user)`, `Blade::render($user)`, Smarty `fetch('string:'.$user)` / `{php}` | fixed templates, Twig sandbox extension | |
| L03 | `eval`, `assert($str)` (<8), `create_function`, `preg_replace /e` (<7), `call_user_func($user)`, `$func()`, `include($user)` | allow-listed callables | |
| L04 | § SQL: `mysqli_query`/`->query` concat, `DB::raw`, `whereRaw/orderByRaw`, Doctrine DQL concat, `$wpdb->query` without `prepare` | PDO prepared statements, query builder bindings, `$wpdb->prepare` | `orderBy($col)` from input = column injection |
| L05 | MongoDB `->find(['user' => $_POST['user']])` where PHP array params (`user[$ne]=x`) become operators | cast `(string)`, reject `$` keys | PHP auto-parses `a[b]=` into arrays |
| L06 | `system/exec/shell_exec/passthru/popen/proc_open`, backticks, `mail()` 5th param | `escapeshellarg` per arg, `proc_open([...])` array form | `escapeshellcmd` on whole string is insufficient |
| L07 | `ldap_search($c, $dn, "(uid=$u)")`, `DOMXPath->query("//u[@n='$x']")` | `ldap_escape($u, '', LDAP_ESCAPE_FILTER)`; quote-safe XPath building | |
| L08 | `header("X: $user")` (rejects newlines since 5.1.2), log injection via `error_log($input)` | structured logs | response splitting N/A on modern PHP |
| L09 | § SSRF: `file_get_contents($url)`, curl, Guzzle, `getimagesize($url)`; wrappers `file://`, `php://filter`, `phar://`, `gopher://` | allow-list, `CURLOPT_PROTOCOLS`, disable redirects | |
| L10 | `include/require($user)` LFI/RFI, `readfile/file_get_contents($base.$user)` | allow-list map, `basename`, `realpath` prefix check | |
| L11 | `move_uploaded_file` into web root with client name/extension, trusting `$_FILES['type']`, `ZipArchive::extractTo` | random names outside web root, `finfo_file`, entry validation | |
| L12 | `unserialize($user)` (POP chains), `phar://` triggers (<8), Laravel `decrypt()` with leaked `APP_KEY` | `json_decode`, `allowed_classes => false` | |
| L13 | `LIBXML_NOENT`/`LIBXML_DTDLOAD` with `simplexml_load_string`/`DOMDocument::loadXML` | defaults on PHP ≥8 / libxml ≥2.9 | XXE needs those flags on modern stacks |
| L14 | Laravel `$guarded = []`, `$fillable` with `is_admin`, `Model::create($request->all())`; `extract($_POST)`, `parse_str($q)` without result array (<8) | `$request->validated()`, explicit `$fillable` | |
| L15 | no `session_regenerate_id(true)` on login, cookie flags off, `session.use_strict_mode=0`, `==` password compare | `password_verify`, regenerate, strict mode | |
| L16 | `firebase/php-jwt` `JWT::decode` without `Key`+alg (old API `decode($t, $k, ['none'])`), OAuth `state` unchecked | `JWT::decode($t, new Key($k, 'RS256'))` | php-jwt ≥6 requires `Key` |
| L17 | Laravel routes outside `auth` middleware, missing Policies/Gates (IDOR), WordPress `wp_ajax_nopriv_*` doing privileged work, REST `permission_callback => '__return_true'`, Symfony `access_control` order | middleware groups, `authorize()`, `current_user_can` | |
| L18 | `VerifyCsrfToken::$except` wildcards, WordPress handlers without `check_admin_referer`/nonce, Symfony `csrf_protection: false` | CSRF tokens / nonces | |
| L19 | `header("Access-Control-Allow-Origin: ".$_SERVER['HTTP_ORIGIN'])` + credentials; Laravel `cors.php` `allowed_origins => ['*']` + `supports_credentials` | explicit list | |
| L20 | `session.cookie_secure/httponly/samesite` off, `expose_php=On`, no security headers | php.ini hardening, middleware | |
| L21 | `header("Location: ".$_GET['url'])`, Laravel `redirect($request->input('next'))` | `redirect()->intended()` with allow-list | |
| L22 | `md5/sha1` passwords, `crypt` DES, `openssl_encrypt(...'-ecb')`, `mcrypt_*` | `password_hash`, `sodium_*`, AES-GCM | |
| L23 | `rand`, `mt_rand`, `uniqid`, `lcg_value`, `str_shuffle` for tokens | `random_bytes`, `random_int` | |
| L24 | `CURLOPT_SSL_VERIFYPEER false`, `VERIFYHOST 0`, Guzzle `verify => false`, stream context `verify_peer => false` | defaults | |
| L25 | `APP_DEBUG=true`, `.env` committed, `wp-config.php` secrets, `display_errors=On` | env per environment | `.env.example` |
| L26 | Whoops/Ignition error pages in prod (Ignition RCE CVE-2021-3129 on old versions), `var_dump` to output | `APP_DEBUG=false`, generic errors | |
| L27 | logging `$_POST`/passwords, Monolog without processors for PII | redaction processors | |
| L28 | `preg_match` with user pattern / catastrophic regex (`pcre.backtrack_limit`), `max_input_vars`, hash-collision DoS (old PHP), unbounded `LIMIT` | `preg_quote`, limits | |
| L29 | balance updates without `lockForUpdate()`/transactions, file-based counters without `flock` | `DB::transaction` + `lockForUpdate`, atomic `UPDATE … SET x = x - ?` | |
| L30 | type juggling: `==` with `"0e…"` magic hashes, `strcmp` with arrays (<8), `in_array` non-strict, `switch` loose, `intval` truncation, float money | `===`, `hash_equals`, `in_array(..., true)`, `bcmath` | |
| L31 | N/A for PHP code; native extensions (`ext/*.c`) → `c-cpp.md`; FFI extension (`FFI::cdef`) with user data | disable FFI (`ffi.enable=0`) | |
| L32 | `composer.json` scripts (`post-install-cmd`), unpinned `*`/`dev-master`, VCS repositories, `composer install` without lock | `composer.lock` + `--no-scripts` in CI where possible | SCA opt-in |
| L33 | Lighthouse/webonyx GraphQL without depth/complexity limits or `@can` guards; Ratchet/Laravel WebSockets channels without auth (`routes/channels.php` returning true) | `QueryDepth`/`QueryComplexity` rules, channel auth callbacks | |
| L34 | `new $className()` from input, `call_user_func([$obj, $_GET['m']])`, `ReflectionClass($user)` | allow-list | |
| L35 | register_globals-style `extract()`, `$$var` variable variables from input, `parse_str` overwriting vars, `null` from failed functions used in `==` checks | explicit assignment, strict types (`declare(strict_types=1)`) | |
