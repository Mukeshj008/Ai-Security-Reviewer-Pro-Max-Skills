# Pack: C / C++ (native services, CGI, libraries, JNI/NDK, Node/Python native addons)

**Detect:** `*.c`, `*.h`, `*.cc`, `*.cpp`, `*.hpp`, `CMakeLists.txt`, `Makefile`, `meson.build`, `binding.gyp`, Android `jni/` / `cpp/`.

Web-class findings (SQLi, SSRF) use the same reasoning as other packs; this pack focuses on memory and native-specific issues.

## Sources

`argv`, `getenv`, `read/recv/recvfrom/fread/fgets`, `scanf` family, network buffers, file contents, IPC (`shm`, pipes), JNI `GetStringUTFChars` / `GetByteArrayElements` from Java callers, CGI `QUERY_STRING`/`CONTENT_LENGTH`.

## Memory corruption

| Vulnerable | Safe equivalent | FP trap |
|-----------|-----------------|---------|
| `strcpy`, `strcat`, `sprintf`, `vsprintf`, `gets`, `scanf("%s")` | `strlcpy`/`snprintf` (check return value for truncation), `fgets`, `%Ns` width | Fixed-literal source into a buffer proven larger is fine |
| `memcpy(dst, src, user_len)` without `user_len <= sizeof(dst)` | bounds check before copy | Length derived from `sizeof(dst)` |
| `strncpy` leaving no NUL terminator | explicit terminate | |
| Off-by-one: `buf[len] = 0` where `len == sizeof(buf)`; `<=` loop bounds | | |
| Integer overflow in size math: `malloc(n * size)`, `malloc(len + 1)` with `len = SIZE_MAX`, signed `int len` from network compared to `size_t` | `calloc(n, size)`, `__builtin_mul_overflow`, `reallocarray` | |
| Signedness: `int len = ntohl(x); if (len < MAX) memcpy(…, len)` (negative passes) | unsigned types + upper bound | |
| Use-after-free / double free: pointer used after `free`, freed in error path and again in cleanup, iterator invalidation in C++ (`vector::push_back` while holding `&v[0]`) | set to `NULL` after free; RAII / smart pointers | |
| Uninitialized memory sent to network / used in decisions | `memset`/value-initialize | |
| Stack VLAs / `alloca(user_len)` | heap with bound | |

## Format strings

`printf(user)`, `fprintf(fp, user)`, `syslog(prio, user)`, `snprintf(buf, n, user)` → info leak / write via `%n`. Safe: `printf("%s", user)`.

## Command / file

- `system(cmd)`, `popen(cmd)` with concatenated input; `execl("/bin/sh","sh","-c",…)` → injection. `execve` with argv array → no shell.
- TOCTOU: `access()` / `stat()` then `open()`; `/tmp` files via `tmpnam`/`mktemp` → use `mkstemp`, `O_CREAT|O_EXCL`, `openat` + `O_NOFOLLOW`.
- Path traversal: `snprintf(path, …, "%s/%s", base, user)` without `realpath` + prefix check.
- Running setuid with `getenv("PATH")`/`LD_PRELOAD` trust.

## Crypto / randomness

`rand()`, `srand(time(NULL))`, `random()` for keys/tokens → `getrandom`, `arc4random_buf`, `RAND_bytes`; OpenSSL `SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, …)`, missing hostname check (`X509_check_host` / `SSL_set1_host`), `EVP_*_ecb`, `MD5`/`SHA1` for passwords; `memcmp` on MACs → `CRYPTO_memcmp`; secrets not cleared (`explicit_bzero`/`OPENSSL_cleanse`).

## C++ specifics

`std::string::c_str()` held past the string's lifetime; `operator[]` vs `.at()` on user index; `reinterpret_cast` on network structs (alignment/endianness); exceptions escaping destructors; `std::regex` (backtracking) on user input (ReDoS + stack overflow).

## Concurrency

Data races on globals without mutex; signal handlers calling non-async-signal-safe functions (`malloc`, `printf`).

## Build hardening (report as Hygiene/Low unless a memory bug exists)

Missing `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-fPIE -pie`, `-Wl,-z,relro,-z,now`, `-Wformat -Werror=format-security`; `-fno-stack-protector`, `-z execstack`.

## JNI / native addons

Trusting Java-side lengths (`GetArrayLength` vs actual buffer); missing `ReleaseStringUTFChars` (leak); returning pointers to stack memory; Node N-API `napi_get_buffer_info` length assumptions.

## Hint rg

```bash
G='--glob *.{c,h,cc,cpp,cxx,hpp,hh} -g !third_party/** -g !vendor/** -g !external/**'
rg -n "\b(strcpy|strcat|sprintf|vsprintf|gets|wcscpy|wcscat)\s*\(" $G
rg -n "\bscanf\s*\(\s*\"[^\"]*%s|\bsscanf\s*\(|\bstrncpy\s*\(" $G
rg -n "\bmemcpy\s*\(|\bmemmove\s*\(|\balloca\s*\(|\bmalloc\s*\([^)]*\*|\brealloc\s*\(" $G
rg -n "\b(printf|fprintf|syslog|snprintf|vprintf)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[,)]" $G
rg -n "\bfree\s*\(" $G
rg -n "\b(system|popen|execl|execlp|execvp)\s*\(" $G
rg -n "\b(access|stat|lstat)\s*\(|\b(tmpnam|tempnam|mktemp)\s*\(" $G
rg -n "\brand\s*\(|srand\s*\(|SSL_VERIFY_NONE|_ecb\s*\(|\bMD5\s*\(|\bSHA1\s*\(|\bmemcmp\s*\(" $G
rg -n "reinterpret_cast|\.c_str\(\)|std::regex" $G
rg -n "fno-stack-protector|execstack|FORTIFY_SOURCE|stack-protector" --glob "{CMakeLists.txt,Makefile,*.mk,*.cmake,meson.build,binding.gyp}"
rg -n "sqlite3_exec|mysql_query|PQexec\s*\(|sqlite3_prepare" $G
rg -n "curl_easy_setopt|CURLOPT_URL|CURLOPT_SSL_VERIFY(PEER|HOST)|SSL_CTX_set_verify" $G
rg -n "xmlReadMemory|xmlParseMemory|XML_PARSE_NOENT|XML_PARSE_DTDLOAD|xmlCtxtUseOptions" $G
rg -n "ldap_search|dlopen\s*\(|dlsym\s*\(|getenv\s*\(" $G
rg -n "pthread_mutex|std::mutex|std::atomic|volatile" $G
rg -n "crow::|drogon|Pistache|cpprest|httplib::|mongoose\.h|civetweb|QUERY_STRING" $G
```

## Class coverage index

| ID | Vulnerable in C / C++ | Safe equivalent | FP trap / note |
|----|----------------------|-----------------|----------------|
| L01 | CGI / embedded web servers (`mongoose`, `civetweb`, Crow, Drogon, cpp-httplib) writing `printf("<p>%s</p>", query)` / `res.body = "<p>" + param` with `text/html` | HTML-encode helper, template engine with escaping (Inja/Crow mustache `{{ }}`) | Crow mustache `{{{ }}}` is raw |
| L02 | Inja/mustache templates compiled from user strings (`env.render(user_tpl, data)`) | fixed templates | |
| L03 | `dlopen(user_path)`, `system()` of user-built scripts, embedded Lua/Python interpreters running user code | allow-listed plugin paths | |
| L04 | `sqlite3_exec(db, sprintf(...user...))`, `mysql_query` with concatenated `std::string`, libpq `PQexec` | `sqlite3_prepare_v2` + `sqlite3_bind_*`, `PQexecParams`, `mysql_stmt_*` | |
| L05 | mongo-c-driver `bson_new_from_json(user)` used as filter (operator injection) | build BSON with typed appends | |
| L06 | § Command: `system`, `popen`, `execl("/bin/sh","-c",…)` | `execve`/`posix_spawn` with argv array | |
| L07 | `ldap_search_ext_s` filter via `snprintf("(uid=%s)", u)`; libxml2 `xmlXPathEval` with concatenated expressions | RFC 4515 escaping of `*()\\\0`; XPath variables | |
| L08 | § Format strings: `printf(user)`, `syslog(prio, user)`; CRLF in hand-built HTTP headers (`"Location: " + user + "\r\n"`) | `printf("%s", user)`, reject CR/LF | |
| L09 | libcurl `CURLOPT_URL` from user (+ `CURLOPT_PROTOCOLS` unset → `file://`, `gopher://`, `dict://`), `CURLOPT_FOLLOWLOCATION=1` | `CURLOPT_PROTOCOLS_STR "http,https"`, host allow-list, `CURLOPT_REDIR_PROTOCOLS_STR` | |
| L10 | § Command/file: `fopen(snprintf("%s/%s", base, user))`, `open()` without `realpath`/`O_NOFOLLOW` | `realpath` + prefix check, `openat` + `O_NOFOLLOW`/`RESOLVE_BENEATH` (`openat2`) | |
| L11 | libarchive/minizip extraction with entry paths unchecked, symlink entries followed | `ARCHIVE_EXTRACT_SECURE_NODOTDOT`/`_SECURE_SYMLINKS`/`_SECURE_NOABSOLUTEPATHS` | |
| L12 | Boost.Serialization / cereal / protobuf from untrusted input with polymorphic types; hand-written binary parsers trusting length fields | bounds-checked parsers, protobuf (no polymorphism), fuzzing | |
| L13 | libxml2 `XML_PARSE_NOENT`, `XML_PARSE_DTDLOAD`, `xmlSubstituteEntitiesDefault(1)`; Xerces with external entities enabled; expat with entity expansion (billion laughs on old versions) | default libxml2 options (no NOENT), `XML_PARSE_NONET`, expat ≥2.4 | |
| L14 | N/A as mass assignment; object injection analogue = type confusion: `reinterpret_cast`/`static_cast` downcasts of attacker-chosen types, unions | `dynamic_cast`, `std::variant` | |
| L15 | hand-rolled auth: `strcmp(password, stored)` (timing), fixed session IDs, sessions without expiry | `CRYPTO_memcmp`, random IDs from `getrandom` | |
| L16 | JWT libs (`jwt-cpp`, `libjwt`) without algorithm pinning (`allow_algorithm`), skipping signature verification | `jwt::verify().allow_algorithm(rs256)` | |
| L17 | missing privilege checks in setuid binaries / daemons (UID from client message), `getuid` vs `geteuid` confusion | `SO_PEERCRED`, drop privileges early | |
| L18 | embedded web UIs (routers/IoT) with cookie auth and no CSRF tokens | tokens + `SameSite` | |
| L19 | embedded servers echoing `Origin` into `Access-Control-Allow-Origin` with credentials | allow-list | |
| L20 | embedded servers without security headers / cookie flags | set headers explicitly | |
| L21 | `Location:` built from user input in CGI | relative path allow-list | |
| L22 | § Crypto: `EVP_*_ecb`, `DES_*`, `MD5()`/`SHA1()` passwords, static IVs, `RSA_PKCS1_PADDING` for encryption | `EVP_aes_256_gcm`, libsodium, `RSA_PKCS1_OAEP_PADDING` | |
| L23 | `rand()`, `srand(time(NULL))`, `std::mt19937`, `std::random_device` on old MinGW (deterministic) | `getrandom`, `arc4random_buf`, `RAND_bytes`, `BCryptGenRandom` | |
| L24 | `SSL_VERIFY_NONE`, no hostname check (`SSL_set1_host` missing), `CURLOPT_SSL_VERIFYPEER 0`/`VERIFYHOST 0`, ignoring `SSL_get_verify_result` | `SSL_VERIFY_PEER` + `SSL_set1_host`, curl defaults | |
| L25 | hardcoded keys/passwords in source or binaries (`strings` reveals them), debug backdoors behind `#ifdef DEBUG` shipped | external config, build flags audit | |
| L26 | error messages exposing addresses (`%p`) / paths; core dumps enabled with secrets in memory | `prctl(PR_SET_DUMPABLE, 0)`, `RLIMIT_CORE=0` | |
| L27 | logging secrets/PII via `syslog`; secrets not wiped (`memset` optimized away) | `explicit_bzero`/`OPENSSL_cleanse`, redaction | |
| L28 | `std::regex` on user input (backtracking + stack overflow), unbounded `malloc` from length fields, recursion depth from input, fd/thread exhaustion | RE2, size caps, iterative parsing | |
| L29 | § Command/file TOCTOU (`access`→`open`), data races on globals, signal-handler reentrancy, `std::shared_ptr` refcount OK but pointee not thread-safe | `O_EXCL`, mutexes/atomics, async-signal-safe handlers | |
| L30 | integer overflow/underflow/signedness in size math, `size_t`↔`int` conversions, `atoi` (no error) | `strtol` + range checks, `__builtin_*_overflow`, `-ftrapv`/UBSan in tests | |
| L31 | § Memory corruption: overflow (`strcpy/sprintf/gets/memcpy`), off-by-one, UAF, double free, uninitialized reads, VLAs/`alloca`; C++ iterator invalidation, dangling `string_view`/`c_str()` | bounded APIs, RAII/smart pointers, `std::span`, ASan/MSan/UBSan + fuzzing, hardening flags | fixed-size literal copies into larger buffers are fine |
| L32 | vendored third-party sources without version tracking, `FetchContent`/`ExternalProject` from git branches without hash, Conan/vcpkg unpinned, `curl … | sh` in build scripts | pinned commits/hashes, `URL_HASH` | |
| L33 | gRPC C++ without auth (`InsecureServerCredentials`), WebSocket servers (Boost.Beast, uWebSockets) without origin/auth checks | `SslServerCredentials` + auth metadata processor | |
| L34 | `dlsym(handle, user_symbol)`, function-pointer tables indexed by unchecked input | bounds-checked index, allow-list | |
| L35 | undefined behaviour optimized into security bugs (null check removed after deref, signed overflow assumptions), `strncpy` non-termination, `scanf` without width, `gets` | compile with `-Wall -Wextra -Werror`, sanitizers | |
