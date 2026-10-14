# Pack: Rust (Actix-web, Axum, Rocket, Warp, Tokio, FFI)

**Detect:** `Cargo.toml`, `*.rs`.

Memory safety holds in safe Rust; findings concentrate in `unsafe`, FFI, logic, and the same web classes as other languages.

## Sources

Actix `web::Query/Path/Json/Form`, `HttpRequest::headers`; Axum `Query`, `Path`, `Json`, `Form`, `HeaderMap`, `TypedHeader`; Rocket request guards / form params; Warp filters; `std::env::args` in CLIs that run as services.

## XSS & templates

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `HttpResponse::Ok().content_type("text/html").body(format!("<p>{}</p>", x))`; Axum `Html(format!(…x…))` | `askama` / `maud` / `tera` with auto-escape; `html_escape::encode_text` | `Json(x)` → JSON |
| Tera `{{ x | safe }}`, `autoescape` disabled (`tera.autoescape_on(vec![])`) | default escaping for `.html` | Tera auto-escapes only `.html/.htm/.xml` by default |
| Askama `{{ x|safe }}`, `escape = "none"` | default | |
| Handlebars-rust `{{{x}}}`, `registry.register_escape_fn(no_escape)` | | |

## SQL

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `sqlx::query(&format!("… {}", x))`, Diesel `sql_query(format!(…))`, `diesel::dsl::sql::<…>(&user)`, `rusqlite` `conn.execute(&format!(…), [])` | `sqlx::query("… $1").bind(x)`, `query!` macro, Diesel DSL, `rusqlite` `params![]` | `sqlx::query!` macros are compile-time checked and bound |

## Command execution

`Command::new("sh").arg("-c").arg(x)` → injection; `Command::new(bin).arg(user)` → no shell (option injection only). Windows: `Command` argument quoting for `.bat`/`.cmd` (CVE-2024-24576, fixed in Rust 1.77.2).

## SSRF / TLS

`reqwest::get(user)`, `Client::get(user)`, `hyper`, `ureq` → allow-list + resolved-IP check; `reqwest::redirect::Policy::none()` or custom. TLS: `danger_accept_invalid_certs(true)`, `danger_accept_invalid_hostnames(true)`, custom `ServerCertVerifier` returning `Ok` (rustls `dangerous()`).

## Path / file

`Path::new(base).join(user)` — absolute `user` replaces base, `..` preserved. Fix: canonicalize + `starts_with(base)`; `actix-files` / `tower-http::ServeDir` handle traversal. Archive extraction: `zip` crate `enclosed_name()` (safe) vs `name()` (unsafe); `tar` crate `unpack_in` (safe) vs manual `unpack(dest.join(path))`.

## Deserialization / DoS

`serde_json` is safe from code exec; risk is DoS (deep nesting — `serde_json` has a recursion limit of 128; `serde_yaml` / `bincode` without size limits → memory exhaustion: `bincode::options().with_limit(...)`). `regex` crate is linear-time (ReDoS FP trap); `fancy-regex` backtracks. Unbounded `Json` body: Axum `DefaultBodyLimit::disable()`, Actix `JsonConfig::default().limit(huge)`.

## Crypto / randomness

`rand::thread_rng()` is a CSPRNG (ChaCha) — **not** a finding for tokens; `rand::rngs::SmallRng`/`StdRng::seed_from_u64(fixed)` is. `md5`/`sha1` crates for passwords → `argon2`/`bcrypt`; `aes` crate ECB usage via raw `BlockEncrypt`; `==` on MACs → `subtle::ConstantTimeEq` / `hmac::Mac::verify_slice`. `jsonwebtoken` `Validation { validate_exp: false, insecure_disable_signature_validation() }`, `dangerous_insecure_decode`.

## Memory safety (unsafe / FFI)

- `unsafe { … }` blocks: raw pointer deref from user-sized lengths, `slice::from_raw_parts(ptr, user_len)`, `get_unchecked`, `set_len` before init, `mem::transmute` between unrelated types, `MaybeUninit::assume_init` before write, `static mut` shared across threads.
- `unsafe impl Send/Sync` on types holding `Rc`/raw pointers.
- FFI: `CStr::from_ptr` on non-NUL-terminated buffers, lifetime of `CString::as_ptr()` (`CString::new(x).unwrap().as_ptr()` dangles).
- Integer overflow: release builds wrap silently (`overflow-checks = false` default in release) — size calculations with `as usize` from user `u64`/`i64`; use `checked_*`.
- `panic!`/`unwrap()`/`expect()`/index out of bounds on user input in request handlers → DoS (Actix/Axum catch panics per task, but `panic = "abort"` in `Cargo.toml` kills the process).

## Auth / CORS

Axum/Actix routes added outside the layer/`wrap` that enforces auth (`Router::route_layer` applies only to routes registered **before** it); `tower_http::cors::CorsLayer::permissive()` / `very_permissive()` / `Any` origins + credentials; `actix-cors` `Cors::permissive()`.

## Hint rg

```bash
G='--glob *.rs -g !target/**'
rg -n "content_type\s*\(\s*\"text/html|Html\s*\(\s*format!|\|\s*safe|autoescape_on|escape\s*=\s*\"none\"|register_escape_fn" --glob "*.{rs,html,tera,hbs}" -g '!target/**'
rg -n "(query|query_as|sql_query|execute|sql::<)\s*[(<][^)]*format!" $G
rg -n "Command::new\s*\(\s*\"(sh|bash|cmd|powershell)" $G
rg -n "reqwest::|Client::new|ureq::|hyper::|danger_accept_invalid|dangerous\(\)|ServerCertVerifier" $G
rg -n "\.join\s*\(|canonicalize|enclosed_name|\.name\(\)|unpack\s*\(" $G
rg -n "unsafe\s*\{|from_raw_parts|get_unchecked|set_len|transmute|assume_init|static mut|unsafe impl (Send|Sync)|CStr::from_ptr|as_ptr\(\)" $G
rg -n "SmallRng|seed_from_u64|md5::|sha1::|insecure_disable_signature_validation|dangerous_insecure_decode|validate_exp\s*:\s*false" $G
rg -n "CorsLayer::(permissive|very_permissive)|Cors::permissive|allow_origin\s*\(\s*Any|DefaultBodyLimit::disable|fancy_regex" $G
rg -n "overflow-checks|panic\s*=\s*\"abort\"" --glob "Cargo.toml"
rg -n "\.unwrap\(\)|\.expect\s*\(|panic!\s*\(|\[[a-z_]+\]" $G
rg -n "Mutex|RwLock|Arc<|tokio::spawn|FOR UPDATE" $G
rg -n "mongodb::|doc!\s*\{|ldap3::|sxd_xpath|quick_xml|roxmltree|xml-rs" $G
rg -n "build\.rs|git\s*=|path\s*=|\[patch" --glob "Cargo.toml"
rg -n "async_graphql|juniper|tonic::|tokio_tungstenite|axum::extract::ws" $G
```

## Class coverage index

| ID | Vulnerable in Rust | Safe equivalent | FP trap / note |
|----|-------------------|-----------------|----------------|
| L01 | § XSS: `Html(format!(…user…))`, `content_type("text/html").body(format!)`, Tera/Askama `|safe`, autoescape disabled | Askama/Maud/Tera auto-escape, `html_escape` | `Json(x)` is JSON; Tera escapes only `.html/.htm/.xml` by default |
| L02 | `Tera::one_off(user_template, …)`, `tera.add_raw_template(name, user)`, Handlebars `render_template(user)` | compile-time templates (Askama) | Askama templates are compiled — not injectable |
| L03 | embedded interpreters (`rhai`, `mlua`, `deno_core`, `boa`) running user scripts; `libloading` with user path | sandboxed engine config, no user code | Rust has no `eval` |
| L04 | § SQL: `sqlx::query(&format!())`, Diesel `sql_query(format!)`, `dsl::sql(user)`, `rusqlite` `execute(&format!)` | `.bind()`, `query!` macros, `params![]` | `query!` is compile-time checked |
| L05 | mongodb crate `doc!{ "user": user_bson }` where value is `Bson` from user JSON (`{"$ne": …}`) | deserialize into typed struct, `Bson::String` only | |
| L06 | `Command::new("sh").arg("-c").arg(x)`; Windows `.bat` arg quoting (CVE-2024-24576, fixed 1.77.2) | `Command::new(bin).args([...])` | no shell by default |
| L07 | `ldap3` filter `format!("(uid={})", u)`; `sxd_xpath` with concatenated expressions | `ldap3::ldap_escape(u)`; fixed XPath + variables | |
| L08 | log injection with `info!("{}", input)` in text logs; `HeaderValue::from_str` rejects CR/LF | `tracing` JSON subscriber, `{:?}` debug quoting | header splitting N/A (http crate validates) |
| L09 | § SSRF: `reqwest::get(user)`, `Client::get(user)`, redirects default to 10 hops | allow-list + resolved-IP check (custom `dns_resolver`), `redirect::Policy::none()` | |
| L10 | `Path::new(base).join(user)` (absolute replaces base) then `fs::read` | `canonicalize` + `starts_with(base)`, `tower_http::ServeDir`, `actix_files` | |
| L11 | `zip` `file.name()` / `mangled_name` misuse, `tar` manual `unpack(dest.join(path))`, multipart filename as path | `enclosed_name()`, `Entry::unpack_in`, generated names | |
| L12 | `bincode`/`rmp-serde`/`serde_yaml` without size limits (memory DoS); `serde` with `#[serde(untagged)]` confusion | `bincode::options().with_limit`, body limits | no gadget-chain RCE in serde |
| L13 | `libxml` bindings with entity substitution; `quick-xml`/`roxmltree`/`xml-rs` don't resolve external entities | pure-Rust parsers | XXE usually N/A; `roxmltree` limits entity depth |
| L14 | `#[derive(Deserialize)]` on DB models with `is_admin`/`role` fields bound from request JSON → mass assignment | separate input DTO, `#[serde(skip_deserializing)]` | |
| L15 | `actix-session`/`tower-sessions` with hardcoded key, `cookie_secure(false)`, no rotation on login (`renew()`) | key from env, secure cookies, `session.renew()` | |
| L16 | `jsonwebtoken` `insecure_disable_signature_validation()`, `dangerous_insecure_decode`, `Validation` with `validate_exp=false`, algorithms not pinned; `oauth2` crate without CSRF `state` check | `Validation::new(Algorithm::RS256)`, compare `CsrfToken` | |
| L17 | Axum `route_layer(auth)` applied before later `.route()` calls (later routes unprotected); handlers loading by ID without owner check | layer after all routes / per-route extractor (`AuthUser`) | Axum `.layer` applies to routes registered before it |
| L18 | cookie-auth forms without CSRF (`axum_csrf`, `actix-csrf`), `SameSite::None` | CSRF middleware, `SameSite::Lax` | bearer APIs N/A |
| L19 | `CorsLayer::permissive()`/`very_permissive()`, `Cors::permissive()`, `AllowOrigin::mirror_request()` + credentials | explicit origins | `tower-http` panics on `Any` + credentials |
| L20 | missing security headers (`tower_http::set_header`), cookies without `secure/http_only` | `SetResponseHeaderLayer`, cookie builder flags | |
| L21 | `Redirect::to(&query.next)` | allow-list / relative paths | |
| L22 | `md5`/`sha1` crates for passwords, raw `aes` block ECB, nonce reuse with `aes-gcm`, hand-rolled crypto | `argon2`, `aes-gcm` + `OsRng` nonces, `ring` | |
| L23 | `SmallRng`, `StdRng::seed_from_u64(const)`, `fastrand` for secrets | `OsRng`, `rand::thread_rng()` (CSPRNG) | `thread_rng` is cryptographically secure |
| L24 | `danger_accept_invalid_certs(true)`, `danger_accept_invalid_hostnames`, rustls `dangerous().set_certificate_verifier(NoVerify)` | default verification | |
| L25 | secrets in `config.toml`/`const`, `RUST_LOG=debug` in prod leaking bodies | env, `secrecy::Secret<String>` | |
| L26 | returning `format!("{:?}", err)` to clients (DB/internal paths), `anyhow` chain in responses | map to generic error responses | |
| L27 | `Debug` derive on structs with passwords/tokens logged via `{:?}` | `secrecy` crate, manual `Debug` | |
| L28 | `unwrap()`/`expect()`/indexing on user input → panic (task dies; `panic="abort"` kills process); unbounded bodies (`DefaultBodyLimit::disable`); `fancy-regex` backtracking | `?` error propagation, body limits, `regex` crate | `regex` crate is linear-time — ReDoS N/A |
| L29 | check-then-act across `.await` with separate lock acquisitions; DB read-modify-write without `FOR UPDATE`; `std::sync::Mutex` held across `.await` (deadlock) | single critical section, DB transactions, `tokio::sync::Mutex` | safe Rust prevents data races, not logic races |
| L30 | release builds wrap integer overflow silently (`overflow-checks=false`); `as` casts truncate (`u64 as u32`, `i64 as usize`); float money | `checked_*`/`try_into()`, `rust_decimal` | |
| L31 | § Memory safety: `unsafe` blocks, `from_raw_parts`, `get_unchecked`, `set_len`, `transmute`, `static mut`, `unsafe impl Send/Sync`, FFI `CStr::from_ptr`, dangling `CString::as_ptr()` | safe abstractions, `miri` testing | memory bugs only in `unsafe`/FFI |
| L32 | `build.rs` running arbitrary code at build, git/path deps, `[patch]` overrides, proc-macro crates with network access, typosquats | `Cargo.lock` committed, `cargo vet`/`cargo deny` | SCA opt-in |
| L33 | `async-graphql` without `limit_depth`/`limit_complexity`, introspection on; `tonic` without interceptor auth; WebSocket upgrade without auth/origin check | schema limits, interceptors, origin validation | |
| L34 | `libloading::Library::new(user)`, dynamic dispatch by user string into function tables | static match | |
| L35 | `unwrap` on `Option` from user input; `Rc<RefCell>` borrow panics; `mem::forget` leaks; `Drop` not running on `process::exit`; secrets not zeroized (`zeroize` crate) | `?`, `zeroize` | |
