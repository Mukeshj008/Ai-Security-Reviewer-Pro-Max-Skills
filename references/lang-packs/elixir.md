# Pack: Elixir / Erlang (Phoenix, Plug, LiveView, Ecto, Absinthe, Cowboy)

**Detect:** `mix.exs`, `*.ex`, `*.exs`, `*.heex`, `*.eex`, `*.leex`, `rebar.config`, `*.erl`.

## Sources

`conn.params`, `conn.query_params`, `conn.body_params`, `conn.path_params`, `get_req_header(conn, …)`, `conn.cookies`; LiveView `handle_event(_, params, socket)`, `mount(params, …)`; Channels `handle_in(event, payload, socket)`; Absinthe resolver args; Oban job args.

## Key language rules

- HEEx/EEx `<%= x %>` in Phoenix templates is escaped via `Phoenix.HTML`; `raw(x)` and `{:safe, x}` are **raw**. Plain `EEx.eval_string` (outside Phoenix) does **not** escape.
- Ecto `from u in User, where: u.name == ^name` binds; `fragment("lower(?)", ^x)` binds; `Ecto.Adapters.SQL.query(Repo, "… #{x}")` and `fragment` with interpolated **string** (not literal) are injection — Ecto rejects non-literal fragment strings at compile time, so look for `Ecto.Adapters.SQL.query` / `Repo.query`.
- `String.to_atom(user_input)` exhausts the atom table (never garbage-collected) → VM crash (DoS).
- `:erlang.binary_to_term(user)` can create atoms and funs → use `binary_to_term(x, [:safe])` (still not fully safe for untrusted data).

## Hint rg

```bash
G='--glob *.{ex,exs,heex,eex,leex,erl} -g !_build/** -g !deps/**'
rg -n "raw\s*\(|\{:safe,|Phoenix\.HTML\.raw|html\s*\(\s*conn\s*,\s*\"" $G
rg -n "EEx\.eval_string|Code\.eval_string|Code\.eval_quoted|:erlang\.binary_to_term|String\.to_atom|List\.to_atom|apply\s*\(" $G
rg -n "SQL\.query|Repo\.query|fragment\s*\(\s*\"[^\"]*#\{" $G
rg -n "System\.cmd|:os\.cmd|Port\.open" $G
rg -n "HTTPoison|Req\.(get|post|request)|Tesla|Finch|:httpc|Mint\.HTTP" $G
rg -n "Path\.join|File\.(read|write|rm|open|stream)|send_file|Plug\.Static" $G
rg -n "protect_from_forgery|put_secure_browser_headers|CORSPlug|check_origin|secret_key_base|signing_salt" $G
rg -n ":rand\.|:crypto\.(hash|strong_rand_bytes)|Bcrypt|Argon2|Pbkdf2|verify_none" $G
rg -n "Regex\.compile|~r/|Absinthe|max_complexity|Phoenix\.Socket|channel\s+\"" $G
```

## Class coverage index

| ID | Vulnerable in Elixir / Erlang | Safe equivalent | FP trap / note |
|----|------------------------------|-----------------|----------------|
| L01 | `raw(x)`, `{:safe, x}`, `html(conn, "<p>#{x}</p>")`, `send_resp(conn, 200, "<…#{x}…>")` with HTML content type | HEEx `<%= x %>` / `{x}`, `json(conn, map)` | HEEx escapes by default |
| L02 | `EEx.eval_string(user_template, assigns)`, Solid/Liquid with unsafe custom filters | compile-time templates (`~H`) | `~H` sigils are compiled |
| L03 | `Code.eval_string/eval_quoted(user)`, `apply(String.to_atom(mod), String.to_atom(fun), args)` | dispatch map | |
| L04 | `Ecto.Adapters.SQL.query(Repo, "… #{x}")`, `Repo.query("… #{x}")` | `Repo.query("… $1", [x])`, Ecto query bindings `^x` | `fragment` requires compile-time literal |
| L05 | MongoDB driver `Mongo.find(conn, coll, params)` with user maps (`%{"$ne" => …}`) | cast with Ecto changesets / explicit scalars | |
| L06 | `:os.cmd(String.to_charlist("ping " <> host))`, `System.cmd("sh", ["-c", x])` | `System.cmd(bin, [arg])` (no shell) | `System.cmd` with arg list is safe |
| L07 | `:eldap.search` with filters built from strings (`:eldap.equalityMatch` is safe), XPath via `SweetXml` `~x` built with interpolation | `:eldap.equalityMatch/2`, fixed `~x` paths | |
| L08 | `put_resp_header(conn, "x", user)` (Plug validates CR/LF), log injection with `Logger.info("… #{x}")` in text format | `Logger` metadata + JSON formatter | header splitting N/A on Plug |
| L09 | `HTTPoison.get(user_url)`, `Req.get(user_url)`, `:httpc.request(user)`, Tesla with user base URL | allow-list + resolved-IP check, `redirect: false` | |
| L10 | `File.read(Path.join(base, user))`, `send_file(conn, 200, user)` | `Path.safe_relative/2` (1.14+), `Plug.Static` | `Path.join` doesn't block `..` |
| L11 | `%Plug.Upload{filename: name}` used as path, `:zip.unzip` / `:erl_tar.extract` without path checks | generated names, validate entries (`:zip.list_dir` first) | |
| L12 | `:erlang.binary_to_term(user)` (atom/fun creation), `Plug.Crypto.non_executable_binary_to_term` misuse | JSON (`Jason`), `binary_to_term(x, [:safe])` + `non_executable_binary_to_term` | |
| L13 | `:xmerl_scan.string(user)` (entity expansion / external entities by default), SweetXml on untrusted XML | `SweetXml.parse(x, dtd: :none)`, `xmerl` with `{:fetch_fun, …}` denying | |
| L14 | `Ecto.Changeset.cast(user, params, [:role, :is_admin])` exposing privileged fields; `struct(User, params)` | cast only user-editable fields; separate admin changesets | |
| L15 | session cookie `signing_salt` without `encryption_salt` storing sensitive data, `secure: false`, no `configure_session(renew: true)` on login | `encryption_salt`, `renew: true` | |
| L16 | `Joken` without signer/claims validation, Guardian `decode_and_verify` skipped (`peek_claims` used for authz), OAuth (Ueberauth) without state check | `Joken.verify_and_validate`, Guardian pipelines | `peek` for display only is fine |
| L17 | routes outside `pipe_through :require_authenticated_user`, LiveView `mount` without auth (`on_mount`), `Repo.get(Post, id)` without owner, channel `join` returning `{:ok, socket}` unconditionally | auth pipelines, `on_mount` hooks, scoped queries | |
| L18 | browser pipeline missing `:protect_from_forgery`, LiveView without CSRF token in `connect_params` | Phoenix defaults | API pipelines with token auth N/A |
| L19 | `CORSPlug, origin: "*"` with credentials, `check_origin: false` on sockets | explicit origins | |
| L20 | browser pipeline without `put_secure_browser_headers`, `force_ssl` missing | Phoenix defaults, `Plug.SSL` | |
| L21 | `redirect(conn, external: params["next"])` | `redirect(conn, to: path)` (local only) | `to:` rejects external URLs |
| L22 | `:crypto.hash(:md5/:sha, password)`, `:crypto.crypto_one_time(:aes_128_ecb, …)` | `Bcrypt`/`Argon2`, `:aes_256_gcm` | |
| L23 | `:rand.uniform` / `Enum.random` for tokens | `:crypto.strong_rand_bytes/1` | |
| L24 | `:ssl` / `:httpc` with `verify: :verify_none` (Erlang/OTP <26 default for `:httpc`!), Hackney `insecure: true` | `verify: :verify_peer` + `cacerts: :public_key.cacerts_get()` | OTP 26+ verifies by default |
| L25 | `secret_key_base`/DB passwords in `config/*.exs` committed, `debug_errors: true` in prod | `config/runtime.exs` with env vars | `dev.exs` not used in prod |
| L26 | `debug_errors: true`, returning `inspect(error)` to clients | `ErrorView`/`ErrorJSON` | |
| L27 | `Logger.info(inspect(params))` with passwords; Phoenix `filter_parameters` missing custom keys | `config :phoenix, :filter_parameters, [...]` | |
| L28 | `String.to_atom(user)` atom exhaustion, `Regex.compile(user)` (PCRE backtracking), unbounded `Plug.Parsers` `length`, mailbox flooding of a GenServer | `String.to_existing_atom`, length limits, back-pressure | |
| L29 | check-then-act across processes without DB locks, GenServer state races when callers bypass the server, Oban jobs without `unique` | `Repo.transaction` + `lock: "FOR UPDATE"`, single-writer GenServer, Oban `unique` | BEAM processes don't share memory |
| L30 | float money, negative quantities, client totals trusted | `Decimal`, changeset validations | |
| L31 | NIFs (C/Rust via Rustler) can crash the whole VM → `c-cpp.md` / `rust.md` | dirty schedulers, safe Rustler code | pure Elixir is memory-safe |
| L32 | `mix.exs` deps from git branches, Hex packages unpinned, `mix.lock` missing, compile-time code execution in deps | `mix.lock`, `mix hex.audit` | SCA opt-in |
| L33 | Absinthe without `max_complexity`/depth, introspection on; Phoenix Channels `join` without auth; `check_origin: false` | `Absinthe.Plug` `analyze_complexity: true`, socket `connect/3` auth | |
| L34 | `apply(String.to_atom(mod), …)`, `Module.concat([user])` | dispatch map | |
| L35 | `String.to_atom` from input, `==` vs `Plug.Crypto.secure_compare` for tokens, `with` clauses falling through on unexpected error tuples (fail-open) | `secure_compare`, explicit `else` in `with` | |
