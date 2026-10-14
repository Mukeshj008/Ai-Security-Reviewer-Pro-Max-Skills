# Pack: Ruby (Rails, Sinatra, Hanami, Rack)

**Detect:** `Gemfile`, `*.rb`, `*.erb`, `*.haml`, `*.slim`, `config/routes.rb`.

## Sources

`params[...]` (Rails/Sinatra), `request.headers`, `request.body`, `cookies`, `request.env`, `params.permit!`, ActiveJob/Sidekiq args.

## XSS & templates

| Vulnerable | Safe equivalent | FP trap |
|-----------|-----------------|---------|
| ERB `<%== x %>`, `raw(x)`, `x.html_safe`, `content_tag` with `html_safe` input | `<%= x %>` (escaped in Rails ≥ 3) | Plain ERB outside Rails (`ERB.new`) does **not** escape |
| `link_to name, user_url` with `javascript:` URL | validate scheme | `link_to` escapes the text, not the scheme |
| HAML `!= x`, Slim `== x` | `= x` | |
| `render inline: params[:x]` / `render html: x.html_safe` | `render plain:` | |
| `sanitize(x)` with custom `tags:`/`attributes:` allowing `style`/`on*` | default allow-list | |

## SSTI / code

`ERB.new(user).result`, `render inline: user` (ERB execution), `eval`, `instance_eval`, `class_eval`, `send(params[:m], …)` / `public_send` with user method name, `constantize` / `safe_constantize` on params (`params[:type].constantize.new`), `Kernel#open(user)` (`|cmd` → command execution), `Object.const_get(user)`.

## SQL / ActiveRecord

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `where("name = '#{x}'")`, `where("… " + x)`, `order(params[:sort])`, `pluck(params[:col])`, `select(user)`, `group/having/joins/from(user)`, `find_by_sql("… #{x}")`, `connection.execute("…#{x}")`, `exists?(params[:id])` with string/hash | `where(name: x)`, `where("name = ?", x)`, `sanitize_sql_array`, allow-listed `order` | `find(params[:id])` is safe; `where(params[:filter])` with a Hash permits arbitrary column conditions |
| `Arel.sql(user)` | | |

## Command execution

`system("… #{x}")`, `` `…#{x}` ``, `%x(…)`, `exec`, `spawn("…")`, `IO.popen("…#{x}")`, `Open3.capture2("… #{x}")`, `Kernel#open("|…")`. Safe: `system(bin, arg1, arg2)` (array form, no shell), `Open3.capture2(bin, arg)`.

## SSRF

`Net::HTTP.get(URI(user))`, `open-uri` `URI.open(user)` (also local files with `open`), `HTTParty.get(user)`, `Faraday`, `RestClient`. TLS: `verify_mode = OpenSSL::SSL::VERIFY_NONE`, `ssl: { verify: false }`.

## Path / file

`File.read(params[:f])`, `send_file(params[:path])`, `File.join(base, user)` (no normalization), `Rails.root.join(user)` (absolute `user` replaces root). Fix: `File.expand_path` + `start_with?(base + '/')`, `File.basename`. ActiveStorage/CarrierWave: content type from client, `extension_allowlist` missing.

## Deserialization

`Marshal.load(user)`, `YAML.load(user)` (Psych < 4 unsafe by default; Psych 4 `load` = safe_load), `YAML.unsafe_load`, `Oj.load(x, mode: :object)`, cookie store with `Marshal` serializer + leaked `secret_key_base` → RCE. Fix: `JSON.parse`, `YAML.safe_load`, `cookies_serializer = :json`.

## XML

Nokogiri `Nokogiri::XML(x) { |c| c.noent }` / `Nokogiri::XML::ParseOptions::NOENT|DTDLOAD` → XXE; default is safe. REXML entity expansion (patched in recent versions).

## Crypto / randomness

`rand`/`Random.new` for tokens → `SecureRandom.hex/urlsafe_base64`; `Digest::MD5/SHA1` for passwords → `bcrypt` / `has_secure_password`; `OpenSSL::Cipher.new('aes-256-ecb')`; `==` on tokens → `ActiveSupport::SecurityUtils.secure_compare` / `Rack::Utils.secure_compare`. `secret_key_base` / `config/master.key` committed.

## Auth / authorization / mass assignment

- `skip_before_action :authenticate_user!` / `skip_before_action :verify_authenticity_token` on sensitive actions; `before_action ... only:` lists that miss new actions.
- IDOR: `Order.find(params[:id])` vs `current_user.orders.find(params[:id])`; Pundit `authorize` / CanCanCan `load_and_authorize_resource` missing (`verify_authorized` absent).
- Mass assignment: `params.permit!`, `permit(:role, :admin)`, `update(params[:user])` (pre-strong-params), `attr_accessible` (Rails 3).
- Devise: `config.paranoid = false` (user enumeration), long `remember_for`, `reset_password_within` unset.
- JWT gem `JWT.decode(t, nil, false)` (verification off) or algorithm not pinned.

## CSRF / CORS / headers

`protect_from_forgery` missing or `with: :null_session` on cookie-auth controllers; `rack-cors` `origins '*'` + `credentials: true` (rack-cors rejects) vs `origins { |src| true }` + credentials (reflection); `config.force_ssl = false` in production; `config.action_dispatch.default_headers` cleared.

## Redirect / misc

`redirect_to params[:url]` (Rails 7 `raise_on_open_redirects` mitigates when enabled), `redirect_to(params.merge(...))` host injection; `config.consider_all_requests_local = true` in production; logging params without `filter_parameters` for `password`, `token`, `otp`.

## DoS

`Regexp.new(params[:q])`; Ruby < 3.2 regex backtracking (3.2 adds memoization and `Regexp.timeout`); unbounded `per_page`.

## Hint rg

```bash
G='--glob *.{rb,erb,haml,slim,rake} -g !vendor/**'
rg -n "<%==|\braw\s*\(|\.html_safe|render\s+(inline|html)\s*:|!=\s|==\s" --glob "*.{erb,haml,slim,rb}" -g '!vendor/**'
rg -n "ERB\.new|\b(eval|instance_eval|class_eval)\b|\.(send|public_send)\s*\(\s*params|constantize|const_get\s*\(" $G
rg -n "\.(where|order|pluck|select|group|having|joins|from|find_by_sql|exists\?)\s*\(\s*(\"[^\"]*#\{|params)|connection\.execute|Arel\.sql" $G
rg -n "\bsystem\s*\(|\`[^\`]*#\{|%x\(|\bexec\s*\(|\bspawn\s*\(|IO\.popen|Open3\.|\bopen\s*\(" $G
rg -n "Net::HTTP|URI\.open|HTTParty|Faraday|RestClient|VERIFY_NONE|verify:\s*false" $G
rg -n "send_file\s*\(|File\.(read|open|join)\s*\(|Rails\.root\.join\s*\(\s*params" $G
rg -n "Marshal\.load|YAML\.(load|unsafe_load)|Oj\.load|cookies_serializer|NOENT|DTDLOAD|\.noent" $G
rg -n "\brand\s*\(|Random\.new|Digest::(MD5|SHA1)|-ecb|secure_compare|secret_key_base" $G
rg -n "skip_before_action|protect_from_forgery|null_session|permit!|\.permit\s*\(|verify_authorized|authorize\s" $G
rg -n "redirect_to\s+params|redirect_to\s*\(\s*params|consider_all_requests_local|force_ssl|filter_parameters|Regexp\.new" $G
rg -n "Net::LDAP|Filter\.(eq|construct)|\.xpath\s*\(|Mongoid|\.where\s*\(\s*params" $G
rg -n "with_lock|lock!|lock\(|transaction\s+do|increment!|update_counters" $G
rg -n "graphql-ruby|GraphQL::Schema|max_depth|ActionCable|stream_from" $G
rg -n "source\s+['\"]http:|git:\s|github:\s" --glob "Gemfile"
```

## Class coverage index

| ID | Vulnerable in Ruby | Safe equivalent | FP trap / note |
|----|-------------------|-----------------|----------------|
| L01 | § XSS: `raw`, `html_safe`, `<%==`, HAML `!=`, `render html:`/`inline:`, `link_to` with `javascript:` | `<%= %>` (Rails escapes), `sanitize` default allow-list | plain `ERB.new` outside Rails doesn't escape |
| L02 | `ERB.new(user).result`, `render inline: params[:x]`, Liquid with custom unsafe filters, Slim/HAML compiled from user strings | fixed templates; Liquid (safe by design) | Liquid templates from users are acceptable |
| L03 | `eval`, `instance_eval`, `class_eval`, `send(params[:m])`, `Kernel#open("|cmd")` | `public_send` with allow-list | |
| L04 | § SQL: string interpolation in `where/order/pluck/select/group/joins/find_by_sql`, `Arel.sql(user)` | hash conditions, `?` placeholders, `sanitize_sql_*` | `find(params[:id])` is safe |
| L05 | Mongoid `where(params[:filter])` / `User.where(name: params[:name])` where name is a Hash (`name[$ne]=`) | `.to_s`, strong params with scalar types | Rack parses `a[b]=` into hashes |
| L06 | `system("…#{x}")`, backticks, `%x()`, `IO.popen(str)`, `Open3.*(str)`, `Kernel#open("|…")` | array form `system(bin, arg)` | |
| L07 | `Net::LDAP::Filter.construct("(uid=#{u})")`; Nokogiri `xpath("//u[@n='#{x}']")` | `Net::LDAP::Filter.eq('uid', u)` (escapes); XPath variable bindings | |
| L08 | `response.headers[...] = user` (Rack rejects newlines in recent versions), log forging in text logs | `Logger` with formatter escaping, lograge JSON | |
| L09 | `Net::HTTP.get(URI(user))`, `URI.open(user)`, HTTParty/Faraday/RestClient with user URL | allow-list, `ssrf_filter` gem | |
| L10 | `send_file(params[:path])`, `File.read(user)`, `Rails.root.join(user)` | `File.expand_path` + prefix check, `File.basename` | |
| L11 | ActiveStorage/CarrierWave without content-type/extension allow-list, `Zip::File` extraction without path checks (rubyzip <1.3) | `extension_allowlist`, rubyzip ≥1.3 `on_exists_proc` + path validation | |
| L12 | `Marshal.load`, `YAML.load` (Psych <4), `YAML.unsafe_load`, `Oj.load(mode: :object)`, Marshal cookie serializer | `JSON.parse`, `YAML.safe_load`, `:json` cookies | Psych 4 `load` is safe |
| L13 | Nokogiri `noent`/`dtdload` options, REXML old versions entity expansion | Nokogiri defaults | |
| L14 | `params.permit!`, `permit(:role, :admin)`, `update(params[:user])` (pre-strong-params), `attr_accessible` | explicit `permit` lists | |
| L15 | Devise `paranoid=false` (enumeration), no lockout (`:lockable`), session not reset on login (`reset_session`) | Devise lockable, `reset_session` | Devise resets session on sign-in |
| L16 | `JWT.decode(t, nil, false)`, algorithm not pinned, OmniAuth without CSRF protection (`omniauth-rails_csrf_protection`) | `JWT.decode(t, key, true, algorithm: 'RS256')` | |
| L17 | `skip_before_action :authenticate_user!`, `Order.find(params[:id])` vs `current_user.orders.find`, Pundit/CanCan missing (`verify_authorized` absent) | scoped finders, `after_action :verify_authorized` | |
| L18 | `skip_before_action :verify_authenticity_token`, `protect_from_forgery with: :null_session` on cookie-auth controllers | `protect_from_forgery with: :exception` | API-only controllers with token auth N/A |
| L19 | rack-cors `origins { true }` / regex unanchored + `credentials: true` | explicit list | |
| L20 | `force_ssl=false`, cleared `default_headers`, cookies without `secure` | `config.force_ssl = true`, `secure_headers` gem | |
| L21 | `redirect_to params[:url]`, `redirect_to(params.merge(host: …))` | `allow_other_host: false` / Rails 7 `raise_on_open_redirects` | |
| L22 | `Digest::MD5/SHA1` passwords, `OpenSSL::Cipher` ECB / static IV | `bcrypt`, `has_secure_password`, AES-GCM via `ActiveSupport::MessageEncryptor` | |
| L23 | `rand`, `Random.new`, `SecureRandom` misuse via `rand(…)` | `SecureRandom.hex/urlsafe_base64/uuid` | |
| L24 | `verify_mode = OpenSSL::SSL::VERIFY_NONE`, Faraday `ssl: { verify: false }` | defaults | |
| L25 | `secret_key_base`/`master.key` committed, credentials in `database.yml` | Rails credentials (encrypted) + env key | |
| L26 | `consider_all_requests_local = true` in prod, exception messages in JSON responses | `rescue_from` with generic messages | |
| L27 | logging params without `filter_parameters` (`password`, `token`, `otp`, `card`) | `config.filter_parameters += [...]` | |
| L28 | `Regexp.new(params[:q])`, backtracking regex (Ruby <3.2 no timeout), unbounded `per_page`, `JSON.parse` huge bodies | `Regexp.timeout` (3.2+), `Regexp.escape`, limits | |
| L29 | balance updates without `with_lock`/`lock!`, `find_or_create_by` races without unique index, Sidekiq job double-run | `with_lock`, unique indexes, `update_counters`, idempotent jobs | |
| L30 | Float money, negative quantities, `to_i` silently returning 0 on bad input | `BigDecimal`, `Integer(x)` (raises), validations | |
| L31 | N/A for Ruby code; C extensions (`ext/*.c`) → `c-cpp.md`; `Fiddle`/FFI with user data | — | |
| L32 | `source 'http://…'`, `git:`/`github:` gems on branches, `Gemfile.lock` missing, gems with native extensions compiling at install | HTTPS source, lockfile, pinned refs | SCA opt-in |
| L33 | graphql-ruby without `max_depth`/`max_complexity`, field-level authorization missing; ActionCable channels without `reject` on unauthenticated `connect` | schema limits, `authorized?`, `identified_by` + reject | |
| L34 | `params[:type].constantize`, `Object.const_get(user)`, `send(user)` | allow-list hash | |
| L35 | `respond_to?`-based dispatch, `method_missing` exposing internals, `==` vs `secure_compare` for tokens, symbol creation from input (DoS on Ruby <2.2) | `ActiveSupport::SecurityUtils.secure_compare` | |
