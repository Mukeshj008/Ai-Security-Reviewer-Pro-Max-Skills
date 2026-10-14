# Pack: Python (Django, Flask, FastAPI, Starlette, Tornado, aiohttp, Celery, scripts)

**Detect:** `*.py` + `requirements*.txt` / `pyproject.toml` / `Pipfile` / `setup.py`; frameworks from imports or deps.

## Sources

Django `request.GET/POST/body/FILES/META/COOKIES/headers`, DRF `request.data/query_params`, URL kwargs; Flask `request.args/form/json/values/files/headers/cookies`, `view_args`; FastAPI path/query/body params (typed — check the type: `str` is still attacker text), `Request.query_params`; Celery task args; `sys.argv`/`input()` only for CLIs exposed to users; values from DB/cache written by users.

## XSS & templates

| Vulnerable | Safe equivalent | FP trap |
|-----------|-----------------|---------|
| Django `{{ x|safe }}`, `{% autoescape off %}`, `mark_safe(user)`, `SafeString(user)`, `format_html` misuse `format_html(user_string)` | `{{ x }}` (auto-escaped), `format_html('<b>{}</b>', x)`, `escape(x)` | `format_html` with literal format string is safe |
| Jinja2 `Environment(...)` **without** `autoescape=True` / `select_autoescape()` — default is **off** | `Environment(autoescape=select_autoescape())` | Flask's `render_template` auto-escapes only `.html/.htm/.xml/.xhtml` templates; `.txt`/`.j2` are **not** |
| Jinja `{{ x|safe }}`, `Markup(user)`, `{% autoescape false %}` | `Markup.escape(x)` | |
| Flask view `return f"<p>{name}</p>"` / `return "<h1>" + x` (default mimetype `text/html`) | `return jsonify(...)`, `escape(x)`, `Response(x, mimetype='text/plain')` | `jsonify` is not XSS |
| FastAPI/Starlette `HTMLResponse(f"...{x}...")` | Jinja2Templates with autoescape | `JSONResponse` / returning dict → JSON |
| `json.dumps(x)` inside `<script>` in a template | Django `{{ x|json_script:"id" }}`, Jinja `{{ x|tojson }}` (escapes `<>&'`) | |

## SSTI / code injection

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `render_template_string(user)`, `Template(user).render()`, `Environment().from_string(user)`, Django `Template(user)` / `engines['django'].from_string(user)` | Fixed templates; user value only in context | `render_template_string(FIXED, name=x)` is safe (but XSS if autoescape off) |
| Mako `Template(user)` | | |
| `eval`, `exec`, `compile`, `__import__(user)`, `importlib.import_module(user)`, `getattr(obj, user)()` | `ast.literal_eval` for literals; dispatch dict | `ast.literal_eval` is safe |
| `str.format` with user **format string** on objects: `user_fmt.format(obj=request)` → attribute read (`{obj.__class__…}`) | f-string with fixed format | |

## SQL / ORM

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `cursor.execute(f"… {x}")`, `"…%s" % x`, `"…" + x`, `.format(x)` | `cursor.execute("… %s", (x,))` (psycopg/MySQLdb), `?` for sqlite3 | `execute(sql, params)` with tuple is safe |
| Django `.raw(f"…{x}")`, `.extra(where=[f"…"])`, `RawSQL(f"…")`, `cursor.execute(f"…")` | `.raw("… %s", [x])`, ORM filters | `Model.objects.filter(email=x)` is parameterized |
| Django `order_by(user)` / `values(*user_fields)` / `filter(**request.GET.dict())` (lookup injection: `password__startswith`) | allow-list field names | |
| SQLAlchemy `text(f"…{x}")`, `session.execute(f"…")`, `.filter(f"…")` / `literal_column(user)` | `text("… :x").bindparams(x=…)`, ORM expressions | |
| Peewee `SQL(f"…")`, pandas `read_sql(f"…")` | params argument | |

## NoSQL

PyMongo `find(request.json)` / `find({"user": data["user"]})` where value can be a dict (`{"$ne": None}`); `$where` with strings. Fix: type-check scalars, reject keys starting with `$`.

## Command execution

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `os.system(x)`, `os.popen(x)`, `subprocess.*(str, shell=True)`, `commands.getoutput` | `subprocess.run([bin, arg], shell=False)`, `shlex.quote` when shell is unavoidable | list args without shell are safe from injection but not from option injection (`-o`, `--`) |
| `subprocess.run(f"… {x}", shell=True)` | | `shell=True` with a fully constant string is not injection |

## SSRF

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `requests.get(user_url)`, `httpx`, `urllib.request.urlopen(user_url)` (also supports `file://`), `aiohttp.ClientSession().get(user_url)` | parse with `urllib.parse`, allow-list host/scheme, resolve and block private/link-local (`ipaddress.ip_address(x).is_private`), `allow_redirects=False` | Base URL from settings + user path param → path control, not host control |
| `urlopen` with user URL → `file:///etc/passwd` | block non-http(s) schemes | |
| PDF/image renderers fetching user HTML (`weasyprint`, `pdfkit`, `imgkit`) | disable remote resources | |

TLS: `requests.get(..., verify=False)`, `ssl._create_unverified_context()`, `urllib3.disable_warnings` alongside `verify=False`.

## Path / file / upload

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| `open(os.path.join(BASE, user))` — absolute `user` **replaces** BASE in `os.path.join` | `p = (BASE / user).resolve(); p.is_relative_to(BASE.resolve())` (3.9+) | `os.path.basename(user)` before join is safe for traversal |
| Flask `send_file(user)` | `send_from_directory(dir, name)` (uses `safe_join`) | |
| Django `FileResponse(open(user))`, storage `save(upload.name)` | `get_valid_filename`, generated names | Django `FileSystemStorage` normalizes names but check custom `upload_to` callables |
| `zipfile.extractall` / `tarfile.extractall` (tar: `../`, symlinks, absolute paths) | Python 3.12+ `extractall(filter='data')`; validate members | `zipfile` blocks `..` in names since 3.6.2 but not symlink tricks in tar |
| `tempfile.mktemp()` | `NamedTemporaryFile`, `mkstemp` | |

## Deserialization

| Vulnerable | Safe |
|-----------|------|
| `pickle.loads`, `cPickle`, `dill`, `joblib.load`, `torch.load` (without `weights_only=True`), `numpy.load(allow_pickle=True)`, `shelve` on untrusted data | `json`, `torch.load(weights_only=True)` |
| `yaml.load(x)` without `Loader` (PyYAML < 5.1 default unsafe), `yaml.load(x, Loader=yaml.Loader/FullLoader/UnsafeLoader)`, `yaml.unsafe_load` | `yaml.safe_load` |
| `jsonpickle.decode(user)` | `json.loads` |
| Django `signing` / sessions with `PickleSerializer` + leaked `SECRET_KEY` → RCE | `JSONSerializer` (default) |

## XML

`xml.etree`, `minidom`, `xml.sax`, `lxml.etree.parse` with `resolve_entities=True` (lxml default resolves internal entities) → XXE/billion laughs depending on parser; use `defusedxml`. `lxml` XPath built from strings → XPath injection; use `xpath('…$x', x=value)`. XML/SOAP strings built with f-strings, `%`, `.format`, or concatenation are structural-injection candidates when attacker data can alter markup; prefer fixed-name `ElementTree`/`lxml` builders or serializers. Run `../xml-security-audit.md`.

## Crypto / randomness

| Vulnerable | Safe |
|-----------|------|
| `random.*` for tokens/OTP/reset links | `secrets.token_urlsafe`, `secrets.randbelow` |
| `hashlib.md5/sha1(password)`, unsalted `sha256(password)` | `bcrypt`, `argon2-cffi`, Django `make_password` |
| PyCrypto/`Crypto.Cipher.AES.new(key, AES.MODE_ECB)`, static IV | `cryptography` AESGCM with random nonce |
| `==` on HMAC/tokens | `hmac.compare_digest` |
| Django `SECRET_KEY` committed; `DEBUG = True` in prod settings; `ALLOWED_HOSTS = ['*']` | env vars per environment |

## Auth / session / JWT

| Vulnerable | Safe | FP trap |
|-----------|------|---------|
| Django view without `@login_required` / `LoginRequiredMixin` / DRF `permission_classes` (check `DEFAULT_PERMISSION_CLASSES` — `AllowAny` is the DRF default) | explicit permission classes | Global `DEFAULT_PERMISSION_CLASSES = [IsAuthenticated]` covers views that don't override |
| DRF `permission_classes = []` or `AllowAny` on sensitive views; `get_queryset` not filtered by `request.user` (IDOR) | filter queryset by owner; object permissions | |
| Flask route without `@login_required` where siblings have it | | Blueprint `before_request` auth hook covers its routes — read it |
| FastAPI route missing `Depends(get_current_user)` | router-level `dependencies=[Depends(...)]` | Router-level dependency covers all routes on that router |
| `jwt.decode(t, options={"verify_signature": False})`, `algorithms` missing (PyJWT < 2) or including `none` | `jwt.decode(t, key, algorithms=["RS256"], audience=…)` | PyJWT ≥ 2 requires `algorithms` |
| `SESSION_COOKIE_SECURE=False`, `CSRF_COOKIE_SECURE=False`, Flask `SECRET_KEY` hardcoded | | |

## CSRF / CORS / headers

- Django `@csrf_exempt` on cookie-authenticated state-changing views; `CsrfViewMiddleware` removed from `MIDDLEWARE`.
- Flask: no `CSRFProtect` with session-cookie auth.
- `django-cors-headers` `CORS_ALLOW_ALL_ORIGINS = True` + `CORS_ALLOW_CREDENTIALS = True`; `CORS_ORIGIN_REGEX_WHITELIST` unanchored; flask-cors `CORS(app, supports_credentials=True)` with `origins='*'`.
- `SECURE_SSL_REDIRECT`, `SECURE_HSTS_SECONDS`, `X_FRAME_OPTIONS`, `SESSION_COOKIE_HTTPONLY` missing in prod settings.
- `USE_X_FORWARDED_HOST = True` / trusting `request.host` for password-reset links → host header poisoning.

## Redirect / mass assignment / logic

- `redirect(request.GET['next'])` — Django `url_has_allowed_host_and_scheme` is the fix.
- DRF `ModelSerializer` with `fields = '__all__'` on writable endpoints → mass assignment of `is_staff`, `balance`, `owner`. Check `read_only_fields`.
- Pydantic models: `extra = 'allow'` + `**model.dict()` into ORM → mass assignment.

## Logging / errors

- `DEBUG = True` / Flask `app.run(debug=True)` (Werkzeug debugger = RCE if reachable).
- `logger.info(request.data)` / `logger.info(f"… {password}")`; `traceback.format_exc()` returned to the client.

## DoS

`re.compile(user)` / catastrophic regex on input; missing `DATA_UPLOAD_MAX_MEMORY_SIZE`/`FILE_UPLOAD_MAX_MEMORY_SIZE` overrides; unbounded `page_size` (DRF `max_page_size` unset); `json.loads` on huge bodies without size cap.

## Hint rg

```bash
G='--glob *.py -g !venv/** -g !.venv/** -g !**/site-packages/**'
rg -n "\|\s*safe|autoescape\s+(off|false)|mark_safe\s*\(|Markup\s*\(|SafeString\s*\(" --glob "*.{py,html,jinja,jinja2,j2,txt}" -g '!venv/**'
rg -n "Environment\s*\(|select_autoescape|autoescape\s*=" $G
rg -n "render_template_string|from_string\s*\(|Template\s*\(" $G
rg -n "return\s+f?['\"]<|HTMLResponse\s*\(|make_response\s*\(\s*f?['\"]<|Response\s*\(\s*f?['\"]<|mimetype\s*=\s*['\"]text/html" $G
rg -n "\b(eval|exec|compile|__import__)\s*\(|import_module\s*\(" $G
rg -n "execute\s*\(\s*f['\"]|execute\s*\([^,]*%\s|execute\s*\([^,]*\.format\(|\.raw\s*\(\s*f|\.extra\s*\(|RawSQL\s*\(|text\s*\(\s*f['\"]" $G
rg -n -i "f['\"][^'\"]*\b(select|insert|update|delete|where)\b|['\"][^'\"]*\b(select|insert|update|delete|where)\b[^'\"]*['\"]\s*(%|\+|\.format)" $G   # SQL built in a variable first
rg -n "order_by\s*\(\s*request|filter\s*\(\s*\*\*request" $G
rg -n "os\.(system|popen)\s*\(|shell\s*=\s*True|subprocess\." $G
rg -n "requests\.(get|post|put|request)\s*\(|httpx\.|urlopen\s*\(|ClientSession" $G
rg -n "verify\s*=\s*False|_create_unverified_context|CERT_NONE" $G
rg -n "os\.path\.join\s*\(|send_file\s*\(|extractall\s*\(|mktemp\s*\(" $G
rg -n "pickle\.|cPickle|dill\.|joblib\.load|torch\.load|allow_pickle\s*=\s*True|yaml\.(load|unsafe_load)\s*\(|jsonpickle" $G
rg -n "xml\.(etree|dom|sax)|lxml\.etree|resolve_entities|defusedxml" $G
rg -n "\brandom\.(random|randint|choice|randrange)|hashlib\.(md5|sha1)|MODE_ECB|compare_digest" $G
rg -n "SECRET_KEY\s*=|DEBUG\s*=\s*True|ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*|debug\s*=\s*True" $G
rg -n "csrf_exempt|CsrfViewMiddleware|CORS_ALLOW_ALL_ORIGINS|CORS_ALLOW_CREDENTIALS|supports_credentials" $G
rg -n "permission_classes|AllowAny|login_required|LoginRequiredMixin|Depends\s*\(|before_request" $G
rg -n "jwt\.decode\s*\(|verify_signature|algorithms\s*=" $G
rg -n "fields\s*=\s*['\"]__all__|extra\s*=\s*['\"]allow|redirect\s*\(\s*request" $G
rg -n "ldap\.|ldap3|search_s\s*\(|\.xpath\s*\(" $G
rg -n "ctypes|cffi|\.from_address|memoryview|pickle\.loads|marshal\.loads" $G
rg -n "select_for_update|transaction\.atomic|F\s*\(\s*['\"]" $G
rg -n "graphene|strawberry|ariadne|websocket|channels\.|grpc\." $G
```

## Class coverage index

| ID | Vulnerable in Python | Safe equivalent | FP trap / note |
|----|---------------------|-----------------|----------------|
| L01 | § XSS: `|safe`, `mark_safe`, `Markup(user)`, `Environment()` without autoescape, `return f"<p>{x}"`, `HTMLResponse(f"...")` | autoescape, `format_html`, `escape` | Flask escapes only `.html/.htm/.xml/.xhtml`; `jsonify` is JSON |
| L02 | § SSTI: `render_template_string(user)`, `Template(user)`, `from_string(user)`, Mako `Template(user)` | fixed templates; `SandboxedEnvironment` (still risky) | fixed template + context is not SSTI |
| L03 | `eval`, `exec`, `compile`, `__import__(user)`, `importlib.import_module(user)`, `str.format` with user format string on objects | `ast.literal_eval`, dispatch dict | `literal_eval` is safe |
| L04 | § SQL: f-string / `%` / `.format` / `+` into `execute`, Django `.raw/.extra/RawSQL`, SQLAlchemy `text(f"")`, `order_by(user)` | `execute(sql, params)`, ORM filters, allow-listed columns | `execute("…%s", (x,))` is bound |
| L05 | PyMongo `find(request.json)` / dict values (`{"$ne": None}`), `$where` | type-check scalars, reject `$` keys | |
| L06 | `os.system`, `os.popen`, `subprocess(..., shell=True)` with input | list args, `shell=False`, `shlex.quote` | constant shell string is fine |
| L07 | `ldap`/`ldap3` `search_s(base, scope, f"(uid={u})")`; lxml `xpath(f"//u[@n='{x}']")` | `ldap.filter.escape_filter_chars`, `ldap3.utils.conv.escape_filter_chars`; `xpath('…$n', n=x)` | |
| L08 | header injection: Werkzeug/Django reject `\n` in headers (modern); log injection with `%s` of raw input into text logs | structured logging / strip CR-LF | `logging` with JSON formatter escapes |
| L09 | § SSRF: `requests/httpx/urllib.urlopen(user_url)` (+`file://`), PDF renderers fetching remote resources | allow-list, IP check (`ipaddress.is_private`), `allow_redirects=False` | settings base + path param = adjacent |
| L10 | `open(os.path.join(BASE, user))` (absolute user replaces BASE), `send_file(user)` | `Path.resolve().is_relative_to(BASE)`, `send_from_directory` | `os.path.basename` first is safe |
| L11 | `upload.name` as path, `tarfile.extractall` (symlinks/`..`), MIME from client | `extractall(filter='data')` (3.12+), generated names, `python-magic` | `zipfile` strips `..` since 3.6.2 |
| L12 | `pickle/cPickle/dill/joblib/torch.load/numpy allow_pickle`, `yaml.load` unsafe loaders, `jsonpickle`, `shelve`, `marshal` | `json`, `yaml.safe_load`, `torch.load(weights_only=True)` | |
| L13 | `xml.etree`/`minidom`/`sax`/`lxml` with unsafe entity settings; f-string/format/concat into XML markup; string-built XPath | `defusedxml`; fixed-name builders/serializers; XPath variables | stdlib `etree` doesn't fetch external entities but can have entity-expansion concerns; safely serialized values are not XML injection |
| L14 | DRF `ModelSerializer fields='__all__'`, Pydantic `extra='allow'` → `**data` into ORM, `setattr(obj, k, v)` loop over request keys, `Model(**request.json)` | explicit fields, `read_only_fields` | |
| L15 | Django views without `@login_required`, DRF default `AllowAny`, Flask routes missing decorator, session cookie flags off, no `cycle_key` on login (Django does it in `login()`) | global permission class, `LoginRequiredMixin` | blueprint `before_request` covers routes |
| L16 | `jwt.decode(..., options={"verify_signature": False})`, missing `algorithms`, `authlib`/`python-jose` alg confusion, OAuth `state` not verified | `jwt.decode(t, k, algorithms=[...], audience=...)` | PyJWT ≥2 requires `algorithms` |
| L17 | `Model.objects.get(pk=pk)` without owner filter, DRF `get_queryset` unfiltered, `has_object_permission` missing | `filter(owner=request.user)`, object permissions | |
| L18 | `@csrf_exempt`, `CsrfViewMiddleware` removed, Flask without `CSRFProtect` on cookie auth | middleware on, tokens | DRF `TokenAuthentication` is not CSRF-prone; `SessionAuthentication` is |
| L19 | `CORS_ALLOW_ALL_ORIGINS + CORS_ALLOW_CREDENTIALS`, unanchored `CORS_ALLOWED_ORIGIN_REGEXES`, flask-cors `supports_credentials` with `*` | explicit origins | |
| L20 | `SESSION_COOKIE_SECURE/HTTPONLY=False`, no `SECURE_HSTS_SECONDS`, `X_FRAME_OPTIONS` unset, missing `SecurityMiddleware` | Django security settings, `flask-talisman` | proxy may add headers |
| L21 | `redirect(request.GET['next'])` | `url_has_allowed_host_and_scheme` | |
| L22 | `hashlib.md5/sha1(password)`, `AES.MODE_ECB`, static IV, PyCrypto (unmaintained) | `bcrypt`/`argon2`, `cryptography` AESGCM | md5 for checksums fine |
| L23 | `random.*` for tokens | `secrets` module | `random` for sampling fine |
| L24 | `verify=False`, `_create_unverified_context`, `CERT_NONE`, `check_hostname=False` | default verification, `certifi` | test code |
| L25 | `SECRET_KEY` committed, `DEBUG=True`, `ALLOWED_HOSTS=['*']`, Flask `debug=True` (Werkzeug console RCE) | env per environment | `settings/dev.py` not used in prod (check `DJANGO_SETTINGS_MODULE`) |
| L26 | `traceback.format_exc()` in responses, `DEBUG=True` error pages, FastAPI `debug=True` | generic errors | |
| L27 | `logger.info(request.data)`, logging passwords/tokens, Sentry `send_default_pii=True` | filters / scrubbing | |
| L28 | `re.compile(user)`, catastrophic regex on input (Python `re` backtracks), unbounded `page_size`, no upload size limits, `json.loads` on huge bodies, zip bombs | `re2`/`regex` with timeout, size caps | |
| L29 | read-modify-write without `select_for_update()`/`F()` expressions; check-then-create without unique constraint; Celery task double-execution; GIL does not prevent races across processes | `transaction.atomic` + `select_for_update`, `F('balance') - x`, idempotency keys | |
| L30 | float money (`float(amount)`), negative quantities, trusting client totals, `int()` of huge strings (CVE-2020-10735 DoS, limited since 3.11) | `Decimal`, server recompute, bounds | |
| L31 | `ctypes`/`cffi` pointer use, C extensions (→ `c-cpp.md`), `memoryview` of freed buffers in extensions | — | pure Python is memory-safe |
| L32 | unpinned `requirements.txt`, `pip install` without hashes, `setup.py` executing code at install, `--extra-index-url` dependency confusion, typosquats | pinned + `--require-hashes`, single index | SCA opt-in |
| L33 | Graphene/Strawberry introspection on, no depth limit, resolver auth missing; Django Channels consumers without auth/origin (`AllowedHostsOriginValidator`); gRPC without interceptor auth | depth limit, `AuthMiddlewareStack`, origin validator | |
| L34 | `getattr(module, user)()`, `globals()[user]`, `importlib.import_module(user)`, `pickle` find_class | allow-list dispatch | |
| L35 | `assert` used for auth checks (stripped with `-O`); mutable default args shared across requests; `is` vs `==` on strings; `tempfile.mktemp`; `zipfile` path trust; `format_map` attribute access | explicit `if … raise`, `mkstemp` | |
