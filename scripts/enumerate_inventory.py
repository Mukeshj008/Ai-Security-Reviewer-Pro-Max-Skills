#!/usr/bin/env python3
"""Inventory-only helper for large-repo reviews (v4.48).

Writes paths and stack facts — never secret values. Not a SAST scanner.
Optional `parallel` block in JSON is metadata (read_ranges for huge files); agents do not spawn workers.

  python3 enumerate_inventory.py [repo_root]

Creates/updates:
  <root>/.security-review/inventory.json
  <root>/.security-review/scan-session-memory.md  (create if missing; do not wipe walked_list;
                                                  appends "## Language packs" if absent)
"""
from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

SKILL_VERSION = "4.51.0"

DEFAULT_MAX_WORKERS = 4
# Shard budget: ~10k LOC or 80 files, whichever comes first.
SHARD_MAX_BYTES = 400_000
SHARD_MAX_FILES = 80
# One file bigger than this is sliced into line ranges so a worker can read it all.
HUGE_FILE_LINES = 4_000
HUGE_FILE_BYTES = 120_000
# Parallel mode pays off only on large or polyglot repos.
PARALLEL_MIN_FILES = 500
PARALLEL_MIN_PROD_PACKS = 3
PARALLEL_MIN_CODE_BYTES = 4_000_000
SHARED_SECURITY_RE = re.compile(
    r"auth|middleware|filter|interceptor|security|session|guard|policy|permission|acl|rbac|csrf|cors",
    re.I,
)
CONFIG_EXTRA_NAMES = {"CMakeLists.txt", "Makefile", "makefile", "GNUmakefile", "Procfile", ".npmrc", ".yarnrc",
                      ".yarnrc.yml", ".pypirc", ".netrc", ".pip.conf", "pip.conf", ".gemrc", "settings.xml",
                      "gradle.properties", "nuget.config", ".dockerignore", "CODEOWNERS", ".arcconfig"}
SECRET_FILE_RE = re.compile(
    r"^(id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|.*\.(pem|key|crt|cer|der|p12|pfx|jks|keystore|truststore|kdbx|asc|gpg)"
    r"(\.enc)?|.*\.(ini|properties|cfg|conf|htpasswd)|credentials|\.pgpass|.*\.ovpn)$",
    re.I,
)
CONFIG_EXTRA_DIRS = {".husky", ".github", ".gitlab", ".circleci", ".buildkite"}
TEMPLATE_DIRS = {"templates", "template", "views", "view", "layouts", "partials", "pages", "emails", "mail"}
# Never worth a worker's time; anything else unassigned is listed for the coordinator.
NON_SOURCE_EXT = {".md", ".rst", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".pdf", ".woff",
                  ".woff2", ".ttf", ".eot", ".map", ".lock", ".sum", ".zip", ".gz", ".tar", ".jar", ".class",
                  ".min.js", ".mp4", ".mp3", ".csv", ".log", ".css", ".scss", ".less", ".xz", ".bz2", ".7z"}
NON_SOURCE_NAMES = {".editorconfig", ".gitattributes", ".gitignore", ".nvmrc", ".prettierignore", ".prettierrc",
                    ".eslintignore", ".node-version", ".python-version", ".tool-versions", "VERSION", "LICENSE"}
SHARED_DIRS = {"middleware", "middlewares", "filters", "guards", "interceptors", "security", "auth", "policies"}
SHARED_ENTRY_STEMS = {"app", "server", "main", "program", "startup", "settings", "urls", "routes", "router"}
SHARED_CONTEXT_MAX = 30

SKIP_DIRS = {
    ".git",
    "node_modules",
    "bower_components",
    "vendor",
    "dist",
    "build",
    "target",
    "bin",
    "obj",
    ".venv",
    "venv",
    "__pycache__",
    "site-packages",
    ".security-review",
    "graphify-out",
    ".idea",
    ".gradle",
    ".next",
    ".nuxt",
    "coverage",
    ".nyc_output",
}
# Dot-dirs that hold security-relevant config and must be walked.
KEEP_DOT_DIRS = {".github", ".gitlab", ".circleci", ".buildkite", ".husky"}

HTTP_NAME_RE = re.compile(
    r"(Controller|Resource|Router|routes?|servlet|Endpoint|Handler|Hub)\.(java|kt|js|ts|mjs|cjs|py|go|rb|php|cs)$"
    r"|^(urls|views|api|viewsets)\.py$"
    r"|_controller\.rb$|^routes\.rb$"
    r"|^(web|api)\.php$",
    re.I,
)
HTTP_DIRS = {"routes", "router", "routers", "controllers", "controller", "endpoints", "api", "views", "resources"}
CODE_EXT = {".js", ".mjs", ".cjs", ".ts", ".py", ".go", ".rb", ".php", ".java", ".kt", ".cs"}

CONFIG_RE = re.compile(
    r"^(application.*\.(yml|yaml|properties)|bootstrap.*\.(yml|yaml|properties)|"
    r"appsettings.*\.json|\.env(\..+)?|config[-_.].*\.(js|cjs|ts|json|ya?ml)|"
    r"settings(_\w+)?\.py|ecosystem.*\.config\.js|web\.config|wp-config\.php|"
    r"secrets?\.(ya?ml|json)|.*\.tfvars|values.*\.ya?ml|nginx.*\.conf)$",
    re.I,
)
CONFIG_DIRS = {"config", "configs", "conf", "settings", "env", "environments"}
CONFIG_EXT = {".js", ".cjs", ".ts", ".json", ".yml", ".yaml", ".properties", ".toml", ".ini", ".env", ".conf", ".xml"}

MODULE_MARKERS = {
    "pom.xml",
    "package.json",
    "go.mod",
    "build.gradle",
    "build.gradle.kts",
    "Cargo.toml",
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "composer.json",
    "Gemfile",
    "build.sbt",
    "mix.exs",
    "pubspec.yaml",
    "cpanfile",
    "rebar.config",
}

LANG_BY_EXT = {
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "jsx",
    ".ts": "typescript", ".tsx": "tsx",
    ".vue": "vue", ".svelte": "svelte",
    ".ejs": "js-template", ".pug": "js-template", ".jade": "js-template", ".hbs": "js-template",
    ".handlebars": "js-template", ".njk": "js-template",
    ".py": "python", ".jinja": "python-template", ".jinja2": "python-template", ".j2": "python-template",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".jsp": "java-template", ".jspx": "java-template",
    ".ftl": "java-template", ".ftlh": "java-template", ".vm": "java-template",
    ".go": "go",
    ".php": "php", ".phtml": "php", ".twig": "php-template",
    ".cs": "csharp", ".cshtml": "csharp-template", ".razor": "csharp-template", ".aspx": "csharp-template",
    ".rb": "ruby", ".erb": "ruby-template", ".haml": "ruby-template", ".slim": "ruby-template",
    ".rs": "rust",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".swift": "swift", ".m": "objc", ".mm": "objc", ".dart": "dart",
    ".scala": "scala", ".sc": "scala",
    ".ex": "elixir", ".exs": "elixir", ".heex": "elixir-template", ".eex": "elixir-template",
    ".leex": "elixir-template", ".erl": "erlang",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ksh": "shell", ".ps1": "powershell", ".psm1": "powershell",
    ".pl": "perl", ".pm": "perl", ".lua": "lua", ".groovy": "groovy", ".gsp": "groovy", ".sol": "solidity",
    ".tf": "terraform", ".html": "html",
}

# (pack, framework label, dependency substrings) — matched case-insensitively in manifests.
FRAMEWORK_DEPS = {
    "package.json": [
        ("javascript-node.md", "express", ['"express"']),
        ("javascript-node.md", "koa", ['"koa"']),
        ("javascript-node.md", "fastify", ['"fastify"']),
        ("javascript-node.md", "nestjs", ['"@nestjs/core"']),
        ("javascript-node.md", "hapi", ['"@hapi/hapi"', '"hapi"']),
        ("javascript-node.md", "restify", ['"restify"']),
        ("javascript-node.md", "next", ['"next"']),
        ("javascript-node.md", "mongoose", ['"mongoose"']),
        ("javascript-node.md", "sequelize", ['"sequelize"']),
        ("javascript-node.md", "prisma", ['"@prisma/client"']),
        ("javascript-node.md", "ejs", ['"ejs"']),
        ("javascript-node.md", "pug", ['"pug"']),
        ("javascript-node.md", "handlebars", ['"handlebars"', '"express-handlebars"', '"hbs"']),
        ("frontend-browser.md", "react", ['"react"', '"react-dom"']),
        ("frontend-browser.md", "vue", ['"vue"', '"nuxt"']),
        ("frontend-browser.md", "angular", ['"@angular/core"']),
        ("frontend-browser.md", "svelte", ['"svelte"']),
        ("frontend-browser.md", "jquery", ['"jquery"']),
        ("mobile", "react-native", ['"react-native"']),
        ("protocol", "graphql", ['"graphql"', '"apollo-server', '"@apollo/server"']),
        ("protocol", "websocket", ['"ws"', '"socket.io"']),
        ("protocol", "grpc", ['"@grpc/grpc-js"', '"grpc"']),
    ],
    "python": [
        ("python.md", "django", ["django"]),
        ("python.md", "flask", ["flask"]),
        ("python.md", "fastapi", ["fastapi"]),
        ("python.md", "tornado", ["tornado"]),
        ("python.md", "aiohttp", ["aiohttp"]),
        ("python.md", "jinja2", ["jinja2"]),
        ("python.md", "sqlalchemy", ["sqlalchemy"]),
        ("python.md", "celery", ["celery"]),
        ("protocol", "graphql", ["graphene", "strawberry-graphql", "ariadne"]),
        ("protocol", "grpc", ["grpcio"]),
    ],
    "jvm": [
        ("java-kotlin.md", "spring-boot", ["spring-boot"]),
        ("java-kotlin.md", "spring-security", ["spring-security", "spring-boot-starter-security"]),
        ("java-kotlin.md", "spring-webflux", ["spring-webflux", "spring-boot-starter-webflux"]),
        ("java-kotlin.md", "jakarta-servlet", ["jakarta.servlet", "javax.servlet"]),
        ("java-kotlin.md", "struts", ["struts"]),
        ("java-kotlin.md", "thymeleaf", ["thymeleaf"]),
        ("java-kotlin.md", "freemarker", ["freemarker"]),
        ("java-kotlin.md", "mybatis", ["mybatis"]),
        ("java-kotlin.md", "hibernate", ["hibernate"]),
        ("java-kotlin.md", "jackson", ["jackson-databind"]),
        ("java-kotlin.md", "log4j2", ["log4j-core"]),
        ("java-kotlin.md", "micronaut", ["micronaut"]),
        ("java-kotlin.md", "quarkus", ["quarkus"]),
        ("protocol", "graphql", ["graphql-java", "spring-graphql"]),
        ("protocol", "grpc", ["grpc-"]),
    ],
    "go.mod": [
        ("go.md", "gin", ["gin-gonic/gin"]),
        ("go.md", "echo", ["labstack/echo"]),
        ("go.md", "fiber", ["gofiber/fiber"]),
        ("go.md", "chi", ["go-chi/chi"]),
        ("go.md", "gorilla-mux", ["gorilla/mux"]),
        ("go.md", "gorm", ["gorm.io/gorm"]),
        ("protocol", "grpc", ["google.golang.org/grpc"]),
        ("protocol", "graphql", ["gqlgen", "graph-gophers/graphql-go"]),
    ],
    "composer.json": [
        ("php.md", "laravel", ["laravel/framework"]),
        ("php.md", "symfony", ["symfony/"]),
        ("php.md", "slim", ["slim/slim"]),
        ("php.md", "codeigniter", ["codeigniter"]),
        ("php.md", "twig", ["twig/twig"]),
    ],
    "Gemfile": [
        ("ruby.md", "rails", ["'rails'", '"rails"']),
        ("ruby.md", "sinatra", ["sinatra"]),
        ("ruby.md", "devise", ["devise"]),
    ],
    "csproj": [
        ("dotnet.md", "aspnetcore", ["microsoft.aspnetcore", 'sdk="microsoft.net.sdk.web"']),
        ("dotnet.md", "efcore", ["microsoft.entityframeworkcore"]),
        ("dotnet.md", "newtonsoft-json", ["newtonsoft.json"]),
        ("dotnet.md", "dapper", ["dapper"]),
    ],
    "build.sbt": [
        ("scala.md", "play", ["playframework", "play-json", "playscala", "enableplugins(play"]),
        ("scala.md", "akka-http", ["akka-http", "pekko-http"]),
        ("scala.md", "http4s", ["http4s"]),
        ("scala.md", "zio-http", ["zio-http"]),
        ("scala.md", "spark", ["spark-sql", "spark-core"]),
        ("scala.md", "slick", ["slick"]),
        ("scala.md", "doobie", ["doobie"]),
        ("protocol", "graphql", ["sangria", "caliban"]),
    ],
    "mix.exs": [
        ("elixir.md", "phoenix", [":phoenix,", ":phoenix "]),
        ("elixir.md", "liveview", [":phoenix_live_view"]),
        ("elixir.md", "ecto", [":ecto"]),
        ("elixir.md", "plug", [":plug"]),
        ("protocol", "graphql", [":absinthe"]),
    ],
    "pubspec.yaml": [
        ("mobile-native.md", "flutter", ["flutter:"]),
        ("mobile-native.md", "webview_flutter", ["webview_flutter"]),
    ],
    "Cargo.toml": [
        ("rust.md", "actix-web", ["actix-web"]),
        ("rust.md", "axum", ["axum"]),
        ("rust.md", "rocket", ["rocket"]),
        ("rust.md", "warp", ["warp"]),
        ("rust.md", "sqlx", ["sqlx"]),
        ("rust.md", "diesel", ["diesel"]),
    ],
}

PACK_BY_LANG = {
    "python": "python.md", "python-template": "python.md",
    "java": "java-kotlin.md", "kotlin": "java-kotlin.md", "java-template": "java-kotlin.md",
    "go": "go.md",
    "php": "php.md", "php-template": "php.md",
    "csharp": "dotnet.md", "csharp-template": "dotnet.md",
    "ruby": "ruby.md", "ruby-template": "ruby.md",
    "rust": "rust.md",
    "c": "c-cpp.md", "cpp": "c-cpp.md",
    "terraform": "iac-ci.md", "ansible-template": "iac-ci.md",
    "scala": "scala.md", "scala-template": "scala.md",
    "elixir": "elixir.md", "elixir-template": "elixir.md", "erlang": "elixir.md",
    "shell": "shell.md", "powershell": "shell.md",
    "swift": "mobile-native.md", "objc": "mobile-native.md", "dart": "mobile-native.md",
    "perl": "other-languages.md", "lua": "other-languages.md", "groovy": "other-languages.md",
    "solidity": "other-languages.md",
    "vue": "frontend-browser.md", "svelte": "frontend-browser.md",
    "jsx": "frontend-browser.md", "tsx": "frontend-browser.md",
    "js-template": "javascript-node.md",
}

CI_FILE_RE = re.compile(
    r"^(\.github/workflows/.+\.ya?ml|\.gitlab-ci\.yml|bitbucket-pipelines\.yml|azure-pipelines\.yml|"
    r"\.circleci/config\.yml|(.*/)?Jenkinsfile[^/]*|\.buildkite/.+\.ya?ml|\.travis\.yml)$"
)
COMPOSE_RE = re.compile(r"^(docker-)?compose[^/]*\.ya?ml$", re.I)
MOBILE_FILES = {"AndroidManifest.xml", "Info.plist", "pubspec.yaml", "Podfile"}
K8S_HINT_DIRS = {"k8s", "kubernetes", "helm", "charts", "manifests", "deploy", "deployment", "kustomize"}
MAX_MANIFEST_BYTES = 512_000
# Non-production dirs: packs triggered only from here are flagged, not dropped.
TEST_DIRS = {"test", "tests", "spec", "specs", "__tests__", "fixtures", "testdata", "mocks", "e2e", "examples",
             "samples", "docs", "doc", "site"}
ANSIBLE_DIRS = {"roles", "playbooks", "group_vars", "host_vars", "devops", "ansible"}


def skip_dir(name: str) -> bool:
    if name in KEEP_DOT_DIRS:
        return False
    return name in SKIP_DIRS or name.startswith(".")


def read_small(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return ""


def manifest_kind(fn: str) -> str | None:
    if fn == "package.json":
        return "package.json"
    if fn in ("pyproject.toml", "Pipfile", "setup.py", "setup.cfg") or (fn.startswith("requirements") and fn.endswith(".txt")):
        return "python"
    if fn in ("pom.xml", "build.gradle", "build.gradle.kts"):
        return "jvm"
    if fn == "go.mod":
        return "go.mod"
    if fn == "composer.json":
        return "composer.json"
    if fn == "Gemfile":
        return "Gemfile"
    if fn.endswith(".csproj"):
        return "csproj"
    if fn == "Cargo.toml":
        return "Cargo.toml"
    if fn == "build.sbt":
        return "build.sbt"
    if fn == "mix.exs":
        return "mix.exs"
    if fn == "pubspec.yaml":
        return "pubspec.yaml"
    return None


def is_http_file(rel: str, fn: str) -> bool:
    if HTTP_NAME_RE.search(fn):
        return True
    ext = os.path.splitext(fn)[1].lower()
    if ext not in CODE_EXT:
        return False
    parts = rel.lower().split("/")[:-1]
    return any(p in HTTP_DIRS for p in parts)


def is_config_file(rel: str, fn: str) -> bool:
    if CONFIG_RE.match(fn) or fn.endswith(".pem") or fn.endswith(".key"):
        return True
    ext = os.path.splitext(fn)[1].lower()
    parts = rel.lower().split("/")[:-1]
    return ext in CONFIG_EXT and any(p in CONFIG_DIRS for p in parts)


def walk(root: Path) -> dict:
    modules: list[str] = []
    configs: list[str] = []
    http_files: list[str] = []
    docker: list[str] = []
    compose: list[str] = []
    ci: list[str] = []
    terraform: list[str] = []
    k8s: list[str] = []
    mobile: list[str] = []
    proto_graphql: list[str] = []
    ansible: list[str] = []
    langs: Counter = Counter()
    test_langs: Counter = Counter()
    frameworks: dict[str, set[str]] = {}
    prod_fw_packs: set[str] = set()
    html_with_script = 0
    n_files = 0
    file_rows: list[dict] = []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not skip_dir(d)]
        n_files += len(filenames)
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        if rel_dir == ".":
            rel_dir = ""
        dir_parts = set(rel_dir.lower().split("/")) if rel_dir else set()
        for fn in filenames:
            rel = f"{rel_dir}/{fn}" if rel_dir else fn
            ext = os.path.splitext(fn)[1].lower()
            full = Path(dirpath) / fn

            in_test = bool(dir_parts & TEST_DIRS)
            in_ansible = bool(dir_parts & ANSIBLE_DIRS)
            lang = None
            if fn.endswith(".blade.php"):
                lang = "php-template"
            elif fn.endswith(".scala.html"):
                lang = "scala-template"
            elif fn in ("Dockerfile",) or fn.startswith("Dockerfile"):
                docker.append(rel)
            elif ext in (".j2", ".jinja", ".jinja2") and in_ansible:
                # Ansible renders these into config files (nginx, systemd) — IaC, not Python web templates.
                lang = "ansible-template"
            elif ext in LANG_BY_EXT:
                lang = LANG_BY_EXT[ext]
            if lang:
                langs[lang] += 1
                if in_test:
                    test_langs[lang] += 1
            if in_ansible and ext in (".yml", ".yaml") and ("tasks" in dir_parts or "handlers" in dir_parts or "playbooks" in dir_parts):
                ansible.append(rel)

            if fn in MODULE_MARKERS or fn.endswith(".csproj"):
                modules.append(rel_dir or ".")

            kind = manifest_kind(fn)
            if kind:
                text = read_small(full)
                for pack, label, needles in FRAMEWORK_DEPS.get(kind, []):
                    if any(n in text for n in needles):
                        frameworks.setdefault(pack, set()).add(label)
                        if not in_test:
                            prod_fw_packs.add(pack)

            if is_config_file(rel, fn) and not in_test:
                configs.append(rel)
            if is_http_file(rel, fn) and not in_test:
                http_files.append(rel)
            if COMPOSE_RE.match(fn):
                compose.append(rel)
            if CI_FILE_RE.match(rel):
                ci.append(rel)
            if ext in (".tf", ".tfvars"):
                terraform.append(rel)
            if ext in (".yaml", ".yml") and (dir_parts & K8S_HINT_DIRS or fn in ("Chart.yaml", "kustomization.yaml")):
                text = read_small(full)
                if "apiversion:" in text and "kind:" in text or fn == "Chart.yaml":
                    k8s.append(rel)
            if fn in MOBILE_FILES:
                mobile.append(rel)
            if ext in (".graphql", ".gql", ".proto"):
                proto_graphql.append(rel)
            if ext == ".html" and html_with_script < 1 and not in_test:
                if "<script" in read_small(full):
                    html_with_script += 1

            try:
                size = full.stat().st_size
            except OSError:
                size = 0
            lines = 0
            if lang and not in_test and size >= HUGE_FILE_BYTES:
                try:
                    with full.open("rb") as fh:
                        lines = sum(1 for _ in fh)
                except OSError:
                    lines = 0
            is_cfg = (is_config_file(rel, fn) or fn in MODULE_MARKERS or fn.endswith(".csproj")
                      or fn.startswith("Dockerfile") or COMPOSE_RE.match(fn) or CI_FILE_RE.match(rel)
                      or ext in (".tf", ".tfvars") or fn in MOBILE_FILES or fn in CONFIG_EXTRA_NAMES
                      or SECRET_FILE_RE.match(fn)
                      or bool(dir_parts & CONFIG_EXTRA_DIRS)
                      or (in_ansible and ext in (".yml", ".yaml")))
            file_rows.append({"path": rel, "lang": lang, "ext": ext, "size": size,
                              "lines": lines, "test": in_test, "config": bool(is_cfg)})

    return {
        "modules": sorted(set(modules)),
        "configs": sorted(set(configs)),
        "http_files": sorted(set(http_files)),
        "docker": sorted(set(docker)),
        "compose": sorted(set(compose)),
        "ci": sorted(set(ci)),
        "terraform": sorted(set(terraform)),
        "k8s": sorted(set(k8s)),
        "mobile": sorted(set(mobile)),
        "proto_graphql": sorted(set(proto_graphql)),
        "ansible": sorted(set(ansible)),
        "languages": dict(langs.most_common()),
        "test_only_languages": {k: v for k, v in test_langs.items() if v == langs[k]},
        "frameworks": {k: sorted(v) for k, v in frameworks.items()},
        "prod_fw_packs": sorted(prod_fw_packs),
        "html_with_script": html_with_script > 0,
        "n_files": n_files,
        "file_rows": file_rows,
    }


def code_pack(row: dict, packs: dict) -> str | None:
    """Language pack for a code file, ignoring HTML."""
    if row["lang"] in ("javascript", "typescript"):
        return "javascript-node.md" if packs.get("javascript-node.md", {}).get("active") else "frontend-browser.md"
    return PACK_BY_LANG.get(row["lang"] or "")


def module_packs(inv: dict, packs: dict) -> dict[str, str]:
    """Dominant server-side pack per module dir, so HTML templates follow their module's engine."""
    counts: dict[str, Counter] = {}
    mods = sorted((m for m in inv["modules"] if m != "."), key=len, reverse=True)
    for row in inv["file_rows"]:
        pack = code_pack(row, packs)
        if not pack or pack == "frontend-browser.md" or row["test"]:
            continue
        mod = next((m for m in mods if row["path"].startswith(m + "/")), ".")
        counts.setdefault(mod, Counter())[pack] += 1
    return {m: c.most_common(1)[0][0] for m, c in counts.items()}


def shard_key(row: dict, packs: dict, mod_pack: dict[str, str], mods: list[str]) -> str | None:
    """Pack (or config shard) that owns a file; None = not reviewed by a worker."""
    if row["test"]:
        return None
    if row["config"]:
        return "config-iac-secrets"
    pack = code_pack(row, packs)
    in_template_dir = bool(set(p.lower() for p in Path(row["path"]).parts[:-1]) & TEMPLATE_DIRS)
    if row["lang"] == "html" or (row["lang"] is None and in_template_dir and row["ext"] not in NON_SOURCE_EXT):
        mod = next((m for m in mods if row["path"].startswith(m + "/")), ".")
        pack = mod_pack.get(mod) or ("frontend-browser.md" if packs.get("frontend-browser.md", {}).get("active") else None)
    if pack and packs.get(pack, {}).get("active"):
        return pack
    return None


def explode_huge(rows: list[dict]) -> list[dict]:
    """Slice a single file over HUGE_FILE_LINES into read_ranges for the reviewing agent."""
    out: list[dict] = []
    for r in rows:
        lines = r.get("lines") or 0
        if lines <= HUGE_FILE_LINES:
            out.append(r)
            continue
        start = 1
        while start <= lines:
            end = min(lines, start + HUGE_FILE_LINES - 1)
            nr = dict(r)
            nr["line_start"] = start
            nr["line_end"] = end
            nr["size"] = max(1, r["size"] * (end - start + 1) // lines)
            out.append(nr)
            start = end + 1
    return out


def split_by_dir(rows: list[dict]) -> list[list[dict]]:
    """Bin-pack files into chunks under the shard budget, keeping directories together."""
    rows = explode_huge(rows)
    groups: dict[str, list[dict]] = {}
    for r in rows:
        parts = r["path"].split("/")
        groups.setdefault("/".join(parts[:2]) if len(parts) > 2 else parts[0] if len(parts) > 1 else ".", []).append(r)
    chunks: list[list[dict]] = []
    cur: list[dict] = []
    cur_bytes = 0
    for _, grp in sorted(groups.items(), key=lambda kv: -sum(r["size"] for r in kv[1])):
        for r in sorted(grp, key=lambda r: r["path"]):
            if cur and (cur_bytes + r["size"] > SHARD_MAX_BYTES or len(cur) >= SHARD_MAX_FILES):
                chunks.append(cur)
                cur, cur_bytes = [], 0
            cur.append(r)
            cur_bytes += r["size"]
    if cur:
        chunks.append(cur)
    return chunks


def plan_shards(inv: dict, packs: dict, max_workers: int) -> dict:
    """Assign every production file to exactly one shard and group shards into waves."""
    owned: dict[str, list[dict]] = {}
    excluded_test = 0
    mod_pack = module_packs(inv, packs)
    mods = sorted((m for m in inv["modules"] if m != "."), key=len, reverse=True)
    unassigned: list[str] = []
    for row in inv["file_rows"]:
        key = shard_key(row, packs, mod_pack, mods)
        if key is None:
            excluded_test += row["test"]
            if (not row["test"] and row["ext"] not in NON_SOURCE_EXT and row["ext"] not in (".json", ".yml", ".yaml")
                    and Path(row["path"]).name not in NON_SOURCE_NAMES):
                unassigned.append(row["path"])
            continue
        owned.setdefault(key, []).append(row)

    shards = []
    for key, rows in sorted(owned.items()):
        chunks = split_by_dir(rows)
        for i, chunk in enumerate(chunks, 1):
            pack = "iac-ci.md" if key == "config-iac-secrets" else key
            sid = key.replace(".md", "") + (f"-{i}" if len(chunks) > 1 else "")
            files: list[str] = []
            seen: set[str] = set()
            for r in chunk:
                if r["path"] not in seen:
                    files.append(r["path"])
                    seen.add(r["path"])
            ranges = [{"path": r["path"], "start": r["line_start"], "end": r["line_end"]}
                      for r in chunk if r.get("line_start")]
            shard = {
                "id": sid,
                "pack": pack,
                "kind": "config" if key == "config-iac-secrets" else "code",
                "files": files,
                "n_files": len(files),
                "approx_loc": sum(r["size"] for r in chunk) // 40,
            }
            if ranges:
                shard["read_ranges"] = ranges
            shards.append(shard)
    shards.sort(key=lambda s: -s["approx_loc"])
    waves = [[s["id"] for s in shards[i:i + max_workers]] for i in range(0, len(shards), max_workers)]

    http = set(inv["http_files"])

    def is_shared(r: dict) -> bool:
        if r["test"] or not r["lang"]:
            return False
        stem = Path(r["path"]).stem.lower()
        dirs = set(p.lower() for p in Path(r["path"]).parts[:-1])
        if SHARED_SECURITY_RE.search(stem) or dirs & SHARED_DIRS:
            return True
        if stem in SHARED_ENTRY_STEMS and r["path"].count("/") <= 2:
            return True
        return stem == "index" and r["path"] in http

    shared = sorted(r["path"] for r in inv["file_rows"] if is_shared(r))[:SHARED_CONTEXT_MAX]

    prod_packs = [p for p, e in packs.items()
                  if p.endswith(".md") and not p.startswith("../") and e["active"]
                  and not e.get("test_fixtures_only") and p != "iac-ci.md"]
    code_bytes = sum(r["size"] for rows in owned.values() for r in rows)
    reasons = []
    if inv["n_files"] >= PARALLEL_MIN_FILES:
        reasons.append(f"files={inv['n_files']}>={PARALLEL_MIN_FILES}")
    if len(prod_packs) >= PARALLEL_MIN_PROD_PACKS:
        reasons.append(f"production packs={len(prod_packs)}>={PARALLEL_MIN_PROD_PACKS}")
    if code_bytes >= PARALLEL_MIN_CODE_BYTES:
        reasons.append(f"code≈{code_bytes // 40} LOC")
    return {
        "parallel_recommended": bool(reasons) and len(shards) > 1,
        "reason": "; ".join(reasons) or "small single-stack repo — single agent is as fast",
        "max_workers": max_workers,
        "shards": shards,
        "waves": waves,
        "shared_context_files": shared,
        "excluded_test_fixture_files": excluded_test,
        "unassigned_files": sorted(unassigned)[:100],
        "unassigned_count": len(unassigned),
    }


def decide_packs(inv: dict) -> dict:
    """Return {pack: {"active": bool, "reason": str, "files": int, "frameworks": [...]}}."""
    langs: dict = inv["languages"]
    test_only: dict = inv["test_only_languages"]
    fw: dict = inv["frameworks"]
    packs: dict[str, dict] = {}

    def add(pack: str, reason: str, files: int = 0, test_only_hit: bool = False) -> None:
        entry = packs.setdefault(pack, {"active": True, "reasons": [], "files": 0,
                                        "frameworks": fw.get(pack, []), "prod_hits": 0})
        entry["reasons"].append(reason + (" (test/fixture dirs only)" if test_only_hit else ""))
        entry["files"] += files
        if not test_only_hit:
            entry["prod_hits"] += 1

    for lang, count in langs.items():
        pack = PACK_BY_LANG.get(lang)
        if pack:
            add(pack, f"{count} {lang} files", count, lang in test_only)

    prod_fw = set(inv["prod_fw_packs"])
    js_files = langs.get("javascript", 0) + langs.get("typescript", 0)
    js_test_only = all(l in test_only for l in ("javascript", "typescript") if langs.get(l))
    if js_files:
        if "javascript-node.md" in fw or "frontend-browser.md" not in fw:
            add("javascript-node.md", f"{js_files} js/ts files", js_files, js_test_only)
        if "frontend-browser.md" in fw:
            add("frontend-browser.md", "frontend deps: " + ", ".join(fw["frontend-browser.md"]), 0,
                "frontend-browser.md" not in prod_fw)
    for pack in fw:
        if pack.endswith(".md") and pack not in packs:
            add(pack, "framework deps: " + ", ".join(fw[pack]), 0, pack not in prod_fw)
    if inv["html_with_script"] and "frontend-browser.md" not in packs:
        add("frontend-browser.md", "*.html with <script>")

    iac_n = (len(inv["docker"]) + len(inv["compose"]) + len(inv["ci"]) + len(inv["terraform"])
             + len(inv["k8s"]) + len(inv["ansible"]))
    if iac_n:
        add("iac-ci.md", f"docker={len(inv['docker'])} compose={len(inv['compose'])} ci={len(inv['ci'])} "
                         f"tf={len(inv['terraform'])} k8s={len(inv['k8s'])} ansible={len(inv['ansible'])}", iac_n)

    if inv["mobile"] or "mobile" in fw:
        names = sorted({Path(m).name for m in inv["mobile"]}) or ["react-native"]
        manifests_in_test = all(set(p.lower() for p in Path(m).parts) & TEST_DIRS for m in inv["mobile"])
        add("mobile-native.md", "mobile manifests: " + ", ".join(names), len(inv["mobile"]),
            manifests_in_test and "mobile" not in prod_fw)

    ext_refs = {}
    if "mobile-native.md" in packs:
        ext_refs["../mobile-sast-audit.md"] = "mobile triggers (read with mobile-native.md)"
    if inv["proto_graphql"] or "protocol" in fw:
        ext_refs["../protocol-scans-graphql-ws-grpc.md"] = ", ".join(fw.get("protocol", [])) or "schema/proto files"

    all_packs = ["javascript-node.md", "frontend-browser.md", "python.md", "java-kotlin.md", "go.md", "php.md",
                 "dotnet.md", "ruby.md", "rust.md", "c-cpp.md", "scala.md", "elixir.md", "shell.md",
                 "mobile-native.md", "other-languages.md", "iac-ci.md"]
    out = {}
    for p in all_packs:
        if p in packs:
            e = packs[p]
            out[p] = {"active": True, "test_fixtures_only": e["prod_hits"] == 0,
                      "reason": "; ".join(e["reasons"]), "files": e["files"], "frameworks": e["frameworks"]}
        else:
            out[p] = {"active": False, "reason": "no triggers", "files": 0, "frameworks": []}
    for ref, why in ext_refs.items():
        out[ref] = {"active": True, "reason": why, "files": 0, "frameworks": fw.get("protocol", []) if "protocol" in ref else []}
    return out


def http_modules_from(modules: list[str], http_files: list[str]) -> list[str]:
    hits: set[str] = set()
    for hf in http_files:
        parent = str(Path(hf).parent).replace("\\", "/")
        best = "."
        for m in modules:
            if m != "." and (parent == m or parent.startswith(m + "/")):
                if best == "." or len(m) > len(best):
                    best = m
        if best == "." and parent not in (".", ""):
            parts = parent.split("/")
            best = "/".join(parts[:2]) if len(parts) >= 2 else parts[0]
        hits.add(best)
    return sorted(hits) or modules


def lang_pack_section(packs: dict) -> str:
    lines = ["## Language packs (lang-packs/README.md — load ONLY active)"]
    for name, e in packs.items():
        if e["active"]:
            fws = ", ".join(e["frameworks"]) or "—"
            tag = "active (test/fixture only — not production attack surface)" if e.get("test_fixtures_only") else "active"
            lines.append(f"- {name}: {tag} | files: {e['files']} | frameworks: {fws} | why: {e['reason']}")
    inactive = [n for n, e in packs.items() if not e["active"]]
    if inactive:
        lines.append(f"- inactive — no triggers (never load): {', '.join(inactive)}")
    return "\n".join(lines) + "\n"


def write_memory(path: Path, http_mods: list[str], configs: list[str], n_files_hint: int, packs: dict, n_code: int = 0) -> None:
    section = lang_pack_section(packs)
    if path.exists():
        text = path.read_text(encoding="utf-8")
        text = re.sub(r"(?m)^skill_version:.*$", f"skill_version: {SKILL_VERSION}", text, count=1)
        if not re.search(r"(?m)^production_must_read_count:", text):
            text = re.sub(
                r"(?m)^(inventory_files_hint:.*)$",
                rf"\1\nproduction_files_read: 0\nproduction_must_read_count: {n_code}",
                text,
                count=1,
            )
        if "## Code files" not in text:
            text = text.rstrip("\n") + (
                f"\n\n## Code files (must_read_files — tests included; do not skip)\n"
                f"enumerated: {n_code}\nread: 0\n"
                f"rule: status complete is forbidden until read == enumerated. "
                f"A named Residual is not a substitute for an unread code file.\n"
            )
        if "## Language packs" in text:
            text = re.sub(r"## Language packs.*?(?=\n## |\Z)", section.rstrip("\n"), text, count=1, flags=re.S)
            path.write_text(text, encoding="utf-8")
        else:
            path.write_text(text.rstrip("\n") + "\n\n" + section, encoding="utf-8")
        return
    nxt = http_mods[0] if http_mods else "(none)"
    residual = ", ".join(http_mods) if http_mods else "none"
    rows = "\n".join(f"| {m} | yes | no | Residual |" for m in http_mods) or "| (none) | no | — | |"
    path.write_text(
        f"""# Scan session memory
skill_version: {SKILL_VERSION}
status: in_progress
git_head: unknown
updated_at: {datetime.now(timezone.utc).isoformat()}
report_slug: (set after derive_report_name.py)
inventory_files_hint: {n_files_hint}
production_files_read: 0
production_must_read_count: {n_code}

## Scope
- Mode: code-only
- Include: all
- Exclude: node_modules, vendor, dist, target, .venv

{section}
## Code files (production_must_read_files — finish this session; tests do not pause the review)
production_enumerated: {n_code}
production_files_read: 0
rule: status complete is forbidden until production_files_read == production_enumerated. Never ask the user to say continue. Unread tests go in Appendix B.

## Configs / secrets (Read, not regex)
enumerated: {len(configs)}
read: 0
residual_unread: (see inventory.json configs)

## Logic walk (senior-researcher LOG-01…15)
walked:
residual_ops: all until walked

## HTTP module walk
enumerated: {len(http_mods)}
walked: 0
residual: {residual}
next_http_module: {nxt}
walked_list:

## Module inventory (do not re-ls unless stale)
| Module | HTTP | AUTH walked | Notes |
|--------|------|-------------|-------|
{rows}

## Manifests already run (names only — optional hints)
- enumerate_inventory.py

## Findings issued (IDs only + one line)

## Candidates pending (path:line — no secret values)

## Do not repeat
- multi-module Step 1 inventory (HEAD unchanged)
""",
        encoding="utf-8",
    )


def is_test_path(rel: str) -> bool:
    """Tests are evidence, not a reason to pause the review."""
    parts = rel.replace("\\", "/").split("/")
    name = parts[-1].lower()
    if any(part.lower() in {"test", "tests", "__tests__", "spec", "specs", "testdata", "fixtures"} for part in parts[:-1]):
        return True
    if name.endswith("_test.go") or name.endswith("_test.py") or name.endswith("_spec.rb"):
        return True
    if ".test." in name or ".spec." in name:
        return True
    if name.endswith("test.java"):
        return True
    return False


def must_read_and_secrets(inv: dict) -> tuple[list[str], list[str], list[dict]]:
    """Every first-party code file. Tests stay in the list but are not the completion gate."""
    must: list[str] = []
    secrets: list[str] = []
    huge: list[dict] = []
    for row in inv["file_rows"]:
        name = Path(row["path"]).name
        if SECRET_FILE_RE.match(name):
            secrets.append(row["path"])
            continue
        if name in NON_SOURCE_NAMES or row["ext"] in NON_SOURCE_EXT:
            continue
        if not (row["lang"] or row["config"] or name.startswith("Dockerfile") or name in MODULE_MARKERS):
            continue
        must.append(row["path"])
        lines = row.get("lines") or 0
        if lines > HUGE_FILE_LINES:
            ranges = []
            start = 1
            while start <= lines:
                end = min(lines, start + HUGE_FILE_LINES - 1)
                ranges.append({"start": start, "end": end})
                start = end + 1
            huge.append({"path": row["path"], "lines": lines, "ranges": ranges})
    return must, secrets, huge


def split_production(must: list[str]) -> tuple[list[str], list[str]]:
    prod, tests = [], []
    for path in must:
        (tests if is_test_path(path) else prod).append(path)
    return prod, tests


def main() -> int:
    args = sys.argv[1:]
    max_workers = DEFAULT_MAX_WORKERS
    if "--max-workers" in args:
        i = args.index("--max-workers")
        max_workers = max(1, int(args[i + 1]))
        del args[i:i + 2]
    root = Path(args[0] if args else ".").resolve()
    out_dir = root / ".security-review"
    out_dir.mkdir(parents=True, exist_ok=True)
    inv = walk(root)
    packs = decide_packs(inv)
    http_mods = http_modules_from(inv["modules"], inv["http_files"])
    shard_plan = plan_shards(inv, packs, max_workers)
    must_read, secret_files, huge_files = must_read_and_secrets(inv)
    production_must_read, test_files_optional = split_production(must_read)
    payload = {
        "root": str(root),
        "skill_version": SKILL_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "languages": inv["languages"],
        "frameworks": inv["frameworks"],
        "lang_packs": packs,
        "module_markers": inv["modules"],
        "http_modules": http_mods,
        "http_files": inv["http_files"],
        "http_files_truncated": False,
        "must_read_files": must_read,
        "must_read_count": len(must_read),
        "production_must_read_files": production_must_read,
        "production_must_read_count": len(production_must_read),
        "test_files_optional": test_files_optional,
        "huge_file_ranges": huge_files,
        "secret_files_metadata_only": secret_files,
        "configs": inv["configs"],
        "dockerfiles": inv["docker"],
        "compose_files": inv["compose"],
        "ci_files": inv["ci"],
        "terraform_files": inv["terraform"],
        "k8s_files": inv["k8s"],
        "mobile_files": inv["mobile"],
        "schema_proto_files": inv["proto_graphql"],
        "ansible_files": inv["ansible"],
        "test_only_languages": inv["test_only_languages"],
        "parallel": shard_plan,
        "counts": {
            "files": inv["n_files"],
            "module_markers": len(inv["modules"]),
            "http_modules": len(http_mods),
            "http_files": len(inv["http_files"]),
            "configs": len(inv["configs"]),
            "must_read_files": len(must_read),
            "production_must_read_files": len(production_must_read),
            "test_files_optional": len(test_files_optional),
            "huge_files": len(huge_files),
            "secret_files_metadata_only": len(secret_files),
            "dockerfiles": len(inv["docker"]),
            "ci_files": len(inv["ci"]),
            "active_lang_packs": sum(1 for e in packs.values() if e["active"]),
            "large_repo": len(http_mods) >= 2 or len(inv["configs"]) >= 15 or inv["n_files"] >= 500,
        },
    }
    (out_dir / "inventory.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    write_memory(out_dir / "scan-session-memory.md", http_mods, inv["configs"], inv["n_files"], packs, len(production_must_read))
    print(json.dumps(payload["counts"], indent=2))
    print("Active lang packs:")
    for name, e in packs.items():
        if e["active"]:
            tag = " [TEST/FIXTURE ONLY]" if e.get("test_fixtures_only") else ""
            print(f"  {name:38s} {e['reason']}" + (f"  [{', '.join(e['frameworks'])}]" if e["frameworks"] else "") + tag)
    large = payload["counts"]["large_repo"]
    print(
        "Review mode: single agent"
        + (" (large repo — use large-repo-runner.md)" if large else "")
    )
    n_huge = sum(1 for s in shard_plan.get("shards", []) if s.get("read_ranges"))
    if n_huge:
        print(f"  inventory entries with read_ranges (for you to Read): {n_huge}")
    print(f"  production files (completion gate): {len(production_must_read)}; "
          f"optional tests (do not pause for these): {len(test_files_optional)}; "
          f"must-read code files (tests included): {len(must_read)}; "
          f"huge files to read in full via huge_file_ranges: {len(huge_files)}; "
          f"key/cert files (name only, do not open): {len(secret_files)}")
    print(f"Wrote {out_dir / 'inventory.json'}")
    print(f"Memory: {out_dir / 'scan-session-memory.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
