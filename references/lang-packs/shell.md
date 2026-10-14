# Pack: Shell (bash / sh / zsh) and PowerShell

**Detect:** `*.sh`, `*.bash`, `*.zsh`, `*.ksh`, files with `#!/bin/(ba|z)?sh` / `#!/usr/bin/env bash` shebang, `*.ps1`, `*.psm1`, `*.psd1`, Makefile recipes, CI `run:` blocks (pair with `iac-ci.md`).

Shell scripts become attack surface when they take input from: CI events (PR titles, branch names), webhooks, cron jobs reading uploaded files, CGI scripts, `sudo` rules, or arguments passed by a web app (`exec('backup.sh ' + name)`).

## Key language rules

- Unquoted `$var` undergoes word splitting **and** glob expansion → argument injection / path tricks. Always `"$var"`.
- `eval "$x"`, `bash -c "$x"`, `sh -c "… $x"`, `source "$x"`, `$(…)` / backticks with input → command injection.
- Arguments starting with `-` are parsed as options (`rm "$f"` with `f=-rf`); use `--`.
- `set -x` prints expanded secrets to CI logs.
- PowerShell: `Invoke-Expression`/`iex`, `[ScriptBlock]::Create($x)`, `& $userCmd`, `Start-Process -ArgumentList "…$x"` → injection; `-ExecutionPolicy Bypass` is not a security boundary.

## Hint rg

```bash
G='--glob *.{sh,bash,zsh,ksh} --glob *.ps1 --glob *.psm1'
rg -n "\beval\b|bash\s+-c|sh\s+-c|\bsource\s+\\\$|\.\s+\\\$|Invoke-Expression|\biex\b|ScriptBlock\]::Create" $G
rg -n "\\\$\{?[A-Za-z_][A-Za-z0-9_]*\}?" $G --no-heading | rg -v "\"[^\"]*\\\$" | head -200
rg -n "\brm\s+-rf?\s+\\\$|\bcp\s+\\\$|\bmv\s+\\\$|\bchmod\s+[0-7]*7[0-7]*\s" $G
rg -n "curl\s+[^|]*\|\s*(ba)?sh|wget\s+[^|]*\|\s*(ba)?sh|curl\s+(-k|--insecure)|wget\s+--no-check-certificate|iwr\s.*\|\s*iex" $G
rg -n "set\s+-x|echo\s+.*(TOKEN|PASSWORD|SECRET|KEY)|Write-Host.*\\\$(env:)?.*(Token|Password|Secret)" -i $G
rg -n "/tmp/[A-Za-z0-9_.-]+|mktemp|\\\$RANDOM|\\\$\\\$" $G
rg -n "(PASSWORD|TOKEN|SECRET|API_KEY)\s*=\s*['\"]?[A-Za-z0-9/+=_-]{8,}" -i $G
rg -n "mysql\s.*-e\s*\"|psql\s.*-c\s*\"|sqlite3\s.*\"" $G
rg -n "sudo\s|NOPASSWD|chown\s|setuid|chmod\s+[ug]\+s" $G
rg -n "ConvertTo-SecureString\s.*-AsPlainText|Set-ExecutionPolicy\s+(Bypass|Unrestricted)|-SkipCertificateCheck|ServerCertificateValidationCallback" $G
```

## Class coverage index

| ID | Vulnerable in shell / PowerShell | Safe equivalent | FP trap / note |
|----|---------------------------------|-----------------|----------------|
| L01 | CGI scripts `echo "<p>$QUERY_STRING</p>"`; scripts generating HTML reports from untrusted data | HTML-encode (`sed 's/&/\&amp;/g; s/</\&lt;/g…'`), generate reports in a real language | |
| L02 | `envsubst` / `eval "cat <<EOF … EOF"` on untrusted template files (heredoc with `$(…)` executes) | quoted heredoc `<<'EOF'`, `envsubst '$ALLOWED'` with explicit var list | |
| L03 | `eval "$x"`, `source "$userfile"`, PowerShell `iex`, `[ScriptBlock]::Create($x)`, `Add-Type -TypeDefinition $user` | case/allow-list dispatch | |
| L04 | `mysql -e "SELECT … '$name'"`, `psql -c "… $x"`, `sqlite3 db "… $x"` | `psql -v name="$x" -c "… :'name'"`, parameterized via a real client | |
| L05 | `mongo --eval "db.u.find({name:'$x'})"` (JS injection into the shell) | `mongosh` with `--eval` built from JSON-escaped values (`jq -Rs`) | |
| L06 | unquoted `$var`, `bash -c "… $x"`, `ssh host "cmd $x"` (remote shell re-parses), `xargs` without `-0`, missing `--` before user args; PowerShell `& $cmd`, `Start-Process … "$x"` | `"$var"`, arrays `"${args[@]}"`, `--`, `printf '%q'` for remote ssh, `xargs -0` | |
| L07 | `ldapsearch … "(uid=$u)"` | escape filter chars (`* ( ) \ NUL`) before interpolation | |
| L08 | `echo "user=$input" >> app.log` (newline injection in logs), building HTTP headers in `curl -H "X: $x"` with CR/LF | strip `\r\n` (`${x//[$'\r\n']/}`) | |
| L09 | `curl "$url"` / `wget "$url"` / `Invoke-WebRequest $url` with user URLs in webhooks/CI | allow-list host, `--proto =https`, `--max-redirs 0` | |
| L10 | `cat "$BASE/$name"`, `rm -rf "$DIR/$name"` (with `name=../..`), `rm -rf "$UNSET_VAR/"` → `/` | `realpath -e` + prefix check, `set -u`, `${VAR:?}` | |
| L11 | `tar xf "$upload"` / `unzip "$upload"` without checking member paths (`../`, absolute, symlinks) | `tar --no-same-owner --no-absolute-filenames`, list then validate, extract into empty dir | GNU tar strips leading `/` by default |
| L12 | N/A as object deserialization; analogue: `source`-ing config files that users can write | parse key=value with `while IFS='=' read -r k v` | |
| L13 | `xmllint --noent` / `xsltproc` on untrusted XML | `xmllint --nonet` without `--noent` | |
| L14 | `export $(cat .env)` / `declare "$k=$v"` from untrusted files overwriting `PATH`, `LD_PRELOAD`, `IFS` | explicit allow-list of keys | |
| L15 | CGI auth by checking `$REMOTE_USER` set by misconfigured proxy; `sudo` rules allowing scripts writable by users | root-owned scripts, `sudoers` with full paths | |
| L16 | tokens passed as CLI args (`curl -H "Authorization: Bearer $T"` visible in `ps`), stored in world-readable files | `curl --config`/stdin, `chmod 600`, secret env vars | |
| L17 | `sudo` / setuid wrappers calling scripts that trust `$1`; scripts run as root reading user-writable paths | drop privileges, validate inputs | |
| L18 | N/A — shell scripts have no browser sessions; CGI handlers follow L18 of the serving server | — | |
| L19 | N/A — CORS headers belong to the web server config (`iac-ci.md`) | — | |
| L20 | N/A — headers are set by the web server; CGI scripts printing `Set-Cookie` without `Secure; HttpOnly` | add flags | |
| L21 | CGI `echo "Location: $next"` | allow-list | |
| L22 | `openssl enc -aes-256-cbc` without `-pbkdf2` (weak EVP_BytesToKey KDF), `-des`, `md5sum` for passwords | `openssl enc -aes-256-gcm`(where supported) / `age`/`gpg`, `-pbkdf2 -iter 600000` | md5sum for file integrity of non-adversarial data is fine |
| L23 | `$RANDOM`, `$$`, `date +%s` for temp names/tokens | `mktemp`, `openssl rand -hex 32`, `/dev/urandom` | |
| L24 | `curl -k`, `wget --no-check-certificate`, `git -c http.sslVerify=false`, PowerShell `-SkipCertificateCheck` / `ServerCertificateValidationCallback = {$true}` | defaults, `--cacert` | |
| L25 | hardcoded passwords/tokens in scripts, `ConvertTo-SecureString -AsPlainText` with literals, secrets in Makefiles | env/secret store, `Get-Secret` | |
| L26 | scripts echoing full command lines/env on failure (`env`, `printenv`) | targeted error messages | |
| L27 | `set -x` with secrets, `history` files containing tokens, logging `$@` | `set +x` around secrets, `HISTCONTROL=ignorespace` | |
| L28 | fork bombs from user-controlled loop counts, unbounded `find`/`grep` on user paths, `yes`-style output to logs | bounds, `timeout` command | |
| L29 | predictable `/tmp/name` (symlink attacks, TOCTOU), `[ -f x ] && cat x` races, concurrent cron runs without lock | `mktemp`, `flock`, `set -o noclobber` | |
| L30 | arithmetic `$(( $x ))` evaluating `x='a[$(cmd)]'` (bash arithmetic command injection), string vs number comparison (`[ "$a" \> "$b" ]`) | validate `[[ $x =~ ^[0-9]+$ ]]` before arithmetic | |
| L31 | N/A — shell has no direct memory access; binaries invoked follow their own pack | — | |
| L32 | `curl … | bash` installers, downloading tools without checksum, `pip/npm install` without lockfiles in scripts | pinned versions + `sha256sum -c` | |
| L33 | `websocat`/`grpcurl` usage with plaintext (`-plaintext`) in prod scripts | TLS | |
| L34 | dynamic function names `"$cmd"_handler` / `${!var}` indirect expansion from input | case statement | |
| L35 | missing `set -euo pipefail` (failures ignored → fail-open), `IFS` manipulation, `[ $x = y ]` with empty `$x` errors, aliases/functions shadowing commands via sourced files, PowerShell `$null -eq` comparison order | `set -euo pipefail`, `[[ ]]`, `shellcheck` clean | |
