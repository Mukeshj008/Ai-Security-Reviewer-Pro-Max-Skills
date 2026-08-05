# Mobile SAST Audit — Android / iOS / RN / Flutter (STATIC ONLY)

**Purpose:** detect mobile security issues visible in **source + manifests + plist + network-security-config** — ATS/cleartext, exploitable exported components (activities / receivers / providers / services), on-device sensitive storage, WebView, weak crypto, logs, backup/debug flags. Designed for bug-bounty–style mobile findings without runtime tooling.

**Mode:** **static analysis only.** Do **not** require Frida, MITM, emulator login, or dynamic instrumentation to raise findings. Runtime DAST (Frida/MITM) remains **Manual / Residual** in attestation.

**Triggers (run full audit when any match):**

```bash
find . \( -name 'AndroidManifest.xml' -o -name 'Info.plist' -o -name 'network_security_config.xml' \) 2>/dev/null | head -20
test -d android -o -d ios -o -d app/src/main
rg -l "SharedPreferences|NSUserDefaults|Keychain|EncryptedSharedPreferences|FlutterSecureStorage|AsyncStorage" \
  --glob '**/*.{java,kt,swift,m,mm,dart,ts,tsx,js}' --glob '!**/node_modules/**' . | head -20
```

If no mobile tree and no mobile client code → mark **N/A** in attestation.

**Also run:** `deeplink-audit.md` whenever deep-link / App Links / Universal Links surfaces exist (overlap with exported BROWSABLE activities).

**Companion checklist IDs:** `mobile-sast-manifest.md` (MOB-01…).

---

## Threat model (static-detectable)

| Class | Abuse | Typical CWE / MASVS |
|-------|-------|---------------------|
| **Exported Activity** | Any app sends Intent → privileged UI / token path / WebView load | CWE-926, CWE-927 |
| **Exported BroadcastReceiver** | Spoofed broadcast → auth bypass, SMS OTP steal, privilege | CWE-925 |
| **Exported ContentProvider** | Path traversal / SQL injection / world-readable PII | CWE-926, CWE-89, CWE-22 |
| **Exported Service** | Remote start/bind without permission | CWE-926 |
| **ATS / cleartext** | HTTP or ATS exceptions → MITM of tokens | CWE-319, MASVS-NETWORK |
| **On-device sensitive storage** | Token/PII in prefs/DB/files recoverable via backup/root/shared UID | CWE-312, CWE-922 |
| **WebView** | JS bridge / file:// / universal access → XSS → native | CWE-749 |
| **Backup / debuggable** | `allowBackup` / `debuggable` → data extraction | CWE-921 |
| **PendingIntent / Intent redirect** | Mutable PendingIntent or `startActivity(getIntent())` | CWE-927 |
| **Clipboard / screenshot / logs** | Secrets leave secure storage | CWE-200 |

---

## Step 0 — Inventory (mandatory)

```bash
# Android manifests (all product flavors)
find . -name 'AndroidManifest.xml' 2>/dev/null | head -40
# iOS
find . \( -name 'Info.plist' -o -name '*.entitlements' -o -name 'NetworkSecurityConfig*' \) 2>/dev/null | head -40
# Network security
find . -name 'network_security_config.xml' 2>/dev/null
```

**Read every** `AndroidManifest.xml` and primary `Info.plist` / entitlements in scope (not a sample). Record module → platform → package/bundle id.

---

## Step 1 — Exported components (Activities, Receivers, Providers, Services)

### 1.1 Manifest harvest

```bash
rg -n "android:exported\s*=\s*\"(true|false)\"|<activity|<receiver|<provider|<service|intent-filter|android:permission|android:grantUriPermissions|android:protectionLevel|android:authorities" \
  --glob '**/AndroidManifest.xml'
```

For **each** component with `android:exported="true"` **OR** with an `<intent-filter>` and no explicit `exported="false"` (pre-API-31 implicit export):

| Field | Record |
|-------|--------|
| Type | activity / receiver / provider / service |
| Name | fully qualified class |
| Permission | none / custom / signature |
| Intent filters | actions / schemes / hosts |
| Sensitive? | handles auth, payment, OTP, WebView URL, file URI, DB |

### 1.2 Exploitability triage (static)

**FINDING** when exported **and** any of:

1. **No** `android:permission` (or only normal permission) **and** component handles secrets, payments, account switch, WebView `loadUrl`, file ops, or SQL.
2. **BroadcastReceiver** listens for SMS / BOOT / custom auth actions without signature permission.
3. **ContentProvider** has `android:grantUriPermissions="true"` or world-readable paths without path validation; or `openFile` / query built from untrusted URI segments.
4. **Activity** is BROWSABLE / deep-link entry without validation (hand off to `deeplink-audit.md` + keep IPC finding if Intent extras trusted).
5. Code does **Intent redirection**: `startActivity(getIntent())`, `getParcelableExtra` → `startActivity`, unvalidated `setClassName` from extras.

```bash
rg -n "startActivity\s*\(\s*getIntent|startActivity\s*\(\s*intent\s*\)|getParcelableExtra\s*\(|getStringExtra\s*\([^)]*\)\s*;|setClassName\s*\(.*get" \
  --glob '**/*.{java,kt}' | head -80
rg -n "onReceive\s*\(|SmsMessage|Telephony\.Sms|OTP|otp|verify" --glob '**/*.{java,kt}' | head -60
rg -n "ContentProvider|openFile\s*\(|query\s*\(|getType\s*\(|call\s*\(" --glob '**/*.{java,kt}' | head -60
rg -n "PendingIntent\.(getActivity|getBroadcast|getService)|FLAG_MUTABLE|FLAG_IMMUTABLE" --glob '**/*.{java,kt}'
```

**Provider path / SQL:**

```bash
rg -n "openFile\s*\(|Uri\.parse|getLastPathSegment|rawQuery\s*\(.*uri|selection\s*\+.*uri" --glob '**/*.{java,kt}'
```

### 1.3 Static PoC (document in finding — not live Frida)

```markdown
### Mobile Component PoC (static reproduction)
# Exported activity
adb shell am start -n com.example/.VulnerableActivity --es url "https://evil.example"

# Exported receiver
adb shell am broadcast -a com.example.CUSTOM_ACTION --es token "stolen"

# Exported provider (path traversal candidate)
adb shell content query --uri content://com.example.provider/../../../data/data/com.example/shared_prefs/secrets.xml
```

Same root cause across many exported components → **one VULN** with `### Instances` (`finding-instances.md`).

---

## Step 2 — ATS / cleartext / network security (MANDATORY)

### Android

```bash
rg -n "usesCleartextTraffic|networkSecurityConfig|cleartextTrafficPermitted|base-config|domain-config|trust-anchors|debug-overrides|certificates\s+src\s*=\s*\"user\"" \
  --glob '**/*.{xml,gradle,kts}'
rg -n "http://(?!schemas\.android|localhost|127\.0\.0\.1)" --glob '**/*.{java,kt,xml,properties,json}' | head -40
```

**Read** every `network_security_config.xml` fully.

| Pattern | Verdict |
|---------|---------|
| `android:usesCleartextTraffic="true"` (release) | FINDING — cleartext allowed |
| `cleartextTrafficPermitted="true"` in base-config | FINDING |
| `debug-overrides` trusting user CAs in **release** merge | FINDING (or Tentative if debug-only source set proven) |
| Hardcoded `http://` API base URL | FINDING (CWE-319) |
| Cleartext only in `debug` source set / BuildConfig.DEBUG | Appendix A or Low — document evidence |

### iOS ATS

```bash
rg -n "NSAppTransportSecurity|NSAllowsArbitraryLoads|NSAllowsArbitraryLoadsInWebContent|NSExceptionAllowsInsecureHTTPLoads|NSExceptionMinimumTLSVersion|NSIncludesSubdomains|NSTemporaryException" \
  --glob '**/Info.plist' -A3
```

| Pattern | Verdict |
|---------|---------|
| `NSAllowsArbitraryLoads` = true | FINDING (High typical) |
| Domain exception with `NSExceptionAllowsInsecureHTTPLoads` | FINDING per domain (instances) |
| `NSAllowsArbitraryLoadsInWebContent` alone | Medium / review WebView usage |

### TLS trust-all in app code

```bash
rg -n "TrustAll|trustAll|ALLOW_ALL|HostnameVerifier|X509TrustManager|checkServerTrusted\s*\{[^}]*\}|DisabledValidation|InsecureTrustManager|ServerTrustPolicy\.disable|AFSecurityPolicy.*AllowInvalid" \
  --glob '**/*.{java,kt,swift,m,mm,dart,ts,js}' | head -40
```

---

## Step 3 — Sensitive data on device (MANDATORY)

### Android storage sinks

```bash
rg -n "getSharedPreferences|SharedPreferences|PreferenceManager|EncryptedSharedPreferences|putString\s*\(|MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|openFileOutput\s*\([^,]+,\s*Context\.MODE_WORLD" \
  --glob '**/*.{java,kt}'
rg -n "SQLiteOpenHelper|Room\.databaseBuilder|rawQuery|execSQL|getWritableDatabase" --glob '**/*.{java,kt}' | head -40
rg -n "getExternalStorage|Environment\.DIRECTORY|MediaStore|File\s*\(\s*getExternal|WRITE_EXTERNAL_STORAGE" --glob '**/*.{java,kt,xml}'
rg -n "Realm\.|ObjectBox|MMKV|Hawk\.|Paper\." --glob '**/*.{java,kt}'
```

### iOS storage sinks

```bash
rg -n "UserDefaults|NSUserDefaults|@AppStorage|FileManager\.default|write\s*\(to:|NSKeyedArchiver|CoreData|Keychain|kSecClass|SecItemAdd" \
  --glob '**/*.{swift,m,mm}' | head -80
```

### Cross-platform

```bash
rg -n "AsyncStorage|SecureStore|FlutterSecureStorage|shared_preferences|Hive\.|GetStorage|expo-secure-store|localStorage\.setItem" \
  --glob '**/*.{ts,tsx,js,jsx,dart}' --glob '!**/node_modules/**' | head -60
```

### What counts as sensitive

Flag when **any** of these land in plaintext prefs / unencrypted DB / external storage / world-readable files / logs:

- session / access / refresh / SSO tokens, cookies, JWT  
- passwords, PINs, OTP, CVV, full PAN  
- private keys, API secrets  
- government ID, health (PHI), precise location + identity together  

**FINDING** examples:

1. `SharedPreferences.putString("token", …)` / `UserDefaults` token without Keychain / EncryptedSharedPreferences  
2. SQLite/Room storing auth tokens without SQLCipher / equivalent  
3. Secrets on external storage or `MODE_WORLD_*`  
4. `allowBackup="true"` **combined with** plaintext prefs containing tokens (chain — elevate severity)  
5. Clipboard copy of OTP/password (`ClipboardManager` / `UIPasteboard`)

```bash
rg -n "ClipboardManager|setPrimaryClip|UIPasteboard|clipboard" --glob '**/*.{java,kt,swift}' 
rg -n "FLAG_SECURE|setFlags\s*\(.*SECURE|isSecureTextEntry|secureTextEntry" --glob '**/*.{java,kt,swift,xml}'
```

Missing `FLAG_SECURE` on login/payment screens → Tentative/Low unless code clearly shows PIN/token UI without it → Medium.

---

## Step 4 — Backup, debuggable, extractability

```bash
rg -n "android:debuggable|android:allowBackup|android:fullBackupContent|dataExtractionRules|android:requestLegacyExternalStorage" \
  --glob '**/AndroidManifest.xml'
rg -n "getApplicationInfo\(\).*FLAG_DEBUGGABLE|BuildConfig\.DEBUG" --glob '**/*.{java,kt}' | head -20
```

| Pattern | Notes |
|---------|-------|
| `debuggable="true"` in main/release manifest | Critical/High |
| `allowBackup="true"` (default) + sensitive prefs | High when storage finding exists; else Medium |
| No `dataExtractionRules` / fullBackupContent deny on API 31+ with secrets | Medium |

iOS: debug entitlements / `get-task-allow` in **distribution** entitlements → FINDING.

```bash
rg -n "get-task-allow|aps-environment|com.apple.security.application-groups" --glob '**/*.{entitlements,plist}'
```

---

## Step 5 — WebView (static)

```bash
rg -n "setJavaScriptEnabled\s*\(\s*true|addJavascriptInterface|setAllowFileAccess\s*\(\s*true|setAllowUniversalAccessFromFileURLs|setAllowFileAccessFromFileURLs|loadUrl\s*\(|loadDataWithBaseURL|shouldOverrideUrlLoading|WKWebView|javaScriptEnabled|allowsBackForwardNavigationGestures" \
  --glob '**/*.{java,kt,swift,m,mm,xml}' | head -80
```

**FINDING** when:

- `addJavascriptInterface` + untrusted URL content  
- `setAllowUniversalAccessFromFileURLs(true)`  
- `loadUrl` / `loadData` fed from Intent extras / deep link without allowlist  
- JS enabled + file access on sensitive flows  

---

## Step 6 — Crypto & secrets in app

```bash
rg -n "AES/ECB|DES/|DESede|MD5|RC4|Cipher\.getInstance\s*\(\s*\"AES\"\s*\)|SecretKeySpec\s*\([^)]*\"[A-Za-z0-9+/]{8,}" \
  --glob '**/*.{java,kt,swift}' 
rg -n "api[_-]?key|secret|password|private[_-]?key\s*[:=]\s*[\"'][^\"']{8,}" \
  --glob '**/*.{java,kt,swift,xml,plist,json,dart,ts}' --glob '!**/node_modules/**' | head -40
```

Hardcoded keys → LEAK/VULN; ECB/hardcoded IV → VULN.

---

## Step 7 — Logging & error surfaces

```bash
rg -n "Log\.[dviwe]\s*\([^)]*(token|password|otp|pin|Authorization|Bearer|session|cookie|card|pan)" \
  --glob '**/*.{java,kt}' -i
rg -n "print\(|NSLog\(|os_log\(|Logger\(|debugPrint\(" --glob '**/*.{swift,m}' | head -30
rg -n "console\.(log|debug)\([^)]*(token|password|otp)" --glob '**/*.{ts,tsx,js}' -i | head -30
```

Sensitive values in logs → **LEAK-NNN** or VULN (CWE-532).

---

## Step 8 — Permissions & privacy (static)

```bash
rg -n "uses-permission|READ_SMS|RECEIVE_SMS|READ_CALL_LOG|PROCESS_OUTGOING_CALLS|ACCESS_FINE_LOCATION|READ_CONTACTS|CAMERA|RECORD_AUDIO|QUERY_ALL_PACKAGES|WRITE_SETTINGS|SYSTEM_ALERT_WINDOW" \
  --glob '**/AndroidManifest.xml'
rg -n "NSPhotoLibraryUsageDescription|NSLocationAlways|NSMicrophone|NSContacts|PrivacyInfo|NSUserTracking" \
  --glob '**/Info.plist'
```

Over-broad permissions without matching code use → Tentative / Appendix A (justify). `READ_SMS` + exported OTP receiver → chain with Step 1.

---

## Step 9 — React Native / Flutter bridges

```bash
rg -n "NativeModules\.|ReactMethod|@ReactMethod|MethodChannel|FlutterMethodChannel|Platform\.|expo-secure-store|AsyncStorage\.setItem" \
  --glob '**/*.{java,kt,ts,tsx,js,dart,swift}' --glob '!**/node_modules/**' | head -60
```

Bridge methods that accept URLs/file paths from JS without validation → FINDING (same as WebView/IPC).

---

## Validation (G1–G5)

| Gate | Mobile static specific |
|------|------------------------|
| G1 | Malicious app / ADB / backup attacker / MITM on cleartext as applicable |
| G2 | Manifest/component → handler code → sensitive sink (≥3 hops) |
| G3 | Signature permission, non-exported, EncryptedSharedPreferences, ATS default deny? |
| G4 | Practical on real package (exported + no permission is enough for High IPC) |
| G5 | Assume release build unless debug-only source set proven; note OEM/API level |

**Do not** drop findings solely because “needs rooted device” if backup/debuggable/exported already enable extraction without root.

---

## Severity calibration (typical)

| Scenario | Band |
|----------|------|
| Exported activity/receiver → session/auth without permission | **High**–**Critical** |
| Exported provider path traversal / PII dump | **High**–**Critical** |
| ATS arbitrary loads / cleartext API + tokens | **High** |
| Token in plaintext SharedPreferences / UserDefaults | **High** |
| Token in prefs + allowBackup true | **High**–**Critical** |
| WebView JS interface + untrusted content | **High** |
| Hardcoded API secret in APK source | **High** (LEAK) |
| Debuggable release | **Critical**–**High** |
| Missing FLAG_SECURE on PIN screen only | **Low**–**Medium** |
| Cleartext only in debug build type | Appendix A / Low |

---

## Reporting

| Field | Guidance |
|-------|----------|
| ID | **VULN-NNN** (IPC, storage, ATS, WebView, crypto); **LEAK-NNN** (secrets in source/logs); rarely **AUTH-NNN** if exported component bypasses login entirely |
| Instances | Same exported-without-permission pattern → one finding, many instances |
| PoC | `### Mobile Component PoC` / storage extraction notes; Burp N/A unless HTTP API involved |
| Discovery | Checklist (MOB-*) |

### Attestation block

```markdown
### Mobile SAST Audit (static)
| Trigger matched | Yes / No |
| Manifests / plists read | N |
| Exported components reviewed | N |
| ATS / network security reviewed | Yes / N/A |
| On-device storage sinks reviewed | Yes / N/A |
| FINDING IDs | VULN-… / LEAK-… / none |
| Runtime Frida/MITM | Residual — not assessed (static-only) |
| N/A reason | (if no mobile code) |
```

---

## Out of scope for this audit (Residual)

- Frida hooking, SSL unpinning demos, dynamic runtime patching  
- Store listing / binary-only APK without source (unless user provides decompiled tree in workspace)  
- Dependency CVE of Play services / CocoaPods (code-only / SCA mode rules apply)  
- Social engineering of users to install attacker APK beyond what exported IPC already allows  

Mark these **Residual — not assessed (static-only mobile mode)** in Completeness & Residual Risk Register when mobile is in scope.
