# Pack: Mobile native (Swift / Objective-C, Android Kotlin / Java, Dart / Flutter, React Native)

**Detect:** `*.swift`, `*.m`, `*.mm`, `Info.plist`, `*.xcodeproj`; `AndroidManifest.xml` (+ `*.kt`/`*.java` in that module); `pubspec.yaml`, `*.dart`; `react-native` in `package.json`.
**Also read (mandatory):** `../mobile-sast-audit.md` (static mobile checks) and `../deeplink-audit.md`. Backend APIs called by the app → backend pack. Runtime testing (Frida/MITM) is Residual in code-only mode.

## Sources

Deep links / universal links / App Links (`onOpenURL`, `application(_:open:)`, `intent.data`, `getIntent().getExtras()`), exported Activities/Services/Receivers/ContentProviders, `UIPasteboard`/clipboard, WebView `postMessage` / JS bridges, push payloads, QR codes, files from share extensions, network responses (if TLS is broken), Flutter `MethodChannel` calls, RN bridge methods.

## Key platform rules

- Android `WebView.addJavascriptInterface` exposes Java methods to any page loaded in the WebView; with `setJavaScriptEnabled(true)` + untrusted URLs → RCE-equivalent within app sandbox.
- Exported components (`android:exported="true"` or intent filters on API <31 defaults) are callable by any app.
- iOS `WKWebView` `evaluateJavaScript` with interpolated strings → JS injection; `UIWebView` is deprecated and unsafe.
- Keychain/Keystore vs `UserDefaults`/`SharedPreferences`: only the former are for secrets.
- `NSAllowsArbitraryLoads` (ATS off) / `android:usesCleartextTraffic="true"` / custom `TrustManager` → MITM.

## Hint rg

```bash
rg -n "addJavascriptInterface|setJavaScriptEnabled\s*\(\s*true|setAllowFileAccess|setAllowUniversalAccessFromFileURLs|loadUrl\s*\(|evaluateJavascript" --glob "*.{kt,java}"
rg -n "android:exported=\"true\"|<intent-filter|android:usesCleartextTraffic|android:debuggable|android:allowBackup=\"true\"|grantUriPermissions" --glob "AndroidManifest.xml"
rg -n "getSharedPreferences|MODE_WORLD_|openFileOutput|getExternalStorage|rawQuery\s*\(|execSQL\s*\(" --glob "*.{kt,java}"
rg -n "X509TrustManager|HostnameVerifier|onReceivedSslError|proceed\s*\(\s*\)|CertificatePinner" --glob "*.{kt,java}"
rg -n "NSAllowsArbitraryLoads|NSExceptionAllowsInsecureHTTPLoads|CFBundleURLSchemes|LSApplicationQueriesSchemes" --glob "*.plist"
rg -n "UserDefaults|NSUserDefaults|kSecAttrAccessibleAlways|evaluateJavaScript|UIWebView|loadHTMLString|canOpenURL|open\s*\(\s*url|onOpenURL|didReceive\s+challenge|performDefaultHandling|useCredential" --glob "*.{swift,m,mm}"
rg -n "sqlite3_exec|stringWithFormat:.*SELECT|NSPredicate\s*\(\s*format:\s*\"[^\"]*%@" --glob "*.{swift,m,mm}"
rg -n "badCertificateCallback|SharedPreferences|flutter_secure_storage|MethodChannel|WebView|javascriptMode|launchUrl|rawQuery|rawInsert" --glob "*.dart"
rg -n "AsyncStorage|WebView|injectJavaScript|originWhitelist|onMessage|Linking\.(openURL|addEventListener)|react-native-keychain" --glob "*.{js,jsx,ts,tsx}" -g '!node_modules/**'
rg -n "(api[_-]?key|secret|client_secret|private_key)\s*[:=]" -i --glob "*.{swift,m,kt,java,dart,plist,xml,json}" -g '!node_modules/**' -g '!Pods/**'
```

## Class coverage index

| ID | Vulnerable on mobile (Swift/ObjC · Android · Flutter · RN) | Safe equivalent | FP trap / note |
|----|-----------------------------------------------------------|-----------------|----------------|
| L01 | WebView XSS: `loadHTMLString(user)`, `loadData(user, "text/html")`, `evaluateJavaScript("show('\(x)')")`, RN `injectJavaScript(\`…${x}\`)`, Flutter `runJavaScript("…$x")` | pass data via `postMessage`/JSON-encoded args, sanitize HTML | native `UILabel`/`TextView`/`Text` widgets are not XSS |
| L02 | server-driven UI templates compiled on device from untrusted sources | signed configs | |
| L03 | `addJavascriptInterface` + untrusted pages, `DexClassLoader`/`PathClassLoader` loading downloaded code, JSContext (`JavaScriptCore`) evaluating remote scripts, RN CodePush from unverified source | no JS bridges for untrusted origins, signed updates | |
| L04 | Android `rawQuery("… " + x)`/`execSQL`, ContentProvider `query()` concatenating `selection`; iOS `sqlite3_exec` with `stringWithFormat`; Flutter `sqflite` `rawQuery('… $x')` | `?` + `selectionArgs`, Room `@Query` binds, `sqlite3_bind_*`, sqflite `whereArgs` | Room DAO params are bound |
| L05 | Realm/NSPredicate: `NSPredicate(format: "name == '\(x)'")` (format injection) | `NSPredicate(format: "name == %@", x)` | `%@` placeholders are safe |
| L06 | `Runtime.exec` on rooted-device helpers, `Process` (macOS Catalyst) | avoid shell | rarely reachable on mobile |
| L07 | N/A — mobile apps rarely build LDAP/XPath queries; `NSXMLDocument` XPath on untrusted XML is the analogue | fixed XPath | |
| L08 | log injection via `Log.d`/`NSLog`/`print` of untrusted data (also L27 leakage) | strip in release builds | |
| L09 | app fetching URLs from deep-link params (`?url=`) with auth headers attached → token theft (mobile "SSRF") | allow-list hosts before attaching credentials | see `../deeplink-audit.md` |
| L10 | ContentProvider `openFile(uri)` with `uri.getPath()` → `../` traversal; `FileProvider` with `<root-path>`; iOS file paths from URL params | canonical path check, narrow `file_paths.xml` | |
| L11 | Zip extraction of downloaded content without entry checks (Android `ZipInputStream`, `SSZipArchive` old versions) | entry path validation | |
| L12 | Android `Serializable`/`Parcelable` from untrusted Intents (`getSerializableExtra`), iOS `NSKeyedUnarchiver.unarchiveObject` (non-secure coding) | `NSKeyedUnarchiver.unarchivedObject(ofClass:from:)` (secure coding), typed Parcelables, `getParcelableExtra(key, Class)` | |
| L13 | `NSXMLParser` with `shouldResolveExternalEntities = true`, Android `DocumentBuilderFactory` defaults (see `java-kotlin.md` L13) | defaults off / secure features | |
| L14 | Intent extras overriding internal state (`intent.getBooleanExtra("isAdmin")`), Codable models decoding server-trust fields from deep links | ignore privileged fields from external inputs | |
| L15 | auth tokens in `UserDefaults`/`SharedPreferences`/`AsyncStorage`, biometric checks via `LocalAuthentication` boolean only (bypassable with hooks; no Keychain-bound key) | Keychain/Keystore, `kSecAccessControlBiometryCurrentSet`, `BiometricPrompt` + `CryptoObject` | |
| L16 | OAuth without PKCE, custom URL-scheme redirect hijack, tokens in deep links, JWT validated client-side only | PKCE + claimed HTTPS redirect (App Links / universal links), `ASWebAuthenticationSession` / AppAuth | |
| L17 | exported Activities exposing privileged screens (`android:exported="true"` without `permission`), iOS URL handlers performing actions without confirmation | `exported=false`, signature permissions, user confirmation | |
| L18 | WebView-based flows with cookie auth loading attacker pages | isolate WebView cookie stores | native API calls with bearer tokens N/A |
| L19 | N/A on device — CORS is server-side; WebView `setAllowUniversalAccessFromFileURLs(true)` is the analogue (file:// pages read any origin) | keep disabled | |
| L20 | `allowBackup="true"` (data extraction via adb backup), screenshots of sensitive screens (`FLAG_SECURE` missing), `debuggable=true` | `allowBackup=false`/`dataExtractionRules`, `FLAG_SECURE` | |
| L21 | deep-link handlers opening arbitrary URLs (`UIApplication.shared.open(url)` / `startActivity(Intent(ACTION_VIEW, uri))` from params) | allow-list | |
| L22 | hardcoded AES keys in app, `CC_MD5`/`CC_SHA1` for passwords, `Cipher.getInstance("AES")` (ECB), static IVs | Keystore/Keychain-generated keys, CryptoKit `AES.GCM` | |
| L23 | `arc4random` is fine; `java.util.Random`, Dart `Random()` (non-secure) for tokens | `SecureRandom`, `SecRandomCopyBytes`, `Random.secure()` | |
| L24 | ATS disabled, `usesCleartextTraffic`, trust-all `TrustManager`, `onReceivedSslError → handler.proceed()`, `URLSession` delegate accepting any `serverTrust`, Flutter `badCertificateCallback = (…) => true` | defaults + certificate pinning (`network_security_config.xml`, `TrustKit`) | debug-only configs (check build type) |
| L25 | API secrets/client secrets in source, `strings.xml`, `Info.plist`, `google-services.json` with unrestricted keys | backend-held secrets, key restrictions | Firebase/Maps keys are public by design if restricted |
| L26 | verbose crash/error dialogs with server responses; debug menus in release builds | strip in release | |
| L27 | `Log.d`/`NSLog`/`print` of tokens/PII in release, analytics with PII, clipboard holding OTP/card data | `ProGuard` stripping, `os_log` privacy `%{private}` | |
| L28 | N/A for server DoS; app crash loops from malformed deep links/intents (local DoS, low) | input validation | usually Low |
| L29 | double-tap payment submission (server must be idempotent), shared mutable state across threads (Swift `actor` misuse, Kotlin coroutines) | idempotency keys server-side | |
| L30 | client-side price/entitlement checks (in-app purchase validated only on device), jailbreak/root checks as the only control | server-side receipt validation | |
| L31 | Swift `UnsafePointer`/`UnsafeMutableRawPointer`, ObjC C buffers, JNI/NDK native code → `c-cpp.md` | safe Swift/Kotlin APIs | |
| L32 | CocoaPods/SPM/Gradle/pub deps unpinned, third-party SDKs with broad permissions, `Podfile` sources over HTTP | lockfiles (`Podfile.lock`, `Package.resolved`, `pubspec.lock`) | SCA opt-in |
| L33 | GraphQL/WebSocket clients without TLS pinning; gRPC with plaintext channels (`ManagedChannelBuilder.usePlaintext()`) | TLS channels | |
| L34 | `NSClassFromString(user)`/`performSelector(NSSelectorFromString(user))`, Android reflection `Class.forName(intentExtra)` | allow-list | |
| L35 | `PendingIntent` mutable/implicit (hijack), sticky broadcasts, iOS pasteboard sharing (`UIPasteboard.general`), Flutter `MethodChannel` handlers trusting any caller, RN `originWhitelist={['*']}` | `FLAG_IMMUTABLE` explicit intents, local pasteboards, origin allow-lists | |
