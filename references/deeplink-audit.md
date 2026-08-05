# Deep Link / Universal Link / App Link Audit (MANDATORY when mobile or deeplink surfaces exist)

**Purpose:** catch **deep-link session theft** and related bugs commonly reported in bug-bounty programs — unvalidated deep links that leak or accept session tokens, cookies, OTPs, or auth codes in URLs, or redirect into attacker-controlled destinations.

**Trigger (run this audit when any match):**

```bash
rg -l -i "deeplink|deep.?link|universal.?link|app.?link|CFBundleURLSchemes|android:scheme|intent-filter|getInitialURL|Linking\.|onNewIntent|associated.?domain|applinks:|branch\.io|appsflyer|adjust\.com|FirebaseDynamicLinks|DynamicLink" \
  --glob '!**/node_modules/**' --glob '!**/target/**' --glob '!**/build/**' . | head -40

# Also trigger for web/BFF that *mint* deep links for mobile
rg -l -i "deeplink|deep_link|universalLink|appLink|intent://|myapp://|fintech://|://login|token=.*=.*http" \
  --glob '*.{java,kt,js,ts,swift,m,mm,xml,plist,yml,json}' --glob '!**/node_modules/**' . | head -40
```

If **no** mobile tree **and** no deeplink minting/handling code → mark **N/A** in attestation with reason.

---

## Threat model (bug-bounty classics)

| Abuse | How it works | Impact |
|-------|--------------|--------|
| **Session / token in deep-link URL** | App or backend puts `token`, `sid`, `sessionId`, `auth`, `otp`, `code` in query/fragment; link is logged, shared, referrer-leaked, or intercepted | Account takeover |
| **Unvalidated deep-link destination** | `redirect`, `url`, `next`, `target`, `path` from deep link loaded in WebView / openURL without allowlist | Phishing, token exfil via fake login |
| **Custom scheme hijacking** | `myapp://` claimed by attacker app on Android; victim link opens attacker app with token params | Session theft |
| **Intent redirection** | Exported activity forwards `Intent` extras / `getData()` to another component without validation | Privilege / session abuse |
| **Missing App Links / Universal Links verification** | `autoVerify` missing or AASA/assetlinks misconfigured → falls back to hijackable custom scheme | Same as scheme hijack |
| **OAuth / magic-link via deep link** | `redirect_uri` or magic link delivers code/token to unvalidated handler | ATO |
| **Web→app bridge without binding** | Server returns deep link with session to any `redirect` param | Session fixation / theft |

---

## Step 1 — Inventory deep-link entry points

### Android

```bash
rg -n "android:scheme|android:host|android:pathPrefix|android:pathPattern|autoVerify|BROWSABLE|android.intent.action.VIEW" --glob "**/AndroidManifest.xml"
rg -n "getIntent\(\)|getData\(\)|onNewIntent|Intent\.parseUri|intent://|setData\(|EXTRA_|" --glob "**/*.{java,kt}" | head -80
```

### iOS

```bash
rg -n "CFBundleURLSchemes|CFBundleURLTypes|applinks:|com.apple.developer.associated-domains" --glob "**/*.{plist,entitlements}"
rg -n "application\(_:open:options:\)|continue userActivity|universalLink|NSUserActivityTypeBrowsingWeb|openURL" --glob "**/*.{swift,m,mm}" | head -80
```

### React Native / Flutter / Web

```bash
rg -n "Linking\.(addEventListener|getInitialURL)|useURL\(|expo-linking|ReactNavigation.*linking|uni_links|app_links|go_router.*redirect" --glob "**/*.{js,ts,tsx,dart}"
rg -n "deeplink|deep_link|universalLink|appLink" --glob "**/*.{java,kt,js,ts,swift,yml,json}" | head -60
```

Record each handler:

```
| Platform | Scheme / host | Handler file:line | Params read | Auth/session params? | Validation? |
```

---

## Step 2 — Session / secret parameters in links (HIGH priority)

```bash
rg -n -i "(deep.?link|universal|app.?link|intent://|://).*(token|session|sid|auth|otp|password|code|jwt|access_token|refresh_token)" --glob '**/*.{java,kt,js,ts,swift,xml,yml,json,properties}'
rg -n -i "(token|sessionId|session_id|authToken|access_token|otp|magic.?link)\s*[=:].*(deeplink|deep_link|redirect|callback|returnUrl)" --glob '**/*.{java,kt,js,ts,swift}'
rg -n -i "Uri\.(parse|build)|URLSearchParams|queryParameters|getQueryParameter\s*\(\s*[\"'](token|session|sid|auth|otp|code)" --glob '**/*.{java,kt,js,ts,swift,dart}'
```

**Flag as FINDING (typically High–Critical)** when:

1. Session, SSO token, JWT, OTP, or OAuth `code` is placed in a deep-link query/fragment, **or**
2. Deep-link handler reads those params and sets local session/cookie/WebView without additional proof (device binding, one-time use, short TTL + PKCE).

**Classify data:** PII / PFI as applicable; session token → Authentication impact **HIGH**.

---

## Step 3 — Missing validation / open redirect via deep link

```bash
rg -n -i "getQueryParameter\s*\(\s*[\"'](url|redirect|next|return|target|dest|link|continue)" --glob '**/*.{java,kt,js,ts,swift,dart}'
rg -n -i "loadUrl\s*\(.*get(Data|StringExtra)|loadUrl\s*\(.*deeplink|WebView.*deep" --glob '**/*.{java,kt,js,ts,swift}'
rg -n -i "openURL\s*\(|canOpenURL|Linking\.openURL\s*\([^)]*deeplink|Linking\.openURL\s*\([^)]*url" --glob '**/*.{js,ts,swift}'
```

**Require allowlist evidence** (exact hosts/paths or signed link verification). If handler navigates to attacker-controlled URL from deep-link param → **VULN-NNN** (CWE-601 Open Redirect / CWE-939 Improper Authorization of Intent).

---

## Step 4 — Custom scheme & verification gaps

| Check | Pass criteria | Fail → finding |
|-------|---------------|----------------|
| Android App Links | `autoVerify=true` + valid `assetlinks.json` referenced | Custom scheme only / no autoVerify on login/token hosts |
| iOS Universal Links | Associated Domains + AASA | Custom scheme only for auth callbacks |
| Exported activities | Permission or non-exported for sensitive handlers | `exported=true` + BROWSABLE + token params |
| Intent forward | Validated component / explicit intent | `startActivity(getIntent())` style redirect |

```bash
rg -n "exported=\"true\"" --glob "**/AndroidManifest.xml" -A5
rg -n "startActivity\s*\(\s*getIntent|startActivity\s*\(\s*intent\s*\)|setClassName\s*\(.*getStringExtra" --glob '**/*.{java,kt}'
```

---

## Step 5 — Backend / BFF that mints deep links

Server-side code often builds `myapp://login?token=...` or https universal links with secrets:

```bash
rg -n -i "deeplink|deep_link|universalLink|app://|intent://|://.*\?(token|session|sid|auth)=" --glob '**/*.{java,kt,js,ts,py,go}' 
rg -n -i "redirect_uri|returnUrl|callbackUrl" --glob '**/*.{java,kt,js,ts}' | head -40
```

**Flag:** minting deep links with long-lived tokens; accepting unbound `redirect_uri` that becomes a deep link; logging full deep-link URLs (LEAK).

---

## Validation (G1–G5)

| Gate | Deep-link specific |
|------|-------------------|
| G1 | Attacker can craft or intercept a link (email, ads, QR, evil app, referrer) |
| G2 | Trace param → session store / WebView / cookie (≥3 hops) |
| G3 | Allowlist, signature (HMAC), one-time code, App Links verified? |
| G4 | Practical ATO or phishing on real scheme/host |
| G5 | Assumptions (Android version, AASA deployed, link preview bots) |

---

## Reporting

| Field | Guidance |
|-------|----------|
| ID | **VULN-NNN** (session theft / open redirect) or **AUTH-NNN** if deep link bypasses login entirely |
| CWE | CWE-598 (info in GET), CWE-601 (open redirect), CWE-927 (use of implicit intent), CWE-939, CWE-200 |
| OWASP Mobile | M1 / M3 / M8 as applicable; OWASP A01/A07 for session |
| Instances | Multiple schemes/handlers → one finding with `### Instances` (`finding-instances.md`) |
| Burp / PoC | For **HTTPS** universal-link landing pages use HTTP PoC; for **custom schemes** document Android/iOS PoC (adb `am start`, `xcrun simctl openurl`) under `### Burp Suite PoC` as **Mobile Deep Link PoC** (Burp N/A for custom scheme — still publish reproduction steps) |

### Mobile Deep Link PoC template

```markdown
### Burp Suite PoC
Burp PoC: N/A — custom-scheme deep link (not HTTP). Use device PoC below.

### Mobile Deep Link PoC
# Android
adb shell am start -a android.intent.action.VIEW -d "myapp://login?token=ATTACKER_CAPTURED_OR_TEST"

# iOS Simulator
xcrun simctl openurl booted "myapp://login?token=ATTACKER_CAPTURED_OR_TEST"

Expected if vulnerable: app establishes session / loads WebView without re-auth.
```

For https App Links / universal links that hit a web endpoint first:

```http
GET /app/link?token=§TOKEN§&redirect=https://evil.example HTTP/1.1
Host: [TARGET_HOST]
```

---

## Severity calibration (typical)

| Scenario | Impact | Severity band |
|----------|--------|---------------|
| Session/JWT/OTP in deep link + no one-time binding | Severe (ATO) | **Critical**–**High** |
| Unvalidated redirect to attacker site after auth | High | **High** |
| Custom scheme auth callback without App Link verify | High | **High** |
| Exported activity + intent redirect | High | **High**–**Medium** |
| Deep link only opens public catalog path (allowlisted) | Low/None | Appendix A or Low |

---

## Attestation

```markdown
### Deep Link Audit
| Trigger matched | Yes / No |
| Handlers inventoried | N |
| Session-in-URL candidates | N |
| Unvalidated destination candidates | N |
| FINDING IDs | VULN-… / AUTH-… / none |
| N/A reason | (if no deeplink surface) |
```
