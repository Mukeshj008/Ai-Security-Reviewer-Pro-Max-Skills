# Mobile SAST Manifest (additive — when android/ or ios/ present)

**Trigger:**

```bash
test -d android || test -d ios || test -d app/src/main/AndroidManifest.xml
find . -name "AndroidManifest.xml" -o -name "Info.plist" 2>/dev/null | head -5
```

**Extends** `extended-category-scans.md` §19 — does not replace it.

---

## SAST-MOB-01…08

| ID | Check | rg / Read |
|----|-------|-----------|
| MOB-01 | Hardcoded API keys in app | `rg "api[_-]?key|secret" android/ ios/` |
| MOB-02 | android:debuggable / allowBackup | `rg "debuggable|allowBackup" AndroidManifest.xml` |
| MOB-03 | Exported components without permission | `rg "exported=\"true\"" AndroidManifest.xml` |
| MOB-04 | WebView JS / file access | `rg "setJavaScriptEnabled|addJavascriptInterface|file://" ` |
| MOB-05 | Weak crypto (ECB, MD5) | `rg "AES/ECB|MD5|DES" android/ ios/` |
| MOB-06 | ATS / cleartext traffic | `rg "NSAllowsArbitraryLoads|cleartextTrafficPermitted"` |
| MOB-07 | Insecure cert pinning bypass | `rg "TrustAll|disableCertificateValidation"` |
| MOB-08 | Sensitive data in logs | `rg "Log\.(d|i|w|e).*password|token" android/` |

---

## DAST / runtime

Frida, MITM, emulator DAST → **Manual** — document N/A or Partial in attestation.

---

## Report

Mark **MOB-*** N/A when no mobile tree. FINDING → VULN-NNN with platform category.

Platform checklist: `platform-coverage-checklist.md` §3–4.
