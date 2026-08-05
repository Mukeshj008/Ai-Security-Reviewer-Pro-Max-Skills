# Mobile SAST Manifest (STATIC ONLY — when android/ or ios/ or mobile client code present)

**Trigger:**

```bash
find . \( -name 'AndroidManifest.xml' -o -name 'Info.plist' -o -name 'network_security_config.xml' \) 2>/dev/null | head -10
test -d android -o -d ios -o -d app/src/main
```

**Mandatory procedure:** run full **`mobile-sast-audit.md`** (not this table alone).  
**Also:** **`deeplink-audit.md`** when deep-link / App Links / Universal Links present.  
**Extends** `extended-category-scans.md` §19.7.

**Static only:** no Frida / MITM / emulator login required to raise findings. Runtime → Residual in attestation.

---

## SAST-MOB checklist

| ID | Check | rg / Read (summary) |
|----|-------|---------------------|
| MOB-01 | Hardcoded API keys / secrets in app | `rg "api[_-]?key\|secret\|private[_-]?key"` mobile sources |
| MOB-02 | `android:debuggable` / release debug flags | Manifest `debuggable`; iOS `get-task-allow` |
| MOB-03 | Exported components without strong permission | Manifest `exported="true"` + no signature permission |
| MOB-04 | WebView JS / file / universal access | `setJavaScriptEnabled`, `addJavascriptInterface`, file URL flags |
| MOB-05 | Weak crypto (ECB, MD5, DES, hardcoded keys) | `AES/ECB`, `MD5`, `SecretKeySpec` |
| MOB-06 | ATS / cleartext traffic | `NSAllowsArbitraryLoads`, `usesCleartextTraffic`, `cleartextTrafficPermitted` |
| MOB-07 | TLS trust-all / pinning bypass in code | `TrustAll`, `HostnameVerifier`, `ServerTrustPolicy.disable` |
| MOB-08 | Sensitive data in logs | `Log.*token\|password`, `NSLog`, `console.log` secrets |
| MOB-09 | Deep links / App Links / Universal Links | **`deeplink-audit.md`** |
| MOB-10 | Session/token query params in link handlers | `deeplink-audit.md` Step 2 |
| MOB-11 | Exported BROWSABLE + autoVerify gaps | `deeplink-audit.md` Step 4 |
| **MOB-12** | **Exploitable exported Activities** | Intent filters + handler sinks; Intent redirect |
| **MOB-13** | **Exploitable exported BroadcastReceivers** | SMS/OTP/custom actions without signature permission |
| **MOB-14** | **Exploitable exported ContentProviders** | Path traversal, openFile, SQL via URI, grantUriPermissions |
| **MOB-15** | **Exploitable exported Services** | start/bind without permission + sensitive ops |
| **MOB-16** | **PendingIntent mutability / IPC injection** | `FLAG_MUTABLE`, `getActivity` without immutable |
| **MOB-17** | **network_security_config / ATS exceptions** | Read every NSC + Info.plist ATS dictionary |
| **MOB-18** | **Hardcoded `http://` API bases** | Cleartext endpoints in code/config |
| **MOB-19** | **Sensitive data in SharedPreferences / UserDefaults** | Tokens/PII without EncryptedSharedPreferences / Keychain |
| **MOB-20** | **Sensitive data in SQLite/Room/Realm/Core Data** | Auth tokens/PII unencrypted at rest |
| **MOB-21** | **External / world-readable storage** | `getExternalStorage`, `MODE_WORLD_*`, public files |
| **MOB-22** | **allowBackup / dataExtractionRules vs secrets** | Backup-enabled + plaintext secrets chain |
| **MOB-23** | **Clipboard / screenshot leakage** | ClipboardManager OTP; missing `FLAG_SECURE` on auth UI |
| **MOB-24** | **RN/Flutter insecure storage bridges** | AsyncStorage / shared_preferences for tokens |
| **MOB-25** | **Dangerous permissions without justification** | READ_SMS, etc. + correlating receivers |
| **MOB-26** | **WebView load from Intent / untrusted URL** | `loadUrl(getIntent…)` without allowlist |

---

## Execution order

1. Inventory manifests / plists (`mobile-sast-audit.md` Step 0)  
2. Exported IPC (Steps 1) — Activities, Receivers, Providers, Services  
3. ATS / cleartext / NSC (Step 2)  
4. On-device storage (Step 3–4)  
5. WebView, crypto, logs, permissions, bridges (Steps 5–9)  
6. Deep links (`deeplink-audit.md`)  
7. Adjudicate G1–G5 → findings with instances  

---

## DAST / runtime

Frida, MITM, emulator interactive DAST → **Residual — not assessed** under static-only mobile mode.  
**Static reproduction** still required in findings: `adb shell am start|broadcast|content query`, storage path notes — see `mobile-sast-audit.md` PoC templates.

---

## Report

- Mark MOB-* **N/A** when no mobile tree.  
- FINDING → **VULN-NNN** / **LEAK-NNN**; same root cause → instances.  
- Attestation must include **`### Mobile SAST Audit (static)`** block from `mobile-sast-audit.md`.  
- Platform checklist: `platform-coverage-checklist.md` §3–4.
