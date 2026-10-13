# ChronoCraft Android Security Audit

**Audit date:** 2026-10-13 (Asia/Calcutta)  
**Assessment type:** Authorized, adversarial static source/configuration review with local build validation and current dependency-advisory lookup  
**App/package:** ChronoCraft / `com.arafat.chrono`  
**Version reviewed:** `2.0.1` (`versionCode 36`)  
**Stack:** React 19 + TypeScript/Vite in a Capacitor 6 Android WebView; Java native plugin code  
**SDKs:** `minSdk 24`, `targetSdk 36`, `compileSdk 36` (`android/variables.gradle:2-4`)  
**Backend/API:** No backend implementation, API documentation, credentials, or base URL was provided. Backend-only assertions are therefore **Not Verifiable**.  
**Provided material:** Source, Android manifests/Gradle files, lockfile, CI workflows. No supplied APK/AAB, signing certificate, installed app, backend, Firebase project, or test accounts.

## 1. Executive summary

**Overall risk: High.** The application is small and contains no authentication, payments, account data, analytics SDK, or obvious backend client, which limits business impact. Its trusted WebView boundary is nevertheless unsafe: the locked Capacitor runtime is affected by a critical same-origin proxy vulnerability, and every release loads a remote debugging script from a public CDN into the Capacitor page. In a rooted/MITM threat model, modification of that script gives attacker JavaScript the app origin, local timer/history data, and access to registered native plugins.

### Finding counts

| Critical | High | Medium | Low | Info | Total |
|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 5 | 3 | 1 | 11 |

### Top five fixes

1. Upgrade `@capacitor/android` and `@capacitor/core` from 6.2.1 to at least 6.2.2, rebuild, and redistribute; this fixes CVE-2026-103922.
2. Remove the release-loaded jsDelivr/Eruda script, self-host required assets, and add a restrictive CSP. Do not execute remote JavaScript inside the Capacitor origin.
3. Set `android:allowBackup="false"` (or explicit restrictive extraction rules) and decide whether clock names/history are sensitive enough to require native encrypted storage.
4. make timer notifications private/redacted on the lock screen and use immutable PendingIntents wherever RemoteInput is not required.
5. Patch or remove the other vulnerable locked dependencies and make `npm audit`, secret scanning, SAST, and Android lint release gates.

### Evidence and validation boundary

- `npm run build`: **PASS**; Vite produced a minified web bundle without source-map files. The resulting `dist/index.html` still contains the remote Eruda script.
- `:app:processReleaseMainManifest`: **PASS** after overriding the checkout's Termux-only AAPT2 setting for this Windows audit. The merged manifest was inspected.
- `npm audit --package-lock-only --json`: **FAIL**; 10 vulnerable packages (3 critical, 4 high, 3 moderate).
- `npm run lint` (`tsc --noEmit`): **FAIL** with unresolved `TimerPreset`, `Clock`, and `capacitorBridge` symbols.
- `:app:assembleRelease`: **NOT-RUN TO COMPLETION**; failed before compilation because no Android SDK location (`ANDROID_HOME`/`sdk.dir`) is available in this checkout.
- Installed-device, rooted-device, Frida/Objection, Burp/mitmproxy, MobSF, APK signature, tapjacking, backup/restore, deep-link fuzzing, and backend authorization tests: **NOT-RUN**.

## 2. Findings table

| ID | Title | Severity (CVSS 3.1) | CWE | OWASP MASVS/MASTG reference | Location |
|---|---|---|---|---|---|
| CC-01 | Critical Capacitor same-origin proxy vulnerability | Critical (9.3) | CWE-346, CWE-441 | MASVS-PLATFORM-1, MASVS-CODE-1; MASTG dependency analysis/WebView testing | `package-lock.json:312-319` |
| CC-02 | Remote Eruda code executes inside the trusted Capacitor origin | High (8.1) | CWE-494, CWE-829 | MASVS-NETWORK-1/2, MASVS-PLATFORM-2, MASVS-CODE-2 | `index.html:12-23` |
| CC-03 | Backup-enabled plaintext WebView storage exposes user history | Medium (5.5) | CWE-312, CWE-922 | MASVS-STORAGE-1/2 | `AndroidManifest.xml:4-10`; `src/utils/storage.ts:55-76,213-230` |
| CC-04 | User-controlled timer names are public on the lock screen | Medium (4.3) | CWE-200, CWE-359 | MASVS-STORAGE-2, MASVS-PRIVACY-1 | `MainActivity.java:64-70`; `capacitorNativeBridge.ts:103-124`; `App.tsx:250-303` |
| CC-05 | Local-notification PendingIntents are unnecessarily mutable | Medium (4.4) | CWE-926, CWE-441 | MASVS-PLATFORM-1/2 | `package-lock.json:385-392`; generated dependency `LocalNotificationManager.java:246-295,323-333` |
| CC-06 | Lockfile contains additional vulnerable runtime/build dependencies | Medium (6.5) | CWE-1104 | MASVS-CODE-1 | `package-lock.json:2020-2028,2251-2259,2847-2859,4376-4387,4407-4418,4800-4807,4885-4897` |
| CC-07 | Release hardening disabled and debugging console shipped | Medium (5.3) | CWE-489, CWE-693 | MASVS-RESILIENCE-3/4, MASVS-CODE-2 | `android/app/build.gradle:19-23`; `index.html:22-23` |
| CC-08 | FileProvider exposes the entire external-storage tree to any future grant | Low (3.3) | CWE-22, CWE-732 | MASVS-PLATFORM-1 | `android/app/src/main/res/xml/file_paths.xml:1-5` |
| CC-09 | Full clock/lap history can be placed on the global clipboard | Low (3.3) | CWE-200 | MASVS-STORAGE-2, MASVS-PRIVACY-1 | `HistoryModal.tsx:148-184`; `StopwatchCard.tsx:221-231` |
| CC-10 | External requests contradict the stated offline/privacy posture | Low (3.1) | CWE-359 | MASVS-PRIVACY-1/2, MASVS-NETWORK-1 | `index.html:12-14,22`; `metadata/com.arafat.chrono.yml:18-20` |
| CC-11 | No runtime integrity, signature, root, hook, or debugger defenses | Info (0.0) | CWE-693 | MASVS-RESILIENCE-1/2/3/4 | No implementation found; `minifyEnabled false` at `android/app/build.gradle:21` |

## 3. Detailed findings

### CC-01 — Critical Capacitor same-origin proxy vulnerability

**Description and affected component.** The lockfile installs `@capacitor/android` 6.2.1. CVE-2026-103922 / GHSA-rvm3-566m-v7fv affects Capacitor Android versions `>=6.0.0 <6.2.2`. Its internal `/_capacitor_http_interceptor_` path can return attacker-selected remote content as a document under the app's own origin. That content can access same-origin storage and registered Capacitor plugins. Upstream CVSS is 9.3 (`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`).

**Evidence.** `package-lock.json:312-319` locks 6.2.1. Installed source also declares the vulnerable proxy paths at `node_modules/@capacitor/android/capacitor/src/main/java/com/getcapacitor/Bridge.java:94-98`; JavaScript/native bridging is enabled at `MessageHandler.java:26-42`. The official advisory states 6.2.2 is the patched 6.x release: <https://github.com/ionic-team/capacitor/security/advisories/GHSA-rvm3-566m-v7fv>.

**Exploit scenario.** (1) An attacker gets a crafted link rendered or navigated in the app WebView. (2) The victim activates it. (3) The URL targets the internal Capacitor proxy and supplies an attacker endpoint. (4) Capacitor 6.2.1 returns attacker HTML under `https://localhost`. (5) Attacker script reads/modifies `localStorage` and invokes available native plugins. No current user-controlled link-rendering feature was found, so the vulnerable component is proven present but this standalone delivery path was not reproduced in this version.

**Impact.** Same-origin compromise of local clock/history data and the Capacitor JavaScript/native trust boundary. Future link-rendering features would make delivery straightforward.

**Fix.** Align Capacitor packages at a patched level and rebuild:

```json
"dependencies": {
  "@capacitor/android": "^6.2.2",
  "@capacitor/core": "^6.2.2"
},
"devDependencies": {
  "@capacitor/cli": "^6.2.2"
}
```

Run `npm install`, `npx cap sync android`, rebuild, and publish a new APK/AAB. Also reject navigation whose path begins `/_capacitor_http_interceptor_` as a temporary defense; disabling `CapacitorHttp` alone is not sufficient on the vulnerable release.

**Verify.** Confirm `npm ls @capacitor/android @capacitor/core` reports `>=6.2.2`; rerun `npm audit`; use an instrumented test page with the advisory's proxy navigation and verify main-frame/subframe navigation is blocked and no attacker script can access `localStorage` or `window.Capacitor`.

### CC-02 — Remote Eruda code executes inside the trusted Capacitor origin

**Description and affected component.** Production HTML loads unversioned `https://cdn.jsdelivr.net/npm/eruda` and immediately initializes it. There is no integrity hash, version pin, CSP, or application-level certificate pinning. In Capacitor, this is not an isolated browser tab: the page has same-origin access to all WebView storage and a bridge to registered plugins.

**Evidence.** `index.html:12-14` loads Google-hosted CSS/fonts; `index.html:22-23` loads and executes Eruda. The production build preserved these tags in `dist/index.html`. `capacitorNativeBridge.ts:49-52` registers LocalNotifications, Haptics, and the custom Chronometer plugin. Capacitor's runtime enables JavaScript/DOM storage and attaches the native bridge (`Bridge.java:560-570`; `MessageHandler.java:26-42`). No CSP exists in `index.html` and no `network_security_config.xml` or pin set exists.

**Exploit scenario.** (1) The attacker controls Wi-Fi and, under the stated rooted-device/Burp model, installs/uses a trusted interception CA, or compromises the CDN/account. (2) The WebView requests the Eruda script at app start. (3) The response is replaced with attacker JavaScript. (4) The script runs as the Capacitor origin, reads/modifies clock history, schedules or cancels notifications, and can abuse any later-added plugin. (5) The code persists indirectly by altering stored application state or service-worker-controlled content.

**Impact.** Trusted-origin JavaScript execution and native-bridge abuse. This defeats the assumption that bundled application code defines the client behavior.

**Fix.** Remove Eruda from release entirely. Bundle any required library in the signed APK; self-host fonts or use system fonts. Move inline bootstrap code into bundled modules and add a CSP such as:

```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
               font-src 'self' data:; img-src 'self' data: blob:; connect-src 'self';
               object-src 'none'; base-uri 'none'; frame-src 'none'">
```

If developer-controlled remote endpoints are later introduced, use narrowly scoped Network Security Configuration/pinning with a rotation plan; never use pinning as a substitute for bundling executable app code.

**Verify.** Inspect built `dist/index.html` and APK assets for `http`, jsDelivr, Eruda, and Google Fonts strings; run Burp with a trusted CA and verify app startup makes no network request and injected script cannot load; use `chrome://inspect` only on a debug build and verify release WebView debugging is disabled.

### CC-03 — Backup-enabled plaintext WebView storage exposes user history

**Description and affected component.** The app stores clock names, timestamps, lap histories, status, and timer state as plaintext JSON in WebView `localStorage`, while the merged manifest explicitly enables backup. These labels can reveal habits, health routines, work activities, or schedules even though the app has no account credentials.

**Evidence.** `android/app/src/main/AndroidManifest.xml:4-10` sets `android:allowBackup="true"`; the merged release manifest retains it at lines 34-42. `storage.ts:55-76,82-103,109-170,213-230` reads/writes stopwatches, timers, intervals, and up to 500 history records. `types.ts:116-134` shows history includes clock names, start/completion time, elapsed time, laps, and rounds. No encryption layer or backup extraction rules exist.

**Exploit scenario.** (1) On an eligible older device or backup/restore path, an attacker obtains an app backup; under the stated rooted model, they can directly copy the WebView storage database. (2) They extract JSON values for the `chrono_*` keys. (3) They reconstruct the user's named activities and timeline. (4) They can modify the same state before restore or while rooted.

**Impact.** Disclosure/tampering of potentially private behavioral history; no password/token compromise was found.

**Fix.** If backup is unnecessary:

```xml
<application
    android:allowBackup="false"
    android:fullBackupContent="false"
    ... />
```

For Android 12+, also define restrictive `android:dataExtractionRules`. If names/history are classified as sensitive, move them behind a native storage plugin using Android Keystore-backed encryption; do not put encryption keys in JavaScript/localStorage. Provide a retention control shorter than the current 500-entry cap if users do not need long history.

**Verify.** On API 24/28 and a current API, create distinctive clock/history values, exercise `adb backup` where supported plus cloud/device-transfer test flows, and inspect rooted `/data/data/com.arafat.chrono/app_webview` storage. Verify backups omit the data and ciphertext/keys are handled as designed.

### CC-04 — User-controlled timer names are public on the lock screen

**Description and affected component.** Timer/stopwatch/interval names are user-controlled and are displayed in notifications configured as `VISIBILITY_PUBLIC`, exposing them on a locked device.

**Evidence.** `App.tsx:250-303` copies `sw.name`, `t.name`, and `inv.name` into notification summaries. `backgroundNotificationService.ts:299-309` forwards the names to the native plugin. `MainActivity.java:64-70` calls `setVisibility(Notification.VISIBILITY_PUBLIC)`. `capacitorNativeBridge.ts:103-124` also creates both channels with visibility `1` (public).

**Exploit scenario.** (1) A user names a timer after medication, a client, a confidential task, or a personal routine. (2) The phone is locked and unattended. (3) Any nearby person reads the full label and timing state without unlocking.

**Impact.** Privacy leakage and possible inference of health, employment, religious, or behavioral information.

**Fix.** Default to `VISIBILITY_PRIVATE` (`0`) and provide a redacted public version such as “Timer running.” Offer an explicit user setting before showing names on the lock screen.

```java
builder.setVisibility(Notification.VISIBILITY_PRIVATE);
Notification publicVersion = new Notification.Builder(context, CHANNEL_ID)
    .setContentTitle("ChronoCraft")
    .setContentText("Timer running")
    .setSmallIcon(appIcon)
    .build();
builder.setPublicVersion(publicVersion);
```

**Verify.** Create a uniquely sensitive label, lock the device under each Android lock-screen notification privacy setting, and confirm the label is redacted until unlock. Inspect channel settings after upgrade because channel properties persist across app updates.

### CC-05 — Local-notification PendingIntents are unnecessarily mutable

**Description and affected component.** The locked `@capacitor/local-notifications` 6.1.3 implementation adds `FLAG_MUTABLE` to content, dismiss, and alarm PendingIntents on Android 12+, including flows that do not use `RemoteInput`. The app uses only `OPEN_APP` and timer delivery, so most of these tokens need no mutability.

**Evidence.** `package.json:19` declares the plugin and `package-lock.json:385-392` resolves 6.1.3. Generated dependency source `node_modules/@capacitor/local-notifications/android/src/main/java/com/capacitorjs/plugins/localnotifications/LocalNotificationManager.java:246-255` makes the content intent mutable; lines 283-295 do the same for dismiss; lines 323-333 do it for scheduled alarms. The app schedules notifications at `capacitorNativeBridge.ts:204-234,258-274` and defines no input action.

**Exploit scenario.** (1) A malicious app obtains a PendingIntent handle through a privileged notification-listener/helper path or another leak. (2) Because the token is mutable, it supplies fill-in fields/extras before sending it. (3) The victim app is launched or its in-app notification action data is modified. Explicit intent targets reduce the blast radius, and no token-leak path was found in app code, so this is defense-in-depth rather than a demonstrated zero-click takeover.

**Impact.** Avoidable intent-tampering surface and future risk if new actions begin trusting notification extras.

**Fix.** Upgrade the notification plugin to a version that uses immutable tokens by default. If maintaining a fork/custom implementation, use `FLAG_IMMUTABLE | FLAG_UPDATE_CURRENT` or `FLAG_CANCEL_CURRENT` for content, dismiss, and alarm PendingIntents; reserve `FLAG_MUTABLE` only for an action that truly requires `RemoteInput`. Treat all received extras as untrusted.

**Verify.** Decompile the rebuilt APK with jadx and search `PendingIntent.get*` call sites. On API 31+, attempt to send fill-in extras through an obtained token and confirm they are ignored/rejected; regression-test notification open, dismiss, schedule, and cancel behavior.

### CC-06 — Lockfile contains additional vulnerable runtime/build dependencies

**Description and affected component.** Current `npm audit` reports 10 vulnerable package nodes in total (including CC-01): 3 critical, 4 high, and 3 moderate. Most non-Capacitor issues are build-time or currently unreachable because no Express server is present, but they remain supply-chain/CI exposure and will become runtime issues if the listed server dependencies are used.

**Evidence.** Exact vulnerable versions include `@xmldom/xmldom 0.9.11` (`package-lock.json:2020-2028`), `brace-expansion 2.1.4` (`2251-2259`), `express 4.22.2` (`2847-2859`), `proxy-addr 2.0.7` (`4376-4387`), `qs 6.15.3` (`4407-4418`), `source-map-js 1.2.1` (`4800-4807`), and `tar 6.2.1` (`4885-4897`). Representative current identifiers: CVE-2026-90711 / GHSA-jqcg-44mw-7w3h (`proxy-addr`), CVE-2026-93749 / GHSA-68fv-2mgg-jv7q (`source-map-js`), CVE-2026-102278 / GHSA-qhr7-859c-m2p7 and CVE-2026-102276 / GHSA-6j4f-fj2g-mc7p (`brace-expansion`), CVE-2026-83616 / GHSA-c7q8-3ch8-vqpv (`xmldom`), plus the additional GHSA IDs emitted by the audit for `tar`, `qs`, and `xmldom`.

**Exploit scenario.** Current app: an attacker would need influence over build inputs (archives, XML, glob/source-map data) to crash or overwrite files in CI; no such untrusted-input pipeline was found. Future Express backend: using `trust proxy` with the vulnerable IPv4-mapped IPv6 form can let a remote client spoof `req.ip`, defeating IP allowlists/rate limiting. The app does not import Express today, so that runtime scenario is not claimed as currently reachable.

**Impact.** CI/build-agent compromise or denial of service under the relevant input preconditions; latent server-side IP spoofing if unused server packages are activated.

**Fix.** Remove unused `express`, `dotenv`, and `@google/genai` dependencies from the mobile package. Update direct dependencies, regenerate the lockfile, and require a zero-known-vulnerability release gate. At minimum resolve `proxy-addr >=2.0.8`, `source-map-js >=1.2.2`, `brace-expansion >=2.1.7`, `qs >=6.16.0`, patched `xmldom`, and a `tar` release outside all reported ranges. Review breaking changes instead of applying `npm audit fix --force` blindly.

**Verify.** Run `npm ci` followed by `npm audit --omit=dev --audit-level=moderate` for shipped dependencies and a separate full `npm audit` for the build toolchain. Generate an SBOM and confirm every advisory has either a patched version or a documented, time-bounded reachability exception.

### CC-07 — Release hardening disabled and debugging console shipped

**Description and affected component.** Android release builds explicitly disable R8/ProGuard minification, and production HTML ships Eruda, a mobile developer console. Vite minifies JavaScript, but that is not equivalent to Android bytecode/resource shrinking and does not remove debug tooling.

**Evidence.** `android/app/build.gradle:19-23` has `release { minifyEnabled false }`. `index.html:22-23` initializes Eruda unconditionally. `android/app/proguard-rules.pro` contains no app-specific rules. `npm run build` confirmed the debug script remains in production HTML.

**Exploit scenario.** (1) The attacker decompiles the APK with jadx/apktool and obtains unobfuscated Java/plugin names and bridge structure. (2) On-device, the bundled console simplifies inspection and state manipulation. (3) Repackaging/hooking is faster, especially when combined with the absence of signature or runtime integrity checks.

**Impact.** Reduced effort for reverse engineering and tampering. This is not a substitute for server-side controls, and the app currently has no license/paywall/auth secret to protect.

**Fix.** Remove Eruda from production and enable release shrinking after testing:

```groovy
release {
    minifyEnabled true
    shrinkResources true
    proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
}
```

Keep only the minimum required Capacitor/plugin rules, set `android.webContentsDebuggingEnabled=false` explicitly in release configuration, and ensure production logging is disabled.

**Verify.** Build a signed release; confirm `adb shell dumpsys package com.arafat.chrono` does not show debuggable, `chrome://inspect` cannot attach, Eruda is absent, and jadx shows expected obfuscation without breaking Capacitor plugin registration.

### CC-08 — FileProvider exposes the entire external-storage tree to any future grant

**Description and affected component.** The FileProvider is not exported, which is good, but its paths file maps `external-path` with `path="."`, authorizing URI generation for the entire legacy external-storage root. Any current or future code that grants one of those URIs can expose far more than the intended export file.

**Evidence.** `android/app/src/main/res/xml/file_paths.xml:1-5` contains `<external-path name="my_images" path="." />`; `AndroidManifest.xml:27-35` sets `grantUriPermissions="true"`. The merged provider remains non-exported. No current application call to `FileProvider.getUriForFile` was found, so exploitation is dormant today.

**Exploit scenario.** (1) A later share/import feature generates a content URI from attacker-influenced or overbroad file input. (2) Because the configured root is all external storage, the provider accepts unrelated files under that tree. (3) The receiving/malicious app reads the mistakenly granted file.

**Impact.** Future accidental disclosure of arbitrary external-storage files accessible to the app. Current direct provider access from another app is blocked.

**Fix.** Remove the unused provider or restrict it to a dedicated directory:

```xml
<paths xmlns:android="http://schemas.android.com/apk/res/android">
    <cache-path name="exports" path="exports/" />
</paths>
```

Canonicalize paths, generate server/app-owned filenames, and grant read-only access to an explicit package for the shortest possible operation.

**Verify.** From a test app, query/open the provider directly (must fail), then test granted access to `cache/exports/test.csv` (must succeed) and attempts outside `exports/` (must throw `IllegalArgumentException`/permission denial).

### CC-09 — Full clock/lap history can be placed on the global clipboard

**Description and affected component.** Multiple UI actions copy named timers, precise timestamps, durations, and laps to the system clipboard. On older Android releases and on devices with privileged/keyboard/accessibility apps, clipboard contents can be observed. The user initiates the copy, lowering severity.

**Evidence.** `HistoryModal.tsx:148-184` builds and copies the history log. `StopwatchCard.tsx:221-231`, `FocusModal.tsx:104-113`, and `LapAnalyticsModal.tsx:85-117` copy lap details. No warning, sensitivity label, or timed clearing exists.

**Exploit scenario.** (1) The user copies a history/lap report. (2) A malicious keyboard, accessibility service, notification-listener-adjacent tool, or older-Android background app reads the clipboard before it changes. (3) The attacker learns names and behavioral timing.

**Impact.** User-triggered privacy leakage; no tokens/passwords are copied.

**Fix.** Prefer direct file export/share with explicit recipient selection for large histories. Warn that copy places data on the system clipboard, minimize copied fields, and clear it after a short user-visible timeout where platform behavior permits. On native Android 13+, use a native clipboard API and `ClipDescription.EXTRA_IS_SENSITIVE=true` to suppress previews.

**Verify.** Exercise each copy action on API 24/28/33+ while a controlled observer app/keyboard monitors clipboard access. Confirm warnings, preview suppression, and clearing behavior.

### CC-10 — External requests contradict the stated offline/privacy posture

**Description and affected component.** Store metadata claims “100% offline & local data storage — zero trackers,” but the first-party HTML makes requests to Google Fonts and jsDelivr. Even absent cookies, those providers receive network metadata such as IP address, time, TLS/client characteristics, and user agent.

**Evidence.** `metadata/com.arafat.chrono.yml:18-20` makes the privacy claim. `index.html:12-14` contacts `fonts.googleapis.com`/`fonts.gstatic.com`; line 22 contacts `cdn.jsdelivr.net`. The production bundle preserved these URLs. The manifest requests `INTERNET` at `AndroidManifest.xml:40`.

**Exploit scenario.** (1) The user opens the purportedly offline app. (2) It contacts third parties. (3) Network observers/providers correlate the request with device/network metadata; on captive or blocked networks the assets may fail or delay.

**Impact.** Privacy-policy/store-listing mismatch and unnecessary metadata disclosure; also creates the executable-code risk in CC-02.

**Fix.** Bundle fonts and all JavaScript in the APK, remove unnecessary `INTERNET` permission if no network feature remains, and update disclosures if any remote traffic is intentionally retained.

**Verify.** Start the app from a clean install behind Burp/mitmproxy and with DNS logging. The expected result for an offline app is zero outbound connections. Repeat after airplane-mode start to ensure identical functionality.

### CC-11 — No runtime integrity, signature, root, hook, or debugger defenses

**Description and affected component.** Searches found no Play Integrity request/verification, signing-certificate check, root/emulator detection, Frida/Xposed/debugger detection, or anti-tamper code. Under the stated threat model, repackaging and hooks are therefore expected to work. This is informational because ChronoCraft currently has no authentication, payment, premium entitlement, or anti-fraud decision to protect, and resilience controls are bypassable defense-in-depth.

**Evidence.** No matching implementation exists in `src/` or `android/app/src/main/`; release minification is disabled at `android/app/build.gradle:21`. The CI release signs artifacts but performs no post-signature or integrity test (`.github/workflows/build-release.yml:61-73`).

**Exploit scenario.** (1) Attacker decompiles and patches JavaScript/Java. (2) They re-sign and install the modified APK or hook functions with Frida. (3) Timer behavior, notifications, and local history can be altered without detection. They do not thereby gain server privilege because no server trust decision was found.

**Impact.** Easy repackaging/hooking and brand impersonation; limited direct security impact in the current offline utility.

**Fix.** First ensure no security decision relies on the client. If future backend abuse, purchases, or regulated data justify it, verify Play Integrity verdicts on the server with nonce/replay protection, bind high-risk actions to authenticated server state, and optionally add certificate/signature self-checks and telemetry. Do not block rooted users for a basic offline timer without a documented need.

**Verify.** Repackage/re-sign the APK, hook native bridge methods with Frida, and test on rooted/emulated devices. If resilience is introduced, verify server rejection of stale/forged integrity verdicts and document bypass expectations.

## 4. Checklist results (all 60 items)

Status applies only to the provided material. **Pass** means the relevant client-side implementation was present and checked or the feature was conclusively absent from the complete client source. **Not Verifiable** identifies the missing artifact/test needed.

1. **Pass — Exported components.** Merged release manifest inspected: only launcher `MainActivity` is unprotected/exported as required; ProfileInstaller receiver is protected by `android.permission.DUMP`; providers are non-exported; notification receivers without filters default non-exported.
2. **Pass — Intent redirection/spoofing.** No implicit outbound intent, redirector, or handling of untrusted intent extras/data exists in app code; dynamic intent fuzzing remains NOT-RUN.
3. **Pass — Deep/App Links.** No VIEW/BROWSABLE deep-link or App Link filter exists in the merged manifest, so there is no deep-link parameter/auth surface in this version.
4. **Fail — Debug/backup/cleartext flags.** `allowBackup=true` is explicit (CC-03). Release debuggable defaults false and cleartext defaults false at target 36, but the checklist item fails on backup alone.
5. **Fail — PendingIntent/task/tapjacking.** Dependency uses mutable PendingIntents (CC-05); launcher uses `singleTask`. No sensitive UI needs `FLAG_SECURE`, but tapjacking/task-hijack runtime tests were NOT-RUN.
6. **Pass — Permissions.** INTERNET, vibration, notifications, exact alarms, wake lock, and boot restore map to implemented timer/notification behavior; no camera, microphone, location, contacts, broad storage, or unprotected custom permission exists. Declaring both exact-alarm permissions is redundant/policy-sensitive and should be reduced to one, but it does not grant another app access to protected data.
7. **Pass — Platform SDK levels.** minSdk 24 and target/compileSdk 36 were verified; target SDK is current for this audit date.
8. **Fail — Plaintext local data.** Timer names/state/history are plaintext WebView `localStorage` (CC-03). No passwords/tokens/keys are present.
9. **Not Verifiable — Token storage.** No authentication/token feature exists in client source; backend/auth material is required to assess any server-issued token storage.
10. **Pass — Broken crypto.** No application cryptography, ECB, static key/IV, MD5/SHA-1, DES, or security use of `Math.random` was found. `Math.random` is used only for IDs/notification IDs, not secrets.
11. **Not Verifiable — Password hashing.** No password handling or backend source/configuration was supplied.
12. **Fail — Clipboard/screenshots/backups.** Full history/laps can enter clipboard (CC-09), backups are enabled (CC-03), and no `FLAG_SECURE` exists. The app has no password/payment screen, but clock labels can be private.
13. **Fail — FileProvider.** Provider is non-exported, but maps all external storage via `<external-path path=".">` (CC-08).
14. **Not Verifiable — File uploads.** No client upload feature was found; backend/API and storage implementation are absent.
15. **Pass — Cleartext/network configuration.** Release config uses `androidScheme: https`, dev cleartext mode is a compile-time false branch, target 36 blocks cleartext by default, and no `http://` production endpoint is present. Dynamic MITM confirmation is NOT-RUN.
16. **Fail — Certificate pinning.** No pinning exists, while security-sensitive remote JavaScript is loaded (CC-02). The correct primary fix is to remove remote executable code.
17. **Pass — TrustManager/HostnameVerifier.** Project and included Capacitor/plugin Java sources contain no trust-all manager, permissive verifier, `onReceivedSslError(...proceed())`, or disabled TLS validation.
18. **Pass — Sensitive URLs/TLS.** No credentials, PII, or tokens are placed in URLs; network references are HTTPS. Remote server cipher/TLS policy was not assessed because those third-party endpoints are not app-controlled.
19. **Not Verifiable — Backend CORS.** No backend deployment/configuration or API base URL was provided.
20. **Not Verifiable — JWT.** No JWT/auth client code exists; backend token issuer/verifier is unavailable.
21. **Not Verifiable — MFA.** No account/authentication feature is represented; product/backend requirements are unavailable.
22. **Pass — Biometric CryptoObject.** No biometric authentication feature or API is present in the complete client source.
23. **Not Verifiable — Session lifetime/rotation.** No session implementation or backend was provided.
24. **Pass — OAuth/OIDC.** No OAuth/OIDC flow, redirect filter, or custom-scheme callback is implemented. `.env.example` comments are template text, not an active flow.
25. **Not Verifiable — Default/test credentials/backdoors.** Current client and git-history pattern scans found no real credentials/backdoor; backend, deployed configuration, and full secret-scanner coverage are missing.
26. **Not Verifiable — Auth/OTP rate limits.** Requires backend endpoints, test accounts, and rate-limit configuration.
27. **Not Verifiable — IDOR/BOLA.** No API/backend or object endpoints were supplied.
28. **Not Verifiable — Function-level authorization.** No API/backend/admin surface was supplied.
29. **Pass — Client-only roles/premium flags.** No role, admin, premium, license, entitlement, or authorization decision exists in the client source.
30. **Not Verifiable — Row/tenant isolation.** Database/backend schema and authorization policies are absent.
31. **Not Verifiable — Mass assignment/excessive responses.** API schemas and server code are absent.
32. **Not Verifiable — Endpoint rate limiting/abuse.** API inventory and gateway/server configuration are absent.
33. **Not Verifiable — Webhook signatures.** No webhook receiver/backend is provided.
34. **Not Verifiable — SSRF.** No backend URL-fetch endpoint is provided. The client does ship vulnerable Capacitor proxy code (CC-01), but that is separately reported.
35. **Not Verifiable — Purchase receipts.** No purchase client code exists; store/backend receipts and product requirements are unavailable.
36. **Not Verifiable — Play Integrity.** No backend trust decision exists in provided material. Client contains no Integrity API; CC-11 explains why that is informational for this offline utility.
37. **Not Verifiable — SQL injection.** No SQLite/Room/ContentProvider query exists in the client; backend query code is absent.
38. **Not Verifiable — XSS.** Client JSX uses React escaping and searches found no `dangerouslySetInnerHTML`, `innerHTML`, `eval`, or user URL loading; backend-rendered content cannot be assessed. Remote trusted-origin script risk is CC-02.
39. **Pass — Command/path/deserialization.** No runtime command execution, unsafe Java serialization, XML parser, or attacker-controlled filesystem path exists. `JSON.parse` reads app-local state and is not used for polymorphic/code deserialization.
40. **Pass — External input validation.** No deep link, QR, NFC, push-payload, clipboard-read, or intent-extra input surface exists. Form data is rendered through React; rooted local-storage tampering can corrupt local state but crosses no server trust boundary.
41. **Not Verifiable — CSRF.** No cookie-authenticated API/WebView backend was supplied.
42. **Fail — JavaScript bridge with untrusted content.** Capacitor requires JavaScript and exposes a bridge; the page loads remote Eruda code (CC-02).
43. **Not Verifiable — WebView file/universal access/Safe Browsing runtime state.** Capacitor source shows mixed content defaults false, but no release APK/device settings dump was available to verify every final WebSettings value; full APK build did not complete.
44. **Fail — Remote/user-controlled URLs/Safe Browsing.** Remote executable/code resources load without an app allowlist/CSP, and no explicit Safe Browsing policy is configured (CC-02).
45. **Pass — Auth tokens in WebView.** No auth tokens exist or are passed to JavaScript/URLs. Local clock data is exposed to same-origin remote code as covered by CC-02/CC-03.
46. **Pass — Hardcoded secrets.** Current source/resources/assets and targeted git-history regex scans found no API secret, private key, signing key, password, or token. `.env.example` contains placeholders only.
47. **Pass — Third-party key restrictions.** No Google Maps/Firebase/other app API key is present. Restriction at provider consoles cannot be assessed because no keys/projects were supplied.
48. **Pass — Committed key/config files.** Git tracks no `.env`, `google-services.json`, JKS/keystore, PEM/private-key, or `local.properties`; `.gitignore:7-18` excludes them.
49. **Fail — R8/debug release code.** `minifyEnabled false` and Eruda is shipped in production (CC-07).
50. **Pass — Source maps/staging endpoints.** Production build emitted no `.map` files/sourceMappingURL and searches found no staging/test release URL. The `localhost` URL is behind `IS_DEV_MODE=false` in source config.
51. **Fail — Dynamic code loading.** Release executes unpinned remote JavaScript from jsDelivr without integrity verification (CC-02).
52. **Fail — Root/emulator/hook/debugger detection.** None exists (CC-11). This is defense-in-depth and not a substitute for server controls.
53. **Fail — App signature/integrity checks.** No runtime signature or integrity verification exists; repackaging is undetected (CC-11).
54. **Pass — Security-critical client-only logic.** No license, paywall, authentication, role, purchase, or anti-fraud logic exists. Timer correctness is local product functionality, not a security control.
55. **Fail — Vulnerable dependencies.** `npm audit` found 10 vulnerable package nodes, including runtime CVE-2026-103922 and multiple build/server advisories (CC-01, CC-06).
56. **Not Verifiable — Firebase/cloud rules.** No Firebase config or project identifiers are present; deployed cloud resources were not supplied.
57. **Pass — Analytics/ads/crash SDKs.** No analytics, ad, or crash-reporting SDK/API call was found. Third-party resource privacy leakage is covered separately in CC-10.
58. **Pass — Sensitive logging.** Client logs only fixed diagnostic text and caught error objects; no tokens, credentials, timer names, history records, or PII are logged in reviewed code. Backend logs are unavailable.
59. **Fail — Data minimization/consent.** The advertised offline app contacts Google Fonts/jsDelivr without an in-app disclosure/consent path (CC-10); request metadata is unnecessary for timer operation.
60. **Fail — Lock-screen notifications.** User-controlled names are deliberately configured `VISIBILITY_PUBLIC` (CC-04).

## 5. Chained attack analysis

The highest-risk chain does not require breaking Android sandboxing:

1. Release HTML requests unversioned Eruda JavaScript from jsDelivr.
2. Under the specified rooted/MITM model, the attacker intercepts that TLS request, or a CDN/package compromise supplies modified JavaScript.
3. The script executes inside the app's Capacitor origin because there is no CSP/SRI isolation.
4. It reads/modifies plaintext WebView state, calls registered notification/haptic/chronometer plugins, and can exploit any newly added plugin authority.
5. Backup and public notification behavior provide additional disclosure channels, while no integrity/signature control signals the modification.

Separately, a future rich-link feature can make CVE-2026-103922 directly exploitable by a clicked proxy-path URL. Fixing only certificate pinning, R8, or root detection does not break the core chain; remote executable code and the vulnerable Capacitor runtime must be removed/upgraded.

## 6. Remediation roadmap

### Fix now (before the next release)

1. Upgrade Capacitor Android/Core/CLI to patched aligned versions (`>=6.2.2`) and verify the CVE regression.
2. Delete release Eruda/CDN loading; bundle fonts/assets; add CSP; remove `INTERNET` if the app remains offline.
3. Set `allowBackup=false` or explicit extraction rules, and document the sensitivity/retention policy for named history.
4. Change all lock-screen content to private/redacted; account for persistent notification-channel settings during upgrade.
5. Patch/remove vulnerable dependencies, regenerate `package-lock.json`, and fail releases on unapproved critical/high advisories.

### This sprint

1. Upgrade/fix LocalNotifications PendingIntent mutability and add API 31+ regression tests.
2. Enable R8/resource shrinking, explicitly disable WebView debugging/logging in release, and add tested keep rules.
3. Remove or narrow FileProvider to a dedicated `cache/exports/` directory.
4. Reduce exact-alarm declarations to the single policy-compliant permission and add a graceful non-exact fallback where possible.
5. Fix existing TypeScript errors so type-checking can become a mandatory CI gate.

### Backlog / risk-based

1. Improve clipboard privacy UX/native sensitive labeling.
2. Add optional integrity/anti-hook controls only if future backend, entitlement, or abuse threats justify their accessibility/privacy cost.
3. Perform a signed-APK dynamic assessment on API 24, 28, 31, and current Android: MobSF, jadx/apktool, Burp, Frida, tapjacking, backup/restore, notification privacy, and malicious companion-app tests.
4. If any backend exists, conduct a separate API audit covering items 11, 14, 19-21, 23, 25-36, 37-38, 41, 56, and backend portions of 57-59.

## 7. Recommended CI tooling and automation

- **Dependency/SBOM:** `npm ci`; `npm audit --omit=dev --audit-level=moderate`; full dev audit; Dependabot/Renovate; CycloneDX SBOM; OSV-Scanner/Trivy/Grype. Record reachability exceptions with owner and expiry.
- **Android static analysis:** Android Lint release task, MobSF static scan of the signed APK, jadx/apktool string/config checks, and `apkanalyzer manifest print` assertions for `debuggable`, backup, exported components, permissions, and network config.
- **SAST:** Semgrep rules for remote `<script>`, missing CSP, WebView unsafe settings, mutable PendingIntents, exported components, implicit intents, FileProvider root paths, clipboard use, notification visibility, logs, cryptography, and hardcoded endpoints/secrets.
- **Secrets:** Gitleaks plus GitHub secret scanning on the current tree and full history; block JKS/keystore, `.env`, service-account JSON, bearer tokens, and private keys.
- **Web bundle assertions:** fail if release assets contain `eruda`, `http://`, unapproved `https://`, `sourceMappingURL`, localhost/staging endpoints, inline remote script tags, or unexpected source maps.
- **Dynamic security regression:** emulator matrix with a Burp CA; verify zero network for offline mode, TLS failure behavior if networking is added, WebView bridge isolation, clipboard/lock-screen behavior, tapjacking overlays, backup extraction, and malicious explicit/implicit intents.
- **Runtime instrumentation:** targeted Frida/Objection tests for WebView URL loads, bridge/plugin calls, SSL hooks, notification inputs, file-provider grants, and any future biometric/integrity logic.
- **Backend pipeline (if applicable):** OpenAPI-driven negative authorization tests, BOLA/BFLA fixtures, rate-limit/OTP tests, CORS/CSRF tests, Semgrep/CodeQL, IaC/cloud-rule scanning, and server-side Play Integrity/replay tests.
- **Release provenance:** reproducible build where practical, pinned GitHub Actions by commit SHA, signed artifact verification, SBOM/provenance attestation, and a post-build check that the distributed APK hash/signing certificate matches the reviewed artifact.

## 8. Evidence index and limitations

Primary local evidence: `android/app/src/main/AndroidManifest.xml`, generated merged release manifest under `android/app/build/intermediates/merged_manifest/release/processReleaseMainManifest/AndroidManifest.xml`, `android/variables.gradle`, `android/app/build.gradle`, `android/app/src/main/java/com/arafat/chrono/MainActivity.java`, `android/app/src/main/res/xml/file_paths.xml`, `capacitor.config.ts`, `index.html`, `src/utils/storage.ts`, `src/utils/capacitorNativeBridge.ts`, `src/utils/backgroundNotificationService.ts`, notification/clipboard UI components, `package.json`, `package-lock.json`, and `.github/workflows/*.yml`.

No claim in this report establishes backend security, production cloud configuration, installed-device behavior, or the contents/signature of a published APK. Those remain unverified until the missing artifacts and dynamic test environment are supplied.

## 9. Remediation validation addendum (2026-10-13)

The following items were remediated after the audit snapshot above:

- **CC-01 / CVE-2026-103922:** `@capacitor/android` and `@capacitor/core` are now pinned to `6.2.2`. The audit-clean Capacitor CLI `8.4.3` is pinned for build tooling and was verified to sync the 6.2.2 Android runtime successfully.
- **CC-06 / vulnerable npm graph:** unused `@google/genai`, `express`, `dotenv`, and `@types/express` packages were removed. The lockfile now resolves patched `tar 7.5.21`, `@xmldom/xmldom 0.9.12`, `brace-expansion 2.1.7`, and `source-map-js 1.2.2`. Both full and production-only npm audits reported zero vulnerabilities.
- **Release gates:** the release job now depends on the reusable security workflow. That workflow runs a clean `npm ci`, npm audit, Gitleaks full-history secret scanning, TypeScript typechecking, the production web build, Android `lintRelease`, and CodeQL `security-extended` analysis for JavaScript/TypeScript and Java/Kotlin. Dependabot monitors npm, Gradle, and GitHub Actions dependencies.
- **Build reproducibility:** CI now uses Node 22, JDK 21, `npm ci`, and the checked-in Gradle wrapper. Machine-specific Termux AAPT2 overrides were removed from `android/gradle.properties`.
- **Validation:** clean npm install, full npm audit, production-only npm audit, TypeScript typecheck, Vite production build, Capacitor Android sync, Android `lintRelease`, `assembleDebug`, and `assembleRelease` all passed. Android lint completed with 0 errors and 21 warnings.

Local build artifacts:

- Installable debug APK: `android/app/build/outputs/apk/debug/app-debug.apk`, SHA-256 `26AC9D5DDD7FB4D244F344A32DA652930FA8E79BFA2126EED1DCF03DC9A254BD`; verified with APK Signature Scheme v2 using the Android debug certificate.
- Unsigned release APK: `android/app/build/outputs/apk/release/ChronoCraft-v2.0.1.apk`, SHA-256 `470485679B753680A2D4EB433B4D41EC02663D3CAAD0E83691B64F032E1C34E3`. It must not be redistributed until signed with the project release key. The tag-triggered release workflow performs that signing using repository secrets.

This addendum does not mark unrelated findings in the original report as fixed.


