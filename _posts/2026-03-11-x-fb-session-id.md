---
title: Reversing Facebook header `x-fb-session-id`
published: true
---

## Table of contents

* toc placeholder
{:toc}

## Introduction

Facebook's custom `x-fb-*` headers show up in a lot of scripts and bug reports (for example [link1](https://github.com/mautrix/facebook/issues/195#issuecomment-999148399), [link2](https://github.com/ibrahimbalic/facebook/blob/4275e01f43dae2aaea8d6da98c53925fd5c5acf5/Facebook_Encrypted_Password.php#L124), [link3](https://rentry.co/LAST_METHOD_77)) but there is barely any info on what they contain. This post reverses one of them (`x-fb-session-id`) with [Ghidra](https://github.com/NationalSecurityAgency/ghidra) and [Frida](https://github.com/frida/frida).

We use an older version of the app ([v518.0.0.63.86](https://www.apkmirror.com/apk/facebook-2/facebook/facebook-518-0-0-63-86-release/)) since the links above are fairly old and the headers might change in newer releases.

## Executive summary

The `x-fb-session-id` HTTP header is generated in the native library `libcoldstart.so`. The format is:

```
x-fb-session-id: nid=<12-char string>;tid=<int>;nc=<int>;fc=<int>;bc=<int>
```

All five fields were located through static analysis in Ghidra and dynamic instrumentation with Frida. The generation logic of `nid` and `tid` is fully understood. `nc`, `fc` and `bc` were located in the struct but their update logic was not found.

| Field | Example | Description |
|-------|---------|---------------|
| `nid` | `oEGVIZbYHscp` | 12-char random session identifier, generated from `/dev/urandom` at startup |
| `tid` | `1`, `2`, `3`, … | Per-request transaction counter, atomically incremented |
| `nc`  | `0` | Likely set somewhere else (e.g. in the Java layer), 0 in most cases |
| `fc`  | `0` | Likely set somewhere else (e.g. in the Java layer), 0 in most cases |
| `bc`  | `0` | Likely set somewhere else (e.g. in the Java layer), 0 in most cases |

Older versions of the header also had `pid` and `cid` fields but Facebook removed them.

## Target

| | |
|---|---|
| **APK** | Facebook Android APK v518.0.0.63.86 (`com.facebook.katana`) |
| **APK SHA256 hash** | `fe3d3e1c2daf06ab276217a7a59422fb32d55ca22bcdf80cba941edc778f1384` |
| **Library** | `libcoldstart.so` |
| **Library SHA256 hash** | `3e91a9316a12c0f24be4ca1bd3f0d5478def5c4f4775cce939ac935641925daa` |
| **Device** | Samsung Galaxy S10e (SM-G970F/DS) |

## Tools

All tools were installed and run on Fedora 43 Linux (kernel 6.18.13, x86_64).

| Tool | Version | Notes |
|------|---------|-------|
| `jadx` | `dev` (commit `7b3563f`) | Build from source: [gemesa/malware-analysis-toolkit](https://github.com/gemesa/malware-analysis-toolkit/?tab=readme-ov-file#jadx) |
| Ghidra | `12.1 DEV` (commit `fc4ea10`) | Build from source: [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra) |
| Android Studio | `Panda 2 2025.3.2` | Install guide: [gemesa/malware-analysis-toolkit](https://github.com/gemesa/malware-analysis-toolkit/?tab=readme-ov-file#android-studio) (provides `emulator`, `avdmanager`, etc.) |
| Frida | `16.7.19` | [github.com/frida/frida/releases](https://github.com/frida/frida/releases) |
| adb | `1.0.41 (35.0.2)` | `sudo dnf install android-tools` |
| `apktool` | `3.0.1` | [github.com/iBotPeaches/Apktool/releases](https://github.com/iBotPeaches/Apktool/releases) |
| `objection` | `1.12.3` | `pip install objection` |
| gmsaas | `1.15.0` | `pip install gmsaas` ([docs.genymotion.com/gmsaas](https://docs.genymotion.com/gmsaas/01_Get_Started/)) |

## Setup

### APK

Downloaded from APKMirror:

```
https://www.apkmirror.com/apk/facebook-2/facebook/facebook-518-0-0-63-86-release/
```

Two variants were downloaded and used:

| Variant | ID | SHA-256 |
|---------|----|---------|
| `arm64-v8a` | `462626377` | `fe3d3e1c2daf06ab276217a7a59422fb32d55ca22bcdf80cba941edc778f1384` |
| `x86_64` | `462626544` | `52e786ab65323e118366667f215d201cd2e5c55485e39d3d6fbcb11acc577f6b` |

The `arm64-v8a` variant was used for all analysis on the physical device. The `x86_64` variant was used in Attempt 1 (AVD emulator).

### Approach and device selection

Attempt 1: x86_64 Android emulator

The APK targets a wide API range: Min API 28 (Android 9.0 Pie), Target API 35 (Android 15). The emulator was created with `android-28` (`google_apis`) to match the minimum supported version.

The first attempt used an AVD with `google_apis` (rootable, not `google_apis_playstore`) targeting the x86_64 APK variant (`462626544`). Root is required to run `frida-server`.

```bash
sdkmanager "system-images;android-28;google_apis;x86_64"
avdmanager create avd -n fb_re -k "system-images;android-28;google_apis;x86_64" --force
emulator -avd fb_re -writable-system -no-snapshot
adb root
adb remount
adb install com.facebook.katana_518.0.0.63.86-462626544_minAPI28\(x86_64\)\(nodpi\)_apkmirror.com.apk
adb shell pm list packages | grep facebook
adb shell am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -n com.facebook.katana/com.facebook.katana.LoginActivity
```

Facebook seemed to detect the emulator and rejected login:

> Unable to log in. An unexpected error occurred. Please try logging in again.

Attempt 2: Genymotion SaaS virtual devices

```bash
pip install gmsaas
export GENYMOTION_API_TOKEN=...
gmsaas config set android-sdk-path ~/Android/Sdk
gmsaas recipes list
# Android 9.0 - Genymotion Phone = aaeecf3e-f4e1-4439-9876-be2117e0ad09
gmsaas instances start aaeecf3e-f4e1-4439-9876-be2117e0ad09 "fb-re"
gmsaas instances list
gmsaas instances adbconnect <uuid>
adb devices
# when done:
gmsaas instances stop <uuid>
```

Facebook also seemed to detect Genymotion and crashed repeatedly with `abortWithReason_JNI_OnLoad` in `libbreakpad.so`, triggered from `libcoldstart.so` and `libdexload.so`. The app crashed on every launch without reaching the login screen. Logcat confirmed repeated `F DEBUG` fatal signals across multiple process restarts until the package got killed.

The relevant portion of the first crash:

```
F DEBUG   : pid: 4204, tid: 4553, name: BgHandler  >>> com.facebook.katana <<<
F DEBUG   :     #00 pc 000000000007d794  /data/data/com.facebook.katana/lib-compressed/libdexload.so
F DEBUG   :     #01 pc 000000000001e3ec  /data/app/com.facebook.katana-.../lib/arm64/libbreakpad.so (abortWithReason_JNI_OnLoad+68)
F DEBUG   :     #02 pc 0000000000021c38  /data/app/com.facebook.katana-.../lib/arm64/libc++_shared.so
F DEBUG   :     #03 pc 000000000005ef54  /data/app/com.facebook.katana-.../lib/arm64/libc++_shared.so
F DEBUG   :     #04 pc 0000000000029030  /data/app/com.facebook.katana-.../lib/arm64/libc++_shared.so
F DEBUG   :     #05 pc 000000000002642c  /data/app/com.facebook.katana-.../lib/arm64/libc++_shared.so
F DEBUG   :     #06 pc 000000000058daa8  /data/data/com.facebook.katana/lib-compressed/libcoldstart.so
F DEBUG   :     #07 pc 00000000006eace0  /data/data/com.facebook.katana/lib-compressed/libcoldstart.so
F DEBUG   :     #08 pc 0000000000004830  /data/data/com.facebook.katana/lib-compressed/libgraphservice-jni-loggedoutservice.so
F DEBUG   :     #16 pc 00000000007324e8  ...zip (com.facebook.graphservice.loggedoutservice.LoggedOutGraphQLServiceJNI.handleQuery+16)
F DEBUG   :     #22 pc 00000000007326ce  ...zip (X.AR5.run+70)
...
W ActivityManager: Process com.facebook.katana has crashed too many times: killing!
```

The crash originates in `libdexload.so` (frame #00), called from `libcoldstart.so` (frames #06-#07) and is caught by `libbreakpad.so`'s `abortWithReason_JNI_OnLoad`, suggesting a possible intentional abort triggered by an integrity check. The abort propagates through `libc++_shared.so` and terminates the process.

Attempt 3: `frida-gadget` via `objection` (arm64 APK)

Tried patching the APK with `frida-gadget` to skip needing a rooted device:

```bash
pip install objection
# install a stable apktool (objection requires valid semver)
wget https://github.com/iBotPeaches/Apktool/releases/download/v3.0.1/apktool_3.0.1.jar
sudo cp apktool_3.0.1.jar /usr/local/bin/apktool.jar
objection patchapk -s com.facebook.katana_518.0.0.63.86-462626377_minAPI28\(arm64-v8a\)\(360,400,420,480,560,640dpi\)_apkmirror.com.apk
```

Output:

```
$ objection patchapk -s com.facebook.katana_518.0.0.63.86-462626377_minAPI28\(arm64-v8a\)\(360,400,420,480,560,640dpi\)_apkmirror.com.apk
No architecture specified. Determining it using `adb`...
Detected target device architecture as: arm64-v8a
Using latest Github gadget version: 17.8.0
Remote FridaGadget version is v17.8.0, local is v0. Downloading...
Downloading from: https://github.com/frida/frida/releases/download/17.8.0/frida-gadget-17.8.0-android-arm64.so.xz
Downloading arm64-v8a library to /home/gemesa/.objection/android/arm64-v8a/libfrida-gadget.so.xz...
Unpacking /home/gemesa/.objection/android/arm64-v8a/libfrida-gadget.so.xz...
Cleaning up downloaded archives...
Patcher will be using Gadget version: 17.8.0
Detected apktool version as: 3.0.1
Running apktool empty-framework-dir...
Apktool 3.0.1 - a tool for reengineering Android apk files
with smali 3.0.9-dev and baksmali 3.0.9-dev
...
Unpacking com.facebook.katana_518.0.0.63.86-462626377_minAPI28(arm64-v8a)(360,400,420,480,560,640dpi)_apkmirror.com.apk
An error may have occurred while extracting the APK.
W: Unsupported type for bags: style.2
...
W: Unsupported type for bags: style.2

App already has android.permission.INTERNET
Target class not specified, searching for launchable activity instead...
Unable to determine the launchable activity using aapt, trying to manually parse the AndroidManifest for activity aliases...
Smali not found in smali directory. This might be a multidex APK. Searching...
Traceback (most recent call last):
  ...
  File "/home/gemesa/.local/lib/python3.14/site-packages/objection/utils/patchers/android.py", line 626, in _determine_smali_path_for_class
    raise Exception('Unable to find smali to patch!')
Exception: Unable to find smali to patch!
Cleaning up temp files...
```

> Note: `objection` independently fetches the latest `frida-gadget` from GitHub (17.8.0 here), regardless of the locally installed `frida` version (16.7.19). This version mismatch is not the cause of the failure.

This failed: `objection` could not find smali to patch (possibly because the APK uses multidex and the launchable activity could not be resolved automatically).

Test account availability

Before starting the instrumentation work, creating a Facebook test account was attempted to avoid using a personal account:

- `https://developers.facebook.com/` --> "The ability to create test users is disabled temporarily"
- `https://www.facebook.com/whitehat/accounts/` --> "Test account creation is temporarily disabled"

A real, freshly created account was used instead.

Final approach: rooted SM-G970F/DS

After all emulator and gadget approaches failed, a physical backup device was rooted: a Samsung Galaxy S10e (SM-G970F/DS, Exynos, Android 12 / One UI 4.1). The rooting process followed the slightly chaotic [XDA Forums guide](https://xdaforums.com/t/tutorial-root-galaxy-s10-series-android-12-one-ui-4-1-stock-firmware.4394629/). The organized and up-to-date version of the rooting guide is available [here](https://shadowshell.io/android-security-handbook/s10e.html). On a rooted physical device, `frida-server` can be run as root and the unmodified APK can be installed and executed normally (no APK patching or gadget injection required). Running on real hardware also avoids emulator detection entirely (though it introduces the potential problem of root detection). The Facebook app does not appear to implement it or at least did not detect the device as rooted.

### Installing the pinned APK

The app auto-updates even when Play Store auto-update is set to "Don't auto-update apps". A complete uninstall and reinstall is required to get back to the pinned version and the package must be frozen after each session.

```bash
# check current version
adb shell dumpsys package com.facebook.katana | grep versionName

# full uninstall
adb shell pm clear com.facebook.katana
adb shell pm uninstall --user 0 com.facebook.katana

# install pinned APK (use -d to force downgrade if a newer version is already installed)
adb install -d com.facebook.katana_518.0.0.63.86-462626377_minAPI28\(arm64-v8a\)\(360,400,420,480,560,640dpi\)_apkmirror.com.apk
adb shell cmd package install-existing com.facebook.katana

# freeze after session to prevent auto-update
adb shell pm disable-user --user 0 com.facebook.katana

# re-enable before next session
adb shell pm enable --user 0 com.facebook.katana
```

Alternatively, toggling airplane mode when not actively analysing might prevent updates.

> Note: Even a full reinstall does not guarantee the same on-device binaries. The extracted library SHA256 may differ from the APK's embedded copy after a reinstall (for example `libcoldstart.so`). Always verify with `adb shell su -c "sha256sum /data/data/com.facebook.katana/lib-compressed/libcoldstart.so"`.

### Java decompilation (`jadx`)

```bash
jadx -d jadx-output \
  com.facebook.katana_518.0.0.63.86-462626377_minAPI28\(arm64-v8a\)\(360,400,420,480,560,640dpi\)_apkmirror.com.apk \
  --log-level error
```

`jadx` emits non-fatal errors on 34 classes/methods out of 12013: `JadxRuntimeException`, `StackOverflowError`, `UnsupportedOperationException` in passes like `RegionMakerVisitor`, `LoopRegionMaker`, `ClassModifier`.

```
ERROR - 34 errors occurred in following nodes:
ERROR -   Class: com.facebook.common.dextricks.DexLibLoader
ERROR -   Class: com.facebook.common.dextricks.DexStore
ERROR -   Class: com.facebook.common.dextricks.MultiDexClassLoaderJava
ERROR -   Class: com.facebook.common.dextricks.SuperpackInputDexIterator
ERROR -   Class: com.facebook.errorreporting.lacrima.detector.lifecycle.ApplicationLifecycleDetector$ActivityCallbacks
ERROR -   Method: X.01t.A06(java.lang.Iterable, java.util.Set):java.util.Set
...
ERROR - finished with errors, count: 34
```

### Smali disassembly (`apktool`)

Due to the `jadx` decompilation errors, `apktool` is used as a complementary tool for string searches to ensure complete coverage:

```bash
apktool d -o apktool-output \
  com.facebook.katana_518.0.0.63.86-462626377_minAPI28\(arm64-v8a\)\(360,400,420,480,560,640dpi\)_apkmirror.com.apk
```

### Locating x-fb-session-id

```bash
$ grep -r "x-fb-session-id" jadx-output/
(no output)
$ grep -r "x-fb" jadx-output/
(no output)
$ grep -r "session-id" jadx-output/
(no output)
```

```bash
$ grep -r "x-fb-session-id" apktool-output/
(no output)
$ grep -r "x-fb" apktool-output/
(no output)
$ grep -r "session-id" apktool-output/
(no output)
```

No results in either output. The header string is not present anywhere in the Java layer. The search then moved to the on-device native libraries.

`jadx` also extracts embedded assets, two of which are relevant:

- `jadx-output/resources/assets/lib/libs.spo`: binary blob
- `jadx-output/resources/assets/lib/metadata.txt`: plaintext manifest listing each `.so` with its size and SHA256 hash

The `metadata.txt` asset provides a manifest of all native libraries with their SHA256 hashes:

```
arm64-v8a/libscrollmerged.so 24135272 7ca8e70d3688eb24b540ca880d5ae0f9e45fed105cdc054a77848457b1e83cee
arm64-v8a/libcoldstart.so 17274800 3e91a9316a12c0f24be4ca1bd3f0d5478def5c4f4775cce939ac935641925daa
arm64-v8a/libarengine-merged.so 12347608 a0d70e2830ff48dd62b37eaf78688f05841af05ed7f64b54b6f80884bc3fcdc0
arm64-v8a/libroomsrsysjniLatest.so 7036408 fdae479055f8fefb60a886db29d5a90679c91dbd5cae90abb3aa8ae3e8131d69
arm64-v8a/libwebrtcLatest.so 4048696 f9286133a4cdc0ce857cf97f2af44535c410318f5e5b359e42e3f38a5653a80a
...
```

`libcoldstart.so` is unpacked at runtime into `/data/data/com.facebook.katana/lib-compressed/`, which is a private app directory (owned by the app's Linux UID, `700` permissions). Root is required to run `frida-server` and to access it. All 100+ `.so` files unpacked at runtime were listed on-device:

```bash
$ adb shell ls /data/data/com.facebook.katana/lib-compressed/
libDav1dExo.so
libIGL.so
libVideoJnimerged.so
...
libcoldstart.so
...
libdexload.so
...
```

All libs were pulled with `copy_libs.sh` and grepped:

```bash
# copy_libs.sh (run on device via adb shell su)
#!/bin/sh
mkdir -p /sdcard/fb_libs
ls /data/data/com.facebook.katana/lib-compressed/ | grep '\.so$' | while read f; do
    cp "/data/data/com.facebook.katana/lib-compressed/$f" /sdcard/fb_libs/
done
```

```bash
# push and run
adb shell su -c "rm -rf /sdcard/fb_libs"
adb push copy_libs.sh /data/local/tmp/copy_libs.sh
adb shell su -c "sh /data/local/tmp/copy_libs.sh"
adb pull /sdcard/fb_libs/ ./fb_libs/
```

```bash
grep -r "x-fb-session-id" ./fb_libs/ --include="*.so" -l
# ./fb_libs/libcoldstart.so
```

This confirms `libcoldstart.so` at SHA256 `3e91a9316a12c0f24be4ca1bd3f0d5478def5c4f4775cce939ac935641925daa` is the primary native component and a natural first target. The string `x-fb-session-id` is embedded as a whole, which makes it straightforward to locate the relevant function via Ghidra's XREF listing. If the string were split, searching for substrings like `x-fb-se` or `session-id` would be needed instead.

```bash
# verify SHA256 before pulling
adb shell su -c "sha256sum /data/data/com.facebook.katana/lib-compressed/libcoldstart.so"

# pull the library
adb shell su -c "cp /data/data/com.facebook.katana/lib-compressed/libcoldstart.so /sdcard/libcoldstart.so"
adb pull /sdcard/libcoldstart.so .
```

## Static analysis

### Overview

The header construction happens in `libcoldstart.so`. The relevant entry point is `TigonRequest::addHeader`, called from `session_builder` once per outgoing HTTP request.

Ghidra base address used throughout: `0x00100000` (Window --> Memory Map --> Image Base).

Throughout the analysis, the raw AArch64 disassembly/listing was preferred over Ghidra's decompiled output. The decompiler is misleading: variable locations, argument registers are misrepresented. The ASM listing is much easier to follow and verify.

The string `x-fb-session-id` is referenced in `session_builder` at `0x0080215c` (Ghidra XREF at `0x002205aa`), so the analysis starts there.

### Function map

| Function | Address | Notes |
|----------|---------|-------|
| `session_builder` | `0x0080215c` | Builds and adds `x-fb-session-id` per request |
| `TigonRequest::addHeader` | `0x007df9dc` | Attaches name/value pair to outgoing request |
| `nid_generate` | `0x006f1318` | Generates a 12-char `nid` from entropy pool |
| `rng_buf_drain` | `0x006d2b18` | Reads N bytes from entropy ring buffer |
| `rng_buf_refill_from_urandom` | `0x006e1e9c` | Refills ring buffer from `/dev/urandom` |
| `atomic_fetch_add` | `0x00c13590` | `std::atomic` fetch-add (`tid` counter) |
| `SharedMutex_lock` | `0x0069f298` | `folly::SharedMutex::lock_shared` |
| `SharedMutex_unlock` | `0x006a4058` | `folly::SharedMutex::unlock_shared` |
| `build_kv_pair` | `0x0068442c` | Builds a `key=value` string pair |
| `string_construct_from_cstr` | `0x006843f8` | Constructs `std::string` from C string |
| `string_copy` | `0x006972e8` | Copies `std::string` |
| `string_copy_from_x21` | `0x006951fc` | Copies `std::string` from x21 |
| `vec_string_copy` | `0x00801e20` | Copies a `std::vector<std::string>` |
| `string_join` | `0x00801fc8` | Joins a vector of strings with `=` and `;` separators |

### `session_builder` (0x0080215c)

Fires once per outgoing HTTP request. The following important functions and data structures have been identified and analyzed from the listing.

`x0` on entry holds a pointer to some outer object. After two dereferences it yields `session_obj*`:

```
                             x0 = some_obj*
                             x23 = x0* = session_obj** (field_0 of some_obj possibly)
        00802168 ldr        x23,[x0]
                             x22 = x23* = session_obj*
                             session_obj layout:
                               0x00: tid
                               0x88: shared_ptr<stats_struct>
        00802170 ldr        x22,[x23]
        00802174 cbz        x22,LAB_0080259c
```

`session_obj+0x88` holds a `shared_ptr<stats_struct>`. A `SharedMutex` read lock is acquired, the raw pointer is loaded and the struct base resolved, then the lock is immediately released:

```
                             session_obj+0x88 = shared_ptr<stats_struct>
        00802180 add        x1,x22,#0x88
        00802184 bl         FUN_0069f298_SharedMutex_lock
        00802188 ldr        x8,[sp]=>local_360
        0080218c mov        x9,#-0x60
        ...
                             x8+x9: base of stats_struct
                             stats_struct layout:
                               0x30: nid
                               0x48: nc
                               0x50: fc
                               0x58: bc
        0080219c add        x21,x8,x9
        008021a0 bl         FUN_006a4058_SharedMutex_unlock
```

`session_obj.tid` is then atomically incremented. The old value is saved in `x22` and incremented by 1 later via `std::to_string`:

```
                             increment session_obj.tid
        008021ac bl         FUN_00c13590_atomic_fetch_add
        008021b0 mov        x22,x0
        ...
                             FUN_00c13590_atomic_fetch_add returned the old tid value,
                             so we increment here by 1
        008021cc add        x0,x22,#0x1
        008021d0 bl         <EXTERNAL>::std::__ndk2::to_string
```

`nid` is copied from `stats_struct+0x30`, then `nc`/`fc`/`bc` are loaded from `+0x48`, `+0x50` and `+0x58`:

```
                             nid slot
                             nid
        008021c0 add        x1,x21,#0x30
        008021c4 bl         FUN_006972e8_string_copy
        ...
                             0x48: nc
                             0x50: fc
        008021d4 ldp        x24,x25,[x21, #0x48]
        ...
                             0x58: bc
        008021e0 ldr        x26,[x21, #0x58]
```

Five key-value pairs (`nid=…`, `tid=…`, `nc=…`, `fc=…`, `bc=…`) are built via `build_kv_pair`, copied into a new vector via `vec_string_copy`, joined with `=` and `;` separators via `string_join`, then passed to `TigonRequest::addHeader`:

```
        008022a8 add        x1=>s_nid_0021d953+0x13,x1,#0x966                = "nid"
        ...
        008022e0 add        x1=>s_tid_0021d4ae+0x22,x1,#0x4d0                = "tid"
        ...
        00802318 add        x1=>s_nc_00232a29+0xb,x1,#0xa34                  = "nc"
        ...
        00802350 add        x1=>s_fc_002334ed,x1,#0x4ed                      = "fc"
        ...
        00802388 add        x1=>s_bc_002341e9,x1,#0x1e9                      = "bc"
        ...
        008023bc bl         FUN_00801e20_vec_string_copy
        ...
        008023f4 bl         FUN_00801fc8_string_join
        ...
        00802400 mov        x0,x20
        00802404 bl         facebook::tigon::TigonRequest::addHeader
```

`session_obj` layout:

| Offset | Field |
|--------|-------|
| `+0x00` | `tid` |
| `+0x88` | `shared_ptr<stats_struct>` (protected by `SharedMutex`) |

`stats_struct` layout:

| Offset | Field |
|--------|-------|
| `+0x30` | `nid` |
| `+0x48` | `nc` |
| `+0x50` | `fc` |
| `+0x58` | `bc` |

### `nid` generation (0x006f1318)

Called four times at startup, producing a pool of four `nid` candidates. The third candidate (index 2, zero-based) is consistently selected as the active session `nid`.

`rng_buf_drain` is called with `w1=0xc` to get 12 random bytes, then a 12-iteration loop maps each byte through the alphabet using a `& 0x3f` mask:

```
        006f1328 mov        w1,#0xc
        006f132c bl         FUN_006f1198
        006f1330 ldr        x0,[sp, #local_38]
        006f1334 mov        w1,#0xc
        006f1338 bl         FUN_006d2b18_rng_buf_drain
                             LAB_006f133c
        006f133c mov        x8,xzr
        006f1340 adrp       x9,0x384000
        006f1344 add        x9,x9,#0x909
                             LAB_006f1348
        006f1348 ldr        x10,[sp, #local_38]
        006f134c cmp        x8,#0xc
        006f1350 b.eq       LAB_006f136c
        006f1354 ldrb       w11,[x10, x8, LSL ]
        006f1358 and        x11,x11,#0x3f
        006f135c ldrb       w11,[x9, x11, LSL ]=>s_ABCDEFGHIJKLMNOPQRSTUVW   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabc...
        006f1360 strb       w11,[x10, x8, LSL ]
        006f1364 add        x8,x8,#0x1
        006f1368 b          LAB_006f1348
```

The result is stored as a `std::string` via SSO writes (`str x9`, `str w10`, `strb wzr` for null terminator):

```
                             LAB_006f136c
        006f136c ldr        x9,[x10]
        006f1370 ldr        w10,[x10, #0x8]
        006f1374 add        x0,sp,#0x8
        006f1378 strb       w8,[x19, #0x17]
        006f137c str        x9,[x19]
        006f1380 str        w10,[x19, #0x8]
        006f1384 strb       wzr,[x19, #0xc]
```

Hook point for capturing the completed `nid`: `strb wzr,[x19,#0xc]` at `0x006f1384` (writes the null terminator, `nid` is fully formed at this point, readable from x19).

Alphabet:

```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
```

Standard base64 alphabet. The `& 0x3f` mask (6 bits, values 0-63) maps each random byte to a valid index.

### `rng_buf_drain` (0x006d2b18)

Reads N bytes from an entropy ring buffer. If the buffer has enough data it copies directly via `memcpy`, otherwise it calls `rng_buf_refill_from_urandom` first:

```
        006d2b40 cmp        x9,x10
        006d2b44 b.ne       LAB_006d2b60
        006d2b48 ldp        x11,x10,[x19, #0x8]
        006d2b4c ldr        x1,[x19, #0x18]
        006d2b50 add        x10,x10,x11
        006d2b54 sub        x10,x10,x1
        006d2b58 cmp        x10,x21
        006d2b5c b.cs       LAB_006d2bcc          // enough data, skip to memcpy
        ...
                             LAB_006d2b88
        006d2b88 cmp        x8,x21
        006d2b8c b.hi       LAB_006d2b9c
        006d2b90 bl         FUN_006a3584
        006d2b94 ...
        006d2b98 b          FUN_006e1e9c_rng_buf_refill_from_urandom
        ...
                             LAB_006d2b9c
        006d2b9c ldp        x9,x1,[x19, #0x10]
        006d2ba0 mov        x0,x20
        ...
        006d2bb8 bl         FUN_006e1e9c_rng_buf_refill_from_urandom
        ...
                             LAB_006d2bcc
        006d2bcc mov        x0,x20
                             LAB_006d2bd0
        006d2bd0 mov        x2,x21
        006d2bd4 bl         <EXTERNAL>::memcpy
```

### `rng_buf_refill_from_urandom` (0x006e1e9c)

Opens `/dev/urandom` once and reads into the ring buffer. Source file is `xplat/folly/Random.cpp` (Facebook's Folly library), confirmed via the log string at `0x001d97a4`. The ring buffer refills lazily when exhausted:

```
        006e1edc adrp       x0,0x1ea000
        006e1ee0 add        x0=>s_/dev/urandom_001eac3c,x0,#0xc3c            = "/dev/urandom"
        006e1ee4 mov        w1,#0x80000
        006e1ee8 bl         <EXTERNAL>::__open_2
        ...
        006e1f0c add        x1=>s_xplat/folly/Random.cpp_001d97a4,x1,#0x7a4  = "xplat/folly/Random.cpp"
        ...
        006e1f98 adrp       x2,0x200000
        006e1f9c add        x2=>s_size_t(bytesRead)_==_size_002008d2,x2,#0   = "size_t(bytesRead) == size"
```

### Call stacks

`nid` generation at startup

```
nid_generate (0x006f1318)          [called 4 times: 3rd result becomes active nid]
  - rng_buf_drain (0x006d2b18)
    - rng_buf_refill_from_urandom (0x006e1e9c)
      - open("/dev/urandom")
      - read(fd, buf, size)
```

`session_builder`: called per-request

```
session_builder (0x0080215c)
  - atomic_fetch_add (0x00c13590)                        [tid increment, at 0x008021ac]
  - string_copy (0x006972e8)                             [copies nid from stats_struct+0x30, at 0x008021c4]
  - string_copy (0x006972e8)                             [copies to_string(nc) result, at 0x00802238]
  - string_copy (0x006972e8)                             [copies to_string(fc) result, at 0x00802360]
  - string_copy (0x006972e8)                             [copies to_string(bc) result, at 0x00802398]
  - build_kv_pair (0x0068442c)                           [nid=<value> ("nid" at 0x0021d953, value from stats_struct+0x30), at 0x008022d4]
  - build_kv_pair (0x0068442c)                           [tid=<value> ("tid" at 0x0021d4ae, old_tid+1 via to_string), at 0x00802308]
  - build_kv_pair (0x0068442c)                           [nc=<value>  ("nc" at 0x00232a29, stats_struct+0x48 via to_string), at 0x00802340]
  - build_kv_pair (0x0068442c)                           [fc=<value>  ("fc" at 0x002334ed, stats_struct+0x50 via to_string), at 0x00802378]
  - build_kv_pair (0x0068442c)                           [bc=<value>  ("bc" at 0x002341e9, stats_struct+0x58 via to_string), at 0x008023b0]
  - vec_string_copy (0x00801e20)                         [copies 5 kv pairs into new vector, at 0x008023bc]
  - string_join (0x00801fc8)                             [joins pairs with "=" and ";" separators, at 0x008023f4]
  - TigonRequest::addHeader (0x007df9dc)                 [emits x-fb-session-id, at 0x00802404]
```

### `tid` generation

`tid` is backed by an atomic integer at `session_obj+0x00`. `atomic_fetch_add` at `0x008021ac` returns the previous value and `session_builder` adds 1 before formatting. First `tid` per session is always `1`.

### `nc` / `fc` / `bc`

Loaded from `stats_struct+0x48/+0x50/+0x58` and included in every header. Increment sites were not found in `libcoldstart.so`. These were always `0` in all observed sessions (toggling WiFi, switching networks and cycling airplane mode had no effect). They might be set somewhere else, e.g. in the Java layer.

## Dynamic analysis

### Frida setup

Frida 17.7.3 (latest at time of writing) caused connection issues on this device. Downgrade to Frida 16.7.19:

```bash
pip uninstall frida frida-tools
pip install frida-tools==13.6.0
```

Install the matching `frida-server` on the device:

```bash
wget https://github.com/frida/frida/releases/download/16.7.19/frida-server-16.7.19-android-arm64.xz
xz -d frida-server-16.7.19-android-arm64.xz
adb push frida-server-16.7.19-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell su -c "/data/local/tmp/frida-server &"

# verify it is running
adb shell ps | grep frida
frida-ps -U | grep -i facebook
```

Run the hook script:

```bash
frida -U -f com.facebook.katana -l hook.js --pause
# at the prompt:
%resume
```

We install the hook after `libcoldstart.so` is mapped into memory. Since the library is loaded dynamically during app startup, hook `android_dlopen_ext` to detect when `libcoldstart.so` is opened, then install all hooks inside the callback.

If `x-fb-session-id` hooking stops working: `adb reboot`.

### Hook script

```javascript
const GHIDRA_BASE = 0x00100000;

const ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function readFBString(p) {
  try {
    const byte23 = p.add(23).readU8();
    if (byte23 & 0x80) {
      const heapPtr = p.readPointer();
      if (heapPtr.isNull()) return "<null>";
      const size = p.add(8).readU64().toNumber() & 0x7fffffff;
      if (size === 0) return "";
      if (size > 8192) return "<invalid size: " + size + ">";
      return heapPtr.readUtf8String(size);
    } else {
      const size = byte23;
      if (size === 0) return "";
      if (size > 23) return "<invalid size: " + size + ">";
      return p.readUtf8String(size);
    }
  } catch (e) {
    try {
      return p.readCString();
    } catch (_) {}
    return "<err: " + e.message + ">";
  }
}

function bytesToNid(buf) {
  let result = "";
  for (let i = 0; i < 12; i++) result += ALPHABET[buf[i] & 0x3f];
  return result;
}

function installHooks(base) {
  console.log("[+] Installing hooks at base: " + base);

  // FUN_0080215c - session-builder
  try {
    Interceptor.attach(base.add(0x0080215c - GHIDRA_BASE), {
      onEnter: function (args) {
        console.log("[session-builder] fired");
      },
    });
    console.log("[+] session-builder hooked");
  } catch (e) {
    console.log("[-] session-builder failed: " + e);
  }

  // facebook::tigon::TigonRequest::addHeader - session headers only
  try {
    Interceptor.attach(base.add(0x007df9dc - GHIDRA_BASE), {
      onEnter: function (args) {
        var name = readFBString(this.context.x1);
        if (name && name.toLowerCase().includes("session")) {
          console.log(
            "[addHeader] " + name + ": " + readFBString(this.context.x2),
          );
        }
      },
    });
    console.log("[+] addHeader hooked");
  } catch (e) {
    console.log("[-] addHeader failed: " + e);
  }

  // FUN_006f1318 nid-gen: hook strb wzr,[x19,#0xc] at 006f1384
  // all 12 nid bytes already written to x19 by preceding str instructions
  try {
    Interceptor.attach(base.add(0x006f1384 - GHIDRA_BASE), {
      onEnter: function (args) {
        try {
          console.log(
            "[nid-gen] generated nid: " + this.context.x19.readUtf8String(12),
          );
        } catch (e) {
          console.log("[nid-gen] read failed: " + e);
        }
      },
    });
    console.log("[+] nid-gen hooked");
  } catch (e) {
    console.log("[-] nid-gen failed: " + e);
  }

  // FUN_006d2b18 - entropy pool memcpy: x0=dest, w1=size, filter w1==0xc
  try {
    Interceptor.attach(base.add(0x006d2b18 - GHIDRA_BASE), {
      onEnter: function (args) {
        this.dest = args[0];
        this.size = args[1].toInt32();
      },
      onLeave: function (retval) {
        if (this.size !== 0xc) return;
        try {
          const raw = new Uint8Array(this.dest.readByteArray(12));
          const hex = Array.from(raw)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join(" ");
          console.log("[nid-rng] raw bytes:   " + hex);
          console.log("[nid-rng] derived nid: " + bytesToNid(raw));
        } catch (e) {
          console.log("[nid-rng] read failed: " + e);
        }
      },
    });
    console.log("[+] nid-rng hooked");
  } catch (e) {
    console.log("[-] nid-rng failed: " + e);
  }

  console.log("[+] All hooks installed!");
}

const dlopen = Module.findExportByName(null, "android_dlopen_ext");
if (dlopen) {
  Interceptor.attach(dlopen, {
    onEnter: function (args) {
      this.path = args[0] ? args[0].readCString() : "";
      if (this.path.includes("libcoldstart")) {
        console.log("[+] libcoldstart.so loading");
        this.isColdstart = true;
      }
    },
    onLeave: function (retval) {
      if (!this.isColdstart) return;
      const mod = Process.findModuleByName("libcoldstart.so");
      if (mod) {
        installHooks(ptr(mod.base));
      } else {
        try {
          const maps = new File("/proc/self/maps", "r");
          let line;
          while ((line = maps.readLine()) !== "") {
            if (line.includes("libcoldstart") && line.includes("r-xp")) {
              maps.close();
              installHooks(ptr("0x" + line.split("-")[0]));
              return;
            }
          }
          maps.close();
        } catch (e) {
          console.log("[-] maps error: " + e);
        }
        console.log("[-] Could not find libcoldstart base");
      }
    },
  });
  console.log("[+] Watching for libcoldstart.so...");
}
```

### Hook points

| Hook point | Hook address | Function address | Purpose |
|-----------|---------|----------|---------|
| `android_dlopen_ext` | --- | --- | Detect library load (install remaining hooks in `onLeave`) |
| `session_builder` | `0x0080215c` | `0x0080215c` | Confirm per-request firing |
| `TigonRequest::addHeader` | `0x007df9dc` | `0x007df9dc` | Capture final header key + value |
| `nid` complete: `strb wzr,[x19,#0xc]` | `0x006f1384` | `0x006f1318` | Read completed `nid` from x19 |
| `rng_buf_drain` | `0x006d2b18` | `0x006d2b18` | Capture raw 12 entropy bytes (filter `w1 == 0xc`) |

### Frida session output

`[nid-rng]` captures the raw 12 bytes from `rng_buf_drain` and manually applies the `ALPHABET[b & 0x3f]` mapping to compute the expected `nid` (`derived nid`). `[nid-gen]` reads the actual result from x19 at `0x006f1384` (`generated nid`). The two matching confirms the algorithm is correct. The app was manually closed on the device at the end of the session.

```
$ frida -U -f com.facebook.katana -l hook.js --pause
     ____
    / _  |   Frida 16.7.19 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to SM G970F (id=RF8M71AZ8HL)
Spawning `com.facebook.katana`...
[+] Watching for libcoldstart.so...
Spawned `com.facebook.katana`. Use %resume to let the main thread start executing!
[SM G970F::com.facebook.katana ]-> %resume
[SM G970F::com.facebook.katana ]-> [+] libcoldstart.so loading
[+] Installing hooks at base: 0x6efaa34000
[+] session-builder hooked
[+] addHeader hooked
[+] nid-gen hooked
[+] nid-rng hooked
[+] All hooks installed!
[nid-rng] raw bytes:   ac d9 45 66 89 20 e6 34 dd 09 e6 69
[nid-rng] derived nid: sZFmJgm0dJmp
[nid-gen] generated nid: sZFmJgm0dJmp
[nid-rng] raw bytes:   c6 d8 89 76 90 66 29 51 b3 90 24 c6
[nid-rng] derived nid: GYJ2QmpRzQkG
[nid-gen] generated nid: GYJ2QmpRzQkG
[nid-rng] raw bytes:   e8 44 06 d5 48 99 9b 58 47 ac 9c e9
[nid-rng] derived nid: oEGVIZbYHscp
[nid-gen] generated nid: oEGVIZbYHscp
[nid-rng] raw bytes:   0b a8 4a f7 2e dc 37 5f e1 1f d1 a5
[nid-rng] derived nid: LoK3uc3fhfRl
[nid-gen] generated nid: LoK3uc3fhfRl
[session-builder] fired
[addHeader] x-fb-session-id: nid=oEGVIZbYHscp;tid=1;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=oEGVIZbYHscp;tid=2;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=oEGVIZbYHscp;tid=3;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=oEGVIZbYHscp;tid=4;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=oEGVIZbYHscp;tid=5;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=oEGVIZbYHscp;tid=6;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=oEGVIZbYHscp;tid=7;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=oEGVIZbYHscp;tid=8;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=oEGVIZbYHscp;tid=9;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=oEGVIZbYHscp;tid=10;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=oEGVIZbYHscp;tid=11;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=oEGVIZbYHscp;tid=12;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=oEGVIZbYHscp;tid=13;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=oEGVIZbYHscp;tid=14;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=oEGVIZbYHscp;tid=15;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=oEGVIZbYHscp;tid=16;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=oEGVIZbYHscp;tid=17;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=oEGVIZbYHscp;tid=18;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=oEGVIZbYHscp;tid=19;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=oEGVIZbYHscp;tid=20;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=oEGVIZbYHscp;tid=21;nc=0;fc=0;bc=0
Process terminated
[SM G970F::com.facebook.katana ]->
Thank you for using Frida!
```

An earlier session (before `nid-gen` and `nid-rng` hooks were added):

```
[+] Installing hooks at base: 0x7bdc801000
[+] session-builder hooked
[+] addHeader hooked
[+] All hooks installed!
[session-builder] fired
[addHeader] x-fb-session-id: nid=AZYSmIqSzFTK;tid=1;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=AZYSmIqSzFTK;tid=2;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=AZYSmIqSzFTK;tid=3;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=AZYSmIqSzFTK;tid=4;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=AZYSmIqSzFTK;tid=5;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=AZYSmIqSzFTK;tid=6;nc=0;fc=0;bc=0
...
[addHeader] x-fb-session-id: nid=AZYSmIqSzFTK;tid=45;nc=0;fc=0;bc=0
```

This confirms that the `nid` and `nc=0`/`fc=0`/`bc=0` pattern is consistent across sessions.

> Crash workaround: An intermittent crash occurred during some sessions (SIGILL in `libnativeloader.so` during native library loading, which seemed intentional). Workaround:
> 1. Start the app with Frida
> 2. Wait for a couple of requests
> 3. Enable airplane mode, then disable it
>
> Alternatively: enable airplane mode --> disable --> turn off WiFi --> turn on WiFi. The crash does not reproduce after this sequence.

```
[session-builder] fired
[addHeader] x-fb-session-id: nid=AZYSmIqSzFTK;tid=96;nc=0;fc=0;bc=0
[session-builder] fired
[addHeader] x-fb-session-id: nid=AZYSmIqSzFTK;tid=97;nc=0;fc=0;bc=0
Process crashed: Illegal instruction

***
* * * * * * * * * * * * * * * *
Build fingerprint: 'samsung/beyond0lteeea/beyond0:12/SP1A.210812.016/G970FXXSGHWC2:user/release-keys'
Revision: '26'
ABI: 'arm64'
Processor: '4'
Timestamp: 2026-03-07 21:20:54.074026163+0700
Process uptime: 9s
Cmdline: com.facebook.katana
pid: 9797, tid: 10091, name: CombinedTP26  >>> com.facebook.katana <<<
uid: 10144
signal 4 (SIGILL), code 1 (ILL_ILLOPC), fault addr 0x200fca600c
    x0  0000007d04a189c0  x1  0000000000000002  x2  0000007b38f93670  x3  000000200fca6000
    x4  0000000000000030  x5  0000007b38f93524  x6  00000000444f4f47  x7  00000000444f4f47
    x8  0000007bfd6b0000  x9  0000000000000000  x10 0000000000000040  x11 0000000000000007
    x12 0000fffffffff3ff  x13 00000000fddda7a0  x14 0000000080000000  x15 000000009908b0df
    x16 0000007f8f7620e4  x17 0000007bece6e408  x18 0000007b32764000  x19 0000007b38f93850
    x20 0000007cd440d558  x21 0000007cd440d558  x22 0000007b38f96000  x23 0000000000000019
    x24 0000007b38f93cfc  x25 0000007b38f96000  x26 0000007d54449990  x27 0000007b38f96000
    x28 0000007ce43b5890  x29 0000007b38f937d0
    lr  0000007f928e0f7c  sp  0000007b38f93640  pc  000000200fca600c  pst 0000000060000000
backtrace:
      #00 pc 000000000000000c  [anon:distract heap]
      #01 pc 000000000001bf78  /apex/com.android.art/lib64/libnativeloader.so (android::NativeLoaderNamespace::Load(char const*) const+184) (BuildId: d784367732e5a77414ccb9ad99ca23fa)
      #02 pc 000000000000ce48  /apex/com.android.art/lib64/libnativeloader.so (OpenNativeLibraryInNamespace+64) (BuildId: d784367732e5a77414ccb9ad99ca23fa)
      #03 pc 000000000000c574  /apex/com.android.art/lib64/libnativeloader.so (OpenNativeLibrary+132) (BuildId: d784367732e5a77414ccb9ad99ca23fa)
      #04 pc 0000000000458658  /apex/com.android.art/lib64/libart.so!libart.so (art::JavaVMExt::LoadNativeLibrary(_JNIEnv*, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&, _jobject*, _jclass*, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >*)+2144) (BuildId: 1724d2edb620afb8c3e8c5ea6c61ac19)
```

### Key observations

- Four `nid`s are generated at startup: the third (index 2) is selected as the active session `nid`
- `nid` is stable for the entire session lifetime
- `tid` starts at 1 and increments by 1 per request with no gaps or resets; if hooks are installed late, early tids are missed but the sequence is unbroken
- `nc`, `fc`, `bc` are 0 in every observed request under normal WiFi conditions

### `nid` algorithm verification

Raw bytes from `rng_buf_drain` mapped through the alphabet, confirmed against the `nid` captured from `nid_generate`:

```
raw:    ac  d9  45  66  89  20  e6  34  dd  09  e6  69
& 0x3f: 2c  19  05  26  09  20  26  34  1d  09  26  29
index:  44  25   5  38   9  32  38  52  29   9  38  41
char:    s   Z   F   m   J   g   m   0   d   J   m   p
result: sZFmJgm0dJmp
```

## Reproduction algorithm

`nid` is generated once at startup and reused for all requests. `tid` starts at 1 and increments by 1 per request with no gaps.

```python
import os

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

class FBSession:
    def __init__(self):
        self.nid = self._gen_nid()
        self.tid = 0

    def _gen_nid(self) -> str:
        return "".join(ALPHABET[b & 0x3f] for b in os.urandom(12))

    def session_id_header(self, nc: int = 0, fc: int = 0, bc: int = 0) -> str:
        self.tid += 1
        return f"nid={self.nid};tid={self.tid};nc={nc};fc={fc};bc={bc}"
```

## Challenges and solutions

| Challenge | Solution |
|-----------|----------|
| `nid` is generated early/during startup | Hook `android_dlopen_ext` (install all hooks in `onLeave`) |
| x86_64 APK on x86_64 AVD triggered possible emulator detection | Switched to arm64 APK on a physical rooted device |
| arm64 APK on Genymotion SaaS virtual arm64 device triggered possible intentional abort | Switched to arm64 APK on a physical rooted device |
| `objection patchapk` failed on multidex APK | Abandoned APK patching (used Frida spawn on a rooted device instead) |
| `jadx` produced decompilation errors on 34 classes/methods out of 12013 (non-fatal) | `apktool` used as an alternative for string search (no decompilation errors) |
| App auto-updates despite Play Store setting | Enable airplane mode and freeze with `pm disable-user` when not actively analysing |
| Frida 17.7.3 (latest) caused connection issues on SM-G970F/DS | Downgraded to Frida 16.7.19 |
| Intermittent SIGILL crash in `libnativeloader.so` during Frida session | Toggle airplane mode / WiFi after starting the app |
| `x-fb-session-id` hooking stops working intermittently | `adb reboot` (possibly caused by a bug in the hook script) |
| Ghidra image base `0x00100000` differs from runtime load address | Use Window --> Memory Map to set correct base before computing hook addresses |
| `nc`/`fc`/`bc` increment sites not in `libcoldstart.so` or in the decompiled Java (`jadx`) or smali code (`apktool`) | Not resolved (observed as 0 in all sessions so not critical) |
| Reinstall produced different `libcoldstart.so` on-device | Always re-verify SHA256 after reinstall |

## Open questions

- The exact meaning of `nc`, `fc` and `bc` was not confirmed in code. They are probably set somewhere else, possibly in the Java layer. Other researchers' logs confirm `nc=0`/`fc=0`/`bc=0` is the norm; the only non-zero value found was `nc=1` in a hardcoded header in a third-party script. References:
  - https://github.com/mautrix/facebook/issues/195
  - https://github.com/Hannan-404/GIFT/blob/main/Enjoy.py
