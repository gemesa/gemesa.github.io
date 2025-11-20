---
title: Reversing a fake Android Chrome updater
published: true
---

## Table of contents

* toc placeholder
{:toc}

## Introduction

In this post we will analyze a randomly picked [Android sample](https://bazaar.abuse.ch/sample/59bb681961028642190f780266e2932a0f928b6ec44881165e1cecd0988c8029/) from 2025 that disguises itself as a Chrome updater using [jadx](https://github.com/skylot/jadx). A search for [existing write-ups](https://www.google.com/search?q=%2259bb681961028642190f780266e2932a0f928b6ec44881165e1cecd0988c8029%22) yields no results, so we are exploring fresh territory. We will also implement YARA rules to detect IOCs and Java code to decrypt the obfuscated strings.

## Executive summary

The [analyzed sample](https://bazaar.abuse.ch/sample/59bb681961028642190f780266e2932a0f928b6ec44881165e1cecd0988c8029/) is a [Sketchware Pro application](https://github.com/Sketchware-Pro/Sketchware-Pro/blob/68334a917e01bf040b51684c61137cf75af848dd/app/src/main/assets/debug/SketchApplication.java) disguised as a Chrome updater with obfuscated strings. After start, it immediately shows an "This app can't run on your device." alert and when the user taps the "OK" button, it exits. In the background it runs `logcat` commands without privilege escalation (`su`), meaning it cannot capture system-wide logs. It only grabs its own app's output, which from a spyware perspective makes it useless. There is no other functionality implemented.

![app preview]({{site.baseurl}}/assets/fake-chrome-updater/preview.png){:.small-image}

This sample is likely either:
- Incomplete/abandoned malware: started but never finished
- UI/social engineering demo: showcases the fake Chrome updater disguise and error dialog tactics without actual malicious functionality
- Template for customization: base version meant to be modified with `su -c logcat` by attackers before deployment

If properly weaponized with root access (`su -c logcat` on a rooted device), the intended attack flow could work like this:

After installation, the app displays a fake "device unsupported" error to make victims think it failed. The malware continuously captures system-wide logs (containing possibly sensitive information) and broadcasts them to Sketchware Pro's [LogReader](https://github.com/Sketchware-Pro/Sketchware-Pro/blob/68334a917e01bf040b51684c61137cf75af848dd/app/src/main/java/mod/khaled/logcat/LogReaderActivity.java) via `pro.sketchware.ACTION_NEW_DEBUG_LOG` intents. The attacker then socially engineers the victim to share the debug logs containing all captured sensitive data. Alternatively, a companion malicious app could listen for these broadcasts and automatically exfiltrate the data to a remote server, eliminating the need for manual social engineering.

The sample uses Sketchware Pro's publicly available [SketchLogger](https://github.com/Sketchware-Pro/Sketchware-Pro/blob/68334a917e01bf040b51684c61137cf75af848dd/app/src/main/assets/debug/SketchLogger.java) template.

## Detailed analysis

Let's shorten the binary name first so it is easier to work with in the following chapters.

```
$ mv 59bb681961028642190f780266e2932a0f928b6ec44881165e1cecd0988c8029.apk ChromeUpdater.apk
```

### Hashes

```
$ md5sum < ChromeUpdater.apk 
ae248271a115abb2eea24fbc922ace72  -
                                  
$ sha1sum < ChromeUpdater.apk 
d0fbcd6d86489c86dfc8db551bf04119347941c9  -

$ sha256sum < ChromeUpdater.apk 
59bb681961028642190f780266e2932a0f928b6ec44881165e1cecd0988c8029  -
```

### Overview

The sample is a regular APK file:

```
$ file ChromeUpdater.apk 
ChromeUpdater.apk: Android package (APK), with AndroidManifest.xml, with APK Signing Block
```

### Static analysis (jadx)

We can decompile the APK with 1 minor error only (that is related to a library function, so we can safely ignore it):

```
$ jadx ChromeUpdater.apk --log-level error -d out
ERROR - JadxRuntimeException in pass: RegionMakerVisitor in method: androidx.localbroadcastmanager.content.LocalBroadcastManager.executePendingBroadcasts():void, file: classes47.dex
jadx.core.utils.exceptions.JadxRuntimeException: Can't find top splitter block for handler:B:26:0x0049
	at jadx.core.utils.BlockUtils.getTopSplitterForHandler(BlockUtils.java:1178)
	at jadx.core.dex.visitors.regions.maker.ExcHandlersRegionMaker.collectHandlerRegions(ExcHandlersRegionMaker.java:53)
	at jadx.core.dex.visitors.regions.maker.ExcHandlersRegionMaker.process(ExcHandlersRegionMaker.java:38)
	at jadx.core.dex.visitors.regions.RegionMakerVisitor.visit(RegionMakerVisitor.java:27)
	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:25)
	at jadx.core.dex.visitors.DepthTraversal.lambda$visit$1(DepthTraversal.java:13)
	at java.base/java.util.ArrayList.forEach(ArrayList.java:1596)
	at jadx.core.dex.visitors.DepthTraversal.visit(DepthTraversal.java:13)
	at jadx.core.ProcessClass.process(ProcessClass.java:76)
	at jadx.core.ProcessClass.generateCode(ProcessClass.java:120)
	at jadx.core.dex.nodes.ClassNode.generateClassCode(ClassNode.java:403)
	at jadx.core.dex.nodes.ClassNode.decompile(ClassNode.java:391)
	at jadx.core.dex.nodes.ClassNode.getCode(ClassNode.java:341)
	at jadx.api.JadxDecompiler.lambda$appendSourcesSave$1(JadxDecompiler.java:407)
	at jadx.core.utils.tasks.TaskExecutor.wrapTask(TaskExecutor.java:198)
	at jadx.core.utils.tasks.TaskExecutor.lambda$runStages$0(TaskExecutor.java:179)
	at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1144)
	at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:642)
	at java.base/java.lang.Thread.run(Thread.java:1583)
ERROR - 1 errors occurred in following nodes:                
ERROR -   Method: androidx.localbroadcastmanager.content.LocalBroadcastManager.executePendingBroadcasts():void
ERROR - finished with errors, count: 1
```

The interesting files are:

```
$ ls sources/com/updater/chrome/
a.java  b.java  c.java  DebugActivity.java  d.java  MainActivity.java  R.java  SketchApplication.java
$ ls sources/defpackage/
a.java  b.java  c.java
$ ls resources/AndroidManifest.xml
resources/AndroidManifest.xml
$ ls resources/res/layout/main.xml 
resources/res/layout/main.xml
```

> Note: `defpackage` is the [placeholder](https://github.com/skylot/jadx/blob/6aeaf6aca936433912a0cb5f6fd69a411a50d416/jadx-core/src/main/java/jadx/core/Consts.java#L27) created by jadx when it encounters classes that have:
> no package declaration
> been moved to the default/root package (e.g. through obfuscation)
> package names that were stripped (by tools like [ProGuard](https://github.com/Guardsquare/proguard))

#### `AndroidManifest.xml`

Before looking at the source code, it is a good idea to check `AndroidManifest.xml` briefly. After launch, a `SketchApplication` instance is created first, then a `MainActivity` instance then finally a `DebugActivity` instance. When an instance is created, the `onCreate()` method is called.

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    android:versionCode="1"
    android:versionName="1.0"
    android:compileSdkVersion="33"
    android:compileSdkVersionCodename="13"
    package="com.updater.chrome"
    platformBuildVersionCode="33"
    platformBuildVersionName="13">
    <uses-sdk
        android:minSdkVersion="21"
        android:targetSdkVersion="34"/>
    <application
        android:theme="@style/AppTheme"
        android:label="@string/app_name"
        android:icon="@drawable/app_icon"
        android:name="com.updater.chrome.SketchApplication"
        android:allowBackup="true"
        android:usesCleartextTraffic="true"
        android:requestLegacyExternalStorage="true">
        <activity
            android:name="com.updater.chrome.MainActivity"
            android:exported="true"
            android:screenOrientation="portrait"
            android:configChanges="smallestScreenSize|screenSize|screenLayout|orientation|keyboardHidden"
            android:hardwareAccelerated="true"
            android:supportsPictureInPicture="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <activity
            android:name="com.updater.chrome.DebugActivity"
            android:screenOrientation="portrait"/>
        <provider
            android:name="androidx.startup.InitializationProvider"
            android:exported="false"
            android:authorities="com.updater.chrome.androidx-startup">
            <meta-data
                android:name="androidx.lifecycle.ProcessLifecycleInitializer"
                android:value="androidx.startup"/>
            <meta-data
                android:name="androidx.emoji2.text.EmojiCompatInitializer"
                android:value="androidx.startup"/>
        </provider>
        <uses-library
            android:name="org.apache.http.legacy"
            android:required="false"/>
    </application>
</manifest>
```

#### `SketchApplication.java`

This code is the standard [`SketchApplication.java`](https://github.com/Sketchware-Pro/Sketchware-Pro/blob/68334a917e01bf040b51684c61137cf75af848dd/app/src/main/assets/debug/SketchApplication.java). The difference is that it is just split into multiple files by jadx and the strings are obfuscated.

> Note: the decoded strings have been added manually to the source files. A decoder will be implemented in a later chapter.

```java
package com.updater.chrome;

import android.app.Application;
import android.content.Context;

/* loaded from: classes54.dex */
public class SketchApplication extends Application {
    private static Context a;

    public static Context a() {
        return a;
    }

    @Override // android.app.Application
    public void onCreate() {
        a = getApplicationContext();
        Thread.setDefaultUncaughtExceptionHandler(new d(this));
        defpackage.b.d();
        super.onCreate();
    }
}
```

```java
package com.updater.chrome;

import android.content.Intent;
import android.os.Process;
import android.util.Log;
import java.lang.Thread;

/* loaded from: classes54.dex */
class d implements Thread.UncaughtExceptionHandler {
    final /* synthetic */ SketchApplication a;

    d(SketchApplication sketchApplication) {
        this.a = sketchApplication;
    }

    @Override // java.lang.Thread.UncaughtExceptionHandler
    public void uncaughtException(Thread thread, Throwable th) {
        Intent intent = new Intent(this.a.getApplicationContext(), (Class<?>) DebugActivity.class);
        intent.setFlags(268468224);
        intent.putExtra(defpackage.c.a("MCY0Qko="), Log.getStackTraceString(th)); // decoded string: error
        this.a.startActivity(intent);
        defpackage.b.c(Log.getStackTraceString(th));
        Process.killProcess(Process.myPid());
        System.exit(1);
    }
}
```

It also calls `defpackage.b.d()` which starts the logger thread (`b.start()`). This code can be found in [`SketchLogger.java`](https://github.com/Sketchware-Pro/Sketchware-Pro/blob/68334a917e01bf040b51684c61137cf75af848dd/app/src/main/assets/debug/SketchLogger.java).

#### `SketchLogger.java`

```java
package defpackage;

import android.content.Context;
import android.content.Intent;
import com.updater.chrome.SketchApplication;

/* loaded from: classes54.dex */
public abstract class b {
    private static volatile boolean a = false;
    private static Thread b = new a();

    public static void c(String str) {
        Context contextA = SketchApplication.a();
        Intent intent = new Intent();
        intent.setAction(c.a("JSYpA0s+MTJOUCI1NEgWFBcSZHcbCwhobwoQA29tEgsKYn8=")); // decoded string: pro.sketchware.ACTION_NEW_DEBUG_LOG
        intent.putExtra(c.a("OTsh"), str); // decoded string: log
        intent.putExtra(c.a("JTUlRlkyMQhMVTA="), contextA.getPackageName()); // decoded string: packageName
        contextA.sendBroadcast(intent);
    }

    public static void d() {
        if (a) {
            throw new IllegalStateException(c.a("GTshSl0ndCdBSjA1IlQYJyEoQ1E7Mw==")); // decoded string: Logger already running
        }
        b.start();
    }
}
```

```java
package defpackage;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/* loaded from: classes54.dex */
class a extends Thread {
    a() {
    }

    @Override // java.lang.Thread, java.lang.Runnable
    public void run() {
        b.a = true;
        try {
            Runtime.getRuntime().exec(c.a("OTshTlkhdGtO")); // decoded string: logcat -c
            try {
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(c.a("OTshTlkh")).getInputStream())); // decoded string: logcat
                try {
                    String line = bufferedReader.readLine();
                    do {
                        b.c(line);
                        if (!b.a) {
                            break;
                        } else {
                            line = bufferedReader.readLine();
                        }
                    } while (line != null);
                    if (b.a) {
                        b.c(c.a("GTshSl0ndCFCTHU/L0FUMDBoDWowJzJMSiE9KEoW")); // decoded string: Logger got killed. Restarting.
                        b.d();
                    } else {
                        b.c(c.a("GTshSl0ndDVZVyUkI0kW")); // decoded string: Logger stopped.
                    }
                    bufferedReader.close();
                } catch (Throwable th) {
                    bufferedReader.close();
                    throw th;
                }
            } finally {
            }
        } catch (IOException e) {
            b.c(e.getMessage());
        }
    }
}
```

#### `MainActivity.java`

If we check `resources/res/layout/main.xml`, we can see that the app sets up a layout and immediately displays an alert with one button.

```java
package com.updater.chrome;

import android.app.AlertDialog;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;

/* loaded from: classes54.dex */
public class MainActivity extends AppCompatActivity {
    private LinearLayout a;
    private LinearLayout b;
    private TextView c;
    private TextView d;
    private Button e;
    private AlertDialog.Builder f;

    private void a(Bundle bundle) {
        this.a = (LinearLayout) findViewById(R.id.linear1);
        this.b = (LinearLayout) findViewById(R.id.linear2);
        this.c = (TextView) findViewById(R.id.textview1);
        this.d = (TextView) findViewById(R.id.textview2);
        this.e = (Button) findViewById(R.id.button1);
        this.f = new AlertDialog.Builder(this);
        this.e.setOnClickListener(new b(this));
    }

    private void b() {
        this.f.setMessage(defpackage.c.a("ATwvXhg0JDYNWzQ6YVkYJyEoDVc7dD9CTSd0IkhOPDcjAw==")); // decoded string: This app can't run on your device.
        this.f.setPositiveButton(defpackage.c.a("Gh8="), new c(this)); // decoded string: OK
        this.f.create().show();
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.main);
        a(bundle);
        b();
    }
}
```

```xml
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android" xmlns:app="http://schemas.android.com/apk/res-auto"
    android:orientation="vertical"
    android:layout_width="match_parent"
    android:layout_height="match_parent">
    <LinearLayout
        android:orientation="vertical"
        android:id="@+id/linear1"
        android:padding="8dp"
        android:layout_width="match_parent"
        android:layout_height="match_parent">
        <LinearLayout
            android:orientation="horizontal"
            android:id="@+id/linear2"
            android:padding="8dp"
            android:layout_width="match_parent"
            android:layout_height="wrap_content">
            <TextView
                android:textSize="30sp"
                android:textColor="#f44336"
                android:id="@+id/textview1"
                android:padding="8dp"
                android:layout_width="wrap_content"
                android:layout_height="wrap_content"
                android:text="Google Chrome Updater"/>
        </LinearLayout>
        <TextView
            android:textSize="20sp"
            android:textStyle="bold"
            android:textColor="#000000"
            android:id="@+id/textview2"
            android:padding="8dp"
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"
            android:text="Your Chrome version is outdated! Chrome version: 65.1 (19 years ago!)"/>
        <Button
            android:textSize="12sp"
            android:textColor="#000000"
            android:id="@+id/button1"
            android:padding="8dp"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:text="Download and install update"/>
    </LinearLayout>
</LinearLayout>
```

After the user taps the alert button, the program exits the `MainActivity` ([`finishAffinity()`](https://developer.android.com/reference/android/app/Activity#finishAffinity())).

```java
package com.updater.chrome;

import android.content.DialogInterface;

/* loaded from: classes54.dex */
class c implements DialogInterface.OnClickListener {
    final /* synthetic */ MainActivity a;

    c(MainActivity mainActivity) {
        this.a = mainActivity;
    }

    @Override // android.content.DialogInterface.OnClickListener
    public void onClick(DialogInterface dialogInterface, int i) {
        this.a.finishAffinity();
    }
}
```

#### Obfuscated strings

The strings are obfuscated and are decoded via the following class that implements a combination of XOR encryption and Base64 decoding.

```java
package defpackage;

import android.util.Base64;
import java.io.UnsupportedEncodingException;
import org.apache.http.protocol.HTTP;

/* loaded from: classes54.dex */
public final class c {
    public static String a(String str) {
        return new c().b(str, HTTP.UTF_8);
    }

    private static byte[] c(byte[] bArr, String str) {
        int length = bArr.length;
        int length2 = str.length();
        int i = 0;
        int i2 = 0;
        while (i < length) {
            if (i2 >= length2) {
                i2 = 0;
            }
            bArr[i] = (byte) (bArr[i] ^ str.charAt(i2));
            i++;
            i2++;
        }
        return bArr;
    }

    public String b(String str, String str2) {
        try {
            return new String(c(Base64.decode(str, 2), str2), HTTP.UTF_8);
        } catch (UnsupportedEncodingException unused) {
            return new String(c(Base64.decode(str, 2), str2));
        }
    }
}
```

Using the code above, we can implement a decoder. We can use it to decode the alert and button strings, and to cross-reference the obfuscated strings with the ones in the original [Sketchware Pro sources](https://github.com/Sketchware-Pro/Sketchware-Pro/tree/68334a917e01bf040b51684c61137cf75af848dd/app/src/main/assets/debug). It can also encode plain strings, in case we want to decode, modify and rebuild the app, e.g. with [`Apktool`](https://github.com/iBotPeaches/Apktool).

```java
import java.util.Base64;

public class ChromeUpdaterCrypt {
    
    private static byte[] xorCrypt(byte[] data, String key) {
        int length = data.length;
        int keyLength = key.length();
        int keyIndex = 0;
        
        for (int i = 0; i < length; i++) {
            if (keyIndex >= keyLength) {
                keyIndex = 0;
            }
            data[i] = (byte) (data[i] ^ key.charAt(keyIndex));
            keyIndex++;
        }
        return data;
    }
    
    public static String encrypt(String plaintext, String key) {
        byte[] data = plaintext.getBytes();
        byte[] encrypted = xorCrypt(data, key);
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    public static String decrypt(String encodedStr, String key) {
        byte[] decoded = Base64.getDecoder().decode(encodedStr);
        byte[] decrypted = xorCrypt(decoded, key);
        return new String(decrypted);
    }
    
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java ChromeUpdaterCrypt <d|e> <string>");
            System.out.println("  d - Decode (decrypt) a Base64+XOR encoded string");
            System.out.println("  e - Encode (encrypt) a plaintext string");
            System.out.println();
            System.out.println("Examples:");
            System.out.println("  java ChromeUpdaterCrypt d \"Gh8=\"");
            System.out.println("  java ChromeUpdaterCrypt e \"OK\"");
            System.exit(1);
        }
        
        String command = args[0];
        String input = args[1];
        String key = "UTF-8";
        
        try {
            switch (command.toLowerCase()) {
                case "d":
                    String decoded = decrypt(input, key);
                    System.out.println(decoded);
                    break;
                    
                case "e":
                    String encoded = encrypt(input, key);
                    System.out.println(encoded);
                    break;
                    
                default:
                    System.err.println("Error: Unknown command '" + command + "'");
                    System.err.println("Use 'd' for decode or 'e' for encode");
                    System.exit(1);
            }
        } catch (IllegalArgumentException e) {
            System.err.println("Error: Invalid Base64 input for decoding");
            System.exit(1);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }
}
```

Example:

```
$ java ChromeUpdaterCrypt.java d ATwvXhg0JDYNWzQ6YVkYJyEoDVc7dD9CTSd0IkhOPDcjAw==
This app can't run on your device.
$ java ChromeUpdaterCrypt.java d Gh8=
OK
```

> Note: `ChromeUpdaterCrypt` is also available [here](https://github.com/gemesa/reversing-scripts).

### IOCs

> Note: the rules are available [here](https://github.com/gemesa/threat-detection-rules) as well.

#### YARA

> Note: the APK needs to be unzipped first.

```
rule fake_chrome_updater_xml_android {
  meta:
    description = "Fake Chrome updater main.xml (Android)"
    author = "Andras Gemes"
    date = "2025-11-18"
    sha256 = "59bb681961028642190f780266e2932a0f928b6ec44881165e1cecd0988c8029"
    ref1 = "https://shadowshell.io/fake-chrome-updater"
    ref2 = "https://bazaar.abuse.ch/sample/59bb681961028642190f780266e2932a0f928b6ec44881165e1cecd0988c8029/"

  strings:
    $0 = "Google Chrome Updater"
    // Your Chrome version is outdated! Chrome version: 65.1 (19 years ago!)
    $1 = /Your Chrome version is outdated! Chrome version: \d+\.\d+ \(\d+ years ago!\)/
    $2 = "Download and install update"

  condition:
    3 of them
}
```

```
rule fake_chrome_updater_dex_android {
  meta:
    description = "Fake Chrome updater classes*.dex (Android)"
    author = "Andras Gemes"
    date = "2025-11-18"
    sha256 = "59bb681961028642190f780266e2932a0f928b6ec44881165e1cecd0988c8029"
    ref1 = "https://shadowshell.io/fake-chrome-updater"
    ref2 = "https://bazaar.abuse.ch/sample/59bb681961028642190f780266e2932a0f928b6ec44881165e1cecd0988c8029/"

  strings:
    // This app can't run on your device.
    $0 = "ATwvXhg0JDYNWzQ6YVkYJyEoDVc7dD9CTSd0IkhOPDcjAw=="
    // OK
    $1 = "Gh8="
    // logcat -c
    $2 = "OTshTlkhdGtO"
    // logcat
    $3 = "OTshTlkh"
    // Logger got killed. Restarting.
    $4 = "GTshSl0ndCFCTHU/L0FUMDBoDWowJzJMSiE9KEoW"
    // Logger stopped.
    $5 = "GTshSl0ndDVZVyUkI0kW"

  condition:
    3 of them
}
```
