---
title: Reversing the QBot interceptor
published: true
---

## Table of contents

* toc placeholder
{:toc}

## Introduction

This analysis covers a [QBot traffic interceptor malware sample](https://www.virustotal.com/gui/file/7fc3f5e06bbaad459af71d3c0d28c51b7802546984f886f14a1b12a779fff6f8/details) using Ghidra. The primary goals are to identify the hooking framework, document all traffic interception subroutines and identify string obfuscation methods. Detection rules are provided as YARA and capa.

## Executive summary

This sample is a QBot man-in-the-browser injector DLL that comes packed with two encrypted payloads (32-bit and 64-bit). It resolves all its API calls dynamically, looks through processes and injects the right payload. Once the payload is injected, it drops inline hooks across different areas: WinInet (HTTP interception), Chrome's BoringSSL, Firefox's NSS/NSPR stack, keystroke and clipboard grabbing, DNS redirection and connection-level functions.

## Hashes

Injector DLL:

```
$ mv 7fc3f5e06bbaad459af71d3c0d28c51b7802546984f886f14a1b12a779fff6f8 qbot.dll

$ md5sum < qbot.dll
a59a669a40ecdfdf9d3ae0c3f2b2db34  -

$ sha1sum < qbot.dll
577522512506487c63a372bbda77be966c23cbd1  -

$ sha256sum < qbot.dll
7fc3f5e06bbaad459af71d3c0d28c51b7802546984f886f14a1b12a779fff6f8  -
```

Payload (32-bit):

```
$ md5sum < payload_32bit.dll 
6e393f179b71d6ac848668e26c2cd236  -

$ sha1sum < payload_32bit.dll
50cf91ee5ff2c723ce18745cff0c0f5648e3a5e5  -

$ sha256sum < payload_32bit.dll
4229f9f1c316c207783f484ba2bc518074180f87ddb01e47328a4f6f23f97089  -
```

Payload (64-bit):

```
$ md5sum < payload_64bit.dll  
c537b90fdaaf77d1d8d5502b5f1f8041  -

$ sha1sum < payload_64bit.dll
ecf5afa76e9e41174e31546450ba59391025ac0b  -

$ sha256sum < payload_64bit.dll
9155b45cc143122bf57cad69c8b84cccdea63a45e18745df0f6076cacc316399  -
```

## Architecture

| Component | Location | Role |
|---|---|---|
| Injector DLL | Sample itself | API resolution, process enumeration, payload injection. |
| 32-bit payload | `RES_DATA_1` (XOR-encrypted) | Hooking engine + all interception. |
| 64-bit payload | `RES_DATA_2` (XOR-encrypted) | Same, for 64-bit targets. |

## Hooking framework

The inline hooking engine lives in the payloads. Both architectures use the same design but there are some minor differences (e.g. because of the different pointer size). These differences are not discussed here. Because of time limitations, only the 32-bit variant is discussed.

Hook installation: `FUN_10002902_install_hook` loops through 5 encrypted descriptor tables containing DLL/API name pairs. It takes 2 args: number of entries in the table and the address of the table. Each table is an array of the following struct:

```c
struct hook_entry {
    DWORD dll_blob_offset;      // 0x00  encrypted string offset --> DLL name
    DWORD api_blob_offset;      // 0x04  encrypted string offset --> API name
    PVOID hook_function;        // 0x08  function to redirect to
    PVOID *original_slot;       // 0x0C  where to save original pointer
    BYTE  pad[5];               // 0x10
};  // 21 bytes
```

Hook tables (table entries are added as comment for simplicity):

```c
void FUN_10002a0f_install_zwresumethread_hook(void)

{
                    /* ntdll.dll/ZwResumeThread */
  FUN_10002902_install_hooks(1,0x100249d4);
  return;
}
```
```c
void FUN_100029f5_install_core_hooks(void)

{
                    /* ntdll.dll/LdrLoadDll
                       ws2_32.dll/WSAConnect
                       ws2_32.dll/connect
                       ws2_32.dll/WSASend
                       ws2_32.dll/send
                       dnsapi.dll/DnsQuery_A
                       dnsapi.dll/DnsQuery_W
                       dnsapi.dll/Query_Main
                       user32.dll/TranslateMessage
                       user32.dll/GetClipboardData */
  FUN_10002902_install_hooks(10,0x100249f0);
  return;
}
```
```c
void FUN_10002a02_install_wininet_hooks(void)

{
                    /* HttpSendRequestA
                       HttpSendRequestW
                       InternetReadFile
                       InternetReadFileExA
                       InternetCloseHandle
                       InternetQueryDataAvailable
                       HttpOpenRequestA
                       HttpOpenRequestW
                       HttpSendRequestExW
                       InternetWriteFile */
  FUN_10002902_install_hooks(10,0x10024b20);
  return;
}
```
```c
void FUN_10002cf3_install_firefox_ssl_hooks(void)

{
  int iVar1;
  
  iVar1 = FUN_1000a1f0();
  if (iVar1 != 0) {
                    /* nss3/PR_OpenTCPSocket
                       nss3/PR_Read
                       nss3/PR_Write
                       nss3/PR_Close
                       nspr4/PR_OpenTCPSocket
                       nspr4/PR_Read
                       nspr4/PR_Write
                       nspr4/PR_Close */
    FUN_10002902_install_hooks(8,0x10024bf8);
    return;
  }
  return;
}
```
```c
void FUN_10002a1c_install_message_loop_hooks(void)

{
                    /* GetMessageA
                       GetMessageW
                       PeekMessageA
                       PeekMessageW */
  FUN_10002902_install_hooks(4,0x10024ac8);
  return;
}
```
It also hooks Chrome functions but since Chrome has its own TLS stack (BoringSSL), the payload handles this with a signature-based approach in `FUN_10002c8c_install_chrome_hooks`. The signature table (`DAT_10024d38_chrome_sig_table`) is available in `FUN_10001000_return_chrome_sig_table` and consists of 20 entries. Each entry contains a byte pattern for a specific Chrome version's BoringSSL implementation.

### YARA

> Note: the rules are available [here](https://github.com/gemesa/threat-detection-rules) as well.

```
$ yara qbot_hooks.yar ../tmp/payload_32bit.dll 
qbot_install_hooks ../tmp/payload_32bit.dll
qbot_install_chrome_hooks ../tmp/payload_32bit.dll
qbot_chrome_boringssl_signature_table ../tmp/payload_32bit.dll
qbot_hook_table_firefox_ssl ../tmp/payload_32bit.dll
qbot_hook_table_wininet ../tmp/payload_32bit.dll
qbot_hook_table_core_0 ../tmp/payload_32bit.dll
qbot_hook_table_core_1 ../tmp/payload_32bit.dll
qbot_hook_table_messageloop ../tmp/payload_32bit.dll
```

```
{% include_file external/threat-detection-rules/qbot/qbot_hooks.yar %}
```

### `capa`

> Note: the rules are available [here](https://github.com/gemesa/threat-detection-rules) as well.

```
$ capa -r rules/ ../tmp/payload_32bit.dll 
┌───────────┬──────────────────────────────────────────────────────────────────┐
│ md5       │ 6e393f179b71d6ac848668e26c2cd236                                 │
│ sha1      │ 50cf91ee5ff2c723ce18745cff0c0f5648e3a5e5                         │
│ sha256    │ 4229f9f1c316c207783f484ba2bc518074180f87ddb01e47328a4f6f23f97089 │
│ analysis  │ static                                                           │
│ os        │ windows                                                          │
│ format    │ pe                                                               │
│ arch      │ i386                                                             │
│ path      │ /home/gemesa/git-repos/group-ib/tmp/payload_32bit.dll            │
└───────────┴──────────────────────────────────────────────────────────────────┘
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ ATT&CK Tactic             ┃ ATT&CK Technique                                 ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ COLLECTION                │ Man in the Browser [T1185]                       │
│ DEFENSE EVASION           │ Obfuscated Files or Information [T1027]          │
│ EXECUTION                 │ Native API [T1106]                               │
└───────────────────────────┴──────────────────────────────────────────────────┘
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ MBC Objective        ┃ MBC Behavior                                          ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ ANTI-STATIC ANALYSIS │ Obfuscated Files or Information::Encryption-Standard  │
│                      │ Algorithm [B0001.005]                                 │
│ COLLECTION           │ API Hooking [F0015]                                   │
└──────────────────────┴───────────────────────────────────────────────────────┘
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Capability                                     ┃ Namespace                   ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ install API hooks using encrypted function     │ persistence/hooking         │
│ references                                     │                             │
│ install hooks in Chrome browser via PE section │ persistence/hooking/browser │
│ scanning                                       │                             │
└────────────────────────────────────────────────┴─────────────────────────────┘
```

```yml
{% include_file external/threat-detection-rules/qbot/hooking-0.yml %}
```

```yml
{% include_file external/threat-detection-rules/qbot/hooking-1.yml %}
```

## Traffic interception

The traffic interception related subroutines can be collected following the hook functions detailed in the previous chapter. Revisiting the following structure, we know that the hook function is the 3. member in the struct (1-indexed).

```c
struct hook_entry {
    DWORD dll_blob_offset;      // 0x00  encrypted string offset --> DLL name
    DWORD api_blob_offset;      // 0x04  encrypted string offset --> API name
    PVOID hook_function;        // 0x08  function to redirect to
    PVOID *original_slot;       // 0x0C  where to save original pointer
    BYTE  pad[5];               // 0x10
};  // 21 bytes
```

Based on this, we can gather the functions from the hook descriptor blocks (see an example below). The traffic interception functions are a subset of these hook functions (+ possibly other functions called by these).

```
                             DAT_100249f0_core_hooks                         XREF[3]:     FUN_100026dc:100027f9(*), 
                                                                                          FUN_100029f5_install_core_hooks:
                                                                                          FUN_10002d56_init_hook_slots:100
        100249f0 2e 07 00 00     ddw        72Eh
                             LdrLoadDll
        100249f4 e4 36 00 00     ddw        36E4h
        100249f8 dc 26 00 10     ddw        100026DCh
        100249fc 78 8a 02 10     ddw        10028A78h
        10024a00 00 00 00        ??[5]
                 00 00
        10024a05 6a 1d 00 00     ddw        1D6Ah
                             WSAConnect
        10024a09 08 06 00 00     ddw        608h
        10024a0d 1f f0 00 10     ddw        1000F01Fh
        10024a11 48 b4 02 10     ddw        1002B448h
        10024a15 00 00 00        ??[5]
                 00 00
        10024a1a 6a 1d 00 00     ddw        1D6Ah
                             connect
        10024a1e 62 19 00 00     ddw        1962h
        10024a22 9c f0 00 10     ddw        1000F09Ch
        10024a26 54 d5 02 10     ddw        1002D554h
        10024a2a 00 00 00        ??[5]
                 00 00
        10024a2f 6a 1d 00 00     ddw        1D6Ah
                             WSASend
        10024a33 e1 28 00 00     ddw        28E1h
        10024a37 0d f1 00 10     ddw        1000F10Dh
        10024a3b 44 b4 02 10     ddw        1002B444h
        10024a3f 00 00 00        ??[5]
                 00 00
        10024a44 6a 1d 00 00     ddw        1D6Ah
                             send
        10024a48 78 36 00 00     ddw        3678h
        10024a4c 90 f1 00 10     ddw        1000F190h
        10024a50 4c b4 02 10     ddw        1002B44Ch
        10024a54 00 00 00        ??[5]
                 00 00
        10024a59 23 09 00 00     ddw        923h
                             DnsQuery_A
        10024a5d 1c 33 00 00     ddw        331Ch
        10024a61 91 25 00 10     ddw        10002591h
        10024a65 68 8a 02 10     ddw        10028A68h
        10024a69 00 00 00        ??[5]
                 00 00
        10024a6e 23 09 00 00     ddw        923h
                             DnsQuery_W
        10024a72 03 27 00 00     ddw        2703h
        10024a76 e8 25 00 10     ddw        100025E8h
        10024a7a 70 8a 02 10     ddw        10028A70h
        10024a7e 00 00 00        ??[5]
                 00 00
        10024a83 23 09 00 00     ddw        923h
                             Query_Main
        10024a87 5f 04 00 00     ddw        45Fh
        10024a8b 7d 26 00 10     ddw        1000267Dh
        10024a8f 6c 8a 02 10     ddw        10028A6Ch
        10024a93 00 00 00        ??[5]
                 00 00
        10024a98 8e 33 00 00     ddw        338Eh
                             TranslateMessage
        10024a9c 60 31 00 00     ddw        3160h
        10024aa0 a1 8e 00 10     ddw        10008EA1h
        10024aa4 b4 8a 02 10     ddw        10028AB4h
        10024aa8 00 00 00        ??[5]
                 00 00
        10024aad 8e 33 00 00     ddw        338Eh
                             GetClipboardData
        10024ab1 fa 06 00 00     ddw        6FAh
        10024ab5 d0 23 00 10     ddw        100023D0h
        10024ab9 64 8a 02 10     ddw        10028A64h
```

Here are the hook functions from the previous chapter that appear in the hook descriptor blocks:

WinInet HTTP interception:

| Hooked API | Hook function | Descriptor table |
|---|---|---|
| HttpSendRequestA | `0x1000DFAF` | wininet_hooks |
| HttpSendRequestW | `0x1000E009` | wininet_hooks |
| InternetReadFile | `0x1000E3B9` | wininet_hooks |
| InternetReadFileExA | `0x1000E4A8` | wininet_hooks |
| InternetCloseHandle | `0x1000D969` | wininet_hooks |
| InternetQueryDataAvailable | `0x1000D8CB` | wininet_hooks |
| HttpOpenRequestA | `0x1000E745` | wininet_hooks |
| HttpOpenRequestW | `0x1000E7AA` | wininet_hooks |
| HttpSendRequestExW | `0x1000E974` | wininet_hooks |
| InternetWriteFile | `0x1000E9BD` | wininet_hooks |

Winsock connection interception:

| Hooked API | Hook function | Descriptor table |
|---|---|---|
| WSAConnect | `0x1000F01F` | core_hooks |
| connect | `0x1000F09C` | core_hooks |
| WSASend | `0x1000F10D` | core_hooks |
| send | `0x1000F190` | core_hooks |

DNS redirection:

| Hooked API | Hook function | Descriptor table |
|---|---|---|
| DnsQuery_A | `0x10002591` | core_hooks |
| DnsQuery_W | `0x100025E8` | core_hooks |
| Query_Main | `0x1000267D` | core_hooks |

Firefox NSS/NSPR interception:

| Hooked API | Hook function | Descriptor table |
|---|---|---|
| PR_OpenTCPSocket | `0x1000A6EF` | firefox_ssl_hooks |
| PR_Read | `0x1000AD91` | firefox_ssl_hooks |
| PR_Write | `0x1000AB38` | firefox_ssl_hooks |
| PR_Close | `0x1000A70E` | firefox_ssl_hooks |

Keystroke and clipboard capture:

| Hooked API | Hook function | Descriptor table |
|---|---|---|
| TranslateMessage | `0x10008EA1` | core_hooks |
| GetClipboardData | `0x100023D0` | core_hooks |

GetMessage/PeekMessage hooks:

| Hooked API | Hook function | Descriptor table |
|---|---|---|
| GetMessageA | `0x10008F57` | message_loop_hooks |
| GetMessageW | `0x10008F95` | message_loop_hooks |
| PeekMessageA | `0x10008FD3` | message_loop_hooks |
| PeekMessageW | `0x10009014` | message_loop_hooks |

Chrome BoringSSL hooks are not in descriptors. They are installed via PE `.text` section signature scanning.

## String obfuscation

### `FUN_100147c5_decrypt_string`

Decryption function in the payload. Used for all DLL names, API names, configuration data. Decrypted strings freed via `FUN_10014863` after use.

It is a rolling XOR decryptor with a 64-byte key. `DAT_100244c0` is the 64-byte static XOR key and `DAT_1002d55c` is the encrypted blob (up to `0x36F4` bytes). Every encrypted string in the payload is just identified by its integer offset into the blob. The callers pass constants like `0x1D29`, `0x338E`, `0x1EC`, etc.

```c
undefined * FUN_100147c5_decrypt_string(int param_1)

{
  byte *pbVar1;
  byte *pbVar2;
  undefined *puVar3;
  uint uVar4;
  int iVar5;
  uint local_8;
  
  local_8 = 0;
  uVar4 = param_1;
  if ((DAT_1002d55c != 0) || (DAT_1002d55c = FUN_10013e0d(), DAT_1002d55c != 0)) {
    for (; uVar4 < 0x36f4; uVar4 = uVar4 + 1) {
      if ((&DAT_100244c0)[uVar4 & 0x3f] == *(char *)(DAT_1002d55c + uVar4)) {
        local_8 = uVar4 - param_1;
        break;
      }
    }
    puVar3 = (undefined *)FUN_10013db6_heapalloc(local_8 + 1);
    if (puVar3 != (undefined *)0x0) {
      uVar4 = 0;
      if (local_8 == 0) {
        return puVar3;
      }
      iVar5 = DAT_1002d55c + param_1;
      do {
        pbVar1 = puVar3 + uVar4;
        pbVar2 = (byte *)(iVar5 + uVar4);
        uVar4 = uVar4 + 1;
        *pbVar1 = (&DAT_100244c0)[(uint)(pbVar1 + (param_1 - (int)puVar3)) & 0x3f] ^ *pbVar2;
      } while (uVar4 < local_8);
      return puVar3;
    }
  }
  return &DAT_1002d5c4;
}
```

### `FUN_10014863_wipe_string`

Decrypted strings are zeroed and freed after use.

### YARA

> Note: the rules are available [here](https://github.com/gemesa/threat-detection-rules) as well.

```
$ yara qbot_string_decryptor.yar ../tmp/payload_32bit.dll 
qbot_string_decryptor ../tmp/payload_32bit.dll
```

```
{% include_file external/threat-detection-rules/qbot/string-obf.yar %}
```
