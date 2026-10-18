---
title: Reversing the Almanahe worm
published: true
---

## Table of contents

* toc placeholder
{:toc}

## Introduction

This post analyses a [worm/rootkit malware sample](https://www.virustotal.com/gui/file/f74399cc0be275376dad23151e3d0c2e2a1c966e6db6a695a05ec1a30551c0ad/details) using Ghidra. The primary goal is to identify and document the process injection techniques used by the binary, map them to MITRE ATT&CK TTPs and trace the infection lifecycle. Additionally, we provide YARA and Sigma detection rules targeting the identified injection behaviors.

## Executive summary

This is a worm that spreads by infecting EXE files on local drives, USB drives and network shares. The malware itself is a DLL pretending to be `linkinfo.dll`. This is a legit Windows library with the `Windows Volume Tracking` description. It proxies the real exports so nothing looks broken to the host process.

The malware uses two different process injection techniques (APC injection and thread hijacking) at different stages of its lifecycle to get its code running inside trusted processes.

## Hashes

```
$ mv f74399cc0be275376dad23151e3d0c2e2a1c966e6db6a695a05ec1a30551c0ad worm.dll

$ md5sum < worm.dll 
26f5d66b94d3bf161a896323f753a06b  -

$ sha1sum < worm.dll 
974ca8f4a4e92b31ecb23eb351da5a0027c0b764  -

$ sha256sum < worm.dll
f74399cc0be275376dad23151e3d0c2e2a1c966e6db6a695a05ec1a30551c0ad  -
```

## Infection lifecycle

The malware spreads by infecting EXE files on drives and network shares. When someone runs an infected EXE:

1. A shellcode stub runs first: decompresses the malware DLL, drops it to `%TEMP%\linkinfo.dll`.
2. Loads the DLL: `DllMain` checks "am I in explorer?". If not, it does nothing.
3. Calls ordinal 101: installs a rootkit driver, then APC-injects into explorer.exe (1. injection method).
4. Explorer loads the DLL: `DllMain` checks again "am I in explorer?". If yes, full activation.
5. Spawns 5 worker threads: file infector, network worm, browser injection, rootkit/AV killer, C2 handler.
6. Browser injection thread uses thread hijacking (2. injection method) to spawn hidden browsers for C2 traffic.
7. The shellcode restores the original EXE code and jumps to the real entry point.

The cycle repeats: the file infector thread searches drives looking for more EXEs to infect.

## The two injections

The two injection techniques serve completely different purposes at different stages:

| | APC injection | Thread hijacking |
|---|---|---|
| Purpose | Bootstrap into explorer (activation). | C2 communication. |
| When | Once, when an infected EXE runs. | Repeatedly, in a loop (so the malware always has a browser). |
| Target | explorer.exe | Default browser. |
| Why that target | Malware only activates inside explorer. | Network traffic looks normal from a browser. |
| Trigger | Shellcode stub calls ordinal 101. | Worker thread inside explorer. |

So simply put, APC injection is "the door into the house". Thread hijacking is "opening a window to talk to the outside".

## Technique 1: Thread execution hijacking

MITRE ATT&CK: [T1055.003 — Process Injection: Thread Execution Hijacking](https://attack.mitre.org/techniques/T1055/003/)

### How it works

First, it spawns a frozen browser (`FUN_10002232_create_suspended_browser`):
- Grabs the default browser path from `HKCR\htmlfile\shell\open\command` ([reference](https://stackoverflow.com/questions/29281552/how-to-verify-safely-if-the-default-browser-for-shellexec-is-ie)).
- Launches it with `CreateProcessA` using `CREATE_SUSPENDED` (flag `0x4`) ([reference](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)).

Then it hijacks the thread (`FUN_10002096_hijack_thread_inject_shellcode`):
- Calls `GetThreadContext` with `CONTEXT_FULL` (`0x10007`) to read the suspended thread's registers (e.g. EIP, the instruction pointer).
- Allocates a chunk of RWX memory inside the browser with `VirtualAllocEx` (`PAGE_EXECUTE_READWRITE`, `0x40`) ([reference](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)).
- Builds a small shellcode stub locally that calls `LoadLibraryA` with this DLL path, then calls ordinal 100 (`FUN_10001e4c_c2_comm`).
- Writes the whole shellcode blob into the browser's memory with `WriteProcessMemory`.
- Overwrites `ctx.Eip` to point at the shellcode, then commits it with `SetThreadContext`.
- Calls `ResumeThread`. The browser runs the shellcode instead of its normal startup code.

What actually gets executed: The shellcode calls `LoadLibraryA` with the malware DLL path, then calls ordinal 100 (`FUN_10001e4c_c2_comm`). The malware is now doing its network activity from inside the browser process.

API call sequence:

```
CreateProcessA(..., CREATE_SUSPENDED, ...)
GetThreadContext(hThread, CONTEXT_FULL)
VirtualAllocEx(hProcess, ..., PAGE_EXECUTE_READWRITE)
WriteProcessMemory(hProcess, shellcode + DLL path)
SetThreadContext(hThread, ...)   // EIP --> shellcode
ResumeThread(hThread)
```

### Callgraph

```
entry (DllMain, DLL_PROCESS_ATTACH)
  - FUN_10005303_dll_init
    - FUN_10003f3c_load_real_linkinfo
    - FUN_100052a2_check_if_explorer
      - CreateThread --> FUN_1000515e_main_thread
        - FUN_10003edc_vm_check
        - CreateMutex("PNP#DMUTEX#1#DL5")
        - FUN_10003aa8_prepare_payload  // compress own DLL
        - FUN_100010bb_peb_unlink_self  // hide DLL from module lists
        - CreateThread --> FUN_100042cd_hosts_and_inject_browser
          - [loop]
            - FUN_10002232_create_suspended_browser
              - read default browser from HKCR\htmlfile\shell\open\command
              - CreateProcessA(..., CREATE_SUSPENDED)
              - FUN_10002096_hijack_thread_inject_shellcode
                - GetThreadContext(CONTEXT_FULL)
                - VirtualAllocEx(PAGE_EXECUTE_READWRITE)
                - WriteProcessMemory (shellcode + DLL path + ordinal 100 RVA)
                - SetThreadContext (EIP --> shellcode)
                - ResumeThread
```

## Technique 2: APC injection

MITRE ATT&CK: [T1055.004 — Process Injection: Asynchronous Procedure Call](https://attack.mitre.org/techniques/T1055/004/)

### How it works

This path only executes when someone runs an infected EXE. The shellcode stub drops the malware DLL, loads it and calls ordinal 101.

Ordinal 101 (`FUN_10003e12_driver_and_apc_entry`) is just two instructions:
```
CALL FUN_100036e4_drop_and_load_rootkit_driver
JMP  FUN_100039fb_apc_injection_entry
```

APC injection:

- Checks if mutex `PNP#DMUTEX#1#DL5` exists. If it does, the malware is already in explorer, so return early (`FUN_100039fb_apc_injection_entry`).
- Enables `SeDebugPrivilege` (requires admin) via `OpenProcessToken` --> `LookupPrivilegeValueA` --> `AdjustTokenPrivileges`.
- Takes a process snapshot, walks it to find the PID of `explorer.exe`.
- Takes a thread snapshot, collects every thread ID of explorer.
- Opens explorer with `PROCESS_ALL_ACCESS` (`FUN_10003919_apc_inject_into_explorer`).
- Allocates memory in explorer, writes the malware DLL path into it.
- For each explorer thread: opens it with `THREAD_ALL_ACCESS` and calls `QueueUserAPC(LoadLibraryA, hThread, dllPath)`.

The next time any explorer thread enters an alertable wait (which happens often), Windows runs the queued APC. This calls `LoadLibraryA`, which loads the DLL and triggers `DllMain` inside explorer. Hitting every thread guarantees almost immediate execution.

API call sequence:

```
AdjustTokenPrivileges(SeDebugPrivilege)
CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) // find explorer.exe PID
CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)  // get all explorer threads
OpenProcess(PROCESS_ALL_ACCESS, explorerPID)
VirtualAllocEx(...)
WriteProcessMemory(hProcess, dllPath)
for each thread:
  OpenThread(THREAD_ALL_ACCESS, threadID)
  QueueUserAPC(LoadLibraryA, hThread, remoteAddr)
```

### Callgraph

```
Infected EXE runs:
  - Shellcode stub (DAT_100062a8, appended to infected EXE)
    - walks SEH chain, finds kernel32.dll base
    - resolves APIs from kernel32 export table (GetProcAddress, LoadLibraryA, CreateFileA, WriteFile, etc.)
    - decompresses malware DLL from appended data
    - drops to disk as %TEMP%\linkinfo.dll
    - LoadLibraryA("linkinfo.dll") --> DllMain --> not explorer --> does nothing
    - GetProcAddress(hModule, ordinal 101)
    - call ordinal 101 (FUN_10003e12_driver_and_apc_entry):
      - FUN_100036e4_drop_and_load_rootkit_driver // IsDrv118.sys
      - FUN_100039fb_apc_injection_entry
        - CreateMutex("PNP#DMUTEX#1#DL5") // skip if already exists
        - FUN_100011bd_enable_debug_privilege
          - OpenProcessToken --> LookupPrivilegeValueA --> AdjustTokenPrivileges
        - FUN_10003919_apc_inject_into_explorer
          - FUN_100037be_find_explorer_pid
            - CreateToolhelp32Snapshot --> Process32First/Next --> match "explorer.exe"
          - FUN_10003886_enumerate_threads_by_pid
            - CreateToolhelp32Snapshot --> Thread32First/Next --> collect thread IDs
          - OpenProcess(PROCESS_ALL_ACCESS, explorerPID)
          - VirtualAllocEx + WriteProcessMemory (DLL path)
          - for each thread:
            - OpenThread --> QueueUserAPC(LoadLibraryA, hThread, dllPath)
    - explorer loads DLL --> DllMain sees "I am in explorer" --> full activation
    - restores original overwritten code bytes to EXE's code section
    - jmp to original entry point --> program runs normally
```

## IOCs

### YARA

> Note: the rules are available [here](https://github.com/gemesa/threat-detection-rules) as well.

```
$ yara worm.yar ../tmp/worm.dll
thread_execution_hijacking_suspended_browser ../tmp/worm.dll
APC_injection_explorer_LoadLibrary ../tmp/worm.dll
linkinfo_DLL_injection_shellcode ../tmp/worm.dll
```

```
{% include_file external/threat-detection-rules/almanahe/worm.yar %}
```

### Sigma rules

> Note: the rules are available [here](https://github.com/gemesa/threat-detection-rules) as well.

These rules are verified via `sigma check file.yml` but not tested otherwise. Additionally, they are formatted via `npx prettier --write file.yml`.

```yml
{% include_file external/threat-detection-rules/almanahe/worm.yml %}
```
