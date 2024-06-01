---
title: Diving into shellcodes
published: true
---

Shellcodes are typically used in the context of exploiting a vulnerability in software, such as a buffer overflow. In an exploit, the shellcode is the payload that gets executed as a result of the vulnerability being exploited. Once the vulnerability is exploited and control of the process is hijacked, the shellcode is executed.

In this post I will show you how to generate and execute a simple messagebox shellcode both in C and Rust. The source code can be found [here](https://github.com/gemesa/shadow-shell).

## C

### msfvenom

Various payloads can be generated using [msfvenom](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html). We will choose a simple Windows messagebox for now:

```
$ msfconsole
...
msf6 > msfvenom -p windows/x64/messagebox --list-options
...
Basic options:
Name      Current Setting   Required  Description
----      ---------------   --------  -----------
EXITFUNC  process           yes       Exit technique (Accepted: '', seh, thread, process, none)
ICON      NO                yes       Icon type (Accepted: NO, ERROR, INFORMATION, WARNING, QUESTION)
TEXT      Hello, from MSF!  yes       Messagebox Text
TITLE     MessageBox        yes       Messagebox Title

Description:
    Spawn a dialog via MessageBox using a customizable title, text & icon
...
msf6 > msfvenom -p windows/x64/messagebox -b \x00 -f c
[*] exec: msfvenom -p windows/x64/messagebox -b \x00 -f c

Overriding user environment variable 'OPENSSL_CONF' to enable legacy functions.
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
Found 3 compatible encoders
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=309, char=0x78)
Attempting to encode payload with 1 iterations of x64/xor
x64/xor succeeded with size 367 (iteration=0)
x64/xor chosen with final size 367
Payload size: 367 bytes
Final size of c file: 1573 bytes
unsigned char buf[] = 
"\x48\x31\xc9\x48\x81\xe9\xd7\xff\xff\xff\x48\x8d\x05\xef"
"\xff\xff\xff\x48\xbb\x3e\x73\x95\x61\xa9\xab\x04\x18\x48"
"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xc2\x3b\x14"
"\x85\x59\x54\xfb\xe7\xd6\xa3\x95\x61\xa9\xea\x55\x59\x6e"
"\x21\xc4\x37\xe1\x9a\xd6\x7d\x76\xf8\xc7\x01\x97\xe3\x8f"
"\x4a\x26\x4d\xdd\xea\xfb\x8b\x3a\x50\xb5\x01\xc5\x5f\xe1"
"\xa4\xb3\x52\x74\x3e\xa4\xa8\xe1\x9a\xc4\xb4\x02\x12\xe9"
"\x63\x85\x8b\x45\xd9\xf7\x7e\xd4\x60\x68\x49\xe9\x4a\x7f"
"\x22\xab\x29\x22\xf9\x24\x26\xb5\x31\xa9\x29\xa8\x7b\x3a"
"\x93\xbe\xfb\x95\x61\xa9\xe3\x81\xd8\x4a\x1c\xdd\x60\x79"
"\xfb\x3a\x93\x76\x6b\xab\x25\x22\xeb\x24\x51\x3f\xa3\x76"
"\x3d\xe1\x54\xcd\x26\x7f\xf8\xa1\xe9\xe1\xaa\xd2\x55\x0f"
"\xba\xdd\x50\x69\x07\x45\xd9\xf7\x7e\xd4\x60\x68\x93\xe4"
"\x6d\xcf\x4d\xd9\x62\xe5\x8f\x0c\x5d\x07\xa2\xe0\xb7\xf1"
"\x95\x40\x93\x7e\x57\xdc\x60\x79\xcd\x3a\x59\xb5\x7f\xdd"
"\x5f\xed\x20\x44\x04\x77\x72\x45\x5f\xe8\x20\x00\x90\x76"
"\x72\x45\x20\xf1\xea\x5c\x46\x67\x29\xd4\x39\xe8\xf2\x45"
"\x42\x76\xf0\x79\x41\xe8\xf9\xfb\xf8\x66\x32\xcc\x3b\x97"
"\xe3\x8f\x0a\xd7\x3a\x6a\x9e\x56\xf6\x3a\x50\xb3\xfe\xbf"
"\x60\xa9\xab\x45\xa2\x72\x04\xb3\x66\x56\x7e\x4d\xdf\xff"
"\x73\x95\x61\xa9\x95\x4c\x95\xab\x7d\x94\x61\xa9\x95\x48"
"\x95\xbb\x6c\x94\x61\xa9\xe3\x35\xd1\x7f\xc9\xd0\xe2\xff"
"\xac\xfb\xcd\x76\x42\x5c\x20\x13\x5b\xb1\xba\x68\x8c\x40"
"\x29\xcc\xc7\x68\x77\x12\x53\xf3\x13\xc6\xc6\x24\x55\x6d"
"\x35\xb4\x61\xe4\xce\x77\x6b\x5f\x14\xf0\x23\xc6\xd3\x04"
"\x6d\x4d\x16\xe7\x52\x9b\x85\x60\x74\x52\x73\x95\x61\xa9"
"\xab\x04\x18";
```

### POC code

Now we can copy and paste the previously generated shellcode into our POC C code:

```
#include <stdio.h>
#include <windows.h>

int main()
{
	unsigned char shellcode[] =
		"\x48\x31\xc9\x48\x81\xe9\xd7\xff\xff\xff\x48\x8d\x05\xef"
		"\xff\xff\xff\x48\xbb\x53\xff\xa0\x36\xf2\xd0\x80\x91\x48"
		"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xaf\xb7\x21"
		"\xd2\x02\x2f\x7f\x6e\xbb\x2f\xa0\x36\xf2\x91\xd1\xd0\x03"
		"\xad\xf1\x60\xba\xe1\x52\xf4\x1b\x74\xf2\x56\xcc\x98\x0b"
		"\xc3\x4b\xc1\xe8\xbd\xa0\xf0\xbe\xd9\xd8\x8d\xf0\x08\xba"
		"\xdf\x37\xdb\x19\xb2\x91\xff\xba\xe1\x40\x3d\x6f\x9e\xdc"
		"\x34\xde\xf0\xc1\x50\x9a\xf2\xe1\x37\x33\x32\x6d\xc3\x12"
		"\xae\x9e\x7e\x79\x82\xa0\xaf\xd8\xbd\x9c\x7e\xf3\x00\xbe"
		"\x1a\xd3\x77\xa0\x36\xf2\x98\x05\x51\x27\x90\xe8\x37\x22"
		"\x80\xbe\x1a\x1b\xe7\x9e\x72\x79\x90\xa0\xd8\x52\x2f\x43"
		"\x6a\xba\x2f\x49\xaf\x12\x74\x94\xbe\xba\xd1\x56\xdc\x62"
		"\x36\xe8\x07\x32\x7c\xc1\x50\x9a\xf2\xe1\x37\x33\xe8\x60"
		"\xe4\xa2\xc1\xec\x35\xbe\xf4\x88\xd4\x6a\x2e\xd5\xe0\xaa"
		"\xee\xc4\x1a\x13\xdb\xe9\x37\x22\xb6\xbe\xd0\xd8\xf3\xe8"
		"\x08\xb6\x5b\xc0\x8d\x1a\xfe\x70\x08\xb3\x5b\x84\x19\x1b"
		"\xfe\x70\x77\xaa\x91\xd8\xcf\x0a\xa5\xe1\x6e\xb3\x89\xc1"
		"\xcb\x1b\x7c\x4c\x16\xb3\x82\x7f\x71\x0b\xbe\xf9\x6c\xcc"
		"\x98\x0b\x83\xba\xb6\x5f\xc9\x0d\x8d\xbe\xd9\xde\x72\x8a"
		"\x37\xf2\xd0\xc1\x2b\x1f\x88\x86\x31\x0d\x05\xc9\x56\x92"
		"\xff\xa0\x36\xf2\xee\xc8\x1c\xc6\xf1\xa1\x36\xf2\xee\xcc"
		"\x1c\xd6\xe0\xa1\x36\xf2\x98\xb1\x58\x12\x45\xe5\xb5\xa4"
		"\xd7\x7f\x44\x1b\xce\x69\x77\x48\x20\x35\x33\x05\x00\x75"
		"\x7e\x97\xbc\xec\xfe\x7f\xdf\xc6\x44\x9d\xbd\xa0\xdc\x00"
		"\xb9\x81\x36\xbf\xb5\xf3\xe2\x32\x98\xc5\x74\x9d\xa8\x80"
		"\xe4\x20\x9a\xd2\x05\xc0\xfe\xe4\xfd\x3f\xff\xa0\x36\xf2"
		"\xd0\x80\x91";

	printf("payload size: %i", sizeof shellcode - 1);

	LPVOID lpAlloc = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (lpAlloc == NULL)
	{
		puts("VirtualAlloc failed!");
		return 1;
	}

	memcpy(lpAlloc, shellcode, sizeof shellcode);

	((void(*)())lpAlloc)();

	return 0;
}
```

Key notes:
- `VirtualAlloc()` allows us to allocate memory with code execution enabled (`PAGE_EXECUTE_READWRITE`)
- `memcpy()` copies our shellcode into the memory allocated by `VirtualAlloc()`
- `((void(*)())lpAlloc)();` executes the code pointed to by `lpAlloc` (which is our shellcode)
- we use `sizeof shellcode - 1` instead of `strlen(shellcode)` because the generated shellcode contains a `\x00` character (even though we specified `-b \x00`)

Now compile the code (I am using Fedora so I have to cross-compile for Windows):

```
$ sudo dnf install mingw64-gcc mingw64-gcc-c++
...
$ x86_64-w64-mingw32-gcc sh.c -o msg.exe
```

### Testing our shellcode

Since I am using Linux I need either a Windows VM or [Wine](https://www.winehq.org/) to run `msg.exe`:

```
$ wine msg.exe
002c:fixme:winediag:loader_init wine-staging 8.19 is a testing version containing experimental patches.
002c:fixme:winediag:loader_init Please mention your exact version when filing bug reports on winehq.org.
0088:fixme:wineusb:query_id Unhandled ID query type 0x5.
0088:fixme:hid:handle_IRP_MN_QUERY_ID Unhandled type 00000005
0088:fixme:hid:handle_IRP_MN_QUERY_ID Unhandled type 00000005
0088:fixme:hid:handle_IRP_MN_QUERY_ID Unhandled type 00000005
0088:fixme:hid:handle_IRP_MN_QUERY_ID Unhandled type 00000005
payload size: 367
```

Our messagebox will also pop up:

![messagebox]({{site.baseurl}}/assets/msf-msg.png)

## Rust

### msfvenom

We choose the same messagebox (but with Rust format: `-f rust`):

```
$ msfconsole
...
msf6 > msfvenom -p windows/x64/messagebox --list-options
...
Basic options:
Name      Current Setting   Required  Description
----      ---------------   --------  -----------
EXITFUNC  process           yes       Exit technique (Accepted: '', seh, thread, process, none)
ICON      NO                yes       Icon type (Accepted: NO, ERROR, INFORMATION, WARNING, QUESTION)
TEXT      Hello, from MSF!  yes       Messagebox Text
TITLE     MessageBox        yes       Messagebox Title

Description:
    Spawn a dialog via MessageBox using a customizable title, text & icon
...
msf6 > msfvenom -p windows/x64/messagebox -b \x00 -f rust
[*] exec: msfvenom -p windows/x64/messagebox -b \x00 -f rust

Overriding user environment variable 'OPENSSL_CONF' to enable legacy functions.
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
Found 3 compatible encoders
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=309, char=0x78)
Attempting to encode payload with 1 iterations of x64/xor
x64/xor succeeded with size 367 (iteration=0)
x64/xor chosen with final size 367
Payload size: 367 bytes
Final size of rust file: 1890 bytes
let buf: [u8; 367] = [0x48,0x31,0xc9,0x48,0x81,0xe9,0xd7,
0xff,0xff,0xff,0x48,0x8d,0x05,0xef,0xff,0xff,0xff,0x48,0xbb,
0xcb,0xc5,0xba,0x88,0x36,0x92,0x0c,0x5b,0x48,0x31,0x58,0x27,
0x48,0x2d,0xf8,0xff,0xff,0xff,0xe2,0xf4,0x37,0x8d,0x3b,0x6c,
0xc6,0x6d,0xf3,0xa4,0x23,0x15,0xba,0x88,0x36,0xd3,0x5d,0x1a,
0x9b,0x97,0xeb,0xde,0x7e,0xa3,0xde,0x3e,0x83,0x4e,0xe8,0xe8,
0x08,0xda,0x87,0x09,0xd3,0xfb,0xf2,0x03,0x64,0xb2,0x32,0x13,
0x40,0xb7,0xea,0xb6,0x7e,0x9d,0xbb,0x11,0x81,0x88,0x8b,0x41,
0x7e,0xa3,0xcc,0xf7,0xf7,0xa4,0xc6,0x8a,0x1a,0xb2,0x4d,0x9a,
0x02,0xc8,0xfb,0x89,0xf7,0x70,0xe1,0x09,0x8a,0x94,0x84,0xc0,
0xbd,0xc0,0x2c,0x65,0x40,0x87,0x86,0xc0,0x37,0x42,0x32,0xd0,
0x4b,0x4d,0xba,0x88,0x36,0xda,0x89,0x9b,0xbf,0xaa,0xf2,0x89,
0xe6,0xc2,0x32,0xd0,0x83,0xdd,0x84,0xcc,0xbd,0xd2,0x2c,0x12,
0xca,0x15,0x59,0xd4,0x7e,0x6d,0xc5,0x65,0x8a,0x4e,0x8e,0x00,
0x7e,0x93,0xda,0x16,0xfa,0x0c,0xf2,0xb9,0xf6,0x3e,0x4d,0x9a,
0x02,0xc8,0xfb,0x89,0xf7,0xaa,0xec,0x2e,0x3a,0xfb,0xf6,0x8b,
0x7a,0xb6,0x04,0x1e,0xf2,0x14,0xcf,0x5e,0x6e,0xac,0x48,0xd0,
0x8b,0xe1,0xf3,0x89,0xe6,0xf4,0x32,0x1a,0x40,0xc9,0xf2,0xb6,
0x72,0x19,0x4c,0x47,0x82,0xc4,0x6a,0xb6,0x77,0x19,0x08,0xd3,
0x83,0xc4,0x6a,0xc9,0x6e,0xd3,0x54,0x05,0x92,0x9f,0xfb,0xd0,
0x77,0xcb,0x4d,0x01,0x83,0x46,0x56,0xa8,0x77,0xc0,0xf3,0xbb,
0x93,0x84,0xe3,0xd2,0x08,0xda,0x87,0x49,0x22,0x8c,0x45,0x77,
0xc9,0xcf,0x32,0x13,0x46,0x48,0x90,0x89,0x36,0x92,0x4d,0xe1,
0x87,0xb2,0x9c,0x8f,0xc9,0x47,0x45,0x9c,0x0a,0xc5,0xba,0x88,
0x36,0xac,0x44,0xd6,0x5e,0xcb,0xbb,0x88,0x36,0xac,0x40,0xd6,
0x4e,0xda,0xbb,0x88,0x36,0xda,0x3d,0x92,0x8a,0x7f,0xff,0x0b,
0x60,0x95,0xf3,0x8e,0x83,0xf4,0x73,0xc9,0x8c,0x62,0xb9,0xf9,
0x9d,0x3a,0x6f,0xc0,0x53,0xfe,0x60,0x34,0xe7,0xe5,0xdc,0xfa,
0x59,0xff,0x2c,0x16,0x98,0x83,0x9b,0x88,0x7b,0xf7,0x7f,0x28,
0xaa,0xa2,0xdf,0xca,0x59,0xea,0x0c,0x2e,0xb8,0xa0,0xc8,0xbb,
0x04,0xbc,0x68,0x37,0xa7,0xc5,0xba,0x88,0x36,0x92,0x0c,0x5b
];
```

### POC code

Now we can copy and paste the previously generated shellcode into our POC Rust code:

```
use windows::Win32::System::Memory::{VirtualAlloc, MEM_COMMIT, PAGE_EXECUTE_READWRITE};

fn main() {
    let shellcode: [u8; 367] = [
        0x48, 0x31, 0xc9, 0x48, 0x81, 0xe9, 0xd7, 0xff, 0xff, 0xff, 0x48, 0x8d, 0x05, 0xef, 0xff,
        0xff, 0xff, 0x48, 0xbb, 0xcb, 0xc5, 0xba, 0x88, 0x36, 0x92, 0x0c, 0x5b, 0x48, 0x31, 0x58,
        0x27, 0x48, 0x2d, 0xf8, 0xff, 0xff, 0xff, 0xe2, 0xf4, 0x37, 0x8d, 0x3b, 0x6c, 0xc6, 0x6d,
        0xf3, 0xa4, 0x23, 0x15, 0xba, 0x88, 0x36, 0xd3, 0x5d, 0x1a, 0x9b, 0x97, 0xeb, 0xde, 0x7e,
        0xa3, 0xde, 0x3e, 0x83, 0x4e, 0xe8, 0xe8, 0x08, 0xda, 0x87, 0x09, 0xd3, 0xfb, 0xf2, 0x03,
        0x64, 0xb2, 0x32, 0x13, 0x40, 0xb7, 0xea, 0xb6, 0x7e, 0x9d, 0xbb, 0x11, 0x81, 0x88, 0x8b,
        0x41, 0x7e, 0xa3, 0xcc, 0xf7, 0xf7, 0xa4, 0xc6, 0x8a, 0x1a, 0xb2, 0x4d, 0x9a, 0x02, 0xc8,
        0xfb, 0x89, 0xf7, 0x70, 0xe1, 0x09, 0x8a, 0x94, 0x84, 0xc0, 0xbd, 0xc0, 0x2c, 0x65, 0x40,
        0x87, 0x86, 0xc0, 0x37, 0x42, 0x32, 0xd0, 0x4b, 0x4d, 0xba, 0x88, 0x36, 0xda, 0x89, 0x9b,
        0xbf, 0xaa, 0xf2, 0x89, 0xe6, 0xc2, 0x32, 0xd0, 0x83, 0xdd, 0x84, 0xcc, 0xbd, 0xd2, 0x2c,
        0x12, 0xca, 0x15, 0x59, 0xd4, 0x7e, 0x6d, 0xc5, 0x65, 0x8a, 0x4e, 0x8e, 0x00, 0x7e, 0x93,
        0xda, 0x16, 0xfa, 0x0c, 0xf2, 0xb9, 0xf6, 0x3e, 0x4d, 0x9a, 0x02, 0xc8, 0xfb, 0x89, 0xf7,
        0xaa, 0xec, 0x2e, 0x3a, 0xfb, 0xf6, 0x8b, 0x7a, 0xb6, 0x04, 0x1e, 0xf2, 0x14, 0xcf, 0x5e,
        0x6e, 0xac, 0x48, 0xd0, 0x8b, 0xe1, 0xf3, 0x89, 0xe6, 0xf4, 0x32, 0x1a, 0x40, 0xc9, 0xf2,
        0xb6, 0x72, 0x19, 0x4c, 0x47, 0x82, 0xc4, 0x6a, 0xb6, 0x77, 0x19, 0x08, 0xd3, 0x83, 0xc4,
        0x6a, 0xc9, 0x6e, 0xd3, 0x54, 0x05, 0x92, 0x9f, 0xfb, 0xd0, 0x77, 0xcb, 0x4d, 0x01, 0x83,
        0x46, 0x56, 0xa8, 0x77, 0xc0, 0xf3, 0xbb, 0x93, 0x84, 0xe3, 0xd2, 0x08, 0xda, 0x87, 0x49,
        0x22, 0x8c, 0x45, 0x77, 0xc9, 0xcf, 0x32, 0x13, 0x46, 0x48, 0x90, 0x89, 0x36, 0x92, 0x4d,
        0xe1, 0x87, 0xb2, 0x9c, 0x8f, 0xc9, 0x47, 0x45, 0x9c, 0x0a, 0xc5, 0xba, 0x88, 0x36, 0xac,
        0x44, 0xd6, 0x5e, 0xcb, 0xbb, 0x88, 0x36, 0xac, 0x40, 0xd6, 0x4e, 0xda, 0xbb, 0x88, 0x36,
        0xda, 0x3d, 0x92, 0x8a, 0x7f, 0xff, 0x0b, 0x60, 0x95, 0xf3, 0x8e, 0x83, 0xf4, 0x73, 0xc9,
        0x8c, 0x62, 0xb9, 0xf9, 0x9d, 0x3a, 0x6f, 0xc0, 0x53, 0xfe, 0x60, 0x34, 0xe7, 0xe5, 0xdc,
        0xfa, 0x59, 0xff, 0x2c, 0x16, 0x98, 0x83, 0x9b, 0x88, 0x7b, 0xf7, 0x7f, 0x28, 0xaa, 0xa2,
        0xdf, 0xca, 0x59, 0xea, 0x0c, 0x2e, 0xb8, 0xa0, 0xc8, 0xbb, 0x04, 0xbc, 0x68, 0x37, 0xa7,
        0xc5, 0xba, 0x88, 0x36, 0x92, 0x0c, 0x5b,
    ];

    println!("payload size: {}", std::mem::size_of_val(&shellcode));

    unsafe {
        let lpalloc = VirtualAlloc(
            None,
            std::mem::size_of_val(&shellcode),
            MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        );

        if lpalloc.is_null() {
            panic!("VirtualAlloc failed!");
        }

        std::ptr::copy_nonoverlapping(
            shellcode.as_ptr(),
            lpalloc as *mut u8,
            std::mem::size_of_val(&shellcode),
        );

        let func: unsafe fn() = std::mem::transmute(lpalloc);
        func();
    }
}

```

Key notes:
- `VirtualAlloc()` allows us to allocate memory with code execution enabled (`PAGE_EXECUTE_READWRITE`)
- `copy_nonoverlapping()` copies our shellcode into the memory allocated by `VirtualAlloc()`
- `let func: unsafe fn() = std::mem::transmute(lpalloc);` and `func();` executes the code pointed to by `lpalloc` (which is our shellcode)

Now compile the code (I am using Fedora so I have to cross-compile for Windows):

```
$ sudo dnf install mingw64-gcc mingw64-gcc-c++
...
$ rustup target add x86_64-pc-windows-gnu
...
$ cargo build --target x86_64-pc-windows-gnu
...
```

### Testing our shellcode

Since I am using Linux I need either a Windows VM or [Wine](https://www.winehq.org/) to run `sh.exe`:

```
$ wine target/x86_64-pc-windows-gnu/debug/sh.exe
002c:fixme:winediag:loader_init wine-staging 8.19 is a testing version containing experimental patches.
002c:fixme:winediag:loader_init Please mention your exact version when filing bug reports on winehq.org.
0088:fixme:wineusb:query_id Unhandled ID query type 0x5.
0088:fixme:hid:handle_IRP_MN_QUERY_ID Unhandled type 00000005
0088:fixme:hid:handle_IRP_MN_QUERY_ID Unhandled type 00000005
0088:fixme:hid:handle_IRP_MN_QUERY_ID Unhandled type 00000005
0088:fixme:hid:handle_IRP_MN_QUERY_ID Unhandled type 00000005
payload size: 367
```

Our messagebox will also pop up:

![messagebox]({{site.baseurl}}/assets/msf-msg.png)

References:
- [https://ivanitlearning.wordpress.com/2018/10/14/shellcoding-with-msfvenom/](https://ivanitlearning.wordpress.com/2018/10/14/shellcoding-with-msfvenom/)
- [http://0xdabbad00.com/2012/12/07/dep-data-execution-prevention-explanation/](http://0xdabbad00.com/2012/12/07/dep-data-execution-prevention-explanation/)
- [https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
- [https://ivanitlearning.wordpress.com/2018/10/14/shellcoding-with-msfvenom/](https://ivanitlearning.wordpress.com/2018/10/14/shellcoding-with-msfvenom/)
- [https://github.com/microsoft/windows-rs](https://github.com/microsoft/windows-rs)
- [https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Memory/fn.VirtualAlloc.html](https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/System/Memory/fn.VirtualAlloc.html)
- [https://doc.rust-lang.org/core/ptr/fn.copy_nonoverlapping.html](https://doc.rust-lang.org/core/ptr/fn.copy_nonoverlapping.html)
- [https://stackoverflow.com/questions/31492799/cross-compile-a-rust-application-from-linux-to-windows](https://stackoverflow.com/questions/31492799/cross-compile-a-rust-application-from-linux-to-windows)
