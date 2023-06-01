---
title: aircrack-ng with TP-Link Archer T2U Plus AC600
published: true
---

## Introduction

[aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) is a set of WiFi security audit tools. The project was started at the end of February 2006 so there is a lot of documentation available, for example:
- [www.aircrack-ng.org](https://www.aircrack-ng.org)
- [github.com/aircrack-ng/aircrack-ng/discussions](https://github.com/aircrack-ng/aircrack-ng/discussions)
- [github.com/brannondorsey/wifi-cracking](https://github.com/brannondorsey/wifi-cracking)
- [www.kali.org/tools/aircrack-ng](https://www.kali.org/tools/aircrack-ng)

Explaining how to use these tools is not the scope of this post. I am going to show you instead how to use them with a WiFi adapter with **no in-kernel support** such as the [TP-Link Archer T2U Plus AC600](https://www.tp-link.com/en/home-networking/high-gain-adapter/archer-t2u-plus/). Note that you need to choose an adapter which supports monitor mode and packet injection. If you are serious about security analysis/pen testing I suggest to use an Alfa adapter instead such as [AWUS036AXML](https://alfa-network.eu/alfa-usb-adapter-awus036axml) or [AWUS036ACHM](https://alfa-network.eu/awus036achm). Both of them are supported with excellent in-kernel drivers.

## Install the driver

You can choose between multiple drivers, for example [8821au-20210708](https://github.com/morrownr/8821au-20210708) or [aircrack-ng/rtl8812au](https://github.com/aircrack-ng/rtl8812au). I suggest to choose the first one. The main differences between this driver and the aircrack driver:

- This driver is based on much more modern source code and is more compatible with modern distros.
- This driver is easier to install and use for those not that familiar with Linux.
- This driver supports pen testing but pen testing is not the primary focus like the aircrack driver.

See more information about the differences under [this issue](https://github.com/morrownr/8821au-20210708/issues/81).

Installation:

```
$ git clone git@github.com:morrownr/8821au-20210708.git
$ cd 8821au-20210708
$ sudo ./install-driver.sh
: ---------------------------
: install-driver.sh v20230227
: x86_64 (architecture)
: 2/2 (in-use/total processing units)
: 4018148 (total system memory)
: 5.15.0-72-generic (kernel version)
: gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0
: ---------------------------

Checking for previously installed drivers.
: ---------------------------

Starting installation.
Installing 8821au.conf to /etc/modprobe.d
The non-dkms installation routines are in use.
make ARCH=x86_64 CROSS_COMPILE= -C /lib/modules/5.15.0-72-generic/build M=/home/gemesa/git-repos/8821au-20210708  modules
make[1]: Entering directory '/usr/src/linux-headers-5.15.0-72-generic'
  CC [M]  /home/gemesa/git-repos/8821au-20210708/core/rtw_cmd.o
  CC [M]  /home/gemesa/git-repos/8821au-20210708/core/rtw_security.o
  CC [M]  /home/gemesa/git-repos/8821au-20210708/core/rtw_debug.o
  CC [M]  /home/gemesa/git-repos/8821au-20210708/core/rtw_io.o
...
  LD [M]  /home/gemesa/git-repos/8821au-20210708/8821au.o
  MODPOST /home/gemesa/git-repos/8821au-20210708/Module.symvers
  CC [M]  /home/gemesa/git-repos/8821au-20210708/8821au.mod.o
  LD [M]  /home/gemesa/git-repos/8821au-20210708/8821au.ko
  BTF [M] /home/gemesa/git-repos/8821au-20210708/8821au.ko
Skipping BTF generation for /home/gemesa/git-repos/8821au-20210708/8821au.ko due to unavailability of vmlinux
make[1]: Leaving directory '/usr/src/linux-headers-5.15.0-72-generic'
install -p -m 644 8821au.ko  /lib/modules/5.15.0-72-generic/kernel/drivers/net/wireless/
/sbin/depmod -a 5.15.0-72-generic
The driver was installed successfully.
: ---------------------------

Info: Upgrade this driver with the following commands as needed:
$ git pull
$ sudo sh install-driver.sh
Note: Upgrades to this driver should be performed before distro upgrades.
Note: Upgrades can be performed as often as you like.
Note: Work on this driver is continuous.
: ---------------------------

Do you want to edit the driver options file now? (recommended) [Y/n] 
Do you want to apply the new options by rebooting now? (recommended) [Y/n] 
```

## airmon-ng and airodump-ng

You can use `airmon-ng` to set monitor mode:

```
$ sudo airmon-ng

PHY	Interface	Driver		Chipset

null	wlp0s20f0u1

$ sudo airmon-ng check kill

Killing these processes:

    PID Name
   2366 wpa_supplicant

$ sudo airmon-ng start wlp0s20f0u1

PHY	Interface	Driver		Chipset

null	wlp0s20f0u1

```

Then `airodump-ng`:

```
$ sudo airodump-ng wlp0s20f0u1  

 CH  3 ][ Elapsed: 12 s ][ 2023-03-09 16:44

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 XX:XX:XX:XX:XX:XX  -86       23        0    0   1  130   WPA2 CCMP   PSK  <essid>
 XX:XX:XX:XX:XX:XX  -96        2        0    0   1  130   WPA2 CCMP   PSK  <essid>
 XX:XX:XX:XX:XX:XX  -86        8        0    0   1  130   WPA2 CCMP   PSK  <essid>

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 (not associated)   XX:XX:XX:XX:XX:XX  -87    0 - 1     50        4                                
 (not associated)   XX:XX:XX:XX:XX:XX  -87    0 - 1     16        4                                                                 
```

## Monitor_Mode and airodump-ng

There is an other, more graceful way to set your adapter to monitor mode:

```
$ git clone https://github.com/morrownr/Monitor_Mode
$ cd Monitor_Mode
$ sudo ./start-mon.sh wlp0s20f0u1

 The following processes have been stopped:

    PID Name
   1555 avahi-daemon
   1633 avahi-daemon
   2248 NetworkManager
   2363 wpa_supplicant

 Note: The above processes can be returned
 to a normal state at the end of this script.

 Press any key to continue...
```
Keep pressing enters to accept the default options or change the address, channel and TX power if you want to. You will end up with a configuration like this:

```
--------------------------------
    start-mon.sh 20230305
 --------------------------------
    WiFi Interface:
             wlp0s20f0u1
 --------------------------------
    name  -  wlp0s20f0u1
    type  -  monitor
    state -  DORMANT
    addr  -  XX:XX:XX:XX:XX:XX
    chan  -  6 (2437 MHz), width: 20 MHz (no HT), center1: 2437 MHz
    txpw  -  16.00 dBm
 --------------------------------

 DORMANT = up but inactive.

 Ready for Monitor Mode use.

 You can place this terminal in
 the background while you run any
 applications you wish to run.

 Press any key to exit...

```

Open an other terminal and run `airodump-ng`:

```
$ sudo airodump-ng wlp0s20f0u1  

 CH  3 ][ Elapsed: 12 s ][ 2023-03-09 16:44

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 XX:XX:XX:XX:XX:XX  -86       23        0    0   1  130   WPA2 CCMP   PSK  <essid>
 XX:XX:XX:XX:XX:XX  -96        2        0    0   1  130   WPA2 CCMP   PSK  <essid>
 XX:XX:XX:XX:XX:XX  -86        8        0    0   1  130   WPA2 CCMP   PSK  <essid>

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 (not associated)   XX:XX:XX:XX:XX:XX  -87    0 - 1     50        4                                
 (not associated)   XX:XX:XX:XX:XX:XX  -87    0 - 1     16        4                                                                 
```

Close `airdump-ng` when you are finished and navigate back to the terminal where `start-mon.sh` is running. Press enter 2x and your adapter will return to the original settings. The previously stopped processes (NetworkManager, wpa_supplicant, etc.) are returned to normal state as well.

```
 Press any key to exit...

 Do you want to return the adapter to original settings? [Y/n]
```
