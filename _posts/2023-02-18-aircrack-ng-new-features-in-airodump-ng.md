---
title: "aircrack-ng: new features in airodump-ng"
published: true
---

## Table of contents

* toc placeholder
{:toc}

## Introduction

I have been working lately on [aircrack-ng](https://github.com/aircrack-ng/aircrack-ng), mainly on improving `airodump-ng`. Besides the numerous bugfixes I have added some new features also which will be included in the next aircrack-ng release (1.8).

## multiple `--bssid <bssid>` options

Previously it was not possible to filter multiple MAC address with no common OUI mask. Now you can pass multiple `--bssid <bssid>` options to `airodump-ng`.

Examples:

Creating 2 APs:

```
$ sudo ./airbase-ng -e "AP1" -c 9 wlp0s20f0u1u2 -a AC:22:05:11:11:11
15:56:24  Created tap interface at0
15:56:24  Trying to set MTU on at0 to 1500
15:56:24  Access Point with BSSID AC:22:05:11:11:11 started.
```
```
$ sudo ./airbase-ng -e "AP2" -c 9 wlp0s20f0u1u3 -a D6:35:1D:22:22:22
15:56:51  Created tap interface at0
15:56:51  Trying to set MTU on at0 to 1500
15:56:51  Access Point with BSSID D6:35:1D:22:22:22 started.
```

Monitoring:

```
$ sudo ./airodump-ng wlan0mon
 CH  3 ][ Elapsed: 0 s ][ 2023-02-12 15:57

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 XX:XX:XX:XX:XX:XX  -76        5        0    0   1  130   WPA2 CCMP   PSK  <ESSID>                                
 XX:XX:XX:XX:XX:XX  -83        3        0    0   1  270   WPA2 CCMP   PSK  <ESSID>                                
 AC:22:05:11:11:11  -58       11        0    0   9   54   OPN              AP1                                       
 XX:XX:XX:XX:XX:XX  -86        8        1    0   1  270   WPA2 CCMP   PSK  <ESSID>                                      
 XX:XX:XX:XX:XX:XX  -77        7        0    0   1  130   WPA2 CCMP   PSK  <ESSID>                             
 XX:XX:XX:XX:XX:XX  -81        7        0    0   1  130   WPA2 CCMP   PSK  <ESSID>                          
 XX:XX:XX:XX:XX:XX  -86        6        0    0   1  130   WPA2 CCMP   PSK  <ESSID>                                
 D6:35:1D:22:22:22  -58       13        0    0   9   54   OPN              AP2
```

```
$ sudo ./airodump-ng wlan0mon --bssid AC:22:05:11:11:11
CH  7 ][ Elapsed: 6 s ][ 2023-02-12 15:58

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 AC:22:05:11:11:11  -58       40        0    0   9   54   OPN              AP1
```

```
$ sudo ./airodump-ng wlan0mon --bssid AC:22:05:11:11:11 --bssid D6:35:1D:22:22:22
 CH  5 ][ Elapsed: 0 s ][ 2023-02-12 15:59

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 D6:35:1D:22:22:22  -58       23        0    0   9   54   OPN              AP2                                       
 AC:22:05:11:11:11  -57       14        0    0   9   54   OPN              AP1
```

```
$ sudo ./airodump-ng wlan0mon --bssid AC:22:05:11:11:11 --bssid D6:35:1D:22:22:22 --netmask FF:FF:FF:00:00:00
 CH  4 ][ Elapsed: 48 s ][ 2023-02-12 16:00

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 D6:35:1D:XX:XX:XX  -91        2        0    0   1  540   WPA2 CCMP   MGT  <ESSID>
 AC:22:05:XX:XX:XX  -88       11        0    0   1  130   WPA2 CCMP   PSK  <ESSID>
 AC:22:05:XX:XX:XX  -83       76        0    0   1  130   WPA2 CCMP   PSK  <ESSID>
 D6:35:1D:22:22:22  -57      349        0    0   9   54   OPN              AP2
 AC:22:05:XX:XX:XX  -39       59       13    0   1  130   WPA2 CCMP   PSK  <ESSID>
 AC:22:05:11:11:11  -58      294        0    0   9   54   OPN              AP1
```

See more information under [this PR](https://github.com/aircrack-ng/aircrack-ng/pull/2432).

## `--min-power` and `--mind-rxq`

2 new filters in `airodump-ng`:

- `-p <number>, --min-pwr <number>` : show networks whose PWR is >= number
- `-q <number>, --min-rxq <number>` : show networks whose RXQ is >= number

Note that `--min-rxq` requires `-c` or `-C` as RXQ column is only displayed in fixed channel or fixed frequency mode:

```
$ sudo ./airodump-ng wlan0mon -q 20      
Error: --min-rxq (or -q) requires --channel (or -c) or -C
"/home/gemesa/git-repos/aircrack-ng/.libs/airodump-ng --help" for help.
```

Examples:

```
$ sudo ./airodump-ng wlan0mon -p -80

 CH  8 ][ Elapsed: 24 s ][ 2023-02-18 21:20

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 XX:XX:XX:XX:XX:XX  -69        1        2    0 100 1733   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -36        1        0    0  40 1170   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -80        1        0    0  36  866   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -74        1        1    0  12  195   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -77        1        0    0  11  130   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -74        1        0    0  10  195   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -74        2        0    0  11  130   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -68        3        0    0   6  195   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -80        1        0    0   6  130   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -72        2        0    0   6  130   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -79        4        0    0   1  270   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -66        5        0    0   4  130   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -76       19       23    0   2  195   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -80      109        5    0   1  540   WPA2 CCMP   MGT  <ESSID>
 XX:XX:XX:XX:XX:XX  -66      127        0    0   1  130   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -33      130       51    0   1  195   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -73      100       11    0   1  540   WPA3 CCMP   SAE  <ESSID>

 BSSID              STATION            PWR    Rate    Lost   Frames  Notes  Probes

 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -93    0 - 1      0        8                                                   
 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -91    0 - 6e     0        1                                                   
 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX   -1    1e- 0      0        1                                                   
 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -81    0 - 1e     0        4                                                   
 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -61    1e- 6      0       51                                                   
 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX   -1    1e- 0      0        1                                                   
 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -61    0 - 1e     0        9
```

```
$ sudo ./airodump-ng wlan0mon -c 1 -q 20

 CH  1 ][ Elapsed: 0 s ][ 2023-02-18 21:22

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 XX:XX:XX:XX:XX:XX  -83  40       22        0    0   1  195   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -76  37       18        4    0   2  195   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -83  35       19        0    0   1  130   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -77  50       25        5    0   1  540   WPA3 CCMP   SAE  <ESSID>
 XX:XX:XX:XX:XX:XX  -80  21       27        3    0   1  540   WPA2 CCMP   MGT  <ESSID>
 XX:XX:XX:XX:XX:XX  -64  70       39        0    0   1  130   WPA2 CCMP   PSK  <ESSID>

 BSSID              STATION            PWR    Rate    Lost   Frames  Notes  Probes

 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -64    1e-24     27      275                                                   
 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -63    0 - 1e     0        3                                                   
 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -56    1e- 6      7       21
```

See more information under [this PR](https://github.com/aircrack-ng/aircrack-ng/pull/2457).

## `--ignore-other-chans`

New filter in `airodump-ng`. Previously when using `airodump-ng -c 11` it displayad all captured data on channel 11, and you ended up with access points on other channels as well. With option `--ignore-other-chans` access points on other channels are ignored (other than the fixed one we selected).

Examples:

```
$ sudo ./airodump-ng wlan0mon -c 1-3

 CH  3 ][ Elapsed: 0 s ][ 2023-02-18 16:32

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID
                      
 XX:XX:XX:XX:XX:XX  -85        1        0    0   1   65   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -76        4        0    0   5  130   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -87        3        0    0   3  130   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -87        8        0    0   3  130   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -68       17        0    0   4  130   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -83        4        0    0  10  195   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -83        4        0    0   1  270   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -96        4        0    0   1  540   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -73       20        3    0   2  195   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -70       22        0    0   1  130   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -85        6        0    0   1  195   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -82       13        2    0   1  540   WPA2 CCMP   MGT  <ESSID>
 XX:XX:XX:XX:XX:XX  -87        5        0    0   1  270   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -96        4        0    0   1  540   WPA2 CCMP   MGT  <ESSID>
 XX:XX:XX:XX:XX:XX  -96        6        0    0   1  130   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -87        6        2    0   1  130   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -82        8        3    1   1  540   WPA3 CCMP   SAE  <ESSID>
 XX:XX:XX:XX:XX:XX  -84        9        0    0   1  130   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -38       16        8    0   1  195   WPA2 CCMP   PSK  <ESSID>

 BSSID              STATION            PWR    Rate    Lost   Frames  Notes  Probes

 (not associated)   XX:XX:XX:XX:XX:XX  -87    0 - 1      1        3         <PROBE>                                
 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -67    0 - 1      0        1                                                   
 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -79    0 - 1      0        3         <PROBE>                            
 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -65    1e-24     29       73  EAPOL  <PROBE>                            
 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -69    0 - 1e     0        2                                                   
 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -55    0 - 1      0        1
```

```
$ sudo ./airodump-ng wlan0mon --ignore-other-chans -c 1-3

 CH  3 ][ Elapsed: 12 s ][ 2023-02-18 16:32

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 XX:XX:XX:XX:XX:XX  -85        2        0    0   1  270   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -87        3        0    0   1  270   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -83        7        1    0   3  130   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -89        2        0    0   1  130   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -86        1        0    0   1  270   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -83       27        2    0   1  540   WPA2 CCMP   MGT  <ESSID>
 XX:XX:XX:XX:XX:XX  -81       47        0    0   1  130   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -83       22        0    0   1  195   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -96       17        1    0   1  130   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -84       27        4    0   1  540   WPA3 CCMP   SAE  <ESSID>
 XX:XX:XX:XX:XX:XX  -76       88        0    0   1  130   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -38       47       19    0   1  195   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -94        2        0    0   1  540   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -92        6        0    0   1   65   WPA2 CCMP   PSK  <ESSID>
 XX:XX:XX:XX:XX:XX  -75       57       17    1   2  195   WPA2 CCMP   PSK  <ESSID>

 BSSID              STATION            PWR    Rate    Lost   Frames  Notes  Probes

 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -85    1e- 1      0        3                                                   
 (not associated)   XX:XX:XX:XX:XX:XX  -93    0 - 1      0        1                                                   
 (not associated)   XX:XX:XX:XX:XX:XX  -85    0 - 1      0        2         <PROBE>                                  
 (not associated)   XX:XX:XX:XX:XX:XX  -87    0 - 1      0        2         <PROBE>                                
 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -89    0 - 1      9        7                                                   
 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -71    0 - 1e     0        8                                                   
 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -53    1e- 6     19       16                                                   
 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -83    0 - 2e    11        5                                                   
 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -82    1e-24      0        2
```
See more information under [this PR](https://github.com/aircrack-ng/aircrack-ng/pull/2456).

## `-z`

New filter in `airodump-ng`. With `-z` only unassociated stations are shown, using in combination with `-a` won't display any of the stations.

Examples:

```
$ sudo ./airodump-ng wlan0mon      
...
 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -75    0 - 1     13        6                                                   
 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -87    0 - 1      5        3                                                   
 (not associated)   XX:XX:XX:XX:XX:XX  -73    0 - 5      0        1                                                   
 (not associated)   XX:XX:XX:XX:XX:XX  -83    0 - 1      0        2         <PROBE> 
```
```
$ sudo ./airodump-ng wlan0mon -a
...
 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -87    0 - 1      1        2                                                   
 XX:XX:XX:XX:XX:XX  XX:XX:XX:XX:XX:XX  -69    0 - 1     16       22         <PROBE>
```

```
$ sudo ./airodump-ng wlan0mon -z
...
 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 (not associated)   XX:XX:XX:XX:XX:XX  -89    0 - 1      0        1         <PROBE>
```

```
$ sudo ./airodump-ng wlan0mon -a -z
...
 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

                                                                                   
```

See more information under [this PR](https://github.com/aircrack-ng/aircrack-ng/pull/2448).
