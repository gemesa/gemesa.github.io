---
title: Unbrick your OpenWRT router
published: true
---

Sometimes you might brick your router when you try to flash an OpenWRT firmware. This happened to me when I tried to download [OpenWRT 19.07.2](https://downloads.openwrt.org/releases/19.07.2/targets/ath79/generic/openwrt-19.07.2-ath79-generic-tplink_archer-c7-v5-squashfs-factory.bin) to my [TP-Link Archer C7 v5](https://openwrt.org/toh/tp-link/archer_c7). Fortunately there are multiple [methods](https://openwrt.org/docs/guide-user/troubleshooting/failsafe_and_factory_reset) to get your router back in a stable state (depending on your problem). In my case I knew I had a corrupt firmware so I had to use TFTP to reflash it (my setup: Thinkpad L580 with Fedora 37 Workstation):

```
$ sudo dnf install tftp-server -y
$ sudo cp /usr/lib/systemd/system/tftp.service /etc/systemd/system/tftp-server.service
$ sudo cp /usr/lib/systemd/system/tftp.socket /etc/systemd/system/tftp-server.socket
$ sudo nano /etc/systemd/system/tftp-server.service
$ sudo cat /etc/systemd/system/tftp-server.service
[Unit]
Description=Tftp Server
Requires=tftp-server.socket
Documentation=man:in.tftpd

[Service]
ExecStart=/usr/sbin/in.tftpd -c -p -s /var/lib/tftpboot
StandardInput=socket

[Install]
WantedBy=multi-user.target
Also=tftp-server.socket
$ sudo cat /etc/systemd/system/tftp-server.socket 
[Unit]
Description=Tftp Server Activation Socket

[Socket]
ListenDatagram=69

[Install]
WantedBy=sockets.target
$ sudo mv <your-firmware>.bin /var/lib/tftpboot/ArcherC7v5_tp_recovery.bin
$ # the next step might not be necessary
$ sudo chmod 777 /var/lib/tftpboot/ArcherC7v5_tp_recovery.bin
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now tftp-server
$ sudo firewall-cmd --add-service=tftp --perm
$ sudo firewall-cmd --reload
$ sudo ifconfig <your-eth-if> 192.168.0.66 netmask 255.255.255.0
```
Power off your router and connect a LAN port of your router to your machine with the TFTP server. To start the TFTP recovery process on the router, press and hold the reset button and then power up the router. Keep the reset button pressed until the WPS LED turns on (it's the LED with two arrows pointing in different directions). Now the flash operation takes a couple of minutes.

After the flashing finished disable the TFTP server:

```
$ sudo firewall-cmd --remove-service=tftp --perm
$ sudo firewall-cmd --reload
$ sudo systemctl disable tftp-server
$ sudo systemctl stop tftp-server
```

References:
- https://openwrt.org/toh/tp-link/archer_c7
- https://community.tp-link.com/en/home/forum/topic/81462
- https://fedoramagazine.org/how-to-set-up-a-tftp-server-on-fedora/
