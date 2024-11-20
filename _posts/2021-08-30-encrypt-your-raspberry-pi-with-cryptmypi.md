---
title: Encrypt your Raspberry Pi with cryptmypi
published: true
---

## Introduction

[cryptmypi](https://github.com/unixabg/cryptmypi) is a shell script assisting in the setup of a Raspberry Pi (RPi). This is no big deal so far, the key differences compared to a basic RPi configuration:
- **full disk encryption** (LUKS)
- **headless mode** (no need for monitor and keyboard, you can ssh into the RPi)
- **remote unlocking** (no need for physical access after a restart for example, you can unlock the encryption remotely using Dropbear)

## How to set up

```
$ git clone git@github.com:unixabg/cryptmypi.git
$ cd cryptmypi
$ nano examples/pios-encrypted-basic-dropbear/cryptmypi.conf
```
Choose a compatible kernel (in my case: Raspberry Pi 4 Model B 4GB --> `v7l+`):

```
export _KERNEL_VERSION_FILTER="v7l+"
```

Choose an arbitrary hostname:

```
export _HOSTNAME="pi-nocchio"
```

Choose your target SD card:
```
export _BLKDEV="/dev/sda"
```

Choose a secure encryption password:
```
export _LUKSPASSWD="secure_luks_p4ssw0rd"
```

Choose the newest available image and update the checksum as well (**updated (2023)**: you can find it in `2023-05-03-raspios-bullseye-armhf-lite.img.xz.sha256`):
```
# updated (2023):
export _IMAGEURL="https://downloads.raspberrypi.org/raspios_lite_armhf/images/raspios_lite_armhf-2023-05-03/2023-05-03-raspios-bullseye-armhf-lite.img.xz"
export _IMAGESHA="b5e3a1d984a7eaa402a6e078d707b506b962f6804d331dcc0daa61debae3a19a"
```

Remove extra packages (I prefer to install everything I need later):
```
export _PKGSINSTALL=""
```

Choose an ssh key (this will be used for remote unlocking):
```
export _SSH_LOCAL_KEYFILE="$_USER_HOME/.ssh/id_rsa_rpi"
```
My preference would be ED25519 but Dropbear does not support that currently so I will stick to RSA:

```
$ ssh-keygen -b 4096
Generating public/private rsa key pair.
Enter file in which to save the key (/home/<username>/.ssh/id_rsa): id_rsa_rpi
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in id_rsa_rpi
Your public key has been saved in id_rsa_rpi.pub
The key fingerprint is:
SHA256:JHN7wOgpgPbyVjUrA5AHpIuVpn2p5dpo0WpYi6F+YKI <username>@<hostname>
The key's randomart image is:
+---[RSA 4096]----+
|.+o              |
|.o.o   o         |
|o.*.  +o=        |
|o*...o.*oo       |
|+..o=+o.S .      |
|oo==o.o  .       |
|==o*.            |
|E *=             |
|.++ .            |
+----[SHA256]-----+
```

Choose a secure root password:
```
export _ROOTPASSWD="secure_root_p4ssw0rd"
```

Now run the cryptmypi script:

```
$ sudo ./cryptmypi.sh examples/pios-encrypted-basic-dropbear

###############################################################################
                               C R Y P T M Y P I
###############################################################################

Loading functions...
- Loading chroot.fns ...
  ... chroot.fns loaded!
- Loading echo.fns ...
  ... echo.fns loaded!
- Loading files.fns ...
  ... files.fns loaded!
- Loading hooks.fns ...
  ... hooks.fns loaded!
- Loading misc.fns ...
  ... misc.fns loaded!
- Loading ssh.fns ...
  ... ssh.fns loaded!
- Loading stage1profiles.fns ...
  ... stage1profiles.fns loaded!
...
```

Press enter when you reach stage 2:

```
###############################################################################
                               C R Y P T M Y P I
                               ---- Stage 2 ----
v4.12-next
###############################################################################

Cryptmypi will attempt to perform the following operations on the sdcard:
    1. Partition and format the sdcard.
    2. Create bootable sdcard with LUKS encrypted root partition.

Press enter to continue.
```

Confirm the SD card:

```
block device:  /dev/sda

If the block device is wrong DO NOT continue. Adjust the
block device in the cryptmypi.conf file located in the
config directory.

To continue type in the phrase 'Yes, do as I say!'
: Yes, do as I say!
```

Wait for the script to finish:

```
Goodbye from cryptmypi (4.11-beta).
```

Plug the SD card into your RPi and power it up then unlock it through ssh:

```
$ ssh root@<your-rpi-ip> -i ~/.ssh/id_rsa_rpi -p 2222
Enter passphrase for key '/home/<username>/.ssh/id_rsa_rpi': 
Enter passphrase for /dev/disk/by-uuid/<your-uuid>: 
Connection to <your-rpi-ip> closed.
```

Wait for boot to finish then ssh into your Pi:

```
$ ssh root@<your-rpi-ip> -i ~/.ssh/id_rsa_rpi
Linux <your-pi> 5.10.103-v7l+ #1529 SMP Tue Mar 8 12:24:00 GMT 2022 armv7l

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Jan 21 21:51:08 2022 from <your-last-ip>

Wi-Fi is currently blocked by rfkill.
Use raspi-config to set the country before use.

root@<your-pi>:~#
```

I suggest you to generate a new ED25519 ssh key now and add it to your `/root/.ssh/authorized_keys` and/or `/home/pi/.ssh/authorized_keys` files, and remove the RSA one. Dropbear has an other `authorized_keys` file so it will still use the RSA key but this way you can harden your system a little bit. You can also remove the ssh key from the root `authorized_keys` and use only your pi user from now on.


## Gotcha 1:

`ssh-rsa` might be disabled on your system:
```
$ ssh root@<your-rpi-ip> -i ~/.ssh/id_rsa_rpi -p 2222
root@<your-rpi-ip>: Permission denied (publickey).
```

```
$ ssh root@<your-rpi-ip> -i ~/.ssh/id_rsa_rpi -p 2222 -vvv
...
debug1: send_pubkey_test: no mutual signature algorithm
...
```

So you need to enable it:

```
$ nano ~/.ssh/config
$ cat ~/.ssh/config
Host *
    PubkeyAcceptedKeyTypes=+ssh-rsa
    HostKeyAlgorithms=+ssh-rsa
```

## Gotcha 2:

After a kernel update you need to rebuild initramfs:
```
sudo apt update && sudo apt upgrade -y
# check kernel version
ls /lib/modules
update-initramfs -u
# replace "5.10.103-v7l+" with the proper version, refer to the output of the previous ls command
sudo mkinitramfs -o /boot/initramfs.gz 5.10.103-v7l+
sudo reboot
```

Otherwise after a reboot your device might get stuck when you try to unlock it:

```
Enter passphrase for /dev/disk/by-uuid/<your-uuid>:
Cannot initialize device-mapper. Is dm_mod kernel module loaded?
Cannot use device crypt, name is invalid or still in use.
Enter passphrase for /dev/disk/by-uuid/<your-uuid>:
```
But even in this case there is still hope. Refer to [this GitHub issue](https://github.com/unixabg/cryptmypi/issues/46) for information.
