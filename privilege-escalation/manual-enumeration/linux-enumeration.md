# Linux Enumeration

Useful links: [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)

## <mark style="color:red;">**Users**</mark>

Gather user context information:

```bash
id
uid=1000(student) gid=1000(student) groups=1000(student)
```

Enumerate users:

```bash
cat /etc/passwd
```

## <mark style="color:red;">**Hostname**</mark>

We can discover the hostname with the aptly-named hostname command:

```bash
hostname
debian
```

## <mark style="color:red;">**Operating System Version and Architecture**</mark>

Extract the name of the operating system, its version and architecture:

```bash
cat /etc/issue
Debian GNU/Linux 9 \n \l

cat /etc/*-release
PRETTY_NAME="Debian GNU/Linux 9 (stretch)"
NAME="Debian GNU/Linux"
VERSION_ID="9"
VERSION="9 (stretch)"
ID=debian
...

uname -a
Linux debian 4.9.0-6-686 #1 SMP Debian 4.9.82-1+deb9u3 (2018-03-02) i686 GNU/Linux
```

## <mark style="color:red;">**Running Processes and Services**</mark>

List system processes (including those run by privileged users):

```bash
ps aux
USER       PID %CPU %MEM    VSZ   RSS STAT START   TIME COMMAND
root         1  0.0  0.6  28032  6256 Ss   Nov07   0:03 /sbin/init
root         2  0.0  0.0      0     0 S    Nov07   0:00 [kthreadd]
root       254  0.0  0.9  54536  9924 Ssl  Nov07   1:45 /usr/bin/vmtoolsd
...
```

## <mark style="color:red;">**Networking Information**</mark>

List the TCP/IP configuration of every network adapter:

```bash
ip a
ifconfig
```

Display network routing tables:

```
/sbin/route
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref   Use Iface
default         192.168.1.254   0.0.0.0         UG    0      0       0 ens192
10.11.0.0       0.0.0.0         255.255.255.0   U     0      0       0 ens224
192.168.1.0     0.0.0.0         255.255.255.0   U     0      0       0 ens192
```

Display active network connections and listening ports:

```bash
ss -anp
Netid State   Recv-Q Send-Q  Local Address:Port  Peer Address:Port              
...
tcp   LISTEN  0      80  127.0.0.1:3306     *:*                  
tcp   LISTEN  0      128     *:22                *:*                  
tcp   ESTAB   0      48852   10.11.0.128:22      10.11.0.4:52804              
...
```

## <mark style="color:red;">**Scheduled Tasks**</mark>

List scheduled tasks:

```bash
ls -lah /etc/cron*
-rw-r--r-- 1 root root  722 Oct  7  2017 /etc/crontab

/etc/cron.d
/etc/cron.daily
/etc/cron.hourly
/etc/cron.monthly
/etc/cron.weekly
```

These tasks should be inspected carefully for insecure file permissions as most jobs in this particular file will run as root:

```bash
cat /etc/crontab 
...

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
5 0	* * *	root	/var/scripts/user_backups.sh
```

## <mark style="color:red;">**Installed Applications and Patch Levels**</mark>

List applications installed (by dpkg):

```bash
student@debian:~$ dpkg -l
||/ Name                Version           Architecture  Description
+++-===================-=================-=============-=============================
ii  acl                 2.2.52-3+b1       i386          Access control list utilities
ii  adduser             3.115             all           add and remove users and grou
ii  adwaita-icon-theme  3.22.0-1+deb9u1   all           default icon theme of GNOME
ii  alsa-utils          1.1.3-1           i386          Utilities for configuring and
...
```

## <mark style="color:red;">**Readable / Writable Files and Directories**</mark>

Searching for every directory writable by the current user on the target system:

```bash
student@debian:~$ find / -writable -type d 2>/dev/null
/usr/local/james/bin
/usr/local/james/bin/lib
/proc/16195/task/16195/fd
/proc/16195/fd
...
```

## <mark style="color:red;">**Unmounted Disks**</mark>

List all mounted filesystems. In addition, the /etc/fstab file lists all drives that will be mounted at boot time:

```bash
cat /etc/fstab
mount
```

View all available disks:

```bash
/bin/lsblk
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
fd0      2:0    1    4K  0 disk 
sda      8:0    0    5G  0 disk 
├─sda1   8:1    0  4.7G  0 part /
├─sda2   8:2    0    1K  0 part 
└─sda5   8:5    0  334M  0 part [SWAP]
```

## <mark style="color:red;">**Device Drivers and Kernel Modules**</mark>

Enumerate the loaded kernel modules:

```bash
lsmod
Module                  Size  Used by
fuse                   90112  3
appletalk              32768  0
ax25                   49152  0
...
```

Find out more about the specific module.

```bash
/sbin/modinfo libata
filename:       /lib/modules/4.9.0-6-686/kernel/drivers/ata/libata.ko
version:        3.00
license:        GPL
description:    Library module for ATA devices
author:         Jeff Garzik
srcversion:     7D8076C4A3FEBA6219DD851
depends:        scsi_mod
retpoline:      Y
intree:         Y
vermagic:       4.9.0-6-686 SMP mod_unload modversions 686
parm:           zpodd_poweroff_delay:Poweroff delay for ZPODD in seconds (int)
...
```

## <mark style="color:red;">**Binaries that AutoElevate**</mark>

If a binary has the SUID bit set and the file is owned by root, any local user will be able to execute that binary with elevated privileges.&#x20;

Search for SUID-marked binaries:

```bash
find / -perm -u=s -type f 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/xorg/Xorg.wrap
/usr/sbin/userhelper
/usr/bin/passwd
/usr/bin/sudo
...
```
