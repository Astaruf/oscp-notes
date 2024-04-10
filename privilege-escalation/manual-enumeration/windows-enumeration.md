# Windows Enumeration

## <mark style="color:red;">**Users**</mark>

Info about user in use:

```powershell
C:\Users\student> whoami
client251\student
C:\Users\student> net user student
```

Discover other user accounts on the system

```powershell
C:\Users\student>net user
User accounts for \\CLIENT251
-------------------------------------------------------------------------------
admin                    Administrator            DefaultAccount
Guest                    student                  WDAGUtilityAccount
The command completed successfully.
```

## <mark style="color:red;">**Hostname**</mark>

Discover the hostname:

```powershell
C:\Users\student>hostname
client251
```

## <mark style="color:red;">**Operating System Version and Architecture**</mark>

Extract the name of the operating system (Name) as well as its version (Version) and architecture (System):

<pre class="language-powershell"><code class="lang-powershell">C:\> systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.16299 N/A Build 16299
System Type:               X86-based PC

# In italian the info changes
<strong>C:\> systeminfo | findstr /B /C:"Nome SO" /C:"Versione SO" /C:"Tipo sistema"
</strong></code></pre>

## <mark style="color:red;">**Running Processes and Services**</mark>

List the running processes:

```bash
C:\> tasklist /SVC
```

## <mark style="color:red;">**Networking Information**</mark>

Display the full TCP/IP configuration of all adapters:

```bash
C:\> ipconfig /all
```

Display the networking routing tables:

```bash
C:\> route print
```

Display active network connections:

```bash
C:\> netstat -ano
```

## <mark style="color:red;">**Firewall Status and Rules**</mark>

Inspect the current firewall profile:

```bash
C:\> netsh advfirewall show currentprofile
```

List firewall rules:

```bash
C:\> netsh advfirewall firewall show rule name=all
```

## <mark style="color:red;">**Scheduled Tasks**</mark>

Display scheduled tasks:

```bash
C:\> schtasks /query /fo LIST /v
```

## <mark style="color:red;">**Installed Applications and Patch Levels**</mark>

List applications and related version that are installed by the _Windows Installer_ (it will not list applications that do not use the Windows Installer)

```bash
C:\> wmic product get name, version, vendor
Name                                       Vendor                      Version
Microsoft OneNote MUI (English) 2016       Microsoft Corporation       16.0.4266.1001
Microsoft Office OSM MUI (English) 2016    Microsoft Corporation       16.0.4266.1001
...
```

Wmic can also be used to list system-wide updates by querying the _Win32\_QuickFixEngineering (qfe)_ WMI class:

```bash
C:\> wmic qfe get Caption, Description, HotFixID, InstalledOn
Caption                                     Description      HotFixID   InstalledOn
                                            Update           KB2693643  4/7/2018
http://support.microsoft.com/?kbid=4088785  Security Update  KB4088785  3/31/2018
...
```

## <mark style="color:red;">**Readable / Writable Files and Directories**</mark>

Find a file with insecure file permissions in the Program Files directory:

```powershell
C:\> accesschk.exe -uws "Everyone" "C:\Program Files"

Accesschk v6.12 - Reports effective permissions for securable objects
Copyright (C) 2006-2017 Mark Russinovich
Sysinternals - www.sysinternals.com

RW C:\Program Files\TestApplication\testapp.exe
```

Searching for any object can be modified (Modify) by members of the Everyone group:

```powershell
PS C:\> Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}

    Directory: C:\Program Files\TestApplication

Path        Owner                  Access
----        -----                  ------
test.exe BUILTIN\Administrators Everyone Allow  Modify, Synchronize...
```

## <mark style="color:red;">**Unmounted Disks**</mark>

List all drives that are currently mounted or physically connected but unmounted:

```powershell
C:\> mountvol
Creates, deletes, or lists a volume mount point.
...
Possible values for VolumeName along with current mount points are:

    \\?\Volume{25721a7f-0000-0000-0000-100000000000}\
        *** NO MOUNT POINTS ***
    \\?\Volume{25721a7f-0000-0000-0000-602200000000}\
        C:\
    \\?\Volume{78fa00a6-3519-11e8-a4dc-806e6f6e6963}\
        D:\
```

## <mark style="color:red;">**Device Drivers and Kernel Modules**</mark>

This technique relies on matching vulnerabilities with corresponding exploits, we'll need to compile a list of drivers and kernel modules that are loaded on the target.

We first produce a list of loaded drivers:

```powershell
C:\> powershell.exe
PS C:\> driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path   
```

Request the version number of each loaded driver:

```
PS C:\Users\student> Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}

DeviceName               DriverVersion Manufacturer
----------               ------------- ------------
VMware VMCI Host Device  9.8.6.0       VMware, Inc.
VMware PVSCSI Controller 1.3.10.0      VMware, Inc.
...
```

## <mark style="color:red;">**Binaries That AutoElevate**</mark>

Check the status of the _AlwaysInstallElevated_ registry setting. If this setting is enabled, we could craft an _MSI_ file and run it to elevate our privileges:

```powershell
C:\> reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1

C:\> reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
```
