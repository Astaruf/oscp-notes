# AD Automatic Enumeration

## <mark style="color:red;">Sharpound</mark>

There are two different Sharphound collectors:

**SharpHound.ps1**: PowerShell script for running Sharphound. However, the latest release of Sharphound has stopped releasing the Powershell script version. This version is good to use with RATs since the script can be loaded directly into memory, evading on-disk AV scans.

SharpHound.exe: a Windows executable version for running Sharphound.

Both are available here:

{% embed url="https://github.com/BloodHoundAD/SharpHound/releases" %}

Run Sharphound using the All and Session collection methods:

```powershell
cmd> Sharphound.exe --CollectionMethods All --Domain asd.domain.com --ExcludeDCs 
```

Once completed, you will have a timestamped ZIP file in the same folder you executed Sharphound from.

## <mark style="color:red;">BloodHound</mark>

From Kali:

```
neo4j console start
```

In another Terminal tab, run:

```bash
bloodhound --no-sandbox # This will show you the authentication GUI
```

{% hint style="info" %}
The default credentials for the neo4j database will be `neo4j:neo4j`
{% endhint %}

Drag and drop the ZIP file onto the Bloodhound GUI to import it.

