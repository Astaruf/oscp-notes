# AD Manual Enumeration

## <mark style="color:red;">Users / Groups / Computers</mark>

* Look for users with high-privs across the domain e.g. Domain Admins or Derivative Local Admins
* Look for custom groups.

```powershell
# get a list of all users in the domain
cmd> net user /domain
PS > Get-NetUser | select cn # Using PowerView.ps1

# get details about a specific user 
cmd> net user [username] /domain # more than 10 group memberships, cmd will fail
PS > Get-ADUser -Identity <username> -Server asd.domain.com -Properties * # Powershell

# get list of all groups in the domain
cmd> net group /domain
PS > Get-ADUser -Filter 'Name -like "*lorenzo"' -Server asd.domain.com | Format-Table Name,SamAccountName -A
PS > Get-NetGroup -GroupName * # Using PowerView.ps1

# enumerate AD groups
PS > Get-ADGroup -Identity Administrators -Server asd.domain.com

# get details such as membership to a group
cmd> net group [groupname] /domain
PS > Get-ADGroupMember -Identity Administrators -Server domain.com # Powershell

# get the password policy of the domain
cmd> net accounts /domain

# get all AD objects that were changed after a specific date
PS > $ChangeDate = New-Object DateTime(2022, 02, 28, 12, 00, 00)
PS > Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -includeDeletedObjects -Server asd.domain.com

# enumerate accounts that have a badPwdCount that is greater than 0
# useful to avoid these accounts in our bruteforce attacks
PS > Get-ADObject -Filter 'badPwdCount -gt 0' -Server domain.com

# get additional information about the specific domain
PS> Get-ADDomain -Server asd.domain.com

# get all computers in domain
cmd> net view
cmd> net view /domain

# get resources/shares of specified computer
cmd> net view \\[computer_name] /domain

# get a list of all operating systems on the domain 
PS > Get-NetComputer -fulldata | select operatingsystem # Using PowerView.ps1
```

Domain Controller hostname (PdcRoleOwner)\*\*

```powershell
PS> [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

This PowerShell script will collect all users along with their attributes:

```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="samAccountType=805306368"
$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }
    Write-Host "------------------------"
}
```

In the filter property, we can set any attribute of the object type we desire. For example, we can use the _name_ property to create a filter for the Jeff\_Admin user as shown below:

```
$Searcher.filter="name=Jeff_Admin"
```

## <mark style="color:red;">Nested Groups</mark>

Locate all groups in the domain and print their names:

<pre class="language-powershell"><code class="lang-powershell">$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="(objectClass=<a data-footnote-ref href="#user-content-fn-1">Group</a>)"
$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
    $obj.Properties.name
}
</code></pre>

List the members of a group by setting an appropriate filter on the _name_ property. In addition, we will only display the _member_ attribute to obtain the group members.

<pre class="language-powershell"><code class="lang-powershell">$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="(name=<a data-footnote-ref href="#user-content-fn-2">GROUPNAME</a>)"
$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
    $obj.Properties.<a data-footnote-ref href="#user-content-fn-3">member</a>
}
</code></pre>

## <mark style="color:red;">Logged-in users and active user sessions</mark>

* More powerview commands [https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters/powerview](https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters/powerview)

```powershell
PS> Set-ExecutionPolicy Unrestricted
PS> Import-Module .\PowerView.ps1
PS> Get-NetLoggedon -ComputerName [computer_name]    # enum logged-in users
PS> Get-NetSession -ComputerName [domain_controller] # enum active user sessions
```

## <mark style="color:red;">Service Principal Names (AD Service Accounts)</mark>

* A SPN is a unique name for a service on a host, used to associate with an Active Directory service account.
* Enum SPNs to obtain the IP address and port number of apps running on servers integrated with Active Directory.
* Query the Domain Controller in search of SPNs.
* SPN Examples
  * `CIFS/MYCOMPUTER$` - file share access.
  * `LDAP/MYCOMPUTER$` - querying AD info via. LDAP.
  * `HTTP/MYCOMPUTER$` - Web services such as IIS.
  * `MSSQLSvc/MYCOMPUTER$` - MSSQL.

For example, let's update our PowerShell enumeration script to filter the _serviceprincipalname_ property for the string _\*http\*_, indicating the presence of a registered web server:

```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="serviceprincipalname=*http*"
$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }
}
```

* Perform `nslookup` of the service hostname -> see if there is an entrypoint here.
* Automated SPN enum scripts:

```powershell
# Kerberoast: https://github.com/nidem/kerberoast/blob/master/GetUserSPNs.ps1
PS> .\GetUserSPNs.ps1

# Powershell Empire: https://github.com/compwiz32/PowerShell/blob/master/Get-SPN.ps1
PS> .\Get-SPN.ps1
```

[^1]: 

[^2]: 

[^3]: 
