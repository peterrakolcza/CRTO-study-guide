## Basic Troubleshooting Guide:
---
- **HTTP beacon and persistence not working with HTTP service:**
  Check if the target machine can reach the team server with a quick Powershell command. If not, that is the problem.
- **Moving laterally with Local Admin credentials:**
  Cobalt Strike's built-in psexec is ticket based, but you can use impacket's psexec.py with socks proxy `proxychains psexec.py './Administrator:password@ip'`
- **Moving laterally after exploiting a Constrained Delegation:**
  Alternative Service Name and use the following table for useful ticket combinations
  
| Technique         | Required Service Tickets |
| ----------------- | ------------------------ |
| psexec            | CIFS (& HOST)               |
| winrm             | HOST & HTTP              |
| dcsync (DCs only) | LDAP                     |


- **One have CIFS Kerberos ticket imported, however jump is not working:**
  Use the FQDN of the machine, not the NetBios name. Furthermore, pass the ticket to a new logon session, passing the ticket to the existing logon session can create anomalies. Lastly cd-ing into the c$ share before jumping sometimes helps.
- **Base64 encoded powershell payload not working:**
  Do not use random online base64 encoder. Use the [[Miscellaneous#Powershell payload base64 encoding]] instead. This also unicode encodes it.
- **Multiple powershell commands seperated by semicolons are not working:**
  Try adding a space after the semicolon...
  