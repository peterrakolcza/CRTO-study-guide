## Bulletpoints for exam
---
1. external recon
	- [ ] [[External Reconnaissance]]
1. initial compromise
	- [ ] phising email (vba script, template, html smuggling)
2. host recon
	- [ ] check current users privileges (whoami /priv, whoami /groups)
    - [ ] seatbelt host enum
    - [ ] LAPS (if we are able to read the AdmPwd, we can impersonate LapsAdmin and access other machines) 
3. host persistence:
	- elevated:
		- [ ] new SMB service
		- [ ] WMI
	- non-elevated:
		- [ ] Task Scheduler
		- [ ] Startup folder
		- [ ] Registry AutoRun
		- [ ] COM Hijacks
		- [ ] GPO
1. domain recon:
	- [ ] domain computers
	- [ ] domain users
	- [ ] enumerate GPOs
	- [ ] enumerate GPOUserLocalGroupMapping
2. lateral movement:
	- [ ] keep in mind firewall limitations
	- [ ] Unconstrained delegation
	- [ ] Constrained delegation
	- [ ] RBCD
	- [ ] Kerberoasting
	- [ ] ASREP roasting
3. credential harvesting:
	- [ ] Windows Credential Manager
	- [ ] MS SQL
	- [ ] File shares
	- [ ] lsadump, lsadump::cache
	- [ ] sekurlsa::logonpasswords, sekurlsa::ekeys
	- [ ] Extracting Kerberos Tickets



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
  Use the FQDN of the machine, not the NetBios name. Furthermore, pass the ticket to a new logon session, passing the ticket to the existing logon session can create anomalies.