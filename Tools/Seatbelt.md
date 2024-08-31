[Seatbelt](https://github.com/GhostPack/Seatbelt) is a C# tool which automatically collects enumeration data for a host.  It can check for security configurations such as OS info, AV, AppLocker, LAPS, PowerShell logging, audit policies, .NET versions, firewall rules, and more.

## Usage

### Host Enumeration

```
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe -group=system
```

### OSInfo

Gathers OS information.

```
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe OSInfo -ComputerName=web
```


### WindowsVault

Enumerates Windows Vault.

```
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsVault
```

### WindowsCredentialFiles

Enumerates Windows Credential Files.

```
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsCredentialFiles
```

### Certificates

Enumerates ADCS certificates.

```
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe Certificates
```

### TokenPrivileges

Enumerates user privileges.

```
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe TokenPrivileges
```