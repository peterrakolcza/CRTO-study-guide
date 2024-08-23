[PowerView](https://github.com/PowerShellMafia/PowerSploit) has long been the de-facto tool for domain enumeration.  One of its biggest strengths is that the queries return proper PowerShell objects, which can be piped to other cmdlets.  This allows you to chain multiple commands together to form complex and powerful queries.


## Usage

---

```
powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1
```

### Get-Domain

Returns a domain object for the current domain or the domain specified with `-Domain`. Useful information includes the domain name, the forest name and the domain controllers.

```
powershell Get-Domain
```

### Get-DomainController

Returns the domain controllers for the current or specified domain.

```
powershell Get-DomainController | select Forest, Name, OSVersion | fl
```

### Get-ForestDomain

Returns all domains for the current forest or the forest specified by `-Forest`.

```
powershell Get-ForestDomain
```

### Get-DomainPolicyData

Returns the default domain policy or the domain controller policy for the current domain or a specified domain/domain controller. Useful for finding information such as the domain password policy.

```
powershell Get-DomainPolicyData | select -expand SystemAccess
```

### Get-DomainUser

Return all (or specific) user(s). To only return specific properties, use `-Properties`. By default, all user objects for the current domain are returned, use `-Identity` to return a specific user.

```
powershell Get-DomainUser -Identity jking -Properties DisplayName, MemberOf | fl
```

### Get-DomainComputer

Return all computers or specific computer objects.

```
powershell Get-DomainComputer -Properties DnsHostName | sort -Property DnsHostName
```

#### Read Property

Reads the specified properties of a domain computer

```
powershell Get-DomainComputer -Identity wkstn-1 -Properties ms-Mcs-AdmPwd
```

#### Keyword

Returns the output for the specified keyword.

```
powershell Get-DomainComputer | ? { $_."ms-Mcs-AdmPwdExpirationTime" -ne $null } | select dnsHostName
```


### Set-DomainObject

Set a value for a domain object.

```
powershell Set-DomainObject -Identity wkstn-1 -Set @{'ms-Mcs-AdmPwdExpirationTime' = '136257686710000000'} -Verbose
```


### Get-DomainOU

Search for all organization units (OUs) or specific OU objects.

```
powershell Get-DomainOU -Properties Name | sort -Property Name
```

### Get-DomainGroup

Return all domain groups or specific domain group objects.

```
powershell Get-DomainGroup | where Name -like "*Admins*" | select SamAccountName
```

### Get-DomainGroupMember

Return the members of a specific domain group.

```
powershell Get-DomainGroupMember -Identity "Domain Admins" | select MemberDistinguishedName
```

Return domain groups and their members.

```
powershell Get-DomainGroup -Identity *SQL* | % { Get-DomainGroupMember -Identity $_.distinguishedname | select groupname, membername }
```

### Get-DomainGPO

Return all Group Policy Objects (GPOs) or specific GPO objects. To enumerate all GPOs that are applied to a particular machine, use `-ComputerIdentity`.

```
powershell Get-DomainGPO -Properties DisplayName | sort -Property DisplayName
```

#### Keyword

Returns the output for the specified keyword.

```
powershell Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl
```

### Get-DomainGPOLocalGroup

Returns all GPOs that modify local group membership through Restricted Groups or Group Policy Preferences.  You can then manually find which OUs, and by extension which computers, these GPOs apply to.

```
powershell Get-DomainGPOLocalGroup | select GPODisplayName, GroupName
```

### Get-DomainGPOUserLocalGroupMapping

Enumerates the machines where a specific domain user/group is a member of a specific local group.  This is useful for finding where domain groups have local admin access, which is a more automated way to perform the manual cross-referencing described above.

```
powershell Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName | fl
```

### Get-DomainTrust

Return all domain trusts for the current or specified domain.

```
powershell Get-DomainTrust
```

Query trusts with `-Domain`


### Get-DomainForeignGroupMember

Enumerate groups that contain users outside of its domain and return its members.

```
powershell Get-DomainForeignGroupMember -Domain dev-studio.com
```

### ConvertFrom-SID

Convert SID to username.

```
powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1120
```

### Get-DomainObject

Get GUID for Trusted Domain Object.

```
powershell Get-DomainObject -Identity "CN=msp.org,CN=System,DC=cyberbotic,DC=io" | select objectGuid
```

### FindDomainShare

Searches for computer shares on the domain.  The `-CheckShareAccess` parameter only shows that shares the current user has read access to.

```
powershell Find-DomainShare -CheckShareAccess
```

### Find-InterestingDomainShareFile

Searches each share, returning results where the specified strings appear in the path.

```
powershell Find-InterestingDomainShareFile -Include *.doc*, *.xls*, *.csv, *.ppt*
```