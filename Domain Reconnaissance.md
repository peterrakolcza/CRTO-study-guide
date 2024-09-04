![[rto_lab.webp]]

## Tools to Use

---

1. [[PowerView]]
2. [[SharpView]]
3. [[ADSearch]]
4. [[SharpSCCM]]


## Microsoft Configuration Manager Enumeration

---

Given a foothold on a machine, we can begin by finding the management point and site code that it is linked to.  This does not require any special privileges in the domain, in SCCM or on the endpoint.

[[SharpSCCM#local site-info]]

This enumeration uses WMI under the hood, which could be done manually.

```
powershell Get-WmiObject -Class SMS_Authority -Namespace root\CCM | select Name, CurrentManagementPoint | fl
```

We can also check the DACL on the `CN=System Management` container in AD for machines that have Full Control over it (as this a pre-requisite of SCCM setup in a domain).

[[SharpSCCM#get site-info]]

Enumerating users, groups, computers, collections, and administrators, etc, does require some level of privilege in SCCM and cannot be done as a standard domain user.  SCCM employs an RBAC security model - the lowest role is "Read-Only Analyst" and the highest is "Full Administrator".  Lots of other roles exist such as "Asset Manager", "Infrastructure Administrator", and "Software Update Manager".  A description of each can be found [here](https://learn.microsoft.com/en-us/mem/configmgr/core/understand/fundamentals-of-role-based-administration).  Furthermore, the "scope" of these roles can be restricted to individual collections as needed by the administrative user.  For example, computers from the DEV and CYBER domains have been grouped into their own collections.

This can really impact your view (as an attacker) of how SCCM is configured.  For example, if we enumerate all the collections as bfarmer, we can see that both DEV and CYBER exist as well as their member counts.

[[SharpSCCM#get collections]]

When enumerating SCCM, you may only see a small slither based on the user you're running the enumeration as.

Administrative users can be found using `get class-instances SMS_Admin`.

[[SharpSCCM#get class-instances]]

Members of these collections can be found using `get collection-members -n <collection-name>`.

[[SharpSCCM#get collection-members]]

Even more information on each device can be obtained using `get devices`.  There are some good ways to filter the output, such as searching by device name, `-n`, and only displaying the properties specified by `-p`.

[[SharpSCCM#get devices]]

You can also use SCCM as a form of user hunting, since it records the last user to login to each managed computer.  The `-u` parameter will only return devices where the given user was the last to login.

[[SharpSCCM#get devices#For User]]

However, take these results with a grain of salt because this information is only updated in SCCM every 7 days by default.


## Forests & Domain Trusts

---

### Enumerate Domain Trust

[[PowerView#Get-DomainTrust]]

```
SourceName      : dev.cyberbotic.io
TargetName      : cyberbotic.io
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST
TrustDirection  : Bidirectional
WhenCreated     : 8/15/2022 4:00:00 PM
WhenChanged     : 8/15/2022 4:00:00 PM
```

SourceName is the current domain, TargetName is the foreign domain, TrustDirection is the trust direction (bidirectional is two-way), and TrustAttributes: WITHIN_FOREST lets us know that both of these domains are part of the same forest which implies a parent/child relationship.

If we have Domain Admin privileges in the child, we can also gain Domain Admin privileges in the parent using a TGT with a special attribute called SID History.  SID History was designed to support migration scenarios, where a user would be moved from one domain to another.  To preserve access to resources in the "old" domain, the user's previous SID would be added to the SID History of their new account.  When creating such a ticket, the SID of a privileged group (EAs, DAs, etc) in the parent domain can be added that will grant access to all resources in the parent.

This can be achieved using either a Golden or Diamond Ticket.
- [[Domain Dominance#Golden Tickets]]
- [[Domain Dominance#Diamond Tickets]]


## Data Hunting & Exfiltration

---

### File Shares

- [[PowerView#FindDomainShare]]
- [[PowerView#Find-InterestingDomainShareFile]]

```
beacon> powershell gc \\fs.dev.cyberbotic.io\finance$\export.csv | select -first 5
```

### Databases

- [[PowerUpSQL#Get-SQLColumnSampleDataThreaded]]
- [[PowerUpSQL#Get-SQLQuery#Search Keywords in SQL Links]]

Note the "employees" table.  Next, list its columns.

```
beacon> powershell Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select column_name from master.information_schema.columns where table_name=''employees''')"
```

Then finally, take a data sample.

```
beacon> powershell Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select top 5 first_name,gender,sort_code from master.dbo.employees')"
```
