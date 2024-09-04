[ADSearch](https://github.com/tomcarver16/ADSearch) has fewer built-in searches compared to PowerView and SharpView, but it does allow you to specify custom Lightweight Directory Access Protocol (LDAP) searches.  These can be used to identify entries in the directory that match a given criteria.


## Example Commands

---

### Get All Object with "user" Category

```
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "objectCategory=user"
```

### Get All Domain Groups That Ends with "admins"

```
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=group)(cn=*Admins))"
```

These can be made more complex with further AND, OR and NOT conditions.  All attributes can be returned using the `--full` parameter, or specific attributes with the `--attributes` parameter.

```
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=group)(cn=MS SQL Admins))" --attributes cn,member
```

Additionally, the `--json` parameter can be used to format the output in JSON.

``` json
[
  {
    "cn": "MS SQL Admins",
    "member": "CN=Developers,CN=Users,DC=dev,DC=cyberbotic,DC=io"
  }
]
```

### Enumerate Kerberoastable Users

```
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(servicePrincipalName=*))" --attributes cn,servicePrincipalName,samAccountName
```

### Enumerate ASREP Roastable Users

```
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,distinguishedname,samaccountname
```

### Enumerate Computers for Unconstrained Delegation

```
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname
```

### Enumerate Computers and Users for Constrained Delegation

```
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto --json
```

### Enumerate Trusted Domains

```
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(objectCategory=trustedDomain)" --domain cyberbotic.io --attributes distinguishedName,name,flatName,trustDirection
```