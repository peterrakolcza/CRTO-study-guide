## DNS Records

---

- simple A record lookup
```
dig <domain>
```

- IP address lookup
```
whois <ip>
```

- DNS scan ([dnscan](https://github.com/rbsec/dnscan))
```
./dnscan.py -d <domain> -w <wordlist>
```

- email security verification for a domain ([Spoofy](https://github.com/MattKeeley/Spoofy))
```
python3 spoofy.py -d <domain> -o stdout
```