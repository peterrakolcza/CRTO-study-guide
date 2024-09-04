[hashcat](https://hashcat.net/hashcat/)
[hashcat wiki](https://hashcat.net/wiki/doku.php?id=rule_based_attack)

## Usage

---

```
hashcat.exe -a 0 -m 1000 ntlm.txt rockyou.txt

58a478135a93ac3bf058a5ea0e8fdb71:Password123
```

Where:

- `-a 0` specifies the wordlist attack mode.
- `-m 1000` specifies that the hash is NTLM.
- `ntlm.txt` is a text file containing the NTLM hash to crack.
- `rockyou.txt` is the wordlist.


### Rules

Rules are a means of extending or manipulating the "base" words in a wordlist in ways that are common habits for users. Such manipulation can include toggling character cases (e.g. `a` to `A`), character replacement (e.g. `a` to `@`) and prepending/appending characters (e.g. `password` to `password!`).  This allows our wordlists to be overall smaller in size (because we don't have to store every permutation), but with the drawback of a slightly slower cracking time.

```
hashcat.exe -a 0 -m 1000 ntlm.txt rockyou.txt -r rules\add-year.rule

acbfc03df96e93cf7294a01a6abbda33:Summer2020
```

Where:

- `-r rules\add-year.rule` is our custom rule file


### Masks

```
hashcat.exe -a 3 -m 1000 C:\Temp\ntlm.txt ?u?l?l?l?l?l?l?l?d

64f12cddaa88057e06a81b54e73b949b:Password1
```

Where:

- `-a 3` specifies the mask attack.
- `?u?l?l?l?l?l?l?l?d` is the mask.

```
hashcat.exe -a 3 -m 1000 ntlm.txt -1 ?d?s ?u?l?l?l?l?l?l?l?1

fbdcd5041c96ddbd82224270b57f11fc:Password!
```

Where:

- `-1 ?d?s` defines a custom charset (digits and specials).
- `?u?l?l?l?l?l?l?l?1` is the mask, where `?1` is the custom charset.

By default, this mask attack sets a static password length - `?u?l?l?l?l?l?l?l?1` defines 9 characters, which means we can only crack a 9-character password. To crack passwords of different lengths, we have to manually adjust the mask accordingly.

Hashcat mask files make this process a lot easier for custom masks that you use often.

```
PS C:\> cat example.hcmask
?d?s,?u?l?l?l?l?1
?d?s,?u?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?l?1
```

```
hashcat.exe -a 3 -m 1000 ntlm.txt example.hcmask
hashcat (v6.1.1) starting...

Status...........: Exhausted
Guess.Mask.......: ?u?l?l?l?l?1 [6]

[...snip...]

Guess.Mask.......: ?u?l?l?l?l?l?1 [7]

820be3700dfcfc49e6eb6ef88d765d01:Chimney!
```

Masks can even have static strings defined, such as a company name or other keyword you suspect are being used in passwords.

```
ZeroPointSecurity?d
ZeroPointSecurity?d?d
ZeroPointSecurity?d?d?d
ZeroPointSecurity?d?d?d?d
```

```
hashcat.exe -a 3 -m 1000 ntlm.txt example2.hcmask

f63ebb17e157149b6dfde5d0cc32803c:ZeroPointSecurity1234
```

```
? | Charset
===+=========
l | abcdefghijklmnopqrstuvwxyz
u | ABCDEFGHIJKLMNOPQRSTUVWXYZ
d | 0123456789
h | 0123456789abcdef
H | 0123456789ABCDEF
s | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
a | ?l?u?d?s
b | 0x00 - 0xff
```


### Combinator

The combinator attack combines the entries from two dictionaries into single-word candidates. Take the following lists as an example:

```
PS C:\> cat list1.txt
purple

PS C:\> cat list2.txt
monkey
dishwasher
```

The combinator will produce "purplemonkey" and "purpledishwasher" as candidates.  You can also apply a rule to each word on the left- or right-hand side using the options `-j` and `-k`.  For instance, `-j $-` and `-k $!` would produce `purple-monkey!`.

```
hashcat.exe -a 1 -m 1000 ntlm.txt list1.txt list2.txt -j $- -k $!

ef81b5ffcbb0d030874022e8fb7e4229:purple-monkey!
```


### Hybrid

Hashcat modes 6 and 7 are hybrid's based on wordlists, masks and the combinator.  You specify both a wordlist and mask on the command line, and the mask is appended or prepended to the words within the list. For example, your dictionary contains the word `Password`, then `-a 6 [...] list.txt ?d?d?d?d` will produce `Password0000` to `Password9999`.

```
hashcat.exe -a 6 -m 1000 ntlm.txt list.txt ?d?d?d?d

be4c5fb0b163f3cc57bd390cdc495bb9:Password5555
```

Where:

- `-a 6` specifies the hybrid wordlist + mask mode.
- `?d?d?d?d` is the mask.

The hybrid mask + wordlist mode (`-a 7`) is practically identical, where the mask comes first.

```
hashcat.exe -a 7 -m 1000 ntlm.txt ?d?d?d?d list.txt

28a3b8f54a6661f15007fca23beccc9c:5555Password
```


### Crack krb5tgs

```
hashcat.exe -a 0 -m 13100 hashes wordlist
```


### Crack krb5asrep

```
hashcat.exe -a 0 -m 18200 squid_svc wordlist
```

Insert `$23$` after `$krb5asrep` in the hash.


### Crack MsCacheV2

Format:

```
$DCC2$10240#username#hash
```

```
hashcat -a 0 -m 2100
```